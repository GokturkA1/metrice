import net from 'node:net';
import dns from 'node:dns/promises';
import EventEmitter from 'node:events';
import { CONFIG } from '../config/index.js';
import { Logger } from '../utils/logger.js';
import { AddressHelper } from '../utils/addressHelper.js';
import { CryptoHelper } from '../utils/cryptoHelper.js';
import { I18n } from '../locales/i18n.js';

const log = new Logger('FEDERATION');

// Nonce Replay Havuzu (Zaman damgası tabanlı TTL)
class NonceTracker {
  constructor(ttlMs = 60000) {
    this.ttlMs = ttlMs;
    this.nonces = new Map(); // nonce -> { timestamp, ip }
  }

  track(nonce, remoteIp = '') {
    const now = Date.now();
    this.cleanup(now);
    
    // Loopback (localhost) testlerinde kendi kendine atılan paketlerin çakışmasını önle
    const key = `${nonce}_${remoteIp}`;
    if (this.nonces.has(key)) {
      return false; 
    }
    this.nonces.set(key, now);
    return true;
  }

  cleanup(now) {
    for (const [key, ts] of this.nonces.entries()) {
      if (now - ts > this.ttlMs) {
        this.nonces.delete(key);
      } else {
        break;
      }
    }
  }
}

// Mesaj Tekilleştirme için TTL Önbelleği
class MessageTtlCache {
  constructor(ttlMs = 120000) { // 2 dakika TTL
    this.ttlMs = ttlMs;
    this.cache = new Map(); // id -> timestamp
  }

  has(id) {
    const now = Date.now();
    const ts = this.cache.get(id);
    if (!ts) return false;
    if (now - ts > this.ttlMs) {
      this.cache.delete(id);
      return false;
    }
    return true;
  }

  add(id) {
    const now = Date.now();
    this.cleanup(now);
    this.cache.set(id, now);
  }

  cleanup(now) {
    if (this.cache.size > 2000) {
      for (const [id, ts] of this.cache.entries()) {
        if (now - ts > this.ttlMs) {
          this.cache.delete(id);
        } else {
          break;
        }
      }
    }
  }
}

class SecureChannel extends EventEmitter {
  constructor(socket, isInitiator, myIdentity, db, nonceTracker) {
    super();
    this.socket = socket;
    this.isInitiator = isInitiator;
    this.myIdentity = myIdentity;
    this.db = db;
    this.nonceTracker = nonceTracker;

    this.isReady = false;
    this.sessionKey = null;
    this.peerNodeAddress = null;
    this.peerIdentityKey = null;
    this.peerKemKey = null;

    this.pendingQueue = [];
    this.buffer = '';

    this.initSocketHandlers();
    if (this.isInitiator) {
      this.sendHandshakeInit();
    }
  }

  initSocketHandlers() {
    this.socket.on('data', (chunk) => {
      this.buffer += chunk.toString();
      const lines = this.buffer.split('\n');
      this.buffer = lines.pop();

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const frame = JSON.parse(line);
          await this.handleFrame(frame);
        } catch (err) {
          log.warn(I18n.t('FED_SECURE_CHANNEL_PARSE_ERR', { error: err.message }));
        }
      }
    });

    this.socket.on('error', (err) => this.emit('error', err));
    this.socket.on('close', () => this.emit('close'));
  }

  sendHandshakeInit() {
    const nonce = CryptoHelper.generateRandomKey(16);
    this.nonceTracker.track(nonce);

    const dataToSign = JSON.stringify({
      type: 'HANDSHAKE_INIT',
      nodeAddress: this.myIdentity.nodeAddress,
      identityPublicKey: this.myIdentity.identityKeyPair.publicKey,
      kemPublicKey: this.myIdentity.kemKeyPair.publicKey,
      nonce
    });

    const sig = CryptoHelper.sign(dataToSign, this.myIdentity.identityKeyPair.privateKey);

    const payload = {
      type: 'HANDSHAKE_INIT',
      nodeAddress: this.myIdentity.nodeAddress,
      identityPublicKey: this.myIdentity.identityKeyPair.publicKey,
      kemPublicKey: this.myIdentity.kemKeyPair.publicKey,
      nonce,
      sig
    };

    this.socket.write(JSON.stringify(payload) + '\n');
  }

  handleFrame(frame) {
    // 1. HANDSHAKE_INIT
    if (frame.type === 'HANDSHAKE_INIT') {
      const remoteIp = this.socket.remoteAddress || '';
      if (!this.nonceTracker.track(frame.nonce, remoteIp)) {
        log.warn(I18n.t('FED_REPLAY_NONCE_DETECTED', { node: frame.nodeAddress }));
        this.socket.destroy();
        return;
      }

      if (!(await validatePeerIp(frame.nodeAddress))) {
        log.warn(I18n.t('FED_IP_SPOOFING_DETECTED', { declared: frame.nodeAddress, remote: this.socket.remoteAddress }));
        this.socket.destroy();
        return;
      }

      const dataToVerify = JSON.stringify({
        type: 'HANDSHAKE_INIT',
        nodeAddress: frame.nodeAddress,
        identityPublicKey: frame.identityPublicKey,
        kemPublicKey: frame.kemPublicKey,
        nonce: frame.nonce
      });

      const isValid = CryptoHelper.verify(dataToVerify, frame.sig, frame.identityPublicKey);
      if (!isValid) {
        log.warn(I18n.t('FED_SECURE_HANDSHAKE_INIT_FAIL', { node: frame.nodeAddress }));
        this.socket.destroy();
        return;
      }

      this.peerNodeAddress = frame.nodeAddress;
      this.peerIdentityKey = frame.identityPublicKey;
      this.peerKemKey = frame.kemPublicKey;
      this.db.saveTrustedNodeKey(this.peerNodeAddress, this.peerIdentityKey, this.peerKemKey);

      const { sharedSecret, encapsulatedKey } = CryptoHelper.encapsulateKey(this.peerKemKey);
      this.sessionKey = CryptoHelper.deriveKey(sharedSecret, frame.nonce, 'p2p-mesh-transport-v1');

      const replyDataToSign = JSON.stringify({
        type: 'HANDSHAKE_REPLY',
        nodeAddress: this.myIdentity.nodeAddress,
        identityPublicKey: this.myIdentity.identityKeyPair.publicKey,
        encapsulatedKey,
        nonce: frame.nonce
      });

      const replySig = CryptoHelper.sign(replyDataToSign, this.myIdentity.identityKeyPair.privateKey);

      const replyPayload = {
        type: 'HANDSHAKE_REPLY',
        nodeAddress: this.myIdentity.nodeAddress,
        identityPublicKey: this.myIdentity.identityKeyPair.publicKey,
        encapsulatedKey,
        nonce: frame.nonce,
        sig: replySig
      };

      this.socket.write(JSON.stringify(replyPayload) + '\n');
      this.markReady();
      return;
    }

    // 2. HANDSHAKE_REPLY
    if (frame.type === 'HANDSHAKE_REPLY') {
      const replyDataToVerify = JSON.stringify({
        type: 'HANDSHAKE_REPLY',
        nodeAddress: frame.nodeAddress,
        identityPublicKey: frame.identityPublicKey,
        encapsulatedKey: frame.encapsulatedKey,
        nonce: frame.nonce
      });

      const isValid = CryptoHelper.verify(replyDataToVerify, frame.sig, frame.identityPublicKey);
      if (!isValid) {
        log.warn(I18n.t('FED_SECURE_HANDSHAKE_REPLY_FAIL', { node: frame.nodeAddress }));
        this.socket.destroy();
        return;
      }

      this.peerNodeAddress = frame.nodeAddress;
      this.peerIdentityKey = frame.identityPublicKey;
      this.db.saveTrustedNodeKey(this.peerNodeAddress, this.peerIdentityKey, this.peerIdentityKey);

      const sharedSecret = CryptoHelper.decapsulateKey(
        this.myIdentity.kemKeyPair.privateKey,
        frame.encapsulatedKey
      );

      this.sessionKey = CryptoHelper.deriveKey(sharedSecret, frame.nonce, 'p2p-mesh-transport-v1');
      this.markReady();
      return;
    }

    // 3. ENCRYPTED_FRAME
    if (frame.type === 'ENCRYPTED_FRAME') {
      if (!this.isReady || !this.sessionKey) {
        log.warn(I18n.t('FED_SECURE_FRAME_NOT_READY'));
        return;
      }

      const decryptedRaw = CryptoHelper.decrypt(frame, this.sessionKey);
      if (!decryptedRaw) {
        log.warn(I18n.t('FED_SECURE_DECRYPT_FAIL', { peer: this.peerNodeAddress }));
        return;
      }

      try {
        const payload = JSON.parse(decryptedRaw);
        this.emit('payload', payload);
      } catch (err) {
        log.warn(I18n.t('FED_SECURE_DECRYPT_JSON_ERR', { error: err.message }));
      }
    }
  }

  async validatePeerIp(declaredNodeAddress) {
    if (!declaredNodeAddress || !declaredNodeAddress.includes(':')) return false;
    const [declaredHost] = declaredNodeAddress.split(':');
    const rawRemote = this.socket.remoteAddress || '';
    const cleanRemote = rawRemote.replace('::ffff:', '');

    // 1. Kendi adresi veya genel sunucu adı toleransı
    if (declaredHost === CONFIG.serverName) {
      return true;
    }

    // 2. Loopback toleransı
    const isLoopback = (ip) => ip === '127.0.0.1' || ip === '::1' || ip === 'localhost';
    if (isLoopback(declaredHost) && isLoopback(cleanRemote)) {
      return true;
    }

    // 3. Özel Ağ / Intranet (RFC 1918) toleransı
    const isPrivateSubnet = (ip) => {
      return /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/.test(ip);
    };

    if (isPrivateSubnet(cleanRemote)) {
      return true;
    }

    // 4. Reverse proxy bayrağı
    if (process.env.TRUST_PROXY === 'true') {
      return true;
    }

    // 5. Doğrudan IP eşleşmesi
    if (declaredHost === cleanRemote) {
      return true;
    }

    // 6. DNS Çözümleme (Domain -> IP Eşleşmesi)
    try {
      const resolved = await dns.lookup(declaredHost, { all: true });
      return resolved.some((entry) => entry.address === cleanRemote);
    } catch {
      return false;
    }
  }

  markReady() {
    this.isReady = true;
    this.emit('ready');

    while (this.pendingQueue.length > 0) {
      const payload = this.pendingQueue.shift();
      this.writePayload(payload);
    }
  }

  writePayload(payload) {
    if (!this.isReady || !this.sessionKey) {
      this.pendingQueue.push(payload);
      return;
    }

    const plaintext = JSON.stringify(payload);
    const encrypted = CryptoHelper.encrypt(plaintext, this.sessionKey);

    const frame = {
      type: 'ENCRYPTED_FRAME',
      iv: encrypted.iv,
      ciphertext: encrypted.ciphertext,
      authTag: encrypted.authTag
    };

    this.socket.write(JSON.stringify(frame) + '\n');
  }
}

export class FederationEngine extends EventEmitter {
  constructor(db, peerManager) {
    super();
    this.db = db;
    this.peerManager = peerManager;
    this.server = null;
    this.outboxInterval = null;
    this.presenceInterval = null;
    this.gossipTimeout = null;

    // Gelişmiş Güvenlik Mekanizmaları
    this.nonceTracker = new NonceTracker(60000);
    this.seenMessages = new MessageTtlCache(180000); // 3 dakika TTL
    this.connectionPool = new Map();

    const identity = this.db.getNodeIdentity();
    this.identityKeyPair = identity.identityKeyPair;
    this.kemKeyPair = identity.kemKeyPair;
    this.nodeAddress = `${CONFIG.serverName}:${CONFIG.federationPort}`;

    this.myIdentity = {
      nodeAddress: this.nodeAddress,
      identityKeyPair: this.identityKeyPair,
      kemKeyPair: this.kemKeyPair
    };

    this.remoteOnlineUsers = new Map();
    this.getLocalStateFn = null;
    this.channelSubscribers = new Map();

    log.info(I18n.t('FED_NODE_IDENTITY_READY', { address: this.nodeAddress }));
  }

  setLocalStateGetter(fn) {
    this.getLocalStateFn = fn;
  }

  getAllOnlineUsers() {
    const now = Date.now();
    const activeRemote = [];
    for (const [userAddr, data] of this.remoteOnlineUsers.entries()) {
      if (now - data.lastSeen < 25000) {
        activeRemote.push(userAddr);
      } else {
        this.remoteOnlineUsers.delete(userAddr);
      }
    }
    const localState = this.getLocalStateFn ? this.getLocalStateFn() : { users: [] };
    return Array.from(new Set([...localState.users, ...activeRemote]));
  }

  getChannelMembers(channelName) {
    const members = [];
    const now = Date.now();

    for (const [userAddr, data] of this.remoteOnlineUsers.entries()) {
      if (now - data.lastSeen < 25000 && Array.isArray(data.channels) && data.channels.includes(channelName)) {
        members.push(userAddr);
      }
    }
    return members;
  }

  getRemoteUserSecurity(userAddress) {
    const data = this.remoteOnlineUsers.get(userAddress);
    if (!data) return null;
    return {
      isSsh: !!data.isSsh,
      kemPublicKey: data.kemPublicKey || ''
    };
  }

  start() {
    this.peerManager.startLanDiscovery();

    this.server = net.createServer((socket) => {
      const remotePeer = `${socket.remoteAddress}:${socket.remotePort}`;
      log.info(I18n.t('FED_INCOMING_CONN', { peer: remotePeer }));

      const secureChannel = new SecureChannel(socket, false, this.myIdentity, this.db, this.nonceTracker);

      secureChannel.on('payload', (payload) => {
        this.handleIncoming(payload, secureChannel, remotePeer);
      });

      secureChannel.on('error', (err) => {
        log.error(I18n.t('FED_SOCKET_ERROR', { peer: remotePeer, error: err.message }));
      });
    });

    this.server.listen(CONFIG.federationPort, () => {
      log.info(I18n.t('FED_LISTENING', { port: CONFIG.federationPort }));
      this.startWorkers();
    });
  }

  startWorkers() {
    this.outboxInterval = setInterval(() => this.processOutbox(), 5000);

    const scheduleGossip = () => {
      const jitter = 12000 + Math.floor(Math.random() * 6000);
      this.gossipTimeout = setTimeout(async () => {
        await this.performRandomGossip();
        scheduleGossip();
      }, jitter);
    };
    scheduleGossip();

    this.presenceInterval = setInterval(() => this.broadcastPresence(), 10000);
  }

  handleIncoming(payload, channel, remotePeer) {
    // 1. Mesaj Dağıtımı (Timestamp-based TTL Deduplication)
    if (payload.type === 'DIRECT_MESSAGE' || payload.type === 'CHANNEL_MESSAGE') {
      if (this.seenMessages.has(payload.id)) {
        channel.writePayload({ status: 'duplicate', id: payload.id });
        return;
      }

      this.seenMessages.add(payload.id);

      if (payload.from && payload.from.startsWith('@')) {
        const existing = this.remoteOnlineUsers.get(payload.from) || { channels: [] };
        existing.lastSeen = Date.now();
        this.remoteOnlineUsers.set(payload.from, existing);
        this.emit('presence_change');

        const parsedSender = AddressHelper.parse(payload.from);
        if (parsedSender && !parsedSender.isLocal && parsedSender.host && parsedSender.port) {
          this.peerManager.addOrUpdate(`${parsedSender.host}:${parsedSender.port}`, true);
        }
      }

      const msg = this.db.saveMessage(payload);
      if (msg) {
        this.emit('message', msg);
        log.info(I18n.t('FED_MSG_RECEIVED', { from: msg.from, to: msg.to }));

        const hop = (payload.hop || 0) + 1;
        const ttl = payload.ttl || 5;

        if (payload.to.startsWith('#') && !payload.to.includes(':') && hop < ttl) {
          this.broadcastChannelMessage({ ...msg, hop, ttl }, remotePeer);
        } else if (this.channelSubscribers.has(payload.to)) {
          this.forwardToChannelSubscribers(payload.to, { ...msg, hop, ttl }, remotePeer);
        }
      }

      channel.writePayload({ status: 'delivered', id: payload.id });
    }

    // 2. Uzak Kanal Abonelikleri
    else if (payload.type === 'CHANNEL_SUBSCRIBE') {
      if (payload.channel && payload.subscriberNode) {
        if (!this.channelSubscribers.has(payload.channel)) {
          this.channelSubscribers.set(payload.channel, new Set());
        }
        this.channelSubscribers.get(payload.channel).add(payload.subscriberNode);
        log.info(I18n.t('FED_CHANNEL_SUBSCRIBED', { peer: payload.subscriberNode, channel: payload.channel }));
        this.peerManager.addOrUpdate(payload.subscriberNode, true);
        channel.writePayload({ status: 'subscribed', channel: payload.channel });
      }
    } else if (payload.type === 'CHANNEL_UNSUBSCRIBE') {
      if (payload.channel && payload.subscriberNode && this.channelSubscribers.has(payload.channel)) {
        this.channelSubscribers.get(payload.channel).delete(payload.subscriberNode);
        log.info(I18n.t('FED_CHANNEL_UNSUBSCRIBED', { peer: payload.subscriberNode, channel: payload.channel }));
        channel.writePayload({ status: 'unsubscribed', channel: payload.channel });
      }
    }

    // 3. Yazıyor (Typing), Presence & Gossip
    else if (payload.type === 'TYPING') {
      if (payload.from && payload.from.startsWith('@')) {
        const existing = this.remoteOnlineUsers.get(payload.from) || { channels: [] };
        existing.lastSeen = Date.now();
        this.remoteOnlineUsers.set(payload.from, existing);
      }
      this.emit('typing', payload);
    } else if (payload.type === 'PRESENCE_SYNC') {
      if (Array.isArray(payload.memberships)) {
        payload.memberships.forEach((m) => {
          if (m.user) {
            this.remoteOnlineUsers.set(m.user, {
              lastSeen: Date.now(),
              channels: m.channels || [],
              isSsh: !!m.isSsh,
              kemPublicKey: m.kemPublicKey || ''
            });
          }
        });
        this.emit('presence_change');
      }

      const myState = this.getLocalStateFn ? this.getLocalStateFn() : { memberships: [] };
      channel.writePayload({ type: 'PRESENCE_ACK', memberships: myState.memberships });
    } else if (payload.type === 'GOSSIP_DISCOVERY') {
      if (payload.selfNode && payload.selfNode.includes(':')) this.peerManager.addOrUpdate(payload.selfNode, true);
      if (Array.isArray(payload.peers)) {
        payload.peers.forEach((p) => {
          if (p && p.includes(':')) this.peerManager.addOrUpdate(p, true);
        });
      }

      channel.writePayload({
        type: 'GOSSIP_RESPONSE',
        selfNode: this.nodeAddress,
        peers: this.peerManager.getRandomSample(5)
      });
    }
  }

  forwardToChannelSubscribers(channelName, msg, exceptPeer = null) {
    const subscribers = this.channelSubscribers.get(channelName);
    if (!subscribers) return;

    const payload = {
      type: 'CHANNEL_MESSAGE',
      id: msg.id,
      from: msg.from,
      to: msg.to,
      content: msg.content,
      isAction: msg.isAction,
      isSnippet: msg.isSnippet,
      isE2EE: !!msg.isE2EE,
      hop: msg.hop || 0,
      ttl: msg.ttl || 5,
      timestamp: msg.timestamp
    };

    for (const peer of subscribers) {
      if (peer === exceptPeer || !peer.includes(':')) continue;
      const [host, portStr] = peer.split(':');
      const port = parseInt(portStr, 10);
      if (!host || isNaN(port)) continue;

      this.sendPacket(host, port, payload).catch(() => {});
    }
  }

  async subscribeRemoteChannel(host, port, channel) {
    try {
      await this.sendPacket(host, port, {
        type: 'CHANNEL_SUBSCRIBE',
        channel,
        subscriberNode: this.nodeAddress
      });
      this.peerManager.addOrUpdate(`${host}:${port}`, true);
    } catch {}
  }

  async unsubscribeRemoteChannel(host, port, channel) {
    try {
      await this.sendPacket(host, port, {
        type: 'CHANNEL_UNSUBSCRIBE',
        channel,
        subscriberNode: this.nodeAddress
      });
    } catch {}
  }

  getOrCreateSecureChannel(host, port) {
    if (!host || !port || host === 'null' || isNaN(port)) {
      return Promise.reject(new Error(`Invalid host or port: ${host}:${port}`));
    }

    const key = `${host}:${port}`;
    const existing = this.connectionPool.get(key);

    if (existing && !existing.socket.destroyed && existing.socket.writable) {
      if (existing.isReady) {
        return Promise.resolve(existing);
      }
      return new Promise((resolve) => existing.once('ready', () => resolve(existing)));
    }

    return new Promise((resolve, reject) => {
      log.debug(I18n.t('FED_CONNECTING', { host, port }));
      const rawSocket = net.createConnection({ host, port }, () => {
        rawSocket.setKeepAlive(true, 10000);
      });

      const secureChannel = new SecureChannel(rawSocket, true, this.myIdentity, this.db, this.nonceTracker);
      this.connectionPool.set(key, secureChannel);

      secureChannel.on('ready', () => {
        rawSocket.setTimeout(0);
        log.info(I18n.t('FED_CONNECTED', { host, port }));
        resolve(secureChannel);
      });

      secureChannel.on('error', (err) => {
        this.connectionPool.delete(key);
        reject(err);
      });

      secureChannel.on('close', () => {
        this.connectionPool.delete(key);
      });

      rawSocket.setTimeout(6000, () => {
        this.connectionPool.delete(key);
        rawSocket.destroy();
        reject(new Error('Secure Channel Timeout'));
      });
    });
  }

  async sendPacket(host, port, data) {
    const channel = await this.getOrCreateSecureChannel(host, port);
    return new Promise((resolve) => {
      const onPayload = (res) => {
        channel.off('payload', onPayload);
        resolve(res);
      };

      channel.once('payload', onPayload);
      channel.writePayload(data);

      setTimeout(() => {
        channel.off('payload', onPayload);
        resolve({ status: 'unacknowledged' });
      }, 3500);
    });
  }

  async broadcastPresence() {
    const peers = this.peerManager.getAllPeers();
    const myState = this.getLocalStateFn ? this.getLocalStateFn() : { memberships: [] };

    for (const peer of peers) {
      if (!peer || !peer.includes(':')) continue;
      const [host, portStr] = peer.split(':');
      const port = parseInt(portStr, 10);
      if (!host || isNaN(port)) continue;

      try {
        const res = await this.sendPacket(host, port, {
          type: 'PRESENCE_SYNC',
          memberships: myState.memberships
        });

        if (res && res.type === 'PRESENCE_ACK' && Array.isArray(res.memberships)) {
          res.memberships.forEach((m) => {
            if (m.user) {
              this.remoteOnlineUsers.set(m.user, {
                lastSeen: Date.now(),
                channels: m.channels || [],
                isSsh: !!m.isSsh,
                kemPublicKey: m.kemPublicKey || ''
              });
            }
          });
          this.emit('presence_change');
        }
      } catch {
        this.peerManager.addOrUpdate(peer, false);
      }
    }
  }

  async broadcastChannelMessage(msg, exceptPeer = null) {
    const peers = this.peerManager.getAllPeers();
    const payload = {
      type: 'CHANNEL_MESSAGE',
      id: msg.id,
      from: msg.from,
      to: msg.to,
      content: msg.content,
      isAction: msg.isAction,
      isSnippet: msg.isSnippet,
      isE2EE: !!msg.isE2EE,
      hop: msg.hop || 0,
      ttl: msg.ttl || 5,
      timestamp: msg.timestamp
    };

    for (const peer of peers) {
      if (!peer || peer === exceptPeer || !peer.includes(':')) continue;
      const [host, portStr] = peer.split(':');
      const port = parseInt(portStr, 10);
      if (!host || isNaN(port)) continue;

      this.sendPacket(host, port, payload).catch(() => {});
    }
  }

  async performRandomGossip() {
    const sample = this.peerManager.getRandomSample(3);
    for (const peer of sample) {
      if (!peer || !peer.includes(':')) continue;
      const [host, portStr] = peer.split(':');
      const port = parseInt(portStr, 10);
      if (!host || isNaN(port)) continue;

      try {
        const res = await this.sendPacket(host, port, {
          type: 'GOSSIP_DISCOVERY',
          selfNode: this.nodeAddress,
          peers: this.peerManager.getRandomSample(5)
        });

        if (res && res.type === 'GOSSIP_RESPONSE') {
          this.peerManager.addOrUpdate(peer, true);
          if (Array.isArray(res.peers)) {
            res.peers.forEach((p) => {
              if (p && p.includes(':')) this.peerManager.addOrUpdate(p, true);
            });
          }
        }
      } catch {
        this.peerManager.addOrUpdate(peer, false);
      }
    }
  }

  async processOutbox() {
    const pending = this.db.getPendingOutbox();
    for (const item of pending) {
      const target = AddressHelper.parse(item.to);
      if (!target || !target.host || !target.port) {
        this.db.removeOutbox(item.id);
        continue;
      }

      try {
        const payload = {
          type: target.type === 'CHANNEL' ? 'CHANNEL_MESSAGE' : 'DIRECT_MESSAGE',
          id: item.id,
          from: item.from,
          to: item.to,
          content: item.content,
          isAction: item.isAction,
          isSnippet: item.isSnippet,
          isE2EE: item.isE2EE,
          timestamp: item.timestamp
        };

        await this.sendPacket(target.host, target.port, payload);
        log.info(I18n.t('FED_OUTBOX_SENT', { id: item.id }));
        this.db.removeOutbox(item.id);
        this.peerManager.addOrUpdate(`${target.host}:${target.port}`, true);
      } catch {
        this.db.updateOutboxRetry(item.id);
        this.peerManager.addOrUpdate(`${target.host}:${target.port}`, false);
      }
    }
  }

  async sendRemoteMessage(from, to, content, isAction = false, isSnippet = false, isE2EE = false) {
    const target = AddressHelper.parse(to);
    if (!target) throw new Error(`Invalid target: ${to}`);

    const payload = {
      type: target.type === 'CHANNEL' ? 'CHANNEL_MESSAGE' : 'DIRECT_MESSAGE',
      id: `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      from,
      to: target.raw,
      content,
      isAction,
      isSnippet,
      isE2EE: !!isE2EE,
      hop: 0,
      ttl: 5,
      timestamp: new Date().toISOString()
    };

    this.seenMessages.add(payload.id);

    if (target.isGlobalChannel) {
      this.broadcastChannelMessage(payload);
      return { status: 'broadcasted' };
    }

    if (!target.host || !target.port) {
      return { status: 'ignored' };
    }

    try {
      const res = await this.sendPacket(target.host, target.port, payload);
      this.peerManager.addOrUpdate(`${target.host}:${target.port}`, true);
      return res;
    } catch (err) {
      log.warn(I18n.t('FED_OUTBOX_QUEUED', { to, error: err.message }));
      this.db.queueOutbox(payload);
      this.peerManager.addOrUpdate(`${target.host}:${target.port}`, false);
      return { status: 'queued' };
    }
  }

  async sendTyping(from, to) {
    const target = AddressHelper.parse(to);
    if (!target || target.isGlobalChannel || !target.host || !target.port) return;

    this.sendPacket(target.host, target.port, {
      type: 'TYPING',
      from,
      to: target.raw
    }).catch(() => {});
  }

  close() {
    if (this.outboxInterval) clearInterval(this.outboxInterval);
    if (this.presenceInterval) clearInterval(this.presenceInterval);
    if (this.gossipTimeout) clearTimeout(this.gossipTimeout);

    for (const channel of this.connectionPool.values()) {
      try {
        channel.socket.destroy();
      } catch {}
    }
    this.connectionPool.clear();

    if (this.server) {
      try {
        this.server.close();
      } catch {}
    }
    log.info(I18n.t('FED_CLOSED'));
  }
}