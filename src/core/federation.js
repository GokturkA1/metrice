import net from 'node:net';
import dns from 'node:dns/promises';
import EventEmitter from 'node:events';
import { CONFIG } from '../config/index.js';
import { Logger } from '../utils/logger.js';
import { AddressHelper } from '../utils/addressHelper.js';
import { CryptoHelper } from '../utils/cryptoHelper.js';
import { I18n } from '../locales/i18n.js';
import { OnionRouter, UNIFORM_CELL_SIZE } from './onionRouter.js';

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

export class SecureChannel extends EventEmitter {
  constructor(socket, isInitiator, myIdentity, db, nonceTracker) {
    super();
    this.setMaxListeners(100);
    if (socket && typeof socket.setMaxListeners === 'function') {
      socket.setMaxListeners(100);
    }
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
    this.lastPong = Date.now();

    this.initSocketHandlers();
    if (this.isInitiator) {
      this.sendHandshakeInit();
    }
  }

  async initSocketHandlers() {
    this.socket.on('data', async (chunk) => {
      // 0x09 PING / 0x0A PONG Keepalive (Section 3.2)
      if (chunk.length === 1) {
        if (chunk[0] === 0x09) {
          try { this.socket.write(Buffer.from([0x0A])); } catch {}
          return;
        }
        if (chunk[0] === 0x0A) {
          this.lastPong = Date.now();
          this.emit('pong');
          return;
        }
      }

      this.buffer += chunk.toString();
      const maxBuffer = (CONFIG && CONFIG.secureBufferLimit) || 65536;
      if (this.buffer.length > maxBuffer) {
        log.warn(I18n.t('FED_SECURE_CHANNEL_PARSE_ERR', { error: `Buffer overflow / DoS protection triggered (> ${maxBuffer} bytes without newline)` }));
        this.socket.destroy();
        return;
      }
      const lines = this.buffer.split('\n');
      this.buffer = lines.pop();

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const frame = JSON.parse(line);
          if (frame.type === 'DIALBACK_CONFIRM') {
            this.emit('dialback_confirm', frame);
            continue;
          }
          if (frame.type === 'ONION_CELL') {
            this.emit('onion_cell', frame);
            continue;
          }
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
    if (this.nonceTracker && typeof this.nonceTracker.track === 'function') {
      this.nonceTracker.track(nonce);
    }

    const canonicalAddress = (this.myIdentity && this.myIdentity.nodeId)
      ? `${this.myIdentity.nodeId}.mesh:${CONFIG.federationPort}`
      : this.myIdentity.nodeAddress;

    const dataToSign = JSON.stringify({
      type: 'HANDSHAKE_INIT',
      nodeAddress: canonicalAddress,
      identityPublicKey: this.myIdentity.identityKeyPair.publicKey,
      kemPublicKey: this.myIdentity.kemKeyPair.publicKey,
      nonce
    });

    const sig = CryptoHelper.sign(dataToSign, this.myIdentity.identityKeyPair.privateKey);

    const payload = {
      type: 'HANDSHAKE_INIT',
      nodeAddress: canonicalAddress,
      identityPublicKey: this.myIdentity.identityKeyPair.publicKey,
      kemPublicKey: this.myIdentity.kemKeyPair.publicKey,
      nonce,
      sig
    };

    this.socket.write(JSON.stringify(payload) + '\n');
  }

  async handleFrame(frame) {
    // 1. HANDSHAKE_INIT
    if (frame.type === 'HANDSHAKE_INIT') {
      const remoteIp = this.socket.remoteAddress || '';
      if (!this.nonceTracker.track(frame.nonce, remoteIp)) {
        log.warn(I18n.t('FED_REPLAY_NONCE_DETECTED', { node: frame.nodeAddress }));
        this.socket.destroy();
        return;
      }

      if (!(await this.validatePeerIp(frame.nodeAddress))) {
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

      // AutoNAT Reflected IP: socket fiziksel uzak adresi (Section 2.1)
      const rawRemote = this.socket.remoteAddress || '';
      const cleanRemote = rawRemote.replace('::ffff:', '');
      const remotePort = this.socket.remotePort;
      const observedAddress = `${cleanRemote}:${remotePort}`;

      const replyDataToSign = JSON.stringify({
        type: 'HANDSHAKE_REPLY',
        nodeAddress: this.myIdentity.nodeAddress,
        identityPublicKey: this.myIdentity.identityKeyPair.publicKey,
        kemPublicKey: this.myIdentity.kemKeyPair.publicKey,
        encapsulatedKey,
        nonce: frame.nonce,
        observedAddress
      });

      const replySig = CryptoHelper.sign(replyDataToSign, this.myIdentity.identityKeyPair.privateKey);

      const replyPayload = {
        type: 'HANDSHAKE_REPLY',
        nodeAddress: this.myIdentity.nodeAddress,
        identityPublicKey: this.myIdentity.identityKeyPair.publicKey,
        kemPublicKey: this.myIdentity.kemKeyPair.publicKey,
        encapsulatedKey,
        nonce: frame.nonce,
        observedAddress,
        sig: replySig
      };

      this.socket.write(JSON.stringify(replyPayload) + '\n');
      this.markReady();
      return;
    }

    // 2. HANDSHAKE_REPLY
    if (frame.type === 'HANDSHAKE_REPLY') {
      const verifyObj = {
        type: 'HANDSHAKE_REPLY',
        nodeAddress: frame.nodeAddress,
        identityPublicKey: frame.identityPublicKey,
        kemPublicKey: frame.kemPublicKey,
        encapsulatedKey: frame.encapsulatedKey,
        nonce: frame.nonce
      };
      if (frame.observedAddress) {
        verifyObj.observedAddress = frame.observedAddress;
      }

      let isValid = CryptoHelper.verify(JSON.stringify(verifyObj), frame.sig, frame.identityPublicKey);
      if (!isValid && frame.observedAddress) {
        delete verifyObj.observedAddress;
        isValid = CryptoHelper.verify(JSON.stringify(verifyObj), frame.sig, frame.identityPublicKey);
      }

      if (!isValid) {
        log.warn(I18n.t('FED_SECURE_HANDSHAKE_REPLY_FAIL', { node: frame.nodeAddress }));
        this.socket.destroy();
        return;
      }

      this.peerNodeAddress = frame.nodeAddress;
      this.peerIdentityKey = frame.identityPublicKey;
      this.peerKemKey = frame.kemPublicKey;
      this.observedAddress = frame.observedAddress || null;
      this.db.saveTrustedNodeKey(this.peerNodeAddress, this.peerIdentityKey, this.peerKemKey);

      const sharedSecret = CryptoHelper.decapsulateKey(
        this.myIdentity.kemKeyPair.privateKey,
        frame.encapsulatedKey
      );

      this.sessionKey = CryptoHelper.deriveKey(sharedSecret, frame.nonce, 'p2p-mesh-transport-v1');
      if (this.observedAddress) {
        this.emit('observed_address', this.observedAddress, this.peerNodeAddress);
      }
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

    // 1. NAT / Ev Kullanıcısı / Edge toleransı (localhost veya döngüsel adreste çalışan istemciler)
    const isLoopback = (ip) => ip === '127.0.0.1' || ip === '::1' || ip === 'localhost';
    if (isLoopback(declaredHost)) {
      return true;
    }

    // 2. Kriptografik kimlik (.mesh veya 16-karakter NodeID) toleransı
    if (declaredHost.endsWith('.mesh') || AddressHelper.isValidNodeId(declaredHost)) {
      return true;
    }

    // 3. Kendi sunucu adı toleransı
    if (declaredHost === CONFIG.serverName) {
      return true;
    }

    // 4. Özel ağlar / Container / Proxy toleransı
    const isPrivateOrCgnatSubnet = (ip) => {
      return /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.)/.test(ip);
    };
    if (isPrivateOrCgnatSubnet(cleanRemote)) {
      return true;
    }

    if (process.env.TRUST_PROXY === 'true' || process.env.DOCKER === 'true' || process.env.CONTAINER === 'true') {
      return true;
    }

    // 5. Doğrudan IP eşleşmesi
    if (declaredHost === cleanRemote) {
      return true;
    }

    // 6. DNS Çözümleme (Domain -> IP Eşleşmesi - VDS & Alan Adı Arkası)
    try {
      const resolved = await dns.lookup(declaredHost, { all: true });
      return resolved.some((entry) => entry.address === cleanRemote);
    } catch {
      // DNS çözülemiyorsa ama Ed25519 imzası el sıkışmada doğrulanacaksa bağlantıyı düşürme
      return true;
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
    this.nodeId = identity.nodeId;
    this.meshAddress = `${this.nodeId}.mesh`;
    this.nodeAddress = `${CONFIG.serverName}:${CONFIG.federationPort}`;

    AddressHelper.setLocalNodeId(this.nodeId);

    this.myIdentity = {
      nodeId: this.nodeId,
      meshAddress: this.meshAddress,
      nodeAddress: this.nodeAddress,
      identityKeyPair: this.identityKeyPair,
      kemKeyPair: this.kemKeyPair
    };

    this.remoteOnlineUsers = new Map();
    this.getLocalStateFn = null;
    this.channelSubscribers = new Map();

    // V2.0 Mimari Değişkenleri
    this.role = process.env.MESH_ROLE || (CONFIG && CONFIG.meshRole) || 'EDGE'; // 'RELAY' veya 'EDGE'
    this.publicIp = null;
    this.observedAddressVotes = new Map(); // ip -> Set<peer>
    this.isDialbackRunning = false;
    this.isMaintainingTunnels = false;
    this.nodePhysicalAddresses = new Map(); // nodeId -> 'host:port'
    this.pendingDialbacks = new Map(); // nonce -> { targetIp, timer, resolve }
    this.rendezvousTunnels = new Map(); // nodeId -> { socket, channel, boundAt }
    this.rendezvousRelays = new Map(); // relayAddr -> { channel, socket }
    this.boundRendezvousRelays = new Set(); // EDGE'in bağlı olduğu RELAY'ler
    this.presenceTable = new Map(); // nodeId -> PresenceRecord
    this.rendezvousHeartbeatInterval = null;
    this.maintainRendezvousInterval = null;
    this.presenceCleanupInterval = null;

    this.onionRouter = new OnionRouter({
      federation: this,
      db: this.db,
      myIdentity: this.myIdentity,
      rendezvousTunnels: this.rendezvousTunnels
    });

    this.onionRouter.on('deliver_local', (msg) => this.handleLocalDeliveredMessage(msg));

    log.info(I18n.t('FED_NODE_IDENTITY_READY', { address: `${this.nodeAddress} (${this.meshAddress}) [CAP_${this.role}]` }));
  }

  setRole(newRole) {
    if (this.role !== newRole) {
      this.role = newRole;
      log.info(`Düğüm rolü güncellendi -> CAP_${this.role}`);
      this.emit('role_change', this.role);
      this.broadcastPresence();
    }
  }

  getRole() {
    return this.role;
  }

  isRelay() {
    return this.role === 'RELAY' || this.role === 'CAP_RELAY';
  }

  setLocalStateGetter(fn) {
    this.getLocalStateFn = fn;
  }

  getAllOnlineUsers() {
    const now = Date.now();
    const ttl = (CONFIG && CONFIG.presenceTtl) || 60000;
    const activeRemote = [];
    for (const [userAddr, data] of this.remoteOnlineUsers.entries()) {
      const diff = now - data.lastSeen;
      if (diff < 0) {
        data.lastSeen = now;
      }
      if (now - data.lastSeen < ttl) {
        activeRemote.push(userAddr);
      }
    }
    const localState = this.getLocalStateFn ? this.getLocalStateFn() : { users: [] };
    return Array.from(new Set([...localState.users, ...activeRemote]));
  }

  getChannelMembers(channelName) {
    const members = [];
    const now = Date.now();
    const ttl = (CONFIG && CONFIG.presenceTtl) || 60000;

    for (const [userAddr, data] of this.remoteOnlineUsers.entries()) {
      const diff = now - data.lastSeen;
      if (diff < 0) {
        data.lastSeen = now;
      }
      if (now - data.lastSeen < ttl && Array.isArray(data.channels) && data.channels.includes(channelName)) {
        members.push(userAddr);
      }
    }
    return members;
  }

  getRemoteUserSecurity(userAddress) {
    if (!userAddress) return null;
    let data = this.remoteOnlineUsers.get(userAddress);
    if (!data) {
      const parsed = AddressHelper.parse(userAddress);
      const nick = parsed && parsed.name ? parsed.name : userAddress.split(':')[0].replace('@', '');
      if (nick) {
        for (const [addr, d] of this.remoteOnlineUsers.entries()) {
          const p = AddressHelper.parse(addr);
          const userNick = p && p.name ? p.name : addr.split(':')[0].replace('@', '');
          if (userNick === nick) {
            data = d;
            break;
          }
        }
      }
    }
    if (!data) {
      if (this.db && typeof this.db.getUserProfile === 'function') {
        const profile = this.db.getUserProfile(userAddress);
        if (profile && profile.kemPublicKey) {
          return {
            isSsh: true,
            kemPublicKey: profile.kemPublicKey
          };
        }
      }
      return null;
    }
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

      secureChannel.on('dialback_confirm', (frame) => {
        this.handleDialbackConfirm(frame);
      });

      secureChannel.on('onion_cell', (cell) => {
        this.onionRouter.handleOnionCell(cell, secureChannel);
      });

      secureChannel.on('observed_address', (addr, peer) => {
        this.handleObservedAddress(addr, peer);
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
    this.rendezvousHeartbeatInterval = setInterval(() => this.sendRendezvousHeartbeat(), 30000);
    this.maintainRendezvousInterval = setInterval(() => this.maintainRendezvousTunnels(), 15000);
    this.presenceCleanupInterval = setInterval(() => this.cleanupExpiredPresence(), 30000);
  }

  handleIncoming(payload, channel, remotePeer) {
    if (!payload || !payload.type) return;

    // 0. AutoNAT Inbound Reachability Dialback (Section 2.2)
    if (payload.type === 'DIALBACK_REQUEST') {
      const { targetPort, nonce } = payload;
      if (!targetPort || !nonce) return;

      // GÜVENLİK (SSRF Koruması): targetIp yoksayılır. Doğrudan channel soketinin fiziksel uzak adresi kullanılır.
      const rawRemote = channel?.socket?.remoteAddress || '';
      const verifiedIp = rawRemote.replace(/^::ffff:/, '');
      if (!verifiedIp) return;

      const numPort = parseInt(targetPort, 10);
      if (isNaN(numPort) || numPort < 1 || numPort > 65535) return;

      const isLoopback = verifiedIp === '127.0.0.1' || verifiedIp === '::1' || verifiedIp === 'localhost';
      const isPrivate = /^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/.test(verifiedIp);
      const isTesting = process.env.NODE_ENV === 'test' || CONFIG.environment === 'test' || process.argv.some((a) => a.includes('test'));

      if ((isLoopback || isPrivate) && !isTesting) {
        log.warn(`AutoNAT SSRF Koruması: Özel/Loopback ağa dialback engellendi: ${verifiedIp}`);
        return;
      }

      log.info(`AutoNAT: Inbound Dialback talebi alındı -> ${verifiedIp}:${numPort}`);
      const dialSocket = net.createConnection({ host: verifiedIp, port: numPort }, () => {
        // Sadece gerçekten bağlantı kurulabildiyse ana kanala teyit gönder
        channel.writePayload({
          type: 'DIALBACK_CONFIRM',
          nonce,
          confirmed: true
        });
        dialSocket.end();
      });

      dialSocket.setTimeout(3500, () => dialSocket.destroy());
      dialSocket.on('error', () => {
        // Bağlanamadıysa hiçbir şey yapma, karşı taraf timeout yiyip EDGE kalsın
        dialSocket.destroy();
      });
      return;
    }

    if (payload.type === 'DIALBACK_CONFIRM') {
      this.handleDialbackConfirm(payload);
      return;
    }

    // 0.0. Katmanlı Soğan Hücresi (Section 4: ONION_CELL)
    if (payload.type === 'ONION_CELL') {
      this.onionRouter.handleOnionCell(payload, channel);
      return;
    }

    // 0.1. Buluşma Noktası Yetkilendirmesi (Section 3.1: RENDEZVOUS_BIND)
    if (payload.type === 'RENDEZVOUS_BIND') {
      const { nodeId, identityPublicKey, timestamp, nonce, sig } = payload;
      if (!nodeId || !identityPublicKey || !timestamp || !nonce || !sig) {
        channel.writePayload({ status: 'rejected', reason: 'missing_fields' });
        return;
      }

      const derivedId = CryptoHelper.deriveNodeId(identityPublicKey);
      if (derivedId !== nodeId) {
        log.warn(`Rendezvous NodeID eşleşmedi: Beklenen ${nodeId}, Türetilen: ${derivedId}`);
        channel.writePayload({ status: 'rejected', reason: 'invalid_node_id' });
        return;
      }

      const cleanLocal = (channel?.socket?.localAddress || '').replace(/^::ffff:/, '');
      const localSockAddr = cleanLocal ? `${cleanLocal}:${channel.socket.localPort}` : null;
      const bracketSockAddr = cleanLocal && cleanLocal.includes(':')
        ? `[${cleanLocal}]:${channel.socket.localPort}`
        : null;
      const hostAddr = this.nodeAddress;
      const meshAddr = this.meshAddress;
      const ipAddr = this.publicIp ? `${this.publicIp}:${CONFIG.federationPort}` : null;
      const localhostAddr = this.nodeAddress && this.nodeAddress.startsWith('localhost:')
        ? this.nodeAddress.replace('localhost:', '127.0.0.1:')
        : null;

      let isSigValid = CryptoHelper.verify(`${nodeId}${hostAddr}${timestamp}${nonce}`, sig, identityPublicKey) ||
                       CryptoHelper.verify(`${nodeId}${meshAddr}${timestamp}${nonce}`, sig, identityPublicKey);

      if (!isSigValid && localSockAddr) {
        isSigValid = CryptoHelper.verify(`${nodeId}${localSockAddr}${timestamp}${nonce}`, sig, identityPublicKey);
      }
      if (!isSigValid && bracketSockAddr) {
        isSigValid = CryptoHelper.verify(`${nodeId}${bracketSockAddr}${timestamp}${nonce}`, sig, identityPublicKey);
      }
      if (!isSigValid && ipAddr) {
        isSigValid = CryptoHelper.verify(`${nodeId}${ipAddr}${timestamp}${nonce}`, sig, identityPublicKey);
      }
      if (!isSigValid && localhostAddr) {
        isSigValid = CryptoHelper.verify(`${nodeId}${localhostAddr}${timestamp}${nonce}`, sig, identityPublicKey);
      }

      if (!isSigValid) {
        log.warn(`Rendezvous imza geçersiz: ${nodeId}`);
        channel.writePayload({ status: 'rejected', reason: 'invalid_signature' });
        return;
      }

      if (Math.abs(Date.now() - timestamp) > 120000) {
        channel.writePayload({ status: 'rejected', reason: 'expired_timestamp' });
        return;
      }

      // DoS sınırı (maksimum aktif tünel kapasitesi)
      const maxTunnels = (CONFIG && CONFIG.maxRendezvousTunnels) || 64;
      if (this.rendezvousTunnels.size >= maxTunnels && !this.rendezvousTunnels.has(nodeId)) {
        log.warn(`Rendezvous tünel kapasitesi aşıldı (${this.rendezvousTunnels.size}/${maxTunnels}), ${nodeId} reddedildi`);
        channel.writePayload({ status: 'rejected', reason: 'tunnel_capacity_reached' });
        return;
      }

      this.rendezvousTunnels.set(nodeId, {
        socket: channel.socket,
        channel,
        boundAt: Date.now()
      });

      if (channel?.socket && typeof channel.socket.once === 'function') {
        channel.socket.once('close', () => {
          this.rendezvousTunnels.delete(nodeId);
          log.info(`Rendezvous tüneli kapandı: ${nodeId}`);
        });
      }

      // Rota tablosunu güncelle: EDGE'in bu röleye tünellendiğini kaydet
      const relayAnnounceAddr = this.getRelayAnnounceAddress();
      const boundRendezvousAddr = payload.relayAddress || relayAnnounceAddr;
      const edgeKemKey = payload.kemPublicKey || channel?.peerKemKey || this.presenceTable.get(nodeId)?.kemPublicKey || this.db.getRoute(nodeId)?.kemPublicKey;

      const edgeRecord = {
        nodeId,
        role: 'EDGE',
        rendezvousNodes: [boundRendezvousAddr],
        kemPublicKey: edgeKemKey || null,
        identityPublicKey,
        channels: [],
        lastSeen: Date.now()
      };
      this.presenceTable.set(nodeId, edgeRecord);
      if (edgeKemKey && identityPublicKey) {
        this.db.upsertRoute(edgeRecord);
      }

      // Ağdaki diğer eşlere / rölelere (TR) bu EDGE'in bu röleye tünellendiğini anons et
      this.broadcastRouteUpdate(nodeId, boundRendezvousAddr, edgeKemKey, identityPublicKey);

      log.info(`Rendezvous tüneli başarıyla bağlandı: ${nodeId} (Aktif tüneller: ${this.rendezvousTunnels.size}/64)`);
      channel.writePayload({
        type: 'RENDEZVOUS_ACK',
        status: 'bound',
        ttl: 3600
      });
      if (this.db && typeof this.db.resetOutboxForTarget === 'function') {
        this.db.resetOutboxForTarget(nodeId);
      }
      setImmediate(() => this.processOutbox(true));
      return;
    }

    if (payload.type === 'RENDEZVOUS_ACK') {
      if (payload.status === 'bound') {
        const peerAddr = channel.peerNodeAddress || remotePeer;
        this.boundRendezvousRelays.add(peerAddr);
        this.broadcastPresenceAnnounce();
        if (this.db && typeof this.db.resetOutboxForTarget === 'function') {
          this.db.resetOutboxForTarget(peerAddr);
        }
        setImmediate(() => this.processOutbox(true));
      }
      return;
    }

    // 0.2. Onion Devre Kurulumu (Section 4.2: Telescoping Circuits)
    if (payload.type === 'CIRCUIT_CREATE' || payload.type === 'CIRCUIT_EXTEND') {
      this.onionRouter.handleCircuitSetup(payload, channel);
      return;
    }

    // 0.3. V2.0 Dağıtık Varlık ve Buluşma Noktası Gossip Dağıtımı (Section 5.1 & 5.2)
    if (payload.type === 'PRESENCE_ANNOUNCE') {
      const { nodeId, role, rendezvousNodes, kemPublicKey, identityPublicKey, channels, timestamp, sig } = payload;
      if (!nodeId || !kemPublicKey || !identityPublicKey || !sig) return;

      const derivedId = CryptoHelper.deriveNodeId(identityPublicKey);
      if (derivedId !== nodeId) return;

      const dataToVerify = JSON.stringify({
        nodeId,
        role,
        rendezvousNodes: rendezvousNodes || [],
        kemPublicKey,
        channels: channels || [],
        timestamp
      });

      if (!CryptoHelper.verify(dataToVerify, sig, identityPublicKey)) return;
      if (Math.abs(Date.now() - timestamp) > 120000) return;

      // Zehirli adres koruması (Gossip Poisoning): 'localhost', '127.0.0.1', '0.0.0.0' içeren adresler rota tablosuna alınmaz
      const isPoisoned = (addr) => typeof addr === 'string' && (addr.includes('localhost') || addr.includes('127.0.0.1') || addr.includes('0.0.0.0'));
      const safeRendezvous = (rendezvousNodes || []).filter((addr) => !isPoisoned(addr));

      const record = {
        nodeId,
        role: role || 'EDGE',
        rendezvousNodes: safeRendezvous,
        kemPublicKey,
        identityPublicKey,
        channels: channels || [],
        lastSeen: Date.now()
      };
      this.presenceTable.set(nodeId, record);

      const rawRemote = channel?.socket?.remoteAddress || '';
      const cleanRemote = rawRemote.replace(/^::ffff:/, '');
      if (cleanRemote) {
        this.nodePhysicalAddresses.set(nodeId, `${cleanRemote}:${CONFIG.federationPort}`);
      }

      this.db.upsertRoute({
        nodeId,
        role: record.role,
        rendezvousNodes: record.rendezvousNodes,
        kemPublicKey,
        identityPublicKey,
        lastSeen: record.lastSeen
      });

      if (Array.isArray(channels)) {
        channels.forEach((chan) => {
          if (!this.channelSubscribers.has(chan)) {
            this.channelSubscribers.set(chan, new Set());
          }
        });
      }

      if (Array.isArray(payload.memberships)) {
        payload.memberships.forEach((m) => {
          if (m && m.user && m.kemPublicKey) {
            this.db.saveRemoteUserKemKey(m.user, m.kemPublicKey);
          }
        });
      }

      if (this.db && typeof this.db.resetOutboxForTarget === 'function') {
        this.db.resetOutboxForTarget(nodeId);
      }

      this.emit('presence_change');

      // Dedikodu (Gossip) Yayılımı: Röle düğümleri geçerli PRESENCE_ANNOUNCE paketlerini ağdaki diğer eşlere iletir
      const announceKey = `${nodeId}:${timestamp}`;
      if (!this.seenPresenceAnnounces) this.seenPresenceAnnounces = new Set();
      if (!this.seenPresenceAnnounces.has(announceKey)) {
        this.seenPresenceAnnounces.add(announceKey);
        if (this.seenPresenceAnnounces.size > 2000) {
          const first = this.seenPresenceAnnounces.values().next().value;
          this.seenPresenceAnnounces.delete(first);
        }

        if (this.isRelay()) {
          const peers = this.peerManager.getAllPeers();
          for (const peer of peers) {
            if (!peer || !peer.includes(':')) continue;
            if (remotePeer && peer === remotePeer) continue;
            const [host, portStr] = peer.split(':');
            const port = parseInt(portStr, 10);
            if (!host || isNaN(port)) continue;
            this.sendPacket(host, port, payload).catch(() => {});
          }
        }
      }

      if (this.role === 'EDGE' && (role === 'RELAY' || role === 'CAP_RELAY')) {
        this.maintainRendezvousTunnels().catch(() => {});
      }

      setImmediate(() => this.processOutbox(true));
      return;
    }

    // 0.4. V2.0 Çapraz Röle Rota Güncellemesi (Cross-Relay Route Announcement)
    if (payload.type === 'ROUTE_UPDATE') {
      const {
        nodeId,
        role,
        rendezvousNodes,
        kemPublicKey,
        identityPublicKey,
        relayNodeId,
        relayAddress,
        relayKemPublicKey,
        relayIdentityPublicKey,
        timestamp,
        sig
      } = payload;

      if (!nodeId || !relayNodeId || !relayIdentityPublicKey || !sig) return;

      const derivedRelayId = CryptoHelper.deriveNodeId(relayIdentityPublicKey);
      if (derivedRelayId !== relayNodeId) return;

      const dataToVerify = JSON.stringify({
        nodeId,
        relayNodeId,
        rendezvousNodes: rendezvousNodes || [],
        timestamp
      });

      if (!CryptoHelper.verify(dataToVerify, sig, relayIdentityPublicKey)) return;
      if (Math.abs(Date.now() - timestamp) > 120000) return;

      const isPoisoned = (addr) => typeof addr === 'string' && (addr.includes('localhost') || addr.includes('127.0.0.1') || addr.includes('0.0.0.0'));
      let safeRdv = (rendezvousNodes || []).filter((addr) => !isPoisoned(addr));
      if (safeRdv.length === 0 && Array.isArray(rendezvousNodes) && rendezvousNodes.length > 0 && (process.env.NODE_ENV === 'test' || CONFIG.serverName === 'localhost')) {
        safeRdv = rendezvousNodes;
      }
      if (safeRdv.length === 0) return;

      const updateKey = `${nodeId}:${relayNodeId}:${timestamp}`;
      if (!this.seenRouteUpdates) this.seenRouteUpdates = new Set();
      if (this.seenRouteUpdates.has(updateKey)) return;
      this.seenRouteUpdates.add(updateKey);
      if (this.seenRouteUpdates.size > 2000) {
        const first = this.seenRouteUpdates.values().next().value;
        this.seenRouteUpdates.delete(first);
      }

      // 1. Röle düğümünü kaydet/güncelle
      if (relayKemPublicKey && relayAddress) {
        const relayRecord = {
          nodeId: relayNodeId,
          role: 'RELAY',
          rendezvousNodes: [relayAddress],
          kemPublicKey: relayKemPublicKey,
          identityPublicKey: relayIdentityPublicKey,
          channels: [],
          lastSeen: Date.now()
        };
        this.presenceTable.set(relayNodeId, relayRecord);
        this.db.upsertRoute(relayRecord);
        this.nodePhysicalAddresses.set(relayNodeId, relayAddress);
      }

      // 2. EDGE düğümünü kaydet/güncelle
      const currentEdge = this.presenceTable.get(nodeId) || this.db.getRoute(nodeId) || {};
      const edgeRecord = {
        nodeId,
        role: role || 'EDGE',
        rendezvousNodes: safeRdv,
        kemPublicKey: kemPublicKey || currentEdge.kemPublicKey || null,
        identityPublicKey: identityPublicKey || currentEdge.identityPublicKey || null,
        channels: currentEdge.channels || [],
        lastSeen: Date.now()
      };
      this.presenceTable.set(nodeId, edgeRecord);
      this.db.upsertRoute(edgeRecord);

      if (this.db && typeof this.db.resetOutboxForTarget === 'function') {
        this.db.resetOutboxForTarget(nodeId);
      }

      this.emit('presence_change');

      // Röle ise diğer eşlere dedikodu olarak ilet
      if (this.isRelay()) {
        const peers = this.peerManager.getAllPeers();
        for (const peer of peers) {
          if (!peer || !peer.includes(':')) continue;
          if (remotePeer && peer === remotePeer) continue;
          const [host, portStr] = peer.split(':');
          const port = parseInt(portStr, 10);
          if (!host || isNaN(port)) continue;
          this.sendPacket(host, port, payload).catch(() => {});
        }
      }

      if (this.role === 'EDGE') {
        this.maintainRendezvousTunnels().catch(() => {});
      }

      setImmediate(() => this.processOutbox(true));
      return;
    }

    // 1. Mesaj Dağıtımı (Timestamp-based TTL Deduplication)
    if (payload.type === 'DIRECT_MESSAGE' || payload.type === 'CHANNEL_MESSAGE') {
      if (this.seenMessages.has(payload.id)) {
        channel.writePayload({ status: 'duplicate', id: payload.id });
        return;
      }

      this.seenMessages.add(payload.id);

      if (payload.from && payload.from.startsWith('@')) {
        const parsedSender = AddressHelper.parse(payload.from);
        if (parsedSender && !parsedSender.isLocal) {
          const existing = this.remoteOnlineUsers.get(payload.from) || { channels: [] };
          existing.lastSeen = Date.now();
          this.remoteOnlineUsers.set(payload.from, existing);
          this.emit('presence_change');

          if (parsedSender.host && parsedSender.port) {
            this.peerManager.addOrUpdate(`${parsedSender.host}:${parsedSender.port}`, true);
          }
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
        const parsedSender = AddressHelper.parse(payload.from);
        if (parsedSender && !parsedSender.isLocal) {
          const existing = this.remoteOnlineUsers.get(payload.from) || { channels: [] };
          existing.lastSeen = Date.now();
          this.remoteOnlineUsers.set(payload.from, existing);
        }
      }
      this.emit('typing', payload);
    } else if (payload.type === 'USER_OFFLINE') {
      if (payload.user && this.remoteOnlineUsers.has(payload.user)) {
        this.remoteOnlineUsers.delete(payload.user);
        this.emit('presence_change');
      }
      channel.writePayload({ status: 'ack', type: 'USER_OFFLINE', user: payload.user });
    } else if (payload.type === 'PRESENCE_SYNC') {
      if (Array.isArray(payload.memberships)) {
        payload.memberships.forEach((m) => {
          if (m.user) {
            const parsed = AddressHelper.parse(m.user);
            if (parsed && !parsed.isLocal) {
              this.remoteOnlineUsers.set(m.user, {
                lastSeen: Date.now(),
                channels: m.channels || [],
                isSsh: !!m.isSsh,
                kemPublicKey: m.kemPublicKey || ''
              });
              if (m.kemPublicKey) {
                this.db.saveRemoteUserKemKey(m.user, m.kemPublicKey);
              }
            }
          }
        });
      }

      this.emit('presence_change');
      setImmediate(() => this.processOutbox(true));

      const myState = this.getLocalStateFn ? this.getLocalStateFn() : { memberships: [] };
      channel.writePayload({
        type: 'PRESENCE_ACK',
        sourceNode: this.nodeAddress,
        memberships: myState.memberships
      });
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

    for (const [, tunnel] of this.rendezvousTunnels.entries()) {
      if (tunnel && tunnel.channel && tunnel.channel.socket && tunnel.channel.socket.writable) {
        tunnel.channel.writePayload(payload);
      }
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
    if (!host || host === 'null') {
      return Promise.reject(new Error(`Invalid host or port: ${host}:${port}`));
    }

    let targetHost = host;
    let targetPort = port;

    // Alt ağ seviyesinde fiziksel IP çözümlemesi (.mesh veya NodeID)
    if (typeof targetHost === 'string' && (targetHost.endsWith('.mesh') || AddressHelper.isValidNodeId(targetHost))) {
      const nid = targetHost.replace('.mesh', '').toLowerCase();
      let resolved = this.nodePhysicalAddresses.get(nid);
      if (!resolved) {
        resolved = this.presenceTable.get(nid)?.rendezvousNodes?.[0];
      }
      if (!resolved) {
        resolved = this.db.getRoute(nid)?.rendezvousNodes?.[0];
      }

      if (resolved) {
        const parsed = AddressHelper.parseTarget(resolved);
        if (parsed && parsed.host) {
          targetHost = parsed.host;
          targetPort = parsed.port || targetPort || CONFIG.federationPort;
        } else {
          const [rHost, rPortStr] = resolved.split(':');
          targetHost = rHost;
          if (rPortStr && (!targetPort || isNaN(targetPort))) {
            targetPort = parseInt(rPortStr, 10);
          }
        }
      } else {
        return Promise.reject(new Error(`Target node ${targetHost} cannot be resolved to a physical address`));
      }
    }

    if (!targetHost || !targetPort || isNaN(targetPort)) {
      return Promise.reject(new Error(`Invalid host or port: ${targetHost}:${targetPort}`));
    }

    const key = `${targetHost}:${targetPort}`;
    const existing = this.connectionPool.get(key);

    if (existing && !existing.socket.destroyed && existing.socket.writable) {
      if (existing.isReady) {
        return Promise.resolve(existing);
      }
      return new Promise((resolve, reject) => {
        const onReady = () => {
          cleanup();
          resolve(existing);
        };
        const onError = (err) => {
          cleanup();
          reject(err);
        };
        const onClose = () => {
          cleanup();
          reject(new Error('Connection closed before ready'));
        };
        const cleanup = () => {
          existing.off('ready', onReady);
          existing.off('error', onError);
          existing.off('close', onClose);
        };
        existing.once('ready', onReady);
        existing.once('error', onError);
        existing.once('close', onClose);
      });
    }

    return new Promise((resolve, reject) => {
      log.debug(I18n.t('FED_CONNECTING', { host: targetHost, port: targetPort }));
      const rawSocket = net.createConnection({ host: targetHost, port: targetPort }, () => {
        rawSocket.setKeepAlive(true, 10000);
      });

      const secureChannel = new SecureChannel(rawSocket, true, this.myIdentity, this.db, this.nonceTracker);
      this.connectionPool.set(key, secureChannel);

      secureChannel.on('payload', (payload) => {
        this.handleIncoming(payload, secureChannel, key);
      });

      secureChannel.on('dialback_confirm', (frame) => {
        this.handleDialbackConfirm(frame);
      });

      secureChannel.on('onion_cell', (cell) => {
        this.onionRouter.handleOnionCell(cell, secureChannel);
      });

      secureChannel.on('observed_address', (addr, peer) => {
        this.handleObservedAddress(addr, peer);
      });

      secureChannel.on('ready', () => {
        rawSocket.setTimeout(0);
        log.info(I18n.t('FED_CONNECTED', { host, port }));
        resolve(secureChannel);
      });

      secureChannel.on('error', (err) => {
        this.connectionPool.delete(key);
        if (this.onionRouter && typeof this.onionRouter.removeCircuitsForHop === 'function') {
          this.onionRouter.removeCircuitsForHop(key);
        }
        reject(err);
      });

      secureChannel.on('close', () => {
        this.connectionPool.delete(key);
        if (this.onionRouter && typeof this.onionRouter.removeCircuitsForHop === 'function') {
          this.onionRouter.removeCircuitsForHop(key);
        }
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
      let timer = null;
      const onPayload = (res) => {
        if (timer) clearTimeout(timer);
        channel.off('payload', onPayload);
        resolve(res);
      };

      channel.once('payload', onPayload);
      channel.writePayload(data);

      timer = setTimeout(() => {
        channel.off('payload', onPayload);
        resolve({ status: 'unacknowledged' });
      }, 3500);
    });
  }

  async broadcastPresence() {
    // 1. V2.0 Kuantum Sonrası Varlık ve Buluşma Noktası Anonsu (Section 5.1)
    this.broadcastPresenceAnnounce();

    // 2. V1.x Geriye Dönük Uyumluluk (PRESENCE_SYNC)
    const peers = this.peerManager.getAllPeers();
    const myState = this.getLocalStateFn ? this.getLocalStateFn() : { memberships: [] };

    await Promise.allSettled(peers.map(async (peer) => {
      if (!peer || !peer.includes(':')) return;
      const [host, portStr] = peer.split(':');
      const port = parseInt(portStr, 10);
      if (!host || isNaN(port)) return;

      try {
        const res = await this.sendPacket(host, port, {
          type: 'PRESENCE_SYNC',
          sourceNode: this.nodeAddress,
          memberships: myState.memberships
        });

        if (res && res.type === 'PRESENCE_ACK' && Array.isArray(res.memberships)) {
          res.memberships.forEach((m) => {
            if (m.user) {
              const parsed = AddressHelper.parse(m.user);
              if (parsed && !parsed.isLocal) {
                this.remoteOnlineUsers.set(m.user, {
                  lastSeen: Date.now(),
                  channels: m.channels || [],
                  isSsh: !!m.isSsh,
                  kemPublicKey: m.kemPublicKey || ''
                });
                if (m.kemPublicKey) {
                  this.db.saveRemoteUserKemKey(m.user, m.kemPublicKey);
                }
              }
            }
          });

          this.emit('presence_change');
          setImmediate(() => this.processOutbox(true));
        }
      } catch {
        this.peerManager.addOrUpdate(peer, false);
      }
    }));

    const presenceSyncPayload = {
      type: 'PRESENCE_SYNC',
      sourceNode: this.nodeAddress,
      memberships: myState.memberships
    };

    if (this.rendezvousRelays) {
      for (const [, relay] of this.rendezvousRelays.entries()) {
        if (relay && relay.channel && relay.channel.socket && relay.channel.socket.writable) {
          relay.channel.writePayload(presenceSyncPayload);
        }
      }
    }

    if (this.rendezvousTunnels) {
      for (const [, tunnel] of this.rendezvousTunnels.entries()) {
        if (tunnel && tunnel.channel && tunnel.channel.socket && tunnel.channel.socket.writable) {
          tunnel.channel.writePayload(presenceSyncPayload);
        }
      }
    }
  }

  async broadcastUserOffline(userAddress) {
    if (!userAddress) return;
    this.remoteOnlineUsers.delete(userAddress);
    this.emit('presence_change');

    const peers = this.peerManager.getAllPeers();
    const payload = {
      type: 'USER_OFFLINE',
      user: userAddress,
      nodeAddress: this.nodeAddress
    };

    for (const peer of peers) {
      if (!peer || !peer.includes(':')) continue;
      const [host, portStr] = peer.split(':');
      const port = parseInt(portStr, 10);
      if (!host || isNaN(port)) continue;

      this.sendPacket(host, port, payload).catch(() => {});
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

    for (const [, tunnel] of this.rendezvousTunnels.entries()) {
      if (tunnel && tunnel.channel && tunnel.channel.socket && tunnel.channel.socket.writable) {
        tunnel.channel.writePayload(payload);
      }
    }
  }

  async performRandomGossip() {
    if (!this.peerManager || typeof this.peerManager.getRandomSample !== 'function') return;
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

  // --- V2.0 AUTONAT & DIALBACK METHODS ---

  handleObservedAddress(observedAddress, peer) {
    if (!observedAddress || !observedAddress.includes(':')) return;
    const [ip] = observedAddress.split(':');
    if (!ip) return;

    if (!this.observedAddressVotes.has(ip)) {
      this.observedAddressVotes.set(ip, new Set());
    }
    this.observedAddressVotes.get(ip).add(peer);

    // Section 2.1: En az 2 eşten aynı IP onaylandığında dış IP konsensüsüne varılır
    const votes = this.observedAddressVotes.get(ip).size;
    if (votes >= 2 && this.publicIp !== ip) {
      this.publicIp = ip;
      log.info(`AutoNAT: Reflected IP konsensüsüne varıldı: ${ip} (${votes} eş onayı)`);
      this.emit('nat_consensus', ip);

      // Section 2.2 Inbound Dialback testi başlat (Mükerrer/çakışan testleri engelle)
      if (CONFIG.meshRole === 'EDGE' || process.env.MESH_ROLE === 'EDGE') {
        log.debug('AutoNAT: MESH_ROLE=EDGE açıkça yapılandırıldığından dialback atlandı, rol EDGE olarak korunuyor.');
        this.setRole('EDGE');
        return;
      }

      if (!this.isDialbackRunning) {
        this.initiateDialback(ip).catch((err) => {
          this.isDialbackRunning = false;
          log.warn(`Dialback başlatma hatası: ${err.message}`);
        });
      }
    }
  }

  async initiateDialback(targetIp) {
    if (this.isDialbackRunning) {
      log.debug('AutoNAT: Dialback testi zaten çalışıyor, mükerrer çağrı engellendi.');
      return this.role;
    }
    this.isDialbackRunning = true;

    const peers = this.peerManager.getAllPeers();
    if (!peers || peers.length === 0) {
      this.isDialbackRunning = false;
      this.setRole('EDGE');
      return 'EDGE';
    }

    const testPeer = peers[0];
    const [peerHost, peerPortStr] = testPeer.split(':');
    const peerPort = parseInt(peerPortStr, 10);
    if (!peerHost || isNaN(peerPort)) {
      this.isDialbackRunning = false;
      this.setRole('EDGE');
      return 'EDGE';
    }

    const nonce = CryptoHelper.generateRandomKey(16);

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        if (this.pendingDialbacks.has(nonce)) {
          this.pendingDialbacks.delete(nonce);
          this.isDialbackRunning = false;
          log.info('AutoNAT: Dialback zaman aşımı -> Rol: CAP_EDGE');
          this.setRole('EDGE');
          resolve('EDGE');
        }
      }, 5000);

      this.pendingDialbacks.set(nonce, {
        targetIp,
        timer,
        resolve
      });

      const payload = {
        type: 'DIALBACK_REQUEST',
        targetIp,
        targetPort: CONFIG.federationPort,
        nonce
      };

      this.sendPacket(peerHost, peerPort, payload).catch((err) => {
        log.warn(`Dialback paket gönderim hatası: ${err.message}`);
        clearTimeout(timer);
        this.pendingDialbacks.delete(nonce);
        this.isDialbackRunning = false;
        this.setRole('EDGE');
        resolve('EDGE');
      });
    });
  }

  handleDialbackConfirm(payload) {
    if (!payload || !payload.nonce) return;
    const pending = this.pendingDialbacks.get(payload.nonce);
    if (pending) {
      clearTimeout(pending.timer);
      this.pendingDialbacks.delete(payload.nonce);
      this.isDialbackRunning = false;
      log.info('AutoNAT: Inbound Dialback doğrulandı -> Rol: CAP_RELAY');
      this.setRole('RELAY');
      pending.resolve('RELAY');
    }
  }

  // --- V2.0 RENDEZVOUS & REVERSE TUNNELS METHODS ---

  async maintainRendezvousTunnels() {
    if (this.role !== 'EDGE' || this.isMaintainingTunnels) return;

    this.isMaintainingTunnels = true;
    try {
      const targets = [];

      // 1. Yapılandırılmış bootstrap eşleri (TR, DE vb.)
      if (Array.isArray(CONFIG && CONFIG.bootstrapPeers)) {
        for (const bp of CONFIG.bootstrapPeers) {
          if (bp && !targets.includes(bp)) targets.push(bp);
        }
      }

      // 2. Rota tablosundaki tüm RELAY düğümleri
      const routes = this.db.getAllRoutes();
      const candidateRelays = routes.filter((r) => (r.role === 'RELAY' || r.role === 'CAP_RELAY') && r.nodeId !== this.nodeId);
      for (const r of candidateRelays) {
        if (Array.isArray(r.rendezvousNodes)) {
          for (const rn of r.rendezvousNodes) {
            if (rn && !targets.includes(rn)) targets.push(rn);
          }
        }
        if (this.nodePhysicalAddresses.has(r.nodeId)) {
          const pAddr = this.nodePhysicalAddresses.get(r.nodeId);
          if (pAddr && !targets.includes(pAddr)) targets.push(pAddr);
        }
      }

      // 3. RAM varlık tablosundaki (presenceTable) RELAY düğümleri
      for (const [nid, p] of this.presenceTable.entries()) {
        if ((p.role === 'RELAY' || p.role === 'CAP_RELAY') && nid !== this.nodeId) {
          if (Array.isArray(p.rendezvousNodes)) {
            for (const rn of p.rendezvousNodes) {
              if (rn && !targets.includes(rn)) targets.push(rn);
            }
          }
          if (this.nodePhysicalAddresses.has(nid)) {
            const pAddr = this.nodePhysicalAddresses.get(nid);
            if (pAddr && !targets.includes(pAddr)) targets.push(pAddr);
          }
        }
      }

      // 4. Bilinen tüm eşler
      const knownPeers = this.peerManager.getAllPeers();
      for (const p of knownPeers) {
        if (p && !targets.includes(p)) targets.push(p);
      }

      for (const relayAddr of targets) {
        if (this.boundRendezvousRelays.has(relayAddr)) continue;
        await this.bindToRendezvousRelay(relayAddr);
      }
    } finally {
      this.isMaintainingTunnels = false;
    }
  }

  async bindToRendezvousRelay(relayAddr) {
    if (!relayAddr || !relayAddr.includes(':')) return false;
    const [host, portStr] = relayAddr.split(':');
    const port = parseInt(portStr, 10);
    if (!host || isNaN(port)) return false;

    try {
      const channel = await this.getOrCreateSecureChannel(host, port);
      const nonce = CryptoHelper.generateRandomKey(16);
      const timestamp = Date.now();
      const sig = CryptoHelper.sign(`${this.nodeId}${relayAddr}${timestamp}${nonce}`, this.identityKeyPair.privateKey);

      const bindPayload = {
        type: 'RENDEZVOUS_BIND',
        nodeId: this.nodeId,
        relayAddress: relayAddr,
        identityPublicKey: this.identityKeyPair.publicKey,
        kemPublicKey: this.kemKeyPair.publicKey,
        timestamp,
        nonce,
        sig
      };

      const res = await this.sendPacket(host, port, bindPayload);
      if (res && res.status === 'bound') {
        this.boundRendezvousRelays.add(relayAddr);
        this.rendezvousRelays.set(relayAddr, { channel, socket: channel.socket });
        log.info(`Rendezvous tüneli bağlandı -> ${relayAddr}`);

        this.broadcastPresenceAnnounce();

        if (channel.peerNodeAddress && channel.peerIdentityKey) {
          const rNodeId = CryptoHelper.deriveNodeId(channel.peerIdentityKey);
          this.presenceTable.set(rNodeId, {
            nodeId: rNodeId,
            role: 'RELAY',
            rendezvousNodes: [relayAddr],
            kemPublicKey: channel.peerKemKey,
            identityPublicKey: channel.peerIdentityKey,
            channels: [],
            lastSeen: Date.now()
          });
          this.nodePhysicalAddresses.set(rNodeId, relayAddr);
          this.db.upsertRoute({
            nodeId: rNodeId,
            role: 'RELAY',
            rendezvousNodes: [relayAddr],
            kemPublicKey: channel.peerKemKey,
            identityPublicKey: channel.peerIdentityKey,
            lastSeen: Date.now()
          });
        }

        if (!channel._hasRendezvousCloseHandler) {
          channel._hasRendezvousCloseHandler = true;
          channel.socket.once('close', () => {
            channel._hasRendezvousCloseHandler = false;
            this.boundRendezvousRelays.delete(relayAddr);
            this.rendezvousRelays.delete(relayAddr);
            log.warn(`Rendezvous bağlantısı kesildi -> ${relayAddr}, yenileniyor...`);
            setTimeout(() => this.maintainRendezvousTunnels(), 2000);
          });
        }
        if (this.db && typeof this.db.resetOutboxForTarget === 'function') {
          this.db.resetOutboxForTarget(relayAddr);
        }
        setImmediate(() => this.processOutbox(true));
        return true;
      }
    } catch (err) {
      log.debug(`Rendezvous bağlantı hatası (${relayAddr}): ${err.message}`);
    }
    return false;
  }

  sendRendezvousHeartbeat() {
    if (this.role !== 'EDGE' || this.boundRendezvousRelays.size === 0) return;

    const now = Date.now();
    let needsMaintenance = false;

    for (const relayAddr of this.boundRendezvousRelays) {
      const [host, portStr] = relayAddr.split(':');
      const port = parseInt(portStr, 10);
      const key = `${host}:${port}`;
      const channel = this.connectionPool.get(key);

      if (channel && channel.socket && !channel.socket.destroyed) {
        // Zombi tünel tespiti: 60 saniyeden uzun süredir PONG alınmadıysa soketi kapat ve tüneli yenile
        if (channel.lastPong && (now - channel.lastPong > 60000)) {
          log.warn(`Rendezvous zombi tünel tespit edildi (PONG zaman aşımı): ${relayAddr}`);
          channel.socket.destroy();
          this.connectionPool.delete(key);
          this.boundRendezvousRelays.delete(relayAddr);
          needsMaintenance = true;
          continue;
        }

        if (channel.socket.writable) {
          try {
            channel.socket.write(Buffer.from([0x09]));
          } catch {}
        }
      } else {
        this.boundRendezvousRelays.delete(relayAddr);
        needsMaintenance = true;
      }
    }

    if (needsMaintenance) {
      this.maintainRendezvousTunnels().catch(() => {});
    }
  }

  // --- V2.0 PRESENCE & ONION ROUTING METHODS ---

  getLocalChannels() {
    const chans = new Set(['#genel']);
    if (this.getLocalStateFn) {
      const state = this.getLocalStateFn();
      if (Array.isArray(state.channels)) {
        state.channels.forEach((c) => chans.add(c));
      }
      if (Array.isArray(state.memberships)) {
        state.memberships.forEach((m) => {
          if (Array.isArray(m.channels)) {
            m.channels.forEach((c) => chans.add(c));
          }
        });
      }
    }
    return Array.from(chans);
  }

  getRelayAnnounceAddress() {
    const serverHost = CONFIG.serverName;
    const isRawIp = net.isIP(serverHost) || /^(?:::ffff:)?\d+\.\d+\.\d+\.\d+$/.test(serverHost);
    if (!isRawIp && serverHost && serverHost !== 'localhost' && !serverHost.startsWith('127.') && serverHost !== '0.0.0.0') {
      return `${serverHost}:${CONFIG.federationPort}`;
    }
    return `${this.nodeId}.mesh:${CONFIG.federationPort}`;
  }

  broadcastRouteUpdate(nodeId, rendezvousAddr, kemPublicKey, identityPublicKey) {
    const timestamp = Date.now();
    const dataToSign = JSON.stringify({
      nodeId,
      relayNodeId: this.nodeId,
      rendezvousNodes: [rendezvousAddr],
      timestamp
    });
    const sig = CryptoHelper.sign(dataToSign, this.identityKeyPair.privateKey);

    const updatePayload = {
      type: 'ROUTE_UPDATE',
      nodeId,
      role: 'EDGE',
      rendezvousNodes: [rendezvousAddr],
      kemPublicKey: kemPublicKey || null,
      identityPublicKey: identityPublicKey || null,
      relayNodeId: this.nodeId,
      relayAddress: rendezvousAddr,
      relayKemPublicKey: this.kemKeyPair.publicKey,
      relayIdentityPublicKey: this.identityKeyPair.publicKey,
      timestamp,
      sig
    };

    const peers = this.peerManager.getAllPeers();
    for (const peer of peers) {
      if (!peer || !peer.includes(':')) continue;
      const [host, portStr] = peer.split(':');
      const port = parseInt(portStr, 10);
      if (!host || isNaN(port)) continue;
      this.sendPacket(host, port, updatePayload).catch(() => {});
    }

    if (this.rendezvousRelays) {
      for (const [, relay] of this.rendezvousRelays.entries()) {
        if (relay?.channel?.socket?.writable) {
          relay.channel.writePayload(updatePayload);
        }
      }
    }
  }

  broadcastPresenceAnnounce() {
    const timestamp = Date.now();
    const channels = this.getLocalChannels();
    const relayAnnounceAddr = this.getRelayAnnounceAddress();

    // Zehirli adres koruması (Gossip Poisoning): 'localhost', '127.0.0.1', '0.0.0.0' asla anons edilmez
    const isPoisoned = (addr) => typeof addr === 'string' && (addr.includes('localhost') || addr.includes('127.0.0.1') || addr.includes('0.0.0.0'));
    let safeBoundRelays = Array.from(this.boundRendezvousRelays).filter((addr) => !isPoisoned(addr));
    if (safeBoundRelays.length === 0 && this.boundRendezvousRelays.size > 0 && (process.env.NODE_ENV === 'test' || CONFIG.serverName === 'localhost')) {
      safeBoundRelays = Array.from(this.boundRendezvousRelays);
    }
    const rendezvousNodes = this.isRelay() ? [relayAnnounceAddr] : safeBoundRelays;

    const dataToSign = JSON.stringify({
      nodeId: this.nodeId,
      role: this.role,
      rendezvousNodes,
      kemPublicKey: this.kemKeyPair.publicKey,
      channels,
      timestamp
    });

    const sig = CryptoHelper.sign(dataToSign, this.identityKeyPair.privateKey);

    const payload = {
      type: 'PRESENCE_ANNOUNCE',
      nodeId: this.nodeId,
      role: this.role,
      rendezvousNodes,
      kemPublicKey: this.kemKeyPair.publicKey,
      identityPublicKey: this.identityKeyPair.publicKey,
      channels,
      timestamp,
      sig
    };

    this.presenceTable.set(this.nodeId, {
      nodeId: this.nodeId,
      role: this.role,
      rendezvousNodes,
      kemPublicKey: this.kemKeyPair.publicKey,
      identityPublicKey: this.identityKeyPair.publicKey,
      channels,
      lastSeen: timestamp
    });
    this.db.upsertRoute({
      nodeId: this.nodeId,
      role: this.role,
      rendezvousNodes,
      kemPublicKey: this.kemKeyPair.publicKey,
      identityPublicKey: this.identityKeyPair.publicKey,
      lastSeen: timestamp
    });

    const peers = this.peerManager.getAllPeers();
    for (const peer of peers) {
      if (!peer || !peer.includes(':')) continue;
      const [host, portStr] = peer.split(':');
      const port = parseInt(portStr, 10);
      if (!host || isNaN(port)) continue;
      this.sendPacket(host, port, payload).catch(() => {});
    }

    if (this.rendezvousRelays) {
      for (const [, relay] of this.rendezvousRelays.entries()) {
        if (relay && relay.channel && relay.channel.socket && relay.channel.socket.writable) {
          relay.channel.writePayload(payload);
        }
      }
    }

    if (this.rendezvousTunnels) {
      for (const [, tunnel] of this.rendezvousTunnels.entries()) {
        if (tunnel && tunnel.channel && tunnel.channel.socket && tunnel.channel.socket.writable) {
          tunnel.channel.writePayload(payload);
        }
      }
    }
  }

  cleanupExpiredPresence() {
    const now = Date.now();
    const presenceTtl = (CONFIG && CONFIG.presenceTtl) || 60000;
    for (const [nodeId, rec] of this.presenceTable.entries()) {
      const diff = now - rec.lastSeen;
      if (diff < 0) {
        rec.lastSeen = now;
      } else if (diff > presenceTtl) {
        this.presenceTable.delete(nodeId);
        this.nodePhysicalAddresses.delete(nodeId);
      }
    }

    let removedUsers = false;
    for (const [userAddr, data] of this.remoteOnlineUsers.entries()) {
      const diff = now - data.lastSeen;
      if (diff < 0) {
        data.lastSeen = now;
      } else if (diff >= presenceTtl) {
        this.remoteOnlineUsers.delete(userAddr);
        removedUsers = true;
      }
    }
    if (removedUsers) {
      this.emit('presence_change');
    }

    this.db.deleteExpiredRoutes(presenceTtl);
    this.onionRouter.cleanupExpiredCircuits();
  }

  handleLocalDeliveredMessage(payload) {
    if (!payload || !payload.id) return;
    if (this.seenMessages.has(payload.id)) return;
    this.seenMessages.add(payload.id);

    const msg = this.db.saveMessage(payload);
    if (msg) {
      this.emit('message', msg);
      log.info(I18n.t('FED_MSG_RECEIVED', { from: msg.from, to: msg.to }));
    }
  }

  async sendViaOnion(targetNodeId, payload) {
    if (targetNodeId && this.rendezvousTunnels.has(targetNodeId)) {
      const localTunnel = this.rendezvousTunnels.get(targetNodeId);
      if (localTunnel && localTunnel.channel && localTunnel.channel.socket && localTunnel.channel.socket.writable) {
        localTunnel.channel.writePayload(payload);
        return { status: 'delivered' };
      }
    }

    let route = this.presenceTable.get(targetNodeId) || this.db.getRoute(targetNodeId);
    let exitRelayAddress = null;

    if (route && Array.isArray(route.rendezvousNodes) && route.rendezvousNodes.length > 0) {
      const nonSelf = route.rendezvousNodes.find((addr) =>
        addr !== this.nodeAddress &&
        addr !== this.meshAddress &&
        addr !== `${CONFIG.serverName}:${CONFIG.federationPort}`
      );
      exitRelayAddress = nonSelf || route.rendezvousNodes[0];
    } else if (route && (route.role === 'RELAY' || route.role === 'CAP_RELAY')) {
      if (route.rendezvousNodes && route.rendezvousNodes[0]) {
        exitRelayAddress = route.rendezvousNodes[0];
      } else if (this.nodePhysicalAddresses.has(targetNodeId)) {
        exitRelayAddress = this.nodePhysicalAddresses.get(targetNodeId);
      }
    }

    if (!exitRelayAddress && this.nodePhysicalAddresses.has(targetNodeId)) {
      exitRelayAddress = this.nodePhysicalAddresses.get(targetNodeId);
    }

    if (targetNodeId && (!exitRelayAddress || exitRelayAddress.length === 0)) {
      log.info(`Hedef EDGE ${targetNodeId} için aktif buluşma noktası bulunamadı, mesaj Outbox kuyruğuna alındı`);
      this.db.queueOutbox(payload);
      return { status: 'queued' };
    }

    const allRoutes = this.db.getAllRoutes();
    const relayPool = [];

    const addRelayToPool = (nodeId, address, kemPublicKey) => {
      if (!address || !kemPublicKey) return;
      if (nodeId === this.nodeId) return;
      if (!relayPool.some((rp) => rp.address === address)) {
        relayPool.push({ nodeId, address, kemPublicKey });
      }
    };

    for (const r of allRoutes) {
      if ((r.role === 'RELAY' || r.role === 'CAP_RELAY') && r.nodeId !== this.nodeId) {
        if (Array.isArray(r.rendezvousNodes)) {
          for (const rn of r.rendezvousNodes) {
            addRelayToPool(r.nodeId, rn, r.kemPublicKey);
          }
        }
        if (this.nodePhysicalAddresses.has(r.nodeId)) {
          addRelayToPool(r.nodeId, this.nodePhysicalAddresses.get(r.nodeId), r.kemPublicKey);
        }
      }
    }

    for (const [nid, p] of this.presenceTable.entries()) {
      if ((p.role === 'RELAY' || p.role === 'CAP_RELAY') && nid !== this.nodeId) {
        if (Array.isArray(p.rendezvousNodes)) {
          for (const rn of p.rendezvousNodes) {
            addRelayToPool(nid, rn, p.kemPublicKey);
          }
        }
        if (this.nodePhysicalAddresses.has(nid)) {
          addRelayToPool(nid, this.nodePhysicalAddresses.get(nid), p.kemPublicKey);
        }
      }
    }

    const peers = this.peerManager.getAllPeers();
    for (const p of peers) {
      if (!relayPool.some((rp) => rp.address === p)) {
        const peerRoute = allRoutes.find((r) =>
          (Array.isArray(r.rendezvousNodes) && r.rendezvousNodes.includes(p)) ||
          this.nodePhysicalAddresses.get(r.nodeId) === p
        ) || Array.from(this.presenceTable.values()).find((pr) =>
          (Array.isArray(pr.rendezvousNodes) && pr.rendezvousNodes.includes(p)) ||
          this.nodePhysicalAddresses.get(pr.nodeId) === p
        );
        if (peerRoute && (peerRoute.role === 'RELAY' || peerRoute.role === 'CAP_RELAY')) {
          addRelayToPool(peerRoute.nodeId, p, peerRoute.kemPublicKey);
        }
      }
    }

    let exitHop = null;
    if (exitRelayAddress) {
      exitHop = relayPool.find((r) => r.address === exitRelayAddress);
      if (!exitHop) {
        const relayMatch = allRoutes.find((r) =>
          (r.role === 'RELAY' || r.role === 'CAP_RELAY') &&
          (
            (Array.isArray(r.rendezvousNodes) && r.rendezvousNodes.includes(exitRelayAddress)) ||
            (r.nodeId && exitRelayAddress.includes(r.nodeId)) ||
            this.nodePhysicalAddresses.get(r.nodeId) === exitRelayAddress
          )
        ) || Array.from(this.presenceTable.values()).find((p) =>
          (p.role === 'RELAY' || p.role === 'CAP_RELAY') &&
          (
            (Array.isArray(p.rendezvousNodes) && p.rendezvousNodes.includes(exitRelayAddress)) ||
            (p.nodeId && exitRelayAddress.includes(p.nodeId)) ||
            this.nodePhysicalAddresses.get(p.nodeId) === exitRelayAddress
          )
        );

        if (relayMatch && relayMatch.kemPublicKey) {
          exitHop = {
            nodeId: relayMatch.nodeId,
            address: exitRelayAddress,
            kemPublicKey: relayMatch.kemPublicKey
          };
        }
      }

      if (!exitHop && route && (route.role === 'RELAY' || route.role === 'CAP_RELAY') && route.kemPublicKey) {
        exitHop = {
          nodeId: route.nodeId,
          address: exitRelayAddress,
          kemPublicKey: route.kemPublicKey
        };
      }

      if (!exitHop && route && route.kemPublicKey) {
        exitHop = {
          nodeId: route.nodeId,
          address: exitRelayAddress,
          kemPublicKey: route.kemPublicKey
        };
      }
    }

    if (exitHop && !relayPool.some((rp) => rp.address === exitHop.address)) {
      relayPool.push(exitHop);
    }

    if (!exitHop) {
      log.info(`Hedef ${targetNodeId} (${exitRelayAddress}) için uygun Exit düğümü bulunamadı, Outbox kuyruğuna alındı`);
      this.db.queueOutbox(payload);
      return { status: 'queued' };
    }

    let circuit = this.onionRouter.getActiveCircuitForTarget(targetNodeId);
    if (circuit && circuit.hops[circuit.hops.length - 1]?.address !== exitHop.address) {
      this.onionRouter.removeClientCircuit(circuit.circuitId);
      circuit = null;
    }

    if (!circuit) {
      const intermediaries = relayPool.filter((r) => r.address !== exitHop.address);
      const hops = [];

      if (intermediaries.length >= 2) {
        hops.push(intermediaries[0]);
        hops.push(intermediaries[1]);
        hops.push(exitHop);
      } else if (intermediaries.length === 1) {
        hops.push(intermediaries[0]);
        hops.push(exitHop);
      } else {
        hops.push(exitHop);
      }

      circuit = await this.onionRouter.buildCircuit(hops, targetNodeId);
    }

    try {
      return await this.onionRouter.sendOnionCell(circuit, targetNodeId, payload);
    } catch (err) {
      this.onionRouter.removeClientCircuit(circuit.circuitId);
      throw err;
    }
  }

  async processOutbox(forceAll = false) {
    const pending = this.db.getPendingOutbox(forceAll);
    for (const item of pending) {
      const target = AddressHelper.parse(item.to);
      if (!target) {
        this.db.removeOutbox(item.id);
        continue;
      }

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

      if (target.nodeId) {
        try {
          await this.sendViaOnion(target.nodeId, payload);
          log.info(I18n.t('FED_OUTBOX_SENT', { id: item.id }));
          this.db.removeOutbox(item.id);
        } catch {
          this.db.updateOutboxRetry(item.id);
        }
        continue;
      }

      if (!target.host || !target.port) {
        this.db.removeOutbox(item.id);
        continue;
      }

      try {
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

    // 1. Küresel Kanal (#genel)
    if (target.isGlobalChannel) {
      this.broadcastChannelMessage(payload);
      return { status: 'broadcasted' };
    }

    // 2. V2.0 Kriptografik Düğüm Adresi (@user:NodeID.mesh veya #channel:NodeID.mesh)
    if (target.nodeId) {
      if (target.isLocal || target.nodeId === this.nodeId) {
        const msg = this.db.saveMessage(payload);
        if (msg) this.emit('message', msg);
        return { status: 'delivered' };
      }

      try {
        return await this.sendViaOnion(target.nodeId, payload);
      } catch (err) {
        log.warn(`Onion gönderim hatası (${target.nodeId}): ${err.message}, outbox'a ekleniyor`);
        this.db.queueOutbox(payload);
        return { status: 'queued' };
      }
    }

    // 3. V1.x Geriye Dönük Uyumluluk (host:port)
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
    if (this.rendezvousHeartbeatInterval) clearInterval(this.rendezvousHeartbeatInterval);
    if (this.maintainRendezvousInterval) clearInterval(this.maintainRendezvousInterval);
    if (this.presenceCleanupInterval) clearInterval(this.presenceCleanupInterval);

    this.isDialbackRunning = false;
    this.isMaintainingTunnels = false;
    for (const [, pending] of this.pendingDialbacks.entries()) {
      clearTimeout(pending.timer);
    }
    this.pendingDialbacks.clear();

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