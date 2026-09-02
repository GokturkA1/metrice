import net from 'node:net';
import EventEmitter from 'node:events';
import { CONFIG } from '../config/index.js';
import { Logger } from '../utils/logger.js';
import { AddressHelper } from '../utils/addressHelper.js';
import { I18n } from '../locales/i18n.js';

const log = new Logger('FEDERATION');

export class FederationEngine extends EventEmitter {
  constructor(db, peerManager) {
    super();
    this.db = db;
    this.peerManager = peerManager;
    this.server = null;
    this.outboxInterval = null;
    this.presenceInterval = null;
    this.gossipTimeout = null;
    this.seenMessageIds = new Set();
    this.connectionPool = new Map();

    // Uzak kullanıcılar: Map<"@user:host:port", { lastSeen, channels: [] }>
    this.remoteOnlineUsers = new Map();
    this.getLocalStateFn = null;

    // Kanal Aboneleri: Map<"#kanal_adi", Set<"host:port">>
    this.channelSubscribers = new Map();
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

  start() {
    this.peerManager.startLanDiscovery();

    this.server = net.createServer((socket) => {
      const remotePeer = `${socket.remoteAddress}:${socket.remotePort}`;
      log.info(I18n.t('FED_INCOMING_CONN', { peer: remotePeer }));
      let buffer = '';

      socket.on('data', (chunk) => {
        buffer += chunk.toString();
        const lines = buffer.split('\n');
        buffer = lines.pop();

        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const payload = JSON.parse(line);
            this.handleIncoming(payload, socket, remotePeer);
          } catch (err) {
            log.warn(I18n.t('FED_INVALID_JSON', { peer: remotePeer, error: err.message }));
            socket.write(JSON.stringify({ status: 'error', message: 'Invalid JSON' }) + '\n');
          }
        }
      });

      socket.on('error', (err) => {
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

  handleIncoming(payload, socket, remotePeer) {
    if (payload.type === 'DIRECT_MESSAGE' || payload.type === 'CHANNEL_MESSAGE') {
      if (this.seenMessageIds.has(payload.id)) {
        // Mükerrer paket tespit edildiğinde soketi askıda bırakma, yanıt dön ve çık
        try {
          socket.write(JSON.stringify({ status: 'duplicate', id: payload.id }) + '\n');
        } catch {}
        return;
      }

      this.seenMessageIds.add(payload.id);
      if (this.seenMessageIds.size > 5000) {
        const first = this.seenMessageIds.values().next().value;
        this.seenMessageIds.delete(first);
      }

      if (payload.from && payload.from.startsWith('@')) {
        const existing = this.remoteOnlineUsers.get(payload.from) || { channels: [] };
        existing.lastSeen = Date.now();
        this.remoteOnlineUsers.set(payload.from, existing);
        this.emit('presence_change');

        // Opportunistic Peering
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

        // Küresel genel kanalsa veya bu kanalın uzak aboneleri varsa dağıt
        if (payload.to.startsWith('#') && !payload.to.includes(':') && hop < ttl) {
          this.broadcastChannelMessage({ ...msg, hop, ttl }, remotePeer);
        } else if (this.channelSubscribers.has(payload.to)) {
          this.forwardToChannelSubscribers(payload.to, { ...msg, hop, ttl }, remotePeer);
        }
      }

      socket.write(JSON.stringify({ status: 'delivered', id: payload.id }) + '\n');
    }

    // Uzak Kanal Aboneliği Talebi
    else if (payload.type === 'CHANNEL_SUBSCRIBE') {
      if (payload.channel && payload.subscriberNode) {
        if (!this.channelSubscribers.has(payload.channel)) {
          this.channelSubscribers.set(payload.channel, new Set());
        }
        this.channelSubscribers.get(payload.channel).add(payload.subscriberNode);
        log.info(I18n.t('FED_CHANNEL_SUBSCRIBED', { peer: payload.subscriberNode, channel: payload.channel }));
        this.peerManager.addOrUpdate(payload.subscriberNode, true);
        socket.write(JSON.stringify({ status: 'subscribed', channel: payload.channel }) + '\n');
      }
    }

    // Uzak Kanal Aboneliğinden Çıkma
    else if (payload.type === 'CHANNEL_UNSUBSCRIBE') {
      if (payload.channel && payload.subscriberNode && this.channelSubscribers.has(payload.channel)) {
        this.channelSubscribers.get(payload.channel).delete(payload.subscriberNode);
        log.info(I18n.t('FED_CHANNEL_UNSUBSCRIBED', { peer: payload.subscriberNode, channel: payload.channel }));
        socket.write(JSON.stringify({ status: 'unsubscribed', channel: payload.channel }) + '\n');
      }
    }

    // Diğer Protokoller
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
              channels: m.channels || []
            });
          }
        });
        this.emit('presence_change');
      }

      const myState = this.getLocalStateFn ? this.getLocalStateFn() : { memberships: [] };
      socket.write(JSON.stringify({ type: 'PRESENCE_ACK', memberships: myState.memberships }) + '\n');
    } else if (payload.type === 'GOSSIP_DISCOVERY') {
      if (payload.selfNode && payload.selfNode.includes(':')) this.peerManager.addOrUpdate(payload.selfNode, true);
      if (Array.isArray(payload.peers)) {
        payload.peers.forEach((p) => {
          if (p && p.includes(':')) this.peerManager.addOrUpdate(p, true);
        });
      }

      socket.write(
        JSON.stringify({
          type: 'GOSSIP_RESPONSE',
          selfNode: `${CONFIG.serverName}:${CONFIG.federationPort}`,
          peers: this.peerManager.getRandomSample(5)
        }) + '\n'
      );
    }
  }

  // Abone uzak sunuculara kanal mesajını ilet
  forwardToChannelSubscribers(channel, msg, exceptPeer = null) {
    const subscribers = this.channelSubscribers.get(channel);
    if (!subscribers) return;

    const payload = {
      type: 'CHANNEL_MESSAGE',
      id: msg.id,
      from: msg.from,
      to: msg.to,
      content: msg.content,
      isAction: msg.isAction,
      isSnippet: msg.isSnippet,
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

  // Uzak sunucuya kanala katıldığımızı bildir
  async subscribeRemoteChannel(host, port, channel) {
    try {
      await this.sendPacket(host, port, {
        type: 'CHANNEL_SUBSCRIBE',
        channel,
        subscriberNode: `${CONFIG.serverName}:${CONFIG.federationPort}`
      });
      this.peerManager.addOrUpdate(`${host}:${port}`, true);
    } catch {}
  }

  // Uzak sunucuya kanaldan ayrıldığımızı bildir
  async unsubscribeRemoteChannel(host, port, channel) {
    try {
      await this.sendPacket(host, port, {
        type: 'CHANNEL_UNSUBSCRIBE',
        channel,
        subscriberNode: `${CONFIG.serverName}:${CONFIG.federationPort}`
      });
    } catch {}
  }

  getOrCreateConnection(host, port) {
    if (!host || !port || host === 'null' || isNaN(port)) {
      return Promise.reject(new Error(`Invalid host or port: ${host}:${port}`));
    }

    const key = `${host}:${port}`;
    const existing = this.connectionPool.get(key);

    if (existing && !existing.destroyed && existing.writable) {
      return Promise.resolve(existing);
    }

    return new Promise((resolve, reject) => {
      log.debug(I18n.t('FED_CONNECTING', { host, port }));
      const client = net.createConnection({ host, port }, () => {
        client.setKeepAlive(true, 10000);
        this.connectionPool.set(key, client);
        log.info(I18n.t('FED_CONNECTED', { host, port }));
        resolve(client);
      });

      let buffer = '';
      client.on('data', (chunk) => {
        buffer += chunk.toString();
        const lines = buffer.split('\n');
        buffer = lines.pop();

        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const res = JSON.parse(line);
            client.emit('packet_response', res);
          } catch {}
        }
      });

      client.on('error', (err) => {
        this.connectionPool.delete(key);
        reject(err);
      });

      client.on('close', () => {
        this.connectionPool.delete(key);
      });

      client.setTimeout(5000, () => {
        this.connectionPool.delete(key);
        client.destroy();
        reject(new Error('Connection Timeout'));
      });
    });
  }

  async sendPacket(host, port, data) {
    const client = await this.getOrCreateConnection(host, port);
    return new Promise((resolve) => {
      const onResponse = (res) => {
        client.off('packet_response', onResponse);
        resolve(res);
      };

      client.once('packet_response', onResponse);
      client.write(JSON.stringify(data) + '\n');

      setTimeout(() => {
        client.off('packet_response', onResponse);
        resolve({ status: 'unacknowledged' });
      }, 3000);
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
                channels: m.channels || []
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
          selfNode: `${CONFIG.serverName}:${CONFIG.federationPort}`,
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
        await this.sendPacket(target.host, target.port, {
          type: target.type === 'CHANNEL' ? 'CHANNEL_MESSAGE' : 'DIRECT_MESSAGE',
          id: item.id,
          from: item.from,
          to: item.to,
          content: item.content,
          isAction: item.isAction,
          isSnippet: item.isSnippet,
          timestamp: item.timestamp
        });
        log.info(I18n.t('FED_OUTBOX_SENT', { id: item.id }));
        this.db.removeOutbox(item.id);
        this.peerManager.addOrUpdate(`${target.host}:${target.port}`, true);
      } catch {
        this.db.updateOutboxRetry(item.id);
        this.peerManager.addOrUpdate(`${target.host}:${target.port}`, false);
      }
    }
  }

  async sendRemoteMessage(from, to, content, isAction = false, isSnippet = false) {
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
      hop: 0,
      ttl: 5,
      timestamp: new Date().toISOString()
    };

    this.seenMessageIds.add(payload.id);

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

    for (const socket of this.connectionPool.values()) {
      try {
        socket.destroy();
      } catch {}
    }
    this.connectionPool.clear();

    if (this.server) {
      try {
        this.server.close();
      } catch {}
    }
    log.info('Federasyon motoru ve bağlantı havuzu güvenle kapatıldı.');
  }
}