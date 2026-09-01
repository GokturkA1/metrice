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
    this.seenMessageIds = new Set();

    // Uzak aktif kullanıcılar: Map<"@user:host:port", lastSeenTimestamp>
    this.remoteOnlineUsers = new Map();
    this.getLocalOnlineUsersFn = null;
  }

  setLocalUsersGetter(fn) {
    this.getLocalOnlineUsersFn = fn;
  }

  getAllOnlineUsers() {
    const now = Date.now();
    const activeRemote = [];
    for (const [userAddr, lastSeen] of this.remoteOnlineUsers.entries()) {
      if (now - lastSeen < 25000) { // 25 saniye içinde sinyal geldiyse aktif
        activeRemote.push(userAddr);
      } else {
        this.remoteOnlineUsers.delete(userAddr);
      }
    }
    const localUsers = this.getLocalOnlineUsersFn ? this.getLocalOnlineUsersFn() : [];
    return Array.from(new Set([...localUsers, ...activeRemote]));
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

    // Rastgele yürüyüşlü Gossip (Peer Keşfi)
    const scheduleGossip = () => {
      const jitter = 12000 + Math.floor(Math.random() * 6000);
      setTimeout(async () => {
        await this.performRandomGossip();
        scheduleGossip();
      }, jitter);
    };
    scheduleGossip();

    // Uzak Düğümlerle Aktiflik (Presence Heartbeat) Senkronizasyonu (10 sn)
    setInterval(() => this.broadcastPresence(), 10000);
  }

  handleIncoming(payload, socket, remotePeer) {
    // 1. Mesajlar
    if (payload.type === 'DIRECT_MESSAGE' || payload.type === 'CHANNEL_MESSAGE') {
      if (this.seenMessageIds.has(payload.id)) {
        socket.write(JSON.stringify({ status: 'already_seen', id: payload.id }) + '\n');
        return;
      }

      this.seenMessageIds.add(payload.id);
      if (this.seenMessageIds.size > 2000) {
        const first = this.seenMessageIds.values().next().value;
        this.seenMessageIds.delete(first);
      }

      // Gönderen uzak kullanıcıyı aktif olarak işaretle
      if (payload.from && payload.from.startsWith('@')) {
        this.remoteOnlineUsers.set(payload.from, Date.now());
        this.emit('presence_change');
      }

      const msg = this.db.saveMessage(payload);
      if (msg) {
        this.emit('message', msg);
        log.info(I18n.t('FED_MSG_RECEIVED', { from: msg.from, to: msg.to }));

        if (payload.to.startsWith('#') && !payload.to.includes(':')) {
          this.broadcastChannelMessage(msg, remotePeer);
        }
      }

      socket.write(JSON.stringify({ status: 'delivered', id: payload.id }) + '\n');
    }

    // 2. Typing Sinyali
    else if (payload.type === 'TYPING') {
      if (payload.from && payload.from.startsWith('@')) {
        this.remoteOnlineUsers.set(payload.from, Date.now());
      }
      this.emit('typing', payload);
    }

    // 3. Aktiflik (Presence Sync) Alındı
    else if (payload.type === 'PRESENCE_SYNC') {
      if (Array.isArray(payload.users)) {
        payload.users.forEach((u) => this.remoteOnlineUsers.set(u, Date.now()));
        this.emit('presence_change');
      }

      // Kendi yerel aktif kullanıcılarımızı dön
      const myUsers = this.getLocalOnlineUsersFn ? this.getLocalOnlineUsersFn() : [];
      socket.write(
        JSON.stringify({
          type: 'PRESENCE_ACK',
          users: myUsers
        }) + '\n'
      );
    }

    // 4. Gossip Düğüm Keşfi
    else if (payload.type === 'GOSSIP_DISCOVERY') {
      if (payload.selfNode) this.peerManager.addOrUpdate(payload.selfNode, true);
      if (Array.isArray(payload.peers)) {
        payload.peers.forEach((p) => this.peerManager.addOrUpdate(p, true));
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

  async broadcastPresence() {
    const peers = this.peerManager.getAllPeers();
    const localUsers = this.getLocalOnlineUsersFn ? this.getLocalOnlineUsersFn() : [];

    for (const peer of peers) {
      const [host, portStr] = peer.split(':');
      const port = parseInt(portStr, 10);
      if (!host || isNaN(port)) continue;

      try {
        const res = await this.sendPacket(host, port, {
          type: 'PRESENCE_SYNC',
          users: localUsers
        });

        if (res && res.type === 'PRESENCE_ACK' && Array.isArray(res.users)) {
          res.users.forEach((u) => this.remoteOnlineUsers.set(u, Date.now()));
          this.emit('presence_change');
        }
      } catch {
        // Eş kapalıysa sonraki turda peer skoru düşecek
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
      timestamp: msg.timestamp
    };

    for (const peer of peers) {
      if (peer === exceptPeer) continue;
      const [host, portStr] = peer.split(':');
      const port = parseInt(portStr, 10);
      if (!host || isNaN(port)) continue;

      this.sendPacket(host, port, payload).catch(() => {});
    }
  }

  async performRandomGossip() {
    const sample = this.peerManager.getRandomSample(3);
    for (const peer of sample) {
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
            res.peers.forEach((p) => this.peerManager.addOrUpdate(p, true));
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
      if (!target) {
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
      timestamp: new Date().toISOString()
    };

    this.seenMessageIds.add(payload.id);

    if (target.isMeshChannel) {
      this.broadcastChannelMessage(payload);
      return { status: 'broadcasted' };
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
    if (!target || target.isMeshChannel) return;

    this.sendPacket(target.host, target.port, {
      type: 'TYPING',
      from,
      to: target.raw
    }).catch(() => {});
  }

  sendPacket(host, port, data) {
    return new Promise((resolve, reject) => {
      const client = net.createConnection({ host, port }, () => {
        client.write(JSON.stringify(data) + '\n');
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
            client.end();
            resolve(res);
            return;
          } catch {}
        }
      });

      client.on('error', (err) => reject(err));
      client.setTimeout(3000, () => {
        client.destroy();
        reject(new Error('Timeout'));
      });
    });
  }
}