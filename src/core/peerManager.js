import dgram from 'node:dgram';
import fs from 'node:fs';
import os from 'node:os';
import { CONFIG } from '../config/index.js';
import { Logger } from '../utils/logger.js';
import { I18n } from '../locales/i18n.js';

const log = new Logger('PEER_MGR');

export class PeerManager {
  constructor(storagePath) {
    this.storagePath = storagePath;
    this.peers = new Map();
    this.udpSocket = null;
    this.broadcastPort = 41234;
    this.publicIp = null;
    this.edgeIps = new Set();
    const publicPort = CONFIG.publicFederationPort || CONFIG.federationPort;
    this.selfNodeAddress = `${CONFIG.serverName}:${publicPort}`;
    this.loadPeers();
  }

  registerEdgeIp(ip) {
    if (!ip) return;
    const cleanIp = ip.replace(/^::ffff:/, '');
    this.edgeIps.add(cleanIp);
    this.evictHost(cleanIp);
  }

  evictHost(host) {
    if (!host) return;
    const cleanHost = host.replace(/^::ffff:/, '');
    let modified = false;
    for (const addr of Array.from(this.peers.keys())) {
      if (!addr || !addr.includes(':')) continue;
      const [h] = addr.split(':');
      const cleanH = h.replace(/^::ffff:/, '');
      if (cleanH === cleanHost) {
        this.peers.delete(addr);
        modified = true;
        log.info(I18n.t('PEER_EVICTED', { peer: addr }));
      }
    }
    if (modified) {
      this.savePeers();
    }
  }

  isSelfAddress(host, port) {
    const pubPort = CONFIG.publicFederationPort || CONFIG.federationPort;
    if (port !== CONFIG.federationPort && port !== pubPort) return false;

    // 1. Alan adı, localhost ve döngüsel adresler
    if (
      host === CONFIG.serverName ||
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '::1' ||
      host === '::ffff:127.0.0.1' ||
      host === '0.0.0.0'
    ) {
      return true;
    }

    // 2. AutoNAT ile tespit edilen yansıyan dış IP (Reflected Public IP)
    if (this.publicIp && (host === this.publicIp || host === `::ffff:${this.publicIp}`)) {
      return true;
    }

    // 3. Makinenin tüm ağ kartlarındaki IP adresleri
    try {
      const interfaces = os.networkInterfaces();
      for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name] || []) {
          const clean = iface.address.replace('::ffff:', '');
          if (clean === host || iface.address === host) {
            return true;
          }
        }
      }
    } catch {}

    return false;
  }

  setPublicIp(ip) {
    if (!ip) return;
    this.publicIp = ip;
    const pubPort = CONFIG.publicFederationPort || CONFIG.federationPort;
    this.selfNodeAddress = `${ip}:${pubPort}`;

    // Havuzda kalan kendi IP ve döngüsel adresleri temizle (Gossip Poisoning koruması)
    for (const addr of this.peers.keys()) {
      if (!addr || !addr.includes(':')) {
        this.peers.delete(addr);
        continue;
      }
      const [host, portStr] = addr.split(':');
      const port = parseInt(portStr, 10);
      if (this.isSelfAddress(host, port)) {
        this.peers.delete(addr);
      }
    }
    this.savePeers();
  }

  loadPeers() {
    if (this.storagePath && typeof this.storagePath === 'string' && fs.existsSync(this.storagePath)) {
      try {
        const raw = JSON.parse(fs.readFileSync(this.storagePath, 'utf-8'));
        raw.forEach(([addr, meta]) => {
          if (!addr || !addr.includes(':')) return;
          const [host, portStr] = addr.split(':');
          const port = parseInt(portStr, 10);
          const cleanHost = host.replace(/^::ffff:/, '');
          
          // Dosyada kalan eski kendi IP'lerini, loopback adreslerini ve yüksek hatalı eşleri temizle
          if (
            !this.isSelfAddress(host, port) &&
            cleanHost !== 'localhost' &&
            cleanHost !== '127.0.0.1' &&
            cleanHost !== '::1' &&
            cleanHost !== '0.0.0.0' &&
            cleanHost !== '255.255.255.255' &&
            (!this.edgeIps || (!this.edgeIps.has(cleanHost) && !this.edgeIps.has(host)))
          ) {
            if (meta && (meta.failures >= 3 || meta.score <= 0)) {
              return;
            }
            this.peers.set(addr, meta);
          }
        });
        log.info(I18n.t('PEER_CACHE_LOADED', { count: this.peers.size }));
      } catch {
        this.peers = new Map();
      }
    }
  }

  savePeers() {
    if (!this.storagePath || typeof this.storagePath !== 'string') return;
    try {
      const data = Array.from(this.peers.entries());
      fs.promises.writeFile(this.storagePath, JSON.stringify(data, null, 2), 'utf-8').catch(() => {});
    } catch (err) {
      log.error(I18n.t('PEER_CACHE_SAVE_ERROR', { error: err.message }));
    }
  }

  addOrUpdate(peerAddr, success = true, fromGossip = false) {
    if (!peerAddr || !peerAddr.includes(':')) return;

    const [host, portStr] = peerAddr.split(':');
    const port = parseInt(portStr, 10);
    if (!host || isNaN(port) || port <= 0 || port > 65535) return;

    const cleanHost = host.replace(/^::ffff:/, '');

    // Loopback, localhost ve broadcast adreslerini engelle (Gossip havuzunu kirletmeyi önler)
    if (cleanHost === 'localhost' || cleanHost === '127.0.0.1' || cleanHost === '::1' || cleanHost === '0.0.0.0' || cleanHost === '255.255.255.255') return;

    // Kendi IP veya domainimiz ise havuza ekleme (IP sızıntısını önler)
    if (this.isSelfAddress(host, port)) return;

    // Bilinen EDGE düğümü IP'si ise havuza ekleme (CGNAT arkası port zehirlenmesini önler)
    if (this.edgeIps && (this.edgeIps.has(cleanHost) || this.edgeIps.has(host))) return;

    const isBootstrap = Array.isArray(CONFIG && CONFIG.bootstrapPeers) && CONFIG.bootstrapPeers.includes(peerAddr);

    if (this.peers.size >= 250 && !this.peers.has(peerAddr)) {
      let lowestKey = null;
      let minScore = Infinity;
      for (const [key, val] of this.peers.entries()) {
        if (val.score < minScore) {
          minScore = val.score;
          lowestKey = key;
        }
      }
      if (lowestKey) this.peers.delete(lowestKey);
    }

    const current = this.peers.get(peerAddr) || {
      score: fromGossip ? 60 : 100,
      lastSeen: Date.now(),
      failures: 0,
      fromGossip: !!fromGossip
    };

    if (success) {
      if (fromGossip) {
        // Üçüncü taraf dedikodusu (gossip) mevcut yerel başarısızlık sayısını ve skorunu sıfırlayamaz
        if (this.peers.has(peerAddr)) {
          current.lastSeen = Date.now();
          this.savePeers();
          return;
        }
        current.score = 60;
        current.failures = 0;
        current.fromGossip = true;
        current.lastSeen = Date.now();
      } else {
        // Doğrudan bağlantı doğrulaması
        current.score = 100;
        current.failures = 0;
        current.fromGossip = false;
        current.lastSeen = Date.now();
      }
    } else {
      current.score -= 5;
      current.failures += 1;
    }

    if (!isBootstrap && (current.score <= 0 || current.failures >= 10 || (current.fromGossip && current.failures >= 1))) {
      this.peers.delete(peerAddr);
      log.debug(I18n.t('PEER_EVICTED', { peer: peerAddr }));
    } else {
      this.peers.set(peerAddr, current);
    }

    this.savePeers();
  }

  getRandomSample(k = 3) {
    const list = Array.from(this.peers.entries())
      .filter(([, meta]) => !meta || (meta.failures === 0 && meta.score >= 80))
      .map(([addr]) => addr);
    if (list.length === 0) return [];
    
    for (let i = list.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [list[i], list[j]] = [list[j], list[i]];
    }

    return list.slice(0, k);
  }

  getAllPeers() {
    return Array.from(this.peers.keys());
  }

  startLanDiscovery() {
    this.udpSocket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

    this.udpSocket.on('error', (err) => {
      log.warn(I18n.t('PEER_UDP_ERROR', { error: err.message }));
    });

    this.udpSocket.on('message', (msg, rinfo) => {
      try {
        const payload = JSON.parse(msg.toString());
        // Kendi yaydığımız paketi geri aldığımızda yut
        if (payload.nodeAddress === this.selfNodeAddress || payload.nodeAddress === `${CONFIG.serverName}:${CONFIG.federationPort}`) {
          return;
        }

        if (payload.type === 'P2P_BEACON' && payload.port) {
          const cleanIp = rinfo.address.replace('::ffff:', '');
          if (!this.isSelfAddress(cleanIp, payload.port)) {
            const peerAddr = `${cleanIp}:${payload.port}`;
            this.addOrUpdate(peerAddr, true);
          }
        }
      } catch {}
    });

    this.udpSocket.bind(this.broadcastPort, () => {
      try {
        this.udpSocket.setBroadcast(true);
      } catch {}

      log.info(I18n.t('PEER_LAN_ACTIVE', { port: this.broadcastPort }));

      this.sendBeacon();

      const scheduleBeacon = () => {
        const interval = 4000 + Math.floor(Math.random() * 2000);
        setTimeout(() => {
          this.sendBeacon();
          scheduleBeacon();
        }, interval);
      };
      scheduleBeacon();
    });
  }

  sendBeacon() {
    if (!this.udpSocket) return;
    const publicPort = CONFIG.publicFederationPort || CONFIG.federationPort;
    const payload = Buffer.from(
      JSON.stringify({
        type: 'P2P_BEACON',
        nodeAddress: this.selfNodeAddress,
        port: publicPort,
        timestamp: Date.now()
      })
    );

    this.udpSocket.send(payload, 0, payload.length, this.broadcastPort, '255.255.255.255', () => {});
    this.udpSocket.send(payload, 0, payload.length, this.broadcastPort, '127.0.0.1', () => {});
  }

  close() {
    if (this.udpSocket) {
      try { this.udpSocket.close(); } catch {}
      this.udpSocket = null;
    }
  }
}