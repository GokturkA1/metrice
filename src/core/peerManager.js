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
    this.selfNodeAddress = `${CONFIG.serverName}:${CONFIG.federationPort}`;
    this.loadPeers();
  }

  isSelfAddress(host, port) {
    if (port !== CONFIG.federationPort) return false;

    // 1. Alan adı, localhost ve döngüsel adresler
    if (
      host === CONFIG.serverName ||
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '::1' ||
      host === '::ffff:127.0.0.1'
    ) {
      return true;
    }

    // 2. Makinenin tüm ağ kartlarındaki IP adresleri
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

  loadPeers() {
    if (this.storagePath && typeof this.storagePath === 'string' && fs.existsSync(this.storagePath)) {
      try {
        const raw = JSON.parse(fs.readFileSync(this.storagePath, 'utf-8'));
        raw.forEach(([addr, meta]) => {
          if (!addr || !addr.includes(':')) return;
          const [host, portStr] = addr.split(':');
          const port = parseInt(portStr, 10);
          
          // Dosyada kalan eski kendi IP'lerini ve loopback adreslerini temizle
          if (!this.isSelfAddress(host, port) && host !== 'localhost' && host !== '127.0.0.1' && host !== '::1' && host !== '0.0.0.0' && host !== '255.255.255.255') {
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

  addOrUpdate(peerAddr, success = true) {
    if (!peerAddr || !peerAddr.includes(':')) return;

    const [host, portStr] = peerAddr.split(':');
    const port = parseInt(portStr, 10);
    if (!host || isNaN(port) || port <= 0 || port > 65535) return;

    // Loopback, localhost ve broadcast adreslerini engelle (Gossip havuzunu kirletmeyi önler)
    if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '0.0.0.0' || host === '255.255.255.255') return;

    // Kendi IP veya domainimiz ise havuza ekleme (IP sızıntısını önler)
    if (this.isSelfAddress(host, port)) return;

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

    const current = this.peers.get(peerAddr) || { score: 10, lastSeen: Date.now(), failures: 0 };

    if (success) {
      current.score = Math.min(100, current.score + 2);
      current.failures = 0;
      current.lastSeen = Date.now();
    } else {
      current.score -= 5;
      current.failures += 1;
    }

    if (current.score <= 0 || current.failures >= 5) {
      this.peers.delete(peerAddr);
      log.debug(I18n.t('PEER_EVICTED', { peer: peerAddr }));
    } else {
      this.peers.set(peerAddr, current);
    }

    this.savePeers();
  }

  getRandomSample(k = 3) {
    const list = Array.from(this.peers.keys());
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
        if (payload.nodeAddress === this.selfNodeAddress) {
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
    const payload = Buffer.from(
      JSON.stringify({
        type: 'P2P_BEACON',
        nodeAddress: this.selfNodeAddress,
        port: CONFIG.federationPort,
        timestamp: Date.now()
      })
    );

    this.udpSocket.send(payload, 0, payload.length, this.broadcastPort, '255.255.255.255', () => {});
    this.udpSocket.send(payload, 0, payload.length, this.broadcastPort, '127.0.0.1', () => {});
  }
}