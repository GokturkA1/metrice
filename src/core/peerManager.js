import dgram from 'node:dgram';
import fs from 'node:fs';
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
    this.loadPeers();
  }

  loadPeers() {
    if (fs.existsSync(this.storagePath)) {
      try {
        const raw = JSON.parse(fs.readFileSync(this.storagePath, 'utf-8'));
        raw.forEach(([addr, meta]) => this.peers.set(addr, meta));
        log.info(I18n.t('PEER_CACHE_LOADED', { count: this.peers.size }));
      } catch {
        this.peers = new Map();
      }
    }
  }

  savePeers() {
    try {
      const data = Array.from(this.peers.entries());
      fs.promises.writeFile(this.storagePath, JSON.stringify(data, null, 2), 'utf-8');
    } catch (err) {
      log.error(I18n.t('PEER_CACHE_SAVE_ERROR', { error: err.message }));
    }
  }

  addOrUpdate(peerAddr, success = true) {
    const selfAddr = `${CONFIG.serverName}:${CONFIG.federationPort}`;
    if (peerAddr === selfAddr || !peerAddr.includes(':')) return;

    // 1. Host & Port Validasyonu (Sybil ve Port Zehirleme Koruması)
    const [host, portStr] = peerAddr.split(':');
    const port = parseInt(portStr, 10);
    if (!host || isNaN(port) || port <= 0 || port > 65535) return;

    // Ayrılmış veya yasaklı IP/broadcast adreslerini engelle
    if (host === '0.0.0.0' || host === '255.255.255.255') return;

    // 2. Maksimum Eş Havuzu Limiti (Sybil Flood Koruması - Max 250 Düğüm)
    if (this.peers.size >= 250 && !this.peers.has(peerAddr)) {
      // En düşük skorlu eşi bul ve tahliye et
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
        if (payload.type === 'P2P_BEACON' && payload.port) {
          const peerAddr = `${rinfo.address}:${payload.port}`;
          this.addOrUpdate(peerAddr, true);
        }
      } catch {}
    });

    this.udpSocket.bind(this.broadcastPort, () => {
        try {
            this.udpSocket.setBroadcast(true);
        } catch {}

        log.info(I18n.t('PEER_LAN_ACTIVE', { port: this.broadcastPort }));

        // Açılışta hemen bir beacon at, ardından aralıklarla devam et
        this.sendBeacon();

        const scheduleBeacon = () => {
            const interval = 3000 + Math.floor(Math.random() * 2000);
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
        port: CONFIG.federationPort,
        timestamp: Date.now()
      })
    );

    // Hem LAN broadcast'e hem de yerel döngü portuna gönder
    this.udpSocket.send(payload, 0, payload.length, this.broadcastPort, '255.255.255.255', () => {});
    this.udpSocket.send(payload, 0, payload.length, this.broadcastPort, '127.0.0.1', () => {});
  }
}