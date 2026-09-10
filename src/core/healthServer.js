import net from 'node:net';
import { CONFIG } from '../config/index.js';
import { Logger } from '../utils/logger.js';
import { I18n } from '../locales/i18n.js';

const log = new Logger('HEALTH_SRV');

export class HealthServer {
  /**
   * @param {import('../storage/database.js').Database} [db]
   * @param {import('./federation.js').FederationEngine} [federation]
   * @param {import('./peerManager.js').PeerManager} [peerManager]
   * @param {object} [options]
   * @param {number} [options.port]
   * @param {boolean} [options.allowOuterHeartbeat]
   */
  constructor(db = null, federation = null, peerManager = null, options = {}) {
    this.db = db;
    this.federation = federation;
    this.peerManager = peerManager;
    this.port = parseInt(options.port || CONFIG.healthPort || '8050', 10);
    this.allowOuter = options.allowOuterHeartbeat ?? CONFIG.allowOuterHeartbeat ?? false;
    this.host = this.allowOuter ? '0.0.0.0' : '127.0.0.1';
    this.server = null;
    this.sockets = new Set();
    this.startTime = Date.now();
  }

  /**
   * Sunucuyu baslatir
   * @returns {Promise<void>}
   */
  start() {
    return new Promise((resolve, reject) => {
      if (this.server) {
        return resolve();
      }

      this.server = net.createServer((socket) => this.handleConnection(socket));

      this.server.on('error', (err) => {
        log.error(`Health server error: ${err.message}`);
        reject(err);
      });

      this.server.listen(this.port, this.host, () => {
        log.info(I18n.t('HEALTH_SRV_LISTENING', { host: this.host, port: this.port }));
        resolve();
      });
    });
  }

  /**
   * Gelen TCP baglantisini ve komutlarini yonetir
   * @param {net.Socket} socket
   */
  handleConnection(socket) {
    this.sockets.add(socket);
    let buffer = '';

    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      if (buffer.length > 8192) {
        // Asiri yuklenmeye karsi tampon siniri
        socket.destroy();
        this.sockets.delete(socket);
        return;
      }

      let newlineIdx;
      while ((newlineIdx = buffer.indexOf('\n')) !== -1) {
        const rawLine = buffer.slice(0, newlineIdx);
        buffer = buffer.slice(newlineIdx + 1);
        const line = rawLine.replace(/\r$/, '').trim();

        if (!line) continue;

        const cmd = line.toUpperCase();
        log.debug(`Received health command: ${cmd} from ${socket.remoteAddress}`);

        if (cmd === 'PING') {
          socket.write('PONG\n');
        } else if (cmd === 'HEALTH' || cmd === 'CHECK') {
          const health = this.getHealthData();
          const prefix = health.status === 'healthy' ? 'OK ' : 'ERR ';
          socket.write(prefix + JSON.stringify(health) + '\n');
        } else if (cmd === 'STATUS' || cmd === 'INFO') {
          const status = this.getStatusData();
          socket.write(JSON.stringify(status) + '\n');
        } else if (cmd === 'QUIT') {
          socket.end();
          break;
        } else {
          socket.write('ERR unknown_command\n');
        }
      }
    });

    socket.on('error', (err) => {
      log.debug(`Health socket connection error (${socket.remoteAddress}): ${err.message}`);
      this.sockets.delete(socket);
    });

    socket.on('close', () => {
      this.sockets.delete(socket);
    });
  }

  /**
   * Hizli saglik verisi uretir
   * @returns {import('../types/protocol.d.ts').HealthCheckResponse}
   */
  getHealthData() {
    let dbStatus = 'healthy';
    let dbError;

    try {
      if (this.db && this.db.db) {
        this.db.db.prepare('SELECT 1').get();
      } else {
        dbStatus = 'unhealthy';
        dbError = 'Database not initialized';
      }
    } catch (err) {
      dbStatus = 'unhealthy';
      dbError = err.message;
    }

    const uptime = Math.floor((Date.now() - this.startTime) / 1000);

    return {
      status: dbStatus === 'healthy' ? 'healthy' : 'unhealthy',
      uptime,
      database: dbStatus,
      timestamp: Date.now(),
      ...(dbError ? { error: dbError } : {})
    };
  }

  /**
   * Ayrintili dugum metriklerini uretir
   * @returns {import('../types/protocol.d.ts').HeartbeatStatusResponse}
   */
  getStatusData() {
    const health = this.getHealthData();
    const mem = process.memoryUsage();

    let activeTunnels = 0;
    const maxTunnels = CONFIG.maxRendezvousTunnels || 64;
    let activeCircuits = 0;
    let nodeAddress = 'unknown';
    let meshRole = CONFIG.meshRole || 'EDGE';

    if (this.federation) {
      if (this.federation.rendezvousTunnels) {
        activeTunnels = this.federation.rendezvousTunnels.size;
      }
      if (this.federation.onionRouter && this.federation.onionRouter.circuits) {
        activeCircuits = this.federation.onionRouter.circuits.size;
      }
      if (this.federation.meshAddress) {
        nodeAddress = this.federation.meshAddress;
      } else if (this.federation.nodeAddress) {
        nodeAddress = this.federation.nodeAddress;
      }
      if (this.federation.role) {
        meshRole = this.federation.role;
      }
    }

    let totalKnownPeers = 0;
    let verifiedPeers = 0;
    if (this.peerManager && this.peerManager.peers) {
      totalKnownPeers = this.peerManager.peers.size;
      for (const [, p] of this.peerManager.peers.entries()) {
        if (p && (p.failures === 0 || !p.failures) && (p.score === undefined || p.score >= 80)) {
          verifiedPeers++;
        }
      }
    }

    return {
      status: health.status,
      version: CONFIG.version,
      serverName: CONFIG.serverName,
      nodeAddress,
      meshRole,
      uptimeSeconds: health.uptime,
      timestamp: Date.now(),
      database: {
        status: health.database,
        walMode: true
      },
      federation: {
        port: CONFIG.federationPort,
        activeRendezvousTunnels: activeTunnels,
        maxRendezvousTunnels: maxTunnels,
        activeCircuits
      },
      peers: {
        totalKnown: totalKnownPeers,
        verified: verifiedPeers
      },
      quantumSecurity: {
        mlkem768: true,
        strictPq: CONFIG.strictPq || false
      },
      memory: {
        rssMb: Math.round((mem.rss / (1024 * 1024)) * 10) / 10,
        heapUsedMb: Math.round((mem.heapUsed / (1024 * 1024)) * 10) / 10
      }
    };
  }

  /**
   * Sunucuyu ve tum acik istemci soketlerini kapatir
   */
  close() {
    for (const socket of this.sockets) {
      try {
        socket.destroy();
      } catch {}
    }
    this.sockets.clear();

    if (this.server) {
      try {
        this.server.close();
      } catch {}
      this.server = null;
      log.info(I18n.t('HEALTH_SRV_CLOSED'));
    }
  }
}
