import net from 'node:net';
import { CONFIG } from '../config/index.js';
import { Logger } from '../utils/logger.js';
import { CryptoHelper } from '../utils/cryptoHelper.js';
import { I18n } from '../locales/i18n.js';

const log = new Logger('AUTONAT');

export class AutoNatService {
  constructor(federation) {
    this.federation = federation;
  }

  handleObservedAddress(observedAddress, peer) {
    const fed = this.federation;
    if (!observedAddress || !observedAddress.includes(':')) return;
    const [ip] = observedAddress.split(':');
    if (!ip) return;

    if (!fed.observedAddressVotes.has(ip)) {
      fed.observedAddressVotes.set(ip, new Set());
    }
    fed.observedAddressVotes.get(ip).add(peer);

    // Section 2.1: En az 2 esten ayni IP onaylandiginda dis IP konsensusune varilir
    const votes = fed.observedAddressVotes.get(ip).size;
    if (votes >= 2 && fed.publicIp !== ip) {
      fed.publicIp = ip;
      if (fed.peerManager && typeof fed.peerManager.setPublicIp === 'function') {
        fed.peerManager.setPublicIp(ip);
      }
      const isLoopbackOrLocal = !CONFIG.serverName || CONFIG.serverName === 'localhost' || CONFIG.serverName.startsWith('127.') || CONFIG.serverName === '0.0.0.0';
      if (fed.isRelay() && isLoopbackOrLocal) {
        const publicPort = CONFIG.publicFederationPort || CONFIG.federationPort;
        fed.nodeAddress = `${ip}:${publicPort}`;
        fed.myIdentity.nodeAddress = fed.nodeAddress;
      }
      log.info(I18n.t('FED_AUTONAT_CONSENSUS', { ip, votes }));
      fed.emit('nat_consensus', ip);

      // Section 2.2 Inbound Dialback testi baslat
      if (CONFIG.meshRole === 'EDGE' || process.env.MESH_ROLE === 'EDGE') {
        log.debug(I18n.t('FED_AUTONAT_EDGE_SKIPPED'));
        fed.setRole('EDGE');
        return;
      }

      if (!fed.isDialbackRunning) {
        this.initiateDialback(ip).catch((err) => {
          fed.isDialbackRunning = false;
          log.warn(I18n.t('FED_AUTONAT_DIALBACK_ERR', { error: err.message }));
        });
      }
    }
  }

  async initiateDialback(targetIp) {
    const fed = this.federation;
    if (fed.isDialbackRunning) {
      log.debug(I18n.t('FED_AUTONAT_ALREADY_RUNNING'));
      return fed.role;
    }
    fed.isDialbackRunning = true;

    const peers = fed.peerManager ? fed.peerManager.getAllPeers() : [];
    if (!peers || peers.length === 0) {
      fed.isDialbackRunning = false;
      fed.setRole('EDGE');
      return 'EDGE';
    }

    const testPeer = peers[0];
    const [peerHost, peerPortStr] = testPeer.split(':');
    const peerPort = parseInt(peerPortStr, 10);
    if (!peerHost || isNaN(peerPort)) {
      fed.isDialbackRunning = false;
      fed.setRole('EDGE');
      return 'EDGE';
    }

    const nonce = CryptoHelper.generateRandomKey(16);

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        if (fed.pendingDialbacks.has(nonce)) {
          fed.pendingDialbacks.delete(nonce);
          fed.isDialbackRunning = false;
          log.info(I18n.t('FED_AUTONAT_TIMEOUT'));
          fed.setRole('EDGE');
          resolve('EDGE');
        }
      }, 5000);

      fed.pendingDialbacks.set(nonce, {
        targetIp,
        timer,
        resolve
      });

      const payload = {
        type: 'DIALBACK_REQUEST',
        targetIp,
        targetPort: CONFIG.publicFederationPort || CONFIG.federationPort,
        nonce
      };

      fed.sendPacket(peerHost, peerPort, payload).catch((err) => {
        log.warn(I18n.t('FED_AUTONAT_PACKET_ERR', { error: err.message }));
        clearTimeout(timer);
        fed.pendingDialbacks.delete(nonce);
        fed.isDialbackRunning = false;
        fed.setRole('EDGE');
        resolve('EDGE');
      });
    });
  }

  handleDialbackConfirm(payload) {
    const fed = this.federation;
    if (!payload || !payload.nonce) return;
    const pending = fed.pendingDialbacks.get(payload.nonce);
    if (pending) {
      clearTimeout(pending.timer);
      fed.pendingDialbacks.delete(payload.nonce);
      fed.isDialbackRunning = false;
      log.info(I18n.t('FED_AUTONAT_VERIFIED'));
      fed.setRole('RELAY');
      pending.resolve('RELAY');
    }
  }

  handleDialbackRequest(payload, channel) {
    const { targetPort, nonce } = payload;
    if (!targetPort || !nonce) return;

    // GUVENLIK (SSRF Korumasi): targetIp yoksayilir, dogrudan soketin uzak IP'si kullanilir
    const rawRemote = channel?.socket?.remoteAddress || '';
    const verifiedIp = rawRemote.replace(/^::ffff:/, '');
    if (!verifiedIp) return;

    const numPort = parseInt(targetPort, 10);
    if (isNaN(numPort) || numPort < 1 || numPort > 65535) return;

    const isLoopback = verifiedIp === '127.0.0.1' || verifiedIp === '::1' || verifiedIp === 'localhost';
    const isPrivate = /^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/.test(verifiedIp);
    const isTesting = process.env.NODE_ENV === 'test' || CONFIG.environment === 'test' || process.argv.some((a) => a.includes('test'));

    if ((isLoopback || isPrivate) && !isTesting) {
      log.warn(I18n.t('FED_AUTONAT_SSRF_BLOCKED', { ip: verifiedIp }));
      return;
    }

    log.info(I18n.t('FED_AUTONAT_INBOUND_REQUEST', { ip: verifiedIp, port: numPort }));
    const dialSocket = net.createConnection({ host: verifiedIp, port: numPort }, () => {
      channel.writePayload({
        type: 'DIALBACK_CONFIRM',
        nonce,
        confirmed: true
      });
      dialSocket.end();
    });

    dialSocket.on('error', () => {
      try { dialSocket.destroy(); } catch {}
    });

    dialSocket.setTimeout(3000, () => {
      try { dialSocket.destroy(); } catch {}
    });
  }
}
