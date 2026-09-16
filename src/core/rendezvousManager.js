import { CONFIG } from '../config/index.js';
import { Logger } from '../utils/logger.js';
import { CryptoHelper } from '../utils/cryptoHelper.js';
import { I18n } from '../locales/i18n.js';

const log = new Logger('RENDEZVOUS');

export class RendezvousManager {
  constructor(federation) {
    this.federation = federation;
  }

  async maintainRendezvousTunnels() {
    const fed = this.federation;
    if (fed.isRelay() || fed.isMaintainingTunnels) return;

    fed.isMaintainingTunnels = true;
    try {
      const targets = [];

      const isCandidateValid = (addr) => {
        if (!addr || typeof addr !== 'string' || !addr.includes(':')) return false;
        if (addr.endsWith('.mesh')) return false;
        const [host, portStr] = addr.split(':');
        const port = parseInt(portStr, 10);
        if (!host || isNaN(port) || port <= 0 || port > 65535) return false;
        if (fed.isSelfPeerAddress(host, port)) return false;
        if (addr === fed.nodeAddress) return false;
        return true;
      };

      // 1. Yapilandirilmis bootstrap esleri
      if (Array.isArray(CONFIG && CONFIG.bootstrapPeers)) {
        for (const bp of CONFIG.bootstrapPeers) {
          if (isCandidateValid(bp) && !targets.includes(bp)) targets.push(bp);
        }
      }

      // 2. Rota tablosundaki tum RELAY dugumleri
      const routes = fed.db.getAllRoutes();
      const candidateRelays = routes.filter((r) => (r.role === 'RELAY' || r.role === 'CAP_RELAY') && r.nodeId !== fed.nodeId);
      for (const r of candidateRelays) {
        if (Array.isArray(r.rendezvousNodes)) {
          for (const rn of r.rendezvousNodes) {
            if (isCandidateValid(rn) && !targets.includes(rn)) targets.push(rn);
          }
        }
        if (fed.nodePhysicalAddresses.has(r.nodeId)) {
          const pAddr = fed.nodePhysicalAddresses.get(r.nodeId);
          if (isCandidateValid(pAddr) && !targets.includes(pAddr)) targets.push(pAddr);
        }
      }

      // 3. RAM varlik tablosundaki (presenceTable) RELAY dugumleri
      for (const [nid, p] of fed.presenceTable.entries()) {
        if ((p.role === 'RELAY' || p.role === 'CAP_RELAY') && nid !== fed.nodeId) {
          if (Array.isArray(p.rendezvousNodes)) {
            for (const rn of p.rendezvousNodes) {
              if (isCandidateValid(rn) && !targets.includes(rn)) targets.push(rn);
            }
          }
          if (fed.nodePhysicalAddresses.has(nid)) {
            const pAddr = fed.nodePhysicalAddresses.get(nid);
            if (isCandidateValid(pAddr) && !targets.includes(pAddr)) targets.push(pAddr);
          }
        }
      }

      // 4. Bilinen tum esler
      const knownPeers = fed.peerManager ? fed.peerManager.getAllPeers() : [];
      for (const p of knownPeers) {
        if (isCandidateValid(p) && !targets.includes(p)) targets.push(p);
      }

      const maxRelays = (CONFIG && CONFIG.maxEdgeRendezvousRelays) ? CONFIG.maxEdgeRendezvousRelays : 4;
      for (const relayAddr of targets) {
        if (!isCandidateValid(relayAddr)) continue;
        if (fed.boundRendezvousRelays.size >= maxRelays) break;
        if (fed.boundRendezvousRelays.has(relayAddr)) continue;
        await this.bindToRendezvousRelay(relayAddr);
      }
    } finally {
      fed.isMaintainingTunnels = false;
    }
  }

  async bindToRendezvousRelay(relayAddr) {
    const fed = this.federation;
    if (!relayAddr || !relayAddr.includes(':')) return false;
    const [host, portStr] = relayAddr.split(':');
    const port = parseInt(portStr, 10);
    if (!host || isNaN(port) || port <= 0 || port > 65535) return false;
    if (fed.isSelfPeerAddress(host, port)) return false;
    if (relayAddr === fed.nodeAddress) return false;

    try {
      const channel = await fed.getOrCreateSecureChannel(host, port);
      const nonce = CryptoHelper.generateRandomKey(16);
      const timestamp = Date.now();
      const sig = CryptoHelper.sign(`${fed.nodeId}${relayAddr}${timestamp}${nonce}`, fed.identityKeyPair.privateKey);

      const bindPayload = {
        type: 'RENDEZVOUS_BIND',
        nodeId: fed.nodeId,
        relayAddress: relayAddr,
        identityPublicKey: fed.identityKeyPair.publicKey,
        kemPublicKey: fed.kemKeyPair.publicKey,
        timestamp,
        nonce,
        sig
      };

      const res = await fed.sendPacket(host, port, bindPayload);
      if (res && res.status === 'bound') {
        fed.boundRendezvousRelays.add(relayAddr);
        fed.rendezvousRelays.set(relayAddr, { channel, socket: channel.socket });
        fed.checkTransitEdgeRole();
        log.info(I18n.t('FED_RDV_CONNECTED', { relay: relayAddr }));

        fed.broadcastPresenceAnnounce();

        if (channel.peerNodeAddress && channel.peerIdentityKey) {
          const rNodeId = CryptoHelper.deriveNodeId(channel.peerIdentityKey);
          fed.presenceTable.set(rNodeId, {
            nodeId: rNodeId,
            role: 'RELAY',
            rendezvousNodes: [relayAddr],
            kemPublicKey: channel.peerKemKey,
            identityPublicKey: channel.peerIdentityKey,
            channels: [],
            lastSeen: Date.now()
          });
          fed.nodePhysicalAddresses.set(rNodeId, relayAddr);
          fed.db.upsertRoute({
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
            fed.boundRendezvousRelays.delete(relayAddr);
            fed.rendezvousRelays.delete(relayAddr);
            fed.checkTransitEdgeRole();
            log.warn(I18n.t('FED_RDV_DISCONNECTED', { relay: relayAddr }));
            setTimeout(() => this.maintainRendezvousTunnels(), 2000);
          });
        }
        if (fed.db && typeof fed.db.resetOutboxForTarget === 'function') {
          fed.db.resetOutboxForTarget(relayAddr);
        }
        setImmediate(() => fed.processOutbox(true));
        return true;
      }
    } catch (err) {
      log.debug(I18n.t('FED_RDV_CONN_ERR', { relay: relayAddr, error: err.message }));
    }
    return false;
  }

  sendRendezvousHeartbeat() {
    const fed = this.federation;
    if (fed.isRelay() || fed.boundRendezvousRelays.size === 0) return;

    const now = Date.now();
    let needsMaintenance = false;

    for (const relayAddr of fed.boundRendezvousRelays) {
      const [host, portStr] = relayAddr.split(':');
      const port = parseInt(portStr, 10);
      const key = `${host}:${port}`;
      const channel = fed.connectionPool.get(key);

      if (channel && channel.socket && !channel.socket.destroyed) {
        // Zombi tunel tespiti: 60 saniyeden uzun suredir PONG alinmadiysa soketi kapat ve tuneli yenile
        if (channel.lastPong && (now - channel.lastPong > 60000)) {
          log.warn(I18n.t('FED_RDV_ZOMBIE_DETECTED', { relay: relayAddr }));
          channel.socket.destroy();
          fed.connectionPool.delete(key);
          fed.boundRendezvousRelays.delete(relayAddr);
          fed.rendezvousRelays.delete(relayAddr);
          fed.checkTransitEdgeRole();
          needsMaintenance = true;
          continue;
        }

        if (channel.socket.writable) {
          try {
            channel.socket.write(Buffer.from([0x09]));
          } catch {}
        }
      } else {
        fed.boundRendezvousRelays.delete(relayAddr);
        fed.rendezvousRelays.delete(relayAddr);
        fed.checkTransitEdgeRole();
        needsMaintenance = true;
      }
    }

    if (needsMaintenance) {
      this.maintainRendezvousTunnels().catch(() => {});
    }
  }

  handleRendezvousBind(payload, channel) {
    const fed = this.federation;
    const { nodeId, identityPublicKey, timestamp, nonce, sig } = payload;
    if (!nodeId || !identityPublicKey || !timestamp || !nonce || !sig) {
      channel.writePayload({ status: 'rejected', reason: 'missing_fields' });
      return;
    }

    const derivedId = CryptoHelper.deriveNodeId(identityPublicKey);
    if (derivedId !== nodeId) {
      log.warn(I18n.t('FED_RDV_NODE_ID_MISMATCH', { expected: nodeId, derived: derivedId }));
      channel.writePayload({ status: 'rejected', reason: 'invalid_node_id' });
      return;
    }

    const cleanLocal = (channel?.socket?.localAddress || '').replace(/^::ffff:/, '');
    const localSockAddr = cleanLocal ? `${cleanLocal}:${channel.socket.localPort}` : null;
    const bracketSockAddr = cleanLocal && cleanLocal.includes(':')
      ? `[${cleanLocal}]:${channel.socket.localPort}`
      : null;
    const hostAddr = fed.nodeAddress;
    const meshAddr = fed.meshAddress;
    const announceAddr = fed.getRelayAnnounceAddress();

    const validRelayAddresses = new Set([
      hostAddr,
      meshAddr,
      announceAddr
    ]);
    if (localSockAddr) validRelayAddresses.add(localSockAddr);
    if (bracketSockAddr) validRelayAddresses.add(bracketSockAddr);

    if (fed.nodeAddress && fed.nodeAddress.startsWith('localhost:')) {
      validRelayAddresses.add(fed.nodeAddress.replace('localhost:', '127.0.0.1:'));
    }

    const publicPort = CONFIG.publicFederationPort || CONFIG.federationPort;
    if (fed.publicIp) {
      validRelayAddresses.add(`${fed.publicIp}:${CONFIG.federationPort}`);
      validRelayAddresses.add(`${fed.publicIp}:${publicPort}`);
    }
    validRelayAddresses.add(`${CONFIG.serverName || '127.0.0.1'}:${CONFIG.federationPort}`);
    validRelayAddresses.add(`${CONFIG.serverName || '127.0.0.1'}:${publicPort}`);
    if (CONFIG.serverName === 'localhost') {
      validRelayAddresses.add(`127.0.0.1:${CONFIG.federationPort}`);
      validRelayAddresses.add(`127.0.0.1:${publicPort}`);
    }

    let isSigValid = false;
    for (const addr of validRelayAddresses) {
      if (!addr) continue;
      if (CryptoHelper.verify(`${nodeId}${addr}${timestamp}${nonce}`, sig, identityPublicKey)) {
        isSigValid = true;
        break;
      }
    }

    if (!isSigValid) {
      log.warn(I18n.t('FED_RDV_INVALID_SIG', { node: nodeId }));
      channel.writePayload({ status: 'rejected', reason: 'invalid_signature' });
      return;
    }

    if (Math.abs(Date.now() - timestamp) > 86400000) {
      channel.writePayload({ status: 'rejected', reason: 'expired_timestamp' });
      return;
    }

    // DoS siniri (maksimum aktif tunel kapasitesi)
    const maxTunnels = (CONFIG && CONFIG.maxRendezvousTunnels) || 64;
    if (fed.rendezvousTunnels.size >= maxTunnels && !fed.rendezvousTunnels.has(nodeId)) {
      log.warn(I18n.t('FED_RDV_CAPACITY_REACHED', { current: fed.rendezvousTunnels.size, max: maxTunnels, node: nodeId }));
      channel.writePayload({ status: 'rejected', reason: 'tunnel_capacity_reached' });
      return;
    }

    // IP basina azami tunel siniri (Sybil DoS korumasi)
    const rawRemote = channel?.socket?.remoteAddress || '';
    const cleanRemote = rawRemote.replace(/^::ffff:/, '');
    const isLoopback = cleanRemote === '127.0.0.1' || cleanRemote === '::1' || cleanRemote === 'localhost';
    const isTestMode = process.env.NODE_ENV === 'test' || isLoopback || !cleanRemote;

    if (!isTestMode) {
      let activeIpTunnels = 0;
      for (const t of fed.rendezvousTunnels.values()) {
        const tIp = (t.socket?.remoteAddress || '').replace(/^::ffff:/, '');
        if (tIp === cleanRemote) activeIpTunnels++;
      }
      const maxPerIp = (CONFIG && CONFIG.maxRendezvousPerIp) || 3;
      if (activeIpTunnels >= maxPerIp && !fed.rendezvousTunnels.has(nodeId)) {
        log.warn(I18n.t('FED_RDV_IP_LIMIT_REACHED', { ip: cleanRemote, max: maxPerIp }));
        channel.writePayload({ status: 'rejected', reason: 'ip_capacity_reached' });
        return;
      }
    }

    const relayAnnounceAddr = fed.getRelayAnnounceAddress();
    const boundRendezvousAddr = payload.relayAddress || relayAnnounceAddr;
    const edgeKemKey = payload.kemPublicKey || channel?.peerKemKey || fed.presenceTable.get(nodeId)?.kemPublicKey || fed.db.getRoute(nodeId)?.kemPublicKey;

    fed.rendezvousTunnels.set(nodeId, {
      socket: channel.socket,
      channel,
      boundAt: Date.now(),
      boundRendezvousAddr,
      edgeKemKey,
      identityPublicKey
    });

    fed.presenceTable.set(nodeId, {
      nodeId,
      role: 'EDGE',
      rendezvousNodes: [boundRendezvousAddr],
      kemPublicKey: edgeKemKey,
      identityPublicKey,
      channels: [],
      lastSeen: Date.now()
    });

    fed.db.upsertRoute({
      nodeId,
      role: 'EDGE',
      rendezvousNodes: [boundRendezvousAddr],
      kemPublicKey: edgeKemKey,
      identityPublicKey,
      lastSeen: Date.now()
    });

    if (channel?.socket && typeof channel.socket.once === 'function') {
      channel.socket.once('close', () => {
        if (fed.rendezvousTunnels.get(nodeId)?.socket === channel.socket) {
          fed.rendezvousTunnels.delete(nodeId);
          log.info(I18n.t('FED_RDV_TUNNEL_CLOSED', { node: nodeId }));
          fed.broadcastPresence();
        }
      });
    }

    channel.writePayload({ type: 'RENDEZVOUS_ACK', status: 'bound', nodeId });
    log.info(I18n.t('FED_RDV_BOUND_SUCCESS', { node: nodeId, total: fed.rendezvousTunnels.size }));

    fed.broadcastRouteUpdate(nodeId, boundRendezvousAddr, edgeKemKey, identityPublicKey);
    fed.broadcastPresence();
  }
}
