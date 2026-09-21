import net from 'node:net';
import EventEmitter from 'node:events';
import { CONFIG } from '../config/index.js';
import { Logger } from '../utils/logger.js';
import { AddressHelper } from '../utils/addressHelper.js';
import { I18n } from '../locales/i18n.js';
import { OnionRouter } from './onionRouter.js';
import { ProxyProtocolParser } from '../utils/proxyProtocol.js';
import { SecureChannel, NonceTracker, MessageTtlCache } from './secureChannel.js';
import { CryptoHelper } from '../utils/cryptoHelper.js';
import { AutoNatService } from './autoNat.js';
import { RendezvousManager } from './rendezvousManager.js';
import { PresenceManager } from './presenceManager.js';
import { FederationPacketHandler } from './federationPacketHandler.js';

export {
  SecureChannel,
  NonceTracker,
  MessageTtlCache,
  AutoNatService,
  RendezvousManager,
  PresenceManager,
  FederationPacketHandler
};

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

    // Gelismis Guvenlik Mekanizmalari
    this.nonceTracker = new NonceTracker(60000);
    this.seenMessages = new MessageTtlCache(180000); // 3 dakika TTL
    this.connectionPool = new Map();

    const identity = this.db.getNodeIdentity();
    this.identityKeyPair = identity.identityKeyPair;
    this.kemKeyPair = identity.kemKeyPair;
    this.nodeId = identity.nodeId;
    this.meshAddress = `${this.nodeId}.mesh`;
    const publicPort = CONFIG.publicFederationPort || CONFIG.federationPort;
    this.nodeAddress = `${CONFIG.serverName}:${publicPort}`;

    AddressHelper.setLocalNodeId(this.nodeId);

    const self = this;
    this.myIdentity = {
      nodeId: this.nodeId,
      meshAddress: this.meshAddress,
      nodeAddress: this.nodeAddress,
      identityKeyPair: this.identityKeyPair,
      kemKeyPair: this.kemKeyPair,
      get role() { return self.role; },
      getRelayAnnounceAddress: () => self.getRelayAnnounceAddress()
    };

    this.remoteOnlineUsers = new Map();
    this.getLocalStateFn = null;
    this.channelSubscribers = new Map();

    // V2.0 Mimari Degiskenleri
    this.role = process.env.MESH_ROLE || (CONFIG && CONFIG.meshRole) || 'EDGE'; // 'RELAY' veya 'EDGE'
    this.publicIp = null;
    this.observedAddressVotes = new Map(); // ip -> Set<peer>
    this.isDialbackRunning = false;
    this.isMaintainingTunnels = false;
    this.nodePhysicalAddresses = new Map(); // nodeId -> 'host:port'
    this.pendingDialbacks = new Map(); // nonce -> { targetIp, timer, resolve }
    this.rendezvousTunnels = new Map(); // nodeId -> { socket, channel, boundAt }
    this.rendezvousRelays = new Map(); // relayAddr -> { channel, socket }
    this.boundRendezvousRelays = new Set(); // EDGE'in bagli oldugu RELAY'ler
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

    this.autoNat = new AutoNatService(this);
    this.rendezvousManager = new RendezvousManager(this);
    this.presenceManager = new PresenceManager(this);
    this.packetHandler = new FederationPacketHandler(this);

    this.onionRouter.on('deliver_local', (msg) => this.handleLocalDeliveredMessage(msg));

    const roleLabel = this.role.startsWith('CAP_') ? this.role : `CAP_${this.role}`;
    log.info(I18n.t('FED_NODE_IDENTITY_READY', { address: `${this.nodeAddress} (${this.meshAddress}) [${roleLabel}]` }));
  }

  setRole(newRole) {
    if (this.role !== newRole) {
      this.role = newRole;
      if (this.isRelay() && this.publicIp) {
        const isLoopbackOrLocal = !CONFIG.serverName || CONFIG.serverName === 'localhost' || CONFIG.serverName.startsWith('127.') || CONFIG.serverName === '0.0.0.0';
        if (isLoopbackOrLocal) {
          const publicPort = CONFIG.publicFederationPort || CONFIG.federationPort;
          this.nodeAddress = `${this.publicIp}:${publicPort}`;
          this.myIdentity.nodeAddress = this.nodeAddress;
        }
      }
      const roleLabel = this.role.startsWith('CAP_') ? this.role : `CAP_${this.role}`;
      log.info(I18n.t('FED_ROLE_UPDATED', { role: roleLabel }));
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

  isSelfPeerAddress(host, port) {
    if (this.peerManager && typeof this.peerManager.isSelfAddress === 'function') {
      return this.peerManager.isSelfAddress(host, port);
    }
    const pubPort = CONFIG.publicFederationPort || CONFIG.federationPort;
    if (port !== null && port !== undefined && port !== CONFIG.federationPort && port !== pubPort) return false;
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
    if (this.publicIp && (host === this.publicIp || host === `::ffff:${this.publicIp}`)) {
      return true;
    }
    return false;
  }

  isTransitEdge() {
    return this.role === 'CAP_EDGE_TRANSIT' || (CONFIG.allowEdgeRouting && this.rendezvousRelays && this.rendezvousRelays.size >= 2);
  }

  checkTransitEdgeRole() {
    if (this.isRelay()) return;
    if (CONFIG.allowEdgeRouting && this.rendezvousRelays && this.rendezvousRelays.size >= 2) {
      if (this.role !== 'CAP_EDGE_TRANSIT') {
        this.setRole('CAP_EDGE_TRANSIT');
      }
    } else {
      if (this.role === 'CAP_EDGE_TRANSIT') {
        this.setRole('EDGE');
      }
    }
  }

  setLocalStateGetter(fn) {
    this.getLocalStateFn = fn;
  }

  getAllOnlineUsers() {
    return this.presenceManager.getAllOnlineUsers();
  }

  getChannelMembers(channelName) {
    return this.presenceManager.getChannelMembers(channelName);
  }

  getRemoteUserSecurity(userAddress) {
    return this.presenceManager.getRemoteUserSecurity(userAddress);
  }

  start() {
    this.peerManager.startLanDiscovery();

    this.server = net.createServer((socket) => {
      const setupChannel = () => {
        const remotePeer = `${socket.realRemoteAddress || socket.remoteAddress}:${socket.realRemotePort || socket.remotePort}`;
        log.info(I18n.t('FED_INCOMING_CONN', { peer: remotePeer }));

        const secureChannel = new SecureChannel(socket, false, this.myIdentity, this.db, this.nonceTracker);

        secureChannel.on('payload', (payload) => {
          this.handleIncoming(payload, secureChannel, remotePeer);
        });

        secureChannel.on('dialback_confirm', (frame) => {
          this.handleDialbackConfirm(frame);
        });

        secureChannel.on('onion_cell', (cell) => {
          this.onionRouter.handleOnionCell(cell, secureChannel).catch((err) => {
            log.error(I18n.t('ONION_CELL_ASYNC_ERR', { error: err.message }));
          });
        });

        secureChannel.on('observed_address', (addr, peer) => {
          this.handleObservedAddress(addr, peer);
        });

        secureChannel.on('error', (err) => {
          log.error(I18n.t('FED_SOCKET_ERROR', { peer: remotePeer, error: err.message }));
        });
      };

      if (CONFIG.useProxyProtocol) {
        ProxyProtocolParser.handle(socket, { trustedIps: CONFIG.proxyProtocolTrustedIps }, (err) => {
          if (err) {
            log.warn(I18n.t('FED_PROXY_HANDSHAKE_ERR', { error: err.message }));
            return;
          }
          setupChannel();
        });
      } else {
        setupChannel();
      }
    });

    this.server.listen(CONFIG.federationPort, () => {
      log.info(I18n.t('FED_LISTENING', { port: CONFIG.federationPort }));
      this.startWorkers();
    });
  }

  startWorkers() {
    this.isProcessingOutbox = false;
    const scheduleOutbox = async () => {
      if (this.isClosed) return;
      if (this.isProcessingOutbox) {
        this.outboxTimeout = setTimeout(scheduleOutbox, 2000);
        return;
      }
      this.isProcessingOutbox = true;
      try {
        await this.processOutbox();
      } catch (err) {
        log.error(I18n.t('FED_OUTBOX_EXCEPTION', { error: err.message }));
      } finally {
        this.isProcessingOutbox = false;
        if (!this.isClosed) {
          this.outboxTimeout = setTimeout(scheduleOutbox, 5000);
        }
      }
    };
    this.outboxTimeout = setTimeout(scheduleOutbox, 5000);

    const scheduleGossip = () => {
      if (this.isClosed) return;
      const jitter = 12000 + Math.floor(Math.random() * 6000);
      this.gossipTimeout = setTimeout(async () => {
        try {
          await this.performRandomGossip();
        } catch (err) {
          log.error(I18n.t('FED_GOSSIP_WORKER_EXCEPTION', { error: err.message }));
        } finally {
          if (!this.isClosed) {
            scheduleGossip();
          }
        }
      }, jitter);
    };
    scheduleGossip();

    this.presenceInterval = setInterval(() => this.broadcastPresence(), 10000);
    this.rendezvousHeartbeatInterval = setInterval(() => this.sendRendezvousHeartbeat(), 30000);
    this.maintainRendezvousInterval = setInterval(() => this.maintainRendezvousTunnels(), 15000);
    this.presenceCleanupInterval = setInterval(() => this.cleanupExpiredPresence(), 30000);
  }

  handleIncoming(payload, channel, remotePeer) {
    return this.packetHandler.handleIncoming(payload, channel, remotePeer);
  }

  forwardToChannelSubscribers(channelName, msg, exceptPeer = null) {
    return this.packetHandler.forwardToChannelSubscribers(channelName, msg, exceptPeer);
  }

  getOrCreateSecureChannel(host, port) {
    if (!host || host === 'null') {
      return Promise.reject(new Error(`Invalid host or port: ${host}:${port}`));
    }

    let targetHost = host;
    let targetPort = port;

    // Alt ag seviyesinde fiziksel IP cozumlemesi (.mesh veya NodeID)
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
          // Eger rota adresinde ozel bir port varsa onu kullan, yoksa isteneni kullan
          targetPort = parsed.port || targetPort || CONFIG.federationPort;
        } else {
          const [rHost, rPortStr] = resolved.split(':');
          targetHost = rHost;
          if (rPortStr) {
            targetPort = parseInt(rPortStr, 10);
          }
        }
      } else {
        return Promise.reject(new Error(`Target node ${targetHost} cannot be resolved to a physical address`));
      }
    } else if (typeof targetHost === 'string' && targetHost.includes(':')) {
      const parsed = AddressHelper.parseTarget(targetHost);
      if (parsed && parsed.host) {
        targetHost = parsed.host;
        targetPort = parsed.port || targetPort || CONFIG.federationPort;
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
        this.onionRouter.handleOnionCell(cell, secureChannel).catch((err) => {
          log.error(I18n.t('ONION_CELL_ASYNC_ERR', { error: err.message }));
        });
      });

      secureChannel.on('observed_address', (addr, peer) => {
        this.handleObservedAddress(addr, peer);
      });

      secureChannel.on('ready', () => {
        rawSocket.setTimeout(0);
        log.info(I18n.t('FED_CONNECTED', { host, port }));
        if (this.peerManager && typeof this.peerManager.addOrUpdate === 'function') {
          this.peerManager.addOrUpdate(`${targetHost}:${targetPort}`, true, false);
        }
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

  broadcastPresence() {
    return this.presenceManager.broadcastPresence();
  }

  broadcastUserOffline(userAddress) {
    return this.presenceManager.broadcastUserOffline(userAddress);
  }

  broadcastChannelMessage(msg, exceptPeer = null) {
    return this.presenceManager.broadcastChannelMessage(msg, exceptPeer);
  }

  performRandomGossip() {
    return this.presenceManager.performRandomGossip();
  }

  subscribeRemoteChannel(host, port, channel) {
    return this.presenceManager.subscribeRemoteChannel(host, port, channel);
  }

  unsubscribeRemoteChannel(host, port, channel) {
    return this.presenceManager.unsubscribeRemoteChannel(host, port, channel);
  }

  subscribeNodeChannel(nodeId, channel) {
    return this.presenceManager.subscribeNodeChannel(nodeId, channel);
  }

  unsubscribeNodeChannel(nodeId, channel) {
    return this.presenceManager.unsubscribeNodeChannel(nodeId, channel);
  }

  // --- AUTONAT & DIALBACK METOTLARI ---
  handleObservedAddress(observedAddress, peer) {
    return this.autoNat.handleObservedAddress(observedAddress, peer);
  }

  initiateDialback(targetIp) {
    return this.autoNat.initiateDialback(targetIp);
  }

  handleDialbackConfirm(payload) {
    return this.autoNat.handleDialbackConfirm(payload);
  }

  // --- BULUSMA NOKTASI & TERS TUNEL METOTLARI ---
  maintainRendezvousTunnels() {
    return this.rendezvousManager.maintainRendezvousTunnels();
  }

  bindToRendezvousRelay(relayAddr) {
    return this.rendezvousManager.bindToRendezvousRelay(relayAddr);
  }

  sendRendezvousHeartbeat() {
    return this.rendezvousManager.sendRendezvousHeartbeat();
  }

  // --- VARLIK & ONION METOTLARI ---
  getLocalChannels() {
    return this.presenceManager.getLocalChannels();
  }

  getRelayAnnounceAddress() {
    return this.presenceManager.getRelayAnnounceAddress();
  }

  broadcastRouteUpdate(nodeId, rendezvousAddr, kemPublicKey, identityPublicKey) {
    return this.presenceManager.broadcastRouteUpdate(nodeId, rendezvousAddr, kemPublicKey, identityPublicKey);
  }

  createPresenceAnnouncePayload() {
    return this.presenceManager.createPresenceAnnouncePayload();
  }

  broadcastPresenceAnnounce() {
    return this.presenceManager.broadcastPresenceAnnounce();
  }

  cleanupExpiredPresence() {
    return this.presenceManager.cleanupExpiredPresence();
  }

  handleLocalDeliveredMessage(payload) {
    if (!payload) return;
    if (!payload.type) {
      if (payload.to && payload.to.startsWith('#')) {
        payload.type = 'CHANNEL_MESSAGE';
      } else if (payload.to && payload.to.startsWith('@')) {
        payload.type = 'DIRECT_MESSAGE';
      }
    }
    const mockChannel = {
      socket: null,
      writePayload: () => {}
    };
    this.handleIncoming(payload, mockChannel, null);
  }

  async sendViaOnion(targetNodeId, payload, fromOutbox = false) {
    if (targetNodeId && this.rendezvousTunnels.has(targetNodeId)) {
      const localTunnel = this.rendezvousTunnels.get(targetNodeId);
      if (localTunnel && localTunnel.channel && localTunnel.channel.socket && localTunnel.channel.socket.writable) {
        localTunnel.channel.writePayload(payload);
        return { status: 'delivered' };
      }
    }

    if (targetNodeId && this.rendezvousRelays) {
      for (const [relayAddr, rObj] of this.rendezvousRelays.entries()) {
        const rChan = rObj.channel;
        const rSock = rObj.socket || rChan?.socket;
        if (rSock && rSock.writable === false) continue;
        const rNodeId = rChan?.peerIdentityKey ? CryptoHelper.deriveNodeId(rChan.peerIdentityKey) : null;
        if (targetNodeId === rNodeId || this.nodePhysicalAddresses.get(targetNodeId) === relayAddr) {
          if (rChan && typeof rChan.writePayload === 'function') {
            rChan.writePayload(payload);
            return { status: 'delivered' };
          }
        }
      }
    }

    let route = this.presenceTable.get(targetNodeId) || this.db.getRoute(targetNodeId);
    let exitRelayAddress = null;

    if (route && Array.isArray(route.rendezvousNodes) && route.rendezvousNodes.length > 0) {
      const nonSelf = route.rendezvousNodes.find((addr) =>
        addr !== this.nodeAddress &&
        addr !== this.meshAddress &&
        addr !== this.getRelayAnnounceAddress() &&
        addr !== `${CONFIG.serverName}:${CONFIG.federationPort}` &&
        addr !== `${CONFIG.serverName}:${CONFIG.publicFederationPort || CONFIG.federationPort}`
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
      if (fromOutbox) {
        throw new Error(I18n.t('FED_TARGET_NO_RDV_ERR', { node: targetNodeId }));
      }
      log.info(I18n.t('FED_NO_ACTIVE_RDV', { node: targetNodeId }));
      this.db.queueOutbox(payload);
      return { status: 'queued' };
    }

    const allRoutes = this.db.getAllRoutes();
    const relayPool = [];
    const isRelayOrTransit = (role) => role === 'RELAY' || role === 'CAP_RELAY' || role === 'CAP_EDGE_TRANSIT';

    const addRelayToPool = (nodeId, address, kemPublicKey) => {
      if (!address || !kemPublicKey) return;
      if (nodeId === this.nodeId) return;
      if (!relayPool.some((rp) => rp.address === address)) {
        relayPool.push({ nodeId, address, kemPublicKey });
      }
    };

    for (const r of allRoutes) {
      if (isRelayOrTransit(r.role) && r.nodeId !== this.nodeId) {
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
      if (isRelayOrTransit(p.role) && nid !== this.nodeId) {
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

    if (this.rendezvousRelays) {
      for (const [relayAddr, rObj] of this.rendezvousRelays.entries()) {
        const rChan = rObj.channel;
        if (rChan && rChan.peerKemKey && rChan.peerIdentityKey) {
          const rNodeId = CryptoHelper.deriveNodeId(rChan.peerIdentityKey);
          addRelayToPool(rNodeId, relayAddr, rChan.peerKemKey);
        }
      }
    }

    const peers = this.peerManager ? this.peerManager.getAllPeers() : [];
    for (const p of peers) {
      if (!relayPool.some((rp) => rp.address === p)) {
        const peerRoute = allRoutes.find((r) =>
          (Array.isArray(r.rendezvousNodes) && r.rendezvousNodes.includes(p)) ||
          this.nodePhysicalAddresses.get(r.nodeId) === p
        ) || Array.from(this.presenceTable.values()).find((pr) =>
          (Array.isArray(pr.rendezvousNodes) && pr.rendezvousNodes.includes(p)) ||
          this.nodePhysicalAddresses.get(pr.nodeId) === p
        );
        if (peerRoute && isRelayOrTransit(peerRoute.role)) {
          addRelayToPool(peerRoute.nodeId, p, peerRoute.kemPublicKey);
        }
      }
    }

    let exitHop = null;
    if (exitRelayAddress) {
      exitHop = relayPool.find((r) => r.address === exitRelayAddress);
      if (!exitHop && this.rendezvousRelays) {
        for (const [relayAddr, rObj] of this.rendezvousRelays.entries()) {
          if (relayAddr === exitRelayAddress || exitRelayAddress.includes(relayAddr) || relayAddr.includes(exitRelayAddress)) {
            const rChan = rObj.channel;
            if (rChan && rChan.peerKemKey && rChan.peerIdentityKey) {
              const rNodeId = CryptoHelper.deriveNodeId(rChan.peerIdentityKey);
              exitHop = {
                nodeId: rNodeId,
                address: exitRelayAddress,
                kemPublicKey: rChan.peerKemKey
              };
              break;
            }
          }
        }
      }

      if (!exitHop) {
        const relayMatch = allRoutes.find((r) =>
          isRelayOrTransit(r.role) &&
          (
            (Array.isArray(r.rendezvousNodes) && r.rendezvousNodes.includes(exitRelayAddress)) ||
            (r.nodeId && exitRelayAddress.includes(r.nodeId)) ||
            this.nodePhysicalAddresses.get(r.nodeId) === exitRelayAddress
          )
        ) || Array.from(this.presenceTable.values()).find((p) =>
          isRelayOrTransit(p.role) &&
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

      if (!exitHop && route && isRelayOrTransit(route.role) && route.kemPublicKey) {
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
      log.info(I18n.t('FED_NO_EXIT_NODE', { node: targetNodeId, exit: exitRelayAddress }));
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

      try {
        circuit = await this.onionRouter.buildCircuit(hops, targetNodeId);
      } catch {
        const guardAddr = hops[0].address;
        let deadChannel = this.connectionPool.get(guardAddr);
        if (!deadChannel && guardAddr.includes(':')) {
          const [gHost, gPortStr] = guardAddr.split(':');
          const parsed = AddressHelper.parseTarget(guardAddr);
          const resolvedKey = parsed?.host ? `${parsed.host}:${parsed.port}` : `${gHost}:${gPortStr}`;
          deadChannel = this.connectionPool.get(resolvedKey);
          this.connectionPool.delete(resolvedKey);
        }
        if (deadChannel?.socket) {
          try { deadChannel.socket.destroy(); } catch {}
        }
        this.connectionPool.delete(guardAddr);
        circuit = await this.onionRouter.buildCircuit(hops, targetNodeId);
      }
    }

    try {
      return await this.onionRouter.sendOnionCell(circuit, targetNodeId, payload);
    } catch (err) {
      this.onionRouter.removeClientCircuit(circuit.circuitId);
      throw err;
    }
  }

  async processOutbox(forceAll = false) {
    if (this.isClosed || !this.db || !this.db.db || (typeof this.db.db.open === 'boolean' && !this.db.db.open)) return;
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
          const res = await this.sendViaOnion(target.nodeId, payload, true);
          if (res && res.status === 'queued') {
            this.db.updateOutboxRetry(item.id);
            continue;
          }
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
    if (!target) throw new Error(I18n.t('FED_INVALID_TARGET_ERR', { target: to }));

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

    // 1. Kuresel Kanal (#genel)
    if (target.isGlobalChannel) {
      this.broadcastChannelMessage(payload);
      return { status: 'broadcasted' };
    }

    // 2. V2.0 Kriptografik Dugum Adresi (@user:NodeID.mesh veya #channel:NodeID.mesh)
    if (target.nodeId) {
      if (target.nodeId === this.nodeId) {
        const msg = this.db.saveMessage(payload);
        if (msg) {
          this.emit('message', msg);
          if (target.type === 'CHANNEL') {
            this.forwardToChannelSubscribers(target.raw, msg);
          }
        }
        return { status: 'delivered' };
      }

      // Doğrudan bağlı olunan Rendezvous Relayı kontrolü (hedefin kendisi, hedefin rendezvous düğümü veya varsayılan ağ geçidi)
      if (this.rendezvousRelays && this.rendezvousRelays.size > 0) {
        const route = this.presenceTable.get(target.nodeId) || this.db.getRoute(target.nodeId);
        const targetRdvList = Array.isArray(route?.rendezvousNodes) ? route.rendezvousNodes : [];

        const targetRelayChans = [];
        let defaultRelayChan = null;

        for (const [relayAddr, rObj] of this.rendezvousRelays.entries()) {
          const rChan = rObj.channel;
          const rSock = rObj.socket || rChan?.socket;
          if (rSock && rSock.writable === false) continue;
          const rNodeId = rChan?.peerIdentityKey ? CryptoHelper.deriveNodeId(rChan.peerIdentityKey) : null;

          const isDirectRelay = target.nodeId === rNodeId || this.nodePhysicalAddresses.get(target.nodeId) === relayAddr;
          const isTargetRdv = targetRdvList.some((rn) => rn === relayAddr || rn.includes(relayAddr) || relayAddr.includes(rn));

          if (isDirectRelay || isTargetRdv) {
            targetRelayChans.push(rChan);
          }
          if (!defaultRelayChan) {
            defaultRelayChan = rChan;
          }
        }

        // Hedef röle biliniyorsa doğrudan o röleye; bilinmiyorsa bağlı olunan tüm rölelere fan-out:
        const dispatchChans = targetRelayChans.length > 0
          ? targetRelayChans
          : (!this.isRelay()
              ? Array.from(this.rendezvousRelays.values()).map((r) => r.channel).filter((c) => (!c?.socket || c.socket.writable !== false))
              : (defaultRelayChan ? [defaultRelayChan] : []));

        let sentAny = false;
        for (const ch of dispatchChans) {
          if (ch && typeof ch.writePayload === 'function') {
            ch.writePayload(payload);
            sentAny = true;
          }
        }

        if (sentAny) {
          return { status: 'delivered' };
        }
      }

      try {
        return await this.sendViaOnion(target.nodeId, payload);
      } catch (err) {
        log.warn(I18n.t('FED_ONION_SEND_ERR', { node: target.nodeId, error: err.message }));
        this.db.queueOutbox(payload);
        return { status: 'queued' };
      }
    }

    // 3. V1.x Geriye Donuk Uyumluluk (host:port)
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
    this.isClosed = true;
    if (this.outboxInterval) clearInterval(this.outboxInterval);
    if (this.outboxTimeout) clearTimeout(this.outboxTimeout);
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