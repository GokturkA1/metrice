import { CONFIG } from '../config/index.js';
import { Logger } from '../utils/logger.js';
import { AddressHelper } from '../utils/addressHelper.js';
import { CryptoHelper } from '../utils/cryptoHelper.js';
import { I18n } from '../locales/i18n.js';

const log = new Logger('FED_PKT');

export class FederationPacketHandler {
  constructor(federation) {
    this.federation = federation;
    this.seenPresenceAnnounces = new Set();
    this.seenRouteUpdates = new Set();
    this.seenOfflineAnnounces = new Set();
  }

  handleIncoming(payload, channel, remotePeer) {
    if (!payload || !payload.type) return;
    if (payload.status === 'ack') return;

    const fed = this.federation;

    // 0. AutoNAT Inbound Reachability Dialback
    if (payload.type === 'DIALBACK_REQUEST') {
      fed.autoNat.handleDialbackRequest(payload, channel);
      return;
    }

    if (payload.type === 'DIALBACK_CONFIRM') {
      fed.autoNat.handleDialbackConfirm(payload);
      return;
    }

    // 0.0. Katmanli Sogan Hucresi
    if (payload.type === 'ONION_CELL') {
      fed.onionRouter.handleIncomingCell(payload, channel);
      return;
    }

    // 0.1. Bulusma Noktasi Yetkilendirmesi
    if (payload.type === 'RENDEZVOUS_BIND') {
      fed.rendezvousManager.handleRendezvousBind(payload, channel);
      return;
    }

    // 0.2. Onion Devre Kurulumu
    if (payload.type === 'CIRCUIT_CREATE' || payload.type === 'CIRCUIT_EXTEND') {
      fed.onionRouter.handleCircuitSetup(payload, channel);
      return;
    }

    // 0.3. Dagitik Varlik ve Bulusma Noktasi Gossip Dagitimi
    if (payload.type === 'PRESENCE_ANNOUNCE') {
      this.handlePresenceAnnounce(payload, channel, remotePeer);
      return;
    }

    // 0.4. Capraz Role Rota Guncellemesi
    if (payload.type === 'ROUTE_UPDATE') {
      this.handleRouteUpdate(payload, channel, remotePeer);
      return;
    }

    // 1. Mesaj Dagitimi
    if (payload.type === 'DIRECT_MESSAGE' || payload.type === 'CHANNEL_MESSAGE') {
      this.handleDirectOrChannelMessage(payload, channel, remotePeer);
      return;
    }

    // 2. Uzak Kanal Abonelikleri
    if (payload.type === 'CHANNEL_SUBSCRIBE') {
      this.handleChannelSubscribe(payload, channel);
      return;
    }
    if (payload.type === 'CHANNEL_UNSUBSCRIBE') {
      this.handleChannelUnsubscribe(payload, channel);
      return;
    }

    // 3. Yaziyor (Typing), Presence & Gossip
    if (payload.type === 'TYPING') {
      this.handleTyping(payload);
      return;
    }
    if (payload.type === 'USER_OFFLINE') {
      this.handleUserOffline(payload, channel, remotePeer);
      return;
    }
    if (payload.type === 'GOSSIP_DISCOVERY') {
      this.handleGossipDiscovery(payload, channel);
      return;
    }
  }

  handlePresenceAnnounce(payload, channel, remotePeer) {
    const fed = this.federation;
    const { nodeId, role, rendezvousNodes, kemPublicKey, identityPublicKey, channels, timestamp, sig } = payload;
    if (!nodeId || !kemPublicKey || !identityPublicKey || !sig) return;

    if (nodeId === fed.nodeId) return;

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
    if (Math.abs(Date.now() - timestamp) > 86400000) {
      log.warn(I18n.t('FED_PRESENCE_ANNOUNCE_SKEW', { node: nodeId, seconds: Math.round(Math.abs(Date.now() - timestamp) / 1000) }));
      return;
    }

    const isPoisoned = (addr) => {
      if (typeof addr !== 'string' || !addr.includes(':')) return true;
      const [host] = addr.split(':');
      return host.endsWith('.mesh') || host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0';
    };
    let safeRendezvous = (rendezvousNodes || []).filter((addr) => !isPoisoned(addr));
    if (safeRendezvous.length === 0 && Array.isArray(rendezvousNodes) && rendezvousNodes.length > 0 && (process.env.NODE_ENV === 'test' || CONFIG.serverName === 'localhost')) {
      safeRendezvous = rendezvousNodes.filter((addr) => {
        if (typeof addr !== 'string' || !addr.includes(':')) return false;
        const [host] = addr.split(':');
        return !host.endsWith('.mesh');
      });
    }

    const record = {
      nodeId,
      role: role || 'EDGE',
      rendezvousNodes: safeRendezvous,
      kemPublicKey,
      identityPublicKey,
      channels: channels || [],
      lastSeen: Date.now()
    };
    fed.presenceTable.set(nodeId, record);

    if (record.role === 'EDGE') {
      const rawRemote = channel?.socket?.realRemoteAddress || channel?.socket?.remoteAddress || '';
      const cleanRemote = rawRemote.replace(/^::ffff:/, '');
      if (cleanRemote && fed.peerManager && typeof fed.peerManager.registerEdgeIp === 'function') {
        fed.peerManager.registerEdgeIp(cleanRemote);
      }
    }

    if (role === 'RELAY' || role === 'CAP_RELAY' || role === 'CAP_EDGE_TRANSIT') {
      if (Array.isArray(safeRendezvous) && safeRendezvous.length > 0) {
        for (const rn of safeRendezvous) {
          const parsedTarget = AddressHelper.parseTarget(rn);
          if (parsedTarget && parsedTarget.host && parsedTarget.port && !fed.isSelfPeerAddress(parsedTarget.host, parsedTarget.port)) {
            fed.nodePhysicalAddresses.set(nodeId, `${parsedTarget.host}:${parsedTarget.port}`);
            break;
          }
        }
      } else if (channel?.peerNodeAddress && !channel.peerNodeAddress.endsWith('.mesh')) {
        const parsedTarget = AddressHelper.parseTarget(channel.peerNodeAddress);
        if (parsedTarget && parsedTarget.host && parsedTarget.port && !fed.isSelfPeerAddress(parsedTarget.host, parsedTarget.port)) {
          fed.nodePhysicalAddresses.set(nodeId, `${parsedTarget.host}:${parsedTarget.port}`);
        }
      }
    }

    if (fed.peerManager && Array.isArray(safeRendezvous) && (role === 'RELAY' || role === 'CAP_RELAY')) {
      for (const rdvAddr of safeRendezvous) {
        if (rdvAddr && rdvAddr.includes(':') && !rdvAddr.endsWith('.mesh')) {
          const [h, p] = rdvAddr.split(':');
          const pNum = parseInt(p, 10);
          if (h && !isNaN(pNum) && !fed.isSelfPeerAddress(h, pNum)) {
            fed.peerManager.addOrUpdate(rdvAddr, true, true);
          }
        }
      }
    }

    fed.db.upsertRoute({
      nodeId,
      role: record.role,
      rendezvousNodes: record.rendezvousNodes,
      kemPublicKey,
      identityPublicKey,
      lastSeen: record.lastSeen
    });

    if (Array.isArray(channels)) {
      channels.forEach((chan) => {
        if (!fed.channelSubscribers.has(chan)) {
          fed.channelSubscribers.set(chan, new Set());
        }
      });
    }

    if (Array.isArray(payload.memberships)) {
      payload.memberships.forEach((m) => {
        if (m && m.user) {
          const parsed = AddressHelper.parse(m.user);
          if (parsed && !parsed.isLocal) {
            const uNodeId = parsed.nodeId || nodeId;
            const canonicalUser = `@${parsed.name}:${uNodeId}.mesh`;

            const incomingNick = parsed.name.toLowerCase();
            for (const existingUser of Array.from(fed.remoteOnlineUsers.keys())) {
              const exParsed = AddressHelper.parse(existingUser);
              if (exParsed && exParsed.name.toLowerCase() === incomingNick && exParsed.nodeId !== uNodeId) {
                fed.remoteOnlineUsers.delete(existingUser);
              }
            }

            fed.remoteOnlineUsers.set(canonicalUser, {
              lastSeen: Date.now(),
              channels: m.channels || [],
              isSsh: !!m.isSsh,
              kemPublicKey: m.kemPublicKey || ''
            });
            if (m.kemPublicKey) {
              fed.db.saveRemoteUserKemKey(canonicalUser, m.kemPublicKey);
            }

            if (uNodeId !== fed.nodeId && !fed.presenceTable.has(uNodeId)) {
              const rdvAddr = payload.relayAnnounceAddress || fed.nodePhysicalAddresses.get(nodeId) || (channel?.peerNodeAddress && !channel.peerNodeAddress.endsWith('.mesh') ? channel.peerNodeAddress : null);
              const rdvList = rdvAddr ? [rdvAddr] : [nodeId];
              fed.presenceTable.set(uNodeId, {
                nodeId: uNodeId,
                role: 'EDGE',
                rendezvousNodes: rdvList,
                kemPublicKey: m.kemPublicKey || '',
                identityPublicKey: '',
                channels: m.channels || [],
                lastSeen: Date.now()
              });
              fed.db.upsertRoute({
                nodeId: uNodeId,
                role: 'EDGE',
                rendezvousNodes: rdvList,
                kemPublicKey: m.kemPublicKey || '',
                identityPublicKey: '',
                lastSeen: Date.now()
              });
            }
          }
        }
      });
    }

    if (fed.db && typeof fed.db.resetOutboxForTarget === 'function') {
      fed.db.resetOutboxForTarget(nodeId);
    }

    const membershipSummary = Array.isArray(payload.memberships)
      ? payload.memberships.map((m) => m?.user || '').sort().join(',')
      : '';
    const announceKey = `${nodeId}:${timestamp}:${membershipSummary}`;
    const isNewAnnounce = !this.seenPresenceAnnounces.has(announceKey);
    if (isNewAnnounce) {
      this.seenPresenceAnnounces.add(announceKey);
      if (this.seenPresenceAnnounces.size > 2000) {
        const first = this.seenPresenceAnnounces.values().next().value;
        this.seenPresenceAnnounces.delete(first);
      }
    }

    fed.emit('presence_change');
    if (channel && typeof channel.writePayload === 'function') {
      channel.writePayload({ status: 'ack', type: 'PRESENCE_ANNOUNCE', nodeId: fed.nodeId });

      const now = Date.now();
      const lastBilateral = channel._lastBilateralSync || 0;
      if (isNewAnnounce && !payload.isBilateralReply && (role === 'RELAY' || role === 'CAP_RELAY') && (now - lastBilateral >= 10000)) {
        channel._lastBilateralSync = now;
        const myPresence = fed.createPresenceAnnouncePayload();
        if (myPresence.memberships && myPresence.memberships.length > 0) {
          myPresence.isBilateralReply = true;
          channel.writePayload(myPresence);
          log.debug(I18n.t('FED_BILATERAL_SYNC', { node: nodeId }));
        }
      }
    }

    if (isNewAnnounce) {
      if (fed.isRelay()) {
        const peers = fed.peerManager ? fed.peerManager.getAllPeers() : [];
        for (const peer of peers) {
          if (!peer || !peer.includes(':')) continue;
          const [host, portStr] = peer.split(':');
          const port = parseInt(portStr, 10);
          if (!host || isNaN(port)) continue;
          if (fed.isSelfPeerAddress(host, port)) continue;

          if (channel?.peerNodeAddress && peer === channel.peerNodeAddress) continue;
          if (remotePeer) {
            if (peer === remotePeer) continue;
            const [rHost] = remotePeer.split(':');
            if (host === rHost) continue;
          }
          if (fed.nodePhysicalAddresses.get(nodeId) === peer) continue;

          fed.getOrCreateSecureChannel(host, port)
            .then((ch) => {
              if (ch && ch !== channel && ch.isReady && ch.socket && ch.socket.writable) {
                ch.writePayload(payload);
              }
            })
            .catch(() => {});
        }
      } else if (CONFIG.allowEdgeGossip && fed.rendezvousRelays && fed.rendezvousRelays.size >= 2) {
        for (const [relayAddr, rObj] of fed.rendezvousRelays.entries()) {
          if (remotePeer && (relayAddr === remotePeer || rObj.channel?.peerNodeAddress === remotePeer)) continue;
          if (channel && (rObj.channel === channel || rObj.socket === channel.socket)) continue;
          if (rObj && rObj.channel && rObj.channel.isReady !== false && (!rObj.socket || rObj.socket.writable !== false)) {
            rObj.channel.writePayload(payload);
          }
        }
      }
    }

    if (!fed.isRelay() && (role === 'RELAY' || role === 'CAP_RELAY')) {
      fed.maintainRendezvousTunnels().catch(() => {});
    }

    setImmediate(() => fed.processOutbox(true));
  }

  handleRouteUpdate(payload, channel, remotePeer) {
    const fed = this.federation;
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
      kemPublicKey: kemPublicKey || null,
      relayKemPublicKey: relayKemPublicKey || null,
      relayAddress: relayAddress || null,
      timestamp
    });

    let effectiveKemPublicKey = kemPublicKey;
    let effectiveRelayKemPublicKey = relayKemPublicKey;

    let isSigValid = CryptoHelper.verify(dataToVerify, sig, relayIdentityPublicKey);
    if (!isSigValid) {
      const dataToVerifyLegacy = JSON.stringify({
        nodeId,
        relayNodeId,
        rendezvousNodes: rendezvousNodes || [],
        timestamp
      });
      if (CryptoHelper.verify(dataToVerifyLegacy, sig, relayIdentityPublicKey)) {
        effectiveKemPublicKey = null;
        effectiveRelayKemPublicKey = null;
        isSigValid = true;
      }
    }

    if (!isSigValid) return;
    if (Math.abs(Date.now() - timestamp) > 86400000) {
      log.warn(I18n.t('FED_ROUTE_UPDATE_SKEW', { node: nodeId, seconds: Math.round(Math.abs(Date.now() - timestamp) / 1000) }));
      return;
    }

    const isPoisoned = (addr) => {
      if (typeof addr !== 'string' || !addr.includes(':')) return true;
      const [host] = addr.split(':');
      return host.endsWith('.mesh') || host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0';
    };
    let safeRdv = (rendezvousNodes || []).filter((addr) => !isPoisoned(addr));
    if (safeRdv.length === 0 && Array.isArray(rendezvousNodes) && rendezvousNodes.length > 0 && (process.env.NODE_ENV === 'test' || CONFIG.serverName === 'localhost')) {
      safeRdv = rendezvousNodes.filter((addr) => {
        if (typeof addr !== 'string' || !addr.includes(':')) return false;
        const [host] = addr.split(':');
        return !host.endsWith('.mesh');
      });
    }
    if (safeRdv.length === 0) return;

    const updateKey = `${nodeId}:${relayNodeId}:${timestamp}`;
    if (this.seenRouteUpdates.has(updateKey)) return;
    this.seenRouteUpdates.add(updateKey);
    if (this.seenRouteUpdates.size > 2000) {
      const first = this.seenRouteUpdates.values().next().value;
      this.seenRouteUpdates.delete(first);
    }

    if (relayAddress) {
      const parsedRelay = AddressHelper.parseTarget(relayAddress);
      const canonicalRelayAddr = (parsedRelay && parsedRelay.host && parsedRelay.port)
        ? `${parsedRelay.host}:${parsedRelay.port}`
        : relayAddress;
      const existingRelay = fed.presenceTable.get(relayNodeId) || fed.db.getRoute(relayNodeId);
      const relayRecord = {
        nodeId: relayNodeId,
        role: 'RELAY',
        rendezvousNodes: [canonicalRelayAddr],
        kemPublicKey: effectiveRelayKemPublicKey || existingRelay?.kemPublicKey || '',
        identityPublicKey: relayIdentityPublicKey,
        channels: [],
        lastSeen: Date.now()
      };
      fed.presenceTable.set(relayNodeId, relayRecord);
      fed.db.upsertRoute(relayRecord);
      fed.nodePhysicalAddresses.set(relayNodeId, canonicalRelayAddr);
      if (fed.peerManager && canonicalRelayAddr.includes(':') && !canonicalRelayAddr.endsWith('.mesh')) {
        fed.peerManager.addOrUpdate(canonicalRelayAddr, true, true);
      }
    }

    const currentEdge = fed.presenceTable.get(nodeId) || fed.db.getRoute(nodeId) || {};
    const edgeRecord = {
      nodeId,
      role: role || 'EDGE',
      rendezvousNodes: safeRdv,
      kemPublicKey: effectiveKemPublicKey || currentEdge.kemPublicKey || null,
      identityPublicKey: identityPublicKey || currentEdge.identityPublicKey || null,
      channels: currentEdge.channels || [],
      lastSeen: Date.now()
    };
    fed.presenceTable.set(nodeId, edgeRecord);
    fed.db.upsertRoute(edgeRecord);

    if (edgeRecord.role === 'EDGE') {
      const rawRemote = channel?.socket?.realRemoteAddress || channel?.socket?.remoteAddress || '';
      const cleanRemote = rawRemote.replace(/^::ffff:/, '');
      if (cleanRemote && fed.peerManager && typeof fed.peerManager.registerEdgeIp === 'function') {
        fed.peerManager.registerEdgeIp(cleanRemote);
      }
    }

    if (fed.peerManager && Array.isArray(safeRdv) && (role === 'RELAY' || role === 'CAP_RELAY')) {
      for (const rdvAddr of safeRdv) {
        if (rdvAddr && rdvAddr.includes(':') && !rdvAddr.endsWith('.mesh')) {
          const [h, p] = rdvAddr.split(':');
          const pNum = parseInt(p, 10);
          if (h && !isNaN(pNum) && !fed.isSelfPeerAddress(h, pNum)) {
            fed.peerManager.addOrUpdate(rdvAddr, true, true);
          }
        }
      }
    }

    if (role === 'RELAY' || role === 'CAP_RELAY' || role === 'CAP_EDGE_TRANSIT') {
      if (Array.isArray(safeRdv) && safeRdv.length > 0) {
        for (const rn of safeRdv) {
          const parsedTarget = AddressHelper.parseTarget(rn);
          if (parsedTarget && parsedTarget.host && parsedTarget.port && !fed.isSelfPeerAddress(parsedTarget.host, parsedTarget.port)) {
            fed.nodePhysicalAddresses.set(nodeId, `${parsedTarget.host}:${parsedTarget.port}`);
            break;
          }
        }
      }
    }

    if (fed.db && typeof fed.db.resetOutboxForTarget === 'function') {
      fed.db.resetOutboxForTarget(nodeId);
    }

    fed.emit('presence_change');

    if (fed.isRelay()) {
      const peers = fed.peerManager ? fed.peerManager.getAllPeers() : [];
      for (const peer of peers) {
        if (!peer || !peer.includes(':')) continue;
        const [host, portStr] = peer.split(':');
        const port = parseInt(portStr, 10);
        if (!host || isNaN(port)) continue;
        if (fed.isSelfPeerAddress(host, port)) continue;
        if (channel?.peerNodeAddress && peer === channel.peerNodeAddress) continue;
        if (remotePeer) {
          if (peer === remotePeer) continue;
          const [rHost] = remotePeer.split(':');
          if (host === rHost) continue;
        }
        if (fed.nodePhysicalAddresses.get(nodeId) === peer) continue;
        fed.sendPacket(host, port, payload).catch(() => {});
      }

      if (fed.rendezvousTunnels) {
        for (const [tNodeId, tunnel] of fed.rendezvousTunnels.entries()) {
          if (tNodeId !== nodeId && tunnel?.channel?.socket?.writable) {
            tunnel.channel.writePayload(payload);
          }
        }
      }
    }

    if (!fed.isRelay()) {
      fed.maintainRendezvousTunnels().catch(() => {});
    }

    setImmediate(() => fed.processOutbox(true));
  }

  handleDirectOrChannelMessage(payload, channel, remotePeer) {
    const fed = this.federation;
    if (fed.seenMessages.has(payload.id)) {
      channel.writePayload({ status: 'duplicate', id: payload.id });
      return;
    }

    fed.seenMessages.add(payload.id);

    if (payload.from && payload.from.startsWith('@')) {
      const parsedSender = AddressHelper.parse(payload.from);
      if (parsedSender && !parsedSender.isLocal) {
        const now = Date.now();
        const canonicalUser = parsedSender.nodeId ? `@${parsedSender.name}:${parsedSender.nodeId}.mesh` : payload.from;
        const existing = fed.remoteOnlineUsers.get(canonicalUser) || fed.remoteOnlineUsers.get(payload.from) || { channels: [] };
        existing.lastSeen = now;
        fed.remoteOnlineUsers.set(canonicalUser, existing);
        if (canonicalUser !== payload.from) {
          fed.remoteOnlineUsers.set(payload.from, existing);
        }

        if (parsedSender.nodeId && fed.presenceTable.has(parsedSender.nodeId)) {
          const pRec = fed.presenceTable.get(parsedSender.nodeId);
          pRec.lastSeen = now;
        }

        fed.emit('presence_change');

        if (parsedSender.host && parsedSender.port) {
          fed.peerManager.addOrUpdate(`${parsedSender.host}:${parsedSender.port}`, true, true);
        }
      }
    }

    const msg = fed.db.saveMessage(payload);
    if (msg) {
      fed.emit('message', msg);
      log.info(I18n.t('FED_MSG_RECEIVED', { from: msg.from, to: msg.to }));

      const hop = (payload.hop || 0) + 1;
      const ttl = payload.ttl || 5;

      if (payload.to.startsWith('#') && !payload.to.includes(':') && hop < ttl) {
        fed.broadcastChannelMessage({ ...msg, hop, ttl }, remotePeer);
      } else if (fed.channelSubscribers.has(payload.to)) {
        this.forwardToChannelSubscribers(payload.to, { ...msg, hop, ttl }, remotePeer);
      }
    }

    channel.writePayload({ status: 'delivered', id: payload.id });
  }

  handleChannelSubscribe(payload, channel) {
    const fed = this.federation;
    if (payload.channel && payload.subscriberNode) {
      if (!fed.channelSubscribers.has(payload.channel)) {
        fed.channelSubscribers.set(payload.channel, new Set());
      }
      fed.channelSubscribers.get(payload.channel).add(payload.subscriberNode);
      log.info(I18n.t('FED_CHANNEL_SUBSCRIBED', { peer: payload.subscriberNode, channel: payload.channel }));
      fed.peerManager.addOrUpdate(payload.subscriberNode, true, true);
      channel.writePayload({ status: 'subscribed', channel: payload.channel });
    }
  }

  handleChannelUnsubscribe(payload, channel) {
    const fed = this.federation;
    if (payload.channel && payload.subscriberNode && fed.channelSubscribers.has(payload.channel)) {
      fed.channelSubscribers.get(payload.channel).delete(payload.subscriberNode);
      log.info(I18n.t('FED_CHANNEL_UNSUBSCRIBED', { peer: payload.subscriberNode, channel: payload.channel }));
      channel.writePayload({ status: 'unsubscribed', channel: payload.channel });
    }
  }

  handleTyping(payload) {
    const fed = this.federation;
    if (payload.from && payload.from.startsWith('@')) {
      const parsedSender = AddressHelper.parse(payload.from);
      if (parsedSender && !parsedSender.isLocal) {
        const existing = fed.remoteOnlineUsers.get(payload.from) || { channels: [] };
        existing.lastSeen = Date.now();
        fed.remoteOnlineUsers.set(payload.from, existing);
      }
    }
    fed.emit('typing', payload);
  }

  handleUserOffline(payload, channel, remotePeer) {
    const fed = this.federation;
    if (!payload.user) return;

    const offlineTs = payload.timestamp || 0;
    const existingData = fed.remoteOnlineUsers.get(payload.user);
    if (existingData && offlineTs > 0 && existingData.lastSeen > offlineTs) {
      log.debug(I18n.t('FED_STALE_OFFLINE_DROPPED', { user: payload.user }));
      if (channel && typeof channel.writePayload === 'function') {
        channel.writePayload({ status: 'ack', type: 'USER_OFFLINE', user: payload.user });
      }
      return;
    }

    let deleted = false;
    if (fed.remoteOnlineUsers.has(payload.user)) {
      fed.remoteOnlineUsers.delete(payload.user);
      deleted = true;
    }
    const parsed = AddressHelper.parse(payload.user);
    const nick = parsed?.name || payload.user.split(':')[0].replace(/^@/, '');
    if (nick) {
      const nickLower = nick.toLowerCase();
      for (const [k, kData] of Array.from(fed.remoteOnlineUsers.entries())) {
        const kParsed = AddressHelper.parse(k);
        const kNick = kParsed?.name || k.split(':')[0].replace(/^@/, '');
        if (kNick.toLowerCase() === nickLower) {
          if (offlineTs > 0 && kData.lastSeen > offlineTs) {
            continue;
          }
          fed.remoteOnlineUsers.delete(k);
          deleted = true;
        }
      }
    }
    if (deleted) {
      fed.emit('presence_change');
    }

    const offlineKey = `${payload.user}:${offlineTs}`;
    if (!this.seenOfflineAnnounces.has(offlineKey)) {
      this.seenOfflineAnnounces.add(offlineKey);
      if (this.seenOfflineAnnounces.size > 2000) {
        const first = this.seenOfflineAnnounces.values().next().value;
        this.seenOfflineAnnounces.delete(first);
      }

      if (fed.isRelay()) {
        const peers = fed.peerManager ? fed.peerManager.getAllPeers() : [];
        for (const peer of peers) {
          if (!peer || !peer.includes(':')) continue;
          const [host, portStr] = peer.split(':');
          const port = parseInt(portStr, 10);
          if (!host || isNaN(port)) continue;
          if (fed.isSelfPeerAddress(host, port)) continue;
          if (channel?.peerNodeAddress && peer === channel.peerNodeAddress) continue;
          if (remotePeer) {
            if (peer === remotePeer) continue;
            const [rHost] = remotePeer.split(':');
            if (host === rHost) continue;
          }
          const poolKey = `${host}:${port}`;
          if (fed.connectionPool && fed.connectionPool.has(poolKey)) continue;

          fed.getOrCreateSecureChannel(host, port)
            .then((ch) => {
              if (ch && ch !== channel && ch.isReady && ch.socket && ch.socket.writable) {
                ch.writePayload(payload);
              }
            })
            .catch(() => {});
        }

        if (fed.connectionPool) {
          for (const [, ch] of fed.connectionPool.entries()) {
            if (ch && ch !== channel && ch.isReady && ch.socket && ch.socket.writable) {
              ch.writePayload(payload);
            }
          }
        }

        if (fed.rendezvousTunnels) {
          for (const [, tunnel] of fed.rendezvousTunnels.entries()) {
            if (tunnel?.channel && tunnel.channel !== channel && tunnel.channel.socket?.writable) {
              tunnel.channel.writePayload(payload);
            }
          }
        }
      }
    }

    if (channel && typeof channel.writePayload === 'function') {
      channel.writePayload({ status: 'ack', type: 'USER_OFFLINE', user: payload.user });
    }
  }

  handleGossipDiscovery(payload, channel) {
    const fed = this.federation;
    if (fed.peerManager) {
      if (payload.selfNode && payload.selfNode.includes(':') && !payload.selfNode.endsWith('.mesh')) {
        const [h, p] = payload.selfNode.split(':');
        const pNum = parseInt(p, 10);
        if (h && !isNaN(pNum) && !fed.isSelfPeerAddress(h, pNum)) {
          fed.peerManager.addOrUpdate(payload.selfNode, true, true);
        }
      }
      if (Array.isArray(payload.peers)) {
        payload.peers.forEach((p) => {
          if (p && p.includes(':') && !p.endsWith('.mesh')) {
            const [h, port] = p.split(':');
            const pNum = parseInt(port, 10);
            if (h && !isNaN(pNum) && !fed.isSelfPeerAddress(h, pNum)) {
              fed.peerManager.addOrUpdate(p, true, true);
            }
          }
        });
      }
    }

    channel.writePayload({
      type: 'GOSSIP_RESPONSE',
      selfNode: fed.isRelay() ? (fed.getRelayAnnounceAddress() || fed.nodeAddress) : null,
      peers: fed.peerManager ? fed.peerManager.getRandomSample(5) : []
    });
  }

  forwardToChannelSubscribers(channelName, msg, exceptPeer = null) {
    const fed = this.federation;
    const subscribers = fed.channelSubscribers.get(channelName);
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
      if (peer === exceptPeer) continue;
      if (peer.includes(':')) {
        const [host, portStr] = peer.split(':');
        const port = parseInt(portStr, 10);
        if (!host || isNaN(port)) continue;

        fed.sendPacket(host, port, payload).catch(() => {});
      } else if (AddressHelper.isValidNodeId(peer) || peer.endsWith('.mesh')) {
        const targetNodeId = peer.replace('.mesh', '');
        fed.sendViaOnion(targetNodeId, payload).catch(() => {});
      }
    }

    for (const [, tunnel] of fed.rendezvousTunnels.entries()) {
      if (tunnel && tunnel.channel && tunnel.channel.socket && tunnel.channel.socket.writable) {
        tunnel.channel.writePayload(payload);
      }
    }
  }
}
