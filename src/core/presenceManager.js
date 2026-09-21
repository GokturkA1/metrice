import { CONFIG } from '../config/index.js';
import { Logger } from '../utils/logger.js';
import { AddressHelper } from '../utils/addressHelper.js';
import { CryptoHelper } from '../utils/cryptoHelper.js';
import { I18n } from '../locales/i18n.js';

const log = new Logger('PRESENCE');

export class PresenceManager {
  constructor(federation) {
    this.federation = federation;
  }

  getLocalChannels() {
    const fed = this.federation;
    const defaultChannel = I18n.t('DEFAULT_CHANNEL_NAME');
    const chans = new Set([defaultChannel]);
    if (fed.getLocalStateFn) {
      const state = fed.getLocalStateFn();
      if (Array.isArray(state.channels)) {
        state.channels.forEach((c) => {
          if (AddressHelper.isGlobalChannel(c)) chans.add(defaultChannel);
          else chans.add(c);
        });
      }
      if (Array.isArray(state.memberships)) {
        state.memberships.forEach((m) => {
          if (Array.isArray(m.channels)) {
            m.channels.forEach((c) => {
              if (AddressHelper.isGlobalChannel(c)) chans.add(defaultChannel);
              else chans.add(c);
            });
          }
        });
      }
    }
    return Array.from(chans);
  }

  getRelayAnnounceAddress() {
    const fed = this.federation;
    const serverHost = CONFIG.serverName;
    const isLoopbackOrLocal = !serverHost || serverHost === 'localhost' || serverHost.startsWith('127.') || serverHost === '0.0.0.0';
    const announcePort = CONFIG.publicFederationPort || CONFIG.federationPort;
    
    // Genel IP konsensusu varsa ve serverName yerelse genel IP'yi onceliklendir
    if (isLoopbackOrLocal && fed.publicIp) {
      return `${fed.publicIp}:${announcePort}`;
    }
    
    return `${serverHost || '127.0.0.1'}:${announcePort}`;
  }

  getAllOnlineUsers() {
    const fed = this.federation;
    const now = Date.now();
    const ttl = (CONFIG && CONFIG.presenceTtl) || 60000;
    const activeRemote = [];
    for (const [userAddr, data] of fed.remoteOnlineUsers.entries()) {
      const diff = now - data.lastSeen;
      if (diff < 0) {
        data.lastSeen = now;
      }
      if (now - data.lastSeen < ttl) {
        activeRemote.push(userAddr);
      }
    }
    const localState = fed.getLocalStateFn ? fed.getLocalStateFn() : { users: [] };
    const allUsers = [...(localState.users || []), ...activeRemote];

    // Tekillestirme: Ayni nickname'e sahip birden fazla kayit varsa .mesh adresini onceliklendir
    const userByNick = new Map();
    for (const u of allUsers) {
      if (typeof u !== 'string') continue;
      const nick = u.split(':')[0].replace('@', '').toLowerCase();
      const existing = userByNick.get(nick);
      if (!existing) {
        userByNick.set(nick, u);
      } else {
        const existingIsMesh = existing.endsWith('.mesh');
        const newIsMesh = u.endsWith('.mesh');
        if (!existingIsMesh && newIsMesh) {
          userByNick.set(nick, u);
        } else if (existingIsMesh && newIsMesh) {
          userByNick.set(nick, u);
        }
      }
    }

    return Array.from(userByNick.values());
  }

  getChannelMembers(channelName) {
    const fed = this.federation;
    const members = [];
    const now = Date.now();
    const ttl = (CONFIG && CONFIG.presenceTtl) || 60000;
    const isGlobal = AddressHelper.isGlobalChannel(channelName);

    for (const [userAddr, data] of fed.remoteOnlineUsers.entries()) {
      const diff = now - data.lastSeen;
      if (diff < 0) {
        data.lastSeen = now;
      }
      if (now - data.lastSeen < ttl) {
        if (isGlobal) {
          members.push(userAddr);
        } else if (Array.isArray(data.channels) && data.channels.includes(channelName)) {
          members.push(userAddr);
        }
      }
    }
    return members;
  }

  getRemoteUserSecurity(userAddress) {
    const fed = this.federation;
    if (!userAddress) return null;
    let data = fed.remoteOnlineUsers.get(userAddress);
    if (!data) {
      const parsed = AddressHelper.parse(userAddress);
      const nick = parsed && parsed.name ? parsed.name : userAddress.split(':')[0].replace('@', '');
      if (nick) {
        for (const [addr, d] of fed.remoteOnlineUsers.entries()) {
          const p = AddressHelper.parse(addr);
          const userNick = p && p.name ? p.name : addr.split(':')[0].replace('@', '');
          if (userNick === nick) {
            data = d;
            break;
          }
        }
      }
    }
    if (!data) {
      if (fed.db && typeof fed.db.getUserProfile === 'function') {
        const profile = fed.db.getUserProfile(userAddress);
        if (profile && profile.kemPublicKey) {
          return {
            isSsh: true,
            kemPublicKey: profile.kemPublicKey
          };
        }
      }
      return null;
    }
    return {
      isSsh: !!data.isSsh,
      kemPublicKey: data.kemPublicKey || ''
    };
  }

  broadcastRouteUpdate(nodeId, rendezvousAddr, kemPublicKey, identityPublicKey) {
    const fed = this.federation;
    const timestamp = Date.now();
    const dataToSign = JSON.stringify({
      nodeId,
      relayNodeId: fed.nodeId,
      rendezvousNodes: [rendezvousAddr],
      kemPublicKey: kemPublicKey || null,
      relayKemPublicKey: fed.kemKeyPair.publicKey,
      relayAddress: rendezvousAddr,
      timestamp
    });
    const sig = CryptoHelper.sign(dataToSign, fed.identityKeyPair.privateKey);

    const updatePayload = {
      type: 'ROUTE_UPDATE',
      nodeId,
      role: 'EDGE',
      rendezvousNodes: [rendezvousAddr],
      kemPublicKey: kemPublicKey || null,
      identityPublicKey: identityPublicKey || null,
      relayNodeId: fed.nodeId,
      relayAddress: rendezvousAddr,
      relayKemPublicKey: fed.kemKeyPair.publicKey,
      relayIdentityPublicKey: fed.identityKeyPair.publicKey,
      timestamp,
      sig
    };

    const peers = fed.peerManager.getAllPeers();
    for (const peer of peers) {
      if (!peer || !peer.includes(':')) continue;
      const [host, portStr] = peer.split(':');
      const port = parseInt(portStr, 10);
      if (!host || isNaN(port)) continue;
      fed.sendPacket(host, port, updatePayload).catch(() => {
        if (fed.peerManager && typeof fed.peerManager.addOrUpdate === 'function') {
          fed.peerManager.addOrUpdate(`${host}:${port}`, false);
        }
      });
    }

    if (fed.rendezvousRelays) {
      for (const [, relay] of fed.rendezvousRelays.entries()) {
        if (relay?.channel?.socket?.writable) {
          relay.channel.writePayload(updatePayload);
        }
      }
    }

    if (fed.rendezvousTunnels) {
      for (const [tNodeId, tunnel] of fed.rendezvousTunnels.entries()) {
        if (tNodeId !== nodeId && tunnel?.channel?.socket?.writable) {
          tunnel.channel.writePayload(updatePayload);
        }
      }
    }
  }

  createPresenceAnnouncePayload() {
    const fed = this.federation;
    const timestamp = Date.now();
    const channels = this.getLocalChannels();
    const relayAnnounceAddr = this.getRelayAnnounceAddress();

    const isPoisoned = (addr) => {
      if (typeof addr !== 'string' || !addr.includes(':')) return true;
      const [host] = addr.split(':');
      return host.endsWith('.mesh') || host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0';
    };
    let safeBoundRelays = Array.from(fed.boundRendezvousRelays || []).filter((addr) => !isPoisoned(addr));
    if (safeBoundRelays.length === 0 && fed.boundRendezvousRelays?.size > 0 && (process.env.NODE_ENV === 'test' || CONFIG.serverName === 'localhost')) {
      safeBoundRelays = Array.from(fed.boundRendezvousRelays).filter((addr) => {
        if (typeof addr !== 'string' || !addr.includes(':')) return false;
        const [host] = addr.split(':');
        return !host.endsWith('.mesh');
      });
    }
    const rendezvousNodes = fed.isRelay() ? [relayAnnounceAddr] : safeBoundRelays;

    const dataToSign = JSON.stringify({
      nodeId: fed.nodeId,
      role: fed.role,
      rendezvousNodes,
      kemPublicKey: fed.kemKeyPair.publicKey,
      channels,
      timestamp
    });

    const sig = CryptoHelper.sign(dataToSign, fed.identityKeyPair.privateKey);
    const myState = fed.getLocalStateFn ? fed.getLocalStateFn() : { memberships: [] };
    const allMemberships = [...(myState.memberships || [])];

    if (fed.isRelay() && fed.rendezvousTunnels) {
      for (const [tNodeId] of fed.rendezvousTunnels.entries()) {
        for (const [userAddr, uData] of fed.remoteOnlineUsers.entries()) {
          if (userAddr.includes(`:${tNodeId}.mesh`)) {
            uData.lastSeen = Date.now();
            if (!allMemberships.some((m) => m.user === userAddr)) {
              allMemberships.push({
                user: userAddr,
                channels: uData.channels || [],
                isSsh: !!uData.isSsh,
                kemPublicKey: uData.kemPublicKey || ''
              });
            }
          }
        }
      }
    }

    return {
      type: 'PRESENCE_ANNOUNCE',
      nodeId: fed.nodeId,
      role: fed.role,
      rendezvousNodes,
      kemPublicKey: fed.kemKeyPair.publicKey,
      identityPublicKey: fed.identityKeyPair.publicKey,
      channels,
      memberships: allMemberships,
      timestamp,
      sig
    };
  }

  broadcastPresenceAnnounce() {
    const fed = this.federation;
    const payload = typeof fed.createPresenceAnnouncePayload === 'function'
      ? fed.createPresenceAnnouncePayload()
      : this.createPresenceAnnouncePayload();
    const { timestamp, rendezvousNodes, channels } = payload;

    fed.presenceTable.set(fed.nodeId, {
      nodeId: fed.nodeId,
      role: fed.role,
      rendezvousNodes,
      kemPublicKey: fed.kemKeyPair.publicKey,
      identityPublicKey: fed.identityKeyPair.publicKey,
      channels,
      lastSeen: timestamp
    });
    fed.db.upsertRoute({
      nodeId: fed.nodeId,
      role: fed.role,
      rendezvousNodes,
      kemPublicKey: fed.kemKeyPair.publicKey,
      identityPublicKey: fed.identityKeyPair.publicKey,
      lastSeen: timestamp
    });

    const writtenChannels = new Set();

    if (fed.connectionPool) {
      for (const [, channel] of fed.connectionPool.entries()) {
        if (channel && !writtenChannels.has(channel) && channel.isReady && channel.socket && channel.socket.writable) {
          writtenChannels.add(channel);
          channel.writePayload(payload);
        }
      }
    }

    if (fed.rendezvousRelays) {
      for (const [, relay] of fed.rendezvousRelays.entries()) {
        const ch = relay?.channel;
        if (ch && !writtenChannels.has(ch) && ch.isReady && (ch.socket?.writable || relay?.socket?.writable)) {
          writtenChannels.add(ch);
          ch.writePayload(payload);
        }
      }
    }

    if (fed.rendezvousTunnels) {
      for (const [, tunnel] of fed.rendezvousTunnels.entries()) {
        const ch = tunnel?.channel;
        if (ch && !writtenChannels.has(ch) && ch.isReady && (ch.socket?.writable || tunnel?.socket?.writable)) {
          writtenChannels.add(ch);
          ch.writePayload(payload);
        }
      }
    }

    if (fed.isRelay()) {
      const peers = fed.peerManager ? fed.peerManager.getAllPeers() : [];
      for (const peer of peers) {
        if (!peer || !peer.includes(':')) continue;
        const [host, portStr] = peer.split(':');
        const port = parseInt(portStr, 10);
        if (!host || isNaN(port)) continue;
        if (fed.isSelfPeerAddress(host, port)) continue;

        const poolKey = `${host}:${port}`;
        if (fed.connectionPool && fed.connectionPool.has(poolKey)) continue;

        fed.getOrCreateSecureChannel(host, port)
          .then((channel) => {
            if (channel && !writtenChannels.has(channel) && channel.isReady && channel.socket && channel.socket.writable) {
              writtenChannels.add(channel);
              channel.writePayload(payload);
            }
          })
          .catch(() => {
            if (fed.peerManager && typeof fed.peerManager.addOrUpdate === 'function') {
              fed.peerManager.addOrUpdate(poolKey, false);
            }
          });
      }
    }
  }

  async broadcastPresence() {
    const fed = this.federation;
    fed.broadcastPresenceAnnounce();

    if (fed.isRelay() && fed.rendezvousTunnels) {
      for (const [tNodeId, tunnel] of fed.rendezvousTunnels.entries()) {
        if (tunnel && tunnel.boundRendezvousAddr) {
          fed.broadcastRouteUpdate(tNodeId, tunnel.boundRendezvousAddr, tunnel.edgeKemKey, tunnel.identityPublicKey);
        }
      }
    }
  }

  async broadcastUserOffline(userAddress) {
    const fed = this.federation;
    if (!userAddress) return;
    fed.remoteOnlineUsers.delete(userAddress);
    const parsed = AddressHelper.parse(userAddress);
    const nick = parsed?.name || userAddress.split(':')[0].replace(/^@/, '');
    if (nick) {
      const nickLower = nick.toLowerCase();
      for (const k of Array.from(fed.remoteOnlineUsers.keys())) {
        const kParsed = AddressHelper.parse(k);
        const kNick = kParsed?.name || k.split(':')[0].replace(/^@/, '');
        if (kNick.toLowerCase() === nickLower) {
          fed.remoteOnlineUsers.delete(k);
        }
      }
    }
    fed.emit('presence_change');
    log.debug(I18n.t('FED_USER_OFFLINE_BROADCAST', { user: userAddress }));

    const payload = {
      type: 'USER_OFFLINE',
      user: userAddress,
      nodeAddress: fed.nodeAddress,
      timestamp: Date.now()
    };

    const peers = fed.peerManager ? fed.peerManager.getAllPeers() : [];
    for (const peer of peers) {
      if (!peer || !peer.includes(':')) continue;
      const [host, portStr] = peer.split(':');
      const port = parseInt(portStr, 10);
      if (!host || isNaN(port)) continue;

      fed.getOrCreateSecureChannel(host, port)
        .then((channel) => {
          if (channel && channel.isReady && channel.socket && channel.socket.writable) {
            channel.writePayload(payload);
          }
        })
        .catch(() => {
          if (fed.peerManager && typeof fed.peerManager.addOrUpdate === 'function') {
            fed.peerManager.addOrUpdate(`${host}:${port}`, false);
          }
        });
    }

    if (fed.connectionPool) {
      for (const [, channel] of fed.connectionPool.entries()) {
        if (channel && channel.isReady && channel.socket && channel.socket.writable) {
          channel.writePayload(payload);
        }
      }
    }

    if (fed.rendezvousTunnels) {
      for (const [, tunnel] of fed.rendezvousTunnels.entries()) {
        if (tunnel?.channel?.socket?.writable) {
          tunnel.channel.writePayload(payload);
        }
      }
    }

    if (fed.rendezvousRelays) {
      for (const [, relay] of fed.rendezvousRelays.entries()) {
        if (relay?.channel?.socket?.writable) {
          relay.channel.writePayload(payload);
        }
      }
    }
  }

  async broadcastChannelMessage(msg, exceptPeer = null) {
    const fed = this.federation;
    const peers = fed.peerManager.getAllPeers();
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

    for (const peer of peers) {
      if (!peer || peer === exceptPeer || !peer.includes(':')) continue;
      const [host, portStr] = peer.split(':');
      const port = parseInt(portStr, 10);
      if (!host || isNaN(port)) continue;

      fed.sendPacket(host, port, payload).catch(() => {});
    }

    if (fed.rendezvousTunnels) {
      for (const [, tunnel] of fed.rendezvousTunnels.entries()) {
        if (tunnel && tunnel.channel && tunnel.channel.socket && tunnel.channel.socket.writable) {
          const tunnelPeer = tunnel.channel.socket ? `${tunnel.channel.socket.remoteAddress}:${tunnel.channel.socket.remotePort}` : null;
          if (exceptPeer && (
            tunnelPeer === exceptPeer ||
            tunnel.channel.peerNodeAddress === exceptPeer ||
            tunnel.channel === exceptPeer ||
            tunnel.channel.socket === exceptPeer ||
            (exceptPeer.socket && tunnel.channel.socket === exceptPeer.socket)
          )) continue;
          tunnel.channel.writePayload(payload);
        }
      }
    }

    if (fed.rendezvousRelays) {
      for (const [relayAddr, relay] of fed.rendezvousRelays.entries()) {
        const relayChan = relay.channel;
        const relaySock = relay.socket || relayChan?.socket;
        const sockPeer = relaySock ? `${relaySock.remoteAddress}:${relaySock.remotePort}` : null;
        if (exceptPeer && (
          relayAddr === exceptPeer ||
          sockPeer === exceptPeer ||
          relayChan?.peerNodeAddress === exceptPeer ||
          relayChan === exceptPeer ||
          relaySock === exceptPeer ||
          (exceptPeer.socket && relaySock === exceptPeer.socket)
        )) {
          continue;
        }
        if (relay && relayChan && relayChan.isReady !== false && (!relaySock || relaySock.writable !== false)) {
          relayChan.writePayload(payload);
        }
      }
    }
  }

  async performRandomGossip() {
    const fed = this.federation;
    if (!fed.peerManager || typeof fed.peerManager.getRandomSample !== 'function') return;
    const sample = fed.peerManager.getRandomSample(3);
    for (const peer of sample) {
      if (!peer || !peer.includes(':')) continue;
      const [host, portStr] = peer.split(':');
      const port = parseInt(portStr, 10);
      if (!host || isNaN(port)) continue;
      if (fed.isSelfPeerAddress(host, port)) continue;

      try {
        const res = await fed.sendPacket(host, port, {
          type: 'GOSSIP_DISCOVERY',
          selfNode: fed.isRelay() ? (this.getRelayAnnounceAddress() || fed.nodeAddress) : null,
          peers: fed.peerManager.getRandomSample(5)
        });

        if (res && res.type === 'GOSSIP_RESPONSE') {
          fed.peerManager.addOrUpdate(peer, true, false);
          if (res.selfNode && res.selfNode.includes(':') && !res.selfNode.endsWith('.mesh')) {
            const [h, p] = res.selfNode.split(':');
            const pNum = parseInt(p, 10);
            if (h && !isNaN(pNum) && !fed.isSelfPeerAddress(h, pNum)) {
              fed.peerManager.addOrUpdate(res.selfNode, true, true);
            }
          }
          if (Array.isArray(res.peers)) {
            res.peers.forEach((p) => {
              if (p && p.includes(':') && !p.endsWith('.mesh')) {
                const [h, pPort] = p.split(':');
                const pNum = parseInt(pPort, 10);
                if (h && !isNaN(pNum) && !fed.isSelfPeerAddress(h, pNum)) {
                  fed.peerManager.addOrUpdate(p, true, true);
                }
              }
            });
          }
        }
      } catch {
        fed.peerManager.addOrUpdate(peer, false);
      }
    }
  }

  async subscribeRemoteChannel(host, port, channel) {
    const fed = this.federation;
    try {
      await fed.sendPacket(host, port, {
        type: 'CHANNEL_SUBSCRIBE',
        channel,
        subscriberNode: fed.nodeAddress
      });
      fed.peerManager.addOrUpdate(`${host}:${port}`, true);
    } catch {}
  }

  async unsubscribeRemoteChannel(host, port, channel) {
    const fed = this.federation;
    try {
      await fed.sendPacket(host, port, {
        type: 'CHANNEL_UNSUBSCRIBE',
        channel,
        subscriberNode: fed.nodeAddress
      });
    } catch {}
  }

  async subscribeNodeChannel(nodeId, channel) {
    const fed = this.federation;
    if (!nodeId || !channel) return;
    const cleanNodeId = nodeId.replace('.mesh', '').toLowerCase();
    const payload = {
      type: 'CHANNEL_SUBSCRIBE',
      channel,
      subscriberNode: fed.meshAddress || fed.nodeId
    };

    // 1. Rendezvous Rölelerine bildir (Edge -> Relay kanalı)
    if (fed.rendezvousRelays && fed.rendezvousRelays.size > 0) {
      for (const [, rObj] of fed.rendezvousRelays.entries()) {
        const rChan = rObj.channel;
        if (rChan && typeof rChan.writePayload === 'function') {
          const isWritable = !rChan.socket || rChan.socket.writable !== false;
          if (isWritable) {
            try { rChan.writePayload(payload); } catch {}
          }
        }
      }
    }

    // 2. Doğrudan yerel tünel varsa
    if (fed.rendezvousTunnels && fed.rendezvousTunnels.has(cleanNodeId)) {
      const tun = fed.rendezvousTunnels.get(cleanNodeId);
      if (tun?.channel?.socket?.writable) {
        try { tun.channel.writePayload(payload); } catch {}
      }
    }

    // 3. Onion devresi ile ulaştırmayı dene
    try {
      await fed.sendViaOnion(cleanNodeId, payload);
    } catch {}
  }

  async unsubscribeNodeChannel(nodeId, channel) {
    const fed = this.federation;
    if (!nodeId || !channel) return;
    const cleanNodeId = nodeId.replace('.mesh', '').toLowerCase();
    const payload = {
      type: 'CHANNEL_UNSUBSCRIBE',
      channel,
      subscriberNode: fed.meshAddress || fed.nodeId
    };

    if (fed.rendezvousRelays && fed.rendezvousRelays.size > 0) {
      for (const [, rObj] of fed.rendezvousRelays.entries()) {
        const rChan = rObj.channel;
        if (rChan && typeof rChan.writePayload === 'function') {
          const isWritable = !rChan.socket || rChan.socket.writable !== false;
          if (isWritable) {
            try { rChan.writePayload(payload); } catch {}
          }
        }
      }
    }

    if (fed.rendezvousTunnels && fed.rendezvousTunnels.has(cleanNodeId)) {
      const tun = fed.rendezvousTunnels.get(cleanNodeId);
      if (tun?.channel?.socket?.writable) {
        try { tun.channel.writePayload(payload); } catch {}
      }
    }

    try {
      await fed.sendViaOnion(cleanNodeId, payload);
    } catch {}
  }

  cleanupExpiredPresence() {
    const fed = this.federation;
    const now = Date.now();
    const presenceTtl = (CONFIG && CONFIG.presenceTtl) || 60000;
    for (const [nodeId, rec] of fed.presenceTable.entries()) {
      const diff = now - rec.lastSeen;
      if (diff < 0) {
        rec.lastSeen = now;
      } else {
        const isRelay = rec.role === 'RELAY' || rec.role === 'CAP_RELAY';
        const effectiveTtl = isRelay ? presenceTtl * 5 : presenceTtl;
        if (diff > effectiveTtl) {
          fed.presenceTable.delete(nodeId);
          const dbRoute = fed.db && typeof fed.db.getRoute === 'function' ? fed.db.getRoute(nodeId) : null;
          const hasValidDbRoute = dbRoute && (dbRoute.role === 'RELAY' || dbRoute.role === 'CAP_RELAY' || (now - dbRoute.lastSeen <= presenceTtl * 5));
          if (!isRelay && !hasValidDbRoute) {
            fed.nodePhysicalAddresses.delete(nodeId);
          }
        } else if (diff > presenceTtl && !isRelay) {
          fed.presenceTable.delete(nodeId);
          const dbRoute = fed.db && typeof fed.db.getRoute === 'function' ? fed.db.getRoute(nodeId) : null;
          const hasValidDbRoute = dbRoute && (dbRoute.role === 'RELAY' || dbRoute.role === 'CAP_RELAY' || (now - dbRoute.lastSeen <= presenceTtl * 5));
          if (!hasValidDbRoute) {
            fed.nodePhysicalAddresses.delete(nodeId);
          }
        }
      }
    }

    let removedUsers = false;
    for (const [userAddr, data] of fed.remoteOnlineUsers.entries()) {
      let isTunneledLive = false;
      if (fed.isRelay() && fed.rendezvousTunnels) {
        for (const [tNodeId] of fed.rendezvousTunnels.entries()) {
          if (userAddr.includes(`:${tNodeId}.mesh`)) {
            isTunneledLive = true;
            break;
          }
        }
      }

      if (isTunneledLive) {
        data.lastSeen = now;
        continue;
      }

      const diff = now - data.lastSeen;
      if (diff < 0) {
        data.lastSeen = now;
      } else if (diff >= presenceTtl) {
        fed.remoteOnlineUsers.delete(userAddr);
        removedUsers = true;
      }
    }
    if (removedUsers) {
      fed.emit('presence_change');
    }

    fed.db.deleteExpiredRoutes(presenceTtl);
    fed.onionRouter.cleanupExpiredCircuits();
    if (fed.db && typeof fed.db.deleteExpiredCircuits === 'function') {
      fed.db.deleteExpiredCircuits(600000);
    }
  }
}
