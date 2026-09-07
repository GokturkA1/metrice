import { CONFIG } from '../config/index.js';
import { I18n } from '../locales/i18n.js';

export class AddressHelper {
  static USER_REGEX = /^[a-zA-Z0-9_-]+$/;
  static NODE_ID_REGEX = /^[a-z2-7]{16}$/;
  static localNodeId = null;

  static setLocalNodeId(nodeId) {
    if (typeof nodeId === 'string') {
      this.localNodeId = nodeId.toLowerCase().trim();
    }
  }

  static getLocalNodeId() {
    return this.localNodeId;
  }

  static isValidUsername(username) {
    return this.USER_REGEX.test(username);
  }

  static isValidNodeId(nodeId) {
    return this.NODE_ID_REGEX.test(nodeId);
  }

  static parseTarget(target) {
    if (!target) return null;

    // 1. V2.0 NodeID / .mesh
    if (target.endsWith('.mesh') || this.isValidNodeId(target)) {
      const nodeId = target.replace('.mesh', '').toLowerCase();
      return {
        isMesh: true,
        nodeId,
        meshAddress: `${nodeId}.mesh`,
        host: null,
        port: null
      };
    }

    // 2. IPv6 köşeli parantez ([2001:db8::1]:8001 veya [2001:db8::1])
    if (target.startsWith('[')) {
      const closeBracket = target.indexOf(']');
      if (closeBracket !== -1) {
        const host = target.slice(1, closeBracket);
        const rest = target.slice(closeBracket + 1);
        let port = CONFIG.federationPort;
        if (rest.startsWith(':') && /^\d+$/.test(rest.slice(1))) {
          port = parseInt(rest.slice(1), 10);
        }
        return { isMesh: false, nodeId: null, host, port, isIpv6: true, bracketWarning: false };
      }
    }

    // 3. IPv4 / domain veya köşeli parantezsiz IPv6
    const colonCount = (target.match(/:/g) || []).length;
    let host = target;
    let port = CONFIG.federationPort;

    if (colonCount === 1) {
      // Tek iki nokta üst üste: host:port (IPv4 veya domain adı)
      const lastColon = target.lastIndexOf(':');
      const possiblePort = target.slice(lastColon + 1);
      const possibleHost = target.slice(0, lastColon);
      if (/^\d+$/.test(possiblePort)) {
        port = parseInt(possiblePort, 10);
        host = possibleHost || CONFIG.serverName;
      }
    } else if (colonCount > 1) {
      // Çoklu iki nokta üst üste: Köşeli parantezsiz IPv6
      const lastColon = target.lastIndexOf(':');
      const possiblePort = target.slice(lastColon + 1);
      const possibleHost = target.slice(0, lastColon);

      // Yalnızca IPv4 eşlemeli IPv6 adreslerinde (örn: ::ffff:127.0.0.1:8001) son kısım porttur
      if (possibleHost.includes('.') && /^\d+$/.test(possiblePort)) {
        port = parseInt(possiblePort, 10);
        host = possibleHost;
      } else {
        // Saf IPv6 adresi (örn: 2001:db8::1): son hextet asla port kabul edilmez
        host = target;
        port = CONFIG.federationPort;
      }
    }

    const isIpv6 = colonCount > 1 || host.includes(':');
    const bracketWarning = colonCount > 1 && !target.startsWith('[') && /^\d+$/.test(target.slice(target.lastIndexOf(':') + 1)) && !target.slice(0, target.lastIndexOf(':')).includes('.');
    return { isMesh: false, nodeId: null, host, port, isIpv6, bracketWarning: !!bracketWarning };
  }

  static parse(rawAddress) {
    if (!rawAddress) return null;
    const clean = rawAddress.trim();
    const isChannel = clean.startsWith('#');
    const isUser = clean.startsWith('@');

    if (!isUser && !isChannel) return null;

    const type = isChannel ? 'CHANNEL' : 'USER';
    const body = clean.slice(1);
    const firstColon = body.indexOf(':');
    const name = firstColon === -1 ? body : body.slice(0, firstColon);
    const target = firstColon === -1 ? null : body.slice(firstColon + 1);

    if (!name) return null;

    // --- KANAL AYRIŞTIRMA (#channel[:target]) ---
    if (type === 'CHANNEL') {
      const channelName = name;
      const globalChannelName = I18n.t('DEFAULT_CHANNEL_NAME').replace('#', '');

      // 1. Küresel Mesh Kanalı (Örn: #genel)
      if ((channelName === globalChannelName || channelName === 'genel') && !target) {
        return {
          type,
          raw: `#${channelName}`,
          name: channelName,
          nodeId: null,
          host: null,
          port: null,
          isGlobalChannel: true,
          isLocal: true
        };
      }

      // 2. Hedefli Kanal (#kanal:hedef)
      if (target) {
        const parsed = this.parseTarget(target);
        if (parsed.isMesh) {
          const isLocal = this.localNodeId ? parsed.nodeId === this.localNodeId : false;
          return {
            type,
            raw: `#${channelName}:${parsed.nodeId}.mesh`,
            name: channelName,
            nodeId: parsed.nodeId,
            meshAddress: parsed.meshAddress,
            host: null,
            port: null,
            isGlobalChannel: false,
            isLocal
          };
        }

        const hostDisplay = parsed.isIpv6 ? `[${parsed.host}]` : parsed.host;
        const isLocal = parsed.host === CONFIG.serverName && parsed.port === CONFIG.federationPort;
        return {
          type,
          raw: `#${channelName}:${hostDisplay}:${parsed.port}`,
          name: channelName,
          nodeId: null,
          host: parsed.host,
          port: parsed.port,
          isGlobalChannel: false,
          isLocal,
          bracketWarning: !!parsed.bracketWarning
        };
      }

      // 3. Yerel düğüm kanalı (#kanal)
      if (this.localNodeId) {
        return {
          type,
          raw: `#${channelName}:${this.localNodeId}.mesh`,
          name: channelName,
          nodeId: this.localNodeId,
          meshAddress: `${this.localNodeId}.mesh`,
          host: null,
          port: null,
          isGlobalChannel: false,
          isLocal: true
        };
      }

      return {
        type,
        raw: `#${channelName}:${CONFIG.serverName}:${CONFIG.federationPort}`,
        name: channelName,
        nodeId: null,
        host: CONFIG.serverName,
        port: CONFIG.federationPort,
        isGlobalChannel: false,
        isLocal: true
      };
    }

    // --- KULLANICI AYRIŞTIRMA (@user[:target]) ---
    if (target) {
      const parsed = this.parseTarget(target);
      if (parsed.isMesh) {
        const isLocal = this.localNodeId ? parsed.nodeId === this.localNodeId : false;
        return {
          type,
          raw: `@${name}:${parsed.nodeId}.mesh`,
          name,
          nodeId: parsed.nodeId,
          meshAddress: parsed.meshAddress,
          host: null,
          port: null,
          isLocal
        };
      }

      const hostDisplay = parsed.isIpv6 ? `[${parsed.host}]` : parsed.host;
      const isLocal = parsed.host === CONFIG.serverName && parsed.port === CONFIG.federationPort;
      return {
        type,
        raw: `@${name}:${hostDisplay}:${parsed.port}`,
        name,
        nodeId: null,
        host: parsed.host,
        port: parsed.port,
        isLocal,
        bracketWarning: !!parsed.bracketWarning
      };
    }

    // Hedefsiz kullanıcı (@user) -> Yerel düğüm
    if (this.localNodeId) {
      return {
        type,
        raw: `@${name}:${this.localNodeId}.mesh`,
        name,
        nodeId: this.localNodeId,
        meshAddress: `${this.localNodeId}.mesh`,
        host: null,
        port: null,
        isLocal: true
      };
    }

    return {
      type,
      raw: `@${name}:${CONFIG.serverName}:${CONFIG.federationPort}`,
      name,
      nodeId: null,
      host: CONFIG.serverName,
      port: CONFIG.federationPort,
      isLocal: true
    };
  }

  static formatUser(username, nodeId = null) {
    const targetNodeId = nodeId || this.localNodeId;
    if (targetNodeId) {
      return `@${username}:${targetNodeId}.mesh`;
    }
    return `@${username}:${CONFIG.serverName}:${CONFIG.federationPort}`;
  }

  static formatChannel(channelName, nodeId = null) {
    const clean = channelName.replace('#', '');
    if (clean === 'genel') return '#genel';
    const targetNodeId = nodeId || this.localNodeId;
    if (targetNodeId) {
      return `#${clean}:${targetNodeId}.mesh`;
    }
    return `#${clean}:${CONFIG.serverName}:${CONFIG.federationPort}`;
  }
}