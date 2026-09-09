import net from 'node:net';
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

  /**
   * RFC 5952 standardına göre IPv6 adresini kanonik ve sıkıştırılmış formata dönüştürür
   * @param {string} ip
   * @returns {string}
   */
  static canonicalizeIPv6(ip) {
    if (!ip || typeof ip !== 'string') return ip;
    let str = ip.trim().replace(/^\[|\]$/g, '');
    const scopeIdx = str.indexOf('%');
    if (scopeIdx !== -1) str = str.slice(0, scopeIdx);

    // IPv4-mapped (örn: ::ffff:192.168.1.1 veya ::192.168.1.1)
    const lastColon = str.lastIndexOf(':');
    const tail = str.slice(lastColon + 1);
    let v4Words = null;
    if (tail.includes('.')) {
      const octets = tail.split('.').map((x) => parseInt(x, 10));
      if (octets.length === 4 && octets.every((o) => !isNaN(o) && o >= 0 && o <= 255)) {
        v4Words = [(octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]];
        str = str.slice(0, lastColon);
      } else {
        return ip;
      }
    }

    let headParts = [];
    let tailParts = [];
    if (str.includes('::')) {
      const halves = str.split('::');
      if (halves.length > 2) return ip;
      headParts = halves[0] ? halves[0].split(':') : [];
      tailParts = halves[1] ? halves[1].split(':') : [];
    } else {
      headParts = str.split(':');
    }

    const headWords = headParts.map((p) => parseInt(p, 16));
    const tailWords = tailParts.map((p) => parseInt(p, 16));
    if (v4Words) tailWords.push(...v4Words);

    if (headWords.some(isNaN) || tailWords.some(isNaN)) return ip;
    const totalProvided = headWords.length + tailWords.length;
    if (totalProvided > 8) return ip;

    const numZeros = 8 - totalProvided;
    const zeros = new Array(Math.max(0, numZeros)).fill(0);
    const words = [...headWords, ...zeros, ...tailWords];
    if (words.length !== 8) return ip;

    let maxRunStart = -1;
    let maxRunLength = 0;
    let currentRunStart = -1;
    let currentRunLength = 0;

    for (let i = 0; i < 8; i++) {
      if (words[i] === 0) {
        if (currentRunStart === -1) {
          currentRunStart = i;
          currentRunLength = 1;
        } else {
          currentRunLength++;
        }
        if (currentRunLength > maxRunLength) {
          maxRunStart = currentRunStart;
          maxRunLength = currentRunLength;
        }
      } else {
        currentRunStart = -1;
        currentRunLength = 0;
      }
    }

    if (maxRunLength >= 2) {
      const left = words.slice(0, maxRunStart).map((w) => w.toString(16)).join(':');
      const right = words.slice(maxRunStart + maxRunLength).map((w) => w.toString(16)).join(':');
      return `${left}::${right}`;
    }

    return words.map((w) => w.toString(16)).join(':');
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

      // 1. Küresel Mesh Kanalı (Örn: #genel / #general)
      if ((channelName === globalChannelName || channelName === 'genel' || channelName === 'general') && !target) {
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
    if (clean === 'genel' || clean === 'general') return '#genel';
    const targetNodeId = nodeId || this.localNodeId;
    if (targetNodeId) {
      return `#${clean}:${targetNodeId}.mesh`;
    }
    return `#${clean}:${CONFIG.serverName}:${CONFIG.federationPort}`;
  }
}