import { CONFIG } from '../config/index.js';

export class AddressHelper {
  static USER_REGEX = /^[a-zA-Z0-9_-]+$/;

  static isValidUsername(username) {
    return this.USER_REGEX.test(username);
  }

  static parse(rawAddress) {
    if (!rawAddress) return null;
    const clean = rawAddress.trim();
    const isChannel = clean.startsWith('#');
    const isUser = clean.startsWith('@');

    if (!isUser && !isChannel) return null;

    const type = isChannel ? 'CHANNEL' : 'USER';
    const prefix = clean.charAt(0);
    const body = clean.slice(1);
    const parts = body.split(':');

    if (type === 'CHANNEL') {
      const channelName = parts[0];
      if (!channelName) return null;

      // Özel sunucu kanalı belirtilmişse (#oda:host:port)
      if (parts.length > 1) {
        const host = parts[1] || CONFIG.serverName;
        const port = parts[2] ? parseInt(parts[2], 10) : CONFIG.federationPort;
        return {
          type,
          raw: `#${channelName}:${host}:${port}`,
          name: channelName,
          host,
          port,
          isMeshChannel: false,
          isLocal: host === CONFIG.serverName && port === CONFIG.federationPort
        };
      }

      // Genel Mesh Kanalı (#genel vb.)
      return {
        type,
        raw: `#${channelName}`,
        name: channelName,
        host: null,
        port: null,
        isMeshChannel: true,
        isLocal: true
      };
    }

    // Kullanıcı Adresi (@user:host[:port])
    const name = parts[0];
    const host = parts[1] || CONFIG.serverName;
    const port = parts[2] ? parseInt(parts[2], 10) : CONFIG.federationPort;

    if (!name || isNaN(port)) return null;

    return {
      type,
      raw: `@${name}:${host}:${port}`,
      name,
      host,
      port,
      isLocal: host === CONFIG.serverName && port === CONFIG.federationPort
    };
  }

  static formatUser(username) {
    return `@${username}:${CONFIG.serverName}:${CONFIG.federationPort}`;
  }
}