import { CONFIG } from '../config/index.js';
import { I18n } from '../locales/i18n.js';

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
    const body = clean.slice(1);
    const parts = body.split(':');

    if (type === 'CHANNEL') {
      const channelName = parts[0];
      if (!channelName) return null;

      const globalChannelName = I18n.t('DEFAULT_CHANNEL_NAME').replace('#', '');

      // 1. Sadece Locale'de tanımlı genel kanal (Örn: #genel) Global Mesh kanalıdır
      if (channelName === globalChannelName && parts.length === 1) {
        return {
          type,
          raw: `#${channelName}`,
          name: channelName,
          host: null,
          port: null,
          isGlobalChannel: true,
          isLocal: true
        };
      }

      // 2. Özel sunucu kanalı (#sohbet:localhost:8002)
      if (parts.length > 1) {
        const host = parts[1] || CONFIG.serverName;
        const port = parts[2] ? parseInt(parts[2], 10) : CONFIG.federationPort;
        const isLocal = host === CONFIG.serverName && port === CONFIG.federationPort;
        return {
          type,
          raw: `#${channelName}:${host}:${port}`,
          name: channelName,
          host,
          port,
          isGlobalChannel: false,
          isLocal
        };
      }

      // 3. Varsayılan olarak yerel sunucu kanalı (#sohbet -> #sohbet:localhost:8001)
      return {
        type,
        raw: `#${channelName}:${CONFIG.serverName}:${CONFIG.federationPort}`,
        name: channelName,
        host: CONFIG.serverName,
        port: CONFIG.federationPort,
        isGlobalChannel: false,
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