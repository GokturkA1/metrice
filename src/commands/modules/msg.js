import { AddressHelper } from '../../utils/addressHelper.js';
import { I18n } from '../../locales/i18n.js';

export default {
  name: 'msg',
  aliases: ['query', 'q', 'dm'],
  description: I18n.t('CMD_MSG_DESC'),
  usage: '/msg @user[:host:port]',
  execute({ args, session, db, federation, userAddress }) {
    if (!args[0]) {
      session.addSystemLog(I18n.t('CMD_MSG_USAGE_ERROR'));
      return;
    }

    const input = args[0].startsWith('@') || args[0].startsWith('#') ? args[0] : `@${args[0]}`;
    const parsed = AddressHelper.parse(input);
    if (parsed && parsed.type === 'USER') {
      if (parsed.bracketWarning) {
        session.addSystemLog(I18n.t('CMD_MSG_IPV6_PORT_SYNTAX'));
      }

      // Opportunistic Peering: Dış bir sunucuysa anında peer havuzuna ekle
      if (!parsed.isLocal && parsed.host && parsed.port && federation?.peerManager) {
        federation.peerManager.addOrUpdate(`${parsed.host}:${parsed.port}`, true);
      }

      let targetRaw = parsed.raw;
      if (parsed.isLocal && federation?.remoteOnlineUsers) {
        const targetNick = parsed.name.toLowerCase();
        for (const u of federation.remoteOnlineUsers.keys()) {
          const p = AddressHelper.parse(u);
          if (p && p.name.toLowerCase() === targetNick) {
            targetRaw = u;
            break;
          }
        }
      }

      session.setTarget(targetRaw);
      session.renderFull(db.getConversation(userAddress, targetRaw));
    } else {
      session.addSystemLog(I18n.t('CMD_MSG_FORMAT_ERROR', { input: args[0] }));
    }
  }
};