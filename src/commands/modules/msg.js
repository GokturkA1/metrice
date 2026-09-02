import { AddressHelper } from '../../utils/addressHelper.js';
import { I18n } from '../../locales/i18n.js';

export default {
  name: 'msg',
  aliases: ['query', 'q', 'dm'],
  description: I18n.t('CMD_MSG_DESC'),
  usage: '/msg @user:host[:port]',
  execute({ args, session, db, federation, userAddress }) {
    if (!args[0]) {
      session.addSystemLog(I18n.t('CMD_MSG_USAGE_ERROR'));
      return;
    }

    const parsed = AddressHelper.parse(args[0]);
    if (parsed && parsed.type === 'USER') {
      // Opportunistic Peering: Dış bir sunucuysa anında peer havuzuna ekle
      if (!parsed.isLocal && parsed.host && parsed.port && federation?.peerManager) {
        federation.peerManager.addOrUpdate(`${parsed.host}:${parsed.port}`, true);
      }

      session.setTarget(parsed.raw);
      session.renderFull(db.getConversation(userAddress, parsed.raw));
    } else {
      session.addSystemLog(I18n.t('CMD_MSG_FORMAT_ERROR', { input: args[0] }));
    }
  }
};