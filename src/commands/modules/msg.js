import { AddressHelper } from '../../utils/addressHelper.js';
import { I18n } from '../../locales/i18n.js';

export default {
  name: 'msg',
  aliases: ['query', 'q', 'dm'],
  description: I18n.t('CMD_MSG_DESC'),
  usage: '/msg @user:host[:port]',
  execute({ args, session, db, userAddress }) {
    if (!args[0]) {
      session.addSystemLog(I18n.t('CMD_MSG_USAGE_ERROR'));
      return;
    }

    const parsed = AddressHelper.parse(args[0]);
    if (parsed) {
      session.setTarget(parsed.raw);
      session.renderFull(db.getConversation(userAddress, parsed.raw));
    } else {
      session.addSystemLog(I18n.t('CMD_MSG_FORMAT_ERROR', { input: args[0] }));
    }
  }
};