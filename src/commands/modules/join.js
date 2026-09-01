import { I18n } from '../../locales/i18n.js';

export default {
  name: 'join',
  aliases: ['j', 'channel'],
  description: I18n.t('CMD_JOIN_DESC'),
  usage: '/join #oda_adi',
  execute({ args, session, db, userAddress }) {
    if (!args[0] || !args[0].startsWith('#')) {
      session.addSystemLog(I18n.t('CMD_JOIN_USAGE_ERROR'));
      return;
    }
    session.setTarget(args[0]);
    session.renderFull(db.getConversation(userAddress, args[0]));
  }
};