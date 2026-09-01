import { I18n } from '../../locales/i18n.js';

export default {
  name: 'who',
  aliases: ['online', 'users'],
  description: I18n.t('CMD_WHO_DESC'),
  usage: '/who',
  execute({ session, clientServer }) {
    const online = clientServer.getOnlineUsers().join(', ') || I18n.t('CMD_WHO_EMPTY');
    session.addSystemLog(I18n.t('CMD_WHO_RESULT', { users: online }));
  }
};