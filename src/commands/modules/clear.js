import { I18n } from '../../locales/i18n.js';

export default {
  name: 'clear',
  aliases: ['cls'],
  description: I18n.t('CMD_CLEAR_DESC'),
  usage: '/clear',
  execute({ session }) {
    if (session.activeTarget === '*sistem') {
      session.systemLogs = [];
    }
    session.renderFull([]);
  }
};