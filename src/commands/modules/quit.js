import { I18n } from '../../locales/i18n.js';

export default {
  name: 'quit',
  aliases: ['exit'],
  description: I18n.t('CMD_QUIT_DESC'),
  usage: '/quit',
  execute({ socket }) {
    socket.end(I18n.t('TUI_SESSION_CLOSED'));
  }
};