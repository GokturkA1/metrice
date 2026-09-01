import { I18n } from '../../locales/i18n.js';

export default {
  name: 'paste',
  aliases: ['raw'],
  description: I18n.t('CMD_PASTE_DESC'),
  usage: '/paste',
  execute({ session }) {
    session.isManualPasteMode = true;
    session.manualPasteLines = [];
    session.addSystemLog(I18n.t('SYS_PASTE_MODE_ON'));
  }
};