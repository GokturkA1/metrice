import { I18n } from '../../locales/i18n.js';

export default {
  name: 'system',
  aliases: ['console', 'sistem'],
  description: I18n.t('CMD_SYSTEM_DESC'),
  usage: '/system',
  execute({ session }) {
    session.setTarget('*sistem');
  }
};