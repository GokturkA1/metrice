import { I18n } from '../../locales/i18n.js';

export default {
  name: 'allowtelnet',
  aliases: ['telnetaccess', 'telnet'],
  description: I18n.t('CMD_ALLOWTELNET_DESC'),
  usage: I18n.t('CMD_ALLOWTELNET_USAGE'),
  execute({ args, session, db, userAddress }) {
    const profile = db.getUserProfile(userAddress);
    const sub = (args[0] || '').toLowerCase();

    if (sub === 'on' || sub === 'enable' || sub === 'ac') {
      db.setUserTelnetAccess(userAddress, true);
      session.addSystemLog(I18n.t('CMD_ALLOWTELNET_ENABLED'));
      return;
    }

    if (sub === 'off' || sub === 'disable' || sub === 'kapat') {
      db.setUserTelnetAccess(userAddress, false);
      session.addSystemLog(I18n.t('CMD_ALLOWTELNET_DISABLED'));
      return;
    }

    const currentStatus = profile.allowTelnet
      ? I18n.t('CMD_ALLOWTELNET_STATUS_OPEN')
      : I18n.t('CMD_ALLOWTELNET_STATUS_LOCKED');

    session.addSystemLog(I18n.t('CMD_ALLOWTELNET_CURRENT_STATUS', { status: currentStatus }));
    session.addSystemLog(I18n.t('CMD_ALLOWTELNET_HELP_TIP'));
  }
};