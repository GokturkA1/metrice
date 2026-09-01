import { I18n } from '../../locales/i18n.js';

export default {
  name: 'me',
  description: I18n.t('CMD_ME_DESC'),
  usage: '/me <eylem>',
  async execute({ argStr, session, clientServer, userAddress }) {
    if (!argStr) {
      session.addSystemLog(I18n.t('CMD_ME_USAGE_ERROR'));
      return;
    }

    if (!session.activeTarget || session.activeTarget === '*sistem') {
      session.addSystemLog(I18n.t('CMD_ME_TARGET_ERROR'));
      return;
    }

    await clientServer.handleOutboundMessage(session, userAddress, session.activeTarget, argStr, true);
  }
};