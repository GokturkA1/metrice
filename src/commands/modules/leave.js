import { AddressHelper } from '../../utils/addressHelper.js';
import { I18n } from '../../locales/i18n.js';

export default {
  name: 'leave',
  aliases: ['part', 'l'],
  description: I18n.t('CMD_LEAVE_DESC'),
  usage: '/leave [#kanal]',
  async execute({ args, session, db, federation, userAddress }) {
    const targetChannel = args[0] ? AddressHelper.parse(args[0])?.raw : session.activeTarget;

    if (!targetChannel || !targetChannel.startsWith('#')) {
      session.addSystemLog(I18n.t('CMD_LEAVE_USAGE_ERROR'));
      return;
    }

    const parsed = AddressHelper.parse(targetChannel);
    // Uzak bir sunucunun kanalıysa aboneliği iptal et
    if (parsed && !parsed.isLocal && !parsed.isGlobalChannel && federation) {
      if (parsed.host && parsed.port) {
        await federation.unsubscribeRemoteChannel(parsed.host, parsed.port, parsed.raw);
      } else if (parsed.nodeId) {
        await federation.unsubscribeNodeChannel(parsed.nodeId, parsed.raw);
      }
    }

    session.removeContact(targetChannel);
    db.clearConversationForUser(userAddress, targetChannel);

    session.addSystemLog(I18n.t('SYS_LEFT_CHANNEL', { channel: targetChannel }));

    if (session.activeTarget === targetChannel) {
      const fallback = session.contacts.find((c) => AddressHelper.isGlobalChannel(c)) || I18n.t('SYSTEM_CONSOLE_NAME');
      session.setTarget(fallback);
    }
  }
};