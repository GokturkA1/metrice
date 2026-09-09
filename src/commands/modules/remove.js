import { AddressHelper } from '../../utils/addressHelper.js';
import { I18n } from '../../locales/i18n.js';

export default {
  name: 'remove',
  aliases: ['close', 'rm'],
  description: I18n.t('CMD_REMOVE_DESC'),
  usage: '/remove [@kisi]',
  execute({ args, session, db, userAddress }) {
    const defaultChannel = I18n.t('DEFAULT_CHANNEL_NAME');
    const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');

    let targetUser = args[0] ? AddressHelper.parse(args[0])?.raw : session.activeTarget;

    if (!targetUser || !targetUser.startsWith('@')) {
      session.addSystemLog(I18n.t('CMD_REMOVE_USAGE_ERROR'));
      return;
    }

    // DM listesinden çıkar ve konuşma geçmişini sadece bu kullanıcı için temizle
    session.removeContact(targetUser);
    db.clearConversationForUser(userAddress, targetUser);

    session.addSystemLog(I18n.t('SYS_REMOVED_DM', { target: targetUser }));

    if (session.activeTarget === targetUser) {
      const fallback = session.contacts.find((c) => AddressHelper.isGlobalChannel(c)) || systemConsole;
      session.setTarget(fallback);
    }
  }
};