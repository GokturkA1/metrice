import { AddressHelper } from '../../utils/addressHelper.js';
import { I18n } from '../../locales/i18n.js';

export default {
  name: 'join',
  aliases: ['j', 'channel'],
  description: I18n.t('CMD_JOIN_DESC'),
  usage: '/join #oda_adi',
  async execute({ args, session, federation }) {
    if (!args[0] || !args[0].startsWith('#')) {
      session.addSystemLog(I18n.t('CMD_JOIN_USAGE_ERROR'));
      return;
    }

    const parsed = AddressHelper.parse(args[0]);
    if (!parsed || parsed.type !== 'CHANNEL') {
      session.addSystemLog(I18n.t('CMD_JOIN_USAGE_ERROR'));
      return;
    }

    // Uzak bir sunucunun kanalıysa o sunucuya SUBSCRIBE sinyali gönder
    if (!parsed.isLocal && !parsed.isGlobalChannel && parsed.host && parsed.port && federation) {
      await federation.subscribeRemoteChannel(parsed.host, parsed.port, parsed.raw);
    }

    session.setTarget(parsed.raw);
    session.addSystemLog(I18n.t('SYS_JOINED_CHANNEL', { channel: parsed.raw }));
  }
};