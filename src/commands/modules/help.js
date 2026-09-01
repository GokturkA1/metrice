import { I18n } from '../../locales/i18n.js';

export default {
  name: 'help',
  aliases: ['yardim', 'h', '?'],
  description: I18n.t('CMD_HELP_DESC'),
  usage: '/help',
  execute({ session, registry }) {
    session.addSystemLog(I18n.t('CMD_HELP_HEADER'));
    const all = registry.getAllUnique();
    for (const cmd of all) {
      const aliasStr = cmd.aliases?.length ? ` (${cmd.aliases.map((a) => '/' + a).join(', ')})` : '';
      session.addSystemLog(`/${cmd.name.padEnd(8)}${aliasStr} : ${cmd.description}`);
    }
  }
};