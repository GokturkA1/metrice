import { Logger } from '../utils/logger.js';
import { I18n } from '../locales/i18n.js';

const log = new Logger('COMMAND_REGISTRY');

export class CommandRegistry {
  constructor() {
    this.commands = new Map();
  }

  register(commandModule) {
    const { name, aliases = [], execute } = commandModule;
    if (!name || typeof execute !== 'function') {
      log.warn(I18n.t('CMD_REG_INVALID_MODULE'));
      return;
    }

    this.commands.set(name.toLowerCase(), commandModule);
    for (const alias of aliases) {
      this.commands.set(alias.toLowerCase(), commandModule);
    }
  }

  get(commandName) {
    return this.commands.get(commandName.toLowerCase());
  }

  getAllUnique() {
    const unique = new Map();
    for (const cmd of this.commands.values()) {
      unique.set(cmd.name, cmd);
    }
    return Array.from(unique.values());
  }

  async execute(input, context) {
    const parts = input.trim().split(' ');
    const cmdName = parts[0].replace('/', '').toLowerCase();
    const args = parts.slice(1);
    const argStr = args.join(' ');

    const command = this.get(cmdName);
    if (!command) {
      context.session.addSystemLog(I18n.t('SYS_UNKNOWN_COMMAND', { cmd: cmdName }));
      return false;
    }

    try {
      await command.execute({ args, argStr, ...context });
      return true;
    } catch (err) {
      context.session.addSystemLog(I18n.t('SYS_COMMAND_ERROR', { cmd: cmdName, error: err.message }));
      return false;
    }
  }
}