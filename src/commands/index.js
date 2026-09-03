import { CommandRegistry } from './commandRegistry.js';
import helpCmd from './modules/help.js';
import meCmd from './modules/me.js';
import msgCmd from './modules/msg.js';
import joinCmd from './modules/join.js';
import leaveCmd from './modules/leave.js';
import removeCmd from './modules/remove.js';
import systemCmd from './modules/system.js';
import whoCmd from './modules/who.js';
import peersCmd from './modules/peers.js';
import statusCmd from './modules/status.js';
import clearCmd from './modules/clear.js';
import quitCmd from './modules/quit.js';
import allowtelnet from './modules/allowtelnet.js';
import keys from './modules/keys.js';

export function createCommandRegistry() {
  const registry = new CommandRegistry();

  registry.register(helpCmd);
  registry.register(meCmd);
  registry.register(msgCmd);
  registry.register(joinCmd);
  registry.register(leaveCmd);
  registry.register(removeCmd);
  registry.register(systemCmd);
  registry.register(whoCmd);
  registry.register(peersCmd);
  registry.register(statusCmd);
  registry.register(clearCmd);
  registry.register(quitCmd);
  registry.register(allowtelnet)
  registry.register(keys)

  return registry;
}