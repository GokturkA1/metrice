import { CommandRegistry } from './commandRegistry.js';
import helpCmd from './modules/help.js';
import meCmd from './modules/me.js';
import msgCmd from './modules/msg.js';
import joinCmd from './modules/join.js';
import systemCmd from './modules/system.js';
import whoCmd from './modules/who.js';
import peersCmd from './modules/peers.js';
import statusCmd from './modules/status.js';
import pasteCmd from './modules/paste.js';
import clearCmd from './modules/clear.js';
import quitCmd from './modules/quit.js';

export function createCommandRegistry() {
  const registry = new CommandRegistry();

  registry.register(helpCmd);
  registry.register(meCmd);
  registry.register(msgCmd);
  registry.register(joinCmd);
  registry.register(systemCmd);
  registry.register(whoCmd);
  registry.register(peersCmd);
  registry.register(statusCmd);
  registry.register(pasteCmd);
  registry.register(clearCmd);
  registry.register(quitCmd);

  return registry;
}