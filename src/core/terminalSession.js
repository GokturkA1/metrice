/* eslint-disable no-control-regex */
import { EventEmitter } from 'node:events';
import { ANSI } from '../utils/ansi.js';
import { I18n } from '../locales/i18n.js';
import { AddressHelper } from '../utils/addressHelper.js';
import { TerminalRenderer } from './terminalRenderer.js';

export { TerminalRenderer };

export class TerminalSession extends EventEmitter {
  constructor(socket, userAddress, initialProfile, getOnlineUsersFn, getChannelMembersFn = null, onProfileChangeFn = null, getSystemStatsFn = null, getKnownCommandsFn = null) {
    super();
    this.socket = socket;
    this.userAddress = userAddress;
    this.userNick = userAddress.split(':')[0].replace('@', '');
    this.getOnlineUsers = getOnlineUsersFn;
    this.getChannelMembers = getChannelMembersFn;
    this.getSystemStats = getSystemStatsFn;
    this.getKnownCommands = getKnownCommandsFn;
    this.onProfileChange = onProfileChangeFn;
    this.renderer = new TerminalRenderer(this);

    // E2EE ve Güvenlik Durumu
    this.isSsh = false;
    this.isSecureE2EE = false;
    this.kemKeyPair = null;
    this.warnedInsecureTargets = new Set();

    const defaultChannel = I18n.t('DEFAULT_CHANNEL_NAME');
    const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');

    this.activeTarget = defaultChannel;

    this.inputBuffer = '';
    this.cursorIndex = 0;
    this.history = initialProfile?.history || [];
    this.historyIndex = -1;
    this.tempInput = '';

    this.focus = 'input';

    this.tabCompletions = [];
    this.tabIndex = -1;
    this.tabPrefix = '';

    const rawSaved = initialProfile?.contacts || [];
    const normalizedSaved = [];
    for (const c of rawSaved) {
      let norm = c;
      if (AddressHelper.isSystemConsole(c)) norm = systemConsole;
      else if (AddressHelper.isGlobalChannel(c)) norm = defaultChannel;
      if (!normalizedSaved.includes(norm)) {
        normalizedSaved.push(norm);
      }
    }
    const baseContacts = [systemConsole, defaultChannel];
    this.contacts = Array.from(new Set([...baseContacts, ...normalizedSaved]));
    this.activeTarget = defaultChannel;
    this.selectedContactIdx = this.contacts.indexOf(defaultChannel) !== -1 ? this.contacts.indexOf(defaultChannel) : 1;

    this.unreadCounts = new Map();

    this.systemLogs = [
      {
        from: `[${I18n.t('TUI_SYSTEM_SENDER')}]`,
        content: I18n.t('SYS_WELCOME', { address: userAddress }),
        timestamp: new Date().toISOString()
      },
      {
        from: `[${I18n.t('TUI_SYSTEM_SENDER')}]`,
        content: I18n.t('SYS_HELP_TIP'),
        timestamp: new Date().toISOString()
      }
    ];

    this.scrollOffset = 0;
    this.typingUser = null;
    this.typingTimeout = null;

    this.width = 110;
    this.height = 24;
    this.leftSidebarWidth = 24;
    this.rightSidebarWidth = 22;

    this.screenBuffer = [];
  }

  isUserMentioned(content) {
    if (!content) return false;
    if (content.includes(this.userAddress)) return true;
    const withoutPort = this.userAddress.split(':').slice(0, 2).join(':');
    if (content.includes(withoutPort)) return true;

    const escapedNick = this.userNick.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`@${escapedNick}\\b`, 'i');
    return regex.test(content);
  }

  isMemberOf(target) {
    if (AddressHelper.isGlobalChannel(target)) return true;
    if (this.contacts.includes(target)) return true;
    return false;
  }

  isViewingTarget(target) {
    if (!target || !this.activeTarget) return false;
    return AddressHelper.isSameTarget(this.activeTarget, target);
  }

  getMyChannels() {
    const defaultChannel = I18n.t('DEFAULT_CHANNEL_NAME');
    const channels = [];
    for (const c of this.contacts) {
      if (!c.startsWith('#')) continue;
      const norm = AddressHelper.isGlobalChannel(c) ? defaultChannel : c;
      if (!channels.includes(norm)) {
        channels.push(norm);
      }
    }
    return channels;
  }

  notifyProfileChange() {
    if (typeof this.onProfileChange === 'function') {
      this.onProfileChange(this.contacts, this.history);
    }
  }

  resize(width, height) {
    this.width = Math.max(40, width || 110);
    this.height = Math.max(10, height || 24);
    this.leftSidebarWidth = Math.min(26, Math.max(18, Math.floor(this.width * 0.22)));
    this.rightSidebarWidth = Math.min(24, Math.max(16, Math.floor(this.width * 0.20)));
    this.screenBuffer = [];
    this.socket.write(ANSI.CLEAR);
    this.emit('request_render');
  }

  addContact(target) {
    if (!target) return;
    const defaultChannel = I18n.t('DEFAULT_CHANNEL_NAME');
    const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');
    let norm = target;
    if (AddressHelper.isSystemConsole(target)) norm = systemConsole;
    else if (AddressHelper.isGlobalChannel(target)) norm = defaultChannel;

    if (!this.contacts.includes(norm)) {
      if (AddressHelper.isSystemConsole(norm)) {
        this.contacts = this.contacts.filter((c) => !AddressHelper.isSystemConsole(c));
        this.contacts.unshift(systemConsole);
      } else if (AddressHelper.isGlobalChannel(norm)) {
        this.contacts = this.contacts.filter((c) => !AddressHelper.isGlobalChannel(c));
        const insertIdx = this.contacts.includes(systemConsole) ? 1 : 0;
        this.contacts.splice(insertIdx, 0, defaultChannel);
      } else {
        this.contacts.push(norm);
      }
    }
    this.notifyProfileChange();
    this.emit('request_render');
  }

  removeContact(target) {
    const isSys = AddressHelper.isSystemConsole(target);
    const isGlob = AddressHelper.isGlobalChannel(target);
    this.contacts = this.contacts.filter((c) => {
      if (c === target) return false;
      if (isSys && AddressHelper.isSystemConsole(c)) return false;
      if (isGlob && AddressHelper.isGlobalChannel(c)) return false;
      return true;
    });
    this.unreadCounts.delete(target);
    if (this.selectedContactIdx >= this.contacts.length) {
      this.selectedContactIdx = Math.max(0, this.contacts.length - 1);
    }
    this.notifyProfileChange();
    this.emit('request_render');
  }

  incrementUnread(target) {
    if (!target) return;
    if (this.isViewingTarget(target)) return;

    const defaultChannel = I18n.t('DEFAULT_CHANNEL_NAME');
    const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');
    let norm = target;
    if (AddressHelper.isSystemConsole(target)) norm = systemConsole;
    else if (AddressHelper.isGlobalChannel(target)) norm = defaultChannel;

    if (this.activeTarget === norm) return;
    const targetNick = norm.split(':')[0];
    const activeNick = this.activeTarget ? this.activeTarget.split(':')[0] : null;
    if (activeNick && targetNick && activeNick === targetNick) return;

    const current = this.unreadCounts.get(norm) || 0;
    this.unreadCounts.set(norm, current + 1);
  }

  setTarget(target) {
    const defaultChannel = I18n.t('DEFAULT_CHANNEL_NAME');
    const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');
    let norm = target;
    if (AddressHelper.isSystemConsole(target)) norm = systemConsole;
    else if (AddressHelper.isGlobalChannel(target)) norm = defaultChannel;

    this.activeTarget = norm;
    this.addContact(norm);
    this.selectedContactIdx = this.contacts.indexOf(norm);
    this.unreadCounts.delete(norm);
    const targetNick = norm ? norm.split(':')[0] : null;
    if (targetNick) {
      this.unreadCounts.delete(targetNick);
      for (const k of this.unreadCounts.keys()) {
        if (k.split(':')[0] === targetNick) {
          this.unreadCounts.delete(k);
        }
      }
    }
    this.scrollOffset = 0;
    this.emit('request_render');
  }

  addSystemLog(content) {
    const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');
    this.systemLogs.push({
      from: `[${I18n.t('TUI_SYSTEM_SENDER')}]`,
      content,
      timestamp: new Date().toISOString()
    });
    if (!AddressHelper.isSystemConsole(this.activeTarget)) {
      this.incrementUnread(systemConsole);
    }
    if (this.systemLogs.length > 200) {
      this.systemLogs.shift();
    }
    this.emit('request_render');
  }

  setTyping(user) {
    this.typingUser = user;
    this.emit('request_render');

    if (this.typingTimeout) clearTimeout(this.typingTimeout);
    this.typingTimeout = setTimeout(() => {
      this.typingUser = null;
      this.emit('request_render');
    }, 3000);
  }

  handleTabCompletion() {
    const leftText = this.inputBuffer.slice(0, this.cursorIndex);
    const tokens = leftText.split(' ');
    const currentWord = tokens[tokens.length - 1];

    if (!currentWord) return;

    if (this.tabIndex === -1 || this.tabPrefix !== currentWord) {
      this.tabPrefix = currentWord;
      const candidates = [];

      if (currentWord.startsWith('/')) {
        const cmdPrefix = currentWord.slice(1).toLowerCase();
        const allCmds = this.getKnownCommands ? this.getKnownCommands() : [];
        allCmds.forEach((c) => {
          if (c.startsWith(cmdPrefix)) candidates.push(`/${c} `);
        });
      } else if (currentWord.startsWith('@')) {
        const userPrefix = currentWord.toLowerCase();
        const onlineUsers = this.getOnlineUsers ? this.getOnlineUsers() : [];
        onlineUsers.forEach((u) => {
          if (u.toLowerCase().startsWith(userPrefix)) candidates.push(`${u} `);
        });
      } else if (currentWord.startsWith('#')) {
        const chanPrefix = currentWord.toLowerCase();
        this.contacts.filter((c) => c.startsWith('#')).forEach((ch) => {
          if (ch.toLowerCase().startsWith(chanPrefix)) candidates.push(`${ch} `);
        });
      }

      if (candidates.length === 0) return;

      this.tabCompletions = candidates;
      this.tabIndex = 0;
    } else {
      this.tabIndex = (this.tabIndex + 1) % this.tabCompletions.length;
    }

    const chosen = this.tabCompletions[this.tabIndex];
    tokens[tokens.length - 1] = chosen;
    const newLeft = tokens.join(' ');
    this.inputBuffer = newLeft + this.inputBuffer.slice(this.cursorIndex);
    this.cursorIndex = newLeft.length;
    this.renderInputOnly();
  }

  resetTabCompletion() {
    this.tabIndex = -1;
    this.tabCompletions = [];
    this.tabPrefix = '';
  }

  insertChar(char) {
    this.resetTabCompletion();
    this.inputBuffer = this.inputBuffer.slice(0, this.cursorIndex) + char + this.inputBuffer.slice(this.cursorIndex);
    this.cursorIndex += char.length;
  }

  backspace() {
    this.resetTabCompletion();
    if (this.cursorIndex > 0) {
      this.inputBuffer = this.inputBuffer.slice(0, this.cursorIndex - 1) + this.inputBuffer.slice(this.cursorIndex);
      this.cursorIndex--;
    }
  }

  deleteForward() {
    this.resetTabCompletion();
    if (this.cursorIndex < this.inputBuffer.length) {
      this.inputBuffer = this.inputBuffer.slice(0, this.cursorIndex + 1);
    }
  }

  moveCursorLeft() {
    this.resetTabCompletion();
    if (this.cursorIndex > 0) this.cursorIndex--;
  }

  moveCursorRight() {
    this.resetTabCompletion();
    if (this.cursorIndex < this.inputBuffer.length) this.cursorIndex++;
  }

  deleteWord() {
    this.resetTabCompletion();
    if (this.cursorIndex === 0) return;
    const leftPart = this.inputBuffer.slice(0, this.cursorIndex).trimEnd();
    const lastSpace = leftPart.lastIndexOf(' ');
    const newLeft = lastSpace === -1 ? '' : leftPart.slice(0, lastSpace + 1);
    this.inputBuffer = newLeft + this.inputBuffer.slice(this.cursorIndex);
    this.cursorIndex = newLeft.length;
  }

  clearInput() {
    this.resetTabCompletion();
    this.inputBuffer = '';
    this.cursorIndex = 0;
  }

  pushHistory(command) {
    if (command.trim()) {
      this.history.push(command);
      this.notifyProfileChange();
    }
    this.historyIndex = -1;
    this.tempInput = '';
  }

  historyUp() {
    if (this.history.length === 0) return;
    if (this.historyIndex === -1) {
      this.tempInput = this.inputBuffer;
      this.historyIndex = this.history.length - 1;
    } else if (this.historyIndex > 0) {
      this.historyIndex--;
    }
    this.inputBuffer = this.history[this.historyIndex] || '';
    this.cursorIndex = this.inputBuffer.length;
  }

  historyDown() {
    if (this.historyIndex === -1) return;
    if (this.historyIndex < this.history.length - 1) {
      this.historyIndex++;
      this.inputBuffer = this.history[this.historyIndex];
    } else {
      this.historyIndex = -1;
      this.inputBuffer = this.tempInput;
    }
    this.cursorIndex = this.inputBuffer.length;
  }

  scrollUp(amount = 3) {
    this.scrollOffset += amount;
  }

  scrollDown(amount = 3) {
    this.scrollOffset = Math.max(0, this.scrollOffset - amount);
  }

  notifyNewMessage() {
    try {
      this.socket.write('\x07');
    } catch {}
  }

  formatTime(isoString) {
    return TerminalRenderer.formatTime(isoString);
  }

  sanitizeContent(str) {
    return TerminalRenderer.sanitizeContent(str);
  }

  wrapLineStrict(line, maxWidth) {
    return TerminalRenderer.wrapLineStrict(line, maxWidth);
  }

  formatMessagesToLines(messages, maxLineWidth) {
    return this.renderer.formatMessagesToLines(messages, maxLineWidth);
  }

  calculateInputRender() {
    return this.renderer.calculateInputRender();
  }

  renderInputOnly() {
    this.renderer.renderInputOnly();
  }

  renderFull(messages = []) {
    this.renderer.renderFull(messages);
  }
}