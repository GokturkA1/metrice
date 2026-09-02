import { EventEmitter } from 'node:events';
import { ANSI } from '../utils/ansi.js';
import { I18n } from '../locales/i18n.js';

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

    const savedContacts = initialProfile?.contacts || [];
    const baseContacts = [systemConsole, defaultChannel];
    this.contacts = Array.from(new Set([...baseContacts, ...savedContacts]));
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
    return this.contacts.includes(target);
  }

  getMyChannels() {
    return this.contacts.filter((c) => c.startsWith('#'));
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
    if (!this.contacts.includes(target)) {
      this.contacts.push(target);
      this.notifyProfileChange();
    }
  }

  removeContact(target) {
    this.contacts = this.contacts.filter((c) => c !== target);
    this.unreadCounts.delete(target);
    if (this.selectedContactIdx >= this.contacts.length) {
      this.selectedContactIdx = Math.max(0, this.contacts.length - 1);
    }
    this.notifyProfileChange();
    this.emit('request_render');
  }

  incrementUnread(target) {
    if (this.activeTarget === target) return;
    const current = this.unreadCounts.get(target) || 0;
    this.unreadCounts.set(target, current + 1);
  }

  setTarget(target) {
    this.activeTarget = target;
    this.addContact(target);
    this.selectedContactIdx = this.contacts.indexOf(target);
    this.unreadCounts.delete(target);
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
    if (this.activeTarget !== systemConsole) {
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
      this.inputBuffer = this.inputBuffer.slice(0, this.cursorIndex) + this.inputBuffer.slice(this.cursorIndex + 1);
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
    try {
      const d = new Date(isoString);
      return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
    } catch {
      return '--:--';
    }
  }

  sanitizeContent(str) {
    if (!str) return '';
    // 1. ANSI escape kodları (CSI, OSC, ESC dizileri) ve kontrol karakterlerini (0x00-0x08, 0x0B-0x0C, 0x0E-0x1F, 0x7F) temizle
    const ansiRegex = /[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g;
    const oscRegex = /\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g;
    const controlCharsRegex = /[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]/g;

    return str
      .replace(oscRegex, '')
      .replace(ansiRegex, '')
      .replace(controlCharsRegex, '')
      .replace(/\r\n/g, '\n')
      .replace(/\r/g, '\n')
      .replace(/\t/g, '  ');
  }

  wrapLineStrict(line, maxWidth) {
    if (!line) return [''];
    if (line.length <= maxWidth) return [line];

    const chunks = [];
    let cur = line;
    while (cur.length > maxWidth) {
      chunks.push(cur.slice(0, maxWidth));
      cur = cur.slice(maxWidth);
    }
    if (cur.length > 0) chunks.push(cur);
    return chunks;
  }

  formatMessagesToLines(messages, maxLineWidth) {
    const formattedLines = [];
    const systemSender = I18n.t('TUI_SYSTEM_SENDER');

    for (const msg of messages) {
      const isMe = msg.from === this.userAddress;
      const isSystem = msg.from === `[${systemSender}]` || msg.from === '[SİSTEM]';
      const sender = isSystem ? systemSender : (isMe ? I18n.t('TUI_ME_SENDER_YOU') : msg.from.split(':')[0].replace('@', ''));
      const timeStr = `${ANSI.FG_GRAY}${this.formatTime(msg.timestamp)}${ANSI.RESET}`;

      // Çözülememiş ham E2EE paketi kontrolü
      const isUndecryptedE2EE = typeof msg.content === 'string' && msg.content.startsWith('e2ee:');

      // Ham şifreli metin yerine kalın kırmızı placeholder göster
      let raw = isUndecryptedE2EE
        ? `${ANSI.BOLD}${ANSI.FG_RED}${I18n.t('E2EE_ENCRYPTED_PLACEHOLDER')}${ANSI.RESET}`
        : this.sanitizeContent(msg.content);

      const isMentioned = !isMe && !isSystem && !isUndecryptedE2EE && this.isUserMentioned(msg.content);

      let color = isMe ? ANSI.FG_CYAN : ANSI.FG_MAGENTA;
      if (isSystem) color = ANSI.FG_YELLOW + ANSI.BOLD;

      const lockBadge = msg.isE2EE ? `${ANSI.FG_YELLOW}🔒${ANSI.RESET} ` : '';

      const isMultiLine = !isUndecryptedE2EE && (raw.includes('\n') || msg.isSnippet);
      const mentionPrefix = isMentioned ? `${ANSI.BG_HEADER}${ANSI.FG_YELLOW}[@] ` : '';
      const mentionSuffix = isMentioned ? `${ANSI.RESET}` : '';

      if (isMultiLine) {
        const titleLine = `${timeStr} ${lockBadge}${mentionPrefix}${color}[${sender}]${ANSI.RESET} ${ANSI.DIM}${I18n.t('TUI_SNIPPET_TITLE')}${ANSI.RESET}${mentionSuffix}`;
        formattedLines.push(titleLine);

        const lines = raw.split('\n');
        const codeMaxWidth = Math.max(10, maxLineWidth - 3);

        for (const line of lines) {
          const chunks = this.wrapLineStrict(line, codeMaxWidth);
          for (const chunk of chunks) {
            formattedLines.push(`${ANSI.FG_GREEN}│${ANSI.RESET} ${ANSI.FG_WHITE}${chunk}${ANSI.RESET}`);
          }
        }
        continue;
      }

      if (msg.isAction && !isUndecryptedE2EE) {
        const fullActionText = `* ${sender} ${raw}`;
        const chunks = this.wrapLineStrict(fullActionText, maxLineWidth - 6);
        for (const chunk of chunks) {
          formattedLines.push(`${timeStr} ${lockBadge}${mentionPrefix}${ANSI.FG_YELLOW}${chunk}${ANSI.RESET}${mentionSuffix}`);
        }
        continue;
      }

      const prefix = `[${sender}] `;
      const prefixLen = 6 + prefix.length + (msg.isE2EE ? 2 : 0) + (isMentioned ? 4 : 0);
      const maxTextWidth = Math.max(10, maxLineWidth - prefixLen);
      const indent = ' '.repeat(prefixLen);
      const chunks = this.wrapLineStrict(raw, maxTextWidth);

      chunks.forEach((chunk, idx) => {
        if (idx === 0) {
          formattedLines.push(`${timeStr} ${lockBadge}${mentionPrefix}${color}${prefix}${ANSI.RESET}${chunk}${mentionSuffix}`);
        } else {
          formattedLines.push(`${indent}${chunk}`);
        }
      });
    }

    return formattedLines;
  }

  calculateInputRender() {
    const inputColor = this.focus === 'input' ? ANSI.FG_GREEN : ANSI.FG_GRAY;
    const maxInputWidth = Math.max(10, this.width - 4);

    let visibleText = this.inputBuffer;
    let visualCursor = this.cursorIndex;

    if (this.inputBuffer.length > maxInputWidth) {
      let start = Math.max(0, this.cursorIndex - Math.floor(maxInputWidth / 2));
      if (start + maxInputWidth > this.inputBuffer.length) {
        start = Math.max(0, this.inputBuffer.length - maxInputWidth);
      }
      visibleText = this.inputBuffer.slice(start, start + maxInputWidth);
      visualCursor = this.cursorIndex - start;
    }

    const padding = ' '.repeat(Math.max(0, maxInputWidth - visibleText.length));
    const lineContent = `${inputColor}> ${ANSI.RESET}${visibleText}${padding}`;
    const cursorCol = 3 + visualCursor;

    return { lineContent, cursorCol };
  }

  renderInputOnly() {
    try {
      if (this.width < 70 || this.height < 12) return;

      const { lineContent, cursorCol } = this.calculateInputRender();
      this.screenBuffer[this.height - 1] = lineContent;

      let out = ANSI.CURSOR_MOVE(this.height, 1) + ANSI.CLEAR_LINE;
      out += lineContent;
      out += ANSI.CURSOR_MOVE(this.height, cursorCol);
      this.socket.write(out);
    } catch {}
  }

  renderFull(messages = []) {
    try {
      if (this.width < 75 || this.height < 14) {
        let warn = ANSI.CLEAR + ANSI.CURSOR_MOVE(Math.floor(this.height / 2), 2);
        warn += `${ANSI.FG_YELLOW}Terminal çok küçük! Lütfen büyütün (Min: 80x15). Şu an: ${this.width}x${this.height}${ANSI.RESET}`;
        this.screenBuffer = [];
        this.socket.write(warn);
        return;
      }

      const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');
      const isSystemWindow = this.activeTarget === systemConsole;
      const newFrame = new Array(this.height);

      const innerLeftWidth = Math.max(10, this.leftSidebarWidth - 2);
      const innerRightWidth = Math.max(10, this.rightSidebarWidth - 2);
      const innerMidWidth = Math.max(10, this.width - this.leftSidebarWidth - this.rightSidebarWidth - 1);

      const onlineList = this.getOnlineUsers ? this.getOnlineUsers() : [];

      let rightPanelLines = [];
      let rightTitle = '';

      if (isSystemWindow) {
        const stats = this.getSystemStats ? this.getSystemStats() : { uptime: '-', rss: '-', peers: [] };
        rightTitle = ' [Düğüm & Eşler] ';
        rightPanelLines.push(`${ANSI.FG_CYAN}UPTIME :${ANSI.RESET} ${stats.uptime}`);
        rightPanelLines.push(`${ANSI.FG_CYAN}RAM    :${ANSI.RESET} ${stats.rss}MB`);
        rightPanelLines.push(`${ANSI.FG_GRAY}----------------${ANSI.RESET}`);
        rightPanelLines.push(`${ANSI.FG_YELLOW}EŞLER (${stats.peers.length}):${ANSI.RESET}`);
        if (stats.peers.length === 0) {
          rightPanelLines.push(`${ANSI.FG_GRAY}(Eş yok)${ANSI.RESET}`);
        } else {
          stats.peers.forEach((p) => {
            rightPanelLines.push(`${ANSI.FG_GREEN}●${ANSI.RESET} ${p}`);
          });
        }
      } else {
        let channelMembers = [];
        if (this.getChannelMembers) {
          channelMembers = this.getChannelMembers(this.activeTarget);
        }
        rightTitle = I18n.t('TUI_MEMBERS_HEADER', { count: channelMembers.length });
        channelMembers.forEach((member) => {
          const isOnline = onlineList.includes(member);
          const isMe = member === this.userAddress;
          const statusChar = isOnline ? '●' : '○';
          const statusColor = isOnline ? ANSI.FG_GREEN : ANSI.FG_GRAY;
          const memberNick = member.split(':')[0].replace('@', '');
          const maxNameLen = Math.max(4, innerRightWidth - 3);
          const visibleMember = memberNick.slice(0, maxNameLen);
          const nameColor = isMe ? ANSI.FG_CYAN + ANSI.BOLD : (isOnline ? ANSI.FG_WHITE : ANSI.FG_GRAY);
          rightPanelLines.push(`${statusColor}${statusChar}${ANSI.RESET} ${nameColor}${visibleMember}${ANSI.RESET}`);
        });
      }

      const activeMessages = isSystemWindow ? this.systemLogs : messages;

      const focusHint = this.focus === 'sidebar'
        ? I18n.t('TUI_HINT_SIDEBAR_FOCUS')
        : I18n.t('TUI_HINT_INPUT_FOCUS');

      const e2eeBadge = this.isSsh ? I18n.t('E2EE_ACTIVE_BADGE') : I18n.t('E2EE_INACTIVE_BADGE');
      const titleText = I18n.t('TUI_HEADER_TITLE', { address: this.userAddress }) + e2eeBadge;
      const spaceBetween = Math.max(1, this.width - titleText.length - focusHint.length);
      newFrame[0] = ANSI.BG_HEADER + ANSI.FG_CYAN + ANSI.BOLD + titleText + ' '.repeat(spaceBetween) + ANSI.FG_YELLOW + focusHint + ANSI.RESET;

      const leftTitle = this.focus === 'sidebar' ? I18n.t('TUI_SIDEBAR_HEADER_FOCUSED') : I18n.t('TUI_SIDEBAR_HEADER_UNFOCUSED');
      const scrollInfo = this.scrollOffset > 0 ? ` [▲ +${this.scrollOffset}]` : '';
      const midTitle = I18n.t('TUI_CHAT_HEADER', { target: this.activeTarget || I18n.t('TUI_CHAT_NO_TARGET'), scroll: scrollInfo });
      const leftBorderColor = this.focus === 'sidebar' ? ANSI.FG_YELLOW : ANSI.FG_CYAN;

      let topBorder = '+';
      topBorder += leftBorderColor + ANSI.BOLD + leftTitle + ANSI.RESET + '-'.repeat(Math.max(0, innerLeftWidth - leftTitle.length)) + '+';
      topBorder += ANSI.FG_CYAN + ANSI.BOLD + midTitle + ANSI.RESET + '-'.repeat(Math.max(0, innerMidWidth - midTitle.length)) + '+';
      topBorder += (isSystemWindow ? ANSI.FG_YELLOW : ANSI.FG_GRAY) + ANSI.BOLD + rightTitle + ANSI.RESET + '-'.repeat(Math.max(0, innerRightWidth - rightTitle.length)) + '+';
      newFrame[1] = topBorder;

      const chatHeight = this.height - 4;
      const allFormattedLines = this.formatMessagesToLines(activeMessages, innerMidWidth - 2);

      const totalLines = allFormattedLines.length;
      const maxScroll = Math.max(0, totalLines - (chatHeight - 2));
      this.scrollOffset = Math.min(this.scrollOffset, maxScroll);

      const endIdx = totalLines - this.scrollOffset;
      const startIdx = Math.max(0, endIdx - (chatHeight - 2));
      const visibleLines = allFormattedLines.slice(startIdx, endIdx);

      for (let i = 1; i <= chatHeight - 2; i++) {
        const frameIndex = 1 + i;

        let leftCell = ' '.repeat(innerLeftWidth);
        const contactIdx = i - 1;
        if (this.contacts[contactIdx]) {
          const contact = this.contacts[contactIdx];
          const isCurrent = contact === this.activeTarget;
          const isSelected = this.focus === 'sidebar' && contactIdx === this.selectedContactIdx;
          const isOnline = onlineList.includes(contact);
          const unread = this.unreadCounts.get(contact) || 0;

          let statusChar = '○';
          let statusColor = ANSI.FG_GRAY;

          if (contact === systemConsole) {
            statusChar = '★';
            statusColor = ANSI.FG_YELLOW;
          } else if (contact.startsWith('#')) {
            statusChar = '#';
            statusColor = ANSI.FG_CYAN;
          } else if (isOnline) {
            statusChar = '●';
            statusColor = ANSI.FG_GREEN;
          }

          const prefix = isCurrent ? '>' : (isSelected ? '▶' : ' ');
          const unreadBadge = unread > 0 ? ` (${unread})` : '';

          const maxTextLen = Math.max(4, innerLeftWidth - 4 - unreadBadge.length);
          const visibleName = contact.slice(0, maxTextLen);

          let nameColor = isCurrent ? ANSI.FG_GREEN + ANSI.BOLD : ANSI.FG_GRAY;
          if (contact === systemConsole && !isCurrent) nameColor = ANSI.FG_YELLOW;
          if (unread > 0 && !isCurrent) nameColor = ANSI.FG_WHITE + ANSI.BOLD;
          if (isSelected) nameColor = ANSI.BG_HEADER + ANSI.FG_YELLOW + ANSI.BOLD;

          const badgeStr = unread > 0 ? `${ANSI.FG_RED}${ANSI.BOLD}${unreadBadge}${ANSI.RESET}` : '';
          const fullLabel = `${statusColor}${statusChar}${ANSI.RESET} ${prefix} ${nameColor}${visibleName}${ANSI.RESET}${badgeStr}`;
          const plainLength = (statusChar + ' ' + prefix + ' ' + visibleName + unreadBadge).length;
          const padding = ' '.repeat(Math.max(0, innerLeftWidth - plainLength));

          leftCell = `${fullLabel}${padding}`;
        }

        let midCell = ' '.repeat(innerMidWidth);
        const lineContent = visibleLines[i - 1];
        if (lineContent !== undefined) {
          const plainLength = lineContent.replace(/\x1b\[[0-9;]*m/g, '').length;
          const padding = ' '.repeat(Math.max(0, innerMidWidth - plainLength));
          midCell = `${lineContent}${padding}`;
        }

        let rightCell = ' '.repeat(innerRightWidth);
        const rContent = rightPanelLines[i - 1];
        if (rContent !== undefined) {
          const plainLength = rContent.replace(/\x1b\[[0-9;]*m/g, '').length;
          const padding = ' '.repeat(Math.max(0, innerRightWidth - plainLength));
          rightCell = `${rContent}${padding}`;
        }

        newFrame[frameIndex] = '|' + leftCell + '|' + midCell + '|' + rightCell + '|';
      }

      newFrame[this.height - 3] = '+' + '-'.repeat(innerLeftWidth) + '+' + '-'.repeat(innerMidWidth) + '+' + '-'.repeat(innerRightWidth) + '+';

      let bottomBarText = I18n.t('TUI_BOTTOM_INFO');
      if (this.typingUser) {
        bottomBarText = I18n.t('TUI_TYPING_INDICATOR', { user: this.typingUser });
      }
      newFrame[this.height - 2] = ANSI.BG_INPUT + ANSI.FG_WHITE + bottomBarText.padEnd(this.width) + ANSI.RESET;

      const { lineContent, cursorCol } = this.calculateInputRender();
      newFrame[this.height - 1] = lineContent;

      let diffOutput = '';
      for (let r = 0; r < this.height; r++) {
        if (this.screenBuffer[r] !== newFrame[r]) {
          diffOutput += ANSI.CURSOR_MOVE(r + 1, 1) + ANSI.CLEAR_LINE + (newFrame[r] || '');
        }
      }

      diffOutput += ANSI.CURSOR_MOVE(this.height, cursorCol);

      this.screenBuffer = newFrame;
      this.socket.write(diffOutput);
    } catch {}
  }
}