import { ANSI } from '../utils/ansi.js';
import { I18n } from '../locales/i18n.js';

export class TerminalSession {
  constructor(socket, userAddress, initialProfile, getOnlineUsersFn) {
    this.socket = socket;
    this.userAddress = userAddress;
    this.getOnlineUsers = getOnlineUsersFn;
    this.activeTarget = '#genel';

    this.inputBuffer = '';
    this.cursorIndex = 0;
    this.history = initialProfile?.history || [];
    this.historyIndex = -1;
    this.tempInput = '';

    this.focus = 'input';
    this.contacts = initialProfile?.contacts || ['*sistem', '#genel'];
    this.selectedContactIdx = this.contacts.indexOf('#genel') !== -1 ? this.contacts.indexOf('#genel') : 1;

    this.unreadCounts = new Map();
    this.isManualPasteMode = false;
    this.manualPasteLines = [];

    this.systemLogs = [
      {
        from: '[SİSTEM]',
        content: I18n.t('SYS_WELCOME', { address: userAddress }),
        timestamp: new Date().toISOString()
      },
      {
        from: '[SİSTEM]',
        content: I18n.t('SYS_HELP_TIP'),
        timestamp: new Date().toISOString()
      }
    ];

    this.scrollOffset = 0;
    this.typingUser = null;
    this.typingTimeout = null;

    this.width = 90;
    this.height = 24;
    this.sidebarWidth = 26;
  }

  addContact(target) {
    if (!this.contacts.includes(target)) {
      this.contacts.push(target);
    }
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
  }

  addSystemLog(content) {
    this.systemLogs.push({
      from: '[SİSTEM]',
      content,
      timestamp: new Date().toISOString()
    });
    if (this.activeTarget !== '*sistem') {
      this.incrementUnread('*sistem');
    }
    if (this.systemLogs.length > 200) {
      this.systemLogs.shift();
    }
  }

  setTyping(user, renderCallback = null) {
    this.typingUser = user;
    if (renderCallback) renderCallback();

    if (this.typingTimeout) clearTimeout(this.typingTimeout);
    this.typingTimeout = setTimeout(() => {
      this.typingUser = null;
      if (renderCallback) renderCallback();
    }, 3000);
  }

  insertChar(char) {
    this.inputBuffer = this.inputBuffer.slice(0, this.cursorIndex) + char + this.inputBuffer.slice(this.cursorIndex);
    this.cursorIndex += char.length;
  }

  backspace() {
    if (this.cursorIndex > 0) {
      this.inputBuffer = this.inputBuffer.slice(0, this.cursorIndex - 1) + this.inputBuffer.slice(this.cursorIndex);
      this.cursorIndex--;
    }
  }

  resize(width, height) {
    // Minimum 60 sütun ve 15 satır garanti edilir
    this.width = Math.max(60, width || 90);
    this.height = Math.max(15, height || 24);
    // Sol menü genişliği pencere boyutuna göre dengeli kalsın
    this.sidebarWidth = Math.min(30, Math.max(20, Math.floor(this.width * 0.28)));
  }

  deleteForward() {
    if (this.cursorIndex < this.inputBuffer.length) {
      this.inputBuffer = this.inputBuffer.slice(0, this.cursorIndex) + this.inputBuffer.slice(this.cursorIndex + 1);
    }
  }

  moveCursorLeft() {
    if (this.cursorIndex > 0) this.cursorIndex--;
  }

  moveCursorRight() {
    if (this.cursorIndex < this.inputBuffer.length) this.cursorIndex++;
  }

  moveCursorHome() {
    this.cursorIndex = 0;
  }

  moveCursorEnd() {
    this.cursorIndex = this.inputBuffer.length;
  }

  deleteWord() {
    if (this.cursorIndex === 0) return;
    const leftPart = this.inputBuffer.slice(0, this.cursorIndex).trimEnd();
    const lastSpace = leftPart.lastIndexOf(' ');
    const newLeft = lastSpace === -1 ? '' : leftPart.slice(0, lastSpace + 1);
    this.inputBuffer = newLeft + this.inputBuffer.slice(this.cursorIndex);
    this.cursorIndex = newLeft.length;
  }

  clearInput() {
    this.inputBuffer = '';
    this.cursorIndex = 0;
  }

  pushHistory(command) {
    if (command.trim()) this.history.push(command);
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

  // Metindeki tüm zararlı görünmez karakterleri ve satır sonlarını arındırır
  sanitizeContent(str) {
    return (str || '')
      .replace(/\x00/g, '')
      .replace(/\r\n/g, '\n')
      .replace(/\r/g, '\n')
      .replace(/\t/g, '  ');
  }

  // Verilen satırı genişlik sınırına göre parçalara ayırır
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

    for (const msg of messages) {
      const isMe = msg.from === this.userAddress;
      const isSystem = msg.from === '[SİSTEM]';
      const sender = isSystem ? I18n.t('TUI_SYSTEM_SENDER') : (isMe ? I18n.t('TUI_ME_SENDER_YOU') : msg.from.split(':')[0].replace('@', ''));
      const timeStr = `${ANSI.FG_GRAY}${this.formatTime(msg.timestamp)}${ANSI.RESET}`;

      let color = isMe ? ANSI.FG_CYAN : ANSI.FG_MAGENTA;
      if (isSystem) color = ANSI.FG_YELLOW + ANSI.BOLD;

      const raw = this.sanitizeContent(msg.content);
      const isMultiLine = raw.includes('\n') || msg.isSnippet;

      // 1. Çok Satırlı Kod / Snippet Bloğu
      if (isMultiLine) {
        const titleLine = `${timeStr} ${color}[${sender}]${ANSI.RESET} ${ANSI.DIM}--- [KOD / METİN BLOKU] ---${ANSI.RESET}`;
        formattedLines.push(titleLine);

        const lines = raw.split('\n');
        const codeMaxWidth = Math.max(10, maxLineWidth - 3); // "│ " (2) + pay

        for (const line of lines) {
          const chunks = this.wrapLineStrict(line, codeMaxWidth);
          for (const chunk of chunks) {
            formattedLines.push(`${ANSI.FG_GREEN}│${ANSI.RESET} ${ANSI.FG_WHITE}${chunk}${ANSI.RESET}`);
          }
        }
        continue;
      }

      // 2. /me Eylem Mesajı
      if (msg.isAction) {
        const fullActionText = `* ${sender} ${raw}`;
        const chunks = this.wrapLineStrict(fullActionText, maxLineWidth - 6);
        for (const chunk of chunks) {
          formattedLines.push(`${timeStr} ${ANSI.FG_YELLOW}${chunk}${ANSI.RESET}`);
        }
        continue;
      }

      // 3. Normal Tek Satırlı Mesaj
      const prefix = `[${sender}] `;
      const prefixLen = 6 + prefix.length;
      const maxTextWidth = Math.max(10, maxLineWidth - prefixLen);
      const indent = ' '.repeat(prefixLen);
      const chunks = this.wrapLineStrict(raw, maxTextWidth);

      chunks.forEach((chunk, idx) => {
        if (idx === 0) {
          formattedLines.push(`${timeStr} ${color}${prefix}${ANSI.RESET}${chunk}`);
        } else {
          formattedLines.push(`${indent}${chunk}`);
        }
      });
    }

    return formattedLines;
  }

  renderInputOnly() {
    try {
      const inputColor = this.focus === 'input' ? ANSI.FG_GREEN : ANSI.FG_GRAY;
      let out = ANSI.CURSOR_MOVE(this.height, 1) + ANSI.CLEAR_LINE;
      const promptSymbol = this.isManualPasteMode ? '[PASTE]> ' : '> ';
      out += `${inputColor}${promptSymbol}${ANSI.RESET}${this.inputBuffer}`;
      out += ANSI.CURSOR_MOVE(this.height, promptSymbol.length + 1 + this.cursorIndex);
      this.socket.write(out);
    } catch {}
  }

  renderFull(messages = []) {
    try {
      let out = ANSI.CLEAR;
      const innerLeftWidth = this.sidebarWidth - 2; // 24 karakter
      const innerRightWidth = this.width - this.sidebarWidth - 1; // 63 karakter
      const onlineList = this.getOnlineUsers ? this.getOnlineUsers() : [];

      const activeMessages = this.activeTarget === '*sistem' ? this.systemLogs : messages;

      // 1. Üst Başlık
      const focusHint = this.focus === 'sidebar'
        ? I18n.t('TUI_HINT_SIDEBAR_FOCUS')
        : I18n.t('TUI_HINT_INPUT_FOCUS');

      const titleText = I18n.t('TUI_HEADER_TITLE', { address: this.userAddress });
      const spaceBetween = Math.max(1, this.width - titleText.length - focusHint.length);
      out += ANSI.CURSOR_MOVE(1, 1) + ANSI.BG_HEADER + ANSI.FG_CYAN + ANSI.BOLD;
      out += titleText + ' '.repeat(spaceBetween) + ANSI.FG_YELLOW + focusHint + ANSI.RESET;

      // 2. Üst Çerçeve
      const leftTitle = this.focus === 'sidebar' ? I18n.t('TUI_SIDEBAR_HEADER_FOCUSED') : I18n.t('TUI_SIDEBAR_HEADER_UNFOCUSED');
      const scrollInfo = this.scrollOffset > 0 ? ` [▲ +${this.scrollOffset}]` : '';
      const rightTitle = I18n.t('TUI_CHAT_HEADER', { target: this.activeTarget || I18n.t('TUI_CHAT_NO_TARGET'), scroll: scrollInfo });
      const leftBorderColor = this.focus === 'sidebar' ? ANSI.FG_YELLOW : ANSI.FG_CYAN;

      let topBorder = ANSI.CURSOR_MOVE(2, 1) + '+';
      topBorder += leftBorderColor + ANSI.BOLD + leftTitle + ANSI.RESET + '-'.repeat(Math.max(0, innerLeftWidth - leftTitle.length)) + '+';
      topBorder += ANSI.FG_CYAN + ANSI.BOLD + rightTitle + ANSI.RESET + '-'.repeat(Math.max(0, innerRightWidth - rightTitle.length)) + '+';
      out += topBorder;

      // 3. Gövde
      const chatHeight = this.height - 4;
      const allFormattedLines = this.formatMessagesToLines(activeMessages, innerRightWidth - 2);

      const totalLines = allFormattedLines.length;
      const maxScroll = Math.max(0, totalLines - (chatHeight - 2));
      this.scrollOffset = Math.min(this.scrollOffset, maxScroll);

      const endIdx = totalLines - this.scrollOffset;
      const startIdx = Math.max(0, endIdx - (chatHeight - 2));
      const visibleLines = allFormattedLines.slice(startIdx, endIdx);

      for (let i = 1; i <= chatHeight - 2; i++) {
        const row = 2 + i;

        // Sol Bölme
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

          if (contact === '*sistem') {
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

          const maxTextLen = innerLeftWidth - 4 - unreadBadge.length;
          const visibleName = contact.slice(0, Math.max(0, maxTextLen));

          let nameColor = isCurrent ? ANSI.FG_GREEN + ANSI.BOLD : ANSI.FG_GRAY;
          if (contact === '*sistem' && !isCurrent) nameColor = ANSI.FG_YELLOW;
          if (unread > 0 && !isCurrent) nameColor = ANSI.FG_WHITE + ANSI.BOLD;
          if (isSelected) nameColor = ANSI.BG_HEADER + ANSI.FG_YELLOW + ANSI.BOLD;

          const badgeStr = unread > 0 ? `${ANSI.FG_RED}${ANSI.BOLD}${unreadBadge}${ANSI.RESET}` : '';
          const fullLabel = `${statusColor}${statusChar}${ANSI.RESET} ${prefix} ${nameColor}${visibleName}${ANSI.RESET}${badgeStr}`;
          const plainLength = (statusChar + ' ' + prefix + ' ' + visibleName + unreadBadge).length;
          const padding = ' '.repeat(Math.max(0, innerLeftWidth - plainLength));

          leftCell = `${fullLabel}${padding}`;
        }

        // Sağ Bölme (ANSI temizleme ve matematiksel genişlik kilitleme)
        let rightCell = ' '.repeat(innerRightWidth);
        const lineContent = visibleLines[i - 1];
        if (lineContent !== undefined) {
          const plainLength = lineContent.replace(/\x1b\[[0-9;]*m/g, '').length;
          const padding = ' '.repeat(Math.max(0, innerRightWidth - plainLength));
          rightCell = `${lineContent}${padding}`;
        }

        out += ANSI.CURSOR_MOVE(row, 1) + '|' + leftCell + '|' + rightCell + '|';
      }

      // 4. Alt Çerçeve
      out += ANSI.CURSOR_MOVE(this.height - 2, 1) + '+' + '-'.repeat(innerLeftWidth) + '+' + '-'.repeat(innerRightWidth) + '+';

      // 5. Bilgi Çubuğu
      out += ANSI.CURSOR_MOVE(this.height - 1, 1) + ANSI.BG_INPUT + ANSI.FG_WHITE;
      let bottomBarText = I18n.t('TUI_BOTTOM_INFO');
      if (this.isManualPasteMode) {
        bottomBarText = ` ${ANSI.FG_YELLOW}[PASTE MODU AKTİF - /end ile gönder, /cancel ile çık]${ANSI.RESET}`;
      } else if (this.typingUser) {
        bottomBarText = I18n.t('TUI_TYPING_INDICATOR', { user: this.typingUser });
      }
      out += bottomBarText.padEnd(this.width) + ANSI.RESET;

      // 6. Giriş Satırı
      const inputBorderColor = this.focus === 'input' ? ANSI.FG_GREEN : ANSI.FG_GRAY;
      out += ANSI.CURSOR_MOVE(this.height, 1) + ANSI.CLEAR_LINE;
      const promptSymbol = this.isManualPasteMode ? '[PASTE]> ' : '> ';
      out += `${inputBorderColor}${promptSymbol}${ANSI.RESET}${this.inputBuffer}`;
      out += ANSI.CURSOR_MOVE(this.height, promptSymbol.length + 1 + this.cursorIndex);

      this.socket.write(out);
    } catch {}
  }
}