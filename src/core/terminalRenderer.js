/* eslint-disable no-control-regex */
import { ANSI } from '../utils/ansi.js';
import { I18n } from '../locales/i18n.js';
import { AddressHelper } from '../utils/addressHelper.js';

export class TerminalRenderer {
  constructor(session) {
    this.session = session;
  }

  static formatTime(isoString) {
    try {
      const d = new Date(isoString);
      return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
    } catch {
      return '--:--';
    }
  }

  static sanitizeContent(str) {
    if (!str) return '';
    // ANSI escape kodlari (CSI, OSC, ESC dizileri) ve kontrol karakterlerini temizle
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

  static wrapLineStrict(line, maxWidth) {
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
    const s = this.session;

    for (const msg of messages) {
      const isMe = msg.from === s.userAddress;
      const isSystem = msg.from === `[${systemSender}]` || msg.from === '[S\u0130STEM]' || msg.from === '[SYSTEM]';
      const sender = isSystem ? systemSender : (isMe ? I18n.t('TUI_ME_SENDER_YOU') : msg.from.split(':')[0].replace('@', ''));
      const timeStr = `${ANSI.FG_GRAY}${TerminalRenderer.formatTime(msg.timestamp)}${ANSI.RESET}`;

      // Cozulememis ham E2EE paketi kontrolu
      const isUndecryptedE2EE = typeof msg.content === 'string' && msg.content.startsWith('e2ee:');

      // Ham sifreli metin yerine kalin kirmizi placeholder goster
      let raw = isUndecryptedE2EE
        ? `${ANSI.BOLD}${ANSI.FG_RED}${I18n.t('E2EE_ENCRYPTED_PLACEHOLDER')}${ANSI.RESET}`
        : TerminalRenderer.sanitizeContent(msg.content);

      const isMentioned = !isMe && !isSystem && !isUndecryptedE2EE && s.isUserMentioned(msg.content);

      let color = isMe ? ANSI.FG_CYAN : ANSI.FG_MAGENTA;
      if (isSystem) color = ANSI.FG_YELLOW + ANSI.BOLD;

      const lockBadge = msg.isE2EE ? `${ANSI.FG_YELLOW}[SEC]${ANSI.RESET} ` : '';

      const isMultiLine = !isUndecryptedE2EE && (raw.includes('\n') || msg.isSnippet);
      const mentionPrefix = isMentioned ? `${ANSI.BG_HEADER}${ANSI.FG_YELLOW}[@] ` : '';
      const mentionSuffix = isMentioned ? `${ANSI.RESET}` : '';

      if (isMultiLine) {
        const titleLine = `${timeStr} ${lockBadge}${mentionPrefix}${color}[${sender}]${ANSI.RESET} ${ANSI.DIM}${I18n.t('TUI_SNIPPET_TITLE')}${ANSI.RESET}${mentionSuffix}`;
        formattedLines.push(titleLine);

        const lines = raw.split('\n');
        const codeMaxWidth = Math.max(10, maxLineWidth - 3);

        for (const line of lines) {
          const chunks = TerminalRenderer.wrapLineStrict(line, codeMaxWidth);
          for (const chunk of chunks) {
            formattedLines.push(`${ANSI.FG_GREEN}\u2502${ANSI.RESET} ${ANSI.FG_WHITE}${chunk}${ANSI.RESET}`);
          }
        }
        continue;
      }

      if (msg.isAction && !isUndecryptedE2EE) {
        const fullActionText = `* ${sender} ${raw}`;
        const chunks = TerminalRenderer.wrapLineStrict(fullActionText, maxLineWidth - 6);
        for (const chunk of chunks) {
          formattedLines.push(`${timeStr} ${lockBadge}${mentionPrefix}${ANSI.FG_YELLOW}${chunk}${ANSI.RESET}${mentionSuffix}`);
        }
        continue;
      }

      const prefix = `[${sender}] `;
      const prefixLen = 6 + prefix.length + (msg.isE2EE ? 2 : 0) + (isMentioned ? 4 : 0);
      const maxTextWidth = Math.max(10, maxLineWidth - prefixLen);
      const indent = ' '.repeat(prefixLen);
      const chunks = TerminalRenderer.wrapLineStrict(raw, maxTextWidth);

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
    const s = this.session;
    const inputColor = s.focus === 'input' ? ANSI.FG_GREEN : ANSI.FG_GRAY;
    const maxInputWidth = Math.max(10, s.width - 4);

    let visibleText = s.inputBuffer;
    let visualCursor = s.cursorIndex;

    if (s.inputBuffer.length > maxInputWidth) {
      let start = Math.max(0, s.cursorIndex - Math.floor(maxInputWidth / 2));
      if (start + maxInputWidth > s.inputBuffer.length) {
        start = Math.max(0, s.inputBuffer.length - maxInputWidth);
      }
      visibleText = s.inputBuffer.slice(start, start + maxInputWidth);
      visualCursor = s.cursorIndex - start;
    }

    const padding = ' '.repeat(Math.max(0, maxInputWidth - visibleText.length));
    const lineContent = `${inputColor}> ${ANSI.RESET}${visibleText}${padding}`;
    const cursorCol = 3 + visualCursor;

    return { lineContent, cursorCol };
  }

  renderInputOnly() {
    try {
      const s = this.session;
      if (s.width < 70 || s.height < 12) return;

      const { lineContent, cursorCol } = this.calculateInputRender();
      s.screenBuffer[s.height - 1] = lineContent;

      let out = ANSI.CURSOR_MOVE(s.height, 1) + ANSI.CLEAR_LINE;
      out += lineContent;
      out += ANSI.CURSOR_MOVE(s.height, cursorCol);
      s.socket.write(out);
    } catch {}
  }

  renderFull(messages = []) {
    try {
      const s = this.session;
      if (s.width < 75 || s.height < 14) {
        let warn = ANSI.CLEAR + ANSI.CURSOR_MOVE(Math.floor(s.height / 2), 2);
        warn += `${ANSI.FG_YELLOW}${I18n.t('TUI_SCREEN_TOO_SMALL', { width: s.width, height: s.height })}${ANSI.RESET}`;
        s.screenBuffer = [];
        s.socket.write(warn);
        return;
      }

      const isSystemWindow = AddressHelper.isSystemConsole(s.activeTarget);
      const newFrame = Array.from({ length: s.height });

      const innerLeftWidth = Math.max(10, s.leftSidebarWidth - 2);
      const innerRightWidth = Math.max(10, s.rightSidebarWidth - 2);
      const innerMidWidth = Math.max(10, s.width - s.leftSidebarWidth - s.rightSidebarWidth - 1);

      const onlineList = s.getOnlineUsers ? s.getOnlineUsers() : [];

      let rightPanelLines = [];
      let rightTitle = '';

      if (isSystemWindow) {
        const stats = s.getSystemStats ? s.getSystemStats() : { uptime: '-', rss: '-', peers: [] };
        rightTitle = I18n.t('TUI_SYS_PANEL_TITLE');
        if (stats.nodeId) {
          rightPanelLines.push(`${ANSI.FG_CYAN}Node:${ANSI.RESET} ${stats.nodeId.slice(0, 10)}`);
        }
        if (stats.role) {
          rightPanelLines.push(`${ANSI.FG_CYAN}Rol:${ANSI.RESET} CAP_${stats.role}`);
        }
        rightPanelLines.push(`${ANSI.FG_CYAN}${I18n.t('TUI_SYS_PANEL_UPTIME')}${ANSI.RESET} ${stats.uptime}`);
        rightPanelLines.push(`${ANSI.FG_CYAN}${I18n.t('TUI_SYS_PANEL_RAM')}${ANSI.RESET} ${stats.rss}MB`);
        rightPanelLines.push(`${ANSI.FG_GRAY}----------------${ANSI.RESET}`);
        rightPanelLines.push(`${ANSI.FG_YELLOW}${I18n.t('TUI_SYS_PANEL_PEERS', { count: stats.peers.length })}${ANSI.RESET}`);
        if (stats.peers.length === 0) {
          rightPanelLines.push(`${ANSI.FG_GRAY}${I18n.t('TUI_SYS_PANEL_NO_PEERS')}${ANSI.RESET}`);
        } else {
          stats.peers.forEach((p) => {
            rightPanelLines.push(`${ANSI.FG_GREEN}\u25CF${ANSI.RESET} ${p}`);
          });
        }
      } else {
        let channelMembers = [];
        if (s.getChannelMembers) {
          channelMembers = s.getChannelMembers(s.activeTarget);
        }
        rightTitle = I18n.t('TUI_MEMBERS_HEADER', { count: channelMembers.length });
        channelMembers.forEach((member) => {
          const memberNick = member.split(':')[0].replace('@', '');
          const isOnline = onlineList.includes(member) ||
            onlineList.some((u) => {
              const uNick = u.split(':')[0].replace('@', '');
              return u === member || uNick === memberNick;
            });
          const isMe = member === s.userAddress || (s.userAddress && s.userAddress.split(':')[0].replace('@', '') === memberNick);
          const statusChar = isOnline ? '\u25CF' : '\u25CB';
          const statusColor = isOnline ? ANSI.FG_GREEN : ANSI.FG_GRAY;
          const maxNameLen = Math.max(4, innerRightWidth - 3);
          const visibleMember = memberNick.slice(0, maxNameLen);
          const nameColor = isMe ? ANSI.FG_CYAN + ANSI.BOLD : (isOnline ? ANSI.FG_WHITE : ANSI.FG_GRAY);
          rightPanelLines.push(`${statusColor}${statusChar}${ANSI.RESET} ${nameColor}${visibleMember}${ANSI.RESET}`);
        });
      }

      const activeMessages = isSystemWindow ? s.systemLogs : messages;

      const focusHint = s.focus === 'sidebar'
        ? I18n.t('TUI_HINT_SIDEBAR_FOCUS')
        : I18n.t('TUI_HINT_INPUT_FOCUS');

      const e2eeBadge = s.isSsh ? I18n.t('E2EE_ACTIVE_BADGE') : I18n.t('E2EE_INACTIVE_BADGE');
      const titleText = I18n.t('TUI_HEADER_TITLE', { address: s.userAddress }) + e2eeBadge;
      const spaceBetween = Math.max(1, s.width - titleText.length - focusHint.length);
      newFrame[0] = ANSI.BG_HEADER + ANSI.FG_CYAN + ANSI.BOLD + titleText + ' '.repeat(spaceBetween) + ANSI.FG_YELLOW + focusHint + ANSI.RESET;

      const leftTitle = s.focus === 'sidebar' ? I18n.t('TUI_SIDEBAR_HEADER_FOCUSED') : I18n.t('TUI_SIDEBAR_HEADER_UNFOCUSED');
      const scrollInfo = s.scrollOffset > 0 ? ` [\u25B2 +${s.scrollOffset}]` : '';
      const midTitle = I18n.t('TUI_CHAT_HEADER', { target: s.activeTarget || I18n.t('TUI_CHAT_NO_TARGET'), scroll: scrollInfo });
      const leftBorderColor = s.focus === 'sidebar' ? ANSI.FG_YELLOW : ANSI.FG_CYAN;

      const safeLeftTitle = leftTitle.length > innerLeftWidth ? leftTitle.slice(0, innerLeftWidth) : leftTitle;
      const safeMidTitle = midTitle.length > innerMidWidth ? midTitle.slice(0, innerMidWidth) : midTitle;
      const safeRightTitle = rightTitle.length > innerRightWidth ? rightTitle.slice(0, innerRightWidth) : rightTitle;

      let topBorder = '+';
      topBorder += leftBorderColor + ANSI.BOLD + safeLeftTitle + ANSI.RESET + '-'.repeat(Math.max(0, innerLeftWidth - safeLeftTitle.length)) + '+';
      topBorder += ANSI.FG_CYAN + ANSI.BOLD + safeMidTitle + ANSI.RESET + '-'.repeat(Math.max(0, innerMidWidth - safeMidTitle.length)) + '+';
      topBorder += (isSystemWindow ? ANSI.FG_YELLOW : ANSI.FG_GRAY) + ANSI.BOLD + safeRightTitle + ANSI.RESET + '-'.repeat(Math.max(0, innerRightWidth - safeRightTitle.length)) + '+';
      newFrame[1] = topBorder;

      const chatHeight = s.height - 4;
      const allFormattedLines = this.formatMessagesToLines(activeMessages, innerMidWidth - 2);

      const totalLines = allFormattedLines.length;
      
      const availableChatRows = s.height - 5;
      const maxScroll = Math.max(0, totalLines - availableChatRows);
      s.scrollOffset = Math.min(s.scrollOffset, maxScroll);

      const endIdx = totalLines - s.scrollOffset;
      const startIdx = Math.max(0, endIdx - (chatHeight - 2));
      const visibleLines = allFormattedLines.slice(startIdx, endIdx);

      for (let i = 1; i <= availableChatRows; i++) {
        const frameIndex = 1 + i;

        let leftCell = ' '.repeat(innerLeftWidth);
        const contactIdx = i - 1;
        if (s.contacts[contactIdx]) {
          const contact = s.contacts[contactIdx];
          const isCurrent = contact === s.activeTarget;
          const isSelected = s.focus === 'sidebar' && contactIdx === s.selectedContactIdx;
          const isOnline = onlineList.includes(contact) || 
            onlineList.some((u) => u === contact || (contact.startsWith('@') && u.split(':')[0] === contact.split(':')[0]));
          const unread = s.unreadCounts.get(contact) || 0;

          let statusChar = '\u25CB';
          let statusColor = ANSI.FG_GRAY;

          if (AddressHelper.isSystemConsole(contact)) {
            statusChar = '\u2605';
            statusColor = ANSI.FG_YELLOW;
          } else if (contact.startsWith('#')) {
            statusChar = '#';
            statusColor = ANSI.FG_CYAN;
          } else if (isOnline) {
            statusChar = '\u25CF';
            statusColor = ANSI.FG_GREEN;
          }

          const prefix = isCurrent ? '>' : (isSelected ? '\u25B6' : ' ');
          const unreadBadge = unread > 0 ? ` (${unread})` : '';

          const maxTextLen = Math.max(4, innerLeftWidth - 4 - unreadBadge.length);
          const visibleName = contact.slice(0, maxTextLen);

          let nameColor = isCurrent ? ANSI.FG_GREEN + ANSI.BOLD : ANSI.FG_GRAY;
          if (AddressHelper.isSystemConsole(contact) && !isCurrent) nameColor = ANSI.FG_YELLOW;
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

      newFrame[s.height - 3] = '+' + '-'.repeat(innerLeftWidth) + '+' + '-'.repeat(innerMidWidth) + '+' + '-'.repeat(innerRightWidth) + '+';

      let bottomBarText = I18n.t('TUI_BOTTOM_INFO');
      if (s.typingUser) {
        bottomBarText = I18n.t('TUI_TYPING_INDICATOR', { user: s.typingUser });
      }
      newFrame[s.height - 2] = ANSI.BG_INPUT + ANSI.FG_WHITE + bottomBarText.padEnd(s.width) + ANSI.RESET;

      const { lineContent, cursorCol } = this.calculateInputRender();
      newFrame[s.height - 1] = lineContent;

      let diffOutput = '';
      for (let r = 0; r < s.height; r++) {
        if (s.screenBuffer[r] !== newFrame[r]) {
          diffOutput += ANSI.CURSOR_MOVE(r + 1, 1) + ANSI.CLEAR_LINE + (newFrame[r] || '');
        }
      }

      diffOutput += ANSI.CURSOR_MOVE(s.height, cursorCol);

      s.screenBuffer = newFrame;
      s.socket.write(diffOutput);
    } catch {}
  }
}
