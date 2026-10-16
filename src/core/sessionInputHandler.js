import { AddressHelper } from '../utils/addressHelper.js';
import { I18n } from '../locales/i18n.js';

export class SessionInputHandler {
  static queueOutboundBurst(session, clientServer, userAddress, textContent, isMultiLineChunk = false, fromChunkWithChars = false) {
    if (!session.pendingPasteLines) {
      session.pendingPasteLines = [];
      session.pendingPasteIsSnippet = false;
      session.pendingPasteFromChunk = false;
    }

    if (session.inputBuffer.length > 0 && isMultiLineChunk) {
      session.pendingPasteLines.push(session.inputBuffer);
      session.clearInput();
    }

    if (isMultiLineChunk) {
      session.pendingPasteIsSnippet = true;
      session.pendingPasteFromChunk = true;
      const lines = textContent.split('\n');
      session.pendingPasteLines.push(...lines);
    } else {
      session.pendingPasteLines.push(textContent);
      if (fromChunkWithChars) {
        session.pendingPasteFromChunk = true;
      }
    }

    this.scheduleBurstFlush(session, clientServer, userAddress);
  }

  static scheduleBurstFlush(session, clientServer, userAddress) {
    if (session.pasteFlushTimer) {
      clearTimeout(session.pasteFlushTimer);
    }

    session.pasteFlushTimer = setTimeout(async () => {
      session.pasteFlushTimer = null;
      const lines = session.pendingPasteLines || [];
      const wasSnippet = session.pendingPasteIsSnippet;
      const wasFromChunk = session.pendingPasteFromChunk;

      session.pendingPasteLines = [];
      session.pendingPasteIsSnippet = false;
      session.pendingPasteFromChunk = false;

      if (lines.length === 0) return;

      if ((lines.length >= 2 || wasSnippet || wasFromChunk) && session.inputBuffer.length > 0) {
        lines.push(session.inputBuffer);
        session.clearInput();
      }

      const isMulti = lines.length > 1 || wasSnippet;

      if (!session.activeTarget || AddressHelper.isSystemConsole(session.activeTarget)) {
        return;
      }

      try {
        if (isMulti) {
          const fullBlock = lines.join('\n').replace(/^\r?\n+|\r?\n+$/g, '');
          if (fullBlock.trim().length > 0) {
            await clientServer.handleOutboundMessage(
              session,
              userAddress,
              session.activeTarget,
              fullBlock,
              false,
              true
            );
          }
        } else {
          const singleMsg = lines[0].trim();
          if (singleMsg.length > 0) {
            session.pushHistory(singleMsg);
            await clientServer.handleOutboundMessage(
              session,
              userAddress,
              session.activeTarget,
              singleMsg,
              false,
              false
            );
          }
        }
      } catch (err) {
        session.addSystemLog(`\x1b[1;31m${I18n.t('CLIENT_MSG_DISPATCH_ERROR', { error: err.message })}\x1b[0m`);
      }
      session.emit('request_render');
    }, 40);
    session.pasteFlushTimer.unref?.();
  }

  static async handlePaste(session, clientServer, userAddress, action) {
    const rawText = action.content || '';
    const cleaned = rawText.replace(/^\r?\n+|\r?\n+$/g, '');
    const trimmed = cleaned.trim();
    if (!trimmed) return;

    const hasPendingBurst = session && session.pendingPasteLines && session.pendingPasteLines.length > 0;

    // 1. Tek satirlik metin yapistirildi: gonderme, mesaj girisine yapistir
    if (!trimmed.includes('\n') && !hasPendingBurst) {
      const singleLine = trimmed.replace(/[\r\n]+/g, ' ');
      if (session) {
        if (session.focus !== 'input') {
          session.focus = 'input';
        }
        session.inputBuffer += singleLine;
        session.cursorIndex = session.inputBuffer.length;
        session.renderInputOnly();
      }
      return;
    }

    // 2. Cok satirli kod veya metin blogu yapistirildi
    if (session && session.activeTarget && !AddressHelper.isSystemConsole(session.activeTarget)) {
      if (action.bracketed === false || hasPendingBurst) {
        this.queueOutboundBurst(session, clientServer, userAddress, cleaned, true, true);
        return;
      }

      let finalBlock = cleaned;
      if (session.inputBuffer.length > 0) {
        finalBlock = `${session.inputBuffer}\n${cleaned}`;
        session.clearInput();
      }

      try {
        await clientServer.handleOutboundMessage(
          session,
          userAddress,
          session.activeTarget,
          finalBlock,
          false,
          true
        );
      } catch (err) {
        session.addSystemLog(`\x1b[1;31m${I18n.t('CLIENT_MSG_DISPATCH_ERROR', { error: err.message })}\x1b[0m`);
      }
      session.emit('request_render');
    }
  }

  static async handleAction(action, session, clientServer, userAddress, socket, db) {
    if (!session) return;

    if (action.type === 'RESIZE') {
      session.resize(action.width, action.height);
      return;
    }

    if (action.type === 'PASTE_COMPLETE') {
      await this.handlePaste(session, clientServer, userAddress, action);
      return;
    }

    switch (action.type) {
      case 'KEY_TAB':
        if (session.focus === 'input' && session.inputBuffer.trim().length > 0) {
          session.handleTabCompletion();
        } else {
          session.focus = session.focus === 'input' ? 'sidebar' : 'input';
          session.emit('request_render');
        }
        break;

      case 'CHAR':
        if (session.pasteFlushTimer && (session.pendingPasteFromChunk || (session.pendingPasteLines && session.pendingPasteLines.length >= 2))) {
          this.scheduleBurstFlush(session, clientServer, userAddress);
        }
        if (session.focus === 'input') {
          session.insertChar(action.char);
          session.renderInputOnly();

          if (session.activeTarget && !session.activeTarget.startsWith('#') && !AddressHelper.isSystemConsole(session.activeTarget)) {
            const targetParsed = AddressHelper.parse(session.activeTarget);
            if (targetParsed) {
              if (targetParsed.isLocal) {
                const localRecipient = clientServer.sessions.get(targetParsed.raw);
                if (localRecipient && AddressHelper.isSameTarget(localRecipient.activeTarget, userAddress)) {
                  const senderNick = userAddress.split(':')[0].replace('@', '');
                  localRecipient.setTyping(senderNick);
                }
              } else {
                clientServer.federation.sendTyping(userAddress, session.activeTarget);
              }
            }
          }
        } else {
          session.focus = 'input';
          session.insertChar(action.char);
          session.emit('request_render');
        }
        break;

      case 'KEY_BACKSPACE':
        if (session.focus === 'input') {
          session.backspace();
          session.renderInputOnly();
        }
        break;

      case 'KEY_DELETE':
        if (session.focus === 'input') {
          session.deleteForward();
          session.renderInputOnly();
        }
        break;

      case 'KEY_CTRL_W':
        if (session.focus === 'input') {
          session.deleteWord();
          session.renderInputOnly();
        }
        break;

      case 'KEY_CTRL_U':
        if (session.focus === 'input') {
          session.clearInput();
          session.renderInputOnly();
        }
        break;

      case 'KEY_LEFT':
        if (session.focus === 'input') {
          session.moveCursorLeft();
          session.renderInputOnly();
        }
        break;

      case 'KEY_RIGHT':
        if (session.focus === 'input') {
          session.moveCursorRight();
          session.renderInputOnly();
        }
        break;

      case 'KEY_PAGE_UP':
        session.scrollUp(5);
        session.emit('request_render');
        break;

      case 'KEY_PAGE_DOWN':
        session.scrollDown(5);
        session.emit('request_render');
        break;

      case 'KEY_UP':
        if (session.focus === 'input') {
          session.historyUp();
          session.renderInputOnly();
        } else if (session.focus === 'sidebar') {
          if (session.selectedContactIdx > 0) session.selectedContactIdx--;
          session.emit('request_render');
        }
        break;

      case 'KEY_DOWN':
        if (session.focus === 'input') {
          session.historyDown();
          session.renderInputOnly();
        } else if (session.focus === 'sidebar') {
          if (session.selectedContactIdx < session.contacts.length - 1) session.selectedContactIdx++;
          session.emit('request_render');
        }
        break;

      case 'KEY_ENTER': {
        if (session.focus === 'sidebar') {
          const selectedTarget = session.contacts[session.selectedContactIdx];
          if (selectedTarget) {
            session.setTarget(selectedTarget);
            session.focus = 'input';
          }
          break;
        }

        const rawLine = session.inputBuffer;
        const input = rawLine.trim();
        session.clearInput();

        const isBurstInProgress = session.pendingPasteLines && session.pendingPasteLines.length > 0;

        if (!input) {
          if (isBurstInProgress) {
            this.queueOutboundBurst(session, clientServer, userAddress, '', false, Boolean(action.fromChunkWithChars));
          } else {
            session.renderInputOnly();
          }
          break;
        }

        const isCommand = !isBurstInProgress && input.startsWith('/') && !input.startsWith('//') && !input.startsWith('/*');

        if (isCommand) {
          session.pushHistory(input);
          await clientServer.commands.execute(input, {
            session,
            socket: session.socket || socket,
            db: db || clientServer.db,
            federation: clientServer.federation,
            clientServer,
            registry: clientServer.commands,
            userAddress
          });

          if (socket && !socket.destroyed && !socket.writableEnded) {
            session?.emit('request_render');
          }
          break;
        }

        if (AddressHelper.isSystemConsole(session.activeTarget)) {
          session.addSystemLog(I18n.t('SYS_SYSTEM_WINDOW_NO_MSG'));
          break;
        }

        if (session.activeTarget) {
          this.queueOutboundBurst(
            session,
            clientServer,
            userAddress,
            rawLine,
            false,
            Boolean(action.fromChunkWithChars)
          );
        }
        break;
      }

      case 'KEY_INTERRUPT':
        if (session && session.socket) {
          session.socket.end(I18n.t('TUI_SESSION_CLOSED'));
        } else if (socket) {
          socket.end(I18n.t('TUI_SESSION_CLOSED'));
        }
        break;
    }
  }
}
