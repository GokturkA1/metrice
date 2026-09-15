import { AddressHelper } from '../utils/addressHelper.js';
import { I18n } from '../locales/i18n.js';

export class SessionInputHandler {
  static async handlePaste(session, clientServer, userAddress, action) {
    const rawText = action.content || '';
    const trimmed = rawText.trim();

    // 1. Komut veya tek satirlik metin yapistirildi
    if (trimmed.startsWith('/') || !rawText.includes('\n')) {
      const singleLine = trimmed.replace(/[\r\n]+/g, ' ');
      if (session && session.focus === 'input') {
        session.inputBuffer += singleLine;
        session.cursorIndex = session.inputBuffer.length;
        session.renderInputOnly();
      }
    } 
    // 2. Cok satirli kod veya metin blogu yapistirildi
    else if (session && session.activeTarget && !AddressHelper.isSystemConsole(session.activeTarget)) {
      await clientServer.handleOutboundMessage(
        session,
        userAddress,
        session.activeTarget,
        rawText,
        false,
        true
      );
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

      case 'KEY_ENTER':
        if (session.focus === 'sidebar') {
          const selectedTarget = session.contacts[session.selectedContactIdx];
          if (selectedTarget) {
            session.setTarget(selectedTarget);
            session.focus = 'input';
          }
          break;
        }

        const input = session.inputBuffer.trim();
        session.clearInput();

        if (!input) {
          session.renderInputOnly();
          break;
        }

        session.pushHistory(input);

        if (input.startsWith('/')) {
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
          await clientServer.handleOutboundMessage(
            session,
            userAddress,
            session.activeTarget,
            input,
            false,
            false
          );
          session.emit('request_render');
        }
        break;

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
