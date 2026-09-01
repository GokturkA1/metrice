import net from 'node:net';
import { CONFIG } from '../config/index.js';
import { Logger } from '../utils/logger.js';
import { InputParser } from '../utils/inputParser.js';
import { AddressHelper } from '../utils/addressHelper.js';
import { TerminalSession } from './terminalSession.js';
import { createCommandRegistry } from '../commands/index.js';
import { I18n } from '../locales/i18n.js';

const log = new Logger('CLIENT_SRV');

const TELNET = {
  IAC: 0xFF,
  WILL: 0xFB,
  DONT: 0xFE,
  DO: 0xFD,
  OPT_ECHO: 0x01,
  OPT_SUPPRESS_GO_AHEAD: 0x03,
  OPT_LINEMODE: 0x22,
  OPT_NAWS: 0x1F
};

export class ClientServer {
  constructor(db, federation) {
    this.db = db;
    this.federation = federation;
    this.sessions = new Map();
    this.commands = createCommandRegistry();

    this.federation.setLocalUsersGetter(() => this.getLocalOnlineUsers());
    this.federation.on('presence_change', () => {
      this.broadcastSessionRefresh();
    });
  }

  sendHandshakeAndSizeQuery(socket) {
    try {
      // 1. Telnet Handshake + DO NAWS
      const initPayload = Buffer.from([
        TELNET.IAC, TELNET.WILL, TELNET.OPT_ECHO,
        TELNET.IAC, TELNET.WILL, TELNET.OPT_SUPPRESS_GO_AHEAD,
        TELNET.IAC, TELNET.DONT, TELNET.OPT_LINEMODE,
        TELNET.IAC, TELNET.DO, TELNET.OPT_NAWS
      ]);
      socket.write(initPayload);

      // 2. Bracketed Paste aç
      socket.write('\x1b[?2004h');

      // 3. Evrensel Boyut Sorgusu: İmleci 999;999'a çek ve pozisyon raporu (CPR) iste
      socket.write('\x1b[s\x1b[999;999H\x1b[6n\x1b[u');
    } catch {}
  }

  getLocalOnlineUsers() {
    return Array.from(this.sessions.keys());
  }

  getOnlineUsers() {
    return this.federation.getAllOnlineUsers();
  }

  broadcastSessionRefresh() {
    for (const [addr, s] of this.sessions.entries()) {
      const conv = s.activeTarget === '*sistem'
        ? s.systemLogs
        : s.activeTarget
        ? this.db.getConversation(addr, s.activeTarget)
        : [];
      s.renderFull(conv);
    }
  }

  start() {
    const server = net.createServer((socket) => {
      const clientAddr = `${socket.remoteAddress}:${socket.remotePort}`;
      log.info(I18n.t('CLIENT_NEW_CONN', { addr: clientAddr }));

      this.sendHandshakeAndSizeQuery(socket);

      let userAddress = null;
      let session = null;
      let loginBuffer = '';
      let detectedWidth = 90;
      let detectedHeight = 24;

      const parser = new InputParser();

      socket.write('\x1b[2J\x1b[H\x1b[1;36m' + I18n.t('TUI_WELCOME_BANNER') + '\x1b[0m');
      socket.write(I18n.t('TUI_LOGIN_PROMPT'));

      socket.on('data', async (chunk) => {
        try {
          const actions = parser.parse(chunk);

          for (const action of actions) {
            // --- 0. Boyutlandırma (Login Öncesi ve Sonrası) ---
            if (action.type === 'RESIZE') {
              detectedWidth = action.width;
              detectedHeight = action.height;

              if (session) {
                session.resize(detectedWidth, detectedHeight);
                const conv = session.activeTarget === '*sistem'
                  ? session.systemLogs
                  : session.activeTarget
                  ? this.db.getConversation(userAddress, session.activeTarget)
                  : [];
                session.renderFull(conv);
              }
              continue;
            }

            // --- 1. Login Ekranı ---
            if (!userAddress) {
              if (action.type === 'CHAR') {
                loginBuffer += action.char;
                socket.write(action.char);
              } else if (action.type === 'KEY_BACKSPACE') {
                if (loginBuffer.length > 0) {
                  loginBuffer = loginBuffer.slice(0, -1);
                  socket.write('\b \b');
                }
              } else if (action.type === 'KEY_ENTER') {
                const username = loginBuffer.trim();
                if (!AddressHelper.isValidUsername(username)) {
                  socket.write(I18n.t('TUI_INVALID_USERNAME'));
                  loginBuffer = '';
                  return;
                }

                userAddress = AddressHelper.formatUser(username);

                if (this.sessions.has(userAddress)) {
                  socket.write(I18n.t('TUI_USERNAME_TAKEN'));
                  loginBuffer = '';
                  return;
                }

                const profile = this.db.getUserProfile(userAddress);
                session = new TerminalSession(socket, userAddress, profile, () => this.getOnlineUsers());
                
                // Başlangıçta tespit edilen gerçek boyutu oturuma uygula
                session.resize(detectedWidth, detectedHeight);
                this.sessions.set(userAddress, session);
                log.info(I18n.t('CLIENT_USER_LOGGED_IN'), { user: userAddress });

                session.renderFull(this.db.getConversation(userAddress, session.activeTarget));
                this.broadcastSessionRefresh();
                this.federation.broadcastPresence();
              }
              continue;
            }

            // --- 2. Çok Satırlı Yapıştırma ---
            if (action.type === 'PASTE_COMPLETE') {
              const pastedText = action.content;
              if (pastedText && session.activeTarget && session.activeTarget !== '*sistem') {
                await this.handleOutboundMessage(session, userAddress, session.activeTarget, pastedText, false, true);
                session.renderFull(this.db.getConversation(userAddress, session.activeTarget));
              }
              continue;
            }

            // --- 3. TUI Navigasyon & Komutlar ---
            const currentConversation = () =>
              session.activeTarget === '*sistem'
                ? session.systemLogs
                : session.activeTarget
                ? this.db.getConversation(userAddress, session.activeTarget)
                : [];

            switch (action.type) {
              case 'KEY_TAB':
                session.focus = session.focus === 'input' ? 'sidebar' : 'input';
                session.renderFull(currentConversation());
                break;

              case 'CHAR':
                if (session.focus === 'input') {
                  session.insertChar(action.char);
                  session.renderInputOnly();

                  if (session.activeTarget && !session.activeTarget.startsWith('#') && session.activeTarget !== '*sistem') {
                    const targetParsed = AddressHelper.parse(session.activeTarget);
                    if (targetParsed) {
                      if (targetParsed.isLocal) {
                        const localRecipient = this.sessions.get(targetParsed.raw);
                        if (localRecipient && localRecipient.activeTarget === userAddress) {
                          const senderNick = userAddress.split(':')[0].replace('@', '');
                          localRecipient.setTyping(senderNick, () => {
                            localRecipient.renderFull(this.db.getConversation(targetParsed.raw, localRecipient.activeTarget));
                          });
                        }
                      } else {
                        this.federation.sendTyping(userAddress, session.activeTarget);
                      }
                    }
                  }
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
                session.renderFull(currentConversation());
                break;

              case 'KEY_PAGE_DOWN':
                session.scrollDown(5);
                session.renderFull(currentConversation());
                break;

              case 'KEY_UP':
                if (session.focus === 'input') {
                  session.historyUp();
                  session.renderInputOnly();
                } else if (session.focus === 'sidebar') {
                  if (session.selectedContactIdx > 0) session.selectedContactIdx--;
                  session.renderFull(currentConversation());
                }
                break;

              case 'KEY_DOWN':
                if (session.focus === 'input') {
                  session.historyDown();
                  session.renderInputOnly();
                } else if (session.focus === 'sidebar') {
                  if (session.selectedContactIdx < session.contacts.length - 1) session.selectedContactIdx++;
                  session.renderFull(currentConversation());
                }
                break;

              case 'KEY_ENTER':
                if (session.focus === 'sidebar') {
                  const selectedTarget = session.contacts[session.selectedContactIdx];
                  if (selectedTarget) {
                    session.setTarget(selectedTarget);
                    session.focus = 'input';
                    session.renderFull(currentConversation());
                  }
                  break;
                }

                const input = session.inputBuffer.trim();
                session.clearInput();

                if (session.isManualPasteMode) {
                  if (input === '/end') {
                    session.isManualPasteMode = false;
                    const fullSnippet = session.manualPasteLines.join('\n');
                    session.manualPasteLines = [];
                    if (fullSnippet && session.activeTarget && session.activeTarget !== '*sistem') {
                      await this.handleOutboundMessage(session, userAddress, session.activeTarget, fullSnippet, false, true);
                    }
                    session.renderFull(currentConversation());
                    break;
                  } else if (input === '/cancel') {
                    session.isManualPasteMode = false;
                    session.manualPasteLines = [];
                    session.addSystemLog(I18n.t('SYS_PASTE_MODE_CANCEL'));
                    session.renderFull(currentConversation());
                    break;
                  } else {
                    session.manualPasteLines.push(input);
                    session.renderInputOnly();
                    break;
                  }
                }

                if (!input) {
                  session.renderInputOnly();
                  break;
                }

                session.pushHistory(input);

                if (input.startsWith('/')) {
                  await this.commands.execute(input, {
                    session,
                    socket,
                    db: this.db,
                    federation: this.federation,
                    clientServer: this,
                    registry: this.commands,
                    userAddress
                  });
                  session.renderFull(currentConversation());
                  break;
                }

                if (session.activeTarget === '*sistem') {
                  session.addSystemLog(I18n.t('SYS_SYSTEM_WINDOW_NO_MSG'));
                  session.renderFull(currentConversation());
                  break;
                }

                if (session.activeTarget) {
                  await this.handleOutboundMessage(session, userAddress, session.activeTarget, input, false, false);
                  session.renderFull(this.db.getConversation(userAddress, session.activeTarget));
                }
                break;

              case 'KEY_INTERRUPT':
                socket.end(I18n.t('TUI_SESSION_CLOSED'));
                break;
            }
          }
        } catch (err) {
          log.error(I18n.t('CLIENT_INPUT_ERROR', { error: err.message }));
        }
      });

      socket.on('close', () => {
        if (userAddress && session) {
          this.db.updateUserProfile(userAddress, session.contacts, session.history);
          this.sessions.delete(userAddress);
          this.broadcastSessionRefresh();
          this.federation.broadcastPresence();
        }
        log.info(I18n.t('CLIENT_CONN_CLOSED', { addr: clientAddr }));
      });

      socket.on('error', (err) => {
        log.error(I18n.t('CLIENT_SOCKET_ERROR', { addr: clientAddr, error: err.message }));
      });
    });

    server.listen(CONFIG.clientPort, () => {
      log.info(I18n.t('CLIENT_LISTENING', { port: CONFIG.clientPort }));
    });

    this.federation.on('message', (msg) => {
      try {
        if (msg.to.startsWith('#')) {
          for (const [addr, userSession] of this.sessions.entries()) {
            if (msg.from !== addr) {
              userSession.addContact(msg.to);
              userSession.incrementUnread(msg.to);
              userSession.notifyNewMessage();
              const conv = userSession.activeTarget === msg.to
                ? this.db.getConversation(addr, msg.to)
                : this.db.getConversation(addr, userSession.activeTarget);
              userSession.renderFull(conv);
            }
          }
        } else {
          const recipientSession = this.sessions.get(msg.to);
          if (recipientSession) {
            recipientSession.addContact(msg.from);
            recipientSession.incrementUnread(msg.from);
            recipientSession.notifyNewMessage();
            const conv = recipientSession.activeTarget === msg.from
              ? this.db.getConversation(msg.to, recipientSession.activeTarget)
              : this.db.getConversation(msg.to, recipientSession.activeTarget);
            recipientSession.renderFull(conv);
          }
        }
      } catch (err) {
        log.error(I18n.t('CLIENT_MSG_DISPATCH_ERROR', { error: err.message }));
      }
    });

    this.federation.on('typing', (payload) => {
      try {
        const recipientSession = this.sessions.get(payload.to);
        if (recipientSession && recipientSession.activeTarget === payload.from) {
          const rawName = payload.from.split(':')[0].replace('@', '');
          recipientSession.setTyping(rawName, () => {
            const conv = this.db.getConversation(payload.to, recipientSession.activeTarget);
            recipientSession.renderFull(conv);
          });
        }
      } catch {}
    });
  }

  async handleOutboundMessage(session, from, to, content, isAction = false, isSnippet = false) {
    const target = AddressHelper.parse(to);
    if (!target) return;

    const messageRecord = {
      from,
      to: target.raw,
      content,
      isAction,
      isSnippet
    };

    const saved = this.db.saveMessage(messageRecord);
    if (!saved) return;

    if (target.type === 'CHANNEL') {
      for (const [addr, userSession] of this.sessions.entries()) {
        if (addr !== from) {
          userSession.addContact(target.raw);
          userSession.incrementUnread(target.raw);
          userSession.notifyNewMessage();
          const conv = userSession.activeTarget === target.raw
            ? this.db.getConversation(addr, target.raw)
            : this.db.getConversation(addr, userSession.activeTarget);
          userSession.renderFull(conv);
        }
      }

      if (target.isMeshChannel) {
        await this.federation.sendRemoteMessage(from, target.raw, content, isAction, isSnippet);
      }
    } else {
      if (target.isLocal) {
        const recipientSession = this.sessions.get(target.raw);
        if (recipientSession) {
          recipientSession.addContact(from);
          recipientSession.incrementUnread(from);
          recipientSession.notifyNewMessage();
          const conv = recipientSession.activeTarget === from
            ? this.db.getConversation(target.raw, from)
            : this.db.getConversation(target.raw, recipientSession.activeTarget);
          recipientSession.renderFull(conv);
        }
      } else {
        const res = await this.federation.sendRemoteMessage(from, target.raw, content, isAction, isSnippet);
        if (res && res.status === 'queued') {
          session.addSystemLog(I18n.t('SYS_OUTBOX_QUEUED', { target: target.raw }));
        }
      }
    }
  }
}