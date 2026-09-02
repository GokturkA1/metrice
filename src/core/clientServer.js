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
    this.server = null;

    this.federation.setLocalStateGetter(() => ({
      users: this.getLocalOnlineUsers(),
      memberships: this.getLocalMemberships()
    }));

    this.federation.on('presence_change', () => {
      this.notifyAllSessionsRender();
    });
  }

  sendHandshakeAndSizeQuery(socket) {
    try {
      const initPayload = Buffer.from([
        TELNET.IAC, TELNET.WILL, TELNET.OPT_ECHO,
        TELNET.IAC, TELNET.WILL, TELNET.OPT_SUPPRESS_GO_AHEAD,
        TELNET.IAC, TELNET.DONT, TELNET.OPT_LINEMODE,
        TELNET.IAC, TELNET.DO, TELNET.OPT_NAWS
      ]);
      socket.write(initPayload);
      socket.write('\x1b[?2004h');
      socket.write('\x1b[s\x1b[999;999H\x1b[6n\x1b[u');
    } catch {}
  }

  getLocalOnlineUsers() {
    return Array.from(this.sessions.keys());
  }

  getLocalMemberships() {
    const list = [];
    for (const [userAddr, session] of this.sessions.entries()) {
      list.push({
        user: userAddr,
        channels: session.getMyChannels()
      });
    }
    return list;
  }

  getOnlineUsers() {
    return this.federation.getAllOnlineUsers();
  }

  getChannelMembers(target) {
    if (!target) return [];

    const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');

    if (target === systemConsole) {
      return this.getOnlineUsers();
    }

    if (target.startsWith('@')) {
      return [target];
    }

    const localMembers = [];
    for (const [userAddr, session] of this.sessions.entries()) {
      if (session.isMemberOf(target)) {
        localMembers.push(userAddr);
      }
    }

    const remoteMembers = this.federation.getChannelMembers(target);
    return Array.from(new Set([...localMembers, ...remoteMembers]));
  }

  notifyAllSessionsRender() {
    for (const session of this.sessions.values()) {
      session.emit('request_render');
    }
  }

  getCurrentConversation(userAddress, activeTarget, systemLogs) {
    const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');
    if (activeTarget === systemConsole) return systemLogs;
    if (!activeTarget) return [];
    return this.db.getConversation(userAddress, activeTarget);
  }

  start() {
    this.server = net.createServer((socket) => {
      const clientAddr = `${socket.remoteAddress}:${socket.remotePort}`;
      log.info(I18n.t('CLIENT_NEW_CONN', { addr: clientAddr }));

      this.sendHandshakeAndSizeQuery(socket);

      let userAddress = null;
      let session = null;
      let loginBuffer = '';
      let detectedWidth = 110;
      let detectedHeight = 24;

      const parser = new InputParser();

      socket.write('\x1b[2J\x1b[H\x1b[1;36m' + I18n.t('TUI_WELCOME_BANNER') + '\x1b[0m');
      socket.write(I18n.t('TUI_LOGIN_PROMPT'));

      socket.on('data', async (chunk) => {
        try {
          const actions = parser.parse(chunk);

          for (const action of actions) {
            if (action.type === 'RESIZE') {
              detectedWidth = action.width;
              detectedHeight = action.height;

              if (session) {
                session.resize(detectedWidth, detectedHeight);
              }
              continue;
            }

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

                const targetUserAddress = AddressHelper.formatUser(username);

                if (this.sessions.has(targetUserAddress)) {
                  socket.write(I18n.t('TUI_USERNAME_TAKEN'));
                  loginBuffer = '';
                  userAddress = null;
                  return;
                }

                userAddress = targetUserAddress;

                const profile = this.db.getUserProfile(userAddress);
                session = new TerminalSession(
                  socket,
                  userAddress,
                  profile,
                  () => this.getOnlineUsers(),
                  (target) => this.getChannelMembers(target),
                  (contacts, history) => {
                    this.db.updateUserProfile(userAddress, contacts, history);
                    this.federation.broadcastPresence();
                  },
                  () => {
                    const uptimeSec = Math.floor(process.uptime());
                    const mins = Math.floor(uptimeSec / 60);
                    const mem = process.memoryUsage();
                    const rssMB = (mem.rss / 1024 / 1024).toFixed(1);
                    const peers = this.federation.peerManager ? this.federation.peerManager.getAllPeers() : [];
                    return { uptime: `${mins}m`, rss: rssMB, peers };
                  },
                  () => this.commands.getAllUnique().map((c) => c.name)
                );

                session.on('request_render', () => {
                  const conv = this.getCurrentConversation(userAddress, session.activeTarget, session.systemLogs);
                  session.renderFull(conv);
                });

                session.resize(detectedWidth, detectedHeight);
                this.sessions.set(userAddress, session);
                log.info(I18n.t('CLIENT_USER_LOGGED_IN'), { user: userAddress });

                session.emit('request_render');
                this.notifyAllSessionsRender();
                this.federation.broadcastPresence();
              }
              continue;
            }

            if (action.type === 'PASTE_COMPLETE') {
              const pastedText = action.content;
              const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');
              if (pastedText && session.activeTarget && session.activeTarget !== systemConsole) {
                await this.handleOutboundMessage(session, userAddress, session.activeTarget, pastedText, false, true);
                session.emit('request_render');
              }
              continue;
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

                  const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');
                  if (session.activeTarget && !session.activeTarget.startsWith('#') && session.activeTarget !== systemConsole) {
                    const targetParsed = AddressHelper.parse(session.activeTarget);
                    if (targetParsed) {
                      if (targetParsed.isLocal) {
                        const localRecipient = this.sessions.get(targetParsed.raw);
                        if (localRecipient && localRecipient.activeTarget === userAddress) {
                          const senderNick = userAddress.split(':')[0].replace('@', '');
                          localRecipient.setTyping(senderNick);
                        }
                      } else {
                        this.federation.sendTyping(userAddress, session.activeTarget);
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
                  await this.commands.execute(input, {
                    session,
                    socket,
                    db: this.db,
                    federation: this.federation,
                    clientServer: this,
                    registry: this.commands,
                    userAddress
                  });
                  session.emit('request_render');
                  break;
                }

                const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');
                if (session.activeTarget === systemConsole) {
                  session.addSystemLog(I18n.t('SYS_SYSTEM_WINDOW_NO_MSG'));
                  break;
                }

                if (session.activeTarget) {
                  await this.handleOutboundMessage(session, userAddress, session.activeTarget, input, false, false);
                  session.emit('request_render');
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
          this.notifyAllSessionsRender();
          this.federation.broadcastPresence();
        }
        log.info(I18n.t('CLIENT_CONN_CLOSED', { addr: clientAddr }));
      });

      socket.on('error', (err) => {
        log.error(I18n.t('CLIENT_SOCKET_ERROR', { addr: clientAddr, error: err.message }));
      });
    });

    this.server.listen(CONFIG.clientPort, () => {
      log.info(I18n.t('CLIENT_LISTENING', { port: CONFIG.clientPort }));
    });

    // --- UZAKTAN GELEN MESAJLARDA MENTION VE ZİL KONTROLÜ ---
    this.federation.on('message', (msg) => {
      try {
        if (msg.to.startsWith('#')) {
          for (const [addr, userSession] of this.sessions.entries()) {
            if (msg.from !== addr) {
              if (userSession.isMemberOf(msg.to)) {
                userSession.incrementUnread(msg.to);

                // Kullanıcı mention edilmişse (@nick veya @nick:server:port) odaya baksa bile zil çal
                const isMentioned = userSession.isUserMentioned(msg.content);
                if (userSession.activeTarget !== msg.to || isMentioned) {
                  userSession.notifyNewMessage();
                }

                userSession.emit('request_render');
              }
            }
          }
        } else {
          const recipientSession = this.sessions.get(msg.to);
          if (recipientSession) {
            recipientSession.addContact(msg.from);
            recipientSession.incrementUnread(msg.from);
            recipientSession.notifyNewMessage();
            recipientSession.emit('request_render');
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
          recipientSession.setTyping(rawName);
        }
      } catch {}
    });
  }

  // --- YEREL KANALA YAZILAN MESAJLARDA MENTION VE ZİL KONTROLÜ ---
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

    // Veritabanına kaydet ve üretilen ID/timestamp değerlerini al
    const saved = this.db.saveMessage(messageRecord);
    if (!saved) return;

    // Pakete kesinleşmiş ID ve zamanı ekle
    messageRecord.id = saved.id;
    messageRecord.timestamp = saved.timestamp;

    if (target.type === 'CHANNEL') {
      for (const [addr, userSession] of this.sessions.entries()) {
        if (addr !== from) {
          if (userSession.isMemberOf(target.raw)) {
            userSession.incrementUnread(target.raw);

            const isMentioned = userSession.isUserMentioned(content);
            if (userSession.activeTarget !== target.raw || isMentioned) {
              userSession.notifyNewMessage();
            }
            userSession.emit('request_render');
          }
        }
      }

      if (target.isGlobalChannel) {
        await this.federation.sendRemoteMessage(from, target.raw, content, isAction, isSnippet);
      } else if (!target.isLocal) {
        await this.federation.sendRemoteMessage(from, target.raw, content, isAction, isSnippet);
      } else {
        // ID'si olan eksiksiz kaydı ilet
        this.federation.forwardToChannelSubscribers(target.raw, messageRecord);
      }
    } else {
      if (target.isLocal) {
        const recipientSession = this.sessions.get(target.raw);
        if (recipientSession) {
          recipientSession.addContact(from);
          recipientSession.incrementUnread(from);
          recipientSession.notifyNewMessage();
          recipientSession.emit('request_render');
        }
      } else {
        const res = await this.federation.sendRemoteMessage(from, target.raw, content, isAction, isSnippet);
        if (res && res.status === 'queued') {
          session.addSystemLog(I18n.t('SYS_OUTBOX_QUEUED', { target: target.raw }));
        }
      }
    }
  }

  close() {
    for (const session of this.sessions.values()) {
      try {
        session.socket.write(I18n.t('TUI_SERVER_SHUTDOWN'));
        session.socket.end();
      } catch {}
    }
    this.sessions.clear();

    if (this.server) {
      try {
        this.server.close();
      } catch {}
    }
    log.info('İstemci TUI sunucusu ve açık oturumlar kapatıldı.');
  }
}