import net from 'node:net';
import crypto from 'node:crypto';
import { CONFIG } from '../config/index.js';
import { Logger } from '../utils/logger.js';
import { InputParser } from '../utils/inputParser.js';
import { AddressHelper } from '../utils/addressHelper.js';
import { CryptoHelper } from '../utils/cryptoHelper.js';
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

const AUTH_STATE = {
  USERNAME: 'USERNAME',
  LOGIN_PASSWORD: 'LOGIN_PASSWORD',
  REGISTER_PASSWORD: 'REGISTER_PASSWORD',
  CONFIRM_PASSWORD: 'CONFIRM_PASSWORD',
  AUTHENTICATED: 'AUTHENTICATED'
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

    this.initFederationListeners();
  }

  initFederationListeners() {
    this.federation.on('presence_change', () => {
      this.notifyAllSessionsRender();
    });

    this.federation.on('message', (msg) => {
      try {
        if (msg.to.startsWith('#')) {
          for (const [addr, userSession] of this.sessions.entries()) {
            if (msg.from !== addr) {
              if (userSession.isMemberOf(msg.to)) {
                userSession.incrementUnread(msg.to);
                const isMentioned = userSession.isUserMentioned(msg.content);
                if (userSession.activeTarget !== msg.to || isMentioned) {
                  userSession.notifyNewMessage();
                }
                userSession.emit('request_render');
              }
            }
          }
        } else {
          const recipientSession = this.findLocalSession(msg.to);
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
        const recipientSession = this.findLocalSession(payload.to);
        if (recipientSession && recipientSession.activeTarget === payload.from) {
          const rawName = payload.from.split(':')[0].replace('@', '');
          recipientSession.setTyping(rawName);
        }
      } catch {}
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
        channels: typeof session.getMyChannels === 'function' ? session.getMyChannels() : [],
        isSsh: !!session.isSsh,
        kemPublicKey: session.kemKeyPair ? session.kemKeyPair.publicKey : ''
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
      if (session && typeof session.emit === 'function') {
        session.emit('request_render');
      }
    }
  }

  findLocalSession(userAddressOrTarget) {
    if (!userAddressOrTarget) return null;
    if (this.sessions.has(userAddressOrTarget)) {
      return this.sessions.get(userAddressOrTarget);
    }
    const parsedTarget = AddressHelper.parse(userAddressOrTarget);
    if (!parsedTarget || !parsedTarget.name) return null;

    for (const [addr, sess] of this.sessions.entries()) {
      if (addr === userAddressOrTarget) return sess;
      const parsedAddr = AddressHelper.parse(addr);
      if (parsedAddr && parsedAddr.name === parsedTarget.name) {
        return sess;
      }
    }
    return null;
  }

  getCurrentConversation(userAddress, activeTarget, systemLogs) {
    const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');
    if (activeTarget === systemConsole) return systemLogs;
    if (!activeTarget) return [];

    const messages = this.db.getConversation(userAddress, activeTarget);
    const session = this.sessions.get(userAddress);

    // E2EE Çift Zarf Deşifre Pipeline'ı
    if (session && session.isSsh && session.kemKeyPair) {
      return messages.map((m) => {
        if (m.isE2EE && typeof m.content === 'string' && m.content.startsWith('e2ee:v2:')) {
          try {
            const parts = m.content.split(':');
            const rCombined = parts[2].split('!');
            const sCombined = parts[3].split('!');
            const iv = parts[4];
            const authTag = parts[5];
            const ciphertext = parts[6];

            const senderNick = m.from ? m.from.split(':')[0].replace('@', '') : '';
            const myNick = userAddress ? userAddress.split(':')[0].replace('@', '') : '';
            const isSender = senderNick === myNick;
            const chosen = isSender ? sCombined : rCombined;

            const sharedSecret = CryptoHelper.decapsulateKey(session.kemKeyPair.privateKey, chosen[0]);
            const wrapAes = CryptoHelper.deriveKey(sharedSecret, 'e2ee-wrap', 'wrap-key');
            const messageKeyBase64 = CryptoHelper.decrypt({ ciphertext: chosen[3], iv: chosen[1], authTag: chosen[2] }, wrapAes);

            const messageKey = Buffer.from(messageKeyBase64, 'base64');
            const plaintext = CryptoHelper.decrypt({ ciphertext, iv, authTag }, messageKey);

            if (!plaintext) {
              return { ...m, content: `\x1b[1;31m${I18n.t('E2EE_DECRYPT_FAIL_PLACEHOLDER')}\x1b[0m` };
            }
            return { ...m, content: plaintext };
          } catch {
            return m;
          }
        }
        return m;
      });
    }

    return messages;
  }

  start() {
    this.server = net.createServer((socket) => {
      const clientAddr = `${socket.remoteAddress}:${socket.remotePort}`;
      log.info(I18n.t('CLIENT_NEW_CONN', { addr: clientAddr }));

      this.sendHandshakeAndSizeQuery(socket);

      let authState = AUTH_STATE.USERNAME;
      let targetUserAddress = null;
      let userProfile = null;
      let loginAttempts = 0;

      let inputBuffer = '';
      let tempPassword = '';

      let userAddress = null;
      let session = null;
      let detectedWidth = 110;
      let detectedHeight = 24;

      const parser = new InputParser();

      const completeLogin = async () => {
        authState = AUTH_STATE.AUTHENTICATED;
        userAddress = targetUserAddress;

        session = new TerminalSession(
          socket,
          userAddress,
          userProfile,
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
            return {
              uptime: `${mins}m`,
              rss: rssMB,
              peers,
              role: this.federation.role,
              nodeId: this.federation.nodeId
            };
          },
          () => this.commands.getAllUnique().map((c) => c.name)
        );

        session.isSsh = false;
        session.isSecureE2EE = false;

        session.on('request_render', () => {
          const conv = this.getCurrentConversation(userAddress, session.activeTarget, session.systemLogs);
          session.renderFull(conv);
        });

        session.resize(detectedWidth, detectedHeight);
        this.sessions.set(userAddress, session);
        log.info(I18n.t('CLIENT_USER_LOGGED_IN', { user: userAddress }));

        session.emit('request_render');
        this.notifyAllSessionsRender();
        this.federation.broadcastPresence();
      };

      socket.write('\x1b[2J\x1b[H\x1b[1;36m' + I18n.t('TUI_WELCOME_BANNER') + '\x1b[0m');
      socket.write(I18n.t('TUI_LOGIN_PROMPT'));

      socket.on('data', async (chunk) => {
        try {
          const actions = parser.parse(chunk);

          for (const action of actions) {
            if (action.type === 'RESIZE') {
              detectedWidth = action.width;
              detectedHeight = action.height;
              if (session) session.resize(detectedWidth, detectedHeight);
              continue;
            }

            if (authState !== AUTH_STATE.AUTHENTICATED) {
              if (action.type === 'CHAR') {
                inputBuffer += action.char;
                if (authState === AUTH_STATE.USERNAME) socket.write(action.char);
                else socket.write('*');
              } else if (action.type === 'KEY_BACKSPACE') {
                if (inputBuffer.length > 0) {
                  inputBuffer = inputBuffer.slice(0, -1);
                  socket.write('\b \b');
                }
              } else if (action.type === 'KEY_ENTER') {
                const val = inputBuffer.trim();
                inputBuffer = '';

                // 1. KULLANICI ADI AŞAMASI (KAYIP BLOK BUYDU!)
                if (authState === AUTH_STATE.USERNAME) {
                  if (!AddressHelper.isValidUsername(val)) {
                    socket.write(I18n.t('TUI_INVALID_USERNAME'));
                    return;
                  }

                  targetUserAddress = AddressHelper.formatUser(val);

                  if (this.sessions.has(targetUserAddress)) {
                    socket.write(I18n.t('TUI_USERNAME_TAKEN'));
                    targetUserAddress = null;
                    return;
                  }

                  userProfile = this.db.getUserProfile(targetUserAddress);

                  if (!userProfile.passwordHash) {
                    authState = AUTH_STATE.REGISTER_PASSWORD;
                    socket.write(I18n.t('TUI_NEW_USER_PASSWORD_PROMPT'));
                  } else {
                    authState = AUTH_STATE.LOGIN_PASSWORD;
                    socket.write(I18n.t('TUI_PASSWORD_PROMPT'));
                  }
                  return;
                }

                // 2. YENİ KULLANICI İLK PAROLA AŞAMASI
                if (authState === AUTH_STATE.REGISTER_PASSWORD) {
                  if (val.length < 4) {
                    socket.write(I18n.t('TUI_PASSWORD_TOO_SHORT'));
                    socket.write(I18n.t('TUI_NEW_USER_PASSWORD_PROMPT'));
                    return;
                  }
                  tempPassword = val;
                  authState = AUTH_STATE.CONFIRM_PASSWORD;
                  socket.write(I18n.t('TUI_CONFIRM_PASSWORD_PROMPT'));
                  return;
                }

                // 3. YENİ KULLANICI PAROLA TEKRAR AŞAMASI
                if (authState === AUTH_STATE.CONFIRM_PASSWORD) {
                  if (val !== tempPassword) {
                    tempPassword = '';
                    authState = AUTH_STATE.REGISTER_PASSWORD;
                    socket.write(I18n.t('TUI_PASSWORD_MISMATCH'));
                    socket.write(I18n.t('TUI_NEW_USER_PASSWORD_PROMPT'));
                    return;
                  }

                  const hash = await CryptoHelper.hashPassword(val);
                  this.db.updateUserPassword(targetUserAddress, hash);
                  userProfile.passwordHash = hash;
                  tempPassword = '';

                  await completeLogin();
                  return;
                }

                // 4. MEVCUT KULLANICI GİRİŞ PAROLASI
                if (authState === AUTH_STATE.LOGIN_PASSWORD) {
                  userProfile = this.db.getUserProfile(targetUserAddress);
                  const isSshVault = userProfile.passwordHash && userProfile.passwordHash.startsWith('{');

                  if (isSshVault) {
                    if (!userProfile.allowTelnet) {
                      socket.write(I18n.t('TUI_TELNET_BLOCKED_SSH_ONLY'));
                      socket.end();
                      return;
                    }

                    if (!userProfile.publicKey) {
                      socket.write(I18n.t('TUI_TELNET_NO_KEY_IN_PROFILE'));
                      socket.end();
                      return;
                    }

                    const isValid = await CryptoHelper.verifyPassword(
                      val,
                      userProfile.passwordHash,
                      userProfile.publicKey,
                      this.federation.nodeAddress
                    );

                    if (!isValid) {
                      loginAttempts++;
                      const remaining = 3 - loginAttempts;
                      if (remaining <= 0) {
                        socket.write(I18n.t('TUI_MAX_LOGIN_ATTEMPTS'));
                        socket.end();
                        return;
                      }
                      socket.write(I18n.t('TUI_WRONG_PASSWORD', { remaining }));
                      socket.write(I18n.t('TUI_PASSWORD_PROMPT'));
                      return;
                    }

                    await completeLogin();

                    if (session) {
                      session.addSystemLog(I18n.t('E2EE_TELNET_BANNER_WARNING'));
                    }
                    return;
                  }

                  // Klasik Telnet hesabı
                  const isValid = await CryptoHelper.verifyPassword(val, userProfile.passwordHash);
                  if (!isValid) {
                    loginAttempts++;
                    const remaining = 3 - loginAttempts;
                    if (remaining <= 0) {
                      socket.write(I18n.t('TUI_MAX_LOGIN_ATTEMPTS'));
                      socket.end();
                      return;
                    }
                    socket.write(I18n.t('TUI_WRONG_PASSWORD', { remaining }));
                    socket.write(I18n.t('TUI_PASSWORD_PROMPT'));
                    return;
                  }

                  await completeLogin();
                  return;
                }
              }
              continue;
            }

            if (action.type === 'PASTE_COMPLETE') {
              const rawText = action.content || '';
              const trimmed = rawText.trim();
              const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');

              // 1. Komut veya tek satırlık metin yapıştırıldı
              if (trimmed.startsWith('/') || !rawText.includes('\n')) {
                const singleLine = trimmed.replace(/[\r\n]+/g, ' ');
                if (session && session.focus === 'input') {
                  session.inputBuffer += singleLine;
                  session.cursorIndex = session.inputBuffer.length;
                  session.renderInputOnly();
                }
              } 
              // 2. Çok satırlı kod veya metin bloğu yapıştırıldı
              else if (session && session.activeTarget && session.activeTarget !== systemConsole) {
                await this.handleOutboundMessage(
                  session,
                  userAddress,
                  session.activeTarget,
                  rawText,
                  false,
                  true // isSnippet = true (girintileri ve satır sonlarını korur)
                );
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
          const exitingUser = userAddress;
          this.db.updateUserProfile(exitingUser, session.contacts, session.history);
          this.sessions.delete(exitingUser);
          this.notifyAllSessionsRender();
          this.federation.broadcastUserOffline(exitingUser);
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
  }

  async handleOutboundMessage(session, from, to, content, isAction = false, isSnippet = false) {
    const target = AddressHelper.parse(to);
    if (!target) return;

    let finalContent = content;
    let isE2EE = false;

    // --- E2EE ŞİFRELEME & GÜVENLİK POSTÜRÜ ---
    if (target.type === 'USER') {
      const recipientSession = this.findLocalSession(target.raw);
      const recipientProfile = this.db.getUserProfile(target.raw);
      const remoteSec = this.federation.getRemoteUserSecurity(target.raw);

      const recipientIsSSH = recipientSession 
        ? recipientSession.isSsh 
        : (remoteSec ? remoteSec.isSsh : !!recipientProfile.kemPublicKey);

      const recipientKemPub = recipientSession?.kemKeyPair?.publicKey 
        || remoteSec?.kemPublicKey 
        || recipientProfile.kemPublicKey;

      if (session.isSsh) {
        if (recipientIsSSH && recipientKemPub && session.kemKeyPair) {
          // İki taraf da SSH: Çift Zarf (Dual-Envelope) ML-KEM-768 Şifreleme
          try {
            const messageKey = crypto.randomBytes(32);
            const enc = CryptoHelper.encrypt(content, messageKey);

            // 1. Alıcının KEM anahtarı ile messageKey sarma
            const rKem = CryptoHelper.encapsulateKey(recipientKemPub);
            const rAes = CryptoHelper.deriveKey(rKem.sharedSecret, 'e2ee-wrap', 'wrap-key');
            const rEncKey = CryptoHelper.encrypt(messageKey.toString('base64'), rAes);

            // 2. Göndericinin KEM anahtarı ile messageKey sarma
            const sKem = CryptoHelper.encapsulateKey(session.kemKeyPair.publicKey);
            const sAes = CryptoHelper.deriveKey(sKem.sharedSecret, 'e2ee-wrap', 'wrap-key');
            const sEncKey = CryptoHelper.encrypt(messageKey.toString('base64'), sAes);

            const rCombined = `${rKem.encapsulatedKey}!${rEncKey.iv}!${rEncKey.authTag}!${rEncKey.ciphertext}`;
            const sCombined = `${sKem.encapsulatedKey}!${sEncKey.iv}!${sEncKey.authTag}!${sEncKey.ciphertext}`;

            finalContent = `e2ee:v2:${rCombined}:${sCombined}:${enc.iv}:${enc.authTag}:${enc.ciphertext}`;
            isE2EE = true;
          } catch (err) {
            log.warn(I18n.t('E2EE_ENCRYPT_ERROR_LOG', { error: err.message }));
            session.addSystemLog(`\x1b[1;31m${I18n.t('E2EE_ENCRYPT_ERROR_NOTICE', { error: err.message })}\x1b[0m`);
          }
        } else {
          // Karşı taraf Telnet
          if (!session.warnedInsecureTargets.has(target.raw)) {
            session.warnedInsecureTargets.add(target.raw);
            session.addSystemLog(I18n.t('E2EE_WARNING_TELNET_PEER', { user: target.raw }));
          }
        }
      }
    }

    const messageRecord = {
      from,
      to: target.raw,
      content: finalContent,
      isAction,
      isSnippet,
      isE2EE
    };

    const saved = this.db.saveMessage(messageRecord);
    if (!saved) return;

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
        await this.federation.sendRemoteMessage(from, target.raw, finalContent, isAction, isSnippet, isE2EE);
      } else if (!target.isLocal) {
        await this.federation.sendRemoteMessage(from, target.raw, finalContent, isAction, isSnippet, isE2EE);
      } else {
        this.federation.forwardToChannelSubscribers(target.raw, messageRecord);
      }
    } else {
      if (target.isLocal) {
        const recipientSession = this.findLocalSession(target.raw);
        if (recipientSession) {
          recipientSession.addContact(from);
          recipientSession.incrementUnread(from);

          recipientSession.notifyNewMessage();
          recipientSession.emit('request_render');
        }
      } else {
        const res = await this.federation.sendRemoteMessage(from, target.raw, finalContent, isAction, isSnippet, isE2EE);
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
    log.info(I18n.t('CLIENT_CLOSED'));
  }
}