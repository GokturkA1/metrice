import { Logger } from '../utils/logger.js';
import { InputParser } from '../utils/inputParser.js';
import { AddressHelper } from '../utils/addressHelper.js';
import { CryptoHelper } from '../utils/cryptoHelper.js';
import { TerminalSession } from './terminalSession.js';
import { SessionInputHandler } from './sessionInputHandler.js';
import { I18n } from '../locales/i18n.js';

const log = new Logger('TELNET_CONN');

export const TELNET = {
  IAC: 0xFF,
  WILL: 0xFB,
  DONT: 0xFE,
  DO: 0xFD,
  OPT_ECHO: 0x01,
  OPT_SUPPRESS_GO_AHEAD: 0x03,
  OPT_LINEMODE: 0x22,
  OPT_NAWS: 0x1F
};

export const AUTH_STATE = {
  USERNAME: 'USERNAME',
  LOGIN_PASSWORD: 'LOGIN_PASSWORD',
  REGISTER_PASSWORD: 'REGISTER_PASSWORD',
  CONFIRM_PASSWORD: 'CONFIRM_PASSWORD',
  AUTHENTICATED: 'AUTHENTICATED'
};

export class TelnetClientConnection {
  constructor(socket, clientServer) {
    this.socket = socket;
    this.clientServer = clientServer;
    this.db = clientServer.db;
    this.federation = clientServer.federation;
    this.commands = clientServer.commands;

    this.clientAddr = `${socket.realRemoteAddress || socket.remoteAddress}:${socket.realRemotePort || socket.remotePort}`;
    log.info(I18n.t('CLIENT_NEW_CONN', { addr: this.clientAddr }));

    this.sendHandshakeAndSizeQuery();

    this.authState = AUTH_STATE.USERNAME;
    this.targetUserAddress = null;
    this.userProfile = null;
    this.loginAttempts = 0;

    this.inputBuffer = '';
    this.tempPassword = '';

    this.userAddress = null;
    this.session = null;
    this.detectedWidth = 110;
    this.detectedHeight = 24;

    this.parser = new InputParser();

    this.initSocket();
  }

  sendHandshakeAndSizeQuery() {
    try {
      const initPayload = Buffer.from([
        TELNET.IAC, TELNET.WILL, TELNET.OPT_ECHO,
        TELNET.IAC, TELNET.WILL, TELNET.OPT_SUPPRESS_GO_AHEAD,
        TELNET.IAC, TELNET.DONT, TELNET.OPT_LINEMODE,
        TELNET.IAC, TELNET.DO, TELNET.OPT_NAWS
      ]);
      this.socket.write(initPayload);
      this.socket.write('\x1b[?2004h');
      this.socket.write('\x1b[s\x1b[999;999H\x1b[6n\x1b[u');
    } catch {}
  }

  async completeLogin() {
    this.authState = AUTH_STATE.AUTHENTICATED;
    this.userAddress = this.targetUserAddress;

    this.session = new TerminalSession(
      this.socket,
      this.userAddress,
      this.userProfile,
      () => this.clientServer.getOnlineUsers(),
      (target) => this.clientServer.getChannelMembers(target),
      (contacts, history) => {
        this.db.updateUserProfile(this.userAddress, contacts, history);
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

    this.session.isSsh = false;
    this.session.isSecureE2EE = false;

    this.session.on('request_render', () => {
      const conv = this.clientServer.getCurrentConversation(this.userAddress, this.session.activeTarget, this.session.systemLogs);
      this.session.renderFull(conv);
    });

    this.session.resize(this.detectedWidth, this.detectedHeight);
    this.clientServer.sessions.set(this.userAddress, this.session);
    log.info(I18n.t('CLIENT_USER_LOGGED_IN', { user: this.userAddress }));

    this.session.emit('request_render');
    this.clientServer.notifyAllSessionsRender();
    this.federation.broadcastPresence();
  }

  initSocket() {
    this.socket.write('\x1b[2J\x1b[H\x1b[1;36m' + I18n.t('TUI_WELCOME_BANNER') + '\x1b[0m');
    this.socket.write(I18n.t('TUI_LOGIN_PROMPT'));

    this.socket.on('data', async (chunk) => {
      try {
        const actions = this.parser.parse(chunk);

        for (const action of actions) {
          if (action.type === 'RESIZE') {
            this.detectedWidth = action.width;
            this.detectedHeight = action.height;
            if (this.session) this.session.resize(this.detectedWidth, this.detectedHeight);
            continue;
          }

          if (this.authState !== AUTH_STATE.AUTHENTICATED) {
            await this.handleAuthInput(action);
            continue;
          }

          if (action.type === 'PASTE_COMPLETE') {
            await this.handlePaste(action);
            continue;
          }

          await this.handleSessionInput(action);
        }
      } catch (err) {
        log.error(I18n.t('CLIENT_INPUT_ERROR', { error: err.message }));
      }
    });

    this.socket.on('close', () => {
      if (this.userAddress && this.session) {
        const exitingUser = this.userAddress;
        this.db.updateUserProfile(exitingUser, this.session.contacts, this.session.history);
        const currentActiveSession = this.clientServer.sessions.get(exitingUser);
        if (currentActiveSession === this.session) {
          this.clientServer.sessions.delete(exitingUser);
          this.clientServer.notifyAllSessionsRender();
          this.federation.broadcastUserOffline(exitingUser);
        }
      }
      log.info(I18n.t('CLIENT_CONN_CLOSED', { addr: this.clientAddr }));
    });

    this.socket.on('error', (err) => {
      log.error(I18n.t('CLIENT_SOCKET_ERROR', { addr: this.clientAddr, error: err.message }));
    });
  }

  async handleAuthInput(action) {
    if (action.type === 'CHAR') {
      this.inputBuffer += action.char;
      if (this.authState === AUTH_STATE.USERNAME) this.socket.write(action.char);
      else this.socket.write('*');
    } else if (action.type === 'KEY_BACKSPACE') {
      if (this.inputBuffer.length > 0) {
        this.inputBuffer = this.inputBuffer.slice(0, -1);
        this.socket.write('\b \b');
      }
    } else if (action.type === 'KEY_ENTER') {
      const val = this.inputBuffer.trim();
      this.inputBuffer = '';

      // 1. KULLANICI ADI ASAMASI
      if (this.authState === AUTH_STATE.USERNAME) {
        if (!AddressHelper.isValidUsername(val)) {
          this.socket.write(I18n.t('TUI_INVALID_USERNAME'));
          return;
        }

        this.targetUserAddress = AddressHelper.formatUser(val);

        if (this.clientServer.sessions.has(this.targetUserAddress)) {
          this.socket.write(I18n.t('TUI_USERNAME_TAKEN'));
          this.targetUserAddress = null;
          return;
        }

        this.userProfile = this.db.getUserProfile(this.targetUserAddress);

        if (!this.userProfile.passwordHash) {
          this.authState = AUTH_STATE.REGISTER_PASSWORD;
          this.socket.write(I18n.t('TUI_NEW_USER_PASSWORD_PROMPT'));
        } else {
          this.authState = AUTH_STATE.LOGIN_PASSWORD;
          this.socket.write(I18n.t('TUI_PASSWORD_PROMPT'));
        }
        return;
      }

      // 2. YENI KULLANICI ILK PAROLA ASAMASI
      if (this.authState === AUTH_STATE.REGISTER_PASSWORD) {
        if (val.length < 4) {
          this.socket.write(I18n.t('TUI_PASSWORD_TOO_SHORT'));
          this.socket.write(I18n.t('TUI_NEW_USER_PASSWORD_PROMPT'));
          return;
        }
        this.tempPassword = val;
        this.authState = AUTH_STATE.CONFIRM_PASSWORD;
        this.socket.write(I18n.t('TUI_CONFIRM_PASSWORD_PROMPT'));
        return;
      }

      // 3. YENI KULLANICI PAROLA TEKRAR ASAMASI
      if (this.authState === AUTH_STATE.CONFIRM_PASSWORD) {
        if (val !== this.tempPassword) {
          this.tempPassword = '';
          this.authState = AUTH_STATE.REGISTER_PASSWORD;
          this.socket.write(I18n.t('TUI_PASSWORD_MISMATCH'));
          this.socket.write(I18n.t('TUI_NEW_USER_PASSWORD_PROMPT'));
          return;
        }

        const hash = await CryptoHelper.hashPassword(val);
        this.db.updateUserPassword(this.targetUserAddress, hash);
        this.userProfile.passwordHash = hash;
        this.tempPassword = '';

        await this.completeLogin();
        return;
      }

      // 4. MEVCUT KULLANICI GIRIS PAROLASI
      if (this.authState === AUTH_STATE.LOGIN_PASSWORD) {
        this.userProfile = this.db.getUserProfile(this.targetUserAddress);
        const isSshVault = this.userProfile.passwordHash && this.userProfile.passwordHash.startsWith('{');

        if (isSshVault) {
          if (!this.userProfile.allowTelnet) {
            this.socket.write(I18n.t('TUI_TELNET_BLOCKED_SSH_ONLY'));
            this.socket.end();
            return;
          }

          if (!this.userProfile.publicKey) {
            this.socket.write(I18n.t('TUI_TELNET_NO_KEY_IN_PROFILE'));
            this.socket.end();
            return;
          }

          const isValid = await CryptoHelper.verifyPassword(
            val,
            this.userProfile.passwordHash,
            this.userProfile.publicKey,
            this.federation.nodeAddress
          );

          if (!isValid) {
            this.loginAttempts++;
            const remaining = 3 - this.loginAttempts;
            if (remaining <= 0) {
              this.socket.write(I18n.t('TUI_MAX_LOGIN_ATTEMPTS'));
              this.socket.end();
              return;
            }
            this.socket.write(I18n.t('TUI_WRONG_PASSWORD', { remaining }));
            this.socket.write(I18n.t('TUI_PASSWORD_PROMPT'));
            return;
          }

          await this.completeLogin();

          if (this.session) {
            this.session.addSystemLog(I18n.t('E2EE_TELNET_BANNER_WARNING'));
          }
          return;
        }

        // Klasik Telnet hesabi
        const isValid = await CryptoHelper.verifyPassword(val, this.userProfile.passwordHash);
        if (!isValid) {
          this.loginAttempts++;
          const remaining = 3 - this.loginAttempts;
          if (remaining <= 0) {
            this.socket.write(I18n.t('TUI_MAX_LOGIN_ATTEMPTS'));
            this.socket.end();
            return;
          }
          this.socket.write(I18n.t('TUI_WRONG_PASSWORD', { remaining }));
          this.socket.write(I18n.t('TUI_PASSWORD_PROMPT'));
          return;
        }

        await this.completeLogin();
      }
    }
  }

  async handlePaste(action) {
    await SessionInputHandler.handlePaste(this.session, this.clientServer, this.userAddress, action);
  }

  async handleSessionInput(action) {
    await SessionInputHandler.handleAction(action, this.session, this.clientServer, this.userAddress, this.socket, this.db);
  }
}
