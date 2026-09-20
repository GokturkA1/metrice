import net from 'node:net';
import crypto from 'node:crypto';
import { CONFIG } from '../config/index.js';
import { Logger } from '../utils/logger.js';
import { AddressHelper } from '../utils/addressHelper.js';
import { CryptoHelper } from '../utils/cryptoHelper.js';
import { createCommandRegistry } from '../commands/index.js';
import { I18n } from '../locales/i18n.js';
import { ProxyProtocolParser } from '../utils/proxyProtocol.js';
import { TelnetClientConnection, TELNET, AUTH_STATE } from './telnetClientConnection.js';

const log = new Logger('CLIENT_SRV');

export { TelnetClientConnection, TELNET, AUTH_STATE };

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

  updateTargetMigration(canonicalUser) {
    const parsed = AddressHelper.parse(canonicalUser);
    if (!parsed || !parsed.name || !parsed.nodeId) return;
    const nickLower = parsed.name.toLowerCase();

    for (const session of this.sessions.values()) {
      let changed = false;

      // 1. Aktif hedef eski NodeID ise güncelle
      if (session.activeTarget && session.activeTarget.startsWith('@')) {
        const activeParsed = AddressHelper.parse(session.activeTarget);
        if (activeParsed && activeParsed.name.toLowerCase() === nickLower && activeParsed.nodeId !== parsed.nodeId) {
          session.activeTarget = canonicalUser;
          changed = true;
        }
      }

      // 2. Rehberdeki (contacts) eski NodeID'yi güncelle
      if (Array.isArray(session.contacts)) {
        let contactsUpdated = false;
        session.contacts = session.contacts.map((c) => {
          if (c.startsWith('@')) {
            const cParsed = AddressHelper.parse(c);
            if (cParsed && cParsed.name.toLowerCase() === nickLower && cParsed.nodeId !== parsed.nodeId) {
              changed = true;
              contactsUpdated = true;
              return canonicalUser;
            }
          }
          return c;
        });
        if (contactsUpdated && typeof session.onProfileChange === 'function') {
          session.onProfileChange(session.contacts, session.history);
        }
      }

      if (changed) {
        session.emit('request_render');
      }
    }
  }

  initFederationListeners() {
    this.federation.on('presence_change', () => {
      try {
        if (this.federation && this.federation.remoteOnlineUsers) {
          for (const u of this.federation.remoteOnlineUsers.keys()) {
            this.updateTargetMigration(u);
          }
        }
      } catch {}
      if (this.renderDebounceTimer) clearTimeout(this.renderDebounceTimer);
      this.renderDebounceTimer = setTimeout(() => {
        this.notifyAllSessionsRender();
      }, 50);
    });

    this.federation.on('message', (msg) => {
      try {
        if (msg.from && msg.from.startsWith('@')) {
          this.updateTargetMigration(msg.from);
        }
        const isChan = msg.to.startsWith('#') || AddressHelper.isGlobalChannel(msg.to);
        if (isChan) {
          const isGlobal = AddressHelper.isGlobalChannel(msg.to);
          for (const [addr, userSession] of this.sessions.entries()) {
            if (msg.from !== addr) {
              if (isGlobal || userSession.isMemberOf(msg.to)) {
                userSession.incrementUnread(msg.to);
                const isMentioned = userSession.isUserMentioned(msg.content);
                const isViewing = userSession.isViewingTarget(msg.to);
                if (!isViewing || isMentioned) {
                  userSession.notifyNewMessage();
                }
                userSession.emit('request_render');
              }
            }
          }
        } else {
          let recipientSession = this.findLocalSession(msg.to);
          if (!recipientSession) {
            const pTo = AddressHelper.parse(msg.to);
            if (pTo && pTo.name) {
              recipientSession = this.findLocalSession(pTo.name);
            }
          }
          if (recipientSession) {
            recipientSession.addContact(msg.from);
            recipientSession.incrementUnread(msg.from);

            const isMentioned = recipientSession.isUserMentioned(msg.content);
            const isViewing = recipientSession.isViewingTarget(msg.from);
            if (!isViewing || isMentioned) {
              recipientSession.notifyNewMessage();
            }
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
        if (recipientSession && AddressHelper.isSameTarget(recipientSession.activeTarget, payload.from)) {
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
    const localNodeId = (this.federation && (this.federation.nodeId || this.federation.myIdentity?.nodeId)) || AddressHelper.getLocalNodeId() || 'local';
    return Array.from(this.sessions.keys()).map((userAddr) => {
      if (typeof userAddr === 'string' && userAddr.endsWith('.mesh')) {
        return userAddr;
      }
      const parsed = AddressHelper.parse(userAddr);
      const nick = parsed?.name || (typeof userAddr === 'string' ? userAddr.split(':')[0].replace('@', '') : 'user');
      return `@${nick}:${localNodeId}.mesh`;
    });
  }

  getLocalMemberships() {
    const list = [];
    const localNodeId = (this.federation && (this.federation.nodeId || this.federation.myIdentity?.nodeId)) || AddressHelper.getLocalNodeId() || 'local';
    for (const [userAddr, session] of this.sessions.entries()) {
      let canonicalUser = userAddr;
      if (typeof userAddr !== 'string' || !userAddr.endsWith('.mesh')) {
        const parsed = AddressHelper.parse(userAddr);
        const nick = parsed?.name || (typeof userAddr === 'string' ? userAddr.split(':')[0].replace('@', '') : 'user');
        canonicalUser = `@${nick}:${localNodeId}.mesh`;
      }
      list.push({
        user: canonicalUser,
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

    if (AddressHelper.isSystemConsole(target) || AddressHelper.isGlobalChannel(target)) {
      return this.getOnlineUsers();
    }

    if (target.startsWith('@')) {
      return [target];
    }

    const localMembers = [];
    const localNodeId = (this.federation && (this.federation.nodeId || this.federation.myIdentity?.nodeId)) || AddressHelper.getLocalNodeId() || 'local';
    for (const [userAddr, session] of this.sessions.entries()) {
      if (session.isMemberOf(target)) {
        const parsed = AddressHelper.parse(userAddr);
        const nick = parsed?.name || userAddr.split(':')[0].replace('@', '');
        const canonicalUser = `@${nick}:${localNodeId}.mesh`;
        localMembers.push(canonicalUser);
      }
    }

    const remoteMembers = this.federation.getChannelMembers(target);
    const allMembers = [...localMembers, ...remoteMembers];
    const memberByNick = new Map();
    for (const m of allMembers) {
      if (typeof m !== 'string') continue;
      const nick = m.split(':')[0].replace('@', '').toLowerCase();
      const existing = memberByNick.get(nick);
      if (!existing) {
        memberByNick.set(nick, m);
      } else if (!existing.endsWith('.mesh') && m.endsWith('.mesh')) {
        memberByNick.set(nick, m);
      }
    }
    return Array.from(memberByNick.values());
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
    const clean = userAddressOrTarget.startsWith('@') || userAddressOrTarget.startsWith('#')
      ? userAddressOrTarget
      : `@${userAddressOrTarget}`;
    const parsedTarget = AddressHelper.parse(clean);
    const targetName = (parsedTarget?.name || clean.replace(/^[@#]/, '').split(':')[0]).toLowerCase();

    for (const [addr, sess] of this.sessions.entries()) {
      if (addr.toLowerCase() === userAddressOrTarget.toLowerCase() || addr.toLowerCase() === clean.toLowerCase()) {
        return sess;
      }
      const parsedAddr = AddressHelper.parse(addr);
      const addrName = (parsedAddr?.name || addr.replace(/^[@#]/, '').split(':')[0]).toLowerCase();
      if (addrName === targetName) {
        return sess;
      }
    }
    return null;
  }

  getCurrentConversation(userAddress, activeTarget, systemLogs) {
    if (AddressHelper.isSystemConsole(activeTarget)) return systemLogs;
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
      const handleClient = () => {
        new TelnetClientConnection(socket, this);
      };

      if (CONFIG.useProxyProtocol) {
        ProxyProtocolParser.handle(socket, { trustedIps: CONFIG.proxyProtocolTrustedIps }, (err) => {
          if (err) {
            log.warn(I18n.t('CLIENT_PROXY_ERR', { error: err.message }));
            return;
          }
          handleClient();
        });
      } else {
        handleClient();
      }
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

      const recipientKemPub = recipientSession?.kemKeyPair?.publicKey 
        || remoteSec?.kemPublicKey 
        || recipientProfile?.kemPublicKey;

      const recipientIsSSH = recipientSession 
        ? recipientSession.isSsh 
        : (remoteSec ? remoteSec.isSsh : Boolean(recipientKemPub));

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
            const isViewing = userSession.isViewingTarget(target.raw);
            if (!isViewing || isMentioned) {
              userSession.notifyNewMessage();
            }
            userSession.emit('request_render');
          }
        }
      }

      if (target.isGlobalChannel) {
        try {
          const res = await this.federation.sendRemoteMessage(from, target.raw, finalContent, isAction, isSnippet, isE2EE);
          log.debug(I18n.t('CLIENT_GLOBAL_CHAN_DISPATCHED', { from, target: target.raw, status: res?.status || 'ok' }));
        } catch (err) {
          log.warn(I18n.t('CLIENT_GLOBAL_CHAN_ERR', { error: err.message }));
        }
      } else if (!target.isLocal) {
        await this.federation.sendRemoteMessage(from, target.raw, finalContent, isAction, isSnippet, isE2EE);
      } else {
        this.federation.forwardToChannelSubscribers(target.raw, messageRecord);
      }
    } else {
      let recipientSession = target.isLocal ? this.findLocalSession(target.raw) : null;
      if (!recipientSession && target.isLocal && target.name) {
        recipientSession = this.findLocalSession(target.name);
      }

      if (recipientSession) {
        recipientSession.addContact(from);
        recipientSession.incrementUnread(from);

        const isMentioned = recipientSession.isUserMentioned(content);
        const isViewing = recipientSession.isViewingTarget(from);
        if (!isViewing || isMentioned) {
          recipientSession.notifyNewMessage();
        }
        recipientSession.emit('request_render');
      } else {
        let remoteTarget = target.raw;
        if (target.isLocal && this.federation?.remoteOnlineUsers) {
          const targetNick = (target.name || target.raw.split(':')[0].replace('@', '')).toLowerCase();
          for (const u of this.federation.remoteOnlineUsers.keys()) {
            const p = AddressHelper.parse(u);
            if (p && p.name.toLowerCase() === targetNick) {
              remoteTarget = u;
              break;
            }
          }
        }
        const res = await this.federation.sendRemoteMessage(from, remoteTarget, finalContent, isAction, isSnippet, isE2EE);
        if (res && res.status === 'queued') {
          session.addSystemLog(I18n.t('SYS_OUTBOX_QUEUED', { target: remoteTarget }));
        }
      }
    }
  }

  close() {
    if (this.renderDebounceTimer) {
      clearTimeout(this.renderDebounceTimer);
      this.renderDebounceTimer = null;
    }
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