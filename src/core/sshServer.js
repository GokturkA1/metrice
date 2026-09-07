import net from 'node:net';
import crypto from 'node:crypto';
import EventEmitter from 'node:events';
import { Logger } from '../utils/logger.js';
import { SshPacketReader, SshPacketWriter } from '../utils/sshPacket.js';
import { CryptoHelper } from '../utils/cryptoHelper.js';
import { AddressHelper } from '../utils/addressHelper.js';
import { InputParser } from '../utils/inputParser.js';
import { TerminalSession } from './terminalSession.js';
import { I18n } from '../locales/i18n.js';
import { CONFIG } from '../config/index.js';

const log = new Logger('SSH_SRV');

const SSH_MSG = {
  DISCONNECT: 1,
  IGNORE: 2,
  UNIMPLEMENTED: 3,
  DEBUG: 4,
  SERVICE_REQUEST: 5,
  SERVICE_ACCEPT: 6,
  KEXINIT: 20,
  NEWKEYS: 21,
  KEX_ECDH_INIT: 30,
  KEX_ECDH_REPLY: 31,
  USERAUTH_REQUEST: 50,
  USERAUTH_FAILURE: 51,
  USERAUTH_SUCCESS: 52,
  USERAUTH_BANNER: 53,
  USERAUTH_PK_OK: 60,
  CHANNEL_OPEN: 90,
  CHANNEL_OPEN_CONFIRMATION: 91,
  CHANNEL_OPEN_FAILURE: 92,
  CHANNEL_WINDOW_ADJUST: 93,
  CHANNEL_DATA: 94,
  CHANNEL_EOF: 96,
  CHANNEL_CLOSE: 97,
  CHANNEL_REQUEST: 98,
  CHANNEL_SUCCESS: 99,
  CHANNEL_FAILURE: 100
};

class SshClientConnection extends EventEmitter {
  constructor(socket, hostKey, db, clientServer, options = {}) {
    super();
    this.socket = socket;
    this.hostKey = hostKey;
    this.db = db;
    this.clientServer = clientServer;
    this.options = options;

    this.state = 'IDENT';
    this.inBuffer = Buffer.alloc(0);
    this.clientVersion = '';

    // SSH Sunucu Versiyon Dizgesi (Öncelik: options.serverVersion -> CONFIG.sshServerVersion -> Fallback)
    const configuredVersion = (options && options.serverVersion) || (CONFIG && CONFIG.sshServerVersion);
    if (typeof configuredVersion === 'string' && configuredVersion.trim().length > 0) {
      const clean = configuredVersion.trim();
      this.serverVersion = clean.startsWith('SSH-2.0-') ? clean : `SSH-2.0-${clean}`;
    } else {
      this.serverVersion = 'SSH-2.0-Metrice_2.1.5';
    }

    this.clientKexPayload = null;
    this.serverKexPayload = null;
    this.selectedKex = 'mlkem768x25519-sha256';
    this.sharedSecret = null;
    this.exchangeHash = null;
    this.sessionIdentifier = null;

    this.isEncryptedIn = false;
    this.isEncryptedOut = false;
    this.encryptCipher = null;
    this.decryptCipher = null;
    this.outHmacKey = null;
    this.inHmacKey = null;
    this.inSeq = 0;
    this.outSeq = 0;

    this.cipherName = 'aes-128-ctr';
    this.keyLen = 16;
    this.ivLen = 16;

    this.offeredClientPub = null;
    this.derivedE2eeSeed = null;
    this.authenticatedUser = null;
    this.channelRemoteId = null;
    this.channelLocalId = 0;
    this.channelRemoteWindow = 0;
    this.channelRemoteMaxPacket = 32768;
    this.session = null;
    this.termWidth = 110;
    this.termHeight = 24;

    this.activeTimeouts = new Set();
    this.parser = new InputParser();
    this.initSocket();
  }

  setManagedTimeout(fn, ms) {
    const timer = setTimeout(() => {
      this.activeTimeouts.delete(timer);
      fn();
    }, ms);
    this.activeTimeouts.add(timer);
    return timer;
  }

  initSocket() {
    this.socket.write(this.serverVersion + '\r\n');

    this.socket.on('data', (chunk) => {
      this.inBuffer = Buffer.concat([this.inBuffer, chunk]);
      this.processIncoming();
    });

    this.socket.on('error', (err) => {
      log.error(I18n.t('SSH_CONN_ERROR', { error: err.message }));
    });

    this.socket.on('close', () => {
      this.cleanup();
    });
  }

  processIncoming() {
    if (this.state === 'IDENT') {
      const idx = this.inBuffer.indexOf('\n');
      if (idx === -1) {
        // ID satırı çok uzun sürerse veya saçma karakterler dolarsa kopar
        if (this.inBuffer.length > 256) {
          log.warn('Geçersiz SSH ID banner uzunluğu, bağlantı kesiliyor.');
          this.socket.destroy();
        }
        return;
      }

      const rawLine = this.inBuffer.subarray(0, idx + 1).toString('utf8');
      this.inBuffer = this.inBuffer.subarray(idx + 1);
      this.clientVersion = rawLine.trim();

      log.debug(I18n.t('SSH_CLIENT_IDENTIFIED', { version: this.clientVersion }));
      this.state = 'KEX';
      this.sendKexInit();
    }

    while (this.inBuffer.length > 0) {
      if (!this.isEncryptedIn) {
        // 5 baytlık standart SSH paket başlığı gelmeden önce tampon aşırı şişerse saldırıdır
        if (this.inBuffer.length < 5) {
          if (this.inBuffer.length > 1024) {
            log.warn('Şifresiz SSH başlık tamponu taştı, bağlantı sıfırlanıyor.');
            this.socket.destroy();
          }
          return;
        }

        const packetLength = this.inBuffer.readUInt32BE(0);
        const paddingLength = this.inBuffer.readUInt8(4);

        // --- ANINDA FIN/RST (DOS & FUZZING KORUMASI) ---
        if (packetLength > 65536 || packetLength < 4 || paddingLength >= packetLength) {
          log.warn(I18n.t('SSH_INVALID_PACKET_SIZE', { size: packetLength }));
          this.socket.destroy(); // Bağlantıyı anında koparır (FIN/RST)
          return;
        }

        if (this.inBuffer.length < 4 + packetLength) return;

        const payload = this.inBuffer.subarray(5, 4 + packetLength - paddingLength);
        this.inBuffer = this.inBuffer.subarray(4 + packetLength);
        this.inSeq = (this.inSeq + 1) >>> 0;
        this.handlePacket(payload);
      } else {
        if (this.inBuffer.length < 4) return;

        if (!this.currentPacketLen) {
          const encHead = this.inBuffer.subarray(0, 4);
          const decHead = this.decryptCipher.update(encHead);
          this.currentPacketLen = decHead.readUInt32BE(0);
          this.decryptedHead = decHead;
          this.inBuffer = this.inBuffer.subarray(4);

          if (this.currentPacketLen > 65536 || this.currentPacketLen < 4) {
            log.warn(I18n.t('SSH_INVALID_PACKET_SIZE', { size: this.currentPacketLen }));
            this.socket.destroy();
            return;
          }
        }

        const neededBytes = this.currentPacketLen + 32;
        if (this.inBuffer.length < neededBytes) {
          return;
        }

        const encBody = this.inBuffer.subarray(0, this.currentPacketLen);
        const macReceived = this.inBuffer.subarray(this.currentPacketLen, neededBytes);
        this.inBuffer = this.inBuffer.subarray(neededBytes);

        const decBody = this.decryptCipher.update(encBody);
        const fullDecrypted = Buffer.concat([this.decryptedHead, decBody]);

        const hmacCalc = crypto.createHmac('sha256', this.inHmacKey);
        const seqBuf = Buffer.alloc(4);
        seqBuf.writeUInt32BE(this.inSeq, 0);
        hmacCalc.update(seqBuf);
        hmacCalc.update(fullDecrypted);
        const expectedMac = hmacCalc.digest();

        if (!crypto.timingSafeEqual(macReceived, expectedMac)) {
          log.warn(I18n.t('SSH_HMAC_FAIL'));
          this.socket.destroy();
          return;
        }

        this.inSeq = (this.inSeq + 1) >>> 0;
        const paddingLength = fullDecrypted.readUInt8(4);
        const payload = fullDecrypted.subarray(5, 4 + this.currentPacketLen - paddingLength);

        this.currentPacketLen = null;
        this.decryptedHead = Buffer.alloc(0);

        this.handlePacket(payload);
      }
    }
  }

  sendPacket(payload) {
    // Soket kapanmış veya sonlandırılmışsa yazmaya çalışma
    if (!this.socket || this.socket.destroyed || !this.socket.writable || this.socket.writableEnded) {
      return;
    }

    const blockSize = 16;
    let paddingLen = blockSize - ((4 + 1 + payload.length) % blockSize);
    if (paddingLen < 4) paddingLen += blockSize;

    const packetLen = 1 + payload.length + paddingLen;
    const padding = crypto.randomBytes(paddingLen);

    const raw = Buffer.alloc(4 + 1 + payload.length + paddingLen);
    raw.writeUInt32BE(packetLen, 0);
    raw.writeUInt8(paddingLen, 4);
    payload.copy(raw, 5);
    padding.copy(raw, 5 + payload.length);

    if (!this.isEncryptedOut) {
      this.socket.write(raw);
    } else {
      const encrypted = this.encryptCipher.update(raw);
      const hmac = crypto.createHmac('sha256', this.outHmacKey);
      const seqBuf = Buffer.alloc(4);
      seqBuf.writeUInt32BE(this.outSeq, 0);
      hmac.update(seqBuf);
      hmac.update(raw);
      const macDigest = hmac.digest();

      this.socket.write(Buffer.concat([encrypted, macDigest]));
    }
    this.outSeq = (this.outSeq + 1) >>> 0;
  }

  sendKexInit() {
    const writer = new SshPacketWriter();
    writer.writeByte(SSH_MSG.KEXINIT);
    writer.writeRaw(crypto.randomBytes(16));
    writer.writeNameList(['mlkem768x25519-sha256', 'curve25519-sha256', 'curve25519-sha256@libssh.org']);
    writer.writeNameList(['ssh-ed25519']);
    writer.writeNameList(['aes128-ctr', 'aes256-ctr']);
    writer.writeNameList(['aes128-ctr', 'aes256-ctr']);
    writer.writeNameList(['hmac-sha2-256']);
    writer.writeNameList(['hmac-sha2-256']);
    writer.writeNameList(['none']);
    writer.writeNameList(['none']);
    writer.writeNameList([]);
    writer.writeNameList([]);
    writer.writeBoolean(false);
    writer.writeUInt32(0);

    this.serverKexPayload = writer.toBuffer();
    this.sendPacket(this.serverKexPayload);
  }

  handlePacket(payload) {
    const reader = new SshPacketReader(payload);
    const msgType = reader.readByte();

    switch (msgType) {
      case SSH_MSG.DISCONNECT:
        this.socket.end();
        break;

      case SSH_MSG.KEXINIT: {
        this.clientKexPayload = Buffer.from(payload);
        reader.offset += 16;
        const clientKexList = reader.readNameList();
        if (clientKexList.includes('mlkem768x25519-sha256') && CryptoHelper.HAS_ML_KEM) {
          this.selectedKex = 'mlkem768x25519-sha256';
        } else {
          this.selectedKex = 'curve25519-sha256';
        }
        log.debug(I18n.t('SSH_KEX_NEGOTIATED', { kex: this.selectedKex }));
        break;
      }

      case SSH_MSG.KEX_ECDH_INIT:
        this.handleKexInitMessage(reader);
        break;

      case SSH_MSG.NEWKEYS:
        this.isEncryptedIn = true;
        log.debug(I18n.t('SSH_TRANSPORT_READY'));
        break;

      case SSH_MSG.SERVICE_REQUEST: {
        const service = reader.readString();
        log.debug(I18n.t('SSH_SERVICE_REQUEST_RECEIVED', { service }));
        if (service === 'ssh-userauth') {
          const w = new SshPacketWriter();
          w.writeByte(SSH_MSG.SERVICE_ACCEPT);
          w.writeString('ssh-userauth');
          this.sendPacket(w.toBuffer());
        }
        break;
      }

      case SSH_MSG.USERAUTH_REQUEST:
        this.handleUserAuth(reader, payload);
        break;

      case SSH_MSG.CHANNEL_OPEN: {
        const chanType = reader.readString();
        this.channelRemoteId = reader.readUInt32();
        this.channelRemoteWindow = reader.readUInt32();
        this.channelRemoteMaxPacket = reader.readUInt32();

        if (chanType === 'session') {
          const w = new SshPacketWriter();
          w.writeByte(SSH_MSG.CHANNEL_OPEN_CONFIRMATION);
          w.writeUInt32(this.channelRemoteId);
          w.writeUInt32(this.channelLocalId);
          w.writeUInt32(1048576);
          w.writeUInt32(32768);
          this.sendPacket(w.toBuffer());
        }
        break;
      }

      case SSH_MSG.CHANNEL_REQUEST: {
        reader.readUInt32();
        const reqType = reader.readString();
        const wantReply = reader.readBoolean();

        if (reqType === 'pty-req') {
          reader.readString();
          this.termWidth = reader.readUInt32();
          this.termHeight = reader.readUInt32();
          if (wantReply) this.sendChannelSuccess();
        } else if (reqType === 'window-change') {
          this.termWidth = reader.readUInt32();
          this.termHeight = reader.readUInt32();
          if (this.session) {
            this.session.resize(this.termWidth, this.termHeight);
          }
        } else if (reqType === 'shell') {
          if (wantReply) this.sendChannelSuccess();
          this.startSshTuiSession();
        }
        break;
      }

      case SSH_MSG.CHANNEL_DATA: {
        reader.readUInt32();
        const data = reader.readBuffer();
        this.handleChannelInput(data);
        break;
      }

      case SSH_MSG.CHANNEL_WINDOW_ADJUST: {
        reader.readUInt32();
        const addBytes = reader.readUInt32();
        this.channelRemoteWindow += addBytes;
        break;
      }

      case SSH_MSG.CHANNEL_EOF:
      case SSH_MSG.CHANNEL_CLOSE: {
        this.cleanup();
        if (this.socket && !this.socket.destroyed) {
          const w = new SshPacketWriter();
          w.writeByte(SSH_MSG.CHANNEL_CLOSE);
          w.writeUInt32(this.channelRemoteId || 0);
          this.sendPacket(w.toBuffer());
          this.socket.end();
        }
        break;
      }
    }
  }

  sendChannelSuccess() {
    const w = new SshPacketWriter();
    w.writeByte(SSH_MSG.CHANNEL_SUCCESS);
    w.writeUInt32(this.channelRemoteId);
    this.sendPacket(w.toBuffer());
  }

  handleKexInitMessage(reader) {
    const clientBlob = reader.readBuffer();

    let serverBlob = null;
    let sharedSecretK = null;

    if (this.selectedKex === 'mlkem768x25519-sha256') {
      const clientKemPubRaw = clientBlob.subarray(0, 1184);
      const clientX25519PubRaw = clientBlob.subarray(1184, 1216);

      const serverX25519 = crypto.generateKeyPairSync('x25519');
      const serverX25519PubRaw = serverX25519.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

      const clientX25519PubKeyObj = crypto.createPublicKey({
        key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), clientX25519PubRaw]),
        format: 'der',
        type: 'spki'
      });
      const kCl = crypto.diffieHellman({
        privateKey: serverX25519.privateKey,
        publicKey: clientX25519PubKeyObj
      });

      if (!SshClientConnection.kemSpkiPrefix) {
        const dummyKey = crypto.generateKeyPairSync('ml-kem-768');
        const dummyDer = dummyKey.publicKey.export({ type: 'spki', format: 'der' });
        SshClientConnection.kemSpkiPrefix = dummyDer.subarray(0, dummyDer.length - 1184);
      }

      const clientKemPubKeyObj = crypto.createPublicKey({
        key: Buffer.concat([SshClientConnection.kemSpkiPrefix, clientKemPubRaw]),
        format: 'der',
        type: 'spki'
      });

      const { sharedKey: kPq, ciphertext: sCt2 } = crypto.encapsulate(clientKemPubKeyObj);
      serverBlob = Buffer.concat([sCt2, serverX25519PubRaw]);
      sharedSecretK = crypto.createHash('sha256').update(kPq).update(kCl).digest();
    } else {
      const serverEcdh = crypto.generateKeyPairSync('x25519');
      serverBlob = serverEcdh.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

      const clientPubKeyObj = crypto.createPublicKey({
        key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), clientBlob]),
        format: 'der',
        type: 'spki'
      });

      sharedSecretK = crypto.diffieHellman({
        privateKey: serverEcdh.privateKey,
        publicKey: clientPubKeyObj
      });
    }

    this.sharedSecret = sharedSecretK;

    const hostKeyBlob = new SshPacketWriter();
    hostKeyBlob.writeString('ssh-ed25519');
    hostKeyBlob.writeBuffer(this.hostKey.rawEd25519Pub);
    const hostKeyBuffer = hostKeyBlob.toBuffer();

    const hashWriter = new SshPacketWriter();
    hashWriter.writeString(this.clientVersion);
    hashWriter.writeString(this.serverVersion);
    hashWriter.writeBuffer(this.clientKexPayload);
    hashWriter.writeBuffer(this.serverKexPayload);
    hashWriter.writeBuffer(hostKeyBuffer);
    hashWriter.writeBuffer(clientBlob);
    hashWriter.writeBuffer(serverBlob);

    if (this.selectedKex === 'mlkem768x25519-sha256') {
      hashWriter.writeBuffer(this.sharedSecret);
    } else {
      hashWriter.writeMpint(this.sharedSecret);
    }

    this.exchangeHash = crypto.createHash('sha256').update(hashWriter.toBuffer()).digest();
    if (!this.sessionIdentifier) {
      this.sessionIdentifier = this.exchangeHash;
    }

    const sigRaw = crypto.sign(null, this.exchangeHash, this.hostKey.privateKey);
    const sigBlob = new SshPacketWriter();
    sigBlob.writeString('ssh-ed25519');
    sigBlob.writeBuffer(sigRaw);

    const reply = new SshPacketWriter();
    reply.writeByte(SSH_MSG.KEX_ECDH_REPLY);
    reply.writeBuffer(hostKeyBuffer);
    reply.writeBuffer(serverBlob);
    reply.writeBuffer(sigBlob.toBuffer());
    this.sendPacket(reply.toBuffer());

    const newKeys = new SshPacketWriter();
    newKeys.writeByte(SSH_MSG.NEWKEYS);
    this.sendPacket(newKeys.toBuffer());

    this.prepareKeys();
    this.isEncryptedOut = true;
  }

  deriveKey(char, length) {
    const charBuf = Buffer.from([char.charCodeAt(0)]);
    let kBuffer;

    if (this.selectedKex === 'mlkem768x25519-sha256') {
      const lenPrefix = Buffer.alloc(4);
      lenPrefix.writeUInt32BE(this.sharedSecret.length, 0);
      kBuffer = Buffer.concat([lenPrefix, this.sharedSecret]);
    } else {
      let kMpint = this.sharedSecret;
      if (kMpint.length === 0 || (kMpint[0] & 0x80) !== 0) {
        const padded = Buffer.alloc(kMpint.length + 1);
        padded[0] = 0x00;
        kMpint.copy(padded, 1);
        kMpint = padded;
      }
      const lenPrefix = Buffer.alloc(4);
      lenPrefix.writeUInt32BE(kMpint.length, 0);
      kBuffer = Buffer.concat([lenPrefix, kMpint]);
    }

    let key = crypto.createHash('sha256')
      .update(kBuffer)
      .update(this.exchangeHash)
      .update(charBuf)
      .update(this.sessionIdentifier)
      .digest();

    while (key.length < length) {
      const next = crypto.createHash('sha256')
        .update(kBuffer)
        .update(this.exchangeHash)
        .update(key)
        .digest();
      key = Buffer.concat([key, next]);
    }
    return key.subarray(0, length);
  }

  prepareKeys() {
    this.cipherName = 'aes-128-ctr';
    this.keyLen = 16;
    this.ivLen = 16;

    this.ivC2S = this.deriveKey('A', this.ivLen);
    this.ivS2C = this.deriveKey('B', this.ivLen);
    this.keyC2S = this.deriveKey('C', this.keyLen);
    this.keyS2C = this.deriveKey('D', this.keyLen);
    this.inHmacKey = this.deriveKey('E', 32);
    this.outHmacKey = this.deriveKey('F', 32);

    this.decryptCipher = crypto.createDecipheriv(this.cipherName, this.keyC2S, this.ivC2S);
    this.encryptCipher = crypto.createCipheriv(this.cipherName, this.keyS2C, this.ivS2C);
  }

  async handleUserAuth(reader, rawPayload) {
    const username = reader.readString();
    const service = reader.readString();
    const method = reader.readString();

    const formattedAddr = AddressHelper.formatUser(username);

    if (method === 'none') {
      const w = new SshPacketWriter();
      w.writeByte(SSH_MSG.USERAUTH_FAILURE);
      w.writeNameList(['publickey', 'password']);
      w.writeBoolean(false);
      this.sendPacket(w.toBuffer());
      return;
    }

    if (method === 'publickey') {
      const hasSig = reader.readBoolean();
      const algo = reader.readString();
      const pubKeyBlob = reader.readBuffer();

      if (algo === 'ssh-ed25519') {
        try {
          const edKeyReader = new SshPacketReader(pubKeyBlob);
          edKeyReader.readString();
          this.offeredClientPub = edKeyReader.readBuffer();
        } catch (err) {
          log.warn(I18n.t('SSH_PUBKEY_READ_ERROR', { error: err.message }));
        }
      }

      const w = new SshPacketWriter();
      w.writeByte(SSH_MSG.USERAUTH_FAILURE);
      w.writeNameList(['password']);
      w.writeBoolean(false);
      this.sendPacket(w.toBuffer());
      return;
    }

    if (method === 'password') {
      reader.readBoolean();
      const password = reader.readString();

      const profile = this.db.getUserProfile(formattedAddr);
      let authOk = false;
      let candidateSeed = null;

      const registeredKeys = profile.publicKeys && profile.publicKeys.length > 0
        ? profile.publicKeys
        : (profile.publicKey ? [profile.publicKey] : []);

      if (this.offeredClientPub) {
        const offeredBase64 = this.offeredClientPub.toString('base64');

        if (registeredKeys.length > 0 && !registeredKeys.includes(offeredBase64)) {
          log.warn(I18n.t('SSH_UNREGISTERED_PUBKEY_WARN', { user: formattedAddr }));
          const w = new SshPacketWriter();
          w.writeByte(SSH_MSG.USERAUTH_FAILURE);
          w.writeNameList(['publickey']);
          w.writeBoolean(false);
          this.sendPacket(w.toBuffer());
          return;
        }
      }

      // Hesaba eklenen 2. ve 3. anahtarlar da kasayı açabilsin diye
      // Kasa tohumu ilk kayıtlı anahtar (kök açık anahtar) üzerinden türetilir:
      let saltPub = registeredKeys.length > 0 
        ? Buffer.from(registeredKeys[0], 'base64') 
        : this.offeredClientPub;

      if (!saltPub) {
        saltPub = Buffer.from(`salt:${this.clientServer.federation.nodeAddress}`);
      }

      try {
        candidateSeed = CryptoHelper.deriveVaultSeed(
          password,
          saltPub,
          this.clientServer.federation.nodeAddress
        );
      } catch (seedErr) {
        log.error(I18n.t('SSH_VAULT_SEED_ERROR', { error: seedErr.message }));
        const w = new SshPacketWriter();
        w.writeByte(SSH_MSG.USERAUTH_FAILURE);
        w.writeNameList(['password']);
        w.writeBoolean(false);
        this.sendPacket(w.toBuffer());
        return;
      }

      if (!profile.passwordHash) {
        const authToken = CryptoHelper.createVaultAuthToken(candidateSeed);
        const tokenSerialized = JSON.stringify(authToken);
        this.db.updateUserPassword(formattedAddr, tokenSerialized);
        profile.passwordHash = tokenSerialized;

        if (this.offeredClientPub) {
          this.db.addUserPublicKey(formattedAddr, this.offeredClientPub.toString('base64'));
        }

        this.derivedE2eeSeed = candidateSeed;
        authOk = true;
      } else {
        try {
          const tokenEncrypted = JSON.parse(profile.passwordHash);
          if (CryptoHelper.verifyVaultAuthToken(tokenEncrypted, candidateSeed)) {
            this.derivedE2eeSeed = candidateSeed;
            authOk = true;
          }
        } catch {
          authOk = false;
        }
      }

      if (authOk) {
        this.authenticatedUser = formattedAddr;
        const w = new SshPacketWriter();
        w.writeByte(SSH_MSG.USERAUTH_SUCCESS);
        this.sendPacket(w.toBuffer());
        log.info(I18n.t('SSH_AUTH_SUCCESS', { user: this.authenticatedUser }));
      } else {
        const w = new SshPacketWriter();
        w.writeByte(SSH_MSG.USERAUTH_FAILURE);
        w.writeNameList(['password']);
        w.writeBoolean(false);
        this.sendPacket(w.toBuffer());
      }
    }
  }

  startSshTuiSession() {
    const profile = this.db.getUserProfile(this.authenticatedUser);

    const virtualSocket = new EventEmitter();
    virtualSocket.write = (data) => {
      if (!this.session || !this.socket || this.socket.destroyed || !this.socket.writable || this.socket.writableEnded) {
        return false;
      }

      try {
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        const w = new SshPacketWriter();
        w.writeByte(SSH_MSG.CHANNEL_DATA);
        w.writeUInt32(this.channelRemoteId);
        w.writeBuffer(buf);
        this.sendPacket(w.toBuffer());
        return true;
      } catch {
        return false;
      }
    };
    
    virtualSocket.end = (data) => {
      if (!this.socket || this.socket.destroyed || this.socket.writableEnded) {
        return;
      }

      // 1. Çıkış mesajını SSH paketi olarak gönder
      if (data) {
        virtualSocket.write(data);
      }

      // 2. Kopyalama modunu kapat ve temiz bir alt satıra geç
      virtualSocket.write('\x1b[?2004l\r\n');

      // 3. İstemcinin paketleri render etmesine fırsat verip soketi kapat
      this.setManagedTimeout(() => {
        if (this.socket && !this.socket.destroyed && this.socket.writable) {
          try {
            this.socket.end();
          } catch {}
        }
      }, 50);
    };

    virtualSocket.destroy = () => {
      if (this.socket && !this.socket.destroyed) {
        this.socket.destroy();
      }
    };

    virtualSocket.write('\x1b[?2004h');

    this.session = new TerminalSession(
      virtualSocket,
      this.authenticatedUser,
      profile,
      () => this.clientServer.getOnlineUsers(),
      (target) => this.clientServer.getChannelMembers(target),
      (contacts, history) => {
        this.db.updateUserProfile(this.authenticatedUser, contacts, history);
        this.clientServer.federation.broadcastPresence();
      },
      () => {
        const mins = Math.floor(process.uptime() / 60);
        const mem = (process.memoryUsage().rss / 1024 / 1024).toFixed(1);
        const peers = this.clientServer.federation.peerManager ? this.clientServer.federation.peerManager.getAllPeers() : [];
        return {
          uptime: `${mins}m`,
          rss: mem,
          peers,
          role: this.clientServer.federation.role,
          nodeId: this.clientServer.federation.nodeId
        };
      },
      () => this.clientServer.commands.getAllUnique().map((c) => c.name)
    );

    this.session.isSsh = true;
    this.session.isSecureE2EE = true;

    if (this.derivedE2eeSeed) {
      this.session.kemKeyPair = CryptoHelper.deriveDeterministicX25519(this.derivedE2eeSeed);
      this.db.updateUserKemKey(this.authenticatedUser, this.session.kemKeyPair.publicKey);
    }

    this.session.on('request_render', () => {
      const conv = this.clientServer.getCurrentConversation(
        this.authenticatedUser,
        this.session.activeTarget,
        this.session.systemLogs
      );
      this.session.renderFull(conv);
    });

    this.session.resize(this.termWidth, this.termHeight);
    this.clientServer.sessions.set(this.authenticatedUser, this.session);

    this.session.emit('request_render');
    this.clientServer.notifyAllSessionsRender();
    this.clientServer.federation.broadcastPresence();
  }

  async handleChannelInput(buffer) {
    if (!this.session || !this.socket || this.socket.destroyed) return;
    const actions = this.parser.parse(buffer);

    for (const action of actions) {
      if (!this.session) return;
      if (action.type === 'RESIZE') {
        this.session.resize(action.width, action.height);
        continue;
      }

      if (action.type === 'PASTE_COMPLETE') {
        const rawText = action.content || '';
        const trimmed = rawText.trim();
        const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');

        if (trimmed.startsWith('/') || !rawText.includes('\n')) {
          const singleLine = trimmed.replace(/[\r\n]+/g, ' ');
          if (this.session.focus === 'input') {
            this.session.inputBuffer += singleLine;
            this.session.cursorIndex = this.session.inputBuffer.length;
            this.session.renderInputOnly();
          }
        } else if (this.session.activeTarget && this.session.activeTarget !== systemConsole) {
          await this.clientServer.handleOutboundMessage(
            this.session,
            this.authenticatedUser,
            this.session.activeTarget,
            rawText,
            false,
            true
          );
          this.session.emit('request_render');
        }
        continue;
      }

      switch (action.type) {
        case 'KEY_TAB':
          if (this.session.focus === 'input' && this.session.inputBuffer.trim().length > 0) {
            this.session.handleTabCompletion();
          } else {
            this.session.focus = this.session.focus === 'input' ? 'sidebar' : 'input';
            this.session.emit('request_render');
          }
          break;

        case 'CHAR':
          if (this.session.focus === 'input') {
            this.session.insertChar(action.char);
            this.session.renderInputOnly();

            const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');
            if (this.session.activeTarget && !this.session.activeTarget.startsWith('#') && this.session.activeTarget !== systemConsole) {
              const targetParsed = AddressHelper.parse(this.session.activeTarget);
              if (targetParsed) {
                if (targetParsed.isLocal) {
                  const localRecipient = this.clientServer.sessions.get(targetParsed.raw);
                  if (localRecipient && localRecipient.activeTarget === this.authenticatedUser) {
                    const senderNick = this.authenticatedUser.split(':')[0].replace('@', '');
                    localRecipient.setTyping(senderNick);
                  }
                } else {
                  this.clientServer.federation.sendTyping(this.authenticatedUser, this.session.activeTarget);
                }
              }
            }
          } else {
            this.session.focus = 'input';
            this.session.insertChar(action.char);
            this.session.emit('request_render');
          }
          break;

        case 'KEY_BACKSPACE':
          if (this.session.focus === 'input') {
            this.session.backspace();
            this.session.renderInputOnly();
          }
          break;

        case 'KEY_DELETE':
          if (this.session.focus === 'input') {
            this.session.deleteForward();
            this.session.renderInputOnly();
          }
          break;

        case 'KEY_CTRL_W':
          if (this.session.focus === 'input') {
            this.session.deleteWord();
            this.session.renderInputOnly();
          }
          break;

        case 'KEY_CTRL_U':
          if (this.session.focus === 'input') {
            this.session.clearInput();
            this.session.renderInputOnly();
          }
          break;

        case 'KEY_LEFT':
          if (this.session.focus === 'input') {
            this.session.moveCursorLeft();
            this.session.renderInputOnly();
          }
          break;

        case 'KEY_RIGHT':
          if (this.session.focus === 'input') {
            this.session.moveCursorRight();
            this.session.renderInputOnly();
          }
          break;

        case 'KEY_PAGE_UP':
          this.session.scrollUp(5);
          this.session.emit('request_render');
          break;

        case 'KEY_PAGE_DOWN':
          this.session.scrollDown(5);
          this.session.emit('request_render');
          break;

        case 'KEY_UP':
          if (this.session.focus === 'input') {
            this.session.historyUp();
            this.session.renderInputOnly();
          } else if (this.session.focus === 'sidebar') {
            if (this.session.selectedContactIdx > 0) this.session.selectedContactIdx--;
            this.session.emit('request_render');
          }
          break;

        case 'KEY_DOWN':
          if (this.session.focus === 'input') {
            this.session.historyDown();
            this.session.renderInputOnly();
          } else if (this.session.focus === 'sidebar') {
            if (this.session.selectedContactIdx < this.session.contacts.length - 1) this.session.selectedContactIdx++;
            this.session.emit('request_render');
          }
          break;

        case 'KEY_ENTER':
          if (this.session.focus === 'sidebar') {
            const selectedTarget = this.session.contacts[this.session.selectedContactIdx];
            if (selectedTarget) {
              this.session.setTarget(selectedTarget);
              this.session.focus = 'input';
            }
            break;
          }

          const input = this.session.inputBuffer.trim();
          this.session.clearInput();

          if (!input) {
            this.session.renderInputOnly();
            break;
          }

          this.session.pushHistory(input);

          if (input.startsWith('/')) {
            await this.clientServer.commands.execute(input, {
              session: this.session,
              socket: this.session.socket,
              db: this.db,
              federation: this.clientServer.federation,
              clientServer: this.clientServer,
              registry: this.clientServer.commands,
              userAddress: this.authenticatedUser
            });

            // Oturum /quit ile sonlandırıldıysa render isteme
            if (this.socket && !this.socket.destroyed && !this.socket.writableEnded) {
              this.session?.emit('request_render');
            }

            break;
          }

          const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');
          if (this.session.activeTarget === systemConsole) {
            this.session.addSystemLog(I18n.t('SYS_SYSTEM_WINDOW_NO_MSG'));
            break;
          }

          if (this.session.activeTarget) {
            await this.clientServer.handleOutboundMessage(
              this.session,
              this.authenticatedUser,
              this.session.activeTarget,
              input,
              false,
              false
            );
            this.session.emit('request_render');
          }
          break;

        case 'KEY_INTERRUPT':
          if (this.session && this.session.socket) {
            this.session.socket.end(I18n.t('TUI_SESSION_CLOSED'));
          } else {
            this.socket.end();
          }
          break;
      }
    }
  }

  cleanup() {
    for (const timer of this.activeTimeouts) {
      clearTimeout(timer);
    }
    this.activeTimeouts.clear();

    if (this.authenticatedUser && this.session) {
      const exitingUser = this.authenticatedUser;
      const session = this.session;
      this.session = null;
      this.authenticatedUser = null;
      try {
        this.db.updateUserProfile(exitingUser, session.contacts, session.history);
        this.clientServer.sessions.delete(exitingUser);
        this.clientServer.notifyAllSessionsRender();
        this.clientServer.federation.broadcastUserOffline(exitingUser);
      } catch (err) {
        log.error(`SSH cleanup error: ${err.message}`);
      }
    }
  }
}

export class SshServer {
  constructor(db, clientServer, options = {}) {
    this.db = db;
    this.clientServer = clientServer;
    this.options = options;
    this.server = null;

    const identity = this.db.getNodeIdentity();
    const ed25519Priv = crypto.createPrivateKey(identity.identityKeyPair.privateKey);
    const ed25519Pub = crypto.createPublicKey(identity.identityKeyPair.publicKey);
    const rawEd25519Pub = ed25519Pub.export({ type: 'spki', format: 'der' }).subarray(-32);

    this.hostKey = {
      privateKey: ed25519Priv,
      publicKey: ed25519Pub,
      rawEd25519Pub
    };
  }

  start(port) {
    this.server = net.createServer((socket) => {
      new SshClientConnection(socket, this.hostKey, this.db, this.clientServer, this.options);
    });

    this.server.listen(port, () => {
      log.info(I18n.t('SSH_SRV_LISTENING', { port }));
    });
  }

  close() {
    if (this.server) {
      try { this.server.close(); } catch {}
    }
  }
}