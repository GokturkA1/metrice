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
  constructor(socket, hostKey, db, clientServer) {
    super();
    this.socket = socket;
    this.hostKey = hostKey;
    this.db = db;
    this.clientServer = clientServer;

    this.state = 'IDENT';
    this.inBuffer = Buffer.alloc(0);
    this.clientVersion = '';
    this.serverVersion = 'SSH-2.0-NodeMesh_ZeroDep_1.0';

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

    this.derivedE2eeSeed = null;
    this.authenticatedUser = null;
    this.channelRemoteId = null;
    this.channelLocalId = 0;
    this.channelRemoteWindow = 0;
    this.channelRemoteMaxPacket = 32768;
    this.session = null;
    this.termWidth = 110;
    this.termHeight = 24;

    this.parser = new InputParser();
    this.initSocket();
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
      if (idx === -1) return;

      const rawLine = this.inBuffer.subarray(0, idx + 1).toString('utf8');
      this.inBuffer = this.inBuffer.subarray(idx + 1);
      this.clientVersion = rawLine.trim();

      log.debug(I18n.t('SSH_CLIENT_IDENTIFIED', { version: this.clientVersion }));
      this.state = 'KEX';
      this.sendKexInit();
    }

    while (this.inBuffer.length > 0) {
      if (!this.isEncryptedIn) {
        if (this.inBuffer.length < 5) return;
        const packetLength = this.inBuffer.readUInt32BE(0);
        const paddingLength = this.inBuffer.readUInt8(4);

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
            log.warn(`Geçersiz SSH paket boyutu: ${this.currentPacketLen}`);
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
    // 1. Post-Quantum mlkem768x25519-sha256 en başta, fallback olarak curve25519-sha256
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
        reader.offset += 16; // Cookie atla
        const clientKexList = reader.readNameList();
        if (clientKexList.includes('mlkem768x25519-sha256') && CryptoHelper.HAS_ML_KEM) {
          this.selectedKex = 'mlkem768x25519-sha256';
        } else {
          this.selectedKex = 'curve25519-sha256';
        }
        log.debug(`Müzakere Edilen SSH KEX: ${this.selectedKex}`);
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
        log.debug(`SSH Servis Talebi Alındı: ${service}`);
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
      // clientBlob: C_PK2 (ML-KEM-768 1184 bayt) || C_PK1 (X25519 32 bayt) = 1216 bayt
      const clientKemPubRaw = clientBlob.subarray(0, 1184);
      const clientX25519PubRaw = clientBlob.subarray(1184, 1216);

      // 1. Klasik X25519 ECDH
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

      // 2. Post-Quantum ML-KEM-768 Encapsulation
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

      // serverBlob: S_CT2 (1088 bayt) || S_PK1 (32 bayt) = 1120 bayt
      serverBlob = Buffer.concat([sCt2, serverX25519PubRaw]);

      // K = SHA256(K_PQ || K_CL) (draft-ietf-sshm-mlkem-hybrid-kex)
      sharedSecretK = crypto.createHash('sha256').update(kPq).update(kCl).digest();
    } else {
      // curve25519-sha256 Fallback
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

    // Exchange Hash (H) Hesaplama
    const hashWriter = new SshPacketWriter();
    hashWriter.writeString(this.clientVersion);
    hashWriter.writeString(this.serverVersion);
    hashWriter.writeBuffer(this.clientKexPayload);
    hashWriter.writeBuffer(this.serverKexPayload);
    hashWriter.writeBuffer(hostKeyBuffer);
    hashWriter.writeBuffer(clientBlob);
    hashWriter.writeBuffer(serverBlob);

    // draft-ietf-sshm-mlkem-hybrid-kex: K değeri mpint DEĞİL, ham string buffer olarak hash'e girer
    if (this.selectedKex === 'mlkem768x25519-sha256') {
      hashWriter.writeBuffer(this.sharedSecret);
    } else {
      hashWriter.writeMpint(this.sharedSecret);
    }

    this.exchangeHash = crypto.createHash('sha256').update(hashWriter.toBuffer()).digest();
    if (!this.sessionIdentifier) {
      this.sessionIdentifier = this.exchangeHash;
    }

    // Ed25519 ile H hash'inin imzalanması
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
      // Hibrit KEX'te K 32 bayt string olarak işlenir
      const lenPrefix = Buffer.alloc(4);
      lenPrefix.writeUInt32BE(this.sharedSecret.length, 0);
      kBuffer = Buffer.concat([lenPrefix, this.sharedSecret]);
    } else {
      // Klasik KEX mpint formatı
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

      const profile = this.db.getUserProfile(formattedAddr);

      if (!hasSig) {
        if (profile.publicKey && profile.publicKey === pubKeyBlob.toString('base64')) {
          const w = new SshPacketWriter();
          w.writeByte(SSH_MSG.USERAUTH_PK_OK);
          w.writeString(algo);
          w.writeBuffer(pubKeyBlob);
          this.sendPacket(w.toBuffer());
          return;
        }

        const w = new SshPacketWriter();
        w.writeByte(SSH_MSG.USERAUTH_FAILURE);
        w.writeNameList(['password']);
        w.writeBoolean(false);
        this.sendPacket(w.toBuffer());
        return;
      }

      const sigBlob = reader.readBuffer();
      const sigReader = new SshPacketReader(sigBlob);
      sigReader.readString();
      const sigRaw = sigReader.readBuffer();

      const signedData = Buffer.concat([
        this.sessionIdentifier,
        rawPayload.subarray(0, rawPayload.length - (4 + sigBlob.length))
      ]);

      let isValidSig = false;
      try {
        if (algo === 'ssh-ed25519') {
          const edKeyReader = new SshPacketReader(pubKeyBlob);
          edKeyReader.readString();
          const rawEdPub = edKeyReader.readBuffer();
          const spkiKey = Buffer.concat([
            Buffer.from('302a300506032b6570032100', 'hex'),
            rawEdPub
          ]);
          const pubKeyObj = crypto.createPublicKey({ key: spkiKey, format: 'der', type: 'spki' });
          isValidSig = crypto.verify(null, signedData, pubKeyObj, sigRaw);
        }
      } catch (err) {
        log.warn(`Public Key imza doğrulama hatası: ${err.message}`);
      }

      if (isValidSig) {
        this.authenticatedUser = formattedAddr;
        // SIGN-TO-DERIVE: İmzadan deterministik 32-bayt E2EE Seed türet
        this.derivedE2eeSeed = CryptoHelper.deriveSeedFromSshSignature(sigRaw, formattedAddr);

        const w = new SshPacketWriter();
        w.writeByte(SSH_MSG.USERAUTH_SUCCESS);
        this.sendPacket(w.toBuffer());
        log.info(`SSH Kullanıcı Public Key ile Giriş Yaptı: ${this.authenticatedUser}`);
        return;
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

      if (!profile.passwordHash) {
        const hash = await CryptoHelper.hashPassword(password);
        this.db.updateUserPassword(formattedAddr, hash);
        profile.passwordHash = hash;
        authOk = true;
      } else {
        authOk = await CryptoHelper.verifyPassword(password, profile.passwordHash);
      }

      if (authOk) {
        this.authenticatedUser = formattedAddr;
        // Parola ile bağlanan SSH oturumu için deterministik seed
        this.derivedE2eeSeed = CryptoHelper.deriveSeedFromPassword(password, formattedAddr);

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
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      const w = new SshPacketWriter();
      w.writeByte(SSH_MSG.CHANNEL_DATA);
      w.writeUInt32(this.channelRemoteId);
      w.writeBuffer(buf);
      this.sendPacket(w.toBuffer());
      return true;
    };
    virtualSocket.end = () => this.socket.end();
    virtualSocket.destroy = () => this.socket.destroy();

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
        return { uptime: `${mins}m`, rss: mem, peers: [] };
      },
      () => this.clientServer.commands.getAllUnique().map((c) => c.name)
    );

    // SIGN-TO-DERIVE ZERO-KNOWLEDGE E2EE
    this.session.isSsh = true;
    this.session.isSecureE2EE = true;

    if (this.derivedE2eeSeed) {
      // Deterministik X25519 E2EE Anahtar Çifti (Oturumlar arası kalıcı, diske yazılmaz)
      this.session.kemKeyPair = CryptoHelper.deriveDeterministicX25519(this.derivedE2eeSeed);
      // Diğer eşlerin bana mesaj atabilmesi için açık anahtarı veritabanına ve ağa duyur
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

  handleChannelInput(buffer) {
    if (!this.session) return;
    const actions = this.parser.parse(buffer);

    for (const action of actions) {
      if (action.type === 'RESIZE') {
        this.session.resize(action.width, action.height);
        continue;
      }

      if (action.type === 'PASTE_COMPLETE') {
        const pastedText = action.content;
        const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');
        if (pastedText && this.session.activeTarget && this.session.activeTarget !== systemConsole) {
          this.clientServer.handleOutboundMessage(this.session, this.authenticatedUser, this.session.activeTarget, pastedText, false, true);
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
            this.clientServer.commands.execute(input, {
              session: this.session,
              socket: this.session.socket,
              db: this.db,
              federation: this.clientServer.federation,
              clientServer: this.clientServer,
              registry: this.clientServer.commands,
              userAddress: this.authenticatedUser
            });
            this.session.emit('request_render');
            break;
          }

          const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');
          if (this.session.activeTarget === systemConsole) {
            this.session.addSystemLog(I18n.t('SYS_SYSTEM_WINDOW_NO_MSG'));
            break;
          }

          if (this.session.activeTarget) {
            this.clientServer.handleOutboundMessage(
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
          this.socket.end(I18n.t('TUI_SESSION_CLOSED'));
          break;
      }
    }
  }

  cleanup() {
    if (this.authenticatedUser && this.session) {
      this.db.updateUserProfile(this.authenticatedUser, this.session.contacts, this.session.history);
      this.clientServer.sessions.delete(this.authenticatedUser);
      this.clientServer.notifyAllSessionsRender();
      this.clientServer.federation.broadcastPresence();
    }
  }
}

export class SshServer {
  constructor(db, clientServer) {
    this.db = db;
    this.clientServer = clientServer;
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
      new SshClientConnection(socket, this.hostKey, this.db, this.clientServer);
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