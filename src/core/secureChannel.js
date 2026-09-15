import net from 'node:net';
import dns from 'node:dns/promises';
import EventEmitter from 'node:events';
import { CONFIG } from '../config/index.js';
import { Logger } from '../utils/logger.js';
import { AddressHelper } from '../utils/addressHelper.js';
import { CryptoHelper } from '../utils/cryptoHelper.js';
import { I18n } from '../locales/i18n.js';

const log = new Logger('FEDERATION');

// Nonce Replay Havuzu (Zaman damgasi tabanli TTL)
export class NonceTracker {
  constructor(ttlMs = 60000) {
    this.ttlMs = ttlMs;
    this.nonces = new Map(); // nonce -> { timestamp, ip }
  }

  track(nonce, remoteIp = '') {
    const now = Date.now();
    this.cleanup(now);
    
    // Loopback (localhost) testlerinde kendi kendine atilan paketlerin cakismasini onle
    const key = `${nonce}_${remoteIp}`;
    if (this.nonces.has(key)) {
      return false; 
    }
    this.nonces.set(key, now);
    return true;
  }

  cleanup(now) {
    for (const [key, ts] of this.nonces.entries()) {
      if (now - ts > this.ttlMs) {
        this.nonces.delete(key);
      } else {
        break;
      }
    }
  }
}

// Mesaj Tekillestirme icin TTL Onbellegi
export class MessageTtlCache {
  constructor(ttlMs = 120000) { // 2 dakika TTL
    this.ttlMs = ttlMs;
    this.cache = new Map(); // id -> timestamp
  }

  has(id) {
    const now = Date.now();
    const ts = this.cache.get(id);
    if (!ts) return false;
    if (now - ts > this.ttlMs) {
      this.cache.delete(id);
      return false;
    }
    return true;
  }

  add(id) {
    const now = Date.now();
    this.cleanup(now);
    this.cache.set(id, now);
  }

  cleanup(now) {
    if (this.cache.size > 2000) {
      for (const [id, ts] of this.cache.entries()) {
        if (now - ts > this.ttlMs) {
          this.cache.delete(id);
        } else {
          break;
        }
      }
    }
  }
}

export class SecureChannel extends EventEmitter {
  constructor(socket, isInitiator, myIdentity, db, nonceTracker) {
    super();
    this.setMaxListeners(100);
    if (socket && typeof socket.setMaxListeners === 'function') {
      socket.setMaxListeners(100);
    }
    this.socket = socket;
    this.isInitiator = isInitiator;
    this.myIdentity = myIdentity;
    this.db = db;
    this.nonceTracker = nonceTracker;

    this.isReady = false;
    this.sessionKey = null;
    this.peerNodeAddress = null;
    this.peerIdentityKey = null;
    this.peerKemKey = null;

    this.pendingQueue = [];
    this.buffer = '';
    this.lastPong = Date.now();

    this.initSocketHandlers();
    if (this.isInitiator) {
      this.sendHandshakeInit();
    }
  }

  async initSocketHandlers() {
    this.socket.on('data', async (chunk) => {
      // 0x09 PING / 0x0A PONG Keepalive (Section 3.2)
      if (chunk.length === 1) {
        if (chunk[0] === 0x09) {
          try { this.socket.write(Buffer.from([0x0A])); } catch {}
          return;
        }
        if (chunk[0] === 0x0A) {
          this.lastPong = Date.now();
          this.emit('pong');
          return;
        }
      }

      this.buffer += chunk.toString();
      const maxBuffer = (CONFIG && CONFIG.secureBufferLimit) || 65536;
      if (this.buffer.length > maxBuffer) {
        log.warn(I18n.t('FED_SECURE_CHANNEL_PARSE_ERR', { error: `Buffer overflow / DoS protection triggered (> ${maxBuffer} bytes without newline)` }));
        this.socket.destroy();
        return;
      }
      const lines = this.buffer.split('\n');
      this.buffer = lines.pop();

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        if (!trimmed.startsWith('{')) {
          this.socket.destroy();
          return;
        }
        try {
          const frame = JSON.parse(line);
          if (frame.type === 'DIALBACK_CONFIRM') {
            this.emit('dialback_confirm', frame);
            continue;
          }
          if (frame.type === 'ONION_CELL') {
            this.emit('onion_cell', frame);
            continue;
          }
          await this.handleFrame(frame);
        } catch (err) {
          log.warn(I18n.t('FED_SECURE_CHANNEL_PARSE_ERR', { error: err.message }));
        }
      }
    });

    this.socket.on('error', (err) => this.emit('error', err));
    this.socket.on('close', () => this.emit('close'));
  }

  sendHandshakeInit() {
    const nonce = CryptoHelper.generateRandomKey(16);

    const isRelay = (typeof this.myIdentity?.role === 'function' ? this.myIdentity.role() : this.myIdentity?.role) === 'RELAY' ||
                    (typeof this.myIdentity?.role === 'function' ? this.myIdentity.role() : this.myIdentity?.role) === 'CAP_RELAY';
    let canonicalAddress;
    if (isRelay && typeof this.myIdentity?.getRelayAnnounceAddress === 'function') {
      canonicalAddress = this.myIdentity.getRelayAnnounceAddress();
    } else {
      canonicalAddress = this.myIdentity?.nodeAddress || null;
    }

    const dataToSign = JSON.stringify({
      type: 'HANDSHAKE_INIT',
      nodeAddress: canonicalAddress,
      identityPublicKey: this.myIdentity.identityKeyPair.publicKey,
      kemPublicKey: this.myIdentity.kemKeyPair.publicKey,
      nonce
    });

    const sig = CryptoHelper.sign(dataToSign, this.myIdentity.identityKeyPair.privateKey);

    const payload = {
      type: 'HANDSHAKE_INIT',
      nodeAddress: canonicalAddress,
      identityPublicKey: this.myIdentity.identityKeyPair.publicKey,
      kemPublicKey: this.myIdentity.kemKeyPair.publicKey,
      nonce,
      sig
    };

    this.socket.write(JSON.stringify(payload) + '\n');
  }

  async handleFrame(frame) {
    // 1. HANDSHAKE_INIT
    if (frame.type === 'HANDSHAKE_INIT') {
      const remoteIp = this.socket.remoteAddress || '';
      if (!this.nonceTracker.track(frame.nonce, remoteIp)) {
        log.warn(I18n.t('FED_REPLAY_NONCE_DETECTED', { node: frame.nodeAddress }));
        this.socket.destroy();
        return;
      }

      if (!(await this.validatePeerIp(frame.nodeAddress, frame.identityPublicKey))) {
        log.warn(I18n.t('FED_IP_SPOOFING_DETECTED', { declared: frame.nodeAddress, remote: this.socket.remoteAddress }));
        this.socket.destroy();
        return;
      }

      const dataToVerify = JSON.stringify({
        type: 'HANDSHAKE_INIT',
        nodeAddress: frame.nodeAddress,
        identityPublicKey: frame.identityPublicKey,
        kemPublicKey: frame.kemPublicKey,
        nonce: frame.nonce
      });

      const isValid = CryptoHelper.verify(dataToVerify, frame.sig, frame.identityPublicKey);
      if (!isValid) {
        log.warn(I18n.t('FED_SECURE_HANDSHAKE_INIT_FAIL', { node: frame.nodeAddress }));
        this.socket.destroy();
        return;
      }

      this.peerNodeAddress = frame.nodeAddress;
      this.peerIdentityKey = frame.identityPublicKey;
      this.peerKemKey = frame.kemPublicKey;
      this.db.saveTrustedNodeKey(this.peerNodeAddress, this.peerIdentityKey, this.peerKemKey);

      const { sharedSecret, encapsulatedKey } = CryptoHelper.encapsulateKey(this.peerKemKey);
      this.sessionKey = CryptoHelper.deriveKey(sharedSecret, frame.nonce, 'p2p-mesh-transport-v1');

      // AutoNAT Reflected IP: socket fiziksel uzak adresi (Section 2.1)
      const rawRemote = this.socket.realRemoteAddress || this.socket.remoteAddress || '';
      const cleanRemote = rawRemote.replace('::ffff:', '');
      const remotePort = this.socket.realRemotePort || this.socket.remotePort;
      const observedAddress = `${cleanRemote}:${remotePort}`;

      const isRelay = (typeof this.myIdentity?.role === 'function' ? this.myIdentity.role() : this.myIdentity?.role) === 'RELAY' ||
                      (typeof this.myIdentity?.role === 'function' ? this.myIdentity.role() : this.myIdentity?.role) === 'CAP_RELAY';
      let canonicalReplyAddress;
      if (isRelay && typeof this.myIdentity?.getRelayAnnounceAddress === 'function') {
        canonicalReplyAddress = this.myIdentity.getRelayAnnounceAddress();
      } else {
        canonicalReplyAddress = this.myIdentity?.nodeAddress || null;
      }

      const replyDataToSign = JSON.stringify({
        type: 'HANDSHAKE_REPLY',
        nodeAddress: canonicalReplyAddress,
        identityPublicKey: this.myIdentity.identityKeyPair.publicKey,
        kemPublicKey: this.myIdentity.kemKeyPair.publicKey,
        encapsulatedKey,
        nonce: frame.nonce,
        observedAddress
      });

      const replySig = CryptoHelper.sign(replyDataToSign, this.myIdentity.identityKeyPair.privateKey);

      const replyPayload = {
        type: 'HANDSHAKE_REPLY',
        nodeAddress: canonicalReplyAddress,
        identityPublicKey: this.myIdentity.identityKeyPair.publicKey,
        kemPublicKey: this.myIdentity.kemKeyPair.publicKey,
        encapsulatedKey,
        nonce: frame.nonce,
        observedAddress,
        sig: replySig
      };

      this.socket.write(JSON.stringify(replyPayload) + '\n');
      this.markReady();
      return;
    }

    // 2. HANDSHAKE_REPLY
    if (frame.type === 'HANDSHAKE_REPLY') {
      const verifyObj = {
        type: 'HANDSHAKE_REPLY',
        nodeAddress: frame.nodeAddress,
        identityPublicKey: frame.identityPublicKey,
        kemPublicKey: frame.kemPublicKey,
        encapsulatedKey: frame.encapsulatedKey,
        nonce: frame.nonce
      };
      if (frame.observedAddress) {
        verifyObj.observedAddress = frame.observedAddress;
      }

      let isValid = CryptoHelper.verify(JSON.stringify(verifyObj), frame.sig, frame.identityPublicKey);
      if (!isValid && frame.observedAddress) {
        delete verifyObj.observedAddress;
        isValid = CryptoHelper.verify(JSON.stringify(verifyObj), frame.sig, frame.identityPublicKey);
      }

      if (!isValid) {
        log.warn(I18n.t('FED_SECURE_HANDSHAKE_REPLY_FAIL', { node: frame.nodeAddress }));
        this.socket.destroy();
        return;
      }

      this.peerNodeAddress = frame.nodeAddress;
      this.peerIdentityKey = frame.identityPublicKey;
      this.peerKemKey = frame.kemPublicKey;
      this.observedAddress = frame.observedAddress || null;
      this.db.saveTrustedNodeKey(this.peerNodeAddress, this.peerIdentityKey, this.peerKemKey);

      const sharedSecret = CryptoHelper.decapsulateKey(
        this.myIdentity.kemKeyPair.privateKey,
        frame.encapsulatedKey
      );

      this.sessionKey = CryptoHelper.deriveKey(sharedSecret, frame.nonce, 'p2p-mesh-transport-v1');
      if (this.observedAddress) {
        this.emit('observed_address', this.observedAddress, this.peerNodeAddress);
      }
      this.markReady();
      return;
    }

    // 3. ENCRYPTED_FRAME
    if (frame.type === 'ENCRYPTED_FRAME') {
      if (!this.isReady || !this.sessionKey) {
        log.warn(I18n.t('FED_SECURE_FRAME_NOT_READY'));
        return;
      }

      const decryptedRaw = CryptoHelper.decrypt(frame, this.sessionKey);
      if (!decryptedRaw) {
        log.warn(I18n.t('FED_SECURE_DECRYPT_FAIL', { peer: this.peerNodeAddress }));
        return;
      }

      try {
        const payload = JSON.parse(decryptedRaw);
        this.emit('payload', payload);
      } catch (err) {
        log.warn(I18n.t('FED_SECURE_DECRYPT_JSON_ERR', { error: err.message }));
      }
    }
  }

  async validatePeerIp(declaredNodeAddress, identityPublicKey = null) {
    if (!declaredNodeAddress) return false;
    const parsed = AddressHelper.parseTarget(declaredNodeAddress);
    if (!parsed) return false;

    let declaredHost = parsed.isMesh ? parsed.nodeId : parsed.host;
    if (!declaredHost) return false;

    const rawRemote = this.socket.realRemoteAddress || this.socket.remoteAddress || '';
    let cleanRemote = rawRemote.replace(/^::ffff:/, '');

    // IPv6 normalizasyonu (RFC 5952 kanonik format)
    if (net.isIPv6(declaredHost)) {
      declaredHost = AddressHelper.canonicalizeIPv6(declaredHost);
    }
    if (net.isIPv6(cleanRemote)) {
      cleanRemote = AddressHelper.canonicalizeIPv6(cleanRemote);
    }

    const cleanDeclared = declaredHost.replace(/\.mesh$/, '').toLowerCase();

    // 1. Kriptografik kimlik (.mesh veya 16-karakter NodeID) dogrulamasi
    if (identityPublicKey) {
      const derivedId = CryptoHelper.deriveNodeId(identityPublicKey).toLowerCase();
      if (cleanDeclared === derivedId) {
        return true;
      }
      if (declaredHost.endsWith('.mesh') || AddressHelper.isValidNodeId(declaredHost)) {
        // Beyan edilen .mesh / NodeID kimligi el sikismadaki acik anahtarla uyusmuyorsa sahteciliktir (Spoofing)
        return false;
      }
    } else {
      if (declaredHost.endsWith('.mesh') || AddressHelper.isValidNodeId(declaredHost)) {
        return true;
      }
    }

    // 2. NAT / Ev Kullanicisi / Edge toleransi (localhost veya dongusel adreste calisan istemciler)
    const isLoopback = (ip) => ip === '127.0.0.1' || ip === '::1' || ip === 'localhost';
    if (isLoopback(declaredHost)) {
      return true;
    }

    // 3. Kendi sunucu adi toleransi
    if (declaredHost === CONFIG.serverName) {
      return true;
    }

    // 4. Ozel aglar / Container / Proxy toleransi
    const isPrivateOrCgnatSubnet = (ip) => {
      return /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.)/.test(ip);
    };
    if (isPrivateOrCgnatSubnet(cleanRemote)) {
      return true;
    }

    if (process.env.TRUST_PROXY === 'true' || process.env.DOCKER === 'true' || process.env.CONTAINER === 'true') {
      return true;
    }

    // 5. Dogrudan IP eslesmesi
    if (declaredHost === cleanRemote) {
      return true;
    }

    // 6. DNS Cozumleme (Domain -> IP Eslesmesi - VDS & Alan Adi Arkasi)
    try {
      const resolved = await dns.lookup(declaredHost, { all: true });
      return resolved.some((entry) => {
        const entryAddr = net.isIPv6(entry.address) ? AddressHelper.canonicalizeIPv6(entry.address) : entry.address;
        return entryAddr === cleanRemote;
      });
    } catch {
      // DNS cozulemediginde rastgele domainler uzerinden IP spoofing baypasini engelle.
      // Yalnizca Ed25519 el sikismasinda acikca dogrulanmis dugum kimligi ile eslestigi takdirde kabul et.
      if (identityPublicKey) {
        const derivedId = CryptoHelper.deriveNodeId(identityPublicKey).toLowerCase();
        if (cleanDeclared === derivedId) {
          return true;
        }
      }
      return false;
    }
  }

  markReady() {
    this.isReady = true;
    this.emit('ready');

    while (this.pendingQueue.length > 0) {
      const payload = this.pendingQueue.shift();
      this.writePayload(payload);
    }
  }

  writePayload(payload) {
    if (!this.isReady || !this.sessionKey) {
      this.pendingQueue.push(payload);
      return;
    }

    const plaintext = JSON.stringify(payload);
    const encrypted = CryptoHelper.encrypt(plaintext, this.sessionKey);

    const frame = {
      type: 'ENCRYPTED_FRAME',
      iv: encrypted.iv,
      ciphertext: encrypted.ciphertext,
      authTag: encrypted.authTag
    };

    this.socket.write(JSON.stringify(frame) + '\n');
  }
}
