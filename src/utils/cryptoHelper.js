import crypto from 'node:crypto';
import { I18n } from '../locales/i18n.js';

export class CryptoHelper {
  static AES_ALGO = 'aes-256-gcm';
  static IV_LENGTH = 12;
  static AUTH_TAG_LENGTH = 16;
  static KEM_ALGO = 'ml-kem-768';
  static HAS_ML_KEM = typeof crypto.encapsulate === 'function' && typeof crypto.decapsulate === 'function';

  static SENTINEL_TEXT = 'NODEMESH_VAULT_SENTINEL_V1';

  // --- KUANTUM GÜVENLİK KONTROLÜ ---
  static verifyQuantumSafePosture() {
    if (!this.HAS_ML_KEM) {
      console.error(I18n.t('CRYPTO_PQ_CRITICAL_BANNER'));

      if (process.env.STRICT_PQ === 'true') {
        console.error(`\x1b[31m${I18n.t('CRYPTO_STRICT_PQ_ABORT')}\x1b[0m`);
        process.exit(1);
      }
      return false;
    }
    return true;
  }

  // --- 1. ED25519 KİMLİK & İMZA YÖNETİMİ ---
  static generateIdentityKeyPair() {
    return crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
  }

  static sign(content, privateKeyPem) {
    const data = Buffer.from(typeof content === 'string' ? content : JSON.stringify(content));
    return crypto.sign(null, data, privateKeyPem).toString('base64');
  }

  static verify(content, signatureBase64, publicKeyPem) {
    try {
      const data = Buffer.from(typeof content === 'string' ? content : JSON.stringify(content));
      const sig = Buffer.from(signatureBase64, 'base64');
      return crypto.verify(null, data, publicKeyPem, sig);
    } catch {
      return false;
    }
  }

  // --- 2. TWO-FACTOR EPHEMERAL VAULT DERIVATION ---
  static deriveVaultSeed(passphrase, clientRawPub, nodeAddress) {
    if (!Buffer.isBuffer(clientRawPub) || clientRawPub.length < 32) {
      throw new Error(I18n.t('CRYPTO_INVALID_CLIENT_ED25519'));
    }

    const salt = clientRawPub.subarray(0, 32);

    const scryptKey = crypto.scryptSync(passphrase, salt, 32, {
      N: 16384,
      r: 8,
      p: 1,
      maxmem: 64 * 1024 * 1024
    });

    const rawArrayBuffer = crypto.hkdfSync(
      'sha256',
      scryptKey,
      Buffer.from(`nodemesh-vault-salt:${nodeAddress}`),
      Buffer.from('nodemesh-vault-seed-v2'),
      32
    );

    return Buffer.from(rawArrayBuffer);
  }

  static createVaultAuthToken(seedBuffer) {
    return this.encrypt(this.SENTINEL_TEXT, seedBuffer);
  }

  static verifyVaultAuthToken(tokenEncrypted, seedBuffer) {
    try {
      const decrypted = this.decrypt(tokenEncrypted, seedBuffer);
      return decrypted === this.SENTINEL_TEXT;
    } catch {
      return false;
    }
  }

  static deriveDeterministicX25519(seed32) {
    const seedBuf = Buffer.isBuffer(seed32) ? seed32 : Buffer.from(seed32);
    const pkcs8Header = Buffer.from('302e020100300506032b656e04220420', 'hex');
    const derPrivateKey = Buffer.concat([pkcs8Header, seedBuf]);

    const privateKey = crypto.createPrivateKey({
      key: derPrivateKey,
      format: 'der',
      type: 'pkcs8'
    });

    const publicKey = crypto.createPublicKey(privateKey);

    return {
      privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
      publicKey: publicKey.export({ type: 'spki', format: 'pem' })
    };
  }

  // --- 3. POST-QUANTUM KEM / X25519 KEM SARMALAMA ---
  static generateKemKeyPair() {
    if (this.HAS_ML_KEM) {
      return crypto.generateKeyPairSync(this.KEM_ALGO, {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
    }

    console.warn(`\x1b[33m${I18n.t('CRYPTO_FALLBACK_X25519_WARN')}\x1b[0m`);
    return crypto.generateKeyPairSync('x25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
  }

  static encapsulateKey(remotePublicKeyPem) {
    const pubKey = crypto.createPublicKey(remotePublicKeyPem);
    const isX25519 = pubKey.asymmetricKeyType === 'x25519';

    if (!isX25519 && this.HAS_ML_KEM) {
      const { sharedKey, ciphertext } = crypto.encapsulate(pubKey);
      return {
        sharedSecret: sharedKey,
        encapsulatedKey: ciphertext.toString('base64')
      };
    }

    const ephemeral = crypto.generateKeyPairSync('x25519');
    const secret = crypto.diffieHellman({ privateKey: ephemeral.privateKey, publicKey: pubKey });
    const ephemPubDer = ephemeral.publicKey.export({ type: 'spki', format: 'der' });
    return {
      sharedSecret: secret,
      encapsulatedKey: ephemPubDer.toString('base64')
    };
  }

  static decapsulateKey(privateKeyPem, encapsulatedKeyBase64) {
    const privKey = crypto.createPrivateKey(privateKeyPem);
    const encBuf = Buffer.from(encapsulatedKeyBase64, 'base64');

    if (privKey.asymmetricKeyType !== 'x25519' && this.HAS_ML_KEM) {
      return crypto.decapsulate(privKey, encBuf);
    }

    const remotePubKey = crypto.createPublicKey({ key: encBuf, format: 'der', type: 'spki' });
    return crypto.diffieHellman({ privateKey: privKey, publicKey: remotePubKey });
  }

  static deriveKey(sharedSecret, salt = 'mesh-default-salt', info = 'p2p-mesh-aes-key') {
    const saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt);
    return crypto.hkdfSync('sha256', sharedSecret, saltBuf, Buffer.from(info), 32);
  }

  // --- 4. SİMETRİK ŞİFRELEME (AES-256-GCM) ---
  static encrypt(plaintext, keyBuffer) {
    const iv = crypto.randomBytes(this.IV_LENGTH);
    const cipher = crypto.createCipheriv(this.AES_ALGO, keyBuffer, iv);

    const textBuffer = Buffer.from(plaintext, 'utf8');
    const encrypted = Buffer.concat([cipher.update(textBuffer), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      ciphertext: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64')
    };
  }

  static decrypt({ ciphertext, iv, authTag }, keyBuffer) {
    try {
      const decipher = crypto.createDecipheriv(
        this.AES_ALGO,
        keyBuffer,
        Buffer.from(iv, 'base64')
      );

      decipher.setAuthTag(Buffer.from(authTag, 'base64'));

      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(ciphertext, 'base64')),
        decipher.final()
      ]);

      return decrypted.toString('utf8');
    } catch {
      return null;
    }
  }

  // OpenSSH ssh-ed25519 formatını ayrıştırır ve test eder
  static parseAndValidateOpenSshKey(keyString) {
    if (!keyString || typeof keyString !== 'string') {
      throw new Error(I18n.t('CRYPTO_INVALID_KEY_FORMAT'));
    }

    const normalized = keyString.replace(/\r?\n|\r/g, ' ').trim();
    const parts = normalized.split(/\s+/);

    let base64Blob = '';
    if (parts[0] === 'ssh-ed25519' && parts[1]) {
      base64Blob = parts[1];
    } else if (parts[0].length > 40 && !parts[0].startsWith('ssh-')) {
      base64Blob = parts[0];
    } else {
      throw new Error(I18n.t('CRYPTO_ONLY_ED25519_SUPPORTED'));
    }

    const rawBuffer = Buffer.from(base64Blob, 'base64');
    if (rawBuffer.length < 32) {
      throw new Error(I18n.t('CRYPTO_KEY_TOO_SHORT'));
    }

    let rawEdPub = null;
    try {
      if (rawBuffer.includes(Buffer.from('ssh-ed25519'))) {
        const typeLen = rawBuffer.readUInt32BE(0);
        const keyOffset = 4 + typeLen;
        const keyLen = rawBuffer.readUInt32BE(keyOffset);
        rawEdPub = rawBuffer.subarray(keyOffset + 4, keyOffset + 4 + keyLen);
      } else if (rawBuffer.length === 32) {
        rawEdPub = rawBuffer;
      }
    } catch {
      throw new Error(I18n.t('CRYPTO_WIRE_FORMAT_ERROR'));
    }

    if (!rawEdPub || rawEdPub.length !== 32) {
      throw new Error(I18n.t('CRYPTO_ED25519_LENGTH_ERROR'));
    }

    try {
      const spkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
      const der = Buffer.concat([spkiHeader, rawEdPub]);
      const pubKeyObj = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });

      if (pubKeyObj.asymmetricKeyType !== 'ed25519') {
        throw new Error(I18n.t('CRYPTO_NOT_ED25519_TYPE'));
      }
    } catch (err) {
      throw new Error(I18n.t('CRYPTO_VERIFICATION_FAILED', { error: err.message }));
    }

    return {
      algo: 'ssh-ed25519',
      rawKey: rawEdPub,
      saltPart: rawEdPub,
      base64: rawEdPub.toString('base64'),
      fingerprint: crypto.createHash('sha256').update(rawEdPub).digest('base64').replace(/=+$/, '')
    };
  }

  static async hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    return new Promise((resolve, reject) => {
      crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (err, derivedKey) => {
        if (err) return reject(err);
        resolve(`${salt}:${derivedKey.toString('hex')}`);
      });
    });
  }

  // --- 5. PAROLA DOĞRULAMA (TELNET / FALLBACK) ---
  static async verifyPassword(password, storedHash, clientRawPub = null, nodeAddress = '') {
    if (!storedHash) return false;

    if (storedHash.includes(':') && !storedHash.startsWith('{')) {
      const [salt, key] = storedHash.split(':');
      if (!salt || !key) return false;

      return new Promise((resolve) => {
        crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (err, derivedKey) => {
          if (err) return resolve(false);
          const keyBuffer = Buffer.from(key, 'hex');
          const match = crypto.timingSafeEqual(keyBuffer, derivedKey);
          resolve(match);
        });
      });
    }

    if (storedHash.startsWith('{')) {
      try {
        let pubBuf = null;
        if (Buffer.isBuffer(clientRawPub)) {
          pubBuf = clientRawPub;
        } else if (typeof clientRawPub === 'string' && clientRawPub.length > 0) {
          pubBuf = Buffer.from(clientRawPub, 'base64');
        }

        if (!pubBuf || pubBuf.length < 32) return false;

        const candidateSeed = this.deriveVaultSeed(password, pubBuf, nodeAddress);
        const tokenEncrypted = JSON.parse(storedHash);
        return this.verifyVaultAuthToken(tokenEncrypted, candidateSeed);
      } catch {
        return false;
      }
    }

    return false;
  }

  static generateRandomKey(bytes = 32) {
    return crypto.randomBytes(bytes).toString('hex');
  }
}