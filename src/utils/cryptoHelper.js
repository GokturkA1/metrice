import crypto from 'node:crypto';

export class CryptoHelper {
  static AES_ALGO = 'aes-256-gcm';
  static IV_LENGTH = 12;
  static AUTH_TAG_LENGTH = 16;
  static KEM_ALGO = 'ml-kem-768';
  static HAS_ML_KEM = typeof crypto.encapsulate === 'function' && typeof crypto.decapsulate === 'function';

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

  // --- 2. DETERMINISTIC X25519 E2EE KEYPAIR (SIGN-TO-DERIVE) ---
  // 32-baytlık deterministik tohumdan doğrudan PKCS#8 DER ile X25519 anahtar çifti türetir
  static deriveDeterministicX25519(seed32) {
    // X25519 PKCS#8 ASN.1 DER Header: 302e020100300506032b656e04220420
    const pkcs8Header = Buffer.from('302e020100300506032b656e04220420', 'hex');
    const derPrivateKey = Buffer.concat([pkcs8Header, seed32]);

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

  // Kullanıcının Ed25519 SSH imzasından 32-bayt kök tohum türetir
  static deriveSeedFromSshSignature(signatureBytes, userAddress) {
    return crypto.hkdfSync(
      'sha256',
      signatureBytes,
      Buffer.from('NodeMesh-E2EE-Salt-v1'),
      Buffer.from(`nodemesh-e2ee-seed:${userAddress}`),
      32
    );
  }

  // SSH Parola ile girenler için deterministik tohum
  static deriveSeedFromPassword(password, userAddress) {
    return crypto.scryptSync(password, `salt:${userAddress}`, 32);
  }

  // --- 3. POST-QUANTUM KEM / X25519 KEM SARMALAMA ---
  static generateKemKeyPair() {
    if (this.HAS_ML_KEM) {
      return crypto.generateKeyPairSync(this.KEM_ALGO, {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
    }

    return crypto.generateKeyPairSync('x25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
  }

  static encapsulateKey(remotePublicKeyPem) {
    const pubKey = crypto.createPublicKey(remotePublicKeyPem);

    // Anahtar X25519 mu yoksa ML-KEM mi?
    const isX25519 = pubKey.asymmetricKeyType === 'x25519';

    if (!isX25519 && this.HAS_ML_KEM) {
      const { sharedKey, ciphertext } = crypto.encapsulate(pubKey);
      return {
        sharedSecret: sharedKey,
        encapsulatedKey: ciphertext.toString('base64')
      };
    }

    // X25519 Diffie-Hellman Encapsulation
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

    // X25519 Diffie-Hellman Decapsulation
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

  // --- 5. PAROLA HASHLEME (SCRYPT) ---
  static async hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    return new Promise((resolve, reject) => {
      crypto.scrypt(password, salt, 64, (err, derivedKey) => {
        if (err) reject(err);
        resolve(`${salt}:${derivedKey.toString('hex')}`);
      });
    });
  }

  static async verifyPassword(password, storedHash) {
    const [salt, key] = storedHash.split(':');
    if (!salt || !key) return false;

    return new Promise((resolve) => {
      crypto.scrypt(password, salt, 64, (err, derivedKey) => {
        if (err) return resolve(false);
        const keyBuffer = Buffer.from(key, 'hex');
        const match = crypto.timingSafeEqual(keyBuffer, derivedKey);
        resolve(match);
      });
    });
  }

  static generateRandomKey(bytes = 32) {
    return crypto.randomBytes(bytes).toString('hex');
  }
}