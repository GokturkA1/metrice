import crypto from 'node:crypto';
import { SshPacketWriter } from '../utils/sshPacket.js';
import { SSH_MSG } from './sshClientConnection.js';

export class SshKexHandler {
  static kemSpkiPrefix = null;

  static deriveKey(conn, char, length) {
    const charBuf = Buffer.from([char.charCodeAt(0)]);
    let kBuffer;

    if (conn.selectedKex === 'mlkem768x25519-sha256') {
      const lenPrefix = Buffer.alloc(4);
      lenPrefix.writeUInt32BE(conn.sharedSecret.length, 0);
      kBuffer = Buffer.concat([lenPrefix, conn.sharedSecret]);
    } else {
      let kMpint = conn.sharedSecret;
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
      .update(conn.exchangeHash)
      .update(charBuf)
      .update(conn.sessionIdentifier)
      .digest();

    while (key.length < length) {
      const next = crypto.createHash('sha256')
        .update(kBuffer)
        .update(conn.exchangeHash)
        .update(key)
        .digest();
      key = Buffer.concat([key, next]);
    }
    return key.subarray(0, length);
  }

  static prepareKeys(conn) {
    conn.cipherName = 'aes-128-ctr';
    conn.keyLen = 16;
    conn.ivLen = 16;

    conn.ivC2S = this.deriveKey(conn, 'A', conn.ivLen);
    conn.ivS2C = this.deriveKey(conn, 'B', conn.ivLen);
    conn.keyC2S = this.deriveKey(conn, 'C', conn.keyLen);
    conn.keyS2C = this.deriveKey(conn, 'D', conn.keyLen);
    conn.inHmacKey = this.deriveKey(conn, 'E', 32);
    conn.outHmacKey = this.deriveKey(conn, 'F', 32);

    conn.decryptCipher = crypto.createDecipheriv(conn.cipherName, conn.keyC2S, conn.ivC2S);
    conn.encryptCipher = crypto.createCipheriv(conn.cipherName, conn.keyS2C, conn.ivS2C);
  }

  static handleKexInitMessage(conn, reader) {
    const clientBlob = reader.readBuffer();

    let serverBlob = null;
    let sharedSecretK = null;

    if (conn.selectedKex === 'mlkem768x25519-sha256') {
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

      if (!SshKexHandler.kemSpkiPrefix) {
        const dummyKey = crypto.generateKeyPairSync('ml-kem-768');
        const dummyDer = dummyKey.publicKey.export({ type: 'spki', format: 'der' });
        SshKexHandler.kemSpkiPrefix = dummyDer.subarray(0, dummyDer.length - 1184);
      }

      const clientKemPubKeyObj = crypto.createPublicKey({
        key: Buffer.concat([SshKexHandler.kemSpkiPrefix, clientKemPubRaw]),
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

    conn.sharedSecret = sharedSecretK;

    const hostKeyBlob = new SshPacketWriter();
    hostKeyBlob.writeString('ssh-ed25519');
    hostKeyBlob.writeBuffer(conn.hostKey.rawEd25519Pub);
    const hostKeyBuffer = hostKeyBlob.toBuffer();

    const hashWriter = new SshPacketWriter();
    hashWriter.writeString(conn.clientVersion);
    hashWriter.writeString(conn.serverVersion);
    hashWriter.writeBuffer(conn.clientKexPayload);
    hashWriter.writeBuffer(conn.serverKexPayload);
    hashWriter.writeBuffer(hostKeyBuffer);
    hashWriter.writeBuffer(clientBlob);
    hashWriter.writeBuffer(serverBlob);

    if (conn.selectedKex === 'mlkem768x25519-sha256') {
      hashWriter.writeBuffer(conn.sharedSecret);
    } else {
      hashWriter.writeMpint(conn.sharedSecret);
    }

    conn.exchangeHash = crypto.createHash('sha256').update(hashWriter.toBuffer()).digest();
    if (!conn.sessionIdentifier) {
      conn.sessionIdentifier = conn.exchangeHash;
    }

    const sigRaw = crypto.sign(null, conn.exchangeHash, conn.hostKey.privateKey);
    const sigBlob = new SshPacketWriter();
    sigBlob.writeString('ssh-ed25519');
    sigBlob.writeBuffer(sigRaw);

    const reply = new SshPacketWriter();
    reply.writeByte(SSH_MSG.KEX_ECDH_REPLY);
    reply.writeBuffer(hostKeyBuffer);
    reply.writeBuffer(serverBlob);
    reply.writeBuffer(sigBlob.toBuffer());
    conn.sendPacket(reply.toBuffer());

    const newKeys = new SshPacketWriter();
    newKeys.writeByte(SSH_MSG.NEWKEYS);
    conn.sendPacket(newKeys.toBuffer());

    this.prepareKeys(conn);
    conn.isEncryptedOut = true;
  }
}
