import { Logger } from '../utils/logger.js';
import { SshPacketReader, SshPacketWriter } from '../utils/sshPacket.js';
import { CryptoHelper } from '../utils/cryptoHelper.js';
import { AddressHelper } from '../utils/addressHelper.js';
import { I18n } from '../locales/i18n.js';
import { SSH_MSG } from './sshClientConnection.js';

const log = new Logger('SSH_AUTH');

export class SshAuthHandler {
  static async handleUserAuth(conn, reader, _rawPayload) {
    try {
      const username = reader.readString();
      reader.readString(); // service
      const method = reader.readString();

      if (!AddressHelper.isValidUsername(username)) {
        log.warn(I18n.t('SSH_INVALID_USERNAME_FORMAT', { username }));
        const w = new SshPacketWriter();
        w.writeByte(SSH_MSG.USERAUTH_FAILURE);
        w.writeNameList(['publickey', 'password']);
        w.writeBoolean(false);
        conn.sendPacket(w.toBuffer());
        return;
      }

      const formattedAddr = AddressHelper.formatUser(username);

      if (method === 'none') {
        const w = new SshPacketWriter();
        w.writeByte(SSH_MSG.USERAUTH_FAILURE);
        w.writeNameList(['publickey', 'password']);
        w.writeBoolean(false);
        conn.sendPacket(w.toBuffer());
        return;
      }

      if (method === 'publickey') {
        reader.readBoolean(); // hasSig
        const algo = reader.readString();
        const pubKeyBlob = reader.readBuffer();

        if (algo === 'ssh-ed25519') {
          try {
            const edKeyReader = new SshPacketReader(pubKeyBlob);
            edKeyReader.readString();
            conn.offeredClientPub = edKeyReader.readBuffer();
          } catch (err) {
            log.warn(I18n.t('SSH_PUBKEY_READ_ERROR', { error: err.message }));
          }
        }

        const w = new SshPacketWriter();
        w.writeByte(SSH_MSG.USERAUTH_FAILURE);
        w.writeNameList(['password']);
        w.writeBoolean(false);
        conn.sendPacket(w.toBuffer());
        return;
      }

      if (method === 'password') {
        reader.readBoolean();
        const password = reader.readString();

        const profile = conn.db.getUserProfile(formattedAddr);
        let authOk = false;
        let candidateSeed = null;

        const registeredKeys = profile.publicKeys && profile.publicKeys.length > 0
          ? profile.publicKeys
          : (profile.publicKey ? [profile.publicKey] : []);

        if (registeredKeys.length > 0) {
          if (!conn.offeredClientPub) {
            log.warn(I18n.t('SSH_UNREGISTERED_PUBKEY_WARN', { user: formattedAddr }));
            const w = new SshPacketWriter();
            w.writeByte(SSH_MSG.USERAUTH_FAILURE);
            w.writeNameList(['publickey']);
            w.writeBoolean(false);
            conn.sendPacket(w.toBuffer());
            return;
          }
          const offeredBase64 = conn.offeredClientPub.toString('base64');
          if (!registeredKeys.includes(offeredBase64)) {
            log.warn(I18n.t('SSH_UNREGISTERED_PUBKEY_WARN', { user: formattedAddr }));
            const w = new SshPacketWriter();
            w.writeByte(SSH_MSG.USERAUTH_FAILURE);
            w.writeNameList(['publickey']);
            w.writeBoolean(false);
            conn.sendPacket(w.toBuffer());
            return;
          }
        }

        // Hesaba eklenen 2. ve 3. anahtarlar da kasayi acabilsin diye
        // Kasa tohumu ilk kayitli anahtar (kok acik anahtar) uzerinden turetilir:
        let saltPub = registeredKeys.length > 0 
          ? Buffer.from(registeredKeys[0], 'base64') 
          : conn.offeredClientPub;

        if (!saltPub) {
          saltPub = Buffer.from(`salt:${conn.clientServer.federation.nodeAddress}`);
        }

        try {
          candidateSeed = CryptoHelper.deriveVaultSeed(
            password,
            saltPub,
            conn.clientServer.federation.nodeAddress
          );
        } catch (seedErr) {
          log.error(I18n.t('SSH_VAULT_SEED_ERROR', { error: seedErr.message }));
          const w = new SshPacketWriter();
          w.writeByte(SSH_MSG.USERAUTH_FAILURE);
          w.writeNameList(['password']);
          w.writeBoolean(false);
          conn.sendPacket(w.toBuffer());
          return;
        }

        if (!profile.passwordHash) {
          const authToken = CryptoHelper.createVaultAuthToken(candidateSeed);
          const tokenSerialized = JSON.stringify(authToken);
          conn.db.updateUserPassword(formattedAddr, tokenSerialized);
          profile.passwordHash = tokenSerialized;

          if (conn.offeredClientPub) {
            conn.db.addUserPublicKey(formattedAddr, conn.offeredClientPub.toString('base64'));
          }

          conn.derivedE2eeSeed = candidateSeed;
          authOk = true;
        } else {
          try {
            const tokenEncrypted = JSON.parse(profile.passwordHash);
            if (CryptoHelper.verifyVaultAuthToken(tokenEncrypted, candidateSeed)) {
              conn.derivedE2eeSeed = candidateSeed;
              authOk = true;
            }
          } catch {
            authOk = false;
          }
        }

        if (authOk) {
          conn.authenticatedUser = formattedAddr;
          const w = new SshPacketWriter();
          w.writeByte(SSH_MSG.USERAUTH_SUCCESS);
          conn.sendPacket(w.toBuffer());
          log.info(I18n.t('SSH_AUTH_SUCCESS', { user: conn.authenticatedUser }));
        } else {
          const w = new SshPacketWriter();
          w.writeByte(SSH_MSG.USERAUTH_FAILURE);
          w.writeNameList(['password']);
          w.writeBoolean(false);
          conn.sendPacket(w.toBuffer());
        }
      }
    } catch (err) {
      log.warn(I18n.t('SSH_AUTH_EXCEPTION', { error: err.message }));
      const w = new SshPacketWriter();
      w.writeByte(SSH_MSG.USERAUTH_FAILURE);
      w.writeNameList(['publickey', 'password']);
      w.writeBoolean(false);
      conn.sendPacket(w.toBuffer());
    }
  }
}
