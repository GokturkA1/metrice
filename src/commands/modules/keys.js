import { CryptoHelper } from '../../utils/cryptoHelper.js';
import { I18n } from '../../locales/i18n.js';

export default {
  name: 'keys',
  aliases: ['key', 'pubkey', 'authorized_keys'],
  description: I18n.t('CMD_KEYS_DESC'),
  usage: I18n.t('CMD_KEYS_USAGE'),
  execute({ args, session, db, userAddress }) {
    const sub = (args[0] || 'list').toLowerCase();
    const profile = db.getUserProfile(userAddress);
    const publicKeys = profile.publicKeys || [];

    // 1. LİSTELEME
    if (sub === 'list' || sub === 'ls') {
      session.addSystemLog(`\x1b[1;36m${I18n.t('CMD_KEYS_HEADER')}\x1b[0m`);
      if (publicKeys.length === 0) {
        session.addSystemLog(`\x1b[33m${I18n.t('CMD_KEYS_EMPTY')}\x1b[0m`);
        return;
      }

      publicKeys.forEach((kBase64, idx) => {
        const raw = Buffer.from(kBase64, 'base64');
        const fp = CryptoHelper.sign ? Buffer.from(raw).toString('hex').slice(0, 16) : '';
        const shortKey = `${kBase64.slice(0, 12)}...${kBase64.slice(-8)}`;
        session.addSystemLog(`\x1b[1;32m[${idx + 1}]\x1b[0m SHA256:${fp} | Base64: ${shortKey}`);
      });
      session.addSystemLog(`\x1b[90m${I18n.t('CMD_KEYS_ADD_PROMPT')}\x1b[0m`);
      return;
    }

    // 2. ANAHTAR EKLEME
    if (sub === 'add') {
      const keyInput = args.slice(1).join(' ').trim();
      if (!keyInput) {
        session.addSystemLog(I18n.t('CMD_KEYS_INPUT_REQUIRED'));
        return;
      }

      try {
        const validated = CryptoHelper.parseAndValidateOpenSshKey(keyInput);

        if (publicKeys.includes(validated.base64)) {
          session.addSystemLog(I18n.t('CMD_KEYS_ALREADY_EXISTS'));
          return;
        }

        db.addUserPublicKey(userAddress, validated.base64);
        session.addSystemLog(I18n.t('CMD_KEYS_ADDED_SUCCESS', { fingerprint: validated.fingerprint }));
      } catch (err) {
        session.addSystemLog(I18n.t('CMD_KEYS_REJECTED', { error: err.message }));
      }
      return;
    }

    // 3. ANAHTAR SİLME
    if (sub === 'del' || sub === 'rm' || sub === 'remove') {
      const target = args[1];
      if (!target) {
        session.addSystemLog(I18n.t('CMD_KEYS_DEL_INDEX_REQUIRED'));
        return;
      }

      if (publicKeys.length <= 1) {
        session.addSystemLog(I18n.t('CMD_KEYS_LAST_KEY_PROTECTION'));
        return;
      }

      const idx = parseInt(target, 10) - 1;
      let targetKey = null;

      if (!isNaN(idx) && publicKeys[idx]) {
        targetKey = publicKeys[idx];
      } else {
        targetKey = publicKeys.find((k) => k.includes(target));
      }

      if (!targetKey) {
        session.addSystemLog(I18n.t('CMD_KEYS_NOT_FOUND', { target }));
        return;
      }

      db.removeUserPublicKey(userAddress, targetKey);
      session.addSystemLog(I18n.t('CMD_KEYS_DELETED_SUCCESS'));
      return;
    }

    session.addSystemLog(I18n.t('CMD_KEYS_SYNTAX_HELP'));
  }
};