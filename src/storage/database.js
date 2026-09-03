import { DatabaseSync } from 'node:sqlite';
import { Logger } from '../utils/logger.js';
import { I18n } from '../locales/i18n.js';
import { CryptoHelper } from '../utils/cryptoHelper.js';

const log = new Logger('DATABASE');

export class Database {
  constructor(filepath) {
    this.filepath = filepath;
    this.db = null;
    this.init();
  }

  init() {
    try {
      this.db = new DatabaseSync(this.filepath);
      this.db.exec('PRAGMA journal_mode = WAL;');
      this.db.exec('PRAGMA synchronous = NORMAL;');

      this.db.exec(`
        CREATE TABLE IF NOT EXISTS messages (
          id TEXT PRIMARY KEY,
          sender TEXT NOT NULL,
          receiver TEXT NOT NULL,
          content TEXT NOT NULL,
          is_action INTEGER DEFAULT 0,
          is_snippet INTEGER DEFAULT 0,
          is_e2ee INTEGER DEFAULT 0,
          deleted_by TEXT DEFAULT '',
          timestamp TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_messages_conversation 
        ON messages(sender, receiver, timestamp);

        CREATE TABLE IF NOT EXISTS profiles (
          user_address TEXT PRIMARY KEY,
          contacts TEXT NOT NULL,
          history TEXT NOT NULL,
          password_hash TEXT DEFAULT '',
          public_key TEXT DEFAULT '',
          kem_public_key TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS node_identity (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          identity_private_key TEXT NOT NULL,
          identity_public_key TEXT NOT NULL,
          kem_private_key TEXT NOT NULL,
          kem_public_key TEXT NOT NULL,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS trusted_keys (
          node_address TEXT PRIMARY KEY,
          identity_public_key TEXT NOT NULL,
          kem_public_key TEXT NOT NULL,
          last_updated TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS outbox (
          id TEXT PRIMARY KEY,
          sender TEXT NOT NULL,
          receiver TEXT NOT NULL,
          content TEXT NOT NULL,
          is_action INTEGER DEFAULT 0,
          is_snippet INTEGER DEFAULT 0,
          is_e2ee INTEGER DEFAULT 0,
          retries INTEGER DEFAULT 0,
          next_retry INTEGER NOT NULL,
          timestamp TEXT NOT NULL
        );
      `);

      try {
        const tableInfo = this.db.prepare('PRAGMA table_info(messages)').all();
        if (!tableInfo.some((col) => col.name === 'deleted_by')) {
          this.db.exec("ALTER TABLE messages ADD COLUMN deleted_by TEXT DEFAULT '';");
        }
        if (!tableInfo.some((col) => col.name === 'is_e2ee')) {
          this.db.exec("ALTER TABLE messages ADD COLUMN is_e2ee INTEGER DEFAULT 0;");
        }

        const profileInfo = this.db.prepare('PRAGMA table_info(profiles)').all();
        if (!profileInfo.some((col) => col.name === 'kem_public_key')) {
          this.db.exec("ALTER TABLE profiles ADD COLUMN kem_public_key TEXT DEFAULT '';");
        }
        if (!profileInfo.some((col) => col.name === 'allow_telnet')) {
          this.db.exec("ALTER TABLE profiles ADD COLUMN allow_telnet INTEGER DEFAULT 0;");
        }

        if (!profileInfo.some((col) => col.name === 'public_keys')) {
          this.db.exec("ALTER TABLE profiles ADD COLUMN public_keys TEXT DEFAULT '[]';");
          this.db.exec(`
            UPDATE profiles 
            SET public_keys = json_array(public_key) 
            WHERE public_key IS NOT NULL AND public_key != '' AND public_keys = '[]';
          `);
        }

        // ML-DSA-44 Düğüm Kimliği Sütunları
        const identityInfo = this.db.prepare('PRAGMA table_info(node_identity)').all();
        if (!identityInfo.some((col) => col.name === 'mldsa_private_key')) {
          this.db.exec("ALTER TABLE node_identity ADD COLUMN mldsa_private_key TEXT DEFAULT '';");
        }
        if (!identityInfo.some((col) => col.name === 'mldsa_public_key')) {
          this.db.exec("ALTER TABLE node_identity ADD COLUMN mldsa_public_key TEXT DEFAULT '';");
        }
      } catch (migErr) {
        log.warn(I18n.t('DB_MIGRATION_WARN', { error: migErr.message }));
      }

      log.info(I18n.t('DB_LOADED', { path: this.filepath }));
    } catch (err) {
      log.error(I18n.t('DB_CORRUPT_RESET', { error: err.message }));
      throw err;
    }
  }

  getNodeIdentity() {
    const stmt = this.db.prepare('SELECT * FROM node_identity WHERE id = 1');
    const row = stmt.get();

    if (row) {
      return {
        identityKeyPair: {
          privateKey: row.identity_private_key,
          publicKey: row.identity_public_key
        },
        kemKeyPair: {
          privateKey: row.kem_private_key,
          publicKey: row.kem_public_key
        }
      };
    }

    log.info(I18n.t('DB_GEN_IDENTITY_KEYS'));
    const identityKeyPair = CryptoHelper.generateIdentityKeyPair();
    const kemKeyPair = CryptoHelper.generateKemKeyPair();

    const insertStmt = this.db.prepare(`
      INSERT INTO node_identity (id, identity_private_key, identity_public_key, kem_private_key, kem_public_key, created_at)
      VALUES (1, ?, ?, ?, ?, ?)
    `);

    insertStmt.run(
      identityKeyPair.privateKey,
      identityKeyPair.publicKey,
      kemKeyPair.privateKey,
      kemKeyPair.publicKey,
      new Date().toISOString()
    );

    return { identityKeyPair, kemKeyPair };
  }

  saveTrustedNodeKey(nodeAddress, identityPublicKey, kemPublicKey) {
    const stmt = this.db.prepare(`
      INSERT INTO trusted_keys (node_address, identity_public_key, kem_public_key, last_updated)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(node_address) DO UPDATE SET
        identity_public_key = excluded.identity_public_key,
        kem_public_key = excluded.kem_public_key,
        last_updated = excluded.last_updated
    `);
    stmt.run(nodeAddress, identityPublicKey, kemPublicKey, new Date().toISOString());
  }

  getTrustedNodeKey(nodeAddress) {
    const stmt = this.db.prepare('SELECT identity_public_key, kem_public_key FROM trusted_keys WHERE node_address = ?');
    return stmt.get(nodeAddress);
  }

  close() {
    try {
      if (this.db) {
        this.db.exec('PRAGMA wal_checkpoint(TRUNCATE);');
        this.db.close();
        log.info(I18n.t('DB_WAL_CLOSED'));
      }
    } catch (err) {
      log.error(I18n.t('DB_CLOSE_ERROR', { error: err.message }));
    }
  }

  getUserProfile(userAddress) {
    const stmt = this.db.prepare('SELECT contacts, history, password_hash, public_key, kem_public_key, allow_telnet, public_keys FROM profiles WHERE user_address = ?');
    const row = stmt.get(userAddress);

    const defaultChannel = I18n.t('DEFAULT_CHANNEL_NAME');
    const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');

    if (!row) {
      const defaultProfile = {
        contacts: [systemConsole, defaultChannel],
        history: [],
        passwordHash: '',
        publicKey: '',
        publicKeys: [],
        kemPublicKey: '',
        allowTelnet: false
      };
      this.updateUserProfile(userAddress, defaultProfile.contacts, defaultProfile.history);
      return defaultProfile;
    }

    let publicKeys = [];
    try {
      publicKeys = JSON.parse(row.public_keys || '[]');
    } catch {
      publicKeys = [];
    }
    if (publicKeys.length === 0 && row.public_key) {
      publicKeys.push(row.public_key);
    }

    try {
      return {
        contacts: JSON.parse(row.contacts),
        history: JSON.parse(row.history),
        passwordHash: row.password_hash || '',
        publicKey: row.public_key || '',
        publicKeys,
        kemPublicKey: row.kem_public_key || '',
        allowTelnet: row.allow_telnet === 1
      };
    } catch {
      return { contacts: [systemConsole, defaultChannel], history: [], passwordHash: '', publicKey: '', publicKeys: [], kemPublicKey: '', allowTelnet: false };
    }
  }

  addUserPublicKey(userAddress, base64Key) {
    const profile = this.getUserProfile(userAddress);
    const keys = new Set(profile.publicKeys || []);
    keys.add(base64Key);
    const updated = Array.from(keys);

    const stmt = this.db.prepare('UPDATE profiles SET public_keys = ?, public_key = ? WHERE user_address = ?');
    stmt.run(JSON.stringify(updated), updated[0] || '', userAddress);
  }

  removeUserPublicKey(userAddress, base64Key) {
    const profile = this.getUserProfile(userAddress);
    const updated = (profile.publicKeys || []).filter((k) => k !== base64Key);

    const stmt = this.db.prepare('UPDATE profiles SET public_keys = ?, public_key = ? WHERE user_address = ?');
    stmt.run(JSON.stringify(updated), updated[0] || '', userAddress);
    return updated.length < profile.publicKeys.length;
  }

  setUserTelnetAccess(userAddress, allow) {
    const stmt = this.db.prepare('UPDATE profiles SET allow_telnet = ? WHERE user_address = ?');
    stmt.run(allow ? 1 : 0, userAddress);
  }

  updateUserProfile(userAddress, contacts, history) {
    const stmt = this.db.prepare(`
      INSERT INTO profiles (user_address, contacts, history)
      VALUES (?, ?, ?)
      ON CONFLICT(user_address) DO UPDATE SET
        contacts = excluded.contacts,
        history = excluded.history
    `);

    const cleanContacts = Array.from(new Set(contacts));
    const cleanHistory = (history || []).slice(-50);

    stmt.run(userAddress, JSON.stringify(cleanContacts), JSON.stringify(cleanHistory));
  }

  saveMessage({ id, from, to, content, isAction = false, isSnippet = false, isE2EE = false, timestamp = new Date().toISOString() }) {
    const messageId = id || `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    
    try {
      const stmt = this.db.prepare(`
        INSERT OR IGNORE INTO messages (id, sender, receiver, content, is_action, is_snippet, is_e2ee, deleted_by, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, '', ?)
      `);

      const res = stmt.run(
        messageId,
        from,
        to,
        content,
        isAction ? 1 : 0,
        isSnippet ? 1 : 0,
        isE2EE ? 1 : 0,
        timestamp
      );

      if (res.changes === 0) return null;

      const record = {
        id: messageId,
        from,
        to,
        content,
        isAction: !!isAction,
        isSnippet: !!isSnippet,
        isE2EE: !!isE2EE,
        timestamp
      };

      log.debug(I18n.t('DB_MSG_SAVED'), { id: record.id, from, to, isE2EE });
      return record;
    } catch (err) {
      log.error(I18n.t('DB_WRITE_ERROR', { error: err.message }));
      return null;
    }
  }

  clearConversationForUser(userAddress, target) {
    if (target.startsWith('#')) {
      const stmt = this.db.prepare(`
        UPDATE messages 
        SET deleted_by = CASE 
          WHEN deleted_by = '' THEN ? 
          WHEN deleted_by NOT LIKE '%' || ? || '%' THEN deleted_by || ',' || ? 
          ELSE deleted_by 
        END
        WHERE receiver = ?
      `);
      stmt.run(userAddress, userAddress, userAddress, target);
    } else {
      const stmt = this.db.prepare(`
        UPDATE messages 
        SET deleted_by = CASE 
          WHEN deleted_by = '' THEN ? 
          WHEN deleted_by NOT LIKE '%' || ? || '%' THEN deleted_by || ',' || ? 
          ELSE deleted_by 
        END
        WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
      `);
      stmt.run(userAddress, userAddress, userAddress, userAddress, target, target, userAddress);
    }
  }

  queueOutbox({ id, from, to, content, isAction = false, isSnippet = false, isE2EE = false, timestamp = new Date().toISOString() }) {
    const outboxId = id || `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const nextRetry = Date.now() + 5000;

    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO outbox (id, sender, receiver, content, is_action, is_snippet, is_e2ee, retries, next_retry, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
    `);

    stmt.run(outboxId, from, to, content, isAction ? 1 : 0, isSnippet ? 1 : 0, isE2EE ? 1 : 0, nextRetry, timestamp);
  }

  getPendingOutbox() {
    const now = Date.now();
    const stmt = this.db.prepare('SELECT * FROM outbox WHERE next_retry <= ? LIMIT 50');
    const rows = stmt.all(now);

    return rows.map((r) => ({
      id: r.id,
      from: r.sender,
      to: r.receiver,
      content: r.content,
      isAction: r.is_action === 1,
      isSnippet: r.is_snippet === 1,
      isE2EE: r.is_e2ee === 1,
      retries: r.retries,
      nextRetry: r.next_retry,
      timestamp: r.timestamp
    }));
  }

  removeOutbox(id) {
    const stmt = this.db.prepare('DELETE FROM outbox WHERE id = ?');
    stmt.run(id);
  }

  updateOutboxRetry(id) {
    const selectStmt = this.db.prepare('SELECT retries FROM outbox WHERE id = ?');
    const row = selectStmt.get(id);

    if (row) {
      const nextRetries = row.retries + 1;
      const delay = Math.min(120000, 5000 * Math.pow(1.5, Math.min(nextRetries, 10)));
      const nextRetry = Date.now() + delay;

      const updateStmt = this.db.prepare('UPDATE outbox SET retries = ?, next_retry = ? WHERE id = ?');
      updateStmt.run(nextRetries, nextRetry, id);
    }
  }

  updateUserPassword(userAddress, passwordHash) {
    const stmt = this.db.prepare(`
      INSERT INTO profiles (user_address, contacts, history, password_hash, public_key, kem_public_key)
      VALUES (?, '[]', '[]', ?, '', '')
      ON CONFLICT(user_address) DO UPDATE SET
        password_hash = excluded.password_hash
    `);
    stmt.run(userAddress, passwordHash);
  }

  updateUserKemKey(userAddress, kemPublicKey) {
    const stmt = this.db.prepare(`
      UPDATE profiles SET kem_public_key = ? WHERE user_address = ?
    `);
    stmt.run(kemPublicKey, userAddress);
  }

  getConversation(targetA, targetB, limit = 100) {
    if (!targetB) return [];

    let rows = [];

    if (targetB.startsWith('#')) {
      const stmt = this.db.prepare(`
        SELECT * FROM (
          SELECT id, sender, receiver, content, is_action, is_snippet, is_e2ee, timestamp 
          FROM messages 
          WHERE receiver = ? AND (deleted_by NOT LIKE '%' || ? || '%')
          ORDER BY timestamp DESC 
          LIMIT ?
        ) ORDER BY timestamp ASC
      `);
      rows = stmt.all(targetB, targetA, limit);
    } else {
      const stmt = this.db.prepare(`
        SELECT * FROM (
          SELECT id, sender, receiver, content, is_action, is_snippet, is_e2ee, timestamp 
          FROM messages 
          WHERE ((sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?))
            AND (deleted_by NOT LIKE '%' || ? || '%')
          ORDER BY timestamp DESC 
          LIMIT ?
        ) ORDER BY timestamp ASC
      `);
      rows = stmt.all(targetA, targetB, targetB, targetA, targetA, limit);
    }

    return rows.map((r) => ({
      id: r.id,
      from: r.sender,
      to: r.receiver,
      content: r.content,
      isAction: r.is_action === 1,
      isSnippet: r.is_snippet === 1,
      isE2EE: r.is_e2ee === 1,
      timestamp: r.timestamp
    }));
  }
}