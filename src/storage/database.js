import { DatabaseSync } from 'node:sqlite';
import { Logger } from '../utils/logger.js';
import { I18n } from '../locales/i18n.js';

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
          deleted_by TEXT DEFAULT '',
          timestamp TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_messages_conversation 
        ON messages(sender, receiver, timestamp);

        CREATE TABLE IF NOT EXISTS profiles (
          user_address TEXT PRIMARY KEY,
          contacts TEXT NOT NULL,
          history TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS outbox (
          id TEXT PRIMARY KEY,
          sender TEXT NOT NULL,
          receiver TEXT NOT NULL,
          content TEXT NOT NULL,
          is_action INTEGER DEFAULT 0,
          is_snippet INTEGER DEFAULT 0,
          retries INTEGER DEFAULT 0,
          next_retry INTEGER NOT NULL,
          timestamp TEXT NOT NULL
        );
      `);

      // Şema Migrasyonu: Mevcut tablolarda deleted_by yoksa ekle
      try {
        const tableInfo = this.db.prepare('PRAGMA table_info(messages)').all();
        const hasDeletedBy = tableInfo.some((col) => col.name === 'deleted_by');
        if (!hasDeletedBy) {
          this.db.exec("ALTER TABLE messages ADD COLUMN deleted_by TEXT DEFAULT '';");
        }
      } catch (migErr) {
        log.warn(`Migrasyon uyarısı: ${migErr.message}`);
      }

      log.info(I18n.t('DB_LOADED', { path: this.filepath }));
    } catch (err) {
      log.error(I18n.t('DB_CORRUPT_RESET', { error: err.message }));
      throw err;
    }
  }

  close() {
    try {
      if (this.db) {
        this.db.exec('PRAGMA wal_checkpoint(TRUNCATE);');
        this.db.close();
        log.info('Veritabanı WAL temizlendi ve güvenle kapatıldı.');
      }
    } catch (err) {
      log.error(`Veritabanı kapatılırken hata: ${err.message}`);
    }
  }

  getUserProfile(userAddress) {
    const stmt = this.db.prepare('SELECT contacts, history FROM profiles WHERE user_address = ?');
    const row = stmt.get(userAddress);

    const defaultChannel = I18n.t('DEFAULT_CHANNEL_NAME');
    const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');

    if (!row) {
      const defaultProfile = {
        contacts: [systemConsole, defaultChannel],
        history: []
      };
      this.updateUserProfile(userAddress, defaultProfile.contacts, defaultProfile.history);
      return defaultProfile;
    }

    try {
      return {
        contacts: JSON.parse(row.contacts),
        history: JSON.parse(row.history)
      };
    } catch {
      return { contacts: [systemConsole, defaultChannel], history: [] };
    }
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

  saveMessage({ id, from, to, content, isAction = false, isSnippet = false, timestamp = new Date().toISOString() }) {
    const messageId = id || `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    
    try {
      const stmt = this.db.prepare(`
        INSERT OR IGNORE INTO messages (id, sender, receiver, content, is_action, is_snippet, deleted_by, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, '', ?)
      `);

      const res = stmt.run(
        messageId,
        from,
        to,
        content,
        isAction ? 1 : 0,
        isSnippet ? 1 : 0,
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
        timestamp
      };

      log.debug(I18n.t('DB_MSG_SAVED'), { id: record.id, from, to });
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

  queueOutbox({ id, from, to, content, isAction = false, isSnippet = false, timestamp = new Date().toISOString() }) {
    const outboxId = id || `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const nextRetry = Date.now() + 5000;

    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO outbox (id, sender, receiver, content, is_action, is_snippet, retries, next_retry, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
    `);

    stmt.run(outboxId, from, to, content, isAction ? 1 : 0, isSnippet ? 1 : 0, nextRetry, timestamp);
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

  getConversation(targetA, targetB, limit = 100) {
    if (!targetB) return [];

    let rows = [];

    if (targetB.startsWith('#')) {
      const stmt = this.db.prepare(`
        SELECT * FROM (
          SELECT id, sender, receiver, content, is_action, is_snippet, timestamp 
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
          SELECT id, sender, receiver, content, is_action, is_snippet, timestamp 
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
      timestamp: r.timestamp
    }));
  }
}