import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Logger } from '../utils/logger.js';
import { I18n } from '../locales/i18n.js';
import { CryptoHelper } from '../utils/cryptoHelper.js';
import { AddressHelper } from '../utils/addressHelper.js';
import { CONFIG } from '../config/index.js';
import { initSchema } from './schema.js';

export { initSchema };

const log = new Logger('DATABASE');

export class Database {
  constructor(filepath) {
    this.filepath = filepath;
    this.db = null;
    this.lockFile = null;
    this.hasLock = false;
    this._exitHandler = null;
    this._exitListenerAttached = false;
    this.init();
  }

  acquireLock() {
    if (!this.filepath || this.filepath === ':memory:') {
      return;
    }

    this.lockFile = path.resolve(`${this.filepath}.lock`);
    const lockPayload = JSON.stringify({
      pid: process.pid,
      createdAt: Date.now(),
      filepath: path.resolve(this.filepath)
    });

    try {
      fs.writeFileSync(this.lockFile, lockPayload, { flag: 'wx' });
      this.hasLock = true;
    } catch (err) {
      if (err.code === 'EEXIST') {
        let lockData = null;
        try {
          const content = fs.readFileSync(this.lockFile, 'utf8');
          lockData = JSON.parse(content);
        } catch {}

        const existingPid = lockData?.pid;
        let isRunning = false;

        if (typeof existingPid === 'number' && existingPid > 0) {
          try {
            process.kill(existingPid, 0);
            isRunning = true;
          } catch (e) {
            isRunning = e.code === 'EPERM';
          }
        }

        if (isRunning) {
          const errorMsg = I18n.t('DB_LOCKED_ERROR', { path: this.filepath, pid: existingPid });
          log.error(errorMsg);
          const lockErr = new Error(errorMsg);
          lockErr.code = 'SQLITE_BUSY_INSTANCE';
          throw lockErr;
        }

        log.warn(I18n.t('DB_STALE_LOCK_REMOVED', { path: this.lockFile, pid: existingPid || 'unknown' }));
        try {
          fs.unlinkSync(this.lockFile);
        } catch {}

        try {
          fs.writeFileSync(this.lockFile, lockPayload, { flag: 'wx' });
          this.hasLock = true;
        } catch (retryErr) {
          const errorMsg = I18n.t('DB_LOCKED_ERROR', { path: this.filepath, pid: 'race_condition' });
          log.error(errorMsg);
          const lockErr = new Error(errorMsg);
          lockErr.code = 'SQLITE_BUSY_INSTANCE';
          throw lockErr;
        }
      } else {
        throw err;
      }
    }

    if (this.hasLock && !this._exitListenerAttached) {
      this._exitHandler = () => {
        this.releaseLock();
      };
      process.once('exit', this._exitHandler);
      this._exitListenerAttached = true;
    }
  }

  releaseLock() {
    if (!this.hasLock || !this.lockFile) {
      return;
    }

    if (this._exitHandler) {
      process.removeListener('exit', this._exitHandler);
      this._exitHandler = null;
      this._exitListenerAttached = false;
    }

    try {
      if (fs.existsSync(this.lockFile)) {
        try {
          const content = fs.readFileSync(this.lockFile, 'utf8');
          const lockData = JSON.parse(content);
          if (lockData.pid === process.pid) {
            fs.unlinkSync(this.lockFile);
          }
        } catch {
          fs.unlinkSync(this.lockFile);
        }
      }
    } catch {}
    this.hasLock = false;
  }

  init() {
    try {
      if (this.filepath && this.filepath !== ':memory:') {
        const dir = path.dirname(this.filepath);
        if (dir && dir !== '.' && !fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        this.acquireLock();
      }
      this.db = new DatabaseSync(this.filepath);
      initSchema(this.db, this.filepath);
    } catch (err) {
      if (err.code === 'SQLITE_BUSY_INSTANCE') {
        throw err;
      }
      this.releaseLock();
      log.error(I18n.t('DB_CORRUPT_RESET', { error: err.message }));
      throw err;
    }
  }

  getNodeIdentity() {
    const stmt = this.db.prepare('SELECT * FROM node_identity WHERE id = 1');
    const row = stmt.get();

    if (row) {
      const identityKeyPair = {
        privateKey: row.identity_private_key,
        publicKey: row.identity_public_key
      };
      const kemKeyPair = {
        privateKey: row.kem_private_key,
        publicKey: row.kem_public_key
      };
      const nodeId = CryptoHelper.deriveNodeId(identityKeyPair.publicKey);
      return { nodeId, identityKeyPair, kemKeyPair };
    }

    log.info(I18n.t('DB_GEN_IDENTITY_KEYS'));
    const identityKeyPair = CryptoHelper.generateIdentityKeyPair();
    const kemKeyPair = CryptoHelper.generateKemKeyPair();
    const nodeId = CryptoHelper.deriveNodeId(identityKeyPair.publicKey);

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

    return { nodeId, identityKeyPair, kemKeyPair };
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

  saveRemoteUserKemKey(userAddress, kemPublicKey) {
    if (!userAddress || !kemPublicKey) return;
    const stmt = this.db.prepare(`
      INSERT INTO profiles (user_address, contacts, history, password_hash, public_key, kem_public_key)
      VALUES (?, '[]', '[]', '', '', ?)
      ON CONFLICT(user_address) DO UPDATE SET
        kem_public_key = excluded.kem_public_key
    `);
    stmt.run(userAddress, kemPublicKey);
  }

  close() {
    try {
      if (this.db) {
        try { this.db.exec('PRAGMA wal_checkpoint(PASSIVE);'); } catch {}
        this.db.close();
        this.db = null;
        log.info(I18n.t('DB_WAL_CLOSED'));
      }
    } catch (err) {
      log.error(I18n.t('DB_CLOSE_ERROR', { error: err.message }));
    } finally {
      this.releaseLock();
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
      const rawContacts = JSON.parse(row.contacts || '[]');
      const normalizedContacts = [];
      for (const c of rawContacts) {
        let norm = c;
        if (AddressHelper.isSystemConsole(c)) norm = systemConsole;
        else if (AddressHelper.isGlobalChannel(c)) norm = defaultChannel;
        if (!normalizedContacts.includes(norm)) {
          normalizedContacts.push(norm);
        }
      }
      if (!normalizedContacts.includes(systemConsole)) {
        normalizedContacts.unshift(systemConsole);
      }
      if (!normalizedContacts.includes(defaultChannel)) {
        normalizedContacts.splice(1, 0, defaultChannel);
      }
      return {
        contacts: normalizedContacts,
        history: JSON.parse(row.history || '[]'),
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

    const defaultChannel = I18n.t('DEFAULT_CHANNEL_NAME');
    const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');
    const normalizedContacts = [];
    for (const c of (contacts || [])) {
      let norm = c;
      if (AddressHelper.isSystemConsole(c)) norm = systemConsole;
      else if (AddressHelper.isGlobalChannel(c)) norm = defaultChannel;
      if (!normalizedContacts.includes(norm)) {
        normalizedContacts.push(norm);
      }
    }
    if (!normalizedContacts.includes(systemConsole)) {
      normalizedContacts.unshift(systemConsole);
    }
    if (!normalizedContacts.includes(defaultChannel)) {
      normalizedContacts.splice(1, 0, defaultChannel);
    }

    const cleanHistory = (history || []).slice(-50);

    stmt.run(userAddress, JSON.stringify(normalizedContacts), JSON.stringify(cleanHistory));
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
    const userPrefix = userAddress.split(':')[0];
    if (AddressHelper.isGlobalChannel(target)) {
      const stmt = this.db.prepare(`
        UPDATE messages 
        SET deleted_by = CASE 
          WHEN deleted_by = '' THEN ?1 
          WHEN deleted_by NOT LIKE '%' || ?1 || '%' AND deleted_by NOT LIKE '%' || ?2 || '%' THEN deleted_by || ',' || ?1 
          ELSE deleted_by 
        END
        WHERE receiver = '#genel' OR receiver = '#general' OR receiver = 'genel' OR receiver = 'general'
      `);
      stmt.run(userAddress, userPrefix);
    } else if (target.startsWith('#')) {
      const chanPrefix = target.split(':')[0];
      const stmt = this.db.prepare(`
        UPDATE messages 
        SET deleted_by = CASE 
          WHEN deleted_by = '' THEN ?1 
          WHEN deleted_by NOT LIKE '%' || ?1 || '%' AND deleted_by NOT LIKE '%' || ?2 || '%' THEN deleted_by || ',' || ?1 
          ELSE deleted_by 
        END
        WHERE receiver = ?3 OR receiver = ?4 OR receiver LIKE ?4 || ':%'
      `);
      stmt.run(userAddress, userPrefix, target, chanPrefix);
    } else {
      const targetPrefix = target.split(':')[0];
      const stmt = this.db.prepare(`
        UPDATE messages 
        SET deleted_by = CASE 
          WHEN deleted_by = '' THEN ?1 
          WHEN deleted_by NOT LIKE '%' || ?1 || '%' AND deleted_by NOT LIKE '%' || ?2 || '%' THEN deleted_by || ',' || ?1 
          ELSE deleted_by 
        END
        WHERE ((sender = ?1 OR sender = ?2 OR sender LIKE ?2 || ':%') AND (receiver = ?3 OR receiver = ?4 OR receiver LIKE ?4 || ':%'))
           OR ((sender = ?3 OR sender = ?4 OR sender LIKE ?4 || ':%') AND (receiver = ?1 OR receiver = ?2 OR receiver LIKE ?2 || ':%'))
      `);
      stmt.run(userAddress, userPrefix, target, targetPrefix);
    }
  }

  cleanExpiredOutbox(
    ttl = (CONFIG && CONFIG.outboxTtl) ? CONFIG.outboxTtl : 86400000,
    maxRetries = (CONFIG && CONFIG.outboxMaxRetries) ? CONFIG.outboxMaxRetries : 20
  ) {
    if (!this.db || (typeof this.db.open === 'boolean' && !this.db.open)) return 0;
    try {
      const now = Date.now();
      const cutoff = now - ttl;

      // 1. Azami yeniden deneme sayisini asan iletileri sil
      const retryStmt = this.db.prepare('DELETE FROM outbox WHERE retries >= ?');
      const retryInfo = retryStmt.run(maxRetries);

      // 2. TTL suresi dolan iletileri sil (created_at veya timestamp uzerinden)
      const cutoffIso = new Date(cutoff).toISOString();
      let ttlCleaned = 0;
      try {
        const ttlStmt = this.db.prepare(`
          DELETE FROM outbox 
          WHERE (created_at > 0 AND created_at < ?)
             OR (created_at <= 0 AND timestamp < ?)
        `);
        const ttlInfo = ttlStmt.run(cutoff, cutoffIso);
        ttlCleaned = ttlInfo?.changes || 0;
      } catch {
        const fallbackTtlStmt = this.db.prepare('DELETE FROM outbox WHERE timestamp < ?');
        const fallbackInfo = fallbackTtlStmt.run(cutoffIso);
        ttlCleaned = fallbackInfo?.changes || 0;
      }

      const totalCleaned = (retryInfo?.changes || 0) + ttlCleaned;
      if (totalCleaned > 0) {
        log.info(I18n.t('DB_OUTBOX_CLEANED', { count: totalCleaned }));
      }
      return totalCleaned;
    } catch (err) {
      log.error(I18n.t('DB_OUTBOX_CLEAN_ERR', { error: err.message }));
      return 0;
    }
  }

  queueOutbox({ id, from, to, content, isAction = false, isSnippet = false, isE2EE = false, timestamp = new Date().toISOString(), createdAt = Date.now() }) {
    const outboxId = id || `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const nextRetry = Date.now() + 5000;
    const created = typeof createdAt === 'number' && !isNaN(createdAt) && createdAt > 0 ? createdAt : Date.now();

    try {
      const stmt = this.db.prepare(`
        INSERT OR REPLACE INTO outbox (id, sender, receiver, content, is_action, is_snippet, is_e2ee, retries, next_retry, timestamp, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
      `);
      stmt.run(outboxId, from, to, content, isAction ? 1 : 0, isSnippet ? 1 : 0, isE2EE ? 1 : 0, nextRetry, String(timestamp), created);
    } catch {
      const fallbackStmt = this.db.prepare(`
        INSERT OR REPLACE INTO outbox (id, sender, receiver, content, is_action, is_snippet, is_e2ee, retries, next_retry, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
      `);
      fallbackStmt.run(outboxId, from, to, content, isAction ? 1 : 0, isSnippet ? 1 : 0, isE2EE ? 1 : 0, nextRetry, String(timestamp));
    }
  }

  getPendingOutbox(forceAll = false) {
    if (!this.db || (typeof this.db.open === 'boolean' && !this.db.open)) return [];
    try {
      const now = Date.now();
      if (!this._lastOutboxClean || now - this._lastOutboxClean >= 5000) {
        this._lastOutboxClean = now;
        if (typeof this.cleanExpiredOutbox === 'function') {
          try { this.cleanExpiredOutbox(); } catch {}
        }
      }

      const stmt = forceAll
        ? this.db.prepare('SELECT * FROM outbox LIMIT 50')
        : this.db.prepare('SELECT * FROM outbox WHERE next_retry <= ? LIMIT 50');
      const rows = forceAll ? stmt.all() : stmt.all(now);

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
        timestamp: r.timestamp,
        createdAt: r.created_at && r.created_at > 0
          ? r.created_at
          : (typeof r.timestamp === 'number' ? r.timestamp : (new Date(r.timestamp).getTime() || now))
      }));
    } catch {
      return [];
    }
  }

  removeOutbox(id) {
    const stmt = this.db.prepare('DELETE FROM outbox WHERE id = ?');
    stmt.run(id);
  }

  updateOutboxRetry(
    id,
    maxRetries = (CONFIG && CONFIG.outboxMaxRetries) ? CONFIG.outboxMaxRetries : 20,
    ttl = (CONFIG && CONFIG.outboxTtl) ? CONFIG.outboxTtl : 86400000
  ) {
    let row;
    try {
      const selectStmt = this.db.prepare('SELECT retries, timestamp, created_at FROM outbox WHERE id = ?');
      row = selectStmt.get(id);
    } catch {
      const fallbackStmt = this.db.prepare('SELECT retries FROM outbox WHERE id = ?');
      row = fallbackStmt.get(id);
    }

    if (row) {
      const nextRetries = (row.retries || 0) + 1;
      const now = Date.now();
      const createdAt = row.created_at && row.created_at > 0
        ? row.created_at
        : (typeof row.timestamp === 'number' ? row.timestamp : (new Date(row.timestamp).getTime() || now));
      const isExpired = (now - createdAt) > ttl;

      if (nextRetries >= maxRetries || isExpired) {
        log.warn(I18n.t('FED_OUTBOX_EXPIRED', { id, retries: nextRetries }));
        this.removeOutbox(id);
        return { expired: true, retries: nextRetries };
      }

      const delay = Math.min(120000, 5000 * Math.pow(1.5, Math.min(nextRetries, 10)));
      const nextRetry = now + delay;

      const updateStmt = this.db.prepare('UPDATE outbox SET retries = ?, next_retry = ? WHERE id = ?');
      updateStmt.run(nextRetries, nextRetry, id);
      return { expired: false, retries: nextRetries, nextRetry };
    }
    return null;
  }

  resetOutboxForTarget(target) {
    if (!target) return;
    const stmt = this.db.prepare(`
      UPDATE outbox SET next_retry = 0, retries = 0 
      WHERE receiver LIKE '%' || ? || '%'
    `);
    stmt.run(target);
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
    const userAPrefix = targetA.split(':')[0];

    if (AddressHelper.isGlobalChannel(targetB)) {
      const stmt = this.db.prepare(`
        SELECT * FROM (
          SELECT rowid, id, sender, receiver, content, is_action, is_snippet, is_e2ee, timestamp 
          FROM messages 
          WHERE (receiver = '#genel' OR receiver = '#general' OR receiver = 'genel' OR receiver = 'general')
            AND (deleted_by NOT LIKE '%' || ? || '%' AND deleted_by NOT LIKE '%' || ? || '%')
          ORDER BY rowid DESC 
          LIMIT ?
        ) ORDER BY rowid ASC
      `);
      rows = stmt.all(targetA, userAPrefix, limit);
    } else if (targetB.startsWith('#')) {
      const chanPrefix = targetB.split(':')[0];
      const stmt = this.db.prepare(`
        SELECT * FROM (
          SELECT rowid, id, sender, receiver, content, is_action, is_snippet, is_e2ee, timestamp 
          FROM messages 
          WHERE (receiver = ? OR receiver = ? OR receiver LIKE ? || ':%')
            AND (deleted_by NOT LIKE '%' || ? || '%' AND deleted_by NOT LIKE '%' || ? || '%')
          ORDER BY rowid DESC 
          LIMIT ?
        ) ORDER BY rowid ASC
      `);
      rows = stmt.all(targetB, chanPrefix, chanPrefix, targetA, userAPrefix, limit);
    } else {
      const userBPrefix = targetB.split(':')[0];
      const stmt = this.db.prepare(`
        SELECT * FROM (
          SELECT rowid, id, sender, receiver, content, is_action, is_snippet, is_e2ee, timestamp 
          FROM messages 
          WHERE (
            ((LOWER(sender) = LOWER(?) OR LOWER(sender) = LOWER(?) OR LOWER(sender) LIKE LOWER(?) || ':%') AND (LOWER(receiver) = LOWER(?) OR LOWER(receiver) = LOWER(?) OR LOWER(receiver) LIKE LOWER(?) || ':%'))
            OR
            ((LOWER(sender) = LOWER(?) OR LOWER(sender) = LOWER(?) OR LOWER(sender) LIKE LOWER(?) || ':%') AND (LOWER(receiver) = LOWER(?) OR LOWER(receiver) = LOWER(?) OR LOWER(receiver) LIKE LOWER(?) || ':%'))
          )
          AND (LOWER(deleted_by) NOT LIKE '%' || LOWER(?) || '%' AND LOWER(deleted_by) NOT LIKE '%' || LOWER(?) || '%')
          ORDER BY rowid DESC 
          LIMIT ?
        ) ORDER BY rowid ASC
      `);
      rows = stmt.all(
        targetA, userAPrefix, userAPrefix, targetB, userBPrefix, userBPrefix,
        targetB, userBPrefix, userBPrefix, targetA, userAPrefix, userAPrefix,
        targetA, userAPrefix, limit
      );
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

  // --- V2.0 ROUTING TABLE & RENDEZVOUS STORAGE ---

  upsertRoute({ nodeId, role, rendezvousNodes = [], kemPublicKey, identityPublicKey, lastSeen = Date.now() }) {
    if (!nodeId) return;
    const cleanIdKey = identityPublicKey || '';
    const cleanKemKey = kemPublicKey || '';
    const stmt = this.db.prepare(`
      INSERT INTO routing_table (node_id, role, rendezvous_nodes, kem_public_key, identity_public_key, last_seen)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(node_id) DO UPDATE SET
        role = excluded.role,
        rendezvous_nodes = excluded.rendezvous_nodes,
        kem_public_key = CASE WHEN excluded.kem_public_key != '' THEN excluded.kem_public_key ELSE routing_table.kem_public_key END,
        identity_public_key = CASE WHEN excluded.identity_public_key != '' THEN excluded.identity_public_key ELSE routing_table.identity_public_key END,
        last_seen = excluded.last_seen
    `);
    const nodesJson = typeof rendezvousNodes === 'string' ? rendezvousNodes : JSON.stringify(rendezvousNodes);
    stmt.run(nodeId, role, nodesJson, cleanKemKey, cleanIdKey, lastSeen);
  }

  getRoute(nodeId) {
    const stmt = this.db.prepare('SELECT * FROM routing_table WHERE node_id = ?');
    const row = stmt.get(nodeId);
    if (!row) return null;
    let rendezvousNodes = [];
    try { rendezvousNodes = JSON.parse(row.rendezvous_nodes); } catch {}
    return {
      nodeId: row.node_id,
      role: row.role,
      rendezvousNodes,
      kemPublicKey: row.kem_public_key,
      identityPublicKey: row.identity_public_key,
      lastSeen: row.last_seen
    };
  }

  getAllRoutes() {
    const stmt = this.db.prepare('SELECT * FROM routing_table ORDER BY last_seen DESC');
    const rows = stmt.all();
    return rows.map((row) => {
      let rendezvousNodes = [];
      try { rendezvousNodes = JSON.parse(row.rendezvous_nodes); } catch {}
      return {
        nodeId: row.node_id,
        role: row.role,
        rendezvousNodes,
        kemPublicKey: row.kem_public_key,
        identityPublicKey: row.identity_public_key,
        lastSeen: row.last_seen
      };
    });
  }

  deleteExpiredRoutes(ttlMs = 60000, relayTtlMs = ttlMs * 5) {
    const threshold = Date.now() - ttlMs;
    const relayThreshold = Date.now() - relayTtlMs;
    const stmt = this.db.prepare(`
      DELETE FROM routing_table 
      WHERE (role NOT IN ('RELAY', 'CAP_RELAY') AND last_seen < ?1)
         OR (role IN ('RELAY', 'CAP_RELAY') AND last_seen < ?2)
    `);
    stmt.run(threshold, relayThreshold);
  }

  // --- V2.0 ONION CIRCUITS STORAGE ---

  saveCircuit({ circuitId, prevHop = null, nextHop = null, symmetricKey, createdAt = Date.now() }) {
    const circuitKey = prevHop ? `${circuitId}_${prevHop}` : circuitId;
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO active_circuits (circuit_key, circuit_id, prev_hop, next_hop, symmetric_key, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(circuitKey, circuitId, prevHop, nextHop, symmetricKey, createdAt);
  }

  getCircuit(circuitId, prevHop = null) {
    if (prevHop) {
      const circuitKey = `${circuitId}_${prevHop}`;
      const stmt = this.db.prepare('SELECT * FROM active_circuits WHERE circuit_key = ?');
      const row = stmt.get(circuitKey);
      if (row) {
        return {
          circuitId: row.circuit_id,
          prevHop: row.prev_hop,
          nextHop: row.next_hop,
          symmetricKey: row.symmetric_key,
          createdAt: row.created_at
        };
      }
    }
    const stmt = this.db.prepare('SELECT * FROM active_circuits WHERE circuit_id = ? ORDER BY created_at DESC LIMIT 1');
    const row = stmt.get(circuitId);
    if (!row) return null;
    return {
      circuitId: row.circuit_id,
      prevHop: row.prev_hop,
      nextHop: row.next_hop,
      symmetricKey: row.symmetric_key,
      createdAt: row.created_at
    };
  }

  deleteCircuit(circuitId, prevHop = null) {
    if (prevHop) {
      const circuitKey = `${circuitId}_${prevHop}`;
      const stmt = this.db.prepare('DELETE FROM active_circuits WHERE circuit_key = ?');
      stmt.run(circuitKey);
    } else {
      const stmt = this.db.prepare('DELETE FROM active_circuits WHERE circuit_id = ?');
      stmt.run(circuitId);
    }
  }

  deleteExpiredCircuits(maxAgeMs = 600000) {
    const cutoff = Date.now() - maxAgeMs;
    const stmt = this.db.prepare('DELETE FROM active_circuits WHERE created_at < ?');
    return stmt.run(cutoff);
  }
}