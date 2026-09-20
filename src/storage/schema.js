import { Logger } from '../utils/logger.js';
import { I18n } from '../locales/i18n.js';
import { AddressHelper } from '../utils/addressHelper.js';

const log = new Logger('DATABASE');

export function initSchema(db, filepath) {
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA synchronous = NORMAL;');

  db.exec(`
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
      timestamp TEXT NOT NULL,
      created_at INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS routing_table (
      node_id TEXT PRIMARY KEY,
      role TEXT NOT NULL,
      rendezvous_nodes TEXT NOT NULL,
      kem_public_key TEXT NOT NULL,
      identity_public_key TEXT NOT NULL,
      last_seen INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS active_circuits (
      circuit_key TEXT PRIMARY KEY,
      circuit_id TEXT NOT NULL,
      prev_hop TEXT,
      next_hop TEXT,
      symmetric_key TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_circuits_cid ON active_circuits(circuit_id);
    CREATE INDEX IF NOT EXISTS idx_circuits_created ON active_circuits(created_at);
    CREATE INDEX IF NOT EXISTS idx_routing_seen ON routing_table(last_seen);
    CREATE INDEX IF NOT EXISTS idx_outbox_next_retry ON outbox(next_retry);
  `);

  try {
    const circuitTableInfo = db.prepare('PRAGMA table_info(active_circuits)').all();
    if (circuitTableInfo.length > 0 && !circuitTableInfo.some((c) => c.name === 'circuit_key')) {
      log.warn(I18n.t('DB_LEGACY_CIRCUITS_UPGRADED'));
      db.exec('DROP TABLE IF EXISTS active_circuits;');
      db.exec(`
        CREATE TABLE active_circuits (
          circuit_key TEXT PRIMARY KEY,
          circuit_id TEXT NOT NULL,
          prev_hop TEXT,
          next_hop TEXT,
          symmetric_key TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_circuits_cid ON active_circuits(circuit_id);
      `);
    }

    const tableInfo = db.prepare('PRAGMA table_info(messages)').all();
    if (!tableInfo.some((col) => col.name === 'deleted_by')) {
      db.exec("ALTER TABLE messages ADD COLUMN deleted_by TEXT DEFAULT '';");
    }
    if (!tableInfo.some((col) => col.name === 'is_e2ee')) {
      db.exec("ALTER TABLE messages ADD COLUMN is_e2ee INTEGER DEFAULT 0;");
    }

    const profileInfo = db.prepare('PRAGMA table_info(profiles)').all();
    if (!profileInfo.some((col) => col.name === 'kem_public_key')) {
      db.exec("ALTER TABLE profiles ADD COLUMN kem_public_key TEXT DEFAULT '';");
    }
    if (!profileInfo.some((col) => col.name === 'allow_telnet')) {
      db.exec("ALTER TABLE profiles ADD COLUMN allow_telnet INTEGER DEFAULT 0;");
    }

    if (!profileInfo.some((col) => col.name === 'public_keys')) {
      db.exec("ALTER TABLE profiles ADD COLUMN public_keys TEXT DEFAULT '[]';");
      db.exec(`
        UPDATE profiles 
        SET public_keys = json_array(public_key) 
        WHERE public_key IS NOT NULL AND public_key != '' AND public_keys = '[]';
      `);
    }

    const outboxInfo = db.prepare('PRAGMA table_info(outbox)').all();
    if (outboxInfo.length > 0 && !outboxInfo.some((col) => col.name === 'created_at')) {
      db.exec("ALTER TABLE outbox ADD COLUMN created_at INTEGER DEFAULT 0;");
      db.exec("UPDATE outbox SET created_at = CAST(strftime('%s', timestamp) AS INTEGER) * 1000 WHERE created_at = 0 AND timestamp LIKE '%-%';");
      db.exec("UPDATE outbox SET created_at = CAST(timestamp AS INTEGER) WHERE created_at = 0 AND timestamp NOT LIKE '%-%';");
      db.exec("UPDATE outbox SET created_at = strftime('%s', 'now') * 1000 WHERE created_at <= 0;");
    }
    db.exec("CREATE INDEX IF NOT EXISTS idx_outbox_retry ON outbox(next_retry, created_at);");

    // Profil kontaklarini mevcut locale dogrultusunda senkronize et
    try {
      const defaultChannel = I18n.t('DEFAULT_CHANNEL_NAME');
      const systemConsole = I18n.t('SYSTEM_CONSOLE_NAME');
      const allProfiles = db.prepare('SELECT user_address, contacts FROM profiles').all();
      const updateStmt = db.prepare('UPDATE profiles SET contacts = ? WHERE user_address = ?');
      for (const p of allProfiles) {
        if (!p.contacts) continue;
        let rawList = [];
        try { rawList = JSON.parse(p.contacts); } catch { continue; }
        const normList = [];
        for (const c of rawList) {
          let norm = c;
          if (AddressHelper.isSystemConsole(c)) norm = systemConsole;
          else if (AddressHelper.isGlobalChannel(c)) norm = defaultChannel;
          if (!normList.includes(norm)) normList.push(norm);
        }
        if (!normList.includes(systemConsole)) normList.unshift(systemConsole);
        if (!normList.includes(defaultChannel)) normList.splice(1, 0, defaultChannel);
        const newJson = JSON.stringify(normList);
        if (newJson !== p.contacts) {
          updateStmt.run(newJson, p.user_address);
        }
      }
    } catch {}
  } catch (migErr) {
    log.warn(I18n.t('DB_MIGRATION_WARN', { error: migErr.message }));
  }

  log.info(I18n.t('DB_LOADED', { path: filepath }));
}
