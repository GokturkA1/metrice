import { CONFIG } from './config/index.js';
import { Database } from './storage/database.js';
import { PeerManager } from './core/peerManager.js';
import { FederationEngine } from './core/federation.js';
import { ClientServer } from './core/clientServer.js';
import { SshServer } from './core/sshServer.js';
import { Logger } from './utils/logger.js';
import { ErrorHandler } from './utils/errorHandler.js';
import { I18n } from './locales/i18n.js';

ErrorHandler.initGlobalHandlers();

const log = new Logger('BOOTSTRAP');

log.info(I18n.t('BOOTSTRAP_BANNER'));
log.info(I18n.t('BOOTSTRAP_STARTING', { name: CONFIG.serverName }));
log.info(I18n.t('BOOTSTRAP_FED_PORT', { port: CONFIG.federationPort }));
log.info(I18n.t('BOOTSTRAP_CLIENT_PORT', { port: CONFIG.clientPort }));
log.info(I18n.t('BOOTSTRAP_LOG_LEVEL', { level: CONFIG.logLevel }));
log.info(I18n.t('BOOTSTRAP_BANNER'));

const db = new Database(CONFIG.dbFile);
const peerManager = new PeerManager(CONFIG.peerCacheFile);
const federation = new FederationEngine(db, peerManager);
const clientServer = new ClientServer(db, federation);
const sshServer = new SshServer(db, clientServer);

federation.start();
clientServer.start();
sshServer.start(CONFIG.sshPort);

// --- GRACEFUL SHUTDOWN (TEMİZ KAPANIŞ) ---
let isShuttingDown = false;
const shutdown = (signal) => {
  if (isShuttingDown) return;
  isShuttingDown = true;

  log.warn(`\n[${signal}] ${I18n.t('BOOTSTRAP_SHUTTING_DOWN')}`);

  try {
    clientServer.close();
    sshServer.close();
    federation.close();
    db.close();
    log.info('Temiz kapanış tamamlandı. Hoşça kalın!');
  } catch (err) {
    log.error(`Kapanış sırasında hata: ${err.message}`);
  } finally {
    process.exit(0);
  }
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));