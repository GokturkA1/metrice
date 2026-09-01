import { CONFIG } from './config/index.js';
import { Database } from './storage/database.js';
import { PeerManager } from './core/peerManager.js';
import { FederationEngine } from './core/federation.js';
import { ClientServer } from './core/clientServer.js';
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

federation.start();
clientServer.start();