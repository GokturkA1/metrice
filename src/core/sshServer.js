import net from 'node:net';
import crypto from 'node:crypto';
import { Logger } from '../utils/logger.js';
import { CONFIG } from '../config/index.js';
import { ProxyProtocolParser } from '../utils/proxyProtocol.js';
import { I18n } from '../locales/i18n.js';
import { SshClientConnection, SSH_MSG } from './sshClientConnection.js';

const log = new Logger('SSH_SRV');

export { SshClientConnection, SSH_MSG };

export class SshServer {
  constructor(db, clientServer, options = {}) {
    this.db = db;
    this.clientServer = clientServer;
    this.options = options;
    this.server = null;

    const identity = this.db.getNodeIdentity();
    const ed25519Priv = crypto.createPrivateKey(identity.identityKeyPair.privateKey);
    const ed25519Pub = crypto.createPublicKey(identity.identityKeyPair.publicKey);
    const rawEd25519Pub = ed25519Pub.export({ type: 'spki', format: 'der' }).subarray(-32);

    this.hostKey = {
      privateKey: ed25519Priv,
      publicKey: ed25519Pub,
      rawEd25519Pub
    };
  }

  start(port) {
    this.server = net.createServer((socket) => {
      const setupSsh = () => {
        new SshClientConnection(socket, this.hostKey, this.db, this.clientServer, this.options);
      };

      if (CONFIG.useProxyProtocol) {
        ProxyProtocolParser.handle(socket, { trustedIps: CONFIG.proxyProtocolTrustedIps }, (err) => {
          if (err) {
            log.warn(I18n.t('SSH_PROXY_HANDSHAKE_ERR', { error: err.message }));
            return;
          }
          setupSsh();
        });
      } else {
        setupSsh();
      }
    });

    this.server.listen(port, () => {
      log.info(I18n.t('SSH_SRV_LISTENING', { port }));
    });
  }

  close() {
    if (this.server) {
      try { this.server.close(); } catch {}
    }
  }
}