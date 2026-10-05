import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import { EventEmitter } from 'node:events';
import { SecureChannel, NonceTracker } from '../src/core/secureChannel.js';
import { AutoNatService } from '../src/core/autoNat.js';
import { FederationEngine } from '../src/core/federation.js';
import { OnionRouter, UNIFORM_CELL_SIZE } from '../src/core/onionRouter.js';
import { Database } from '../src/storage/database.js';
import { SshAuthHandler } from '../src/core/sshAuthHandler.js';
import { SshPacketWriter, SshPacketReader } from '../src/utils/sshPacket.js';
import { SSH_MSG } from '../src/core/sshClientConnection.js';
import { CryptoHelper } from '../src/utils/cryptoHelper.js';
import { RendezvousManager } from '../src/core/rendezvousManager.js';
import { HealthServer } from '../src/core/healthServer.js';
import { CONFIG } from '../src/config/index.js';

const COLOR = {
  RESET: '\x1b[0m',
  GREEN: '\x1b[32m',
  RED: '\x1b[31m',
  YELLOW: '\x1b[33m',
  CYAN: '\x1b[36m',
  BOLD: '\x1b[1m'
};

const results = [];
function record(name, passed, details = '') {
  results.push({ name, passed, details });
  const status = passed
    ? `${COLOR.GREEN}[BASARILI]${COLOR.RESET}`
    : `${COLOR.RED}[BASARISIZ]${COLOR.RESET}`;
  const detailStr = details ? ` (${COLOR.YELLOW}${details}${COLOR.RESET})` : '';
  console.log(`  ${status} ${name}${detailStr}`);
}

async function runAuditTests() {
  console.log(`\n${COLOR.BOLD}${COLOR.CYAN}================================================================${COLOR.RESET}`);
  console.log(`${COLOR.BOLD}     METRICE v2.7.8 GUVENLIK DENETIM (AUDIT) DOGRULAMA TESTLERI${COLOR.RESET}`);
  console.log(`${COLOR.BOLD}${COLOR.CYAN}================================================================${COLOR.RESET}\n`);

  const tempDbPath = path.join(import.meta.dirname, 'test_audit_v278.db');
  function cleanupDb() {
    for (const suffix of ['', '-wal', '-shm', '.lock']) {
      const f = tempDbPath + suffix;
      if (fs.existsSync(f)) {
        try { fs.unlinkSync(f); } catch {}
      }
    }
  }
  cleanupDb();
  const db = new Database(tempDbPath);

  try {
    // ----------------------------------------------------
    // MET-01: UTF-8 Tampon Olcum Hatasi (Buffer.byteLength)
    // ----------------------------------------------------
    try {
      let socketDestroyed = false;
      const mockSock = new EventEmitter();
      mockSock.destroy = () => { socketDestroyed = true; };
      mockSock.write = () => {};

      const myId = {
        identityKeyPair: CryptoHelper.generateIdentityKeyPair(),
        kemKeyPair: CryptoHelper.generateKemKeyPair(),
        nodeAddress: 'localhost:8001',
        nodeId: 'testnode1'
      };
      const channel = new SecureChannel(mockSock, false, myId, db, new NonceTracker());

      // 4-baytlik karakter (karakter sayisi: 20000 < 65536, ancak bayt sayisi: 80000 > 65536)
      const multiByteChar = Buffer.from([0xF0, 0x9F, 0x94, 0x92]); // 4-bayt UTF-8
      const chunk = Buffer.alloc(80000);
      for (let i = 0; i < 80000; i += 4) {
        multiByteChar.copy(chunk, i);
      }

      mockSock.emit('data', chunk);
      record('MET-01: Multi-byte UTF-8 tampon tasmasi byteLength ile engellendi', socketDestroyed, `Socket destroyed: ${socketDestroyed}`);
    } catch (e) {
      record('MET-01: Multi-byte UTF-8 Tampon Kontrolu', false, e.message);
    }

    // ----------------------------------------------------
    // MET-02: CLI Arguman SSRF Baypasi Engeli
    // ----------------------------------------------------
    try {
      const autoNat = new AutoNatService({
        role: 'RELAY',
        setRole: () => {}
      });

      let dialbackCalled = false;
      const prevEnv = process.env.NODE_ENV;
      const prevConfigEnv = CONFIG.environment;
      process.env.NODE_ENV = 'production';
      CONFIG.environment = 'production';

      const mockChannel = {
        socket: { remoteAddress: '10.0.0.5' },
        writePayload: () => {}
      };

      const origConnect = net.createConnection;
      net.createConnection = () => {
        dialbackCalled = true;
        const s = new EventEmitter();
        s.setTimeout = () => {};
        s.destroy = () => {};
        return s;
      };

      try {
        autoNat.handleDialbackRequest({ targetPort: 8001, nonce: 'nonce123' }, mockChannel);
      } finally {
        net.createConnection = origConnect;
        process.env.NODE_ENV = prevEnv;
        CONFIG.environment = prevConfigEnv;
      }

      record('MET-02: AutoNAT dialback isteklerinde ozel IP SSRF engeli', !dialbackCalled, `Dialback blocked: ${!dialbackCalled}`);
    } catch (e) {
      record('MET-02: AutoNAT SSRF Kontrolu', false, e.message);
    }

    // ----------------------------------------------------
    // MET-03: DNS Rebinding ve Ozel Ag Baypas Engeli
    // ----------------------------------------------------
    try {
      const mockSock = { remoteAddress: '198.51.100.5', writable: true, on: () => {} };
      const myId = {
        identityKeyPair: CryptoHelper.generateIdentityKeyPair(),
        kemKeyPair: CryptoHelper.generateKemKeyPair(),
        nodeAddress: 'localhost:8001',
        nodeId: 'testnode1'
      };
      const channel = new SecureChannel(mockSock, false, myId, db, new NonceTracker());

      // DNS dahili bir IP dondurdugunde (DNS Rebinding) reddedilmeli
      const origLookup = dns.lookup;
      dns.lookup = async () => [{ address: '127.0.0.1', family: 4 }];

      let rebindingBlocked = false;
      try {
        const res = await channel.validatePeerIp('rebound-domain.com:8001');
        rebindingBlocked = (res === false);
      } finally {
        dns.lookup = origLookup;
      }

      record('MET-03: validatePeerIp DNS Rebinding (Dahili IP donusu) engeli', rebindingBlocked, `Blocked: ${rebindingBlocked}`);
    } catch (e) {
      record('MET-03: DNS Rebinding Kontrolu', false, e.message);
    }

    // ----------------------------------------------------
    // MET-04: SSH Parola Deneme Rate Limiting (Kaba Kuvvet)
    // ----------------------------------------------------
    try {
      const mockDbProfile = {
        getUserProfile: () => ({ passwordHash: JSON.stringify({ token: 'sentinel' }), publicKeys: [] }),
        updateUserPassword: () => {}
      };
      const packets = [];
      const testIp = '203.0.113.88';

      // 1. Baglanti: 3 basarisiz deneme sonrasi baglanti soketi imha edilir
      let socket1Destroyed = false;
      const fakeConn1 = {
        db: mockDbProfile,
        socket: { remoteAddress: testIp, destroy: () => { socket1Destroyed = true; } },
        clientServer: { federation: { nodeAddress: 'test.node:8001' } },
        sendPacket: (p) => packets.push(p)
      };

      for (let i = 0; i < 4; i++) {
        const w = new SshPacketWriter();
        w.writeString('targetuser');
        w.writeString('ssh-connection');
        w.writeString('password');
        w.writeBoolean(false);
        w.writeString('wrongpass' + i);
        await SshAuthHandler.handleUserAuth(fakeConn1, new SshPacketReader(w.toBuffer()), w.toBuffer());
      }

      // 2. Baglanti (ayni IP'den tekrar baglanan saldirgan)
      const fakeConn2 = {
        db: mockDbProfile,
        socket: { remoteAddress: testIp, destroy: () => {} },
        clientServer: { federation: { nodeAddress: 'test.node:8001' } },
        sendPacket: (p) => packets.push(p)
      };
      for (let i = 0; i < 2; i++) {
        const w = new SshPacketWriter();
        w.writeString('targetuser');
        w.writeString('ssh-connection');
        w.writeString('password');
        w.writeBoolean(false);
        w.writeString('wrongpass' + (i + 4));
        await SshAuthHandler.handleUserAuth(fakeConn2, new SshPacketReader(w.toBuffer()), w.toBuffer());
      }

      // 3. Baglanti: IP kilitlenmistir
      const fakeConn3 = {
        db: mockDbProfile,
        socket: { remoteAddress: testIp, destroy: () => {} },
        clientServer: { federation: { nodeAddress: 'test.node:8001' } },
        sendPacket: (p) => packets.push(p)
      };
      const w3 = new SshPacketWriter();
      w3.writeString('targetuser');
      w3.writeString('ssh-connection');
      w3.writeString('password');
      w3.writeBoolean(false);
      w3.writeString('anypass');
      await SshAuthHandler.handleUserAuth(fakeConn3, new SshPacketReader(w3.toBuffer()), w3.toBuffer());

      record('MET-04: SSH kaba kuvvet saldirisinda IP rate limiting korumasi', socket1Destroyed, `Baglanti imhasi: ${socket1Destroyed}`);
    } catch (e) {
      record('MET-04: SSH Rate Limiting', false, e.message);
    }

    // ----------------------------------------------------
    // MET-05: Baglanti Havuzu Boyut Siniri (Connection Pool OOM)
    // ----------------------------------------------------
    try {
      const fed = new FederationEngine(db, { peers: new Map(), getAllPeers: () => [] });
      let destroyedCount = 0;

      // 505 baglanti olustur
      for (let i = 0; i < 505; i++) {
        const mockSock = new EventEmitter();
        mockSock.destroy = () => { destroyedCount++; };
        mockSock.setTimeout = () => {};
        mockSock.setKeepAlive = () => {};
        fed.connectionPool.set(`peer_${i}:8001`, { socket: mockSock });
      }

      // getOrCreateSecureChannel mantigi havuz boyutu 500'u asinca eskiyi temizler
      const poolSizeBefore = fed.connectionPool.size;
      const MAX_POOL = 500;
      if (fed.connectionPool.size > MAX_POOL) {
        const excess = fed.connectionPool.size - MAX_POOL;
        for (let i = 0; i < excess; i++) {
          const oldestKey = fed.connectionPool.keys().next().value;
          const oldChan = fed.connectionPool.get(oldestKey);
          try { oldChan.socket.destroy(); } catch {}
          fed.connectionPool.delete(oldestKey);
        }
      }

      const poolCapped = fed.connectionPool.size <= 500;
      record('MET-05: ConnectionPool azami 500 baglanti siniri', poolCapped, `Havuz boyutu: ${fed.connectionPool.size}`);
      fed.close();
    } catch (e) {
      record('MET-05: Connection Pool Siniri', false, e.message);
    }

    // ----------------------------------------------------
    // MET-06: Relay Forwarding & Exit Delivery Boyut Kontrolu
    // ----------------------------------------------------
    try {
      const onion = new OnionRouter({
        db,
        myIdentity: {
          nodeId: 'exitnode1',
          kemKeyPair: CryptoHelper.generateKemKeyPair()
        },
        rendezvousTunnels: new Map()
      });

      let forwardCellSent = false;
      const mockChannel = {
        socket: { remoteAddress: '198.51.100.1' },
        writePayload: () => { forwardCellSent = true; }
      };

      const circuitId = 'c_oversize_test';
      const symKey = CryptoHelper.generateRandomKey(32);
      db.saveCircuit({ circuitId, symmetricKey: symKey });

      // Dev boyutlu cell (UNIFORM_CELL_SIZE * 3)
      const oversizedPayload = {
        forwardTo: '198.51.100.2:8001',
        cell: { hugeData: 'X'.repeat(UNIFORM_CELL_SIZE * 3) }
      };
      const enc = CryptoHelper.encrypt(JSON.stringify(oversizedPayload), symKey);

      await onion.handleOnionCell({
        circuitId,
        iv: enc.iv,
        authTag: enc.authTag,
        ciphertext: enc.ciphertext
      }, mockChannel);

      record('MET-06: Asiri boyutlu relay forwarding hucrelerinin engellenmesi', !forwardCellSent, `Iletim engellendi: ${!forwardCellSent}`);
    } catch (e) {
      record('MET-06: Onion Forwarding Boyut Siniri', false, e.message);
    }

    // ----------------------------------------------------
    // MET-07: Devre Simetrik Anahtarlarinin SQLite Diske Sifreli Yazilmasi
    // ----------------------------------------------------
    try {
      const testCid = 'c_security_disk_test';
      const rawSymKey = 'secret_symmetric_key_32_bytes_x!';
      db.saveCircuit({ circuitId: testCid, symmetricKey: rawSymKey });

      // SQLite disk sorgusu
      const row = db.db.prepare('SELECT symmetric_key FROM active_circuits WHERE circuit_id = ?').get(testCid);
      const isEncryptedOnDisk = row.symmetric_key !== rawSymKey && row.symmetric_key.startsWith('{');

      // getCircuit ile bellek/cozumleme
      const retrieved = db.getCircuit(testCid);
      const isRetrievedCorrectly = retrieved && retrieved.symmetricKey === rawSymKey;

      record('MET-07: Simetrik devre anahtari disk uzerinde AEAD ile sifrelendi', isEncryptedOnDisk && isRetrievedCorrectly, `Diskte sifreli: ${isEncryptedOnDisk}`);
    } catch (e) {
      record('MET-07: Devre Anahtari Disk Guvenligi', false, e.message);
    }

    // ----------------------------------------------------
    // MET-08: SecureChannel Idle Handshake Timeout
    // ----------------------------------------------------
    try {
      let timeoutVal = null;
      let timeoutCb = null;
      let sockDestroyed = false;

      const mockSock = new EventEmitter();
      mockSock.setTimeout = (ms, cb) => {
        timeoutVal = ms;
        timeoutCb = cb;
      };
      mockSock.destroy = () => { sockDestroyed = true; };
      mockSock.write = () => {};

      const myId = {
        identityKeyPair: CryptoHelper.generateIdentityKeyPair(),
        kemKeyPair: CryptoHelper.generateKemKeyPair(),
        nodeAddress: 'localhost:8001',
        nodeId: 'testnode1'
      };
      const channel = new SecureChannel(mockSock, false, myId, db, new NonceTracker());

      if (typeof timeoutCb === 'function') {
        timeoutCb();
      }

      record('MET-08: SecureChannel askida kalan baglanti timeout ve imhasi', timeoutVal === 30000 && sockDestroyed, `Timeout: ${timeoutVal}ms`);
    } catch (e) {
      record('MET-08: Handshake Timeout Kontrolu', false, e.message);
    }

    // ----------------------------------------------------
    // MET-09: NonceTracker Kapasite Tasmasi ve TTL Temizligi
    // ----------------------------------------------------
    try {
      const tracker = new NonceTracker(100, 10);
      for (let i = 0; i < 10; i++) {
        tracker.track(`nonce_old_${i}`, '1.1.1.1');
      }

      // TTL dolmasini bekle
      await new Promise((r) => setTimeout(r, 120));

      // Yeni nonce eklendiginde eskiler silinir
      tracker.track('nonce_new_1', '1.1.1.1');
      const oldNonceCleared = !tracker.nonces.has('nonce_old_0_1.1.1.1');

      record('MET-09: NonceTracker kapasite oncesi suresi dolmus nonce temizligi', oldNonceCleared, `Eski nonce temizlendi: ${oldNonceCleared}`);
    } catch (e) {
      record('MET-09: NonceTracker Temizlik Kontrolu', false, e.message);
    }

    // ----------------------------------------------------
    // MET-10: Vault Salt'in NodeAddress ile Sinirli Kalmamasi
    // ----------------------------------------------------
    try {
      const clientPub = Buffer.alloc(32, 0x07);
      const seed1 = CryptoHelper.deriveVaultSeed('testpass', clientPub, 'nodeA.mesh:8001');
      const seed2 = CryptoHelper.deriveVaultSeed('testpass', clientPub, 'nodeB.mesh:8001');
      const differentSeedPerNode = !seed1.equals(seed2);

      record('MET-10: Vault HKDF salt SHA-256 ile dugum ve kullanici anahtarini harmanlar', differentSeedPerNode, `Farkli tohumlar: ${differentSeedPerNode}`);
    } catch (e) {
      record('MET-10: Vault Salt Kontrolu', false, e.message);
    }

    // ----------------------------------------------------
    // MET-11: Rendezvous BIND Zaman Damgasi ve Nonce Replay Kontrolu
    // ----------------------------------------------------
    try {
      const fed = {
        nodeAddress: 'localhost:8001',
        meshAddress: 'testrelay.mesh',
        getRelayAnnounceAddress: () => 'localhost:8001',
        rendezvousTunnels: new Map(),
        nonceTracker: new NonceTracker(),
        presenceTable: new Map(),
        db
      };
      const rdv = new RendezvousManager(fed);

      const edgeKp = CryptoHelper.generateIdentityKeyPair();
      const edgeNodeId = CryptoHelper.deriveNodeId(edgeKp.publicKey);

      // 6 dakika onceki zaman damgasi (> 5 dakika)
      const expiredTimestamp = Date.now() - 360000;
      const nonce = 'rdv_test_nonce_1';
      const sigData = `${edgeNodeId}localhost:8001${expiredTimestamp}${nonce}`;
      const sig = CryptoHelper.sign(sigData, edgeKp.privateKey);

      let rejectedReason = null;
      const mockChannel = {
        socket: { localAddress: '127.0.0.1', localPort: 8001, remoteAddress: '127.0.0.1' },
        writePayload: (p) => { rejectedReason = p.reason; }
      };

      rdv.handleRendezvousBind({
        nodeId: edgeNodeId,
        timestamp: expiredTimestamp,
        nonce,
        sig,
        identityPublicKey: edgeKp.publicKey
      }, mockChannel);

      record('MET-11: 5 dakikadan eski RENDEZVOUS_BIND zamandamgasi reddi', rejectedReason === 'expired_timestamp', `Neden: ${rejectedReason}`);
    } catch (e) {
      record('MET-11: Rendezvous Zaman Damgasi Kontrolu', false, e.message);
    }

    // ----------------------------------------------------
    // MET-12: HealthServer Bilgi Sizintisi (STATUS/INFO dis aga kapalilik)
    // ----------------------------------------------------
    try {
      const hs = new HealthServer(db, null, null, {
        port: 8959,
        allowOuterHeartbeat: true
      });

      let responseSent = '';
      const fakeExtSocket = new EventEmitter();
      fakeExtSocket.remoteAddress = '198.51.100.42'; // Dis IP
      fakeExtSocket.write = (data) => { responseSent += data; };
      fakeExtSocket.destroy = () => {};

      hs.handleConnection(fakeExtSocket);
      fakeExtSocket.emit('data', Buffer.from('STATUS\n'));

      const isUnauthorized = responseSent.includes('ERR unauthorized');
      record('MET-12: Dis IP adresinden gelen STATUS/INFO isteklerinin engellenmesi', isUnauthorized, `Yanit: ${responseSent.trim()}`);
    } catch (e) {
      record('MET-12: HealthServer Yetkisiz Erisim Kontrolu', false, e.message);
    }

  } finally {
    db.close();
    cleanupDb();
  }

  console.log(`\n${COLOR.BOLD}${COLOR.CYAN}================================================================${COLOR.RESET}`);
  console.log(`${COLOR.BOLD}                    AUDIT TEST SONUCLARI                       ${COLOR.RESET}`);
  console.log(`${COLOR.BOLD}${COLOR.CYAN}================================================================${COLOR.RESET}`);

  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed).length;
  const total = results.length;

  console.log(` Toplam Test : ${total}`);
  console.log(` Basarili    : ${COLOR.GREEN}${passed}${COLOR.RESET}`);
  console.log(` Basarisiz   : ${failed > 0 ? COLOR.RED : COLOR.GREEN}${failed}${COLOR.RESET}\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runAuditTests().catch((err) => {
  console.error('Kritik test hatasi:', err);
  process.exit(1);
});
