/**
 * Metrice P2P-Mesh Presence Senkronizasyon Test Süiti
 * tests/presence.test.js
 * 
 * Bu test süiti; kullanıcıların çıkıp girmesi (disconnect -> reconnect) sırasında
 * varlık senkronizasyonunun bozulmasını, gecikmiş USER_OFFLINE yarışlarını,
 * ters tünel varlık temsilini (Proxy Presence), röleler arası dedikodu yayılımını
 * ve 30 saniyelik temizleme/keepalive döngülerini kapsamlı olarak doğrular.
 */

import fs from 'node:fs';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { fileURLToPath } from 'node:url';
import { Database } from '../src/storage/database.js';
import { PeerManager } from '../src/core/peerManager.js';
import { FederationEngine } from '../src/core/federation.js';
import { ClientServer } from '../src/core/clientServer.js';
import { SshClientConnection } from '../src/core/sshServer.js';
import { AddressHelper } from '../src/utils/addressHelper.js';
import { CryptoHelper } from '../src/utils/cryptoHelper.js';
import { Logger } from '../src/utils/logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const COLOR = {
  GREEN: '\x1b[32m',
  RED: '\x1b[31m',
  YELLOW: '\x1b[33m',
  CYAN: '\x1b[36m',
  RESET: '\x1b[0m',
  BOLD: '\x1b[1m'
};

const results = [];

function record(name, passed, detail = '') {
  results.push({ name, passed, detail });
  const status = passed
    ? `${COLOR.GREEN}GEÇTİ ✔${COLOR.RESET}`
    : `${COLOR.RED}BAŞARISIZ ✘${COLOR.RESET}`;
  console.log(`[TEST] ${name.padEnd(80)} ${status}`);
  if (detail) {
    console.log(`       ${COLOR.YELLOW}Detay: ${detail}${COLOR.RESET}`);
  }
}

async function runPresenceTestSuite() {
  console.log(`\n${COLOR.CYAN}${COLOR.BOLD}====================================================${COLOR.RESET}`);
  console.log(`${COLOR.CYAN}${COLOR.BOLD} METRICE PRESENCE SENKRONİZASYON TEST SÜİTİ         ${COLOR.RESET}`);
  console.log(`${COLOR.CYAN}${COLOR.BOLD}====================================================${COLOR.RESET}\n`);

  const createdFiles = [];
  const trackFile = (p) => { createdFiles.push(p); return p; };

  try {
    // -------------------------------------------------------------
    // TEST 1: ACK Paketlerinin Sonsuz Döngüye Yol Açmaması (Ack Loop Shield)
    // -------------------------------------------------------------
    const db1Path = trackFile(path.join(rootDir, 'test_pres_db1.db'));
    if (fs.existsSync(db1Path)) fs.unlinkSync(db1Path);
    const db1 = new Database(db1Path);
    const fed1 = new FederationEngine(db1, new PeerManager());

    let writeCount = 0;
    const mockChannel = {
      isReady: true,
      socket: { writable: true },
      writePayload: () => {
        writeCount++;
      }
    };

    // status: 'ack' içeren USER_OFFLINE paketi handleIncoming'e gönderildiğinde yeni paket üretmemeli
    fed1.handleIncoming({
      status: 'ack',
      type: 'USER_OFFLINE',
      user: '@alice:node111111111.mesh'
    }, mockChannel, '127.0.0.1:8001');

    fed1.handleIncoming({
      status: 'ack',
      type: 'PRESENCE_ANNOUNCE',
      nodeId: 'node1111111111111'
    }, mockChannel, '127.0.0.1:8001');

    const test1Ok = writeCount === 0;
    record('P.1 [GÜVENLİK / ACK SHIELD] status:ack Paketlerinin Sonsuz Döngü Üretmeden Yutulması', !!test1Ok,
      `Üretilen Paket Sayısı: ${writeCount} (Beklenen: 0)`);

    fed1.close();
    db1.close();

    // -------------------------------------------------------------
    // TEST 2: Gecikmiş / Yarışan USER_OFFLINE Paketinin Yeni Oturumu Silmemesi (Stale Offline Race Guard)
    // -------------------------------------------------------------
    const db2Path = trackFile(path.join(rootDir, 'test_pres_db2.db'));
    if (fs.existsSync(db2Path)) fs.unlinkSync(db2Path);
    const db2 = new Database(db2Path);
    const fed2 = new FederationEngine(db2, new PeerManager());

    const testUser = '@bob:node222222222.mesh';
    const tNow = Date.now();

    // Kullanıcı T = tNow anında online kaydediliyor
    fed2.remoteOnlineUsers.set(testUser, {
      lastSeen: tNow,
      channels: ['#genel'],
      isSsh: true,
      kemPublicKey: 'kem_key_bob'
    });

    // Kullanıcıya T = tNow - 2000 ms (2 saniye önce) oluşturulmuş eski bir USER_OFFLINE paketi ulaşıyor
    fed2.handleIncoming({
      type: 'USER_OFFLINE',
      user: testUser,
      timestamp: tNow - 2000
    }, mockChannel, '127.0.0.1:8002');

    const userSurvivedStaleOffline = fed2.remoteOnlineUsers.has(testUser);

    // Kullanıcıya T = tNow + 1000 ms (taze) oluşturulmuş geçerli bir USER_OFFLINE paketi ulaşıyor
    fed2.handleIncoming({
      type: 'USER_OFFLINE',
      user: testUser,
      timestamp: tNow + 1000
    }, mockChannel, '127.0.0.1:8002');

    const userDeletedOnFreshOffline = !fed2.remoteOnlineUsers.has(testUser);

    const test2Ok = userSurvivedStaleOffline && userDeletedOnFreshOffline;
    record('P.2 [YARIŞ KORUMASI / STALE DROP] Eski USER_OFFLINE Paketinin Taze Oturumu Ezmemesi', !!test2Ok,
      `Eski Paketten Sağ Çıkma: ${userSurvivedStaleOffline}, Taze Pakette Silinme: ${userDeletedOnFreshOffline}`);

    fed2.close();
    db2.close();

    // -------------------------------------------------------------
    // TEST 3: Çıkış ve Hızlı Yeniden Girişte (Disconnect -> Reconnect) Varlık Tutarlılığı
    // -------------------------------------------------------------
    const db3EdgePath = trackFile(path.join(rootDir, 'test_pres_db3_edge.db'));
    const db3RelayPath = trackFile(path.join(rootDir, 'test_pres_db3_relay.db'));
    if (fs.existsSync(db3EdgePath)) fs.unlinkSync(db3EdgePath);
    if (fs.existsSync(db3RelayPath)) fs.unlinkSync(db3RelayPath);

    const db3Edge = new Database(db3EdgePath);
    const db3Relay = new Database(db3RelayPath);
    const fed3Edge = new FederationEngine(db3Edge, new PeerManager());
    fed3Edge.role = 'EDGE';
    const fed3Relay = new FederationEngine(db3Relay, new PeerManager());
    fed3Relay.role = 'RELAY';

    const cs3Edge = new ClientServer(db3Edge, fed3Edge);
    const cs3Relay = new ClientServer(db3Relay, fed3Relay);

    // Tünel kur
    const chEdgeToRelay = {
      isReady: true,
      socket: { writable: true },
      writePayload: (p) => {
        if (p.status === 'ack') return;
        fed3Relay.handleIncoming(p, chRelayToEdge, '127.0.0.1:8001');
      }
    };
    const chRelayToEdge = {
      isReady: true,
      socket: { writable: true },
      writePayload: (p) => {
        if (p.status === 'ack') return;
        fed3Edge.handleIncoming(p, chEdgeToRelay, '127.0.0.1:8002');
      }
    };

    fed3Relay.rendezvousTunnels.set(fed3Edge.nodeId, {
      socket: { writable: true },
      channel: chRelayToEdge,
      boundAt: Date.now(),
      boundRendezvousAddr: '127.0.0.1:8002'
    });
    fed3Edge.boundRendezvousRelays.add('127.0.0.1:8002');
    fed3Edge.rendezvousRelays.set('127.0.0.1:8002', {
      channel: chEdgeToRelay,
      socket: { writable: true }
    });

    const aliceAddress = `@alice:${fed3Edge.nodeId}.mesh`;
    const dummySession1 = { contacts: [], history: [], getMyChannels: () => ['#genel'], isSsh: true, kemKeyPair: { publicKey: 'k1' } };
    cs3Edge.sessions.set(aliceAddress, dummySession1);
    fed3Edge.broadcastPresence();

    const stage1RelaySeesAlice = fed3Relay.getAllOnlineUsers().includes(aliceAddress);

    // Alice çıkış yapıyor
    cs3Edge.sessions.delete(aliceAddress);
    await fed3Edge.broadcastUserOffline(aliceAddress);

    const stage2RelayClearedAlice = !fed3Relay.getAllOnlineUsers().includes(aliceAddress);

    // Alice hemen tekrar giriyor (reconnect)
    const dummySession2 = { contacts: [], history: [], getMyChannels: () => ['#genel'], isSsh: true, kemKeyPair: { publicKey: 'k2' } };
    cs3Edge.sessions.set(aliceAddress, dummySession2);
    fed3Edge.broadcastPresence();

    const stage3RelayReacquiredAlice = fed3Relay.getAllOnlineUsers().includes(aliceAddress);

    const test3Ok = stage1RelaySeesAlice && stage2RelayClearedAlice && stage3RelayReacquiredAlice;
    record('P.3 [HIZLI YENİDEN BAĞLANTI] Disconnect -> Reconnect Döngüsünde Varlığın Kararlı Senkronizasyonu', !!test3Ok,
      `Giriş: ${stage1RelaySeesAlice}, Çıkış: ${stage2RelayClearedAlice}, Yeniden Giriş: ${stage3RelayReacquiredAlice}`);

    fed3Edge.close();
    fed3Relay.close();
    db3Edge.close();
    db3Relay.close();

    // -------------------------------------------------------------
    // TEST 4: Çoklu Röle ve Dedikodu Üzerinden USER_OFFLINE Anında Senkronizasyonu (Gossip Offline Propagation)
    // -------------------------------------------------------------
    const db4R1Path = trackFile(path.join(rootDir, 'test_pres_db4_r1.db'));
    const db4R2Path = trackFile(path.join(rootDir, 'test_pres_db4_r2.db'));
    if (fs.existsSync(db4R1Path)) fs.unlinkSync(db4R1Path);
    if (fs.existsSync(db4R2Path)) fs.unlinkSync(db4R2Path);

    const db4R1 = new Database(db4R1Path);
    const db4R2 = new Database(db4R2Path);
    const fed4R1 = new FederationEngine(db4R1, new PeerManager());
    fed4R1.role = 'RELAY';
    const fed4R2 = new FederationEngine(db4R2, new PeerManager());
    fed4R2.role = 'RELAY';

    let r1ToR2OfflinePayload = null;
    const chR1ToR2 = {
      isReady: true,
      socket: { writable: true },
      writePayload: (p) => {
        if (p.status === 'ack') return;
        if (p.type === 'USER_OFFLINE') r1ToR2OfflinePayload = p;
        fed4R2.handleIncoming(p, chR2ToR1, '127.0.0.1:8001');
      }
    };
    const chR2ToR1 = {
      isReady: true,
      socket: { writable: true },
      writePayload: (p) => {
        if (p.status === 'ack') return;
        fed4R1.handleIncoming(p, chR1ToR2, '127.0.0.1:8002');
      }
    };

    fed4R1.connectionPool.set('127.0.0.1:8002', chR1ToR2);
    fed4R2.connectionPool.set('127.0.0.1:8001', chR2ToR1);
    fed4R1.peerManager.addOrUpdate('127.0.0.1:8002', true);
    fed4R2.peerManager.addOrUpdate('127.0.0.1:8001', true);

    const userEdge4 = '@tester:edge444444444.mesh';
    // Her iki rölede de kullanıcı online
    fed4R1.remoteOnlineUsers.set(userEdge4, { lastSeen: Date.now(), channels: ['#genel'] });
    fed4R2.remoteOnlineUsers.set(userEdge4, { lastSeen: Date.now(), channels: ['#genel'] });

    // Röle 1 bir USER_OFFLINE paketi alıyor (EDGE'den geldi)
    fed4R1.handleIncoming({
      type: 'USER_OFFLINE',
      user: userEdge4,
      timestamp: Date.now()
    }, { isReady: true, socket: { writable: true }, writePayload: () => {} }, '127.0.0.1:9000');

    // Röle 1 kendisinden silmeli
    const r1Cleared = !fed4R1.remoteOnlineUsers.has(userEdge4);

    // Röle 1 bu paketi Röle 2'ye iletmiş olmalı (Gossip)
    const r2Cleared = !fed4R2.remoteOnlineUsers.has(userEdge4);

    const test4Ok = r1Cleared && r2Cleared && r1ToR2OfflinePayload !== null;
    record('P.4 [DEDİKODU / GOSSIP OFFLINE] Röleler Arası USER_OFFLINE Paketinin Anında Yayılması', !!test4Ok,
      `Röle 1 Silinme: ${r1Cleared}, Röle 2 Dedikodu İle Silinme: ${r2Cleared}, Paket İletimi: ${!!r1ToR2OfflinePayload}`);

    fed4R1.close();
    fed4R2.close();
    db4R1.close();
    db4R2.close();

    // -------------------------------------------------------------
    // TEST 5: Proxy Presence ve Tünel Canlılığı Senkronizasyonu (Proxy Presence Keepalive)
    // -------------------------------------------------------------
    const db5Path = trackFile(path.join(rootDir, 'test_pres_db5.db'));
    if (fs.existsSync(db5Path)) fs.unlinkSync(db5Path);
    const db5 = new Database(db5Path);
    const fed5 = new FederationEngine(db5, new PeerManager());
    fed5.role = 'RELAY';

    const edgeNodeId5 = 'edgenode55555555';
    fed5.rendezvousTunnels = new Map([
      [edgeNodeId5, {
        socket: { writable: true },
        channel: { isReady: true, socket: { writable: true }, writePayload: () => {} },
        boundRendezvousAddr: '198.51.100.1:8001'
      }]
    ]);

    const oldTimestamp = Date.now() - 70000; // 70 saniye önce (presence TTL 60s'den eski)
    const userEdge5 = `@tunneled:${edgeNodeId5}.mesh`;
    fed5.remoteOnlineUsers.set(userEdge5, {
      channels: ['#genel'],
      isSsh: true,
      kemPublicKey: 'kem5',
      lastSeen: oldTimestamp
    });

    // Tünel canlı olduğu için createPresenceAnnouncePayload veya cleanupExpiredPresence tünelli kullanıcıyı tazelemeli
    fed5.createPresenceAnnouncePayload();
    fed5.cleanupExpiredPresence();

    const tunneledUserAlive = fed5.remoteOnlineUsers.has(userEdge5);
    const freshLastSeen = fed5.remoteOnlineUsers.get(userEdge5)?.lastSeen || 0;
    const isRefreshed = freshLastSeen > oldTimestamp;

    const test5Ok = tunneledUserAlive && isRefreshed;
    record('P.5 [PROXY PRESENCE / KEEPALIVE] Tünel Canlı Olduğu Sürece Kullanıcının TTL Zamanaşımından Korunması', !!test5Ok,
      `Kullanıcı Hayatta: ${tunneledUserAlive}, Zaman Tazelendi: ${isRefreshed}`);

    fed5.close();
    db5.close();

    // -------------------------------------------------------------
    // TEST 6: Bilateral Varlık Yanıtında Tünelli Kullanıcıların Taşınması
    // -------------------------------------------------------------
    const db6Path = trackFile(path.join(rootDir, 'test_pres_db6.db'));
    if (fs.existsSync(db6Path)) fs.unlinkSync(db6Path);
    const db6 = new Database(db6Path);
    const fed6 = new FederationEngine(db6, new PeerManager());
    fed6.role = 'RELAY';

    // fed6'nın kendi yerel kullanıcısı YOK (myState.memberships boş)
    fed6.setLocalStateGetter(() => ({ users: [], memberships: [] }));

    // Ancak tünelli bir kullanıcısı var
    const edgeNodeId6 = 'edgenode66666666';
    fed6.rendezvousTunnels = new Map([
      [edgeNodeId6, {
        socket: { writable: true },
        channel: { isReady: true, socket: { writable: true }, writePayload: () => {} },
        boundRendezvousAddr: '198.51.100.1:8001'
      }]
    ]);
    const tunneledUser6 = `@remote_alice:${edgeNodeId6}.mesh`;
    fed6.remoteOnlineUsers.set(tunneledUser6, {
      channels: ['#genel'],
      isSsh: true,
      kemPublicKey: 'kem6',
      lastSeen: Date.now()
    });

    let bilateralPayload6 = null;
    const mockChannel6 = {
      isReady: true,
      socket: { writable: true },
      writePayload: (p) => {
        if (p.isBilateralReply) bilateralPayload6 = p;
      }
    };

    // Karşı röleden PRESENCE_ANNOUNCE geliyor
    const incomingIdKeyPair = CryptoHelper.generateIdentityKeyPair();
    const incomingNodeId = CryptoHelper.deriveNodeId(incomingIdKeyPair.publicKey);
    const incomingKem = CryptoHelper.generateKemKeyPair();
    const ts6 = Date.now();
    const dataToSign6 = JSON.stringify({
      nodeId: incomingNodeId,
      role: 'RELAY',
      rendezvousNodes: ['1.2.3.4:8001'],
      kemPublicKey: incomingKem.publicKey,
      channels: ['#genel'],
      timestamp: ts6
    });
    const sig6 = CryptoHelper.sign(dataToSign6, incomingIdKeyPair.privateKey);

    fed6.handleIncoming({
      type: 'PRESENCE_ANNOUNCE',
      nodeId: incomingNodeId,
      role: 'RELAY',
      rendezvousNodes: ['1.2.3.4:8001'],
      kemPublicKey: incomingKem.publicKey,
      identityPublicKey: incomingIdKeyPair.publicKey,
      channels: ['#genel'],
      memberships: [],
      timestamp: ts6,
      sig: sig6
    }, mockChannel6, '1.2.3.4:8001');

    const bilateralSent = bilateralPayload6 !== null;
    const bilateralIncludesTunneled = bilateralPayload6?.memberships?.some((m) => m.user === tunneledUser6);

    const test6Ok = bilateralSent && bilateralIncludesTunneled;
    record('P.6 [BİLATERAL SENKRONİZASYON] Yerel Kullanıcı Olmasa da Tünelli Varlıkların Yanıtta Taşınması', !!test6Ok,
      `Bilateral Yanıt Gönderildi: ${bilateralSent}, Tünelli Kullanıcı Taşındı: ${bilateralIncludesTunneled}`);

    fed6.close();
    db6.close();

    // -------------------------------------------------------------
    // TEST 7: getAllOnlineUsers Tekilleştirme ve Güncel .mesh Önceliği
    // -------------------------------------------------------------
    const db7Path = trackFile(path.join(rootDir, 'test_pres_db7.db'));
    if (fs.existsSync(db7Path)) fs.unlinkSync(db7Path);
    const db7 = new Database(db7Path);
    const fed7 = new FederationEngine(db7, new PeerManager());

    // Aynı kullanıcının eski IP adresi ve yeni .mesh adresi
    fed7.remoteOnlineUsers.set('@user:192.168.1.50:8001', { lastSeen: Date.now(), channels: [] });
    fed7.remoteOnlineUsers.set('@user:newnode77777777.mesh', { lastSeen: Date.now(), channels: [] });

    const list7 = fed7.getAllOnlineUsers();
    const meshPrioritized = list7.includes('@user:newnode77777777.mesh') && !list7.includes('@user:192.168.1.50:8001');
    const singleEntry = list7.filter((u) => u.split(':')[0] === '@user').length === 1;

    const test7Ok = meshPrioritized && singleEntry;
    record('P.7 [TEKİLLEŞTİRME / NICK] getAllOnlineUsers İçinde Eski Adres Yerine Güncel .mesh Önceliği', !!test7Ok,
      `Mesh Önceliklendi: ${meshPrioritized}, Tekil Kayıt: ${singleEntry} (Liste: ${JSON.stringify(list7)})`);

    fed7.close();
    db7.close();

    // -------------------------------------------------------------
    // TEST 8: LOG_LEVEL Dinamik Filtreleme (INFO Seviyesinde DEBUG Engeli)
    // -------------------------------------------------------------
    const originalLogLevel = process.env.LOG_LEVEL;
    const originalGlobalLevel = Logger.globalLevel;

    let interceptedLogs = [];
    const originalConsoleLog = console.log;
    console.log = (msg) => {
      interceptedLogs.push(msg);
    };

    try {
      Logger.setGlobalLevel('INFO');
      const testLogger = new Logger('TEST_MOD');

      testLogger.debug('Gizli debug mesaji');
      testLogger.info('Gorunur info mesaji');

      const debugBlocked = !interceptedLogs.some((l) => l.includes('Gizli debug mesaji'));
      const infoEmitted = interceptedLogs.some((l) => l.includes('Gorunur info mesaji'));

      Logger.setGlobalLevel('WARN');
      interceptedLogs = [];
      testLogger.info('Engellenen info mesaji');
      testLogger.warn('Gorunur warn mesaji');

      const infoBlockedOnWarn = !interceptedLogs.some((l) => l.includes('Engellenen info mesaji'));
      const warnEmitted = interceptedLogs.some((l) => l.includes('Gorunur warn mesaji'));

      const test8Ok = debugBlocked && infoEmitted && infoBlockedOnWarn && warnEmitted;
      record('P.8 [LOGLAMA / LOG_LEVEL] INFO/WARN Seviyesinde Alt Düzey Logların Başarıyla Filtrelenmesi', !!test8Ok,
        `DebugEngellendi: ${debugBlocked}, InfoYazildi: ${infoEmitted}, InfoWarnEngellendi: ${infoBlockedOnWarn}, WarnYazildi: ${warnEmitted}`);
    } finally {
      console.log = originalConsoleLog;
      Logger.globalLevel = originalGlobalLevel;
      if (originalLogLevel !== undefined) {
        process.env.LOG_LEVEL = originalLogLevel;
      } else {
        delete process.env.LOG_LEVEL;
      }
    }

    // -------------------------------------------------------------
    // TEST 9: [EDGE-TO-EDGE ROUTE SYNC] Yeni Tünel Bağlandığında Mevcut Tünellerin Rota Eşitlemesi
    // -------------------------------------------------------------
    const db9Path = trackFile(path.join(rootDir, 'test_pres_db9.db'));
    if (fs.existsSync(db9Path)) fs.unlinkSync(db9Path);
    const db9 = new Database(db9Path);
    const fed9 = new FederationEngine(db9, new PeerManager());

    // Mevcut bir Edge tüneli simüle et
    const existingEdgeNodeId = 'edgeexistingnode1';
    fed9.rendezvousTunnels.set(existingEdgeNodeId, {
      socket: { writable: true },
      channel: { writePayload: () => {} },
      boundRendezvousAddr: 'relay.mesh:8001',
      edgeKemKey: 'mock_kem_key_1',
      identityPublicKey: 'mock_id_key_1'
    });

    const receivedRouteUpdates = [];
    const newEdgeChannel = {
      isReady: true,
      socket: { writable: true },
      writePayload: (p) => {
        if (p && p.type === 'ROUTE_UPDATE') {
          receivedRouteUpdates.push(p);
        }
      }
    };

    const newEdgeIdKey = CryptoHelper.generateIdentityKeyPair();
    const newEdgeNodeId = CryptoHelper.deriveNodeId(newEdgeIdKey.publicKey);
    const newEdgeKem = CryptoHelper.generateKemKeyPair();
    const ts9 = Date.now();
    const nonce9 = CryptoHelper.generateRandomKey(16);
    const rdvRelayAddr9 = fed9.nodeAddress;
    const bindSig9 = CryptoHelper.sign(`${newEdgeNodeId}${rdvRelayAddr9}${ts9}${nonce9}`, newEdgeIdKey.privateKey);

    fed9.rendezvousManager.handleRendezvousBind({
      nodeId: newEdgeNodeId,
      relayAddress: rdvRelayAddr9,
      identityPublicKey: newEdgeIdKey.publicKey,
      kemPublicKey: newEdgeKem.publicKey,
      timestamp: ts9,
      nonce: nonce9,
      sig: bindSig9
    }, newEdgeChannel);

    const receivedExistingRoute = receivedRouteUpdates.some((r) => r.nodeId === existingEdgeNodeId && r.role === 'EDGE');
    const test9Ok = receivedExistingRoute;
    record('P.9 [KOPUKLUK GİDERME] Yeni Edge Bağlandığında Mevcut Tünellerin Rotalarının Otomatik Eşitlenmesi', !!test9Ok,
      `Yeni tünel eski rotayı aldı: ${receivedExistingRoute}`);

    fed9.close();
    db9.close();

    // -------------------------------------------------------------
    // TEST 10: [PRESENCE ANNOUNCE ROUTE UPSERT] Uzak Üye İçin Rota Tablosuna Otomatik Ekleme
    // -------------------------------------------------------------
    const db10Path = trackFile(path.join(rootDir, 'test_pres_db10.db'));
    if (fs.existsSync(db10Path)) fs.unlinkSync(db10Path);
    const db10 = new Database(db10Path);
    const fed10 = new FederationEngine(db10, new PeerManager());

    const remoteEdgeNodeId = 'edge2remotenode9';
    const remoteUserAddress = `@remoteedgeuser:${remoteEdgeNodeId}.mesh`;
    
    const relayIdKey10 = CryptoHelper.generateIdentityKeyPair();
    const relayNodeId10 = CryptoHelper.deriveNodeId(relayIdKey10.publicKey);
    const relayKem10 = CryptoHelper.generateKemKeyPair();
    const ts10 = Date.now();
    const dataToSign10 = JSON.stringify({
      nodeId: relayNodeId10,
      role: 'RELAY',
      rendezvousNodes: ['198.51.100.10:8001'],
      kemPublicKey: relayKem10.publicKey,
      channels: ['#genel'],
      timestamp: ts10
    });
    const sig10 = CryptoHelper.sign(dataToSign10, relayIdKey10.privateKey);

    fed10.handleIncoming({
      type: 'PRESENCE_ANNOUNCE',
      nodeId: relayNodeId10,
      role: 'RELAY',
      relayAnnounceAddress: '198.51.100.10:8001',
      rendezvousNodes: ['198.51.100.10:8001'],
      kemPublicKey: relayKem10.publicKey,
      identityPublicKey: relayIdKey10.publicKey,
      channels: ['#genel'],
      memberships: [
        {
          user: remoteUserAddress,
          channels: ['#genel'],
          isSsh: true,
          kemPublicKey: 'mock_remote_kem_key'
        }
      ],
      timestamp: ts10,
      sig: sig10
    }, { isReady: true, socket: { writable: true }, writePayload: () => {} }, '198.51.100.10:8001');

    const routeInTable = fed10.presenceTable.get(remoteEdgeNodeId);
    const routeInDb = fed10.db.getRoute(remoteEdgeNodeId);
    const test10Ok = routeInTable && routeInDb && routeInTable.rendezvousNodes.includes('198.51.100.10:8001');

    record('P.10 [ROTA TÜRETME] PRESENCE_ANNOUNCE İle Gelen Uzak Edge Üyeliğinin Rota Tablosuna İşlenmesi', !!test10Ok,
      `Tabloda Var: ${!!routeInTable}, DBde Var: ${!!routeInDb}, Rendezvous: ${routeInTable?.rendezvousNodes?.[0]}`);

    fed10.close();
    db10.close();

    // -------------------------------------------------------------
    // TEST 11: [ADRES TOLERANSI] Ön Eksiz Adres Ayrıştırma ve Yerel-Uzak Hedef Eşleşmesi
    // -------------------------------------------------------------
    const parseNoPrefix = AddressHelper.parse('alice');
    const parseOk = parseNoPrefix && parseNoPrefix.name === 'alice' && parseNoPrefix.type === 'USER';

    AddressHelper.localNodeId = 'localedgenode123';
    const matchSame = AddressHelper.isSameTarget('@relayuser:localedgenode123.mesh', '@relayuser:remoterelay999.mesh');
    const matchLocalFallback = AddressHelper.isSameTarget('@relayuser:local.mesh', '@relayuser:remoterelay999.mesh');
    const matchNoHost = AddressHelper.isSameTarget('@relayuser', '@relayuser:remoterelay999.mesh');

    const test11Ok = parseOk && matchSame && matchLocalFallback && matchNoHost;
    record('P.11 [ADRES & RENDER TOLERANSI] Ön Eksiz Ayrıştırma ve Yerel Fallback ile Uzak Adres Eşleşmesi', !!test11Ok,
      `Parse: ${parseOk}, MatchSame: ${matchSame}, MatchLocal: ${matchLocalFallback}, MatchNoHost: ${matchNoHost}`);

    // -------------------------------------------------------------
    // TEST 12: [EDGE-TO-EDGE DM TRANSİT] İki Edge Arası Relay Ters Tünel DM İletimi
    // -------------------------------------------------------------
    const dbRelayPath = trackFile(path.join(rootDir, 'test_pres_dbrelay12.db'));
    const dbEdgeAPath = trackFile(path.join(rootDir, 'test_pres_dbedgea12.db'));
    const dbEdgeBPath = trackFile(path.join(rootDir, 'test_pres_dbedgeb12.db'));
    if (fs.existsSync(dbRelayPath)) fs.unlinkSync(dbRelayPath);
    if (fs.existsSync(dbEdgeAPath)) fs.unlinkSync(dbEdgeAPath);
    if (fs.existsSync(dbEdgeBPath)) fs.unlinkSync(dbEdgeBPath);

    const dbRelay = new Database(dbRelayPath);
    const dbEdgeA = new Database(dbEdgeAPath);
    const dbEdgeB = new Database(dbEdgeBPath);

    const fedRelay = new FederationEngine(dbRelay, new PeerManager());
    fedRelay.setRole('RELAY');
    const fedEdgeA = new FederationEngine(dbEdgeA, new PeerManager());
    fedEdgeA.setRole('EDGE');
    const fedEdgeB = new FederationEngine(dbEdgeB, new PeerManager());
    fedEdgeB.setRole('EDGE');

    const edgeANodeId = fedEdgeA.nodeId;
    const edgeBNodeId = fedEdgeB.nodeId;
    const relayNodeId = fedRelay.nodeId;
    const relayAddr = fedRelay.nodeAddress;

    // Mock soket kanalları ile Edge A <-> Relay ve Edge B <-> Relay bağlantıları
    const channelRelayToA = {
      isReady: true,
      peerIdentityKey: fedEdgeA.identityKeyPair.publicKey,
      peerKemKey: fedEdgeA.kemKeyPair.publicKey,
      socket: { writable: true },
      writePayload: (p) => fedEdgeA.packetHandler.handleIncoming(p, channelAToRelay, relayAddr)
    };
    const channelAToRelay = {
      isReady: true,
      peerIdentityKey: fedRelay.identityKeyPair.publicKey,
      peerKemKey: fedRelay.kemKeyPair.publicKey,
      socket: { writable: true },
      writePayload: (p) => fedRelay.packetHandler.handleIncoming(p, channelRelayToA, '198.51.100.10:8001')
    };

    const channelRelayToB = {
      isReady: true,
      peerIdentityKey: fedEdgeB.identityKeyPair.publicKey,
      peerKemKey: fedEdgeB.kemKeyPair.publicKey,
      socket: { writable: true },
      writePayload: (p) => fedEdgeB.packetHandler.handleIncoming(p, channelBToRelay, relayAddr)
    };
    const channelBToRelay = {
      isReady: true,
      peerIdentityKey: fedRelay.identityKeyPair.publicKey,
      peerKemKey: fedRelay.kemKeyPair.publicKey,
      socket: { writable: true },
      writePayload: (p) => fedRelay.packetHandler.handleIncoming(p, channelRelayToB, '198.51.100.20:8001')
    };

    // Edge A, Relay'e bağlansın
    fedEdgeA.boundRendezvousRelays.add(relayAddr);
    fedEdgeA.rendezvousRelays.set(relayAddr, { channel: channelAToRelay, socket: channelAToRelay.socket });
    fedRelay.rendezvousTunnels.set(edgeANodeId, {
      channel: channelRelayToA,
      socket: channelRelayToA.socket,
      boundRendezvousAddr: relayAddr,
      edgeKemKey: fedEdgeA.kemKeyPair.publicKey,
      identityPublicKey: fedEdgeA.identityKeyPair.publicKey
    });

    // Edge B, Relay'e bağlansın (handleRendezvousBind çağrısıyla)
    const tsB = Date.now();
    const nonceB = CryptoHelper.generateRandomKey(16);
    const bindSigB = CryptoHelper.sign(`${edgeBNodeId}${relayAddr}${tsB}${nonceB}`, fedEdgeB.identityKeyPair.privateKey);
    fedRelay.rendezvousManager.handleRendezvousBind({
      nodeId: edgeBNodeId,
      relayAddress: relayAddr,
      identityPublicKey: fedEdgeB.identityKeyPair.publicKey,
      kemPublicKey: fedEdgeB.kemKeyPair.publicKey,
      timestamp: tsB,
      nonce: nonceB,
      sig: bindSigB
    }, channelRelayToB);

    fedEdgeB.boundRendezvousRelays.add(relayAddr);
    fedEdgeB.rendezvousRelays.set(relayAddr, { channel: channelBToRelay, socket: channelBToRelay.socket });

    // Edge A'ya da Edge B'nin rota anonsu gitsin
    fedRelay.broadcastRouteUpdate(edgeBNodeId, relayAddr, fedEdgeB.kemKeyPair.publicKey, fedEdgeB.identityKeyPair.publicKey);

    // Mesaj dinleyicileri
    let receivedAtB = null;
    fedEdgeB.on('message', (m) => {
      if (m && m.content === 'Merhaba Edge B') {
        receivedAtB = m;
      }
    });

    let receivedAtA = null;
    fedEdgeA.on('message', (m) => {
      if (m && m.content === 'Selam Edge A!') {
        receivedAtA = m;
      }
    });

    // Edge A -> Edge B DM gönderimi
    await fedEdgeA.sendRemoteMessage(`@alice:${edgeANodeId}.mesh`, `@bob:${edgeBNodeId}.mesh`, 'Merhaba Edge B');

    // Edge B -> Edge A DM yanıtı
    await fedEdgeB.sendRemoteMessage(`@bob:${edgeBNodeId}.mesh`, `@alice:${edgeANodeId}.mesh`, 'Selam Edge A!');

    const test12Ok = receivedAtB && receivedAtB.from.includes('alice') && receivedAtA && receivedAtA.from.includes('bob');
    record('P.12 [EDGE-TO-EDGE DM TRANSİT] İki Edge Arasında Relay Üzerinden Çift Yönlü DM İletimi', !!test12Ok,
      `Edge B aldı: ${Boolean(receivedAtB)}, Edge A yanıt aldı: ${Boolean(receivedAtA)}`);

    fedRelay.close();
    fedEdgeA.close();
    fedEdgeB.close();
    dbRelay.close();
    dbEdgeA.close();
    dbEdgeB.close();

    // -------------------------------------------------------------
    // TEST 13: [CROSS-RELAY TRANSİT DM] İki Ayrı Relay Üzerinden Çapraz DM İletimi
    // -------------------------------------------------------------
    const dbR1Path = trackFile(path.join(rootDir, 'test_r1.db'));
    const dbR2Path = trackFile(path.join(rootDir, 'test_r2.db'));
    const dbE1Path = trackFile(path.join(rootDir, 'test_e1.db'));
    const dbE2Path = trackFile(path.join(rootDir, 'test_e2.db'));

    [dbR1Path, dbR2Path, dbE1Path, dbE2Path].forEach((p) => { if (fs.existsSync(p)) fs.unlinkSync(p); });

    const dbR1 = new Database(dbR1Path);
    const dbR2 = new Database(dbR2Path);
    const dbE1 = new Database(dbE1Path);
    const dbE2 = new Database(dbE2Path);

    const fedR1 = new FederationEngine(dbR1, new PeerManager());
    const fedR2 = new FederationEngine(dbR2, new PeerManager());
    const fedE1 = new FederationEngine(dbE1, new PeerManager());
    const fedE2 = new FederationEngine(dbE2, new PeerManager());

    fedR1.role = 'RELAY';
    fedR2.role = 'RELAY';
    fedE1.role = 'EDGE';
    fedE2.role = 'EDGE';

    const r1Addr = '198.51.100.101:7171';
    const r2Addr = '198.51.100.102:7171';
    fedR1.nodeAddress = r1Addr;
    fedR2.nodeAddress = r2Addr;

    const e1NodeId = fedE1.nodeId;
    const e2NodeId = fedE2.nodeId;

    // Relay 1 <-> Relay 2 federe kanalı
    class TestChannel extends EventEmitter {
      constructor(peerKey, peerKem, peerAddr) {
        super();
        this.isReady = true;
        this.peerIdentityKey = peerKey;
        this.peerKemKey = peerKem;
        this.peerNodeAddress = peerAddr;
        this.socket = { writable: true };
        this.targetHandler = null;
        this.targetChannel = null;
        this.fromAddr = null;
      }
      writePayload(p) {
        if (this.targetHandler) {
          setImmediate(() => {
            const res = this.targetHandler(p, this.targetChannel, this.fromAddr);
            this.emit('payload', res || { status: 'delivered' });
          });
        }
      }
    }

    const chanR1toR2 = new TestChannel(fedR2.identityKeyPair.publicKey, fedR2.kemKeyPair.publicKey, r2Addr);
    const chanR2toR1 = new TestChannel(fedR1.identityKeyPair.publicKey, fedR1.kemKeyPair.publicKey, r1Addr);
    chanR1toR2.targetHandler = (p, c, f) => fedR2.packetHandler.handleIncoming(p, c, f);
    chanR1toR2.targetChannel = chanR2toR1;
    chanR1toR2.fromAddr = r1Addr;

    chanR2toR1.targetHandler = (p, c, f) => fedR1.packetHandler.handleIncoming(p, c, f);
    chanR2toR1.targetChannel = chanR1toR2;
    chanR2toR1.fromAddr = r2Addr;

    fedR1.peerManager.addOrUpdate(r2Addr, true, true);
    fedR2.peerManager.addOrUpdate(r1Addr, true, true);
    fedR1.connectionPool.set(r2Addr, chanR1toR2);
    fedR2.connectionPool.set(r1Addr, chanR2toR1);

    // Edge 1 <-> Relay 1
    const chanE1toR1 = new TestChannel(fedR1.identityKeyPair.publicKey, fedR1.kemKeyPair.publicKey, r1Addr);
    const chanR1toE1 = new TestChannel(fedE1.identityKeyPair.publicKey, fedE1.kemKeyPair.publicKey, 'edge1:8001');
    chanE1toR1.targetHandler = (p, c, f) => fedR1.packetHandler.handleIncoming(p, c, f);
    chanE1toR1.targetChannel = chanR1toE1;
    chanE1toR1.fromAddr = 'edge1:8001';

    chanR1toE1.targetHandler = (p, c, f) => fedE1.packetHandler.handleIncoming(p, c, f);
    chanR1toE1.targetChannel = chanE1toR1;
    chanR1toE1.fromAddr = r1Addr;

    fedE1.boundRendezvousRelays.add(r1Addr);
    fedE1.rendezvousRelays.set(r1Addr, { channel: chanE1toR1, socket: chanE1toR1.socket });
    fedR1.rendezvousTunnels.set(e1NodeId, {
      channel: chanR1toE1,
      socket: chanR1toE1.socket,
      boundRendezvousAddr: r1Addr,
      edgeKemKey: fedE1.kemKeyPair.publicKey,
      identityPublicKey: fedE1.identityKeyPair.publicKey
    });
    fedR1.presenceTable.set(e1NodeId, {
      nodeId: e1NodeId,
      role: 'EDGE',
      rendezvousNodes: [r1Addr],
      kemPublicKey: fedE1.kemKeyPair.publicKey,
      identityPublicKey: fedE1.identityKeyPair.publicKey,
      channels: [],
      lastSeen: Date.now()
    });

    // Edge 2 <-> Relay 2
    const chanE2toR2 = new TestChannel(fedR2.identityKeyPair.publicKey, fedR2.kemKeyPair.publicKey, r2Addr);
    const chanR2toE2 = new TestChannel(fedE2.identityKeyPair.publicKey, fedE2.kemKeyPair.publicKey, 'edge2:8001');
    chanE2toR2.targetHandler = (p, c, f) => fedR2.packetHandler.handleIncoming(p, c, f);
    chanE2toR2.targetChannel = chanR2toE2;
    chanE2toR2.fromAddr = 'edge2:8001';

    chanR2toE2.targetHandler = (p, c, f) => fedE2.packetHandler.handleIncoming(p, c, f);
    chanR2toE2.targetChannel = chanE2toR2;
    chanR2toE2.fromAddr = r2Addr;

    fedE2.boundRendezvousRelays.add(r2Addr);
    fedE2.rendezvousRelays.set(r2Addr, { channel: chanE2toR2, socket: chanE2toR2.socket });
    fedR2.rendezvousTunnels.set(e2NodeId, {
      channel: chanR2toE2,
      socket: chanR2toE2.socket,
      boundRendezvousAddr: r2Addr,
      edgeKemKey: fedE2.kemKeyPair.publicKey,
      identityPublicKey: fedE2.identityKeyPair.publicKey
    });
    fedR2.presenceTable.set(e2NodeId, {
      nodeId: e2NodeId,
      role: 'EDGE',
      rendezvousNodes: [r2Addr],
      kemPublicKey: fedE2.kemKeyPair.publicKey,
      identityPublicKey: fedE2.identityKeyPair.publicKey,
      channels: [],
      lastSeen: Date.now()
    });

    let msgAtE2 = null;
    fedE2.on('message', (m) => {
      if (m && m.content === 'Selam E2!') msgAtE2 = m;
    });

    let msgAtE1 = null;
    fedE1.on('message', (m) => {
      if (m && m.content === 'Selam E1!') msgAtE1 = m;
    });

    // E1 (Relay 1 arkasında) -> E2 (Relay 2 arkasında) DM gönderimi
    await fedE1.sendRemoteMessage(`@user1:${e1NodeId}.mesh`, `@user2:${e2NodeId}.mesh`, 'Selam E2!');
    await new Promise((r) => setTimeout(r, 60));

    // E2 -> E1 DM yanıtı
    await fedE2.sendRemoteMessage(`@user2:${e2NodeId}.mesh`, `@user1:${e1NodeId}.mesh`, 'Selam E1!');
    await new Promise((r) => setTimeout(r, 60));

    const test13Ok = msgAtE2 && msgAtE2.from.includes('user1') && msgAtE1 && msgAtE1.from.includes('user2');
    record('P.13 [CROSS-RELAY TRANSİT DM] İki Ayrı Relay Üzerinden Çapraz Federe DM İletimi', !!test13Ok,
      `E2 aldı: ${Boolean(msgAtE2)}, E1 yanıt aldı: ${Boolean(msgAtE1)}`);

    fedR1.close();
    fedR2.close();
    fedE1.close();
    fedE2.close();
    dbR1.close();
    dbR2.close();
    dbE1.close();
    dbE2.close();

  } catch (err) {
    console.error(`\n${COLOR.RED}[HATA] Test sırasında beklenmeyen hata: ${err.message}${COLOR.RESET}`);
    console.error(err.stack);
  } finally {
    for (const f of createdFiles) {
      try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch {}
    }
  }

  // ==========================================
  // ÖZET RAPOR
  // ==========================================
  console.log(`\n${COLOR.CYAN}====================================================${COLOR.RESET}`);
  console.log(`${COLOR.CYAN}${COLOR.BOLD} PRESENCE TEST SONUÇLARI                           ${COLOR.RESET}`);
  console.log(`${COLOR.CYAN}====================================================${COLOR.RESET}`);

  const passedCount = results.filter((r) => r.passed).length;
  const failedCount = results.filter((r) => !r.passed).length;

  console.log(`  Toplam Test  : ${results.length}`);
  console.log(`  ${COLOR.GREEN}Başarılı     : ${passedCount}${COLOR.RESET}`);
  console.log(`  ${failedCount > 0 ? COLOR.RED : COLOR.GREEN}Başarısız    : ${failedCount}${COLOR.RESET}`);

  if (failedCount === 0) {
    console.log(`\n${COLOR.GREEN}${COLOR.BOLD}TÜM PRESENCE TESTLERİ BAŞARIYLA GEÇTİ! ✔${COLOR.RESET}\n`);
    process.exit(0);
  } else {
    console.log(`\n${COLOR.RED}${COLOR.BOLD}BAZI TESTLER BAŞARISIZ OLDU! ✘${COLOR.RESET}\n`);
    process.exit(1);
  }
}

runPresenceTestSuite();
