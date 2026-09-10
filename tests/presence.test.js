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
import { fileURLToPath } from 'node:url';
import { Database } from '../src/storage/database.js';
import { PeerManager } from '../src/core/peerManager.js';
import { FederationEngine } from '../src/core/federation.js';
import { ClientServer } from '../src/core/clientServer.js';
import { SshClientConnection } from '../src/core/sshServer.js';
import { AddressHelper } from '../src/utils/addressHelper.js';
import { CryptoHelper } from '../src/utils/cryptoHelper.js';

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
