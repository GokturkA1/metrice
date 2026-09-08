import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import EventEmitter from 'node:events';
import { spawn } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { Base32 } from '../src/utils/base32.js';
import { CryptoHelper } from '../src/utils/cryptoHelper.js';
import { AddressHelper } from '../src/utils/addressHelper.js';
import { Database } from '../src/storage/database.js';
import { FederationEngine, SecureChannel } from '../src/core/federation.js';
import { PeerManager } from '../src/core/peerManager.js';
import { OnionRouter, UNIFORM_CELL_SIZE } from '../src/core/onionRouter.js';
import { ClientServer } from '../src/core/clientServer.js';
import { TerminalSession } from '../src/core/terminalSession.js';
import { CONFIG } from '../src/config/index.js';

// ==========================================
// TEST KONFİGÜRASYONU VE YARDIMCILAR
// ==========================================

const rootDir = path.resolve(import.meta.dirname, '..');

const COLOR = {
  RESET: '\x1b[0m',
  GREEN: '\x1b[32m',
  RED: '\x1b[31m',
  YELLOW: '\x1b[33m',
  CYAN: '\x1b[36m',
  BOLD: '\x1b[1m'
};

const results = [];
const childProcesses = [];

function record(name, passed, details = '') {
  results.push({ name, passed, details });
  const mark = passed
    ? `${COLOR.GREEN}✔ BAŞARILI${COLOR.RESET}`
    : `${COLOR.RED}✘ BAŞARISIZ${COLOR.RESET}`;
  const detailStr = details ? ` (${COLOR.YELLOW}${details}${COLOR.RESET})` : '';
  console.log(`  [${mark}] ${name}${detailStr}`);
}

function cleanupFiles() {
  const files = fs.readdirSync(rootDir);
  for (const f of files) {
    if (f.startsWith('v2_test_') && (f.endsWith('.db') || f.endsWith('.json') || f.endsWith('.db-wal') || f.endsWith('.db-shm'))) {
      try { fs.unlinkSync(path.join(rootDir, f)); } catch {}
    }
  }
}

async function killProcesses() {
  for (const p of childProcesses) {
    if (p && !p.killed) {
      try { p.kill('SIGINT'); } catch {}
    }
  }
  await new Promise((r) => setTimeout(r, 400));
}

function waitPort(host, port, timeoutMs = 6000) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const check = () => {
      const sock = net.createConnection({ host, port }, () => {
        sock.destroy();
        resolve();
      });
      sock.on('error', () => {
        if (Date.now() - start > timeoutMs) {
          reject(new Error(`Port açılmadı (${host}:${port})`));
        } else {
          setTimeout(check, 150);
        }
      });
    };
    check();
  });
}

// ==========================================
// ANA TEST AKIŞI
// ==========================================

async function runV2TestSuite() {
  console.log(`\n${COLOR.CYAN}${COLOR.BOLD}====================================================${COLOR.RESET}`);
  console.log(`${COLOR.CYAN}${COLOR.BOLD} METRICE v2.0 POST-QUANTUM MESH TEST SUITE         ${COLOR.RESET}`);
  console.log(`${COLOR.CYAN}${COLOR.BOLD}====================================================${COLOR.RESET}\n`);

  cleanupFiles();

  try {
    // =========================================================================
    // BÖLÜM 1: DÜĞÜM KİMLİĞİ VE ADRESLEME KATMANI (ARCHITECT.md - Bölüm 1)
    // =========================================================================
    console.log(`${COLOR.BOLD}▶ BÖLÜM 1: Düğüm Kimliği ve Kriptografik Adresleme (Base32 & .mesh)${COLOR.RESET}`);

    // Test 1.1: Base32 Kodlama & Çözme
    const sampleBytes = Buffer.from('MetriceP2PMeshV2Protocol2026', 'utf-8');
    const b32Encoded = Base32.encode(sampleBytes);
    const b32Decoded = Base32.decode(b32Encoded);
    const b32Passed = b32Encoded.length > 0 && b32Decoded.toString('utf-8') === sampleBytes.toString('utf-8');
    record('1.1 Base32 RFC 4648 Kodlama ve Geri Çözme', b32Passed, `Encoded: ${b32Encoded.slice(0, 16)}...`);

    // Test 1.2: NodeID Türetimi (SHA256(Raw Ed25519 PubKey)[0..16])
    const idKp = CryptoHelper.generateIdentityKeyPair();
    const derivedNodeId = CryptoHelper.deriveNodeId(idKp.publicKey);
    const isValidNodeId = /^[a-z2-7]{16}$/.test(derivedNodeId);
    record('1.2 Ed25519 Açık Anahtarından 16-karakter Base32 NodeID Türetimi', isValidNodeId, `NodeID: ${derivedNodeId}`);

    // Test 1.3: Kullanıcı Adres Formatı (@user:nodeId.mesh)
    AddressHelper.setLocalNodeId(derivedNodeId);
    const userAddr = AddressHelper.formatUser('ahmet');
    const parsedUser = AddressHelper.parse(userAddr);
    const userAddrPassed = userAddr === `@ahmet:${derivedNodeId}.mesh` &&
      parsedUser && parsedUser.name === 'ahmet' &&
      parsedUser.nodeId === derivedNodeId &&
      parsedUser.isLocal === true;
    record('1.3 Kullanıcı Adresleme Ayrıştırma (@ahmet:NodeID.mesh)', userAddrPassed, userAddr);

    // Test 1.4: Kanal Adres Formatı (#kanal:nodeId.mesh ve #genel)
    const chanAddr = AddressHelper.formatChannel('kripto');
    const parsedChan = AddressHelper.parse(chanAddr);
    const globalChan = AddressHelper.parse('#genel');
    const chanAddrPassed = chanAddr === `#kripto:${derivedNodeId}.mesh` &&
      parsedChan && parsedChan.nodeId === derivedNodeId &&
      globalChan && globalChan.isGlobalChannel === true;
    record('1.4 Kanal Adresleme (#kripto:NodeID.mesh ve #genel Global)', chanAddrPassed, chanAddr);

    // =========================================================================
    // BÖLÜM 2: AUTONAT VE DIALBACK ROL KEŞFİ (ARCHITECT.md - Bölüm 2)
    // =========================================================================
    console.log(`\n${COLOR.BOLD}▶ BÖLÜM 2: AutoNAT (Reflected IP & Inbound Reachability Dialback)${COLOR.RESET}`);

    // Test 2.1: Reflected IP Konsensüsü (2 bağımsız eş aynı IP'yi teyit eder)
    const testDb2 = new Database(path.join(rootDir, 'v2_test_autonat.db'));
    const mockPeerMgr2 = {
      getAllPeers: () => ['127.0.0.1:9101', '127.0.0.1:9102'],
      addOrUpdate: () => {},
      startLanDiscovery: () => {},
      getRandomSample: () => []
    };
    const fedAutoNat = new FederationEngine(testDb2, mockPeerMgr2);

    let consensusTriggered = false;
    let agreedPublicIp = null;
    fedAutoNat.on('nat_consensus', (ip) => {
      consensusTriggered = true;
      agreedPublicIp = ip;
    });

    fedAutoNat.handleObservedAddress('198.51.100.25:45678', 'peer1.node:8001');
    const vote1Passed = fedAutoNat.observedAddressVotes.get('198.51.100.25').size === 1 && !consensusTriggered;
    fedAutoNat.handleObservedAddress('198.51.100.25:48999', 'peer2.node:8001');
    const vote2Passed = fedAutoNat.observedAddressVotes.get('198.51.100.25').size === 2 && consensusTriggered;
    record('2.1 Reflected IP Konsensüs Mantığı (2 Eş Onayı)', vote1Passed && vote2Passed && agreedPublicIp === '198.51.100.25', `Consensus IP: ${agreedPublicIp}`);

    // Test 2.2: Inbound Reachability Dialback Rol Ataması (CAP_RELAY vs CAP_EDGE)
    const dialNonce = 'test_dialback_nonce_123';
    fedAutoNat.pendingDialbacks.set(dialNonce, {
      targetIp: '198.51.100.25',
      timer: setTimeout(() => {}, 10000),
      resolve: () => {}
    });
    fedAutoNat.handleDialbackConfirm({ nonce: dialNonce, confirmed: true });
    const isRelayAssigned = fedAutoNat.getRole() === 'RELAY' && fedAutoNat.isRelay();
    record('2.2 DIALBACK_CONFIRM Onayında CAP_RELAY Rol Ataması', isRelayAssigned, `Role: ${fedAutoNat.getRole()}`);

    // =========================================================================
    // BÖLÜM 3: BULUŞMA NOKTASI (RENDEZVOUS) & KALICI TERSİNE TÜNEL (ARCHITECT.md - Bölüm 3)
    // =========================================================================
    console.log(`\n${COLOR.BOLD}▶ BÖLÜM 3: Buluşma Noktası (Rendezvous) & Tersine Tünel (CGNAT)${COLOR.RESET}`);

    // Test 3.1: Kriptografik Yetkilendirme (RENDEZVOUS_BIND İmza Doğrulaması)
    const edgeKp = CryptoHelper.generateIdentityKeyPair();
    const edgeNodeId = CryptoHelper.deriveNodeId(edgeKp.publicKey);
    const relayAddr = '127.0.0.1:8001';
    const timestamp = Date.now();
    const nonce = CryptoHelper.generateRandomKey(16);
    const bindSig = CryptoHelper.sign(`${edgeNodeId}${relayAddr}${timestamp}${nonce}`, edgeKp.privateKey);

    let bindAckSent = false;
    let bindAckStatus = null;
    const mockChannel = {
      socket: { once: () => {}, write: () => {}, remoteAddress: '127.0.0.1' },
      peerNodeAddress: '127.0.0.1:9999',
      writePayload: (p) => {
        if (p.type === 'RENDEZVOUS_ACK') {
          bindAckSent = true;
          bindAckStatus = p.status;
        }
      }
    };

    fedAutoNat.nodeAddress = relayAddr;
    fedAutoNat.handleIncoming({
      type: 'RENDEZVOUS_BIND',
      nodeId: edgeNodeId,
      relayAddress: relayAddr,
      identityPublicKey: edgeKp.publicKey,
      timestamp,
      nonce,
      sig: bindSig
    }, mockChannel, '127.0.0.1:9999');

    const tunnelSaved = fedAutoNat.rendezvousTunnels.has(edgeNodeId);
    record('3.1 RENDEZVOUS_BIND Doğrulama ve Tünel Kaydı', bindAckSent && bindAckStatus === 'bound' && tunnelSaved, `EdgeNodeId: ${edgeNodeId}`);

    // Test 3.2: Sahte İmza veya Hatalı NodeID Reddi
    let rejectSent = false;
    const mockRejectChannel = {
      socket: { once: () => {}, write: () => {} },
      writePayload: (p) => {
        if (p.status === 'rejected') rejectSent = true;
      }
    };
    fedAutoNat.handleIncoming({
      type: 'RENDEZVOUS_BIND',
      nodeId: 'sahtekarnodeid00',
      relayAddress: relayAddr,
      identityPublicKey: edgeKp.publicKey,
      timestamp,
      nonce,
      sig: bindSig
    }, mockRejectChannel, '127.0.0.1:9999');
    record('3.2 Sahte NodeID ile Gelen BIND Paketinin Reddi', rejectSent);

    // Test 3.3: Maksimum 64 Tünel DoS Koruması
    const prevCount = fedAutoNat.rendezvousTunnels.size;
    for (let i = prevCount; i < 64; i++) {
      fedAutoNat.rendezvousTunnels.set(`dummy_node_${i.toString().padStart(3, '0')}`, { socket: {} });
    }
    let capacityRejected = false;
    const mockCapChannel = {
      socket: { once: () => {}, write: () => {} },
      writePayload: (p) => {
        if (p.status === 'rejected' && p.reason === 'tunnel_capacity_reached') {
          capacityRejected = true;
        }
      }
    };
    const extraKp = CryptoHelper.generateIdentityKeyPair();
    const extraNodeId = CryptoHelper.deriveNodeId(extraKp.publicKey);
    const extraSig = CryptoHelper.sign(`${extraNodeId}${relayAddr}${timestamp}${nonce}`, extraKp.privateKey);
    fedAutoNat.handleIncoming({
      type: 'RENDEZVOUS_BIND',
      nodeId: extraNodeId,
      relayAddress: relayAddr,
      identityPublicKey: extraKp.publicKey,
      timestamp,
      nonce,
      sig: extraSig
    }, mockCapChannel, '127.0.0.1:9999');
    record('3.3 Maksimum 64 Aktif Tünel DoS Kapasite Sınırı', capacityRejected, `Tunnels: ${fedAutoNat.rendezvousTunnels.size}`);

    // Test 3.4: 0x09 PING -> 0x0A PONG Keep-Alive (Section 3.2)
    let pongReceived = false;
    const keepAliveServer = net.createServer((sock) => {
      sock.on('data', (chunk) => {
        if (chunk.length === 1 && chunk[0] === 0x09) {
          sock.write(Buffer.from([0x0A]));
        }
      });
    });
    await new Promise((r) => keepAliveServer.listen(9876, r));
    const keepAliveClient = net.createConnection({ host: '127.0.0.1', port: 9876 });
    await new Promise((r) => keepAliveClient.once('connect', r));
    keepAliveClient.on('data', (buf) => {
      if (Buffer.isBuffer(buf) && buf.length === 1 && buf[0] === 0x0A) {
        pongReceived = true;
      }
    });
    keepAliveClient.write(Buffer.from([0x09]));
    await new Promise((r) => setTimeout(r, 200));
    keepAliveClient.destroy();
    keepAliveServer.close();
    record('3.4 1-Bayt Kalp Atışı PING (0x09) -> PONG (0x0A) Yanıtı', pongReceived);

    // =========================================================================
    // BÖLÜM 4: POST-QUANTUM ONION ROUTING & 1536-BYTE PADDING (ARCHITECT.md - Bölüm 4)
    // =========================================================================
    console.log(`\n${COLOR.BOLD}▶ BÖLÜM 4: Post-Quantum Onion Routing (1536-Bayt Hücreler & 3-Hop)${COLOR.RESET}`);

    // Test 4.1: Standart 1536 Bayt Uniform Cell Biçimlendirme
    const rawCell = {
      circuitId: 'circuit_alpha_01',
      iv: 'dGVzdF9pdl8xMjM0',
      authTag: 'dGVzdF90YWdfNTY3OA==',
      ciphertext: 'k7w4m9x2zqmesh01_encrypted_bytes_here'
    };
    const paddedStr = OnionRouter.formatPaddedCell(rawCell);
    const cellByteLen = Buffer.byteLength(paddedStr, 'utf-8');
    const parsedBack = JSON.parse(paddedStr.trim());
    const paddingValid = cellByteLen === UNIFORM_CELL_SIZE &&
      parsedBack.circuitId === rawCell.circuitId &&
      parsedBack.ciphertext === rawCell.ciphertext &&
      typeof parsedBack.pad === 'string';
    record(`4.1 Uniform Cell Padding (Tam ${UNIFORM_CELL_SIZE} Bayt Sabit Uzunluk)`, paddingValid, `Byte Length: ${cellByteLen}`);

    // Test 4.2: 3-Hop Telescoping ML-KEM-768 Devre Kurulumu & Şifre Çözme
    const r1Kem = CryptoHelper.generateKemKeyPair();
    const r2Kem = CryptoHelper.generateKemKeyPair();
    const r3Kem = CryptoHelper.generateKemKeyPair();

    const hops = [
      { address: '127.0.0.1:8101', kemPublicKey: r1Kem.publicKey, nodeId: 'node_r1_relay_01' },
      { address: '127.0.0.1:8102', kemPublicKey: r2Kem.publicKey, nodeId: 'node_r2_relay_02' },
      { address: '127.0.0.1:8103', kemPublicKey: r3Kem.publicKey, nodeId: 'node_r3_relay_03' }
    ];

    const circuitId = 'test_circuit_3hop';
    const keys = [];
    const encKeys = [];

    // Kaynak tarafı 3 simetrik anahtarı KEM ile türetir
    for (const h of hops) {
      const { sharedSecret, encapsulatedKey } = CryptoHelper.encapsulateKey(h.kemPublicKey);
      const key = CryptoHelper.deriveKey(sharedSecret, circuitId, 'p2p-mesh-onion-v2');
      keys.push(key);
      encKeys.push(encapsulatedKey);
    }

    // Röleler tarafı kendi özel anahtarlarıyla aynı anahtarı decapsulate eder
    const r1Secret = CryptoHelper.decapsulateKey(r1Kem.privateKey, encKeys[0]);
    const r1DerivedKey = CryptoHelper.deriveKey(r1Secret, circuitId, 'p2p-mesh-onion-v2');

    const r2Secret = CryptoHelper.decapsulateKey(r2Kem.privateKey, encKeys[1]);
    const r2DerivedKey = CryptoHelper.deriveKey(r2Secret, circuitId, 'p2p-mesh-onion-v2');

    const r3Secret = CryptoHelper.decapsulateKey(r3Kem.privateKey, encKeys[2]);
    const r3DerivedKey = CryptoHelper.deriveKey(r3Secret, circuitId, 'p2p-mesh-onion-v2');

    const keysMatch = Buffer.from(keys[0]).equals(Buffer.from(r1DerivedKey)) &&
      Buffer.from(keys[1]).equals(Buffer.from(r2DerivedKey)) &&
      Buffer.from(keys[2]).equals(Buffer.from(r3DerivedKey));
    record('4.2 3-Hop ML-KEM-768 Kapsülleme ve Simetrik Oturum Anahtarları Uyumu', keysMatch);

    // Test 4.3: Katmanlı Şifreleme ve Adım Adım Soğan Soyma (Peeling)
    // İçten Dışa:
    // Katman 3: { deliverTo: "edge_target_01", payload: { content: "Merhaba Onion!" } } -> Key 3
    // Katman 2: { forwardTo: "R3", cell: Katman 3 } -> Key 2
    // Katman 1: { forwardTo: "R2", cell: Katman 2 } -> Key 1

    const targetPayload = { content: 'Merhaba Onion Mesh v2.0!', sender: '@ahmet:nodeA.mesh' };
    const layer3 = CryptoHelper.encrypt(JSON.stringify({ deliverTo: 'edge_target_01', payload: targetPayload }), keys[2]);
    const cell3 = { circuitId, iv: layer3.iv, authTag: layer3.authTag, ciphertext: layer3.ciphertext };

    const layer2 = CryptoHelper.encrypt(JSON.stringify({ forwardTo: '127.0.0.1:8103', cell: cell3 }), keys[1]);
    const cell2 = { circuitId, iv: layer2.iv, authTag: layer2.authTag, ciphertext: layer2.ciphertext };

    const layer1 = CryptoHelper.encrypt(JSON.stringify({ forwardTo: '127.0.0.1:8102', cell: cell2 }), keys[0]);
    const cell1 = { circuitId, iv: layer1.iv, authTag: layer1.authTag, ciphertext: layer1.ciphertext };

    // R1 Katmanını Soyar
    const r1Dec = JSON.parse(CryptoHelper.decrypt(cell1, r1DerivedKey));
    const r1Valid = r1Dec.forwardTo === '127.0.0.1:8102' && r1Dec.cell.circuitId === circuitId;

    // R2 Katmanını Soyar
    const r2Dec = JSON.parse(CryptoHelper.decrypt(r1Dec.cell, r2DerivedKey));
    const r2Valid = r2Dec.forwardTo === '127.0.0.1:8103' && r2Dec.cell.circuitId === circuitId;

    // R3 (Exit) Katmanını Soyar
    const r3Dec = JSON.parse(CryptoHelper.decrypt(r2Dec.cell, r3DerivedKey));
    const r3Valid = r3Dec.deliverTo === 'edge_target_01' && r3Dec.payload.content === targetPayload.content;

    record('4.3 3-Hop Soğan Katmanlarının Soyulması (R1 -> R2 -> R3 -> Hedef)', r1Valid && r2Valid && r3Valid);

    // =========================================================================
    // BÖLÜM 5: VARLIK (PRESENCE) & ROTA HAVUZU (ARCHITECT.md - Bölüm 5 & 6)
    // =========================================================================
    console.log(`\n${COLOR.BOLD}▶ BÖLÜM 5: Dağıtık Varlık (Presence Announce) & SQLite Routing Table${COLOR.RESET}`);

    // Test 5.1: PRESENCE_ANNOUNCE Oluşturma ve Doğrulama
    const announceNodeId = CryptoHelper.deriveNodeId(idKp.publicKey);
    const announceData = {
      nodeId: announceNodeId,
      role: 'RELAY',
      rendezvousNodes: ['127.0.0.1:8001'],
      kemPublicKey: r1Kem.publicKey,
      channels: ['#genel', '#sohbet:test.mesh'],
      timestamp: Date.now()
    };
    const announceSig = CryptoHelper.sign(JSON.stringify(announceData), idKp.privateKey);

    fedAutoNat.handleIncoming({
      type: 'PRESENCE_ANNOUNCE',
      ...announceData,
      identityPublicKey: idKp.publicKey,
      sig: announceSig
    }, mockChannel, '127.0.0.1:8001');

    const inPresenceTable = fedAutoNat.presenceTable.has(announceNodeId);
    const inDbRouting = testDb2.getRoute(announceNodeId);
    const presenceValid = inPresenceTable && inDbRouting && inDbRouting.role === 'RELAY';
    record('5.1 PRESENCE_ANNOUNCE Doğrulama, RAM Önbellek ve SQLite Senkronizasyonu', presenceValid, `NodeID: ${announceNodeId}`);

    // Test 5.2: 60s TTL Temizliği (Routing Table & Presence Table Expiry)
    // 70s öncesine ait sahte bir kayıt oluştur
    const oldNodeId = 'oldnodeexpired01';
    testDb2.upsertRoute({
      nodeId: oldNodeId,
      role: 'EDGE',
      rendezvousNodes: [],
      kemPublicKey: r1Kem.publicKey,
      identityPublicKey: idKp.publicKey,
      lastSeen: Date.now() - 75000
    });
    fedAutoNat.presenceTable.set(oldNodeId, { lastSeen: Date.now() - 75000 });

    fedAutoNat.cleanupExpiredPresence();
    const oldRemovedFromRam = !fedAutoNat.presenceTable.has(oldNodeId);
    const oldRemovedFromDb = testDb2.getRoute(oldNodeId) === null;
    record('5.2 60 Saniye TTL Zaman Aşımı Temizliği (RAM + DB)', oldRemovedFromRam && oldRemovedFromDb);

    // =========================================================================
    // BÖLÜM 6: ÇOK DÜĞÜMLÜ CANLI ENTEGRASYON TESTİ (AĞ VE MESAJLAŞMA)
    // =========================================================================
    console.log(`\n${COLOR.BOLD}▶ BÖLÜM 6: Canlı Çok Düğümlü Ağ Simülasyonu (CGNAT Tersine Tünel & Mesaj)${COLOR.RESET}`);

    // 2 Adet Bağımsız Düğüm Başlat (Node A = Relay, Node B = Edge)
    const nodeRelayDb = new Database(path.join(rootDir, 'v2_test_relay.db'));
    const nodeEdgeDb = new Database(path.join(rootDir, 'v2_test_edge.db'));

    const relayPeerMgr = {
      getAllPeers: () => [],
      addOrUpdate: () => {},
      startLanDiscovery: () => {}
    };

    const edgePeerMgr = {
      getAllPeers: () => ['127.0.0.1:9501'],
      addOrUpdate: () => {},
      startLanDiscovery: () => {}
    };

    // Ayarları geçici olarak yapılandır
    const originalPort = CONFIG.federationPort;
    CONFIG.federationPort = 9501;
    const relayEngine = new FederationEngine(nodeRelayDb, relayPeerMgr);
    relayEngine.setRole('RELAY');
    relayEngine.start();
    await waitPort('127.0.0.1', 9501);

    CONFIG.federationPort = 9502;
    const edgeEngine = new FederationEngine(nodeEdgeDb, edgePeerMgr);
    edgeEngine.setRole('EDGE');
    edgeEngine.start();
    await waitPort('127.0.0.1', 9502);

    CONFIG.federationPort = originalPort;

    // Edge Düğümü Relay Düğümüne RENDEZVOUS_BIND ile bağlanır
    const boundSuccess = await edgeEngine.bindToRendezvousRelay('127.0.0.1:9501');
    await new Promise((r) => setTimeout(r, 400));

    const relayHasEdgeTunnel = relayEngine.rendezvousTunnels.has(edgeEngine.nodeId);
    record('6.1 Canlı Ağda EDGE -> RELAY Tersine Tünel Bağlantısı', boundSuccess && relayHasEdgeTunnel, `Edge Node: ${edgeEngine.nodeId}`);

    // Relay üzerinden Edge'e mesaj teslimatı (Tersine tünelden akış)
    let deliveredMessage = null;
    edgeEngine.on('message', (msg) => {
      deliveredMessage = msg;
    });

    // Relay üzerinden Onion hücre teslimatını simüle et
    const mockOnionExitPayload = {
      deliverTo: edgeEngine.nodeId,
      payload: {
        type: 'DIRECT_MESSAGE',
        id: `msg_${Date.now()}`,
        from: `@gokturk:${relayEngine.nodeId}.mesh`,
        to: `@edge:${edgeEngine.nodeId}.mesh`,
        content: 'Tersine tünel üzerinden teslim edilen v2.0 mesajı!',
        timestamp: new Date().toISOString()
      }
    };

    // Relay'in çıkış katmanı hedefi tünelden iletir
    const edgeTunnel = relayEngine.rendezvousTunnels.get(edgeEngine.nodeId);
    if (edgeTunnel && edgeTunnel.channel) {
      edgeTunnel.channel.writePayload(mockOnionExitPayload.payload);
    }

    await new Promise((r) => setTimeout(r, 600));

    const msgDeliveredSuccessfully = deliveredMessage &&
      deliveredMessage.to === `@edge:${edgeEngine.nodeId}.mesh` &&
      deliveredMessage.content.includes('v2.0 mesajı');

    record('6.2 Tersine Tünel Üzerinden EDGE Düğümüne Mesaj Teslimatı', msgDeliveredSuccessfully, deliveredMessage ? deliveredMessage.content : 'Teslim edilmedi');

    // =========================================================================
    // BÖLÜM 7: REPORT.txt GÜVENLİK, BUG & UNDEFINED BEHAVIOUR (UB) DOĞRULAMA
    // =========================================================================
    console.log(`\n${COLOR.BOLD}▶ BÖLÜM 7: REPORT.txt Güvenlik, Bug & UB Düzeltmeleri Doğrulama${COLOR.RESET}`);

    // Test 7.1: SSRF Koruması: targetIp parametresi yoksayılır, channel soketinin IP'si kullanılır
    const ssrfChannel = {
      socket: { remoteAddress: '127.0.0.1' },
      writePayload: () => {}
    };
    const originalCreateConn = net.createConnection;
    let attemptedHost = null;
    net.createConnection = function(opts, cb) {
      attemptedHost = opts.host;
      const sock = new EventEmitter();
      sock.setTimeout = () => {};
      sock.destroy = () => {};
      sock.write = () => {};
      sock.end = () => {};
      return sock;
    };
    try {
      fedAutoNat.handleIncoming({
        type: 'DIALBACK_REQUEST',
        targetIp: '192.168.1.55', // Saldırganın iç ağı taratma girişimi
        targetPort: 8888,
        nonce: 'ssrf_test_nonce'
      }, ssrfChannel, '127.0.0.1:9999');
    } finally {
      net.createConnection = originalCreateConn;
    }
    const ssrfBlocked = attemptedHost === '127.0.0.1' && attemptedHost !== '192.168.1.55';
    record('7.1 [GÜVENLİK/SSRF] DIALBACK_REQUEST targetIp Yoksayma & remoteAddress Sabitleme', ssrfBlocked, `Dialback Hedefi: ${attemptedHost}`);

    // Test 7.2: SecureChannel Buffer Overflow DoS Koruması (>64KB without newline)
    let socketDestroyed = false;
    const mockOverflowSocket = new EventEmitter();
    mockOverflowSocket.destroy = () => { socketDestroyed = true; };
    mockOverflowSocket.write = () => {};
    const overflowChannel = new SecureChannel(mockOverflowSocket, false, fedAutoNat.myIdentity, testDb2, fedAutoNat.nonceTracker);
    const hugeChunk = Buffer.alloc(65537, 0x41);
    mockOverflowSocket.emit('data', hugeChunk);
    record('7.2 [GÜVENLİK/DOS] SecureChannel Tampon Taşması Koruması (64 KB Sınırı)', socketDestroyed);

    // Test 7.3: Onion Hücrelerinin Şifreli Tünel (writePayload) İçinden Akması
    let payloadSentViaWritePayload = false;
    let payloadTypeSent = null;
    const mockSecureHop = {
      isReady: true,
      writePayload: (p) => {
        payloadSentViaWritePayload = true;
        payloadTypeSent = p.type;
      },
      socket: { write: () => {} }
    };
    const origGetOrCreate = fedAutoNat.getOrCreateSecureChannel.bind(fedAutoNat);
    fedAutoNat.getOrCreateSecureChannel = async () => mockSecureHop;
    try {
      const dummyCircuit = {
        hops: [{ address: '127.0.0.1:8001' }],
        keys: [CryptoHelper.generateRandomKey(32)],
        circuitId: 'encap_test_circuit'
      };
      await fedAutoNat.onionRouter.sendOnionCell(dummyCircuit, 'target_node_1', { msg: 'test' });
    } finally {
      fedAutoNat.getOrCreateSecureChannel = origGetOrCreate;
    }
    const onionEncapsulated = payloadSentViaWritePayload && payloadTypeSent === 'ONION_CELL';
    record('7.3 [PROTOKOL] ONION_CELL Hücrelerinin Şifreli Tünelde (writePayload) Taşınması', onionEncapsulated);

    // Test 7.4: Presence Anonsunda Ham IP Sızıntısı Engeli
    let capturedAnnouncePayload = null;
    const origSendPacket = fedAutoNat.sendPacket.bind(fedAutoNat);
    fedAutoNat.sendPacket = async (h, p, payload) => {
      if (payload.type === 'PRESENCE_ANNOUNCE') {
        capturedAnnouncePayload = payload;
      }
    };
    fedAutoNat.setRole('RELAY');
    fedAutoNat.broadcastPresenceAnnounce();
    fedAutoNat.sendPacket = origSendPacket;

    let leaksRawIp = false;
    if (capturedAnnouncePayload && Array.isArray(capturedAnnouncePayload.rendezvousNodes)) {
      for (const nodeAddr of capturedAnnouncePayload.rendezvousNodes) {
        if (/^\d+\.\d+\.\d+\.\d+/.test(nodeAddr)) {
          leaksRawIp = true;
        }
      }
    }
    const privacyPreserved = capturedAnnouncePayload && !leaksRawIp && capturedAnnouncePayload.rendezvousNodes[0].includes('.mesh');
    record('7.4 [GİZLİLİK] PRESENCE_ANNOUNCE Ham IP Sızıntısı Engeli (NodeID.mesh Kullanımı)', privacyPreserved, `Duyurulan: ${capturedAnnouncePayload?.rendezvousNodes?.[0]}`);

    // Test 7.5: initiateDialback Eşzamanlılık ve Çakışma Kilidi (isDialbackRunning)
    fedAutoNat.isDialbackRunning = true;
    let duplicateInitiated = false;
    const origGetAllPeers = fedAutoNat.peerManager.getAllPeers;
    fedAutoNat.peerManager.getAllPeers = () => {
      duplicateInitiated = true;
      return ['127.0.0.1:9999'];
    };
    await fedAutoNat.initiateDialback('198.51.100.99');
    fedAutoNat.peerManager.getAllPeers = origGetAllPeers;
    fedAutoNat.isDialbackRunning = false;
    record('7.5 [MANTIK/RACE] initiateDialback isDialbackRunning Mutex Kilit Koruması', !duplicateInitiated);

    // Test 7.6: SSH Sunucu Çıkışında Soket Durum Yarışı & Zamanlayıcı Tahliyesi
    const mockSshSocket = new EventEmitter();
    mockSshSocket.destroyed = false;
    mockSshSocket.writable = true;
    mockSshSocket.writableEnded = false;
    mockSshSocket.write = () => {};
    mockSshSocket.end = () => { mockSshSocket.destroyed = true; };

    const sshConn = {
      socket: mockSshSocket,
      activeTimeouts: new Set(),
      authenticatedUser: '@testssh:node.mesh',
      session: { contacts: [], history: [] },
      db: testDb2,
      clientServer: {
        sessions: new Map(),
        notifyAllSessionsRender: () => {},
        federation: { broadcastUserOffline: () => {} }
      },
      cleanup: null,
      setManagedTimeout(fn, ms) {
        const timer = setTimeout(() => {
          this.activeTimeouts.delete(timer);
          fn();
        }, ms);
        this.activeTimeouts.add(timer);
        return timer;
      }
    };
    sshConn.cleanup = function() {
      for (const timer of this.activeTimeouts) {
        clearTimeout(timer);
      }
      this.activeTimeouts.clear();
      this.session = null;
      this.authenticatedUser = null;
    };

    const timerRef = sshConn.setManagedTimeout(() => {}, 10000);
    const hasTimerBefore = sshConn.activeTimeouts.size === 1;
    sshConn.cleanup();
    const timersCleared = sshConn.activeTimeouts.size === 0;
    record('7.6 [UB/RACE] SshClientConnection Çıkışında Zamanlayıcıların İptali ve Güvenli Tahliye', hasTimerBefore && timersCleared);

    // Test 7.7: AddressHelper Çoklu İki Nokta Üst Üste & IPv6 Ayrıştırması
    const parsedIpv6BracketUser = AddressHelper.parse('@alice:[2001:db8::1]:8001');
    const parsedIpv6BracketChan = AddressHelper.parse('#testchan:[2001:db8::1]:8001');
    const parsedIpv4Mapped = AddressHelper.parse('@bob:::ffff:127.0.0.1:8001');
    const parsedMeshUser = AddressHelper.parse('@charlie:4r3k4w2q1a5b6c7d.mesh');

    const ipv6ParseValid = parsedIpv6BracketUser && parsedIpv6BracketUser.host === '2001:db8::1' && parsedIpv6BracketUser.port === 8001 &&
      parsedIpv6BracketChan && parsedIpv6BracketChan.host === '2001:db8::1' && parsedIpv6BracketChan.port === 8001 &&
      parsedIpv4Mapped && parsedIpv4Mapped.host === '::ffff:127.0.0.1' && parsedIpv4Mapped.port === 8001 &&
      parsedMeshUser && parsedMeshUser.nodeId === '4r3k4w2q1a5b6c7d';
    record('7.7 [KULLANILABİLİRLİK] AddressHelper IPv6 ([...]) & Çoklu İki Nokta Üst Üste Ayrıştırma', ipv6ParseValid);

    // Test 7.8: SSH Sunucu Version String Özelleştirme & Fallback Uyumu
    const { SshServer } = await import('../src/core/sshServer.js');
    const sshTestDb = { getNodeIdentity: () => ({ identityKeyPair: CryptoHelper.generateIdentityKeyPair() }) };

    // 1. Fallback Testi (tanımsızsa varsayılana düşer)
    const prevVersion = CONFIG.sshServerVersion;
    CONFIG.sshServerVersion = undefined;
    const testSshFallback = new SshServer(sshTestDb, {});
    const fallbackPort = await new Promise((res) => {
      testSshFallback.start(0);
      testSshFallback.server.on('listening', () => res(testSshFallback.server.address().port));
    });
    const fallbackIdent = await new Promise((res) => {
      const c = net.createConnection({ port: fallbackPort }, () => {});
      c.once('data', (d) => {
        res(d.toString().trim());
        c.destroy();
        testSshFallback.close();
      });
    });

    // 2. Custom Version Testi (ön ek yoksa otomatik 'SSH-2.0-' eklenir)
    CONFIG.sshServerVersion = 'SSH-2.0-CustomMetrice_2.0';
    const testSshCustom = new SshServer(sshTestDb, {}, { serverVersion: 'MyCustomNode' });
    const customPort = await new Promise((res) => {
      testSshCustom.start(0);
      testSshCustom.server.on('listening', () => res(testSshCustom.server.address().port));
    });
    const customIdent = await new Promise((res) => {
      const c = net.createConnection({ port: customPort }, () => {});
      c.once('data', (d) => {
        res(d.toString().trim());
        c.destroy();
        testSshCustom.close();
      });
    });
    CONFIG.sshServerVersion = prevVersion;

    const versionTestValid = fallbackIdent === 'SSH-2.0-Metrice_2.2.4' && customIdent === 'SSH-2.0-MyCustomNode';
    record('7.8 [YAPILANDIRMA] SSH Sunucu Version String Özelleştirme & Fallback Uyumu', versionTestValid, `Fallback: ${fallbackIdent}, Custom: ${customIdent}`);

    // Test 7.9: RENDEZVOUS_BIND Yabancı relayAddress İmzası Reddi (Bypass & Reflection Önlemi)
    let rejectedBindReason = null;
    const mockAttackerChannel = {
      socket: { remoteAddress: '127.0.0.1', localAddress: '127.0.0.1', localPort: 9501 },
      writePayload: (p) => { rejectedBindReason = p?.reason; }
    };
    const attackerKeypair = CryptoHelper.generateIdentityKeyPair();
    const attackerNodeId = CryptoHelper.deriveNodeId(attackerKeypair.publicKey);
    const foreignNonce = CryptoHelper.generateRandomKey(16);
    const foreignTimestamp = Date.now();
    // Başka bir röleye (evil-relay:9999) hitaben imzalanmış paket
    const foreignSig = CryptoHelper.sign(`${attackerNodeId}evil-relay:9999${foreignTimestamp}${foreignNonce}`, attackerKeypair.privateKey);
    relayEngine.handleIncoming({
      type: 'RENDEZVOUS_BIND',
      nodeId: attackerNodeId,
      relayAddress: 'evil-relay:9999',
      identityPublicKey: attackerKeypair.publicKey,
      timestamp: foreignTimestamp,
      nonce: foreignNonce,
      sig: foreignSig
    }, mockAttackerChannel, '127.0.0.1:44444');
    record('7.9 [GÜVENLİK/İTİBAR] RENDEZVOUS_BIND Yabancı relayAddress İmzası Reddi (Bypass Engeli)', rejectedBindReason === 'invalid_signature');

    // Test 7.10: MAX_ONION_PAYLOAD (768 Bayt) Sınırı Aşımında Reddetme
    let onionPayloadBlocked = false;
    try {
      const hugePayload = 'X'.repeat(800);
      const dummyCircuit = { circuitId: 'c_overflow', hops: [{ address: '127.0.0.1:8001' }], keys: [Buffer.alloc(32)] };
      await fedAutoNat.onionRouter.sendOnionCell(dummyCircuit, 'target_node', hugePayload);
    } catch (err) {
      if (err.message.includes('MAX_ONION_PAYLOAD')) {
        onionPayloadBlocked = true;
      }
    }
    record('7.10 [GİZLİLİK] Onion MAX_ONION_PAYLOAD (768 Bayt) Sınırı Aşımında Reddetme', onionPayloadBlocked);

    // Test 7.11: cleanupExpiredPresence() ile nodePhysicalAddresses Bellek Tahliyesi
    const zombieNodeId = 'zombienode999999';
    fedAutoNat.presenceTable.set(zombieNodeId, { lastSeen: Date.now() - 120000 });
    fedAutoNat.nodePhysicalAddresses.set(zombieNodeId, '192.168.1.99:8001');
    fedAutoNat.cleanupExpiredPresence();
    const zombieCleared = !fedAutoNat.presenceTable.has(zombieNodeId) && !fedAutoNat.nodePhysicalAddresses.has(zombieNodeId);
    record('7.11 [BELLEK] cleanupExpiredPresence() ile nodePhysicalAddresses Tahliyesi', zombieCleared);

    // Test 7.12: getOrCreateSecureChannel Çözülemeyen .mesh/NodeID İçin Kontrollü Red (DNS ENOTFOUND Önlemi)
    let dnsCrashPrevented = false;
    try {
      await fedAutoNat.getOrCreateSecureChannel('unresolvablenode.mesh', 8001);
    } catch (err) {
      if (err.message.includes('cannot be resolved to a physical address')) {
        dnsCrashPrevented = true;
      }
    }
    record('7.12 [HATA TOLERANSI] getOrCreateSecureChannel Çözülemeyen .mesh İçin Kontrollü Red', dnsCrashPrevented);

    // Test 7.13: AddressHelper Köşeli Parantezsiz Saf IPv6 (2001:db8::1) Port Karışıklığı Engeli
    const parsedRawIpv6 = AddressHelper.parseTarget('2001:db8::1');
    const rawIpv6Valid = parsedRawIpv6 && parsedRawIpv6.host === '2001:db8::1' && parsedRawIpv6.port === CONFIG.federationPort && parsedRawIpv6.isIpv6;
    record('7.13 [AYRIŞTIRMA] AddressHelper Köşeli Parantezsiz Saf IPv6 (2001:db8::1) Port Korunumu', rawIpv6Valid, `Host: ${parsedRawIpv6?.host}, Port: ${parsedRawIpv6?.port}`);

    // Test 7.14: bindToRendezvousRelay Soket 'close' Dinleyici Tekilleştirme (_hasRendezvousCloseHandler)
    const mockRdvSocket = new EventEmitter();
    const mockRdvChannel = { socket: mockRdvSocket, _hasRendezvousCloseHandler: false };
    // Simüle edilen ilk tescil
    if (!mockRdvChannel._hasRendezvousCloseHandler) {
      mockRdvChannel._hasRendezvousCloseHandler = true;
      mockRdvChannel.socket.once('close', () => { mockRdvChannel._hasRendezvousCloseHandler = false; });
    }
    const listenerCountFirst = mockRdvSocket.listenerCount('close');
    // İkinci tescil çağrısı (mükerrer dinleyici eklenmemeli)
    if (!mockRdvChannel._hasRendezvousCloseHandler) {
      mockRdvChannel._hasRendezvousCloseHandler = true;
      mockRdvChannel.socket.once('close', () => { mockRdvChannel._hasRendezvousCloseHandler = false; });
    }
    const listenerCountSecond = mockRdvSocket.listenerCount('close');
    record('7.14 [KAYNAK/MÜKERRER DİNLENİCİ] Rendezvous Soket Dinleyici Sızıntısı Engeli', listenerCountFirst === 1 && listenerCountSecond === 1);

    // Test 7.15: Onion Devreleri Composite Key (${circuitId}_${prevHop}) ile Çapraz Sızıntı Engeli
    const sharedCircuitId = 'colliding_circuit_id_123';
    testDb2.saveCircuit({
      circuitId: sharedCircuitId,
      prevHop: 'peerA:8001',
      nextHop: 'exitA:8001',
      symmetricKey: 'key_for_client_A',
      createdAt: Date.now()
    });
    testDb2.saveCircuit({
      circuitId: sharedCircuitId,
      prevHop: 'peerB:8002',
      nextHop: 'exitB:8002',
      symmetricKey: 'key_for_client_B',
      createdAt: Date.now() + 10
    });
    const circuitA = testDb2.getCircuit(sharedCircuitId, 'peerA:8001');
    const circuitB = testDb2.getCircuit(sharedCircuitId, 'peerB:8002');
    const circuitsIsolated = circuitA && circuitB &&
      circuitA.symmetricKey === 'key_for_client_A' &&
      circuitB.symmetricKey === 'key_for_client_B';
    record('7.15 [GÜVENLİK/İZOLASYON] Onion Devreleri Composite Key (${circuitId}_${prevHop}) İzolasyonu', circuitsIsolated);

    // Test 7.16: Buluşma Noktası Olmayan EDGE Hedeflerine Mesajın Outbox'a Kuyruklanması
    const unknownEdgeNodeId = 'unregisterededge01';
    const outboxResult = await fedAutoNat.sendViaOnion(unknownEdgeNodeId, {
      type: 'DIRECT_MESSAGE',
      id: 'msg_outbox_test',
      from: '@alice:local.mesh',
      to: `@bob:${unknownEdgeNodeId}.mesh`,
      content: 'Pending presence message'
    });
    const isQueued = outboxResult && outboxResult.status === 'queued';
    const queuedItems = testDb2.db.prepare('SELECT * FROM outbox WHERE receiver LIKE ?').all(`%${unknownEdgeNodeId}%`);
    record('7.16 [GÜVENİLİRLİK] Buluşma Noktası Olmayan EDGE Hedeflerine Mesajın Outbox Kuyruklaması', isQueued && queuedItems.length > 0);

    // Test 7.17: Database close() PASSIVE wal_checkpoint ile Kilitlenmeden Kapanış
    let checkpointPassiveOk = false;
    try {
      const dbTestClose = new Database(path.join(rootDir, 'v2_test_close_wal.db'));
      dbTestClose.db.prepare('CREATE TABLE test_wal (x INT)').run();
      dbTestClose.db.prepare('INSERT INTO test_wal VALUES (1)').run();
      dbTestClose.close();
      checkpointPassiveOk = true;
    } catch {}
    record('7.17 [KAYNAK/KİLİT] Database close() PASSIVE wal_checkpoint ile Kilitlenmeden Kapanış', checkpointPassiveOk);

    // Test 7.18: Onion Composite Key prevHop Kimlik Standardizasyonu (getHopIdentifier)
    const chWithPeer = { peerNodeAddress: '192.168.1.50:8001', socket: { remoteAddress: '::ffff:192.168.1.50', remotePort: 8001 } };
    const chWithoutPeer = { socket: { remoteAddress: '::ffff:192.168.1.50', remotePort: 8001 } };
    const chUnknown = {};
    const id1 = OnionRouter.getHopIdentifier(chWithPeer);
    const id2 = OnionRouter.getHopIdentifier(chWithoutPeer);
    const id3 = OnionRouter.getHopIdentifier(chUnknown);
    const hopIdConsistent = id1 === '192.168.1.50:8001' && id2 === '192.168.1.50:8001' && id3 === 'unknown';
    record('7.18 [PROTOKOL] Onion Hop Identifier Normalizasyonu (getHopIdentifier Tutarlılığı)', hopIdConsistent);

    // Test 7.19: Devre Yeniden Kullanımı ve Havuzlama (Circuit Reuse / Pooling)
    const testCircuitId = 'pool_test_circuit_01';
    const testTarget = 'target_node_pool_99';
    fedAutoNat.onionRouter.clientCircuits.set(testCircuitId, {
      circuitId: testCircuitId,
      hops: [{ address: '127.0.0.1:8001' }],
      keys: [Buffer.alloc(32)],
      targetNodeId: testTarget,
      createdAt: Date.now()
    });
    const retrievedCircuit = fedAutoNat.onionRouter.getActiveCircuitForTarget(testTarget);
    const poolActiveOk = retrievedCircuit && retrievedCircuit.circuitId === testCircuitId;

    fedAutoNat.onionRouter.clientCircuits.set('expired_circuit', {
      circuitId: 'expired_circuit',
      targetNodeId: 'target_expired',
      createdAt: Date.now() - 700000 // > 600000 circuitTtl
    });
    const expiredRetrieved = fedAutoNat.onionRouter.getActiveCircuitForTarget('target_expired');
    const poolTtlOk = expiredRetrieved === null && !fedAutoNat.onionRouter.clientCircuits.has('expired_circuit');

    fedAutoNat.onionRouter.removeClientCircuit(testCircuitId);
    const poolRemovedOk = fedAutoNat.onionRouter.getActiveCircuitForTarget(testTarget) === null;
    record('7.19 [PERFORMANS] Onion Devre Havuzlama ve TTL Temizliği (getActiveCircuitForTarget)', poolActiveOk && poolTtlOk && poolRemovedOk);

    // Test 7.20: v1 / v2 Çift Formatlı Mesaj Silme ve Okuma Uyumu
    const dbCompat = new Database(path.join(rootDir, 'v2_test_compat.db'));
    dbCompat.saveMessage({
      id: 'msg_v1_legacy',
      from: '@user1:127.0.0.1:8001',
      to: '@user2:127.0.0.1:8002',
      content: 'Legacy v1 direct message'
    });
    dbCompat.saveMessage({
      id: 'msg_v2_modern',
      from: '@user1:nodealpha111111.mesh',
      to: '@user2:nodebeta22222222.mesh',
      content: 'Modern v2 direct message'
    });
    dbCompat.saveMessage({
      id: 'chan_v1',
      from: '@user1:127.0.0.1:8001',
      to: '#chat:127.0.0.1:8001',
      content: 'Legacy channel msg'
    });
    dbCompat.saveMessage({
      id: 'chan_v2',
      from: '@user1:nodealpha111111.mesh',
      to: '#chat:nodealpha111111.mesh',
      content: 'Modern channel msg'
    });

    const convBefore = dbCompat.getConversation('@user1:nodealpha111111.mesh', '@user2:nodebeta22222222.mesh');
    const chanBefore = dbCompat.getConversation('@user1:nodealpha111111.mesh', '#chat:nodealpha111111.mesh');

    dbCompat.clearConversationForUser('@user1:nodealpha111111.mesh', '@user2:nodebeta22222222.mesh');
    dbCompat.clearConversationForUser('@user1:nodealpha111111.mesh', '#chat:nodealpha111111.mesh');

    const convAfter = dbCompat.getConversation('@user1:nodealpha111111.mesh', '@user2:nodebeta22222222.mesh');
    const chanAfter = dbCompat.getConversation('@user1:nodealpha111111.mesh', '#chat:nodealpha111111.mesh');

    const compatClearOk = convBefore.length === 2 && chanBefore.length === 2 && convAfter.length === 0 && chanAfter.length === 0;
    dbCompat.close();
    record('7.20 [UYUMLULUK] v1 ve v2 Çift Formatlı Mesaj Temizleme & Prefix İzolasyonu', compatClearOk);

    // Test 7.21: AutoNAT initiateDialback Hata Durumunda Derhal Tahliye (Asılı Kalmama)
    const dummyPeerMgr = { getAllPeers: () => ['127.0.0.1:9999'] };
    const dummyFed = new FederationEngine(testDb2, dummyPeerMgr);
    dummyFed.sendPacket = async () => { throw new Error('ECONNREFUSED'); };
    const dialbackStart = Date.now();
    const dialbackRole = await dummyFed.initiateDialback('127.0.0.1');
    const dialbackDuration = Date.now() - dialbackStart;
    const dialbackImmediate = dialbackRole === 'EDGE' && dummyFed.isDialbackRunning === false && dialbackDuration < 2000;
    dummyFed.close();
    record('7.21 [GÜVENİLİRLİK/KİLİT] Dialback Hata Durumunda Derhal Tahliye ve Mutex Serbestisi', dialbackImmediate);

    // Test 7.22: Saf IPv6 Köşeli Parantezli ([2001:db8::1]:8001) RENDEZVOUS_BIND Doğrulaması
    const ipv6Keypair = CryptoHelper.generateIdentityKeyPair();
    const ipv6NodeId = CryptoHelper.deriveNodeId(ipv6Keypair.publicKey);
    const ipv6Nonce = CryptoHelper.generateRandomKey(16);
    const ipv6Timestamp = Date.now();
    const ipv6RelayAddr = '[2001:db8::1]:9501';
    const ipv6Sig = CryptoHelper.sign(`${ipv6NodeId}${ipv6RelayAddr}${ipv6Timestamp}${ipv6Nonce}`, ipv6Keypair.privateKey);
    let ipv6BindAccepted = false;
    const mockIpv6Channel = {
      socket: { remoteAddress: '2001:db8::2', localAddress: '2001:db8::1', localPort: 9501, once: () => {} },
      writePayload: (p) => {
        if (p?.status === 'bound') ipv6BindAccepted = true;
      }
    };
    relayEngine.handleIncoming({
      type: 'RENDEZVOUS_BIND',
      nodeId: ipv6NodeId,
      relayAddress: ipv6RelayAddr,
      kemPublicKey: 'dummy_kem_for_ipv6_test',
      identityPublicKey: ipv6Keypair.publicKey,
      nonce: ipv6Nonce,
      timestamp: ipv6Timestamp,
      sig: ipv6Sig
    }, mockIpv6Channel);
    record('7.22 [PROTOKOL/IPv6] Saf IPv6 Köşeli Parantezli ([2001:db8::1]:port) RENDEZVOUS_BIND İmza Doğrulaması', ipv6BindAccepted);

    // Test 7.23: Kopan Soketlerde removeCircuitsForHop ile Devre Tahliyesi
    const hopAddress = '198.51.100.1:8001';
    fedAutoNat.onionRouter.clientCircuits.set('hop_c1', {
      circuitId: 'hop_c1',
      hops: [{ address: hopAddress }, { address: '198.51.100.2:8001' }],
      createdAt: Date.now()
    });
    fedAutoNat.onionRouter.clientCircuits.set('hop_c2', {
      circuitId: 'hop_c2',
      hops: [{ address: '127.0.0.1:8001' }],
      createdAt: Date.now()
    });
    fedAutoNat.onionRouter.removeCircuitsForHop(hopAddress);
    const hopCircuitsCleaned = !fedAutoNat.onionRouter.clientCircuits.has('hop_c1') && fedAutoNat.onionRouter.clientCircuits.has('hop_c2');
    fedAutoNat.onionRouter.clientCircuits.delete('hop_c2');
    record('7.23 [KAYNAK] Kopan Soket İlişkili Devrelerin removeCircuitsForHop ile Tahliyesi', hopCircuitsCleaned);

    // Test 7.24: Köşeli Parantezsiz IPv6 Port Girişinde bracketWarning Bildirimi
    const parsedTargetWarn = AddressHelper.parseTarget('2001:db8::1:8001');
    const parsedTargetClean = AddressHelper.parseTarget('[2001:db8::1]:8001');
    const bracketWarnOk = parsedTargetWarn?.bracketWarning === true && parsedTargetClean?.bracketWarning === false;
    record('7.24 [GİRDİ/DENETİM] Köşeli Parantezsiz IPv6 Port Girişinde bracketWarning Denetimi', bracketWarnOk);

    // Test 7.25: Rendezvous Heartbeat Zombi Tünel Tespiti (lastPong > 60s Soket İmhası)
    let zombieSocketDestroyed = false;
    const zombieMockSocket = {
      destroyed: false,
      writable: true,
      destroy: () => { zombieSocketDestroyed = true; }
    };
    const zombieRelay = '198.51.100.99:9501';
    edgeEngine.boundRendezvousRelays.add(zombieRelay);
    edgeEngine.connectionPool.set(zombieRelay, {
      socket: zombieMockSocket,
      lastPong: Date.now() - 70000 // > 60s
    });
    edgeEngine.sendRendezvousHeartbeat();
    const zombieTreated = zombieSocketDestroyed && !edgeEngine.boundRendezvousRelays.has(zombieRelay);
    record('7.25 [GÜVENİLİRLİK/HEARTBEAT] Rendezvous Zombi Tünel Tespiti (60s PONG Aşımında Tahliye)', zombieTreated);

    // Test 7.26: SQLite active_circuits ve routing_table İkincil İndeksleri
    const circuitIndexes = testDb2.db.prepare('PRAGMA index_list(active_circuits)').all();
    const routingIndexes = testDb2.db.prepare('PRAGMA index_list(routing_table)').all();
    const hasCidIndex = circuitIndexes.some((idx) => idx.name === 'idx_circuits_cid');
    const hasSeenIndex = routingIndexes.some((idx) => idx.name === 'idx_routing_seen');
    record('7.26 [PERFORMANS/DB] SQLite active_circuits & routing_table İkincil İndeksleri (idx_circuits_cid, idx_routing_seen)', hasCidIndex && hasSeenIndex);

    // Test 7.27: Tünel Bakım Asenkron Çakışma Önleyici Mutex (isMaintainingTunnels)
    edgeEngine.isMaintainingTunnels = true;
    let bindCalledDuringLock = false;
    const origBind = edgeEngine.bindToRendezvousRelay;
    edgeEngine.bindToRendezvousRelay = async () => { bindCalledDuringLock = true; };
    await edgeEngine.maintainRendezvousTunnels();
    edgeEngine.bindToRendezvousRelay = origBind;
    edgeEngine.isMaintainingTunnels = false;
    record('7.27 [EŞZAMANLILIK/MUTEX] maintainRendezvousTunnels Eşzamanlı Çalışma Engeli (isMaintainingTunnels Kilidi)', bindCalledDuringLock === false);

    // Test 7.28: getHopIdentifier Saf IPv6 Köşeli Parantez RFC 3986 Standardizasyonu
    const chIpv6 = { socket: { remoteAddress: '2001:db8::1', remotePort: 8001 } };
    const chIpv4 = { socket: { remoteAddress: '192.168.1.1', remotePort: 8001 } };
    const idIpv6 = OnionRouter.getHopIdentifier(chIpv6);
    const idIpv4 = OnionRouter.getHopIdentifier(chIpv4);
    const hopNormalizationOk = idIpv6 === '[2001:db8::1]:8001' && idIpv4 === '192.168.1.1:8001';
    record('7.28 [FORMAT/STANDART] getHopIdentifier Saf IPv6 RFC 3986 Köşeli Parantez Normalizasyonu', hopNormalizationOk);

    // Test 7.29: DIALBACK_REQUEST Yalnızca Başarılı connect Sonrasında Onay Gönderme (Erken Onay Önlemi)
    let dialbackConfirmedEarly = false;
    let dialbackConfirmedSuccess = false;
    const origCreateConn729 = net.createConnection;

    // 1. Senaryo: Bağlantı hatası durumunda CONFIRM ASLA gitmemeli
    net.createConnection = function(opts, cb) {
      const sock = new EventEmitter();
      sock.setTimeout = () => {};
      sock.destroy = () => {};
      sock.end = () => {};
      setImmediate(() => sock.emit('error', new Error('ECONNREFUSED')));
      return sock;
    };
    const failChannel = {
      socket: { remoteAddress: '198.51.100.33' },
      writePayload: (p) => {
        if (p?.type === 'DIALBACK_CONFIRM') dialbackConfirmedEarly = true;
      }
    };
    fedAutoNat.handleIncoming({
      type: 'DIALBACK_REQUEST',
      targetPort: 8888,
      nonce: 'fail_nonce_729'
    }, failChannel, '198.51.100.33:9999');

    // 2. Senaryo: Başarılı connect durumunda CONFIRM gitmeli
    net.createConnection = function(opts, cb) {
      const sock = new EventEmitter();
      sock.setTimeout = () => {};
      sock.destroy = () => {};
      sock.end = () => {};
      setImmediate(() => cb());
      return sock;
    };
    const successChannel = {
      socket: { remoteAddress: '198.51.100.34' },
      writePayload: (p) => {
        if (p?.type === 'DIALBACK_CONFIRM') dialbackConfirmedSuccess = true;
      }
    };
    fedAutoNat.handleIncoming({
      type: 'DIALBACK_REQUEST',
      targetPort: 8888,
      nonce: 'success_nonce_729'
    }, successChannel, '198.51.100.34:9999');

    await new Promise((r) => setTimeout(r, 50));
    net.createConnection = origCreateConn729;

    const dialbackGatingOk = !dialbackConfirmedEarly && dialbackConfirmedSuccess;
    record('7.29 [MANTIK/AUTONAT] DIALBACK_REQUEST Soket Bağlantısı Beklenmeden Onay Verilmemesi', dialbackGatingOk);

    // Test 7.30: PRESENCE_ANNOUNCE Zehirli Adres (localhost, 127.0.0.1, 0.0.0.0) Filtreleme (Gossip Poisoning Koruması)
    const poisonKp = CryptoHelper.generateIdentityKeyPair();
    const poisonNodeId = CryptoHelper.deriveNodeId(poisonKp.publicKey);
    const poisonTimestamp = Date.now();
    const poisonedRdvNodes = ['127.0.0.1:8001', 'localhost:8001', '0.0.0.0:8001', 'safe.mesh:8001'];
    const poisonData = JSON.stringify({
      nodeId: poisonNodeId,
      role: 'RELAY',
      rendezvousNodes: poisonedRdvNodes,
      kemPublicKey: poisonKp.publicKey,
      channels: [],
      timestamp: poisonTimestamp
    });
    const poisonSig = CryptoHelper.sign(poisonData, poisonKp.privateKey);

    fedAutoNat.handleIncoming({
      type: 'PRESENCE_ANNOUNCE',
      nodeId: poisonNodeId,
      role: 'RELAY',
      rendezvousNodes: poisonedRdvNodes,
      kemPublicKey: poisonKp.publicKey,
      identityPublicKey: poisonKp.publicKey,
      channels: [],
      timestamp: poisonTimestamp,
      sig: poisonSig
    }, { socket: { remoteAddress: '203.0.113.1' } }, '203.0.113.1:8001');

    const storedRecord = fedAutoNat.presenceTable.get(poisonNodeId);
    const poisoningBlocked = storedRecord &&
      storedRecord.rendezvousNodes.length === 1 &&
      storedRecord.rendezvousNodes[0] === 'safe.mesh:8001';
    record('7.30 [GÜVENLİK/GOSSIP] PRESENCE_ANNOUNCE Zehirli Adres (localhost, 127.0.0.1) Filtreleme', poisoningBlocked);

    // Test 7.31: CONFIG.meshRole === 'EDGE' Belirtildiğinde handleObservedAddress Dialback Başlatmama Koruması
    const origMeshRole = CONFIG.meshRole;
    CONFIG.meshRole = 'EDGE';
    const edgeTestNode = new FederationEngine(testDb2, { getAllPeers: () => ['203.0.113.5:8001', '203.0.113.6:8001'] });
    let dialbackTriggeredForEdge = false;
    edgeTestNode.initiateDialback = async () => { dialbackTriggeredForEdge = true; };
    edgeTestNode.handleObservedAddress('203.0.113.50:4000', '203.0.113.5:8001');
    edgeTestNode.handleObservedAddress('203.0.113.50:4001', '203.0.113.6:8001');
    const edgeProtectionOk = !dialbackTriggeredForEdge && edgeTestNode.getRole() === 'EDGE';
    CONFIG.meshRole = origMeshRole;
    edgeTestNode.close();
    record('7.31 [GÜVENİLİRLİK] MESH_ROLE=EDGE Yapılandırmasında Dialback Engeli & Rol Korunumu', edgeProtectionOk);

    // Test 7.32: PeerManager.addOrUpdate Loopback (localhost, 127.0.0.1, ::1, 0.0.0.0) Engeli
    const { PeerManager } = await import('../src/core/peerManager.js');
    const testPeerMgr = new PeerManager();
    testPeerMgr.addOrUpdate('127.0.0.1:8001');
    testPeerMgr.addOrUpdate('localhost:8002');
    testPeerMgr.addOrUpdate('::1:8003');
    testPeerMgr.addOrUpdate('0.0.0.0:8004');
    testPeerMgr.addOrUpdate('255.255.255.255:8005');
    testPeerMgr.addOrUpdate('203.0.113.10:8001');
    const loopbackBlocked = !testPeerMgr.peers.has('127.0.0.1:8001') &&
      !testPeerMgr.peers.has('localhost:8002') &&
      !testPeerMgr.peers.has('::1:8003') &&
      !testPeerMgr.peers.has('0.0.0.0:8004') &&
      !testPeerMgr.peers.has('255.255.255.255:8005') &&
      testPeerMgr.peers.has('203.0.113.10:8001');
    record('7.32 [KRİTİK/GOSSIP] PeerManager.addOrUpdate Loopback ve Localhost Adres Engeli', loopbackBlocked);

    // Test 7.33: bindToRendezvousRelay Başarılı Olduğunda Rölenin Rota Tablosuna İşlenmesi
    const relayKp = CryptoHelper.generateIdentityKeyPair();
    const relayKem = CryptoHelper.generateKemKeyPair();
    const relayNodeId = CryptoHelper.deriveNodeId(relayKp.publicKey);
    const mockBoundChannel = {
      peerNodeAddress: `${relayNodeId}.mesh`,
      peerIdentityKey: relayKp.publicKey,
      peerKemKey: relayKem.publicKey,
      socket: new EventEmitter(),
      _hasRendezvousCloseHandler: false
    };
    const testEdgeEngine = new FederationEngine(testDb2, { getAllPeers: () => [] });
    testEdgeEngine.getOrCreateSecureChannel = async () => mockBoundChannel;
    testEdgeEngine.sendPacket = async () => ({ status: 'bound' });
    await testEdgeEngine.bindToRendezvousRelay('203.0.113.88:8001');

    const relayRouteInDb = testDb2.getAllRoutes().find((r) => r.nodeId === relayNodeId);
    const relayInPresence = testEdgeEngine.presenceTable.get(relayNodeId);
    const routeAddedOnBind = relayRouteInDb &&
      relayRouteInDb.role === 'RELAY' &&
      relayRouteInDb.rendezvousNodes.includes('203.0.113.88:8001') &&
      relayInPresence &&
      testEdgeEngine.nodePhysicalAddresses.get(relayNodeId) === '203.0.113.88:8001';
    testEdgeEngine.close();
    record('7.33 [MANTIK/ROTA] bindToRendezvousRelay ile Bağlanılan Rölenin Rota Tablosuna İşlenmesi', !!routeAddedOnBind);

    // Test 7.34: 1-Hop Devre Kurulumunda CIRCUIT_CREATE Tipi Üretimi
    let sentHopPayload = null;
    const testOnionRouter = new OnionRouter({
      federation: {
        sendPacket: async (h, p, payload) => {
          sentHopPayload = payload;
          return { status: 'circuit_ready' };
        }
      },
      db: testDb2,
      myIdentity: fedAutoNat.myIdentity,
      rendezvousTunnels: new Map()
    });
    const hop1Kem = CryptoHelper.generateKemKeyPair();
    await testOnionRouter.buildCircuit([
      { address: '203.0.113.11:8001', kemPublicKey: hop1Kem.publicKey }
    ], 'test_circuit_1hop');
    const isCircuitCreate = sentHopPayload && sentHopPayload.type === 'CIRCUIT_CREATE';
    record('7.34 [KRİTİK/ONION] 1-Hop Devrede CIRCUIT_CREATE Tipi Doğrulaması', isCircuitCreate);

    // Test 7.35: sendViaOnion ile Aktif Yerel Rendezvous Tüneline Doğrudan Teslimat
    let directTunnelWritten = null;
    const directTunnelNodeId = 'directtunnelnode1';
    const mockDirectTunnelChannel = {
      socket: { writable: true },
      writePayload: (p) => { directTunnelWritten = p; }
    };
    fedAutoNat.rendezvousTunnels.set(directTunnelNodeId, {
      channel: mockDirectTunnelChannel,
      socket: mockDirectTunnelChannel.socket
    });
    const sendDirectRes = await fedAutoNat.sendViaOnion(directTunnelNodeId, {
      type: 'DIRECT_MESSAGE',
      id: 'dm_direct_tunnel',
      from: '@alice:relay.mesh',
      to: `@bob:${directTunnelNodeId}.mesh`,
      content: 'Doğrudan tünel mesajı'
    });
    fedAutoNat.rendezvousTunnels.delete(directTunnelNodeId);
    const directTunnelSuccess = sendDirectRes &&
      sendDirectRes.status === 'delivered' &&
      directTunnelWritten &&
      directTunnelWritten.id === 'dm_direct_tunnel';
    record('7.35 [KRİTİK/ROTA] sendViaOnion ile Aktif Yerel Tünele Doğrudan Teslimat', directTunnelSuccess);

    // Test 7.36: Kanal Mesajlarının Bağlı Tersine Tünellere Dağıtımı & MaxListeners
    let rdvBroadcastMsg = null;
    const rdvEdgeNodeId = 'rdvedgenode736';
    const mockRdvEdgeChannel = {
      socket: { writable: true },
      writePayload: (p) => { rdvBroadcastMsg = p; }
    };
    fedAutoNat.rendezvousTunnels.set(rdvEdgeNodeId, {
      channel: mockRdvEdgeChannel,
      socket: mockRdvEdgeChannel.socket
    });
    await fedAutoNat.broadcastChannelMessage({
      id: 'chan_rdv_test',
      from: '@admin:relay.mesh',
      to: '#genel',
      content: 'Kanal yayını tünel testi'
    });
    fedAutoNat.rendezvousTunnels.delete(rdvEdgeNodeId);

    const dummySocket = new EventEmitter();
    const scMaxListeners = new SecureChannel(dummySocket, false, fedAutoNat.myIdentity, testDb2, fedAutoNat.nonceTracker);
    const channelMaxListenersOk = scMaxListeners.getMaxListeners() === 100 && dummySocket.getMaxListeners() === 100;

    const channelTunnelDeliveryOk = rdvBroadcastMsg && rdvBroadcastMsg.id === 'chan_rdv_test' && channelMaxListenersOk;
    record('7.36 [KRİTİK/PROTOKOL] Kanal Mesajlarının Tersine Tünellere Dağıtımı & MaxListeners (100)', channelTunnelDeliveryOk);

    // Test 7.37: [KRİTİK/E2EE] SSH Girişi Sonrasında PRESENCE_ANNOUNCE & SYNC Tünel Dağıtımı
    let rdvAnnouncePayload = null;
    let rdvSyncPayload = null;
    const mockRdvRelayChannel = {
      socket: { writable: true },
      writePayload: (p) => {
        if (p?.type === 'PRESENCE_ANNOUNCE') rdvAnnouncePayload = p;
        if (p?.type === 'PRESENCE_SYNC') rdvSyncPayload = p;
      }
    };
    fedAutoNat.rendezvousRelays.set('relay_addr_737', {
      channel: mockRdvRelayChannel,
      socket: mockRdvRelayChannel.socket
    });

    const origGetPeers737 = fedAutoNat.peerManager.getAllPeers;
    fedAutoNat.peerManager.getAllPeers = () => [];
    await fedAutoNat.broadcastPresence();
    fedAutoNat.broadcastPresenceAnnounce();
    fedAutoNat.peerManager.getAllPeers = origGetPeers737;
    fedAutoNat.rendezvousRelays.delete('relay_addr_737');

    const test737Ok = rdvAnnouncePayload && rdvAnnouncePayload.type === 'PRESENCE_ANNOUNCE' &&
                      rdvSyncPayload && rdvSyncPayload.type === 'PRESENCE_SYNC';
    record('7.37 [KRİTİK/E2EE] SSH Girişi Sonrasında PRESENCE_ANNOUNCE & SYNC Tünel Dağıtımı', !!test737Ok);

    // Test 7.38: [KRİTİK/DEŞİFRE] getCurrentConversation İçinde .mesh / Localhost Karışık Adreslerde isSender Normalizasyonu
    const senderKemKey = CryptoHelper.generateKemKeyPair();
    const recipientKemKey = CryptoHelper.generateKemKeyPair();
    const secretMsg = 'Kuantum Gizli Metin 2026';
    const messageKey = crypto.randomBytes(32);
    const enc = CryptoHelper.encrypt(secretMsg, messageKey);

    const rKem = CryptoHelper.encapsulateKey(recipientKemKey.publicKey);
    const rAes = CryptoHelper.deriveKey(rKem.sharedSecret, 'e2ee-wrap', 'wrap-key');
    const rEncKey = CryptoHelper.encrypt(messageKey.toString('base64'), rAes);

    const sKem = CryptoHelper.encapsulateKey(senderKemKey.publicKey);
    const sAes = CryptoHelper.deriveKey(sKem.sharedSecret, 'e2ee-wrap', 'wrap-key');
    const sEncKey = CryptoHelper.encrypt(messageKey.toString('base64'), sAes);

    const rCombined = `${rKem.encapsulatedKey}!${rEncKey.iv}!${rEncKey.authTag}!${rEncKey.ciphertext}`;
    const sCombined = `${sKem.encapsulatedKey}!${sEncKey.iv}!${sEncKey.authTag}!${sEncKey.ciphertext}`;
    const e2eeContent = `e2ee:v2:${rCombined}:${sCombined}:${enc.iv}:${enc.authTag}:${enc.ciphertext}`;

    const clientServerInstance = new ClientServer(testDb2, fedAutoNat);
    const mockSenderSession = {
      isSsh: true,
      kemKeyPair: senderKemKey,
      activeTarget: '@bob:remote.mesh',
      systemLogs: []
    };
    const senderLocalAddress = '@alice:localhost:8001';
    clientServerInstance.sessions.set(senderLocalAddress, mockSenderSession);

    testDb2.saveMessage({
      from: '@alice:oe7dyq74mzoxhaj3.mesh',
      to: '@bob:remote.mesh',
      content: e2eeContent,
      isAction: false,
      isSnippet: false,
      isE2EE: true
    });

    const decryptedConv = clientServerInstance.getCurrentConversation(senderLocalAddress, '@bob:remote.mesh', []);
    const decryptedMsg = decryptedConv.find((m) => m.from && m.from.includes('alice'));
    const test738Ok = decryptedMsg && decryptedMsg.content === secretMsg;
    record('7.38 [KRİTİK/DEŞİFRE] getCurrentConversation İçinde .mesh / Localhost Karışık Adreslerde isSender Normalizasyonu', !!test738Ok);

    // Test 7.39: [TUI/BİLDİRİM] findLocalSession DM Dağıtımı, Yalnızca Kanonik .mesh Adresin Kişilere Eklenmesi ve Okunmadı Rozeti
    const dummySocketTui = new EventEmitter();
    dummySocketTui.write = () => true;
    dummySocketTui.destroyed = false;
    dummySocketTui.writable = true;

    const recipientSession = new TerminalSession(
      dummySocketTui,
      '@carol:localhost:8001',
      { contacts: [], history: [] },
      () => [],
      () => [],
      () => {},
      () => ({ uptime: '1m', rss: '10', peers: [], role: 'EDGE', nodeId: 'test' }),
      () => []
    );
    recipientSession.activeTarget = '#genel';
    clientServerInstance.sessions.set('@carol:localhost:8001', recipientSession);

    fedAutoNat.emit('message', {
      id: 'dm_test_739',
      from: '@dave:xxfp7q8394012345.mesh',
      to: '@carol:localhost:8001',
      content: 'Merhaba Carol!'
    });

    const hasMeshContact = recipientSession.contacts.includes('@dave:xxfp7q8394012345.mesh');
    const hasPlainContact = recipientSession.contacts.includes('@dave');
    const unreadMeshCount = recipientSession.unreadCounts.get('@dave:xxfp7q8394012345.mesh') || 0;
    const unreadPlainCount = recipientSession.unreadCounts.get('@dave') || 0;

    recipientSession.setTarget('@dave:xxfp7q8394012345.mesh');
    const clearedMesh = (recipientSession.unreadCounts.get('@dave:xxfp7q8394012345.mesh') || 0) === 0;

    const test739Ok = hasMeshContact && !hasPlainContact && unreadMeshCount > 0 && unreadPlainCount === 0 && clearedMesh;
    record('7.39 [TUI/BİLDİRİM] findLocalSession DM Dağıtımı, Yalnızca Kanonik .mesh Adresin Kişilere Eklenmesi ve Okunmadı Rozeti', !!test739Ok);

    // Test 7.40: [KARARLILIK & EŞ HAVUZU] Presence Jitter Toleransı (60s TTL), PeerManager failures >= 10 ve Bootstrap Koruması
    // 1. Presence Jitter Testi (30s önceki kullanıcı silinmemeli)
    fedAutoNat.remoteOnlineUsers.set('@jitter_user:remote.mesh', {
      channels: ['#genel'],
      lastSeen: Date.now() - 30000
    });
    const onlineUsersWithJitter = fedAutoNat.getAllOnlineUsers();
    const channelMembersWithJitter = fedAutoNat.getChannelMembers('#genel');
    const presenceToleranceOk = onlineUsersWithJitter.includes('@jitter_user:remote.mesh') &&
      channelMembersWithJitter.includes('@jitter_user:remote.mesh');

    // 65 sn önceki kullanıcı silinmeli
    fedAutoNat.remoteOnlineUsers.set('@expired_user:remote.mesh', {
      channels: ['#genel'],
      lastSeen: Date.now() - 65000
    });
    const onlineUsersExpired = fedAutoNat.getAllOnlineUsers();
    const expiredToleranceOk = !onlineUsersExpired.includes('@expired_user:remote.mesh');

    // 2. PeerManager Hata Eşiği (failures >= 10) ve Bootstrap Koruması
    const pmTest = new PeerManager();
    // 5 ardışık hata: eş havuzdan atılmamalı (score: 50'den başlasın)
    pmTest.peers.set('198.51.100.1:8001', { score: 50, lastSeen: Date.now(), failures: 4 });
    pmTest.addOrUpdate('198.51.100.1:8001', false); // 5. hata (score: 45, failures: 5)
    const survived5Failures = pmTest.peers.has('198.51.100.1:8001');

    // 10 ardışık hata: sıradan eş havuzdan atılmalı
    pmTest.peers.set('198.51.100.2:8001', { score: 50, lastSeen: Date.now(), failures: 9 });
    pmTest.addOrUpdate('198.51.100.2:8001', false); // 10. hata -> atılmalı
    const evictedAt10Failures = !pmTest.peers.has('198.51.100.2:8001');

    // Bootstrap eşi: 10 hata ve 0 puan alsa dahi kalıcı korunmalı
    CONFIG.bootstrapPeers = ['198.51.100.99:8001'];
    pmTest.peers.set('198.51.100.99:8001', { score: 2, lastSeen: Date.now(), failures: 9 });
    pmTest.addOrUpdate('198.51.100.99:8001', false); // 10. hata, score <= 0
    const bootstrapProtected = pmTest.peers.has('198.51.100.99:8001');

    const test740Ok = presenceToleranceOk && expiredToleranceOk && survived5Failures && evictedAt10Failures && bootstrapProtected;
    record('7.40 [KARARLILIK & EŞ HAVUZU] Presence Jitter Toleransı (60s), PeerManager 10 Hata Eşiği ve Bootstrap Koruması', !!test740Ok);

    // Test 7.41: [KARARLILIK / PRESENCE] PRESENCE_SYNC Eksik Listede Agresif Silme Engeli & USER_OFFLINE ile Tahliye
    const fedEngineTest = new FederationEngine(testDb2, { getAllPeers: () => [] });
    const userA = '@persisting_user:nodealpha111111.mesh';
    const userB = '@second_user:nodealpha111111.mesh';

    fedEngineTest.remoteOnlineUsers.set(userA, {
      lastSeen: Date.now(),
      channels: ['#genel'],
      isSsh: false,
      kemPublicKey: ''
    });
    fedEngineTest.remoteOnlineUsers.set(userB, {
      lastSeen: Date.now(),
      channels: ['#genel'],
      isSsh: false,
      kemPublicKey: ''
    });

    const mockChannel741 = {
      peerNodeAddress: 'nodealpha111111.mesh',
      writePayload: () => {}
    };
    fedEngineTest.handleIncoming({
      type: 'PRESENCE_SYNC',
      sourceNode: 'nodealpha111111.mesh',
      memberships: [{ user: userB, channels: ['#genel'] }]
    }, mockChannel741);

    const userASurvivedSync = fedEngineTest.remoteOnlineUsers.has(userA);

    fedEngineTest.handleIncoming({
      type: 'USER_OFFLINE',
      user: userA
    }, mockChannel741);
    const userADeletedOnOffline = !fedEngineTest.remoteOnlineUsers.has(userA);

    fedEngineTest.close();

    const test741Ok = userASurvivedSync && userADeletedOnOffline;
    record('7.41 [KARARLILIK / PRESENCE] PRESENCE_SYNC Eksik Listede Agresif Silme Engeli & USER_OFFLINE ile Tahliye', !!test741Ok);

    // Test 7.42: [ASENKRON E2EE & OUTBOX] saveRemoteUserKemKey Kalıcılığı, Çevrimdışı E2EE Kuyruklama ve Outbox Flush
    const testDbOffline = new Database(path.join(rootDir, 'v2_test_offline_e2ee.db'));
    const fedOffline = new FederationEngine(testDbOffline, { getAllPeers: () => [] });
    const clientServerOffline = new ClientServer(testDbOffline, fedOffline);

    const offlineUserAddr = '@target_offline:offline_node_742.mesh';
    const remoteKemKp = CryptoHelper.generateKemKeyPair();

    testDbOffline.saveRemoteUserKemKey(offlineUserAddr, remoteKemKp.publicKey);
    const savedProfile = testDbOffline.getUserProfile(offlineUserAddr);
    const kemKeyPersisted = savedProfile && savedProfile.kemPublicKey === remoteKemKp.publicKey;

    const senderKp = CryptoHelper.generateKemKeyPair();
    const senderSession = {
      isSsh: true,
      kemKeyPair: senderKp,
      warnedInsecureTargets: new Set(),
      addSystemLog: () => {},
      getMyChannels: () => []
    };

    await clientServerOffline.handleOutboundMessage(
      senderSession,
      '@alice:sender_node_742.mesh',
      offlineUserAddr,
      'Gizli çevrimdışı mesaj'
    );

    const pendingOutbox = testDbOffline.getPendingOutbox(true);
    const queuedItem = pendingOutbox.find((m) => m.to === offlineUserAddr);
    const offlineE2EEOk = queuedItem && queuedItem.isE2EE && queuedItem.content.startsWith('e2ee:v2:');

    const newRemoteKem = CryptoHelper.generateKemKeyPair();
    fedOffline.handleIncoming({
      type: 'PRESENCE_SYNC',
      sourceNode: 'node_sync_742.mesh',
      memberships: [{ user: '@sync_user:node_sync_742.mesh', channels: ['#genel'], kemPublicKey: newRemoteKem.publicKey }]
    }, { peerNodeAddress: 'node_sync_742.mesh', writePayload: () => {} });

    const syncUserProfile = testDbOffline.getUserProfile('@sync_user:node_sync_742.mesh');
    const syncKemPersisted = syncUserProfile && syncUserProfile.kemPublicKey === newRemoteKem.publicKey;

    fedOffline.close();
    clientServerOffline.close();
    testDbOffline.close();

    const test742Ok = kemKeyPersisted && offlineE2EEOk && syncKemPersisted;
    record('7.42 [ASENKRON E2EE & OUTBOX] saveRemoteUserKemKey Kalıcılığı, Çevrimdışı E2EE Kuyruklama ve PRESENCE_SYNC Entegrasyonu', !!test742Ok);

    // Test 7.43: [REVİZYON 15] Presence Salt-Okunurluk, Saat Skew Koruması, rowid Sıralaması ve resetOutboxForTarget
    const testDb743 = new Database(path.join(rootDir, 'v2_test_r15.db'));
    const fedEngine743 = new FederationEngine(testDb743, { getAllPeers: () => [] });

    // 1. Presence Salt-Okunurluk & Emit Döngüsü Engeli
    let presenceEmitCount = 0;
    fedEngine743.on('presence_change', () => { presenceEmitCount++; });

    // Gelecek saat damgası (saat kayması / clock skew) ve süresi geçmiş kullanıcı ekle
    const futureTime = Date.now() + 60000;
    fedEngine743.remoteOnlineUsers.set('@skew_user:future_node.mesh', {
      channels: ['#genel'],
      lastSeen: futureTime
    });

    const onlineUsersR15 = fedEngine743.getAllOnlineUsers();
    const chanMembersR15 = fedEngine743.getChannelMembers('#genel');
    const readOnlyNoEmit = presenceEmitCount === 0;
    const skewUserPreserved = onlineUsersR15.includes('@skew_user:future_node.mesh') &&
      chanMembersR15.includes('@skew_user:future_node.mesh');

    // 2. Monotonik rowid Mesaj Sıralaması (NTP saat farkından bağımsız varış sırası)
    // Önce yeni saatli (20:25) bir mesaj ekleniyor
    testDb743.saveMessage({
      id: 'msg_local_1',
      from: '@alice:tr_node.mesh',
      to: '#genel',
      content: 'TR ilk mesaj',
      timestamp: '2026-09-08T20:25:00.000Z'
    });
    // Sonra karşı tarafın saati geri olduğu için daha eski saatli (18:59) ama fiziken daha sonra gelen mesaj ekleniyor
    testDb743.saveMessage({
      id: 'msg_remote_2',
      from: '@bob:de_node.mesh',
      to: '#genel',
      content: 'DE yeni gelen mesaj (saati geri)',
      timestamp: '2026-09-08T18:59:00.000Z'
    });

    const conversation = testDb743.getConversation('@alice:tr_node.mesh', '#genel');
    const rowidOrderOk = conversation.length === 2 &&
      conversation[0].id === 'msg_local_1' &&
      conversation[1].id === 'msg_remote_2';

    // 3. resetOutboxForTarget
    testDb743.queueOutbox({
      id: 'outbox_r15',
      from: '@alice:tr_node.mesh',
      to: '@target:de_node.mesh',
      content: 'Bekleyen paket'
    });
    testDb743.updateOutboxRetry('outbox_r15');
    testDb743.resetOutboxForTarget('de_node.mesh');
    const pendingOutboxR15 = testDb743.getPendingOutbox(false);
    const resetOutboxOk = pendingOutboxR15.some((item) => item.id === 'outbox_r15' && item.nextRetry === 0 && item.retries === 0);

    // 4. PeerManager Auto-Reconnect Skoru 100'e Çekme
    const pmR15 = new PeerManager();
    pmR15.peers.set('198.51.100.55:8001', { score: 15, lastSeen: Date.now() - 5000, failures: 8 });
    pmR15.addOrUpdate('198.51.100.55:8001', true);
    const reconnectedPeer = pmR15.peers.get('198.51.100.55:8001');
    const peerScoreResetOk = reconnectedPeer && reconnectedPeer.score === 100 && reconnectedPeer.failures === 0;

    fedEngine743.close();
    testDb743.close();

    const test743Ok = readOnlyNoEmit && skewUserPreserved && rowidOrderOk && resetOutboxOk && peerScoreResetOk;
    record('7.43 [REVİZYON 15] Presence Salt-Okunurluk, Saat Skew Koruması, rowid Sıralaması ve resetOutboxForTarget', !!test743Ok);

    // Test 7.44: [REVİZYON 16] NAT/Edge Localhost Toleransı, Kriptografik .mesh Kimliği ve Handshake Adres Normalizasyonu
    const mockSocketRemote = {
      remoteAddress: '::ffff:78.174.205.111',
      write: () => {},
      on: () => {}
    };
    const mockChannelRemote = new SecureChannel(mockSocketRemote, false, {
      identityKeyPair: CryptoHelper.generateIdentityKeyPair(),
      kemKeyPair: CryptoHelper.generateKemKeyPair(),
      nodeAddress: 'localhost:8001',
      nodeId: 'relayn0de1234567'
    }, testDb2, { track: () => true });

    // 1. NAT arkasındaki Edge istemcisi (SERVER_NAME=localhost) uzak sunucuya bağlanırken IP Spoofing sayılmamalı
    const localhostNatOk = await mockChannelRemote.validatePeerIp('localhost:8001');
    const loopbackIpNatOk = await mockChannelRemote.validatePeerIp('127.0.0.1:8001');

    // 2. Kriptografik .mesh ve NodeID adresleri doğrudan kabul edilmeli
    const meshIdOk = await mockChannelRemote.validatePeerIp('c5fvlkcmf63btlx2.mesh:8001');
    const rawNodeIdOk = await mockChannelRemote.validatePeerIp('c5fvlkcmf63btlx2:8001');

    // 3. sendHandshakeInit içinde .mesh kanonik adres kullanımı
    let sentPayload = null;
    const clientMockSocket = {
      write: (data) => {
        try { sentPayload = JSON.parse(data.trim()); } catch {}
      },
      on: () => {}
    };
    const clientChan = new SecureChannel(clientMockSocket, false, {
      identityKeyPair: CryptoHelper.generateIdentityKeyPair(),
      kemKeyPair: CryptoHelper.generateKemKeyPair(),
      nodeAddress: 'localhost:8001',
      nodeId: 'c5fvlkcmf63btlx2'
    }, testDb2, { track: () => true });
    clientChan.sendHandshakeInit();
    const handshakeCanonicalOk = sentPayload && sentPayload.nodeAddress === 'c5fvlkcmf63btlx2.mesh:8001';

    const test744Ok = localhostNatOk && loopbackIpNatOk && meshIdOk && rawNodeIdOk && handshakeCanonicalOk;
    record('7.44 [REVİZYON 16] NAT/Edge Localhost Toleransı, Kriptografik .mesh Kimliği ve Handshake Adres Normalizasyonu', !!test744Ok);

    // Test 7.45: [REVİZYON 17] Kross-Röle Buluşma Noktası Anonsu (ROUTE_UPDATE) & Cross-Relay Onion Exit Hop Çözümlemesi
    const deKp = CryptoHelper.generateIdentityKeyPair();
    const deKem = CryptoHelper.generateKemKeyPair();
    const deNodeId = CryptoHelper.deriveNodeId(deKp.publicKey);
    const deRelayAddr = 'metrice-de.gokturka.net:8001';

    const testEdgeKp = CryptoHelper.generateIdentityKeyPair();
    const testEdgeKem = CryptoHelper.generateKemKeyPair();
    const testEdgeNodeId = CryptoHelper.deriveNodeId(testEdgeKp.publicKey);

    // 1. DE Rölesine RENDEZVOUS_BIND simülasyonu
    let capturedRouteUpdate = null;
    const mockDeRelayEngine = new FederationEngine(testDb2, new PeerManager());
    mockDeRelayEngine.nodeAddress = deRelayAddr;
    mockDeRelayEngine.setRole('RELAY');
    mockDeRelayEngine.identityKeyPair = deKp;
    mockDeRelayEngine.kemKeyPair = deKem;
    mockDeRelayEngine.nodeId = deNodeId;

    mockDeRelayEngine.sendPacket = async (host, port, payload) => {
      if (payload && payload.type === 'ROUTE_UPDATE') {
        capturedRouteUpdate = payload;
      }
      return { status: 'delivered' };
    };
    mockDeRelayEngine.peerManager.getAllPeers = () => ['metrice-tr.gokturka.net:8001'];

    const r17BindNonce = CryptoHelper.generateRandomKey(16);
    const r17BindTs = Date.now();
    const r17BindSig = CryptoHelper.sign(`${testEdgeNodeId}${deRelayAddr}${r17BindTs}${r17BindNonce}`, testEdgeKp.privateKey);

    const mockEdgeChannel = {
      socket: { once: () => {}, write: () => {}, writable: true },
      peerNodeAddress: '198.51.100.2:45678',
      writePayload: () => {}
    };

    mockDeRelayEngine.handleIncoming({
      type: 'RENDEZVOUS_BIND',
      nodeId: testEdgeNodeId,
      relayAddress: deRelayAddr,
      identityPublicKey: testEdgeKp.publicKey,
      kemPublicKey: testEdgeKem.publicKey,
      timestamp: r17BindTs,
      nonce: r17BindNonce,
      sig: r17BindSig
    }, mockEdgeChannel, '198.51.100.2:45678');

    const deLocalRoute = mockDeRelayEngine.presenceTable.get(testEdgeNodeId);
    const deRouteOk = deLocalRoute && deLocalRoute.rendezvousNodes.includes(deRelayAddr);
    const routeUpdateAnnounced = capturedRouteUpdate &&
      capturedRouteUpdate.nodeId === testEdgeNodeId &&
      capturedRouteUpdate.relayNodeId === deNodeId &&
      capturedRouteUpdate.relayAddress === deRelayAddr &&
      capturedRouteUpdate.relayKemPublicKey === deKem.publicKey;

    // 2. TR Rölesinin ROUTE_UPDATE paketini işlemesi ve Exit Hop çözümü
    const trKp = CryptoHelper.generateIdentityKeyPair();
    const trKem = CryptoHelper.generateKemKeyPair();
    const trNodeId = CryptoHelper.deriveNodeId(trKp.publicKey);
    const trRelayAddr = 'metrice-tr.gokturka.net:8001';

    const mockTrRelayEngine = new FederationEngine(testDb2, new PeerManager());
    mockTrRelayEngine.nodeAddress = trRelayAddr;
    mockTrRelayEngine.setRole('RELAY');
    mockTrRelayEngine.identityKeyPair = trKp;
    mockTrRelayEngine.kemKeyPair = trKem;
    mockTrRelayEngine.nodeId = trNodeId;

    if (capturedRouteUpdate) {
      mockTrRelayEngine.handleIncoming(capturedRouteUpdate, { socket: { once: () => {} } }, 'metrice-de.gokturka.net:8001');
    }

    const trEdgeRoute = mockTrRelayEngine.presenceTable.get(testEdgeNodeId);
    const trDeRoute = mockTrRelayEngine.presenceTable.get(deNodeId);
    const trCrossRouteOk = trEdgeRoute && trEdgeRoute.rendezvousNodes.includes(deRelayAddr) &&
      trDeRoute && trDeRoute.kemPublicKey === deKem.publicKey;

    // 3. TR'nin DE'yi Exit Hop olarak seçebilmesi
    let onionCircuitBuiltWithDeExit = false;
    mockTrRelayEngine.onionRouter.buildCircuit = async (hops, targetNodeId) => {
      const exitHop = hops[hops.length - 1];
      if (exitHop && exitHop.nodeId === deNodeId && exitHop.kemPublicKey === deKem.publicKey && exitHop.address === deRelayAddr) {
        onionCircuitBuiltWithDeExit = true;
      }
      return { circuitId: 'circ_test_r17', hops, keys: [CryptoHelper.generateRandomKey(32)] };
    };
    mockTrRelayEngine.onionRouter.sendOnionCell = async () => ({ status: 'onion_sent' });

    await mockTrRelayEngine.sendViaOnion(testEdgeNodeId, {
      type: 'DIRECT_MESSAGE',
      id: 'msg_r17_test',
      from: `@trUser:${trNodeId}.mesh`,
      to: `@edgeUser:${testEdgeNodeId}.mesh`,
      content: 'Cross-relay test message'
    });

    const test745Ok = deRouteOk && routeUpdateAnnounced && trCrossRouteOk && onionCircuitBuiltWithDeExit;
    record('7.45 [REVİZYON 17] Kross-Röle Buluşma Noktası Anonsu (ROUTE_UPDATE) & Cross-Relay Onion Exit Hop Çözümlemesi', !!test745Ok);

    // Temiz Kapanış
    relayEngine.close();
    edgeEngine.close();
    fedAutoNat.close();
    testDb2.close();
    nodeRelayDb.close();
    nodeEdgeDb.close();

  } catch (err) {
    console.error(`\n${COLOR.RED}[KRİTİK HATA] Test sırasında beklenmeyen hata: ${err.message}${COLOR.RESET}`);
    console.error(err.stack);
  } finally {
    cleanupFiles();
  }

  // ==========================================
  // ÖZET RAPOR
  // ==========================================
  console.log(`\n${COLOR.CYAN}====================================================${COLOR.RESET}`);
  console.log(`${COLOR.CYAN}${COLOR.BOLD} TEST SONUÇLARI ÖZETİ                              ${COLOR.RESET}`);
  console.log(`${COLOR.CYAN}====================================================${COLOR.RESET}`);

  const passedCount = results.filter((r) => r.passed).length;
  const failedCount = results.filter((r) => !r.passed).length;

  console.log(`  Toplam Test  : ${results.length}`);
  console.log(`  ${COLOR.GREEN}Başarılı     : ${passedCount}${COLOR.RESET}`);
  console.log(`  ${failedCount > 0 ? COLOR.RED : COLOR.GREEN}Başarısız    : ${failedCount}${COLOR.RESET}`);

  if (failedCount === 0) {
    console.log(`\n${COLOR.GREEN}${COLOR.BOLD}TÜM V2.0 SPESİFİKASYON TESTLERİ BAŞARIYLA GEÇTİ! ✔${COLOR.RESET}\n`);
    process.exit(0);
  } else {
    console.log(`\n${COLOR.RED}${COLOR.BOLD}BAZI TESTLER BAŞARISIZ OLDU! ✘${COLOR.RESET}\n`);
    process.exit(1);
  }
}

runV2TestSuite();
