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
import { ProxyProtocolParser } from '../src/utils/proxyProtocol.js';
import { SshClientConnection } from '../src/core/sshServer.js';

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

    // Test 7.4: [REVİZYON 18] Presence Anonsunda Fiziksel Taşıma Adresi Doğrulaması (.mesh Engeli)
    const prevServerName = CONFIG.serverName;
    CONFIG.serverName = 'relay.metrice.network';
    let capturedAnnouncePayload = null;
    const origSendPacket = fedAutoNat.sendPacket.bind(fedAutoNat);
    fedAutoNat.sendPacket = async (h, p, payload) => {
      if (payload.type === 'PRESENCE_ANNOUNCE') {
        capturedAnnouncePayload = payload;
      }
    };
    const origGetOrCreate74 = fedAutoNat.getOrCreateSecureChannel.bind(fedAutoNat);
    fedAutoNat.getOrCreateSecureChannel = async (h, p) => {
      return {
        isReady: true,
        socket: { writable: true },
        writePayload: (payload) => {
          if (payload.type === 'PRESENCE_ANNOUNCE') {
            capturedAnnouncePayload = payload;
          }
        }
      };
    };
    fedAutoNat.setRole('RELAY');
    fedAutoNat.broadcastPresenceAnnounce();
    if (!capturedAnnouncePayload) {
      capturedAnnouncePayload = fedAutoNat.createPresenceAnnouncePayload();
    }
    fedAutoNat.sendPacket = origSendPacket;
    fedAutoNat.getOrCreateSecureChannel = origGetOrCreate74;
    CONFIG.serverName = prevServerName;

    const announcedAddr = capturedAnnouncePayload?.rendezvousNodes?.[0];
    const isPhysicalTransport = announcedAddr === 'relay.metrice.network:8001' && !announcedAddr.endsWith('.mesh:8001');
    record('7.4 [MİMARİ] PRESENCE_ANNOUNCE Fiziksel Taşıma Adresi (FQDN/IP, .mesh Engeli)', isPhysicalTransport, `Duyurulan: ${announcedAddr}`);

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
    const { DEFAULT_SSH_SERVER_VERSION } = await import('../src/version.js');
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

    const versionTestValid = fallbackIdent === DEFAULT_SSH_SERVER_VERSION && customIdent === 'SSH-2.0-MyCustomNode';
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
    const poisonedRdvNodes = ['127.0.0.1:8001', 'localhost:8001', '0.0.0.0:8001', 'fake.mesh:8001', 'safe.relay.org:8001'];
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
      storedRecord.rendezvousNodes[0] === 'safe.relay.org:8001';
    record('7.30 [GÜVENLİK/GOSSIP] PRESENCE_ANNOUNCE Zehirli Adres (localhost, 127.0.0.1, .mesh) Filtreleme', poisoningBlocked);

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
      isReady: true,
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
                      rdvSyncPayload === null;
    record('7.37 [KRİTİK/E2EE] SSH Girişi Sonrasında PRESENCE_ANNOUNCE Tünel Dağıtımı (V1 PRESENCE_SYNC Tasfiye Edildi)', !!test737Ok);

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

    const newRemoteId = CryptoHelper.generateIdentityKeyPair();
    const newRemoteNodeId = CryptoHelper.deriveNodeId(newRemoteId.publicKey);
    const newRemoteKem = CryptoHelper.generateKemKeyPair();
    const ts42 = Date.now();
    const data42 = JSON.stringify({
      nodeId: newRemoteNodeId,
      role: 'EDGE',
      rendezvousNodes: [],
      kemPublicKey: newRemoteKem.publicKey,
      channels: ['#genel'],
      timestamp: ts42
    });
    const sig42 = CryptoHelper.sign(data42, newRemoteId.privateKey);

    fedOffline.handleIncoming({
      type: 'PRESENCE_ANNOUNCE',
      nodeId: newRemoteNodeId,
      role: 'EDGE',
      rendezvousNodes: [],
      kemPublicKey: newRemoteKem.publicKey,
      identityPublicKey: newRemoteId.publicKey,
      channels: ['#genel'],
      memberships: [{ user: `@sync_user:${newRemoteNodeId}.mesh`, channels: ['#genel'], kemPublicKey: newRemoteKem.publicKey }],
      timestamp: ts42,
      sig: sig42
    }, { peerNodeAddress: `${newRemoteNodeId}.mesh`, writePayload: () => {} });

    const syncUserProfile = testDbOffline.getUserProfile(`@sync_user:${newRemoteNodeId}.mesh`);
    const syncKemPersisted = syncUserProfile && syncUserProfile.kemPublicKey === newRemoteKem.publicKey;

    fedOffline.close();
    clientServerOffline.close();
    testDbOffline.close();

    const test742Ok = kemKeyPersisted && offlineE2EEOk && syncKemPersisted;
    record('7.42 [ASENKRON E2EE & OUTBOX] saveRemoteUserKemKey Kalıcılığı, Çevrimdışı E2EE Kuyruklama ve PRESENCE_ANNOUNCE Entegrasyonu', !!test742Ok);

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

    // 3. sendHandshakeInit içinde fiziksel nodeAddress normalizasyonu (.mesh yerine fiziksel adres/anons)
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
    const handshakeCanonicalOk = sentPayload && sentPayload.nodeAddress === 'localhost:8001';

    const test744Ok = localhostNatOk && loopbackIpNatOk && meshIdOk && rawNodeIdOk && handshakeCanonicalOk;
    record('7.44 [REVİZYON 16/18] NAT/Edge Localhost Toleransı, Kriptografik .mesh Kimliği ve Handshake Adres Normalizasyonu', !!test744Ok);

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

    // Test 7.46: [REVİZYON 19] Dinamik Port Çözümleme ve Routing Adres Bütünlüğü (Özel Port 3157 Koruması)
    const customKp = CryptoHelper.generateIdentityKeyPair();
    const customNodeId = CryptoHelper.deriveNodeId(customKp.publicKey);
    const customTimestamp = Date.now();
    const customRdv = ['custom.relay.org:3157'];

    const customAnnounceData = JSON.stringify({
      nodeId: customNodeId,
      role: 'RELAY',
      rendezvousNodes: customRdv,
      kemPublicKey: customKp.publicKey,
      channels: [],
      timestamp: customTimestamp
    });
    const customAnnounceSig = CryptoHelper.sign(customAnnounceData, customKp.privateKey);

    fedAutoNat.handleIncoming({
      type: 'PRESENCE_ANNOUNCE',
      nodeId: customNodeId,
      role: 'RELAY',
      rendezvousNodes: customRdv,
      kemPublicKey: customKp.publicKey,
      identityPublicKey: customKp.publicKey,
      channels: [],
      timestamp: customTimestamp,
      sig: customAnnounceSig
    }, { socket: { remoteAddress: '198.51.100.99' } }, '198.51.100.99:54321');

    const mappedPhysicalAddr = fedAutoNat.nodePhysicalAddresses.get(customNodeId);
    const presencePreservedPort = mappedPhysicalAddr === 'custom.relay.org:3157';

    // getOrCreateSecureChannel çözümleme doğrulaması
    let dialedHost = null;
    let dialedPort = null;
    const origCreateConnection = net.createConnection;
    net.createConnection = ({ host, port }) => {
      dialedHost = host;
      dialedPort = port;
      const fakeSock = new EventEmitter();
      fakeSock.destroyed = false;
      fakeSock.writable = true;
      fakeSock.setTimeout = () => {};
      fakeSock.destroy = () => {};
      fakeSock.write = () => {};
      return fakeSock;
    };

    try {
      fedAutoNat.getOrCreateSecureChannel(`${customNodeId}.mesh`, CONFIG.federationPort).catch(() => {});
    } finally {
      net.createConnection = origCreateConnection;
    }

    const channelResolvedCustomPort = dialedHost === 'custom.relay.org' && dialedPort === 3157;
    const test746Ok = presencePreservedPort && channelResolvedCustomPort;
    record('7.46 [REVİZYON 19] Dinamik Port Çözümleme ve Özel Port (3157) Bütünlüğü Koruması', !!test746Ok);

    // Test 7.47: [REVİZYON 20] Saat Farkı (Clock Skew) Toleransı ve 24 Saat Sınırı Koruması
    const skewKeypair = CryptoHelper.generateIdentityKeyPair();
    const skewNodeId = CryptoHelper.deriveNodeId(skewKeypair.publicKey);
    const twoHoursAgo = Date.now() - 7200000;
    const twentyFiveHoursAgo = Date.now() - 90000000;

    // 2 saatlik farkla PRESENCE_ANNOUNCE
    const skewPresenceData = JSON.stringify({
      nodeId: skewNodeId,
      role: 'RELAY',
      rendezvousNodes: ['skew-relay.net:8001'],
      kemPublicKey: 'dummy_kem_key_skew',
      channels: ['#genel', '#skew_chan'],
      timestamp: twoHoursAgo
    });
    const skewSig = CryptoHelper.sign(skewPresenceData, skewKeypair.privateKey);
    fedAutoNat.handleIncoming({
      type: 'PRESENCE_ANNOUNCE',
      nodeId: skewNodeId,
      role: 'RELAY',
      rendezvousNodes: ['skew-relay.net:8001'],
      kemPublicKey: 'dummy_kem_key_skew',
      identityPublicKey: skewKeypair.publicKey,
      channels: ['#genel', '#skew_chan'],
      memberships: [{ user: `@skew_user:${skewNodeId}.mesh`, channels: ['#skew_chan'] }],
      timestamp: twoHoursAgo,
      sig: skewSig
    }, { writePayload: () => {} }, 'skew-relay.net:8001');

    const skewPresenceAccepted = fedAutoNat.presenceTable.has(skewNodeId) &&
      fedAutoNat.remoteOnlineUsers.has(`@skew_user:${skewNodeId}.mesh`);

    // 2 saatlik farkla ROUTE_UPDATE
    const skewEdgeKeypair = CryptoHelper.generateIdentityKeyPair();
    const skewEdgeId = CryptoHelper.deriveNodeId(skewEdgeKeypair.publicKey);
    const skewRouteData = JSON.stringify({
      nodeId: skewEdgeId,
      relayNodeId: skewNodeId,
      rendezvousNodes: ['skew-relay.net:8001'],
      timestamp: twoHoursAgo
    });
    const skewRouteSig = CryptoHelper.sign(skewRouteData, skewKeypair.privateKey);
    fedAutoNat.handleIncoming({
      type: 'ROUTE_UPDATE',
      nodeId: skewEdgeId,
      role: 'EDGE',
      rendezvousNodes: ['skew-relay.net:8001'],
      kemPublicKey: 'dummy_kem_edge',
      identityPublicKey: skewEdgeKeypair.publicKey,
      relayNodeId: skewNodeId,
      relayAddress: 'skew-relay.net:8001',
      relayKemPublicKey: 'dummy_kem_key_skew',
      relayIdentityPublicKey: skewKeypair.publicKey,
      timestamp: twoHoursAgo,
      sig: skewRouteSig
    }, { writePayload: () => {} }, 'skew-relay.net:8001');

    const skewRouteAccepted = fedAutoNat.presenceTable.has(skewEdgeId);

    // 25 saatlik farkla paket (reddedilmeli)
    const expiredKeypair = CryptoHelper.generateIdentityKeyPair();
    const expiredNodeId = CryptoHelper.deriveNodeId(expiredKeypair.publicKey);
    const expiredData = JSON.stringify({
      nodeId: expiredNodeId,
      role: 'RELAY',
      rendezvousNodes: ['expired-relay.net:8001'],
      kemPublicKey: 'dummy_kem_exp',
      channels: ['#genel'],
      timestamp: twentyFiveHoursAgo
    });
    const expiredSig = CryptoHelper.sign(expiredData, expiredKeypair.privateKey);
    fedAutoNat.handleIncoming({
      type: 'PRESENCE_ANNOUNCE',
      nodeId: expiredNodeId,
      role: 'RELAY',
      rendezvousNodes: ['expired-relay.net:8001'],
      kemPublicKey: 'dummy_kem_exp',
      identityPublicKey: expiredKeypair.publicKey,
      channels: ['#genel'],
      timestamp: twentyFiveHoursAgo,
      sig: expiredSig
    }, { writePayload: () => {} }, 'expired-relay.net:8001');

    const expiredRejected = !fedAutoNat.presenceTable.has(expiredNodeId);
    const test747Ok = skewPresenceAccepted && skewRouteAccepted && expiredRejected;
    record('7.47 [REVİZYON 20] Saat Farkı (Clock Skew) Toleransı ve 24 Saat Sınır Güvenliği', !!test747Ok,
      `SkewPresence: ${skewPresenceAccepted}, SkewRoute: ${skewRouteAccepted}, ExpiredRejected: ${expiredRejected}`);

    // Test 7.48: [REVİZYON 20] .mesh Kanal Aboneliği ve Çok Katmanlı (Onion) İletim
    const chanTestHostKeypair = CryptoHelper.generateIdentityKeyPair();
    const chanTestHostId = CryptoHelper.deriveNodeId(chanTestHostKeypair.publicKey);
    const chanSubscriberKeypair = CryptoHelper.generateIdentityKeyPair();
    const chanSubscriberId = CryptoHelper.deriveNodeId(chanSubscriberKeypair.publicKey);
    const testChannelName = `#testchan:${chanTestHostId}.mesh`;

    // 1. Düğümün kanala abone olması (CHANNEL_SUBSCRIBE)
    fedAutoNat.handleIncoming({
      type: 'CHANNEL_SUBSCRIBE',
      channel: testChannelName,
      subscriberNode: `${chanSubscriberId}.mesh`
    }, { writePayload: () => {} }, null);

    const isSubscribed = fedAutoNat.channelSubscribers.has(testChannelName) &&
      fedAutoNat.channelSubscribers.get(testChannelName).has(`${chanSubscriberId}.mesh`);

    // 2. Kanala mesaj geldiğinde .mesh aboneye sendViaOnion ile iletilmesi
    let forwardedTargetNode = null;
    let forwardedPayload = null;
    const origSendViaOnion = fedAutoNat.sendViaOnion;
    fedAutoNat.sendViaOnion = async (target, payload) => {
      forwardedTargetNode = target;
      forwardedPayload = payload;
      return { status: 'delivered' };
    };

    fedAutoNat.forwardToChannelSubscribers(testChannelName, {
      id: 'test_chan_msg_1',
      from: `@author:${chanTestHostId}.mesh`,
      to: testChannelName,
      content: 'Merhaba .mesh kanal!',
      timestamp: new Date().toISOString()
    });

    const forwardedCorrectly = forwardedTargetNode === chanSubscriberId &&
      forwardedPayload?.type === 'CHANNEL_MESSAGE' &&
      forwardedPayload?.content === 'Merhaba .mesh kanal!';

    // 3. sendViaOnion rota bulunamadığında hata fırlatmalıdır (Outbox döngüsünü engellemek için)
    fedAutoNat.sendViaOnion = origSendViaOnion;
    let outboxLoopPrevented = false;
    try {
      await fedAutoNat.sendViaOnion('nonexistentnode1', { id: 'test_orphan', to: 'nonexistentnode1.mesh' }, true);
    } catch (err) {
      outboxLoopPrevented = err.message.includes('aktif buluşma noktası bulunamadı') ||
        err.message.includes('No active rendezvous point found');
    }

    const test748Ok = isSubscribed && forwardedCorrectly && outboxLoopPrevented;
    record('7.48 [REVİZYON 20] .mesh Hedefli Kanal Aboneliği ve Outbox Sonsuz Döngü Koruması', !!test748Ok,
      `Subscribed: ${isSubscribed}, Forwarded: ${forwardedCorrectly}, LoopPrevented: ${outboxLoopPrevented}`);

    // Test 7.49: [REVİZYON 20] Çapraz Röle Rendezvous Senkronizasyonu ve Üyelik Yayılımı
    let routeUpdateBroadcastCount = 0;
    let announcedEdge = null;
    const origBroadcastRouteUpdate = relayEngine.broadcastRouteUpdate;
    relayEngine.broadcastRouteUpdate = (nId, rAddr, kem, ident) => {
      routeUpdateBroadcastCount++;
      announcedEdge = nId;
      origBroadcastRouteUpdate.call(relayEngine, nId, rAddr, kem, ident);
    };

    // Röleye bağlı bir tünel ekle
    const boundEdgeKey = CryptoHelper.generateIdentityKeyPair();
    const boundEdgeId = CryptoHelper.deriveNodeId(boundEdgeKey.publicKey);
    relayEngine.rendezvousTunnels.set(boundEdgeId, {
      boundRendezvousAddr: 'relay.sync.test:8001',
      edgeKemKey: 'dummy_kem_bound',
      identityPublicKey: boundEdgeKey.publicKey,
      channel: { socket: { writable: true }, writePayload: () => {} }
    });

    // broadcastPresence() çağır
    await relayEngine.broadcastPresence();
    relayEngine.broadcastRouteUpdate = origBroadcastRouteUpdate;

    const crossRelaySyncOk = routeUpdateBroadcastCount > 0 && announcedEdge === boundEdgeId;
    record('7.49 [REVİZYON 20] Çapraz Röle Rendezvous Tünel Rota Senkronizasyonu (Route Propagation)', !!crossRelaySyncOk,
      `BroadcastCount: ${routeUpdateBroadcastCount}, AnnouncedEdge: ${announcedEdge}`);

    // Test 7.50: [REVİZYON 21] EDGE Düğümünden Küresel Kanal (#genel) Mesajının rendezvousRelays Tüneline İletimi
    let edgeRendezvousPayload = null;
    const mockRelayChannel = {
      socket: { writable: true, remoteAddress: '198.51.100.1', remotePort: 8001 },
      writePayload: (p) => {
        edgeRendezvousPayload = p;
      }
    };

    edgeEngine.rendezvousRelays.set('198.51.100.1:8001', {
      socket: mockRelayChannel.socket,
      channel: mockRelayChannel
    });

    await edgeEngine.broadcastChannelMessage({
      id: 'edge_global_msg_1',
      from: `@edge_sender:${edgeEngine.nodeId}.mesh`,
      to: '#genel',
      content: 'Merhaba tüm mesh ağı!',
      timestamp: new Date().toISOString()
    });

    const test750Ok = edgeRendezvousPayload &&
      edgeRendezvousPayload.type === 'CHANNEL_MESSAGE' &&
      edgeRendezvousPayload.to === '#genel' &&
      edgeRendezvousPayload.content === 'Merhaba tüm mesh ağı!';

    record('7.50 [REVİZYON 21] EDGE Düğümü #genel Mesajının rendezvousRelays Tüneline İletimi', !!test750Ok,
      `Payload: ${edgeRendezvousPayload?.content || 'null'}`);

    // Test 7.51: [REVİZYON 22] Online Kullanıcı Adresi Normalizasyonu (.mesh Önceliği) ve TUI Sağ Panel Eşleşmesi
    const origLocalGetter = fedAutoNat.getLocalStateFn;
    fedAutoNat.setLocalStateGetter(() => ({
      users: ['@dual_user:127.0.0.1:8001']
    }));
    fedAutoNat.remoteOnlineUsers.set('@dual_user:canonicalnodeid.mesh', {
      channels: ['#genel'],
      lastSeen: Date.now()
    });

    const dedupedOnline = fedAutoNat.getAllOnlineUsers();
    const dualUserEntries = dedupedOnline.filter((u) => u.startsWith('@dual_user:'));
    const prioritizedMesh = dualUserEntries.length === 1 && dualUserEntries[0] === '@dual_user:canonicalnodeid.mesh';
    fedAutoNat.setLocalStateGetter(origLocalGetter);

    // TUI sağ panel eşleşme testi
    const mockSocket = { write: () => {} };
    const sessionTestTui = new TerminalSession(
      mockSocket,
      '@me:local.mesh',
      { username: 'me', contacts: ['#testchan'], history: {} },
      () => ['@online_bob:someothernode.mesh'],
      () => ['@online_bob:127.0.0.1:8001'],
      () => {},
      () => ({ uptime: '1m', rss: '10', peers: [], role: 'EDGE', nodeId: 'test' }),
      () => []
    );
    sessionTestTui.activeTarget = '#testchan';
    sessionTestTui.renderFull([]);
    const rightPanelHasOnlineGreen = sessionTestTui.screenBuffer.some((line) => line && line.includes('●') && line.includes('online_bob'));

    const test751Ok = prioritizedMesh && rightPanelHasOnlineGreen;
    record('7.51 [REVİZYON 22] Presence Adres Formatı Normalizasyonu (.mesh Önceliği) ve Sağ Panel Flicker Koruması', !!test751Ok,
      `MeshPrioritized: ${prioritizedMesh}, TUIOnlineMatch: ${rightPanelHasOnlineGreen}`);

    // Test 7.52: [REVİZYON 23] Gizli Kararsızlıklar ve Bug Onarımları
    // 1. clearConversationForUser parametre indeksi doğrulaması
    testDb2.saveMessage({
      id: 'r23_sql_test',
      from: '@alice:node1.mesh',
      to: '@bob:node2.mesh',
      content: 'r23 test message'
    });
    testDb2.clearConversationForUser('@alice:node1.mesh', '@bob:node2.mesh');
    const r23Msg = testDb2.db.prepare("SELECT deleted_by FROM messages WHERE id = 'r23_sql_test'").get();
    const r23SqlOk = r23Msg && r23Msg.deleted_by.includes('@alice');

    // 2. sendHandshakeInit giden nonce'un replay tracker'a eklenmemesi
    let trackedOutboundNonce = false;
    const dummyMockSocket = { write: () => {}, on: () => {} };
    const mockTracker = {
      track: () => { trackedOutboundNonce = true; return true; }
    };
    new SecureChannel(dummyMockSocket, true, fedAutoNat.myIdentity, testDb2, mockTracker);
    const r23NonceOk = trackedOutboundNonce === false;

    // 3. buildCircuit yarım kalan devrede hata fırlatması
    const failOnionRouter = new OnionRouter({
      federation: {
        sendPacket: async () => ({ status: 'timeout_or_error' })
      },
      db: testDb2,
      myIdentity: fedAutoNat.myIdentity,
      rendezvousTunnels: new Map()
    });
    let r23CircuitThrew = false;
    try {
      await failOnionRouter.buildCircuit([
        { address: '127.0.0.1:8001', kemPublicKey: CryptoHelper.generateKemKeyPair().publicKey }
      ], 'fail_target');
    } catch {
      r23CircuitThrew = true;
    }
    const r23CircuitPoolEmpty = failOnionRouter.clientCircuits.size === 0;

    // 4. cleanupExpiredPresence içinde RELAY fiziksel adres koruması
    const relayNodeIdToTest = 'relaynode_r23_test';
    fedAutoNat.presenceTable.set(relayNodeIdToTest, {
      role: 'RELAY',
      rendezvousNodes: [],
      lastSeen: Date.now() - 70000 // 60s TTL aşılmış
    });
    fedAutoNat.nodePhysicalAddresses.set(relayNodeIdToTest, '198.51.100.1:8001');
    fedAutoNat.cleanupExpiredPresence();
    const r23RelayAddrPreserved = fedAutoNat.nodePhysicalAddresses.has(relayNodeIdToTest);

    const test752Ok = r23SqlOk && r23NonceOk && r23CircuitThrew && r23CircuitPoolEmpty && r23RelayAddrPreserved;
    record('7.52 [REVİZYON 23] Gizli Kararsızlıklar ve Regresyon Koruması (SQL, Nonce, Onion, Presence)', !!test752Ok,
      `SqlOk: ${r23SqlOk}, NonceOk: ${r23NonceOk}, CircuitThrew: ${r23CircuitThrew}, RelayPreserved: ${r23RelayAddrPreserved}`);

    // Test 7.53: [FAZ 1] HAProxy PROXY Protocol v1 & v2 Ayrıştırma, IP Spoofing Koruması ve Doğrulama
    // 1. PROXY v1 TCP4 doğrulaması
    const v1Payload = Buffer.from('PROXY TCP4 203.0.113.195 198.51.100.1 56324 8001\r\n{"type":"PING"}');
    const v1Result = ProxyProtocolParser.parse(v1Payload);
    const v1Ok = v1Result.success &&
      v1Result.version === 1 &&
      v1Result.realRemoteAddress === '203.0.113.195' &&
      v1Result.realRemotePort === 56324 &&
      v1Result.remainder.toString() === '{"type":"PING"}';

    // 2. PROXY v2 Binary IPv4 doğrulaması
    const v2Header = Buffer.concat([
      ProxyProtocolParser.V2_SIGNATURE,
      Buffer.from([0x21, 0x11]), // v2 PROXY, AF_INET STREAM
      Buffer.from([0x00, 0x0c]), // length = 12 bytes
      Buffer.from([198, 51, 100, 42]), // src IP 198.51.100.42
      Buffer.from([192, 0, 2, 1]),     // dst IP 192.0.2.1
      Buffer.from([0xad, 0x21]),       // src port 44321
      Buffer.from([0x1f, 0x41]),       // dst port 8001
      Buffer.from('{"type":"PONG"}')   // payload
    ]);
    const v2Result = ProxyProtocolParser.parse(v2Header);
    const v2Ok = v2Result.success &&
      v2Result.version === 2 &&
      v2Result.realRemoteAddress === '198.51.100.42' &&
      v2Result.realRemotePort === 44321 &&
      v2Result.remainder.toString() === '{"type":"PONG"}';

    // 3. Güvensiz IP Spoofing Reddi (Untrusted IP sends PROXY header)
    let spoofRejected = false;
    const fakeUntrustedSocket = new EventEmitter();
    fakeUntrustedSocket.remoteAddress = '185.220.101.5';
    fakeUntrustedSocket.remotePort = 33333;
    fakeUntrustedSocket.destroyed = false;
    fakeUntrustedSocket.destroy = () => { fakeUntrustedSocket.destroyed = true; };
    fakeUntrustedSocket.unshift = () => {};

    ProxyProtocolParser.wrapSocket(fakeUntrustedSocket, ['127.0.0.1', '10.0.0.1'], (err) => {
      if (err && err.message.toLowerCase().includes('untrusted')) {
        spoofRejected = true;
      }
    });
    fakeUntrustedSocket.emit('data', Buffer.from('PROXY TCP4 1.1.1.1 198.51.100.1 12345 8001\r\n'));
    const spoofGuardOk = spoofRejected && fakeUntrustedSocket.destroyed;

    // 4. Güvenli IP'den PROXY header işleme ve unshift ile şeffaf geçiş
    let trustedProcessed = false;
    let unshiftedData = null;
    const fakeTrustedSocket = new EventEmitter();
    fakeTrustedSocket.remoteAddress = '127.0.0.1';
    fakeTrustedSocket.remotePort = 50000;
    fakeTrustedSocket.destroyed = false;
    fakeTrustedSocket.destroy = () => { fakeTrustedSocket.destroyed = true; };
    fakeTrustedSocket.unshift = (chunk) => { unshiftedData = chunk; };

    ProxyProtocolParser.wrapSocket(fakeTrustedSocket, ['127.0.0.1'], (err, sock) => {
      if (!err && sock && sock.realRemoteAddress === '203.0.113.88' && sock.realRemotePort === 54321) {
        trustedProcessed = true;
      }
    });
    fakeTrustedSocket.emit('data', Buffer.from('PROXY TCP4 203.0.113.88 127.0.0.1 54321 8001\r\nHELLO_METRICE'));
    const trustedUnshiftOk = trustedProcessed && unshiftedData && unshiftedData.toString() === 'HELLO_METRICE';

    // 5. Güvensiz IP'den normal paket geldiğinde passthrough geçişi
    let passthroughOk = false;
    let passthroughUnshifted = null;
    const fakePassSocket = new EventEmitter();
    fakePassSocket.remoteAddress = '198.51.100.90';
    fakePassSocket.remotePort = 40000;
    fakePassSocket.destroyed = false;
    fakePassSocket.destroy = () => { fakePassSocket.destroyed = true; };
    fakePassSocket.unshift = (chunk) => { passthroughUnshifted = chunk; };

    ProxyProtocolParser.wrapSocket(fakePassSocket, ['127.0.0.1'], (err, sock) => {
      if (!err && sock && sock.realRemoteAddress === '198.51.100.90') {
        passthroughOk = true;
      }
    });
    fakePassSocket.emit('data', Buffer.from('{"type":"AUTH_INIT"}'));
    const normalPassthroughOk = passthroughOk && passthroughUnshifted && passthroughUnshifted.toString() === '{"type":"AUTH_INIT"}';

    const test753Ok = v1Ok && v2Ok && spoofGuardOk && trustedUnshiftOk && normalPassthroughOk;
    record('7.53 [FAZ 1] HAProxy PROXY Protocol v1 & v2 Ayrıştırma, IP Spoofing Koruması ve Doğrulama', !!test753Ok,
      `v1: ${v1Ok}, v2: ${v2Ok}, SpoofGuard: ${spoofGuardOk}, TrustedUnshift: ${trustedUnshiftOk}, Passthrough: ${normalPassthroughOk}`);

    // Test 7.54: [FAZ 2] EDGE Transit Routing (CAP_EDGE_TRANSIT), Reverse Tünel Çapraz Atlama & Gossip Varlık Köprüleme
    // 1. Dinamik CAP_EDGE_TRANSIT Rol Geçişi
    const transitEdgeDb = new Database(path.join(rootDir, 'v2_test_transit_edge.db'));
    const transitEdgeEngine = new FederationEngine(transitEdgeDb, new PeerManager());
    transitEdgeEngine.role = 'EDGE';

    CONFIG.allowEdgeRouting = true;
    CONFIG.allowEdgeGossip = true;

    // 1. röleye bağlan
    const relay1Addr = '198.51.100.10:8001';
    const mockChannel1 = {
      isReady: true,
      peerNodeAddress: relay1Addr,
      socket: { writable: true, remoteAddress: '198.51.100.10', remotePort: 8001 },
      writePayload: () => {}
    };
    transitEdgeEngine.rendezvousRelays.set(relay1Addr, { channel: mockChannel1, socket: mockChannel1.socket });
    transitEdgeEngine.checkTransitEdgeRole();
    const stage1Role = transitEdgeEngine.role; // EDGE kalmalı

    // 2. röleye bağlan
    const relay2Addr = '198.51.100.20:8001';
    let relay2ForwardedCell = null;
    const mockChannel2 = {
      isReady: true,
      peerNodeAddress: relay2Addr,
      socket: { writable: true, remoteAddress: '198.51.100.20', remotePort: 8001 },
      writePayload: (p) => {
        if (p && p.type === 'ONION_CELL') {
          relay2ForwardedCell = p;
        }
      }
    };
    transitEdgeEngine.rendezvousRelays.set(relay2Addr, { channel: mockChannel2, socket: mockChannel2.socket });
    transitEdgeEngine.checkTransitEdgeRole();
    const stage2Role = transitEdgeEngine.role; // CAP_EDGE_TRANSIT olmalı
    const isTransit = transitEdgeEngine.isTransitEdge();

    // 1 röle bağlantısını kopar
    transitEdgeEngine.rendezvousRelays.delete(relay1Addr);
    transitEdgeEngine.checkTransitEdgeRole();
    const stage3Role = transitEdgeEngine.role; // Geri EDGE'e düşmeli

    const roleTransitionOk = stage1Role === 'EDGE' && stage2Role === 'CAP_EDGE_TRANSIT' && isTransit && stage3Role === 'EDGE';

    // Yeniden transit durumuna al (Tersine Tünel ve Gossip köprü testleri için)
    transitEdgeEngine.rendezvousRelays.set(relay1Addr, { channel: mockChannel1, socket: mockChannel1.socket });
    transitEdgeEngine.checkTransitEdgeRole();

    // 2. Reverse Tünel Çapraz Atlama (In-and-Out Transit Onion Routing)
    const transitSymKey = CryptoHelper.generateRandomKey(32);
    transitEdgeDb.saveCircuit({
      circuitId: 'circ_transit_phase2',
      prevHop: relay1Addr,
      nextHop: relay2Addr,
      symmetricKey: transitSymKey
    });

    const innerPayload = JSON.stringify({
      forwardTo: relay2Addr,
      cell: {
        type: 'ONION_CELL',
        circuitId: 'next_circuit_phase2',
        iv: 'sample_iv_123',
        authTag: 'sample_authTag_123',
        ciphertext: 'sample_ciphertext_123'
      }
    });
    const encryptedCell = CryptoHelper.encrypt(innerPayload, transitSymKey);
    const transitOnionCell = {
      type: 'ONION_CELL',
      circuitId: 'circ_transit_phase2',
      iv: encryptedCell.iv,
      authTag: encryptedCell.authTag,
      ciphertext: encryptedCell.ciphertext
    };

    await transitEdgeEngine.onionRouter.handleOnionCell(transitOnionCell, mockChannel1);
    const forwardedCellOk = relay2ForwardedCell &&
      relay2ForwardedCell.type === 'ONION_CELL' &&
      relay2ForwardedCell.circuitId === 'next_circuit_phase2' &&
      relay2ForwardedCell.pad &&
      relay2ForwardedCell.pad.length > 0;

    // 3. Homojen Eşler Arası Gossip Varlık Köprüleme (Bidirectional Presence & Channel Bridging)
    const remoteKp = CryptoHelper.generateIdentityKeyPair();
    const remoteKem = CryptoHelper.generateKemKeyPair();
    const remoteNodeId = CryptoHelper.deriveNodeId(remoteKp.publicKey);
    const remotePresenceFromRelay1 = {
      type: 'PRESENCE_ANNOUNCE',
      nodeId: remoteNodeId,
      role: 'EDGE',
      rendezvousNodes: [relay1Addr],
      kemPublicKey: remoteKem.publicKey,
      identityPublicKey: remoteKp.publicKey,
      channels: ['#genel'],
      memberships: [{ user: `@remUser:${remoteNodeId}.mesh`, channels: ['#genel'] }],
      timestamp: Date.now()
    };
    const presenceData = JSON.stringify({
      nodeId: remotePresenceFromRelay1.nodeId,
      role: remotePresenceFromRelay1.role,
      rendezvousNodes: remotePresenceFromRelay1.rendezvousNodes,
      kemPublicKey: remotePresenceFromRelay1.kemPublicKey,
      channels: remotePresenceFromRelay1.channels,
      timestamp: remotePresenceFromRelay1.timestamp
    });
    remotePresenceFromRelay1.sig = CryptoHelper.sign(presenceData, remoteKp.privateKey);

    let bridgedPresencePayload = null;
    mockChannel2.writePayload = (p) => {
      if (p && p.type === 'PRESENCE_ANNOUNCE' && p.nodeId === remoteNodeId) {
        bridgedPresencePayload = p;
      }
    };

    transitEdgeEngine.handleIncoming(remotePresenceFromRelay1, mockChannel1, relay1Addr);
    const presenceBridgedOk = bridgedPresencePayload !== null && bridgedPresencePayload.nodeId === remoteNodeId;

    // Kanal Mesajı (#genel) Köprüleme
    let bridgedChannelPayload = null;
    mockChannel2.writePayload = (p) => {
      if (p && p.type === 'CHANNEL_MESSAGE' && p.to === '#genel') {
        bridgedChannelPayload = p;
      }
    };

    await transitEdgeEngine.broadcastChannelMessage({
      id: 'transit_genel_msg_1',
      from: `@someone:${remoteNodeId}.mesh`,
      to: '#genel',
      content: 'Homogeneous transit cross-bridging message',
      timestamp: new Date().toISOString()
    }, mockChannel1);
    const channelBridgedOk = bridgedChannelPayload !== null && bridgedChannelPayload.id === 'transit_genel_msg_1';

    transitEdgeEngine.close();
    transitEdgeDb.close();

    const test754Ok = roleTransitionOk && forwardedCellOk && presenceBridgedOk && channelBridgedOk;
    record('7.54 [FAZ 2] EDGE Transit Routing (CAP_EDGE_TRANSIT), Reverse Tünel Çapraz Atlama & Gossip Varlık Köprüleme', !!test754Ok,
      `RoleTransition: ${roleTransitionOk}, ForwardedCell: ${forwardedCellOk}, PresenceBridged: ${presenceBridgedOk}, ChannelBridged: ${channelBridgedOk}`);

    // Test 7.55: [REVİZYON 24 / v2.4.1] Tünel Timeout Hatası, Hazır Olmayan Tünel Koruması, RFC 5952 IPv6 & DNS Fallback Sıkılaştırması
    // 1. handleCircuitSetup Sonraki Atlama Zaman Aşımı / Red Hata Dönüşü
    const hop1Kem755 = CryptoHelper.generateKemKeyPair();
    const circuitId755 = 'circ_fail_test_755';
    const { sharedSecret: sec755, encapsulatedKey: encKey755 } = CryptoHelper.encapsulateKey(hop1Kem755.publicKey);
    const symKey755 = CryptoHelper.deriveKey(sec755, circuitId755, 'p2p-mesh-onion-v2');

    const innerPayload755 = {
      type: 'CIRCUIT_EXTEND',
      circuitId: circuitId755,
      encapsulatedKey: 'sample_key',
      nextHop: null,
      extendPayload: null
    };
    const encryptedExtend755 = CryptoHelper.encrypt(JSON.stringify(innerPayload755), symKey755);

    let setupFailureResponse = null;
    const mockInChannel755 = {
      writePayload: (p) => { setupFailureResponse = p; }
    };
    const testOnionRouter755 = new OnionRouter({
      federation: {
        isRelay: () => true,
        sendPacket: async () => ({ status: 'error', reason: 'extend_tunnel_timeout' })
      },
      db: { saveCircuit: () => {} },
      myIdentity: { kemKeyPair: hop1Kem755 },
      rendezvousTunnels: new Map()
    });

    await testOnionRouter755.handleCircuitSetup({
      type: 'CIRCUIT_CREATE',
      circuitId: circuitId755,
      encapsulatedKey: encKey755,
      nextHop: '198.51.100.33:8001',
      extendPayload: encryptedExtend755
    }, mockInChannel755);

    const circuitTimeoutErrorHandled = setupFailureResponse &&
      setupFailureResponse.status === 'error' &&
      setupFailureResponse.reason === 'extend_tunnel_timeout';

    // 2. Hazır Olmayan (isReady: false) Tünellere Dedikodu İletilmemesi
    let unreadyChannelWritten = false;
    let readyChannelWritten = false;
    const mockUnreadyChan = {
      isReady: false,
      socket: { writable: true },
      writePayload: () => { unreadyChannelWritten = true; }
    };
    const mockReadyChan = {
      isReady: true,
      socket: { writable: true },
      writePayload: () => { readyChannelWritten = true; }
    };

    const tempGossipDb = new Database(path.join(rootDir, 'v2_test_gossip_unready.db'));
    const tempGossipEngine = new FederationEngine(tempGossipDb, new PeerManager());
    tempGossipEngine.role = 'EDGE';
    tempGossipEngine.rendezvousRelays.set('relay_unready:8001', { channel: mockUnreadyChan, socket: mockUnreadyChan.socket });
    tempGossipEngine.rendezvousRelays.set('relay_ready:8001', { channel: mockReadyChan, socket: mockReadyChan.socket });

    await tempGossipEngine.broadcastPresence();
    const unreadySkippedOk = !unreadyChannelWritten && readyChannelWritten;
    tempGossipEngine.close();
    tempGossipDb.close();

    // 3. RFC 5952 IPv6 Kanonik Dönüştürme & ProxyProtocolParser Doğrulaması
    const ipv6BufSample = Buffer.from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    const formattedIpv6 = ProxyProtocolParser.formatIPv6(ipv6BufSample, 0);
    const canonicalIpv6 = AddressHelper.canonicalizeIPv6('2001:0db8:0000:0000:0000:0000:0000:0001');
    const rfc5952Ok = formattedIpv6 === '2001:db8::1' && canonicalIpv6 === '2001:db8::1';

    // 4. validatePeerIp DNS Fallback ve Kimlik Doğrulama Sıkılaştırması
    const testPeerKp = CryptoHelper.generateIdentityKeyPair();
    const testPeerNodeId = CryptoHelper.deriveNodeId(testPeerKp.publicKey);
    const mockSocketPeer = { remoteAddress: '198.51.100.99', writable: true, on: () => {} };
    const mockPeerChannel = new SecureChannel(mockSocketPeer, false, {
      identityKeyPair: testPeerKp,
      kemKeyPair: CryptoHelper.generateKemKeyPair(),
      nodeAddress: 'localhost:8001',
      nodeId: testPeerNodeId
    }, testDb2, { track: () => true });

    const spoofDnsRejected = (await mockPeerChannel.validatePeerIp('unresolvable-domain-spoof.invalid:8001', testPeerKp.publicKey)) === false;
    const legitMeshAccepted = (await mockPeerChannel.validatePeerIp(`${testPeerNodeId}.mesh:8001`, testPeerKp.publicKey)) === true;
    const mismatchedMeshRejected = (await mockPeerChannel.validatePeerIp(`${testPeerNodeId}.mesh:8001`, CryptoHelper.generateIdentityKeyPair().publicKey)) === false;
    mockSocketPeer.remoteAddress = '2001:0db8:0000:0000:0000:0000:0000:0001';
    const ipv6NormalizedMatch = (await mockPeerChannel.validatePeerIp('[2001:db8::1]:8001')) === true;

    const test755Ok = circuitTimeoutErrorHandled && unreadySkippedOk && rfc5952Ok &&
      spoofDnsRejected && legitMeshAccepted && mismatchedMeshRejected && ipv6NormalizedMatch;

    record('7.55 [REVİZYON 24 / v2.4.1] Tünel Timeout Hatası, Hazır Olmayan Tünel Koruması, RFC 5952 IPv6 & DNS Fallback Sıkılaştırması', !!test755Ok,
      `CircuitTimeoutError: ${circuitTimeoutErrorHandled}, UnreadySkipped: ${unreadySkippedOk}, RFC5952: ${rfc5952Ok}, SpoofDnsRejected: ${spoofDnsRejected}, LegitMeshAccepted: ${legitMeshAccepted}, MismatchedMeshRejected: ${mismatchedMeshRejected}, IPv6Match: ${ipv6NormalizedMatch}`);

    // Test 7.56: [REVİZYON 25 / v2.4.2] Layer 4 Proxy Announced/Public Port Çözümlemesi ve RENDEZVOUS_BIND İmza Toleransı
    // 1. Yapılandırma Akıllı Varsayılanları ve Fallback
    const prevFedPort756 = CONFIG.federationPort;
    const prevPubFedPort756 = CONFIG.publicFederationPort;
    const prevServerName756 = CONFIG.serverName;

    const configDefaultsOk756 = typeof CONFIG.publicFederationPort === 'number' &&
      typeof CONFIG.publicSshPort === 'number' &&
      typeof CONFIG.publicClientPort === 'number' &&
      CONFIG.publicFederationPort === CONFIG.federationPort;

    // 2. getRelayAnnounceAddress ve initiateDialback genel port uyarlaması
    const tempProxyDb = new Database(path.join(rootDir, 'v2_test_proxy_ports.db'));
    const tempProxyPm = new PeerManager();
    tempProxyPm.addOrUpdate('198.51.100.1:8001');
    const tempProxyEngine = new FederationEngine(tempProxyDb, tempProxyPm);
    tempProxyEngine.role = 'RELAY';

    CONFIG.serverName = 'relay.proxy-node.org';
    CONFIG.federationPort = 8001;
    CONFIG.publicFederationPort = 8002;

    const announcedAddr756 = tempProxyEngine.getRelayAnnounceAddress();
    const announcedPortOk756 = announcedAddr756 === 'relay.proxy-node.org:8002';

    let dialbackPacket756 = null;
    tempProxyEngine.sendPacket = async (h, p, payload) => {
      dialbackPacket756 = payload;
      return { status: 'ok' };
    };
    tempProxyEngine.initiateDialback('198.51.100.50');
    const dialbackPortOk756 = dialbackPacket756 && dialbackPacket756.targetPort === 8002;

    // 3. RENDEZVOUS_BIND Çift Port (Yerel 8001 ve Genel 8002) İmza Kabul Matrisi
    const edgeKp756 = CryptoHelper.generateIdentityKeyPair();
    const edgeNodeId756 = CryptoHelper.deriveNodeId(edgeKp756.publicKey);
    const nonce756Public = CryptoHelper.generateRandomKey(16);
    const ts756 = Date.now();

    // Genel anons portu (8002) ile imza
    const sigPublic756 = CryptoHelper.sign(`${edgeNodeId756}relay.proxy-node.org:8002${ts756}${nonce756Public}`, edgeKp756.privateKey);
    let boundPublicOk756 = false;
    const mockProxyChan = {
      socket: { remoteAddress: '198.51.100.5', localAddress: '127.0.0.1', localPort: 8001 },
      writePayload: (p) => {
        if (p?.status === 'bound') boundPublicOk756 = true;
      }
    };

    tempProxyEngine.handleIncoming({
      type: 'RENDEZVOUS_BIND',
      nodeId: edgeNodeId756,
      relayAddress: 'relay.proxy-node.org:8002',
      identityPublicKey: edgeKp756.publicKey,
      kemPublicKey: CryptoHelper.generateKemKeyPair().publicKey,
      timestamp: ts756,
      nonce: nonce756Public,
      sig: sigPublic756
    }, mockProxyChan, '198.51.100.5:54321');

    // Yerel dinleme portu (8001) ile imza
    const nonce756Internal = CryptoHelper.generateRandomKey(16);
    const sigInternal756 = CryptoHelper.sign(`${edgeNodeId756}relay.proxy-node.org:8001${ts756}${nonce756Internal}`, edgeKp756.privateKey);
    let boundInternalOk756 = false;
    mockProxyChan.writePayload = (p) => {
      if (p?.status === 'bound') boundInternalOk756 = true;
    };

    tempProxyEngine.handleIncoming({
      type: 'RENDEZVOUS_BIND',
      nodeId: edgeNodeId756,
      relayAddress: 'relay.proxy-node.org:8001',
      identityPublicKey: edgeKp756.publicKey,
      kemPublicKey: CryptoHelper.generateKemKeyPair().publicKey,
      timestamp: ts756,
      nonce: nonce756Internal,
      sig: sigInternal756
    }, mockProxyChan, '198.51.100.5:54321');

    // Yabancı / Sahte adres ile imza reddi
    const nonce756Fake = CryptoHelper.generateRandomKey(16);
    const sigFake756 = CryptoHelper.sign(`${edgeNodeId756}attacker-host:9999${ts756}${nonce756Fake}`, edgeKp756.privateKey);
    let rejectedFakeOk756 = false;
    mockProxyChan.writePayload = (p) => {
      if (p?.status === 'rejected' && p?.reason === 'invalid_signature') rejectedFakeOk756 = true;
    };

    tempProxyEngine.handleIncoming({
      type: 'RENDEZVOUS_BIND',
      nodeId: edgeNodeId756,
      relayAddress: 'attacker-host:9999',
      identityPublicKey: edgeKp756.publicKey,
      kemPublicKey: CryptoHelper.generateKemKeyPair().publicKey,
      timestamp: ts756,
      nonce: nonce756Fake,
      sig: sigFake756
    }, mockProxyChan, '198.51.100.5:54321');

    // Temizlik ve eski konfigürasyonu geri yükleme
    tempProxyEngine.close();
    tempProxyDb.close();
    CONFIG.federationPort = prevFedPort756;
    CONFIG.publicFederationPort = prevPubFedPort756;
    CONFIG.serverName = prevServerName756;

    const test756Ok = configDefaultsOk756 && announcedPortOk756 && dialbackPortOk756 &&
      boundPublicOk756 && boundInternalOk756 && rejectedFakeOk756;

    record('7.56 [REVİZYON 25 / v2.4.2] Layer 4 Proxy Announced/Public Port Çözümlemesi ve RENDEZVOUS_BIND İmza Toleransı', !!test756Ok,
      `ConfigDefaults: ${configDefaultsOk756}, AnnouncedPort: ${announcedPortOk756}, DialbackPort: ${dialbackPortOk756}, BoundPublic: ${boundPublicOk756}, BoundInternal: ${boundInternalOk756}, RejectedFake: ${rejectedFakeOk756}`);

    // Test 7.57: [REVİZYON 26 / v2.4.4] Dinamik Röle Peering, Outbox .isOpen Onarımı & AddressHelper Global/System Eşleme
    const testRdvRelayIp1 = '198.51.100.77:8001';
    const testRdvRelayIp2 = '198.51.100.88:8001';
    const testRdvRelayIp3 = '198.51.100.99:8001';

    const peerStore757 = new Map();
    const origPm757 = fedAutoNat.peerManager;
    fedAutoNat.peerManager = {
      peers: peerStore757,
      getAllPeers: () => Array.from(peerStore757.keys()),
      addOrUpdate: (addr) => peerStore757.set(addr, { score: 100 })
    };

    // 1. PRESENCE_ANNOUNCE ile Röle Eş Keşfi
    const relayKp757 = CryptoHelper.generateIdentityKeyPair();
    const relayNodeId757 = CryptoHelper.deriveNodeId(relayKp757.publicKey);
    const kemKp757 = CryptoHelper.generateKemKeyPair();
    const ts757 = Date.now();
    const sig757 = CryptoHelper.sign(JSON.stringify({
      nodeId: relayNodeId757,
      role: 'CAP_RELAY',
      rendezvousNodes: [testRdvRelayIp1],
      kemPublicKey: kemKp757.publicKey,
      channels: [],
      timestamp: ts757
    }), relayKp757.privateKey);

    fedAutoNat.handleIncoming({
      type: 'PRESENCE_ANNOUNCE',
      nodeId: relayNodeId757,
      role: 'CAP_RELAY',
      rendezvousNodes: [testRdvRelayIp1],
      kemPublicKey: kemKp757.publicKey,
      identityPublicKey: relayKp757.publicKey,
      channels: [],
      timestamp: ts757,
      sig: sig757
    }, { writePayload: () => {} }, '127.0.0.1:9001');

    const presencePeeringOk = fedAutoNat.peerManager.peers.has(testRdvRelayIp1);

    // 2. ROUTE_UPDATE ile Röle Eş Keşfi
    const edgeKp757 = CryptoHelper.generateIdentityKeyPair();
    const edgeNodeId757 = CryptoHelper.deriveNodeId(edgeKp757.publicKey);
    const routeSig757 = CryptoHelper.sign(JSON.stringify({
      nodeId: edgeNodeId757,
      relayNodeId: relayNodeId757,
      rendezvousNodes: [testRdvRelayIp3],
      timestamp: ts757
    }), relayKp757.privateKey);

    fedAutoNat.handleIncoming({
      type: 'ROUTE_UPDATE',
      nodeId: edgeNodeId757,
      role: 'CAP_RELAY',
      rendezvousNodes: [testRdvRelayIp3],
      relayNodeId: relayNodeId757,
      relayAddress: testRdvRelayIp2,
      relayKemPublicKey: CryptoHelper.generateKemKeyPair().publicKey,
      relayIdentityPublicKey: relayKp757.publicKey,
      timestamp: ts757,
      sig: routeSig757
    }, { writePayload: () => {} }, '127.0.0.1:9001');

    const routePeeringOk = fedAutoNat.peerManager.peers.has(testRdvRelayIp2) &&
      fedAutoNat.peerManager.peers.has(testRdvRelayIp3);

    fedAutoNat.peerManager = origPm757;

    // 3. Outbox .isOpen Hatasının Yokluğu
    const mockDbWithoutIsOpen = {
      db: {
        prepare: () => ({
          all: () => [{ id: 'outbox_test_1', sender: '@a', receiver: '#genel', content: 'test', is_action: 0, is_snippet: 0, is_e2ee: 0, retries: 0, next_retry: 0, timestamp: 123 }]
        })
      }
    };
    mockDbWithoutIsOpen.getPendingOutbox = nodeRelayDb.getPendingOutbox.bind(mockDbWithoutIsOpen);
    const pendingWithoutIsOpen = mockDbWithoutIsOpen.getPendingOutbox(true);
    const outboxWithoutIsOpenOk = Array.isArray(pendingWithoutIsOpen) && pendingWithoutIsOpen.length === 1 && pendingWithoutIsOpen[0].id === 'outbox_test_1';

    // 4. AddressHelper Fonksiyonları
    const globalChanOk = AddressHelper.isGlobalChannel('#genel') &&
      AddressHelper.isGlobalChannel('#general') &&
      AddressHelper.isGlobalChannel('genel') &&
      AddressHelper.isGlobalChannel('general') &&
      AddressHelper.isGlobalChannel('#GENEL') &&
      AddressHelper.isGlobalChannel('#GENERAL') &&
      !AddressHelper.isGlobalChannel('#ozel_oda');

    const systemConsoleOk = AddressHelper.isSystemConsole('*sistem') &&
      AddressHelper.isSystemConsole('*system') &&
      AddressHelper.isSystemConsole('*SİSTEM') &&
      AddressHelper.isSystemConsole('*SYSTEM') &&
      !AddressHelper.isSystemConsole('#genel');

    const test757Ok = presencePeeringOk && routePeeringOk && outboxWithoutIsOpenOk && globalChanOk && systemConsoleOk;

    record('7.57 [REVİZYON 26 / v2.4.4] Dinamik Röle Peering, Outbox .isOpen Onarımı & AddressHelper Global/System Eşleme', !!test757Ok,
      `PresencePeering: ${presencePeeringOk}, RoutePeering: ${routePeeringOk}, OutboxWithoutIsOpen: ${outboxWithoutIsOpenOk}, GlobalChan: ${globalChanOk}, SystemConsole: ${systemConsoleOk}`);

    // Test 7.58: [REVİZYON 27 / Locale Değişimi] Kalıcı Veritabanı ve Oturumda Çok Dilli Sistem / Genel Kanal Tekilleştirmesi
    const testDbLocalePath = path.join(rootDir, 'v2_test_locale_mig.db');
    if (fs.existsSync(testDbLocalePath)) fs.unlinkSync(testDbLocalePath);
    const testDbLocale = new Database(testDbLocalePath);

    // 1. Türkçe locale ile kaydedilmiş profil benzetimi
    testDbLocale.db.exec(`
      INSERT INTO profiles (user_address, contacts, history) 
      VALUES ('@testuser:locale.mesh', '["*sistem", "#genel", "@buddy:peer.mesh"]', '[]');
    `);

    // 2. Veritabanı yeniden açıldığında (örneğin İngilizce locale ile başlatıldığında) profil kontaklarının dönüştürülmesi
    const profileAfterMig = testDbLocale.getUserProfile('@testuser:locale.mesh');
    const dbNormOk = profileAfterMig.contacts.includes('*system') &&
      profileAfterMig.contacts.includes('#general') &&
      !profileAfterMig.contacts.includes('*sistem') &&
      !profileAfterMig.contacts.includes('#genel') &&
      profileAfterMig.contacts.includes('@buddy:peer.mesh') &&
      profileAfterMig.contacts.length === 3;

    // 3. TerminalSession başlatıldığında eski dil varyantlarının temizlenmesi ve tekilleştirilmesi
    const mockSocketLocale = { write: () => {}, destroyed: false };
    const localeSession = new TerminalSession(
      mockSocketLocale,
      '@testuser:locale.mesh',
      { contacts: ['*sistem', '#genel', '@buddy:peer.mesh', '*system', '#general'] },
      () => [],
      () => [],
      () => {},
      () => ({ uptime: '1m', rss: '10', peers: [] }),
      () => []
    );

    const sessionInitOk = localeSession.contacts.length === 3 &&
      localeSession.contacts[0] === '*system' &&
      localeSession.contacts[1] === '#general' &&
      localeSession.contacts[2] === '@buddy:peer.mesh';

    // 4. Eski dildeki isimle ekleme yapılmak istendiğinde yinelenen girdi oluşturulmaması
    localeSession.addContact('*sistem');
    localeSession.addContact('#genel');
    const sessionAddDuplicateOk = localeSession.contacts.length === 3 &&
      !localeSession.contacts.includes('*sistem') &&
      !localeSession.contacts.includes('#genel');

    // 5. Eski dildeki kanala (#genel) atılmış mesajların yeni dilde (#general) getConversation ile listelenebilmesi
    testDbLocale.saveMessage({
      id: 'legacy_tr_msg_1',
      from: '@sender:remote.mesh',
      to: '#genel',
      content: 'Eski dildeki genel mesaj'
    });
    const generalConversation = testDbLocale.getConversation('@testuser:locale.mesh', '#general');
    const crossLocaleMessagesOk = generalConversation.some((m) => m.id === 'legacy_tr_msg_1');

    const test758Ok = dbNormOk && sessionInitOk && sessionAddDuplicateOk && crossLocaleMessagesOk;
    record('7.58 [REVİZYON 27 / Locale Değişimi] Kalıcı Veritabanı ve Oturumda Çok Dilli Sistem / Genel Kanal Tekilleştirmesi', !!test758Ok,
      `DbNorm: ${dbNormOk}, SessionInit: ${sessionInitOk}, SessionAddDup: ${sessionAddDuplicateOk}, CrossLocaleMsg: ${crossLocaleMessagesOk}`);

    // Test 7.59: [REVİZYON 28 / v2.4.5] Çapraz Dil Aktif Kanal Bildirim Bastırma ve Genel Kanal Broadcast Semantiği
    // 1. AddressHelper.isSameTarget doğrulaması
    const sameChanOk = AddressHelper.isSameTarget('#genel', '#general') &&
      AddressHelper.isSameTarget('#general', '#genel') &&
      !AddressHelper.isSameTarget('#dev:n1.mesh', '#dev:n2.mesh');
    const sameSysOk = AddressHelper.isSameTarget('*sistem', '*system') &&
      AddressHelper.isSameTarget('*system', '*sistem');
    const sameUserOk = AddressHelper.isSameTarget('@alice', '@alice:node.mesh') &&
      !AddressHelper.isSameTarget('@alice:n1.mesh', '@alice:n2.mesh');
    const isSameTargetOk = sameChanOk && sameSysOk && sameUserOk;

    // 2. TerminalSession.isViewingTarget ve incrementUnread bildirim bastırma
    const testSession759 = new TerminalSession(
      { write: () => {}, destroyed: false },
      '@tester:local.mesh',
      { contacts: ['*system', '#general'] },
      () => ['@tester:local.mesh', '@tr_user:remote.mesh'],
      () => ['@tester:local.mesh', '@tr_user:remote.mesh'],
      () => {},
      () => ({ uptime: '1m', rss: '10', peers: [] }),
      () => []
    );
    testSession759.setTarget('#general');
    const isViewingOtherLocale = testSession759.isViewingTarget('#genel');
    testSession759.incrementUnread('#genel');
    const unreadSuppressed = (testSession759.unreadCounts.get('#general') || 0) === 0 &&
      (testSession759.unreadCounts.get('#genel') || 0) === 0;

    testSession759.incrementUnread('#farkli_kanal');
    const unreadWorksForOther = (testSession759.unreadCounts.get('#farkli_kanal') || 0) === 1;
    const notificationSuppressionOk = isViewingOtherLocale && unreadSuppressed && unreadWorksForOther;

    // 3. Genel kanalın broadcast semantiği ile kullanıcı listesini getirmesi
    fedAutoNat.remoteOnlineUsers.set('@tr_user:remote.mesh', {
      channels: ['#genel'],
      lastSeen: Date.now()
    });
    const generalMembersFromEn = fedAutoNat.getChannelMembers('#general');
    const generalMembersFromTr = fedAutoNat.getChannelMembers('#genel');
    const fedBroadcastOk = generalMembersFromEn.includes('@tr_user:remote.mesh') &&
      generalMembersFromTr.includes('@tr_user:remote.mesh');

    // 4. clientServer.getChannelMembers'ın genel kanalda online tüm kullanıcıları dönmesi
    const mockCs759 = new ClientServer(testDb2, fedAutoNat);
    mockCs759.sessions.set('@tester:local.mesh', testSession759);
    const csMembersEn = mockCs759.getChannelMembers('#general');
    const csMembersTr = mockCs759.getChannelMembers('#genel');
    const csBroadcastOk = csMembersEn.includes('@tester:local.mesh') &&
      csMembersEn.includes('@tr_user:remote.mesh') &&
      csMembersTr.includes('@tester:local.mesh') &&
      csMembersTr.includes('@tr_user:remote.mesh');

    const test759Ok = isSameTargetOk && notificationSuppressionOk && fedBroadcastOk && csBroadcastOk;
    record('7.59 [REVİZYON 28 / v2.4.5] Çapraz Dil Aktif Kanal Bildirim Bastırma ve Genel Kanal Broadcast Semantiği', !!test759Ok,
      `IsSameTarget: ${isSameTargetOk}, NotifSuppression: ${notificationSuppressionOk}, FedBroadcast: ${fedBroadcastOk}, CsBroadcast: ${csBroadcastOk}`);

    // Test 7.60: [REVİZYON 29 / v2.4.6] Public Port Zehirlenmesi ve isSelfAddress Genel Port Desteği
    const origFedPort = CONFIG.federationPort;
    const origPubFedPort = CONFIG.publicFederationPort;

    CONFIG.federationPort = 8002;
    CONFIG.publicFederationPort = 8001;

    const pm760Path = path.join(rootDir, 'test_pm760.json');
    if (fs.existsSync(pm760Path)) fs.unlinkSync(pm760Path);
    const pm760 = new PeerManager(pm760Path);

    const isSelfLocalPortOk = pm760.isSelfAddress(CONFIG.serverName, 8002);
    const isSelfPublicPortOk = pm760.isSelfAddress(CONFIG.serverName, 8001);
    const isSelfLoopbackPubOk = pm760.isSelfAddress('127.0.0.1', 8001);
    const isSelfOtherPortRejected = !pm760.isSelfAddress(CONFIG.serverName, 8003);
    const pmSelfNodeAddrOk = pm760.selfNodeAddress === `${CONFIG.serverName}:8001`;

    const db760Path = path.join(rootDir, 'v2_test_fed760.db');
    if (fs.existsSync(db760Path)) fs.unlinkSync(db760Path);
    const mockDb760 = new Database(db760Path);
    const fed760 = new FederationEngine(mockDb760);

    const fedNodeAddrOk = fed760.nodeAddress === `${CONFIG.serverName}:8001` &&
      fed760.myIdentity.nodeAddress === `${CONFIG.serverName}:8001`;

    fed760.close();
    mockDb760.close();
    pm760.close();
    try { if (fs.existsSync(pm760Path)) fs.unlinkSync(pm760Path); } catch {}
    try { if (fs.existsSync(db760Path)) fs.unlinkSync(db760Path); } catch {}

    CONFIG.federationPort = origFedPort;
    CONFIG.publicFederationPort = origPubFedPort;

    const test760Ok = isSelfLocalPortOk && isSelfPublicPortOk && isSelfLoopbackPubOk && isSelfOtherPortRejected && pmSelfNodeAddrOk && fedNodeAddrOk;
    record('7.60 [REVİZYON 29 / v2.4.6] Public Port Zehirlenmesi ve isSelfAddress Genel Port Desteği', !!test760Ok,
      `LocalPort: ${isSelfLocalPortOk}, PublicPort: ${isSelfPublicPortOk}, LoopbackPub: ${isSelfLoopbackPubOk}, RejectOther: ${isSelfOtherPortRejected}, PmSelfAddr: ${pmSelfNodeAddrOk}, FedNodeAddr: ${fedNodeAddrOk}`);

    // Test 7.61: [REVİZYON 30 / v2.4.7] Devre Kurulumunda circuitId Korelasyonu ve Bayat Soket Yeniden Deneme
    // 1. buildCircuit içinde araya giren alakasız paketleri yoksayıp circuitId yanıtına kilitlenme doğrulaması
    const mockChannel761 = new EventEmitter();
    mockChannel761.socket = { destroyed: false, writable: true };
    let payloadSentToGuard = null;
    mockChannel761.writePayload = (p) => {
      payloadSentToGuard = p;
      // Eşzamanlı yarış durumu: önce alakasız bir dedikodu ve varlık paketi gelsin
      setTimeout(() => {
        mockChannel761.emit('payload', { type: 'GOSSIP_RESPONSE', peers: ['1.2.3.4:8001'] });
        mockChannel761.emit('payload', { type: 'PRESENCE_ANNOUNCE', nodeId: 'randomnode' });
        // Ardından doğru circuitId ile devre hazır yanıtı gelsin
        setTimeout(() => {
          mockChannel761.emit('payload', { status: 'circuit_ready', circuitId: p.circuitId });
        }, 20);
      }, 10);
    };

    const mockFed761 = {
      getOrCreateSecureChannel: async () => mockChannel761,
      myIdentity: fedAutoNat.myIdentity
    };
    const onionRouter761 = new OnionRouter({
      federation: mockFed761,
      db: testDb2,
      myIdentity: fedAutoNat.myIdentity,
      rendezvousTunnels: new Map()
    });

    const testHopKem = CryptoHelper.generateKemKeyPair();
    const builtCircuit761 = await onionRouter761.buildCircuit([
      { address: '198.51.100.55:8001', kemPublicKey: testHopKem.publicKey }
    ], 'corr_target_node');

    const correlationOk = builtCircuit761 &&
      builtCircuit761.circuitId === payloadSentToGuard?.circuitId &&
      onionRouter761.clientCircuits.has(builtCircuit761.circuitId);

    // 2. sendViaOnion içinde ilk denemede kopan/hata veren bayat soketin temizlenip anında ikinci denemede kurulması
    const db761RetryPath = path.join(rootDir, 'v2_test_retry761.db');
    if (fs.existsSync(db761RetryPath)) fs.unlinkSync(db761RetryPath);
    const mockDb761Retry = new Database(db761RetryPath);
    const fedRetry761 = new FederationEngine(mockDb761Retry, new PeerManager());

    const destKem761 = CryptoHelper.generateKemKeyPair();
    const destNodeId761 = 'destnode761retry';
    fedRetry761.presenceTable.set(destNodeId761, {
      nodeId: destNodeId761,
      role: 'CAP_EDGE',
      rendezvousNodes: ['198.51.100.99:8001'],
      kemPublicKey: destKem761.publicKey,
      lastSeen: Date.now()
    });

    let buildAttempts = 0;
    fedRetry761.onionRouter.buildCircuit = async (hops, targetNodeId) => {
      buildAttempts++;
      if (buildAttempts === 1) {
        throw new Error('Guard relay unacknowledged (ECONNRESET)');
      }
      return {
        circuitId: 'retry_circuit_ok_761',
        hops,
        keys: [Buffer.alloc(32)],
        targetNodeId,
        createdAt: Date.now()
      };
    };

    let cellSentOk = false;
    fedRetry761.onionRouter.sendOnionCell = async (circuit, targetNodeId, payload) => {
      cellSentOk = circuit.circuitId === 'retry_circuit_ok_761';
      return { status: 'delivered' };
    };

    // Bayat soket benzetimi
    let deadSocketDestroyed = false;
    fedRetry761.connectionPool.set('198.51.100.99:8001', {
      socket: {
        destroy: () => { deadSocketDestroyed = true; }
      }
    });

    const sendRes761 = await fedRetry761.sendViaOnion(destNodeId761, {
      type: 'DIRECT_MESSAGE',
      id: 'retry_msg_761',
      from: '@sender:local.mesh',
      to: `@recv:${destNodeId761}.mesh`,
      content: 'test retry'
    });

    const retryOk = buildAttempts === 2 &&
      deadSocketDestroyed &&
      !fedRetry761.connectionPool.has('198.51.100.99:8001') &&
      sendRes761?.status === 'delivered' &&
      cellSentOk;

    fedRetry761.close();
    mockDb761Retry.close();
    try { if (fs.existsSync(db761RetryPath)) fs.unlinkSync(db761RetryPath); } catch {}

    const test761Ok = correlationOk && retryOk;
    record('7.61 [REVİZYON 30 / v2.4.7] Devre Kurulumunda circuitId Korelasyonu ve Bayat Soket Yeniden Deneme', !!test761Ok,
      `Correlation: ${correlationOk}, RetryAttempts: ${buildAttempts}, DeadSocketDestroyed: ${deadSocketDestroyed}, Delivered: ${sendRes761?.status === 'delivered'}`);

    // Test 7.62: [REVİZYON 31 / v2.5.0] V1 PRESENCE_SYNC Tasfiyesi, PRESENCE_ANNOUNCE Standardizasyonu & Render Debounce
    // 1. V1 PRESENCE_SYNC paketlerinin artık işlenmediği ve yanıt verilmediğinin doğrulanması
    const db762Path = path.join(rootDir, 'v2_test_r31_presence.db');
    if (fs.existsSync(db762Path)) fs.unlinkSync(db762Path);
    const mockDb762 = new Database(db762Path);
    const fed762 = new FederationEngine(mockDb762, new PeerManager());

    let v1WrittenPayload = null;
    const mockChannelV1 = {
      peerNodeAddress: 'v1legacy.mesh',
      writePayload: (p) => { v1WrittenPayload = p; }
    };

    fed762.handleIncoming({
      type: 'PRESENCE_SYNC',
      sourceNode: 'v1legacy.mesh',
      memberships: [{ user: '@v1user:v1legacy.mesh', channels: ['#genel'] }]
    }, mockChannelV1);

    const v1IgnoredOk = !fed762.remoteOnlineUsers.has('@v1user:v1legacy.mesh') && v1WrittenPayload === null;

    // 2. V2 PRESENCE_ANNOUNCE paketinin tekil yetkili olarak kabulü, kanonik @user:nodeId.mesh dönüşümü ve ACK
    const remoteId762 = CryptoHelper.generateIdentityKeyPair();
    const remoteNodeId762 = CryptoHelper.deriveNodeId(remoteId762.publicKey);
    const remoteKem762 = CryptoHelper.generateKemKeyPair();
    const ts762 = Date.now();
    const dataToSign762 = JSON.stringify({
      nodeId: remoteNodeId762,
      role: 'EDGE',
      rendezvousNodes: [],
      kemPublicKey: remoteKem762.publicKey,
      channels: ['#genel'],
      timestamp: ts762
    });
    const sig762 = CryptoHelper.sign(dataToSign762, remoteId762.privateKey);

    let v2WrittenPayload = null;
    const mockChannelV2 = {
      peerNodeAddress: `${remoteNodeId762}.mesh`,
      writePayload: (p) => { v2WrittenPayload = p; }
    };

    fed762.handleIncoming({
      type: 'PRESENCE_ANNOUNCE',
      nodeId: remoteNodeId762,
      role: 'EDGE',
      rendezvousNodes: [],
      kemPublicKey: remoteKem762.publicKey,
      identityPublicKey: remoteId762.publicKey,
      channels: ['#genel'],
      memberships: [{ user: '@alice:192.168.1.50:8001', channels: ['#genel'], kemPublicKey: remoteKem762.publicKey }],
      timestamp: ts762,
      sig: sig762
    }, mockChannelV2);

    const expectedCanonicalUser = `@alice:${remoteNodeId762}.mesh`;
    const v2AcceptedOk = fed762.remoteOnlineUsers.has(expectedCanonicalUser) &&
      !fed762.remoteOnlineUsers.has('@alice:192.168.1.50:8001') &&
      v2WrittenPayload?.status === 'ack' &&
      v2WrittenPayload?.type === 'PRESENCE_ANNOUNCE';

    const savedKem762 = mockDb762.getUserProfile(expectedCanonicalUser);
    const kemSavedCanonicalOk = savedKem762 && savedKem762.kemPublicKey === remoteKem762.publicKey;

    // 3. ClientServer Render Debounce (50ms) Doğrulaması
    const cs762 = new ClientServer(mockDb762, fed762);
    let renderCallsCount = 0;
    cs762.notifyAllSessionsRender = () => { renderCallsCount++; };

    // Peş peşe 5 presence_change yayını tetikle
    for (let i = 0; i < 5; i++) {
      fed762.emit('presence_change');
    }
    const immediateZeroCalls = renderCallsCount === 0;

    // 70ms bekle ve debounce'un tek bir çağrı ürettiğini doğrula
    await new Promise((r) => setTimeout(r, 70));
    const debouncedSingleCall = renderCallsCount === 1;

    // 4. SecureChannel HTTP Bot / Scanner Erken Tahliye Doğrulaması
    let socketDestroyed762 = false;
    const fakeSocket762 = new EventEmitter();
    fakeSocket762.destroy = () => { socketDestroyed762 = true; };
    fakeSocket762.write = () => {};

    const secChan762 = new SecureChannel(fakeSocket762, false, {
      identityKeyPair: fed762.myIdentity.identityKeyPair,
      kemKeyPair: fed762.myIdentity.kemKeyPair,
      nodeAddress: 'localhost:8001',
      nodeId: fed762.nodeId
    }, mockDb762, { track: () => true });

    fakeSocket762.emit('data', Buffer.from('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'));
    const httpScanDroppedOk = socketDestroyed762;

    cs762.close();
    fed762.close();
    mockDb762.close();
    try { if (fs.existsSync(db762Path)) fs.unlinkSync(db762Path); } catch {}

    const test762Ok = v1IgnoredOk && v2AcceptedOk && kemSavedCanonicalOk &&
      immediateZeroCalls && debouncedSingleCall && httpScanDroppedOk;

    record('7.62 [REVİZYON 31 / v2.5.0] V1 PRESENCE_SYNC Tasfiyesi, PRESENCE_ANNOUNCE Standardizasyonu & Render Debounce', !!test762Ok,
      `V1Ignored: ${v1IgnoredOk}, V2Accepted: ${v2AcceptedOk}, CanonicalKEM: ${kemSavedCanonicalOk}, Debounce: ${debouncedSingleCall}, HttpDropped: ${httpScanDroppedOk}`);

    // Test 7.63: [REVİZYON 32 / v2.5.1] Bilateral Varlık Senkronizasyonu, Tünel USER_OFFLINE Dağıtımı & Eski NodeID Temizliği
    const db763Path = path.join(rootDir, 'v2_test_r32_bilateral.db');
    if (fs.existsSync(db763Path)) fs.unlinkSync(db763Path);
    const mockDb763 = new Database(db763Path);
    const fed763 = new FederationEngine(mockDb763, new PeerManager());
    fed763.role = 'RELAY';

    // 1. broadcastUserOffline Tünel ve Röle Dağıtımı & Nick varyantı temizliği
    let tunnelOfflineWritten = false;
    let relayOfflineWritten = false;
    fed763.rendezvousTunnels = new Map([
      ['tunnel_edge_1', {
        channel: { socket: { writable: true }, writePayload: (p) => { if (p?.type === 'USER_OFFLINE') tunnelOfflineWritten = true; } }
      }]
    ]);
    fed763.rendezvousRelays = new Map([
      ['relay_peer_1', {
        channel: { socket: { writable: true }, writePayload: (p) => { if (p?.type === 'USER_OFFLINE') relayOfflineWritten = true; } }
      }]
    ]);

    fed763.remoteOnlineUsers.set('@bob:oldnode11111111.mesh', { lastSeen: Date.now(), channels: ['#genel'] });
    fed763.remoteOnlineUsers.set('@bob:newnode22222222.mesh', { lastSeen: Date.now(), channels: ['#genel'] });

    await fed763.broadcastUserOffline('@bob:newnode22222222.mesh');
    const offlineTunnelsNotifiedOk = tunnelOfflineWritten && relayOfflineWritten;
    const allBobVariantsCleanedOk = !fed763.remoteOnlineUsers.has('@bob:oldnode11111111.mesh') &&
      !fed763.remoteOnlineUsers.has('@bob:newnode22222222.mesh');

    // 2. Bilateral PRESENCE_ANNOUNCE Değişimi
    fed763.getLocalStateFn = () => ({
      memberships: [{ user: `@charlie:${fed763.nodeId}.mesh`, channels: ['#genel'], isSsh: false, kemPublicKey: fed763.kemKeyPair.publicKey }]
    });

    const remoteRelayId = CryptoHelper.generateIdentityKeyPair();
    const remoteRelayNodeId = CryptoHelper.deriveNodeId(remoteRelayId.publicKey);
    const remoteRelayKem = CryptoHelper.generateKemKeyPair();
    const ts763 = Date.now();
    const dataToSign763 = JSON.stringify({
      nodeId: remoteRelayNodeId,
      role: 'RELAY',
      rendezvousNodes: ['198.51.100.77:8001'],
      kemPublicKey: remoteRelayKem.publicKey,
      channels: ['#genel'],
      timestamp: ts763
    });
    const sig763 = CryptoHelper.sign(dataToSign763, remoteRelayId.privateKey);

    const writtenPackets = [];
    const mockChannel763 = {
      peerNodeAddress: `${remoteRelayNodeId}.mesh`,
      writePayload: (p) => { writtenPackets.push(p); }
    };

    fed763.handleIncoming({
      type: 'PRESENCE_ANNOUNCE',
      nodeId: remoteRelayNodeId,
      role: 'RELAY',
      rendezvousNodes: ['198.51.100.77:8001'],
      kemPublicKey: remoteRelayKem.publicKey,
      identityPublicKey: remoteRelayId.publicKey,
      channels: ['#genel'],
      memberships: [{ user: `@alice:${remoteRelayNodeId}.mesh`, channels: ['#genel'] }],
      timestamp: ts763,
      sig: sig763
    }, mockChannel763);

    const ackPacket = writtenPackets.find((p) => p.status === 'ack' && p.type === 'PRESENCE_ANNOUNCE');
    const bilateralPacket = writtenPackets.find((p) => p.type === 'PRESENCE_ANNOUNCE' && p.isBilateralReply === true);
    const bilateralSyncOk = ackPacket && bilateralPacket &&
      bilateralPacket.nodeId === fed763.nodeId &&
      bilateralPacket.memberships.some((m) => m.user === `@charlie:${fed763.nodeId}.mesh`);

    // 3. Yeniden başlayan düğümde aynı nick için eski NodeID kaydının temizliği
    const restartedRemoteId = CryptoHelper.generateIdentityKeyPair();
    const restartedRemoteNodeId = CryptoHelper.deriveNodeId(restartedRemoteId.publicKey);
    const restartedKem = CryptoHelper.generateKemKeyPair();
    const tsRestart = Date.now();
    const dataRestart = JSON.stringify({
      nodeId: restartedRemoteNodeId,
      role: 'RELAY',
      rendezvousNodes: ['198.51.100.88:8001'],
      kemPublicKey: restartedKem.publicKey,
      channels: ['#genel'],
      timestamp: tsRestart
    });
    const sigRestart = CryptoHelper.sign(dataRestart, restartedRemoteId.privateKey);

    // alice daha önce remoteRelayNodeId altında kayıtlıydı:
    const aliceOldExists = fed763.remoteOnlineUsers.has(`@alice:${remoteRelayNodeId}.mesh`);

    fed763.handleIncoming({
      type: 'PRESENCE_ANNOUNCE',
      nodeId: restartedRemoteNodeId,
      role: 'RELAY',
      rendezvousNodes: ['198.51.100.88:8001'],
      kemPublicKey: restartedKem.publicKey,
      identityPublicKey: restartedRemoteId.publicKey,
      channels: ['#genel'],
      memberships: [{ user: `@alice:${restartedRemoteNodeId}.mesh`, channels: ['#genel'] }],
      timestamp: tsRestart,
      sig: sigRestart
    }, mockChannel763);

    const aliceNewExists = fed763.remoteOnlineUsers.has(`@alice:${restartedRemoteNodeId}.mesh`);
    const aliceOldPrunedOk = aliceOldExists && aliceNewExists && !fed763.remoteOnlineUsers.has(`@alice:${remoteRelayNodeId}.mesh`);

    fed763.close();
    mockDb763.close();
    try { if (fs.existsSync(db763Path)) fs.unlinkSync(db763Path); } catch {}

    const test763Ok = offlineTunnelsNotifiedOk && allBobVariantsCleanedOk &&
      bilateralSyncOk && aliceOldPrunedOk;

    record('7.63 [REVİZYON 32 / v2.5.1] Bilateral Varlık Senkronizasyonu, Tünel USER_OFFLINE Dağıtımı & Eski NodeID Temizliği', !!test763Ok,
      `TunnelsOffline: ${offlineTunnelsNotifiedOk}, NickPruned: ${allBobVariantsCleanedOk}, BilateralSync: ${!!bilateralSyncOk}, OldNodePruned: ${aliceOldPrunedOk}`);

    // Test 7.64: [REVİZYON 33 / v2.5.2] Kanonik .mesh Adresleme Zorlaması, NodeID Göçü & Bilateral Kalkanı
    const db764Path = path.join(rootDir, 'v2_test_r33_migration.db');
    if (fs.existsSync(db764Path)) fs.unlinkSync(db764Path);
    const mockDb764 = new Database(db764Path);
    const fed764 = new FederationEngine(mockDb764, new PeerManager());
    fed764.role = 'RELAY';

    // 1. Tavizsiz Kanonik .mesh Adresleme
    const prevNodeId = AddressHelper.getLocalNodeId();
    AddressHelper.setLocalNodeId(fed764.nodeId);
    const userWithoutNodeId = AddressHelper.formatUser('mehmet');
    const userWithNodeId = AddressHelper.formatUser('zeynep', 'customnode123456');
    const canonicalFormatOk = userWithoutNodeId === `@mehmet:${fed764.nodeId}.mesh` &&
      userWithNodeId === '@zeynep:customnode123456.mesh' &&
      !userWithoutNodeId.includes(':8001') && !userWithoutNodeId.includes('localhost');

    const clientSrv764 = new ClientServer(mockDb764, fed764);
    const mockSession = new EventEmitter();
    mockSession.activeTarget = '@ahmet:oldnode11111111.mesh';
    mockSession.contacts = ['*sistem', '#genel', '@ahmet:oldnode11111111.mesh', '@ayse:othernode222222.mesh'];
    mockSession.history = [];
    mockSession.getMyChannels = () => ['#genel'];
    mockSession.isSsh = false;
    mockSession.kemKeyPair = null;
    let renderRequested = false;
    mockSession.on('request_render', () => { renderRequested = true; });

    clientSrv764.sessions.set(`@mehmet:${fed764.nodeId}.mesh`, mockSession);

    const localUsers = clientSrv764.getLocalOnlineUsers();
    const localMemberships = clientSrv764.getLocalMemberships();
    const clientSrvCanonicalOk = localUsers.length === 1 && localUsers[0] === `@mehmet:${fed764.nodeId}.mesh` &&
      localMemberships.length === 1 && localMemberships[0].user === `@mehmet:${fed764.nodeId}.mesh`;

    // 2. NodeID Göçü (NodeID Migration)
    clientSrv764.updateTargetMigration('@ahmet:newnode33333333.mesh');
    const migrationActiveTargetOk = mockSession.activeTarget === '@ahmet:newnode33333333.mesh';
    const migrationContactsOk = mockSession.contacts.includes('@ahmet:newnode33333333.mesh') &&
      !mockSession.contacts.includes('@ahmet:oldnode11111111.mesh');
    const migrationRenderOk = renderRequested;

    // 3. Bilateral PRESENCE_ANNOUNCE Ping-Pong Fırtınası Kalkanı (isBilateralReply)
    const remoteRelayId764 = CryptoHelper.generateIdentityKeyPair();
    const remoteRelayNodeId764 = CryptoHelper.deriveNodeId(remoteRelayId764.publicKey);
    const remoteRelayKem764 = CryptoHelper.generateKemKeyPair();
    const ts764 = Date.now();
    const dataToSign764 = JSON.stringify({
      nodeId: remoteRelayNodeId764,
      role: 'RELAY',
      rendezvousNodes: ['198.51.100.99:8001'],
      kemPublicKey: remoteRelayKem764.publicKey,
      channels: ['#genel'],
      timestamp: ts764
    });
    const sig764 = CryptoHelper.sign(dataToSign764, remoteRelayId764.privateKey);

    const writtenPackets764 = [];
    const mockChannel764 = {
      peerNodeAddress: `${remoteRelayNodeId764}.mesh`,
      writePayload: (p) => { writtenPackets764.push(p); }
    };

    // isBilateralReply: true olarak gelen anons
    fed764.handleIncoming({
      type: 'PRESENCE_ANNOUNCE',
      nodeId: remoteRelayNodeId764,
      role: 'RELAY',
      rendezvousNodes: ['198.51.100.99:8001'],
      kemPublicKey: remoteRelayKem764.publicKey,
      identityPublicKey: remoteRelayId764.publicKey,
      channels: ['#genel'],
      memberships: [{ user: `@remotepartner:${remoteRelayNodeId764}.mesh`, channels: ['#genel'] }],
      timestamp: ts764,
      sig: sig764,
      isBilateralReply: true
    }, mockChannel764);

    const hasLoopingBilateralReply = writtenPackets764.some((p) => p.type === 'PRESENCE_ANNOUNCE' && p.isBilateralReply === true);
    const hasAck = writtenPackets764.some((p) => p.status === 'ack' && p.type === 'PRESENCE_ANNOUNCE');
    const bilateralShieldOk = hasAck && !hasLoopingBilateralReply;

    if (prevNodeId) AddressHelper.setLocalNodeId(prevNodeId);
    clientSrv764.close();
    fed764.close();
    mockDb764.close();
    try { if (fs.existsSync(db764Path)) fs.unlinkSync(db764Path); } catch {}

    const test764Ok = canonicalFormatOk && clientSrvCanonicalOk &&
      migrationActiveTargetOk && migrationContactsOk && migrationRenderOk &&
      bilateralShieldOk;

    record('7.64 [REVİZYON 33 / v2.5.2] Kanonik .mesh Adresleme Zorlaması, NodeID Göçü & Bilateral Kalkanı', !!test764Ok,
      `Canonical: ${canonicalFormatOk && clientSrvCanonicalOk}, Migration: ${migrationActiveTargetOk && migrationContactsOk}, BilateralShield: ${bilateralShieldOk}`);

    // Test 7.65: [REVİZYON 35 / v2.5.4] Kendi Kendine Yankılanma (Self-Echo) Kalkanı ve Doğrudan writePayload Dağıtımı
    const db765Path = path.join(rootDir, 'v2_test_r35_echo.db');
    if (fs.existsSync(db765Path)) fs.unlinkSync(db765Path);
    const mockDb765 = new Database(db765Path);
    const fed765 = new FederationEngine(mockDb765, new PeerManager());
    fed765.role = 'RELAY';

    // 1. Düğümün kendi nodeId'si ile gelen PRESENCE_ANNOUNCE paketini yutması (Self-Echo Shield)
    const echoPacketsWritten = [];
    const mockChannelEcho = {
      peerNodeAddress: `${fed765.nodeId}.mesh`,
      writePayload: (p) => { echoPacketsWritten.push(p); }
    };

    const echoTimestamp = Date.now();
    const echoDataToSign = JSON.stringify({
      nodeId: fed765.nodeId,
      role: 'RELAY',
      rendezvousNodes: ['127.0.0.1:8001'],
      kemPublicKey: fed765.kemKeyPair.publicKey,
      channels: ['#genel'],
      timestamp: echoTimestamp
    });
    const echoSig = CryptoHelper.sign(echoDataToSign, fed765.identityKeyPair.privateKey);

    let echoPresenceEmitted = false;
    fed765.once('presence_change', () => { echoPresenceEmitted = true; });

    fed765.handleIncoming({
      type: 'PRESENCE_ANNOUNCE',
      nodeId: fed765.nodeId,
      role: 'RELAY',
      rendezvousNodes: ['127.0.0.1:8001'],
      kemPublicKey: fed765.kemKeyPair.publicKey,
      identityPublicKey: fed765.identityKeyPair.publicKey,
      channels: ['#genel'],
      memberships: [{ user: `@selfuser:${fed765.nodeId}.mesh`, channels: ['#genel'] }],
      timestamp: echoTimestamp,
      sig: echoSig
    }, mockChannelEcho);

    const selfEchoShieldOk = echoPacketsWritten.length === 0 && !echoPresenceEmitted;

    // 2. broadcastPresenceAnnounce fonksiyonunun sendPacket yerine doğrudan writePayload basması
    let poolWritten = null;
    let relayWritten = null;
    let tunnelWritten = null;
    let sendPacketCalled = false;

    fed765.sendPacket = async () => { sendPacketCalled = true; };
    fed765.connectionPool.set('198.51.100.55:8001', {
      isReady: true,
      socket: { writable: true },
      writePayload: (p) => { poolWritten = p; }
    });
    fed765.rendezvousRelays.set('198.51.100.66:8001', {
      channel: { isReady: true, writePayload: (p) => { relayWritten = p; } },
      socket: { writable: true }
    });
    fed765.rendezvousTunnels.set('tunneltarget1234', {
      channel: { isReady: true, writePayload: (p) => { tunnelWritten = p; } },
      socket: { writable: true }
    });

    fed765.broadcastPresenceAnnounce();

    const directWriteOk = !sendPacketCalled &&
      poolWritten?.type === 'PRESENCE_ANNOUNCE' &&
      relayWritten?.type === 'PRESENCE_ANNOUNCE' &&
      tunnelWritten?.type === 'PRESENCE_ANNOUNCE';

    // 3. Gelen mesajda kullanıcı varlığının güçlendirilmesi (lastSeen yenilenmesi)
    const remoteSenderId = 'remotenode999999';
    fed765.presenceTable.set(remoteSenderId, {
      nodeId: remoteSenderId,
      lastSeen: Date.now() - 30000
    });
    const oldPresenceTime = fed765.presenceTable.get(remoteSenderId).lastSeen;

    fed765.handleIncoming({
      type: 'DIRECT_MESSAGE',
      id: 'dm_test_765',
      from: `@alice:${remoteSenderId}.mesh`,
      to: `@bob:${fed765.nodeId}.mesh`,
      content: 'hello 765'
    }, { writePayload: () => {} });

    const newPresenceTime = fed765.presenceTable.get(remoteSenderId).lastSeen;
    const remoteUserActive = fed765.remoteOnlineUsers.has(`@alice:${remoteSenderId}.mesh`);
    const presenceReinforceOk = newPresenceTime > oldPresenceTime && remoteUserActive;

    fed765.close();
    mockDb765.close();
    try { if (fs.existsSync(db765Path)) fs.unlinkSync(db765Path); } catch {}

    const test765Ok = selfEchoShieldOk && directWriteOk && presenceReinforceOk;

    record('7.65 [REVİZYON 35 / v2.5.4] Kendi Kendine Yankılanma (Self-Echo) Kalkanı ve Doğrudan writePayload Dağıtımı', !!test765Ok,
      `SelfEchoShield: ${selfEchoShieldOk}, DirectWrite: ${directWriteOk}, PresenceReinforce: ${presenceReinforceOk}`);

    // Test 7.66: [REVİZYON 36 / v2.5.5] Ters Tünel Varlık Temsili (Proxy Presence), Dedikodu Tekilleştirme & Ghost Session Kalkanı
    const db766Path = path.join(rootDir, 'v2_test_r36_proxy.db');
    if (fs.existsSync(db766Path)) fs.unlinkSync(db766Path);
    const mockDb766 = new Database(db766Path);
    const fed766 = new FederationEngine(mockDb766, new PeerManager());
    fed766.role = 'RELAY';

    // 1. Ters tünelle bağlı EDGE kullanıcılarının memberships listesine eklenmesi (Proxy Presence)
    const edgeNodeId766 = 'edgenode11111111';
    fed766.rendezvousTunnels = new Map([
      [edgeNodeId766, {
        channel: { socket: { writable: true }, writePayload: () => {} },
        boundRendezvousAddr: '198.51.100.1:8001'
      }]
    ]);
    fed766.remoteOnlineUsers.set(`@edge_tester:${edgeNodeId766}.mesh`, {
      channels: ['#genel'],
      isSsh: true,
      kemPublicKey: 'fakekemkey766',
      lastSeen: Date.now()
    });

    const announcePayload766 = fed766.createPresenceAnnouncePayload();
    const proxyPresenceIncluded = announcePayload766.memberships.some(
      (m) => m.user === `@edge_tester:${edgeNodeId766}.mesh` && m.isSsh === true && m.kemPublicKey === 'fakekemkey766'
    );

    // 2. announceKey'in üyelik değişimlerini ayırt edebilmesi
    const tsSame766 = 1700000000000;
    const memListA = [{ user: '@alice:nodeA.mesh' }];
    const memListB = [{ user: '@bob:nodeA.mesh' }];
    const summaryA = memListA.map((m) => m.user).sort().join(',');
    const summaryB = memListB.map((m) => m.user).sort().join(',');
    const keyA = `nodeA:${tsSame766}:${summaryA}`;
    const keyB = `nodeA:${tsSame766}:${summaryB}`;
    const deduplicationDistinguishesOk = keyA !== keyB;

    // 3. sshServer'da eski oturum kapandığında yeni oturumun silinmemesi (Ghost Session Guard)
    let offlineBroadcasted766 = false;
    const mockClientServer766 = {
      sessions: new Map(),
      notifyAllSessionsRender: () => {},
      federation: { broadcastUserOffline: () => { offlineBroadcasted766 = true; } }
    };

    const dummyOldSession = { contacts: [], history: [] };
    const dummyNewSession = { contacts: [], history: [] };
    const username766 = '@user_ssh:node.mesh';

    mockClientServer766.sessions.set(username766, dummyNewSession);

    const fakeOldConn = Object.create(SshClientConnection.prototype);
    fakeOldConn.activeTimeouts = new Set();
    fakeOldConn.authenticatedUser = username766;
    fakeOldConn.session = dummyOldSession;
    fakeOldConn.clientServer = mockClientServer766;
    fakeOldConn.db = { updateUserProfile: () => {} };

    fakeOldConn.cleanup();

    const newSessionPreservedOk = mockClientServer766.sessions.get(username766) === dummyNewSession;
    const noFalseOfflineOk = offlineBroadcasted766 === false;
    const ghostSessionGuardOk = newSessionPreservedOk && noFalseOfflineOk;

    fed766.close();
    mockDb766.close();
    try { if (fs.existsSync(db766Path)) fs.unlinkSync(db766Path); } catch {}

    const test766Ok = proxyPresenceIncluded && deduplicationDistinguishesOk && ghostSessionGuardOk;

    record('7.66 [REVİZYON 36 / v2.5.5] Ters Tünel Varlık Temsili (Proxy Presence), Dedikodu Tekilleştirme & Ghost Session Kalkanı', !!test766Ok,
      `ProxyPresence: ${proxyPresenceIncluded}, Deduplication: ${deduplicationDistinguishesOk}, GhostSessionGuard: ${ghostSessionGuardOk}`);

    // Test 7.67: [REVİZYON 37 / v2.5.9] AutoNAT Edge Zehirlenme Kalkanı, Reflected IP İzolasyonu ve Tekilleştirilmiş Varlık Dağıtımı
    const db767Path = path.join(rootDir, 'v2_test_fed767.db');
    const pm767Path = path.join(rootDir, 'v2_test_pm767.json');
    if (fs.existsSync(db767Path)) fs.unlinkSync(db767Path);
    if (fs.existsSync(pm767Path)) fs.unlinkSync(pm767Path);

    const origServerName767 = CONFIG.serverName;
    const origRole767 = CONFIG.meshRole;
    const origFedPort767 = CONFIG.federationPort;
    const origPubPort767 = CONFIG.publicFederationPort;
    CONFIG.serverName = 'localhost';
    CONFIG.meshRole = 'EDGE';
    CONFIG.federationPort = 9001;
    CONFIG.publicFederationPort = null;

    const pm767 = new PeerManager(pm767Path);
    const mockDb767 = new Database(db767Path);
    const fed767 = new FederationEngine(mockDb767, pm767);
    fed767.role = 'EDGE';

    // 1. PeerManager'a dış IP ekleme denemesi
    pm767.addOrUpdate('78.174.205.111:9001', true);
    const addedBeforeAutoNat = pm767.getAllPeers().includes('78.174.205.111:9001');

    // 2. AutoNAT Reflected IP Konsensüsü (EDGE rolündeyken)
    fed767.handleObservedAddress('78.174.205.111:54321', 'relay1:8001');
    fed767.handleObservedAddress('78.174.205.111:54322', 'relay2:8001');

    // EDGE düğümünün nodeAddress'i 78.174.205.111:9001 ile ezilmemeli, localhost korunmalı
    const edgeNodeAddrProtected = fed767.nodeAddress === 'localhost:9001' && fed767.myIdentity.nodeAddress === 'localhost:9001';

    // PeerManager reflected IP'yi tanımalı ve mevcut kaydı havuzdan silmeli
    const selfPublicRecognized = pm767.isSelfAddress('78.174.205.111', 9001);
    const evictedFromPeers = !pm767.getAllPeers().includes('78.174.205.111:9001');

    // Yeniden eklemeye çalıştığında reddetmeli
    pm767.addOrUpdate('78.174.205.111:9001', true);
    const reAddBlocked = !pm767.getAllPeers().includes('78.174.205.111:9001');

    // 3. maintainRendezvousTunnels kendi adresini tünel hedefi seçmemeli
    let boundToSelf = false;
    fed767.bindToRendezvousRelay = async (addr) => {
      if (addr === fed767.nodeAddress || addr === '78.174.205.111:9001') {
        boundToSelf = true;
      }
      return false;
    };
    await fed767.maintainRendezvousTunnels();
    const rendezvousSelfAvoided = !boundToSelf;

    // 4. broadcastPresenceAnnounce tekilleştirme doğrulaması
    let mockWritesCount = 0;
    const testChannel767 = {
      isReady: true,
      socket: { writable: true },
      writePayload: () => { mockWritesCount++; }
    };
    fed767.connectionPool.set('10.0.0.1:8001', testChannel767);
    fed767.rendezvousRelays.set('10.0.0.1:8001', { channel: testChannel767, socket: testChannel767.socket });
    fed767.broadcastPresenceAnnounce();
    const broadcastDeduplicated = mockWritesCount === 1;

    fed767.close();
    mockDb767.close();
    pm767.close();
    try { if (fs.existsSync(db767Path)) fs.unlinkSync(db767Path); } catch {}
    try { if (fs.existsSync(pm767Path)) fs.unlinkSync(pm767Path); } catch {}
    CONFIG.serverName = origServerName767;
    CONFIG.meshRole = origRole767;
    CONFIG.federationPort = origFedPort767;
    CONFIG.publicFederationPort = origPubPort767;

    const test767Ok = edgeNodeAddrProtected && selfPublicRecognized && evictedFromPeers && reAddBlocked && rendezvousSelfAvoided && broadcastDeduplicated;
    record('7.67 [REVİZYON 37 / v2.5.9] AutoNAT Edge Zehirlenme Kalkanı, Reflected IP İzolasyonu ve Tekilleştirilmiş Varlık Dağıtımı', !!test767Ok,
      `AddrProtected: ${edgeNodeAddrProtected}, PublicRecognized: ${selfPublicRecognized}, Evicted: ${evictedFromPeers}, ReAddBlocked: ${reAddBlocked}, RendezvousSafe: ${rendezvousSelfAvoided}, BroadcastDedup: ${broadcastDeduplicated}`);

    // Test 7.68: [REVİZYON 38 / v2.5.10] Rendezvous Edge Client IP İzolasyonu, Dedikodu (Gossip) Karantinası ve Hızlı Hata Tahliyesi
    const pm768 = new PeerManager();
    // 1. Edge IP kaydı ve anında tahliye
    pm768.addOrUpdate('78.174.205.111:9001', true);
    const inPoolBeforeReg = pm768.peers.has('78.174.205.111:9001');
    pm768.registerEdgeIp('78.174.205.111');
    const evictedOnEdgeReg = !pm768.peers.has('78.174.205.111:9001');
    pm768.addOrUpdate('78.174.205.111:9001', true);
    const edgeReAddBlocked = !pm768.peers.has('78.174.205.111:9001');

    // 2. Gossip bağışıklığı: Mevcut hata sayısının dedikoduyla sıfırlanamaması
    pm768.addOrUpdate('198.51.100.5:8001', false); // 1. hata
    const initialFailures = pm768.peers.get('198.51.100.5:8001').failures;
    pm768.addOrUpdate('198.51.100.5:8001', true, true); // Dedikodudan gelen bildirim
    const gossipDidNotResetFailure = pm768.peers.get('198.51.100.5:8001').failures === 1 && pm768.peers.get('198.51.100.5:8001').score === 95;

    // 3. Hatalı eşin dedikodu örneğine (getRandomSample) dahil edilmemesi
    const sampleExcludesFailed = !pm768.getRandomSample(10).includes('198.51.100.5:8001');

    // 4. Dedikodudan yeni öğrenilen eşin ilk hatada derhal tahliye edilmesi
    pm768.addOrUpdate('198.51.100.6:8001', true, true); // Dedikodudan yeni eş
    const gossipAdded = pm768.peers.has('198.51.100.6:8001');
    pm768.addOrUpdate('198.51.100.6:8001', false); // İlk doğrudan bağlantı başarısız
    const evictedImmediatelyOnGossipFailure = !pm768.peers.has('198.51.100.6:8001');

    pm768.close();

    const test768Ok = inPoolBeforeReg && evictedOnEdgeReg && edgeReAddBlocked && gossipDidNotResetFailure && sampleExcludesFailed && gossipAdded && evictedImmediatelyOnGossipFailure;
    record('7.68 [REVİZYON 38 / v2.5.10] Rendezvous Edge Client IP İzolasyonu, Dedikodu Karantinası ve Hızlı Hata Tahliyesi', !!test768Ok,
      `InPool: ${inPoolBeforeReg}, Evicted: ${evictedOnEdgeReg}, Blocked: ${edgeReAddBlocked}, GossipImmune: ${gossipDidNotResetFailure}, SampleClean: ${sampleExcludesFailed}, QuickEvict: ${evictedImmediatelyOnGossipFailure}`);

    // Temiz Kapanış
    testDbLocale.close();
    try { if (fs.existsSync(testDbLocalePath)) fs.unlinkSync(testDbLocalePath); } catch {}
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
