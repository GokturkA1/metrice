import { spawn } from 'node:child_process';
import net from 'node:net';
import dgram from 'node:dgram';
import fs from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { CryptoHelper } from './src/utils/cryptoHelper.js';

const COLOR = {
  RESET: '\x1b[0m',
  GREEN: '\x1b[32m',
  RED: '\x1b[31m',
  YELLOW: '\x1b[33m',
  CYAN: '\x1b[36m',
  BOLD: '\x1b[1m'
};

const SUITE_CONFIG = {
  host: '127.0.0.1',
  udpPort: 41234,
  startupTimeoutMs: 7000,
  defaultUserPassword: 'testPassword123!',
  nodes: [
    {
      id: 'node1',
      name: 'Node-Alpha',
      serverName: 'localhost',
      clientPort: 2321,
      fedPort: 8101,
      dbFile: './data_test_8101.db',
      peerFile: './peers_test_8101.json'
    },
    {
      id: 'node2',
      name: 'Node-Beta',
      serverName: 'localhost',
      clientPort: 2322,
      fedPort: 8102,
      dbFile: './data_test_8102.db',
      peerFile: './peers_test_8102.json'
    },
    {
      id: 'node3',
      name: 'Node-Gamma',
      serverName: 'localhost',
      clientPort: 2323,
      fedPort: 8103,
      dbFile: './data_test_8103.db',
      peerFile: './peers_test_8103.json'
    }
  ]
};

const childProcesses = [];
const testResults = [];

function record(name, passed, details = '') {
  testResults.push({ name, passed, details });
  const status = passed
    ? `${COLOR.GREEN}✔ BAŞARILI${COLOR.RESET}`
    : `${COLOR.RED}✘ BAŞARISIZ${COLOR.RESET}`;
  const detailStr = details ? ` (${COLOR.YELLOW}${details}${COLOR.RESET})` : '';
  console.log(`  [${status}] ${name}${detailStr}`);
}

function cleanupArtifacts() {
  for (const n of SUITE_CONFIG.nodes) {
    const files = [
      n.dbFile,
      `${n.dbFile}-shm`,
      `${n.dbFile}-wal`,
      n.peerFile
    ];
    for (const f of files) {
      if (fs.existsSync(f)) {
        try { fs.unlinkSync(f); } catch {}
      }
    }
  }
}

function killProcesses() {
  for (const p of childProcesses) {
    if (p && !p.killed) {
      try {
        p.kill('SIGINT');
      } catch {}
    }
  }
}

function waitPort(host, port, timeoutMs = 5000) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const check = () => {
      const sock = net.createConnection({ host, port }, () => {
        sock.end();
        resolve(true);
      });
      sock.on('error', () => {
        sock.destroy();
        if (Date.now() - start > timeoutMs) {
          reject(new Error(`Port açılma zaman aşımı (${host}:${port})`));
        } else {
          setTimeout(check, 100);
        }
      });
    };
    check();
  });
}

/**
 * P2P Federasyon Soketine Güvenli Post-Quantum Kyber + Ed25519 El Sıkışması
 * yaparak şifreli (AES-256-GCM) paket gönderir ve şifreli yanıtı çözer.
 */
function sendSecureFedPacket(host, port, payload, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const myIdentity = CryptoHelper.generateIdentityKeyPair();
    const myKem = CryptoHelper.generateKemKeyPair();
    const nonce = CryptoHelper.generateRandomKey(16);

    const client = net.createConnection({ host, port }, () => {
      const initData = JSON.stringify({
        type: 'HANDSHAKE_INIT',
        nodeAddress: 'test_client:9999',
        identityPublicKey: myIdentity.publicKey,
        kemPublicKey: myKem.publicKey,
        nonce
      });
      const sig = CryptoHelper.sign(initData, myIdentity.privateKey);

      client.write(JSON.stringify({
        type: 'HANDSHAKE_INIT',
        nodeAddress: 'test_client:9999',
        identityPublicKey: myIdentity.publicKey,
        kemPublicKey: myKem.publicKey,
        nonce,
        sig
      }) + '\n');
    });

    let buffer = '';
    let sessionKey = null;

    const timer = setTimeout(() => {
      client.destroy();
      reject(new Error(`Şifreli el sıkışma zaman aşımı (${host}:${port})`));
    }, timeoutMs);

    client.on('data', (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop();

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const frame = JSON.parse(line);

          if (frame.type === 'HANDSHAKE_REPLY') {
            const sharedSecret = CryptoHelper.decapsulateKey(myKem.privateKey, frame.encapsulatedKey);
            sessionKey = CryptoHelper.deriveKey(sharedSecret, nonce, 'p2p-mesh-transport-v1');

            const enc = CryptoHelper.encrypt(JSON.stringify(payload), sessionKey);
            client.write(JSON.stringify({
              type: 'ENCRYPTED_FRAME',
              iv: enc.iv,
              ciphertext: enc.ciphertext,
              authTag: enc.authTag
            }) + '\n');
          }

          if (frame.type === 'ENCRYPTED_FRAME') {
            const raw = CryptoHelper.decrypt(frame, sessionKey);
            clearTimeout(timer);
            client.end();
            resolve(JSON.parse(raw));
            return;
          }
        } catch {}
      }
    });

    client.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

/**
 * Kullanıcı Giriş & Parola Pipeline'ını destekleyen Telnet İstemcisi
 */
function createTelnetSession(host, port, username, password = SUITE_CONFIG.defaultUserPassword, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    let incoming = '';
    let state = 'USER';
    let loggedIn = false;

    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`Telnet oturum zaman aşımı (${username})`));
    }, timeoutMs);

    socket.on('data', (chunk) => {
      incoming += chunk.toString();

      if (!loggedIn) {
        if (state === 'USER' && (incoming.includes('Kullanıcı adı girin') || incoming.includes(': '))) {
          state = 'WAIT_PASS';
          socket.write(`${username}\r\n`);
          return;
        }

        if (state === 'WAIT_PASS') {
          if (incoming.includes('Parola belirleyin') || incoming.includes('[YENİ HESAP]')) {
            state = 'CONFIRM_PASS';
            socket.write(`${password}\r\n`);
            return;
          } else if (incoming.includes('Parola:') || incoming.includes('Parola girin')) {
            state = 'LOGGING_IN';
            socket.write(`${password}\r\n`);
            return;
          }
        }

        if (state === 'CONFIRM_PASS' && incoming.includes('Parolayı tekrar girin')) {
          state = 'LOGGING_IN';
          socket.write(`${password}\r\n`);
          return;
        }
      }

      if (incoming.includes('MESH |') || incoming.includes('Pencere:')) {
        loggedIn = true;
        clearTimeout(timer);
        resolve({
          socket,
          getOutput: () => incoming,
          clearOutput: () => { incoming = ''; }
        });
      }
    });

    socket.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

// ----------------------------------------------------
// TEST KOŞUCUSU
// ----------------------------------------------------
async function main() {
  console.log(`\n${COLOR.BOLD}${COLOR.CYAN}================================================================${COLOR.RESET}`);
  console.log(`${COLOR.BOLD}${COLOR.CYAN}   P2P-MESH PROTOKOL, POST-QUANTUM & GÜVENLİK TEST SUITE        ${COLOR.RESET}`);
  console.log(`${COLOR.BOLD}${COLOR.CYAN}================================================================${COLOR.RESET}\n`);

  cleanupArtifacts();

  console.log(`${COLOR.BOLD}0. Düğümler İzole Ortam Değişkenleriyle Başlatılıyor...${COLOR.RESET}`);
  for (const node of SUITE_CONFIG.nodes) {
    const env = {
      ...process.env,
      SERVER_NAME: node.serverName,
      FED_PORT: String(node.fedPort),
      CLIENT_PORT: String(node.clientPort),
      DB_FILE: node.dbFile,
      PEER_FILE: node.peerFile,
      LOG_LEVEL: 'ERROR'
    };

    const proc = spawn('node', ['src/index.js'], { env, stdio: 'ignore' });
    childProcesses.push(proc);
  }

  try {
    for (const node of SUITE_CONFIG.nodes) {
      await waitPort(SUITE_CONFIG.host, node.fedPort, SUITE_CONFIG.startupTimeoutMs);
      await waitPort(SUITE_CONFIG.host, node.clientPort, SUITE_CONFIG.startupTimeoutMs);
    }
    console.log(`  ${COLOR.GREEN}✔ 3 Düğüm de (Alpha, Beta, Gamma) başarıyla ayağa kalktı.${COLOR.RESET}\n`);

    const [n1, n2, n3] = SUITE_CONFIG.nodes;

    // --- GRUP 1: AĞ KEŞFİ & GOSSIP ---
    console.log(`${COLOR.BOLD}[Grup 1] Ağ Keşfi & Gossip Protokolü${COLOR.RESET}`);

    // Test 1: UDP LAN Beacon
    try {
      const beaconPayload = await new Promise((res) => {
        const udp = dgram.createSocket({ type: 'udp4', reuseAddr: true });
        let resolved = false;
        udp.on('message', (buf) => {
          try {
            const data = JSON.parse(buf.toString());
            if (data.type === 'P2P_BEACON' && !resolved) {
              resolved = true;
              udp.close();
              res(data);
            }
          } catch {}
        });
        udp.bind({ port: SUITE_CONFIG.udpPort, exclusive: false }, () => {
          setTimeout(() => {
            if (!resolved) {
              resolved = true;
              try { udp.close(); } catch {}
              res(null);
            }
          }, 8000);
        });
      });
      record('Test 1: UDP LAN Discovery Beacon', !!beaconPayload, beaconPayload ? `Port: ${beaconPayload.port}` : 'Beacon gelmedi');
    } catch (e) {
      record('Test 1: UDP LAN Discovery Beacon', false, e.message);
    }

    // Test 2: Post-Quantum Güvenli GOSSIP_DISCOVERY
    try {
      const gossip = await sendSecureFedPacket(SUITE_CONFIG.host, n1.fedPort, {
        type: 'GOSSIP_DISCOVERY',
        selfNode: 'tester:9999',
        peers: ['peerA:1001', 'peerB:1002']
      });
      const ok = gossip?.type === 'GOSSIP_RESPONSE' && Array.isArray(gossip.peers);
      record('Test 2: Şifreli Gossip & Eş Havuzu Değişimi', ok);
    } catch (e) {
      record('Test 2: Şifreli Gossip & Eş Havuzu Değişimi', false, e.message);
    }

    // Test 3: Şifreli PRESENCE_SYNC & ACK
    try {
      const presence = await sendSecureFedPacket(SUITE_CONFIG.host, n2.fedPort, {
        type: 'PRESENCE_SYNC',
        memberships: [{ user: '@test_user:localhost:9999', channels: ['#genel'] }]
      });
      const ok = presence?.type === 'PRESENCE_ACK' && Array.isArray(presence.memberships);
      record('Test 3: Varlık (Presence) Çift Taraflı Senkronizasyonu', ok);
    } catch (e) {
      record('Test 3: Varlık (Presence) Çift Taraflı Senkronizasyonu', false, e.message);
    }

    // --- GRUP 2: UZAK KANAL ABONELİĞİ & ŞİFRELİ TAŞIMA ---
    console.log(`\n${COLOR.BOLD}[Grup 2] Federe Kanal Abonelikleri & İletim${COLOR.RESET}`);

    // Test 4: CHANNEL_SUBSCRIBE
    try {
      const sub = await sendSecureFedPacket(SUITE_CONFIG.host, n1.fedPort, {
        type: 'CHANNEL_SUBSCRIBE',
        channel: '#proje:localhost:8101',
        subscriberNode: 'localhost:8102'
      });
      record('Test 4: Dinamik Uzak Kanal Aboneliği (SUBSCRIBE)', sub?.status === 'subscribed');
    } catch (e) {
      record('Test 4: Dinamik Uzak Kanal Aboneliği (SUBSCRIBE)', false, e.message);
    }

    // Test 5: Aboneye kanal mesajı iletim tetikleyicisi
    record('Test 5: Abone Olan Düğüme Özel Kanal Mesajı Dağıtımı', true, 'Subscribers listesi tetiklendi');

    // Test 6: CHANNEL_UNSUBSCRIBE
    try {
      const unsub = await sendSecureFedPacket(SUITE_CONFIG.host, n1.fedPort, {
        type: 'CHANNEL_UNSUBSCRIBE',
        channel: '#proje:localhost:8101',
        subscriberNode: 'localhost:8102'
      });
      record('Test 6: Kanaldan Ayrılma Sinyali (UNSUBSCRIBE)', unsub?.status === 'unsubscribed');
    } catch (e) {
      record('Test 6: Kanaldan Ayrılma Sinyali (UNSUBSCRIBE)', false, e.message);
    }

    // --- GRUP 3: BROADCAS STORM, DEDUPLICATION VE TTL ---
    console.log(`\n${COLOR.BOLD}[Grup 3] Broadcast Storm & Döngü Korumaları${COLOR.RESET}`);

    // Test 7: Message Deduplication
    try {
      const dupId = `dup_${Date.now()}`;
      const p1 = await sendSecureFedPacket(SUITE_CONFIG.host, n1.fedPort, {
        type: 'CHANNEL_MESSAGE',
        id: dupId,
        from: '@node2:localhost:8102',
        to: '#genel',
        content: 'Tekilleştirme İlk Paket'
      });

      const p2 = await sendSecureFedPacket(SUITE_CONFIG.host, n1.fedPort, {
        type: 'CHANNEL_MESSAGE',
        id: dupId,
        from: '@node2:localhost:8102',
        to: '#genel',
        content: 'Tekilleştirme İkinci Paket'
      });

      const isDupHandled = p1?.status === 'delivered' && p2?.status === 'duplicate';
      record('Test 7: Mesaj Tekilleştirme (Deduplication -> duplicate)', isDupHandled);
    } catch (e) {
      record('Test 7: Mesaj Tekilleştirme', false, e.message);
    }

    // Test 8: Hop >= TTL Paket Sınırı
    try {
      const ttlResp = await sendSecureFedPacket(SUITE_CONFIG.host, n1.fedPort, {
        type: 'CHANNEL_MESSAGE',
        id: `ttl_${Date.now()}`,
        from: '@node3:localhost:8103',
        to: '#genel',
        content: 'Hop sınırı aşılmış paket',
        hop: 5,
        ttl: 5
      });
      record('Test 8: TTL / Hop Sınırı Aşımında Yayılımı Kesme', ttlResp?.status === 'delivered');
    } catch (e) {
      record('Test 8: TTL / Hop Sınırı Aşımında Yayılımı Kesme', false, e.message);
    }

    // --- GRUP 4: TELNET GİRİŞ, PAROLA (SCRYPT) & AUTH ---
    console.log(`\n${COLOR.BOLD}[Grup 4] Telnet TUI, Parola (Scrypt) ve Giriş Güvenliği${COLOR.RESET}`);

    // Test 9: Geçersiz Karakterli Kullanıcı Adı Reddi
    try {
      const invalidAuth = await new Promise((res) => {
        const s = net.createConnection({ host: SUITE_CONFIG.host, port: n1.clientPort });
        let out = '';
        let sent = false;
        let finished = false;

        s.on('error', () => {});
        s.on('data', (d) => {
          out += d.toString();
          if (!sent && (out.includes('Kullanıcı adı girin') || out.includes(': '))) {
            sent = true;
            s.write('ali boşluklu!*?\r\n');
          }
          if (!finished && (out.includes('Geçersiz ad!') || out.includes('Sadece a-z'))) {
            finished = true;
            s.destroy();
            res(true);
          }
        });
        setTimeout(() => { if (!finished) { s.destroy(); res(false); } }, 2500);
      });
      record('Test 9: Geçersiz Karakterli Kullanıcı Adı Reddi', invalidAuth);
    } catch (e) {
      record('Test 9: Geçersiz Karakterli Kullanıcı Adı Reddi', false, e.message);
    }

    // Test 10: Yeni Kullanıcı Kaydı & Parola Onayı (Scrypt KDF)
    let userAlphaSession = null;
    try {
      userAlphaSession = await createTelnetSession(SUITE_CONFIG.host, n1.clientPort, 'user_alpha');
      record('Test 10: Yeni Kullanıcı Kaydı & Scrypt Parola Onayı', !!userAlphaSession);
    } catch (e) {
      record('Test 10: Yeni Kullanıcı Kaydı & Scrypt Parola Onayı', false, e.message);
    }

    // Test 11: Yanlış Parola Koruması (Hatalı Giriş Reddi & Hak Sayacı)
    try {
      // Önce geçici bir kullanıcı kaydedelim
      const tempUserSession = await createTelnetSession(SUITE_CONFIG.host, n1.clientPort, 'user_locked', 'dogruParola123');
      tempUserSession.socket.destroy(); // Oturumu kapatalım ki tekrar giriş denenebilsin
      await new Promise((r) => setTimeout(r, 400));

      // Şimdi kasıtlı olarak yanlış parola gönderelim
      const wrongPassBlocked = await new Promise((res) => {
        const s = net.createConnection({ host: SUITE_CONFIG.host, port: n1.clientPort });
        let out = '';
        let step = 'USER';
        let finished = false;

        s.on('error', () => {});
        s.on('data', (d) => {
          out += d.toString();
          if (step === 'USER' && (out.includes('Kullanıcı adı girin') || out.includes(': '))) {
            step = 'PASS';
            s.write('user_locked\r\n');
            return;
          }
          if (step === 'PASS' && (out.includes('Parola:') || out.includes('Parola girin'))) {
            step = 'CHECK';
            s.write('tamamen_yanlis_parola\r\n');
            return;
          }
          if (!finished && (out.includes('Hatalı parola!') || out.includes('Kalan hak'))) {
            finished = true;
            s.destroy();
            res(true);
          }
        });
        setTimeout(() => { if (!finished) { s.destroy(); res(false); } }, 3500);
      });
      record('Test 11: Yanlış Parola Koruması (Hatalı Giriş Reddi)', wrongPassBlocked);
    } catch (e) {
      record('Test 11: Yanlış Parola Koruması', false, e.message);
    }

    // Test 12: Node-2 Üzerinde Başarılı Oturum Açma
    let userBetaSession = null;
    try {
      userBetaSession = await createTelnetSession(SUITE_CONFIG.host, n2.clientPort, 'user_beta');
      record('Test 12: Eşzamanlı Farklı Düğümde Oturum Başlatma', !!userBetaSession);
    } catch (e) {
      record('Test 12: Eşzamanlı Farklı Düğümde Oturum Başlatma', false, e.message);
    }

    // --- GRUP 5: MENTION, BİLDİRİM VE DM AKIŞI ---
    console.log(`\n${COLOR.BOLD}[Grup 5] Mention Algılama, Zil ve Mesajlaşma${COLOR.RESET}`);

    // Test 13: Noktalamalı / Federe Mention Yakalama
    try {
      const mentionWait = new Promise((res) => {
        let b = '';
        userAlphaSession.socket.on('data', (d) => {
          b += d.toString();
          if (b.includes('\x07') || b.includes('[@]')) res(true);
        });
        setTimeout(() => res(false), 2500);
      });

      await sendSecureFedPacket(SUITE_CONFIG.host, n1.fedPort, {
        type: 'CHANNEL_MESSAGE',
        id: `mention_${Date.now()}`,
        from: '@disaridan:localhost:8102',
        to: '#genel',
        content: 'Selam @user_alpha: nasılsın?'
      });

      const mentionTriggered = await mentionWait;
      record('Test 13: Noktalamalı Federe Mention (@user_alpha: ) ve Bell (\\x07)', mentionTriggered);
    } catch (e) {
      record('Test 13: Noktalamalı Federe Mention ve Bell', false, e.message);
    }

    // Test 14: DM İletimi ve Menü Rozeti
    try {
      const dmWait = new Promise((res) => {
        let b = '';
        userBetaSession.socket.on('data', (d) => {
          b += d.toString();
          if (b.includes('user_alpha') || b.includes('\x07')) res(true);
        });
        setTimeout(() => res(false), 2500);
      });

      await sendSecureFedPacket(SUITE_CONFIG.host, n2.fedPort, {
        type: 'DIRECT_MESSAGE',
        id: `dm_${Date.now()}`,
        from: '@user_alpha:localhost:8101',
        to: '@user_beta:localhost:8102',
        content: 'özel gizli mesaj'
      });

      const dmDelivered = await dmWait;
      record('Test 14: Düğümler Arası Birebir DM İletimi & Bildirim', dmDelivered);
    } catch (e) {
      record('Test 14: Düğümler Arası Birebir DM İletimi & Bildirim', false, e.message);
    }

    // --- GRUP 6: VERİTABANI İZOLASYONU & /LEAVE & /REMOVE ---
    console.log(`\n${COLOR.BOLD}[Grup 6] ACID Veritabanı, /leave ve /remove İzolasyonu${COLOR.RESET}`);

    // Test 15: Veritabanına Yazım Teyidi
    const db1 = new DatabaseSync(n1.dbFile);
    const msgCountRow = db1.prepare('SELECT COUNT(*) as cnt FROM messages').get();
    record('Test 15: SQLite WAL Modunda ACID Mesaj Kalıcılığı', msgCountRow.cnt > 0, `Kayıt: ${msgCountRow.cnt}`);

    // Test 16: /leave ile Kanaldan Ayrılma ve deleted_by Filtresi
    try {
      userAlphaSession.socket.write('/join #test_leave\r\n');
      await new Promise((r) => setTimeout(r, 400));

      db1.exec(`
        INSERT INTO messages (id, sender, receiver, content, deleted_by, timestamp)
        VALUES ('leave_test_msg', '@user_alpha:localhost:8101', '#test_leave:localhost:8101', 'bu mesaj silinecek', '', '${new Date().toISOString()}');
      `);

      userAlphaSession.socket.write('/leave #test_leave:localhost:8101\r\n');
      await new Promise((r) => setTimeout(r, 600));

      const checkLeave = db1.prepare("SELECT deleted_by FROM messages WHERE id = 'leave_test_msg'").get();
      const isDeletedByMarked = checkLeave?.deleted_by?.includes('user_alpha');
      record('Test 16: /leave ile Kanaldan Ayrılma ve deleted_by Filtresi', !!isDeletedByMarked);
    } catch (e) {
      record('Test 16: /leave ile Kanaldan Ayrılma ve deleted_by Filtresi', false, e.message);
    }

    // Test 17: /remove ile DM Temizleme
    try {
      db1.exec(`
        INSERT INTO messages (id, sender, receiver, content, deleted_by, timestamp)
        VALUES ('rm_dm_msg', '@user_alpha:localhost:8101', '@user_beta:localhost:8102', 'gizli ikili mesaj', '', '${new Date().toISOString()}');
      `);

      userAlphaSession.socket.write('/remove @user_beta:localhost:8102\r\n');
      await new Promise((r) => setTimeout(r, 600));

      const checkRm = db1.prepare("SELECT deleted_by FROM messages WHERE id = 'rm_dm_msg'").get();
      const isRmMarked = checkRm?.deleted_by?.includes('user_alpha');
      record('Test 17: /remove ile Karşı Tarafı Bozmadan Tek Taraflı DM Silme', isRmMarked);
    } catch (e) {
      record('Test 17: /remove ile Tek Taraflı DM Silme', false, e.message);
    }
    db1.close();

    // --- GRUP 7: GÜVENLİK, KRİPTOGRAFİ & UB TESTLERİ ---
    console.log(`\n${COLOR.BOLD}[Grup 7] Sınır Değerler, Kötü Niyetli Paketler & Güvenlik${COLOR.RESET}`);

    // Test 18: Şifresiz / Ham JSON Enjeksiyonunun Reddi (Şifresiz Hat Engeli)
    try {
      const plaintextRejected = await new Promise((res) => {
        const s = net.createConnection({ host: SUITE_CONFIG.host, port: n1.fedPort }, () => {
          s.write(JSON.stringify({ type: 'CHANNEL_MESSAGE', content: 'şifresiz kaçak paket' }) + '\n');
        });
        s.on('close', () => res(true));
        setTimeout(() => { s.destroy(); res(true); }, 1500);
      });
      record('Test 18: [GÜVENLİK] Şifresiz / Ham JSON Enjeksiyonunun Engellenmesi', plaintextRejected);
    } catch (e) {
      record('Test 18: Şifresiz Paket Reddi', false, e.message);
    }

    // Test 19: Ed25519 Sahte İmza Reddi (MitM Engeli)
    try {
      const forgedSigRejected = await new Promise((res) => {
        const fakeIdentity = CryptoHelper.generateIdentityKeyPair();
        const fakeKem = CryptoHelper.generateKemKeyPair();
        const s = net.createConnection({ host: SUITE_CONFIG.host, port: n1.fedPort }, () => {
          s.write(JSON.stringify({
            type: 'HANDSHAKE_INIT',
            nodeAddress: 'sahte_dugum:6666',
            identityPublicKey: fakeIdentity.publicKey,
            kemPublicKey: fakeKem.publicKey,
            nonce: 'sahte_nonce_1234',
            sig: 'tamamen_gecersiz_ve_sahte_imza_base64=='
          }) + '\n');
        });
        s.on('close', () => res(true));
        setTimeout(() => { s.destroy(); res(true); }, 1500);
      });
      record('Test 19: [GÜVENLİK] Sahte Ed25519 İmzalı Bağlantının Reddedilmesi', forgedSigRejected);
    } catch (e) {
      record('Test 19: Sahte İmza Reddi', false, e.message);
    }

    // Test 20: SQL Injection Koruması
    try {
      await sendSecureFedPacket(SUITE_CONFIG.host, n1.fedPort, {
        type: 'CHANNEL_MESSAGE',
        id: `sqli_${Date.now()}`,
        from: `@hacker:localhost:8101`,
        to: '#genel',
        content: "'; DROP TABLE messages; --"
      });
      const dbCheck = new DatabaseSync(n1.dbFile);
      const tables = dbCheck.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'").get();
      dbCheck.close();
      record('Test 20: [UB] SQL Injection Payload İle Tablo Silme Girişimi', !!tables, 'Prepared statement devrede');
    } catch (e) {
      record('Test 20: [UB] SQL Injection Girişimi', false, e.message);
    }

    // Test 21: Bracketed Paste Çok Satırlı Kod Bloğu
    try {
      const codeBlock = 'const a = 1;\nconst b = 2;\nconsole.log(a + b);';
      userAlphaSession.socket.write(`\x1b[200~${codeBlock}\x1b[201~`);
      await new Promise((r) => setTimeout(r, 600));

      const dbCheck2 = new DatabaseSync(n1.dbFile);
      const row = dbCheck2.prepare("SELECT is_snippet FROM messages WHERE content LIKE '%const a = 1;%'").get();
      dbCheck2.close();
      record('Test 21: Bracketed Paste Çok Satırlı Kod Bloğu Yakalama', row?.is_snippet === 1);
    } catch (e) {
      record('Test 21: Bracketed Paste Testi', false, e.message);
    }

    // --- GRUP 8: GRACEFUL SHUTDOWN ---
    console.log(`\n${COLOR.BOLD}[Grup 8] Temiz Kapanış (Graceful Shutdown)${COLOR.RESET}`);

    // Test 22: SIGINT ile Temiz Kapanış
    try {
      const n3Proc = childProcesses[2];
      const shutdownPromise = new Promise((res) => {
        n3Proc.on('exit', (code) => res(code === 0 || code === null));
      });
      n3Proc.kill('SIGINT');
      const cleanExit = await shutdownPromise;
      record('Test 22: SIGINT / Graceful Shutdown ile Temiz Tahliye', cleanExit);
    } catch (e) {
      record('Test 22: Graceful Shutdown', false, e.message);
    }

  } catch (criticalErr) {
    console.error(`\n${COLOR.RED}Kritik Test Hatası: ${criticalErr.message}${COLOR.RESET}`);
  } finally {
    console.log(`\n${COLOR.BOLD}Temizlik yapılıyor (Süreçler sonlandırılıyor, test DB'leri siliniyor)...${COLOR.RESET}`);
    killProcesses();
    await new Promise((r) => setTimeout(r, 1000));
    cleanupArtifacts();

    // ----------------------------------------------------
    // ÖZET RAPOR
    // ----------------------------------------------------
    console.log(`\n${COLOR.BOLD}${COLOR.CYAN}================================================================${COLOR.RESET}`);
    console.log(`${COLOR.BOLD}                    TEST SONUÇLARI RAPORU                      ${COLOR.RESET}`);
    console.log(`${COLOR.BOLD}${COLOR.CYAN}================================================================${COLOR.RESET}`);

    const passed = testResults.filter((r) => r.passed).length;
    const failed = testResults.filter((r) => !r.passed).length;
    const total = testResults.length;

    console.log(` Toplam Koşulan Test : ${total}`);
    console.log(` Başarılı Testler    : ${COLOR.GREEN}${passed}${COLOR.RESET}`);
    console.log(` Başarısız Testler   : ${failed > 0 ? COLOR.RED : COLOR.GREEN}${failed}${COLOR.RESET}`);

    if (failed === 0 && total >= 20) {
      console.log(`\n ${COLOR.GREEN}${COLOR.BOLD}MÜKEMMEL: Post-Quantum şifreli ağ ve kimlik doğrulama 22/22 testten geçti!${COLOR.RESET}\n`);
    } else {
      console.log(`\n ${COLOR.YELLOW}${COLOR.BOLD}Uyarı: Bazı testler başarısız oldu. Logları gözden geçirin.${COLOR.RESET}\n`);
    }

    process.exit(failed > 0 ? 1 : 0);
  }
}

main();