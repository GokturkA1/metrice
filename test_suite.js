import net from 'node:net';
import dgram from 'node:dgram';
import { DatabaseSync } from 'node:sqlite';

// ==========================================
// TEST KONFİGÜRASYONU
// ==========================================
const TEST_CONFIG = {
  host: '127.0.0.1',
  udpPort: 41234,
  timeoutMs: 4000,
  nodes: [
    {
      name: 'Node-1',
      clientPort: 2222,
      fedPort: 8001,
      dbFile: './data_8001.db'
    },
    {
      name: 'Node-2',
      clientPort: 2223,
      fedPort: 8002,
      dbFile: './data_8002.db'
    }
  ]
};

// Renkli konsol çıktıları
const COLOR = {
  RESET: '\x1b[0m',
  GREEN: '\x1b[32m',
  RED: '\x1b[31m',
  YELLOW: '\x1b[33m',
  CYAN: '\x1b[36m',
  BOLD: '\x1b[1m'
};

const results = [];

function recordResult(testName, passed, details = '') {
  results.push({ testName, passed, details });
  const mark = passed ? `${COLOR.GREEN}✔ BAŞARILI${COLOR.RESET}` : `${COLOR.RED}✘ BAŞARISIZ${COLOR.RESET}`;
  console.log(`  [${mark}] ${testName} ${details ? `(${COLOR.YELLOW}${details}${COLOR.RESET})` : ''}`);
}

// ==========================================
// YARDIMCI SOKET FONKSİYONLARI
// ==========================================

// Federasyon portuna JSON satırı gönderip gelen ilk yanıtı bekler
function sendFedPacket(host, port, payload, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port }, () => {
      socket.write(JSON.stringify(payload) + '\n');
    });

    let buffer = '';
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`Zaman aşımı (${host}:${port})`));
    }, timeoutMs);

    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const parsed = JSON.parse(line);
          clearTimeout(timer);
          socket.end();
          resolve(parsed);
          return;
        } catch {}
      }
    });

    socket.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

// Telnet Portuna bağlanıp raw login simülasyonu yapar
function connectTelnetClient(host, port, username, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    let incoming = '';

    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`Telnet istemci bağlanma zaman aşımı (${username})`));
    }, timeoutMs);

    socket.on('data', (chunk) => {
      incoming += chunk.toString();
      // Login prompt'u geldiğinde kullanıcı adını gönder
      if (incoming.includes('Kullanıcı adı girin') || incoming.includes(':')) {
        socket.write(`${username}\r\n`);
      }
      // TUI çizimi başladığında giriş başarılıdır
      if (incoming.includes('METRICE |') || incoming.includes('Pencere:')) {
        clearTimeout(timer);
        resolve(socket);
      }
    });

    socket.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

// ==========================================
// TEST KOŞUCUSU
// ==========================================
async function runTestSuite() {
  console.log(`\n${COLOR.BOLD}${COLOR.CYAN}====================================================${COLOR.RESET}`);
  console.log(`${COLOR.BOLD}${COLOR.CYAN} P2P-MESH PROTOKOL VE ENTEGRASYON DOĞRULAMA TESTİ${COLOR.RESET}`);
  console.log(`${COLOR.BOLD}${COLOR.CYAN}====================================================${COLOR.RESET}\n`);

  const nodeA = TEST_CONFIG.nodes[0];
  const nodeB = TEST_CONFIG.nodes[1];

  // ----------------------------------------------------
  // TEST GRUBU 1: PORT VE BAĞLANTI CANLILIK KONTROLÜ
  // ----------------------------------------------------
  console.log(`${COLOR.BOLD}1. Port Erişilebilirlik ve Canlılık Kontrolleri${COLOR.RESET}`);
  for (const node of TEST_CONFIG.nodes) {
    try {
      await new Promise((res, rej) => {
        const s = net.createConnection({ host: TEST_CONFIG.host, port: node.fedPort }, () => {
          s.end();
          res();
        });
        s.on('error', rej);
      });
      recordResult(`${node.name} Federasyon Portu (${node.fedPort}) Açık`, true);
    } catch (err) {
      recordResult(`${node.name} Federasyon Portu (${node.fedPort}) Açık`, false, err.message);
    }

    try {
      await new Promise((res, rej) => {
        const s = net.createConnection({ host: TEST_CONFIG.host, port: node.clientPort }, () => {
          s.end();
          res();
        });
        s.on('error', rej);
      });
      recordResult(`${node.name} Client/TUI Portu (${node.clientPort}) Açık`, true);
    } catch (err) {
      recordResult(`${node.name} Client/TUI Portu (${node.clientPort}) Açık`, false, err.message);
    }
  }

// ----------------------------------------------------
  // TEST GRUBU 2: UDP LAN DISCOVERY (BEACON) YAYINI
  // ----------------------------------------------------
  console.log(`\n${COLOR.BOLD}2. UDP LAN Keşif Yayını (Beacon Dinleme)${COLOR.RESET}`);
  try {
    const receivedBeacon = await new Promise((resolve) => {
      const udp = dgram.createSocket({ type: 'udp4', reuseAddr: true });
      let done = false;

      udp.on('error', () => {
        if (!done) {
          done = true;
          try { udp.close(); } catch {}
          resolve(null);
        }
      });

      udp.on('message', (msg) => {
        try {
          const payload = JSON.parse(msg.toString());
          if (payload.type === 'P2P_BEACON' && payload.port) {
            if (!done) {
              done = true;
              try { udp.close(); } catch {}
              resolve(payload);
            }
          }
        } catch {}
      });

      udp.bind({ port: TEST_CONFIG.udpPort, exclusive: false }, () => {
        try {
          udp.setBroadcast(true);
        } catch {}

        setTimeout(() => {
          if (!done) {
            done = true;
            try { udp.close(); } catch {}
            resolve(null);
          }
        }, 9000);
      });
    });

    if (receivedBeacon) {
      recordResult('LAN UDP Beacon Alındı', true, `Port: ${receivedBeacon.port}`);
    } else {
      recordResult('LAN UDP Beacon Alındı', false, 'Belirlenen sürede beacon yakalanamadı');
    }
  } catch (err) {
    recordResult('LAN UDP Beacon Alındı', false, err.message);
  }

  // ----------------------------------------------------
  // TEST GRUBU 3: GOSSIP KEŞFİ VE EŞ TABLOSU
  // ----------------------------------------------------
  console.log(`\n${COLOR.BOLD}3. Gossip Keşfi ve Protokol Senkronizasyonu${COLOR.RESET}`);
  try {
    const gossipResp = await sendFedPacket(TEST_CONFIG.host, nodeA.fedPort, {
      type: 'GOSSIP_DISCOVERY',
      selfNode: 'virtual_node:9999',
      peers: ['virtual_peer_1:9001', 'virtual_peer_2:9002']
    });

    const isGossipValid = gossipResp && gossipResp.type === 'GOSSIP_RESPONSE' && Array.isArray(gossipResp.peers);
    recordResult('Node-1 GOSSIP_DISCOVERY Yanıtı', isGossipValid, `Gelen eş sayısı: ${gossipResp?.peers?.length ?? 0}`);
  } catch (err) {
    recordResult('Node-1 GOSSIP_DISCOVERY Yanıtı', false, err.message);
  }

  // ----------------------------------------------------
  // TEST GRUBU 4: FEDERASYON VARLIK (PRESENCE) VE KANAL ÜYELİĞİ
  // ----------------------------------------------------
  console.log(`\n${COLOR.BOLD}4. Federasyon Varlık ve Kanal Üyelik Senkronizasyonu (Presence)${COLOR.RESET}`);
  try {
    const presenceResp = await sendFedPacket(TEST_CONFIG.host, nodeA.fedPort, {
      type: 'PRESENCE_SYNC',
      memberships: [
        {
          user: '@bot_tester:localhost:9999',
          channels: ['#genel', '#test_odasi']
        }
      ]
    });

    const isPresenceValid = presenceResp && presenceResp.type === 'PRESENCE_ACK' && Array.isArray(presenceResp.memberships);
    recordResult('Node-1 PRESENCE_SYNC -> PRESENCE_ACK Protokolü', isPresenceValid);
  } catch (err) {
    recordResult('Node-1 PRESENCE_SYNC Protokolü', false, err.message);
  }

  // ----------------------------------------------------
  // TEST GRUBU 5: UZAK KANAL ABONELİĞİ (SUBSCRIBE / UNSUBSCRIBE)
  // ----------------------------------------------------
  console.log(`\n${COLOR.BOLD}5. Dinamik Uzak Kanal Abonelik Protokolü${COLOR.RESET}`);
  try {
    const subResp = await sendFedPacket(TEST_CONFIG.host, nodeA.fedPort, {
      type: 'CHANNEL_SUBSCRIBE',
      channel: '#ozel_oda:localhost:8001',
      subscriberNode: 'localhost:8002'
    });
    const isSubOk = subResp && subResp.status === 'subscribed';
    recordResult('Node-1 CHANNEL_SUBSCRIBE Kaydı', isSubOk);

    const unsubResp = await sendFedPacket(TEST_CONFIG.host, nodeA.fedPort, {
      type: 'CHANNEL_UNSUBSCRIBE',
      channel: '#ozel_oda:localhost:8001',
      subscriberNode: 'localhost:8002'
    });
    const isUnsubOk = unsubResp && unsubResp.status === 'unsubscribed';
    recordResult('Node-1 CHANNEL_UNSUBSCRIBE Çıkışı', isUnsubOk);
  } catch (err) {
    recordResult('Uzak Kanal Abonelik Protokolü', false, err.message);
  }

  // ----------------------------------------------------
  // TEST GRUBU 6: KÜRESEL MESAJ İLETİMİ VE SQLITE KAYIT KONTROLÜ
  // ----------------------------------------------------
  console.log(`\n${COLOR.BOLD}6. Mesaj İletimi ve Veritabanı Bütünlüğü (#genel & DM)${COLOR.RESET}`);
  const testMsgId = `test_${Date.now()}`;
  try {
    const deliveryResp = await sendFedPacket(TEST_CONFIG.host, nodeA.fedPort, {
      type: 'CHANNEL_MESSAGE',
      id: testMsgId,
      from: '@dis_kullanici:localhost:9999',
      to: '#genel',
      content: 'Protokol düzeyinde otomatik test mesajı',
      isAction: false,
      isSnippet: false,
      hop: 0,
      ttl: 5,
      timestamp: new Date().toISOString()
    });

    const isDelivered = deliveryResp && deliveryResp.status === 'delivered';
    recordResult('Node-1 Federasyon Mesaj Kabulü', isDelivered);

    // SQLite üzerinden doğrudan kayıt doğrulama
    try {
      const db = new DatabaseSync(nodeA.dbFile);
      const row = db.prepare('SELECT id, content FROM messages WHERE id = ?').get(testMsgId);
      db.close();

      const isDbOk = row && row.id === testMsgId;
      recordResult('Node-1 SQLite Veritabanı Kayıt Teyidi', isDbOk, isDbOk ? 'Kayıt diske yazıldı' : 'Satır bulunamadı');
    } catch (dbErr) {
      recordResult('Node-1 SQLite Veritabanı Kayıt Teyidi', false, dbErr.message);
    }
  } catch (err) {
    recordResult('Federasyon Mesaj İletimi', false, err.message);
  }

  // ----------------------------------------------------
  // TEST GRUBU 7: TELNET TUI VE MENTION / BİLDİRİM DOĞRULAMA
  // ----------------------------------------------------
  console.log(`\n${COLOR.BOLD}7. Telnet İstemci Girişi ve Mention / Zil Sinyali Testi${COLOR.RESET}`);
  let telnetClient = null;
  try {
    telnetClient = await connectTelnetClient(TEST_CONFIG.host, nodeA.clientPort, 'tester_bot');
    recordResult('Telnet Handshake ve Oturum Açma', true, 'Kullanıcı: tester_bot');

    // Bot dinlemedeyken ona federasyon portundan mention atan bir mesaj fırlatıyoruz
    const mentionMsgId = `mention_${Date.now()}`;
    const mentionPromise = new Promise((resolve) => {
      let buffer = '';
      telnetClient.on('data', (chunk) => {
        buffer += chunk.toString();
        // Zil karakteri (\x07) ve Mention [@]/[tester_bot] vurgusu yakalama
        if (buffer.includes('\x07') || buffer.includes('[@]') || buffer.includes('tester_bot')) {
          resolve(true);
        }
      });
      setTimeout(() => resolve(false), 3000);
    });

    await sendFedPacket(TEST_CONFIG.host, nodeA.fedPort, {
      type: 'CHANNEL_MESSAGE',
      id: mentionMsgId,
      from: '@gonderici:localhost:9999',
      to: '#genel',
      content: 'Hey @tester_bot nasılsın?',
      isAction: false,
      isSnippet: false,
      hop: 0,
      ttl: 5,
      timestamp: new Date().toISOString()
    });

    const isMentionReceived = await mentionPromise;
    recordResult('Mention (@tester_bot) Algılama ve Zil Sinyali', isMentionReceived, isMentionReceived ? 'Zil ve vurgu yakalandı' : 'Sinyal alınamadı');

    telnetClient.end();
  } catch (err) {
    recordResult('Telnet İstemci ve Mention Testi', false, err.message);
    if (telnetClient) telnetClient.destroy();
  }

  // ----------------------------------------------------
  // RAPOR ÖZETİ
  // ----------------------------------------------------
  console.log(`\n${COLOR.BOLD}${COLOR.CYAN}====================================================${COLOR.RESET}`);
  console.log(`${COLOR.BOLD} TEST TAMAMLANDI - ÖZET RAPOR${COLOR.RESET}`);
  console.log(`${COLOR.BOLD}${COLOR.CYAN}====================================================${COLOR.RESET}`);

  const passedCount = results.filter((r) => r.passed).length;
  const failedCount = results.filter((r) => !r.passed).length;
  const total = results.length;

  console.log(`Toplam Test : ${total}`);
  console.log(`Başarılı    : ${COLOR.GREEN}${passedCount}${COLOR.RESET}`);
  console.log(`Başarısız   : ${failedCount > 0 ? COLOR.RED : COLOR.GREEN}${failedCount}${COLOR.RESET}`);

  if (failedCount === 0) {
    console.log(`\n${COLOR.GREEN}${COLOR.BOLD}Tüm mimari ve protokol bileşenleri kusursuz çalışıyor!${COLOR.RESET}\n`);
  } else {
    console.log(`\n${COLOR.YELLOW}${COLOR.BOLD}Bazı kontroller başarısız oldu. Yukarıdaki logları inceleyin.${COLOR.RESET}\n`);
  }
}

runTestSuite();