import net from 'node:net';
import path from 'node:path';
import fs from 'node:fs';
import { HealthServer } from '../src/core/healthServer.js';
import { Database } from '../src/storage/database.js';

const testDbPath = path.join(import.meta.dirname, 'test_health.db');

function cleanup() {
  for (const suffix of ['', '-wal', '-shm']) {
    const f = testDbPath + suffix;
    if (fs.existsSync(f)) {
      try { fs.unlinkSync(f); } catch {}
    }
  }
}

function sendCommand(port, host, cmd) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, host);
    let data = '';
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('Socket timeout'));
    }, 3000);

    socket.on('connect', () => {
      if (cmd) {
        socket.write(cmd + '\n');
      }
    });

    socket.on('data', (chunk) => {
      data += chunk.toString('utf8');
      if (data.includes('\n')) {
        clearTimeout(timer);
        socket.end();
        resolve(data.trim());
      }
    });

    socket.on('close', () => {
      clearTimeout(timer);
      resolve(data.trim());
    });

    socket.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function runTests() {
  console.log('====================================================');
  console.log(' METRICE TCP HEALTH & HEARTBEAT PROTOL TEST SÜİTİ  ');
  console.log('====================================================\n');

  cleanup();
  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`[✔ GEÇTİ] ${message}`);
      passed++;
    } else {
      console.error(`[✖ BAŞARISIZ] ${message}`);
      failed++;
    }
  }

  const db = new Database(testDbPath);
  const mockFederation = {
    role: 'RELAY',
    meshAddress: 'testnode12345678.mesh',
    nodeAddress: 'localhost:8001',
    rendezvousTunnels: new Map([['peer1', {}]]),
    onionRouter: { circuits: new Map([['c1', {}], ['c2', {}]]) }
  };
  const mockPeerManager = {
    peers: new Map([
      ['peer1:8001', { failures: 0, score: 95 }],
      ['peer2:8001', { failures: 2, score: 40 }]
    ])
  };

  const testPort = 8950;
  const server = new HealthServer(db, mockFederation, mockPeerManager, {
    port: testPort,
    allowOuterHeartbeat: false
  });

  try {
    await server.start();
    assert(server.host === '127.0.0.1', 'Varsayılan host 127.0.0.1 (Loopback) olarak yapılandırıldı');
    assert(server.port === testPort, `Port ${testPort} olarak başarıyla bağlandı`);

    // Test 1: PING -> PONG
    const pingRes = await sendCommand(testPort, '127.0.0.1', 'PING');
    assert(pingRes === 'PONG', `PING komutuna PONG yanıtı alındı (${pingRes})`);

    // Test 2: HEALTH
    const healthRes = await sendCommand(testPort, '127.0.0.1', 'HEALTH');
    assert(healthRes.startsWith('OK '), `HEALTH komutu OK ile başladı: ${healthRes}`);
    const healthJson = JSON.parse(healthRes.slice(3));
    assert(healthJson.status === 'healthy', 'HEALTH durumu "healthy" döndü');
    assert(healthJson.database === 'healthy', 'Veritabanı durumu "healthy" döndü');
    assert(typeof healthJson.uptime === 'number', 'Çalışma süresi (uptime) sayısal formatta döndü');

    // Test 3: STATUS / INFO
    const statusRes = await sendCommand(testPort, '127.0.0.1', 'STATUS');
    const statusJson = JSON.parse(statusRes);
    assert(statusJson.status === 'healthy', 'STATUS durumu "healthy"');
    assert(statusJson.meshRole === 'RELAY', `Düğüm rolü RELAY doğrulandı (${statusJson.meshRole})`);
    assert(statusJson.nodeAddress === 'testnode12345678.mesh', `Düğüm mesh adresi doğrulandı (${statusJson.nodeAddress})`);
    assert(statusJson.federation.activeRendezvousTunnels === 1, 'Aktif Rendezvous tünel sayısı (1) raporlandı');
    assert(statusJson.federation.activeCircuits === 2, 'Aktif Onion devresi sayısı (2) raporlandı');
    assert(statusJson.peers.totalKnown === 2, 'Toplam bilinen eş sayısı (2) raporlandı');
    assert(statusJson.peers.verified === 1, 'Doğrulanmış eş sayısı (1) raporlandı');
    assert(typeof statusJson.memory.rssMb === 'number', 'Bellek RSS metrikleri raporlandı');

    // Test 4: QUIT
    const quitRes = await sendCommand(testPort, '127.0.0.1', 'QUIT');
    assert(quitRes === '', 'QUIT komutu soketi temiz şekilde kapattı');

    // Test 5: Bilinmeyen komut
    const errRes = await sendCommand(testPort, '127.0.0.1', 'UNKNOWN_COMMAND');
    assert(errRes === 'ERR unknown_command', 'Bilinmeyen komuta ERR yanıtı verildi');

    // Test 6: Ani soket kapanışı (Silent disconnect)
    await new Promise((resolve) => {
      const s = net.connect(testPort, '127.0.0.1', () => {
        s.destroy();
        setTimeout(resolve, 50);
      });
    });
    assert(true, 'Ani istemci kopması (s.destroy) sunucuda hatasız yönetildi');

    server.close();

    // Test 7: ALLOW_OUTER_HEARTBEAT yapılandırması
    const outerServer = new HealthServer(db, mockFederation, mockPeerManager, {
      port: 8951,
      allowOuterHeartbeat: true
    });
    await outerServer.start();
    assert(outerServer.host === '0.0.0.0', 'allowOuterHeartbeat: true durumunda host 0.0.0.0 olarak yapılandırıldı');
    outerServer.close();

  } finally {
    server.close();
    db.close();
    cleanup();
  }

  console.log('\n====================================================');
  console.log(` Toplam Test : ${passed + failed}`);
  console.log(` Başarılı    : ${passed}`);
  console.log(` Başarısız   : ${failed}`);
  console.log('====================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Test süiti beklenmeyen hata ile sonlandı:', err);
  process.exit(1);
});
