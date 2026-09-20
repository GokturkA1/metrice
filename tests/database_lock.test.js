import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs';
import { Database } from '../src/storage/database.js';

const rootDir = import.meta.dirname;
const testDbPath = path.join(rootDir, 'test_database_lock.db');
const testLockPath = `${testDbPath}.lock`;

function cleanup() {
  for (const suffix of ['', '-wal', '-shm', '.lock']) {
    const f = testDbPath + suffix;
    if (fs.existsSync(f)) {
      try { fs.unlinkSync(f); } catch {}
    }
  }
}

let passed = 0;
let failed = 0;

function record(name, condition, details = '') {
  if (condition) {
    passed++;
    console.log(`[BASARILI] ${name} ${details ? '(' + details + ')' : ''}`);
  } else {
    failed++;
    console.error(`[BASARISIZ] ${name} ${details ? '(' + details + ')' : ''}`);
  }
}

async function runTests() {
  console.log('\n====================================================');
  console.log(' METRICE DATABASE INSTANCE LOCK TEST SUITE');
  console.log('====================================================\n');

  cleanup();

  try {
    // 1. In-memory database lock muafiyeti
    const memDb1 = new Database(':memory:');
    const memDb2 = new Database(':memory:');
    record('Test 1: :memory: veritabanı kilit dosyasından muaftır', memDb1.lockFile === null && memDb2.lockFile === null);
    memDb1.close();
    memDb2.close();

    // 2. İlk instance dosya kilidini alır
    const db1 = new Database(testDbPath);
    record('Test 2.1: İlk instance kilit dosyasını başarıyla oluşturdu', fs.existsSync(testLockPath) && db1.hasLock === true);

    const lockContent = JSON.parse(fs.readFileSync(testLockPath, 'utf8'));
    record('Test 2.2: Kilit içeriği geçerli PID ve dosya yolu içeriyor', lockContent.pid === process.pid && lockContent.filepath === path.resolve(testDbPath));

    // 3. İkinci instance aynı db'yi açmaya çalıştığında SQLITE_BUSY_INSTANCE hatası fırlatır
    let lockedErr = null;
    try {
      new Database(testDbPath);
    } catch (err) {
      lockedErr = err;
    }
    record('Test 3.1: İkinci instance başlatılırken hata fırlatıldı', lockedErr !== null);
    record('Test 3.2: Hata kodu SQLITE_BUSY_INSTANCE', lockedErr && lockedErr.code === 'SQLITE_BUSY_INSTANCE');
    record('Test 3.3: Hata mesajı kilit bilgisini içeriyor', lockedErr && lockedErr.message.includes(String(process.pid)));

    // 4. İlk instance close() ile kapandığında lock dosyası silinir
    db1.close();
    record('Test 4.1: close() sonrası hasLock false oldu', db1.hasLock === false);
    record('Test 4.2: close() sonrası .lock dosyası silindi', !fs.existsSync(testLockPath));

    // 5. İlk instance kapandıktan sonra yeni instance sorunsuz açılır
    const db2 = new Database(testDbPath);
    record('Test 5.1: Kapanış sonrası yeni instance başarıyla açıldı', fs.existsSync(testLockPath) && db2.hasLock === true);
    db2.close();
    record('Test 5.2: İkinci instance kapatıldıktan sonra kilit temizlendi', !fs.existsSync(testLockPath));

    // 6. Stale / Zombi kilit temizliği testi
    // Var olmayan bir PID (ör. 99999999) içeren kilit dosyası oluşturuluyor
    const stalePayload = JSON.stringify({
      pid: 99999999,
      createdAt: Date.now() - 60000,
      filepath: path.resolve(testDbPath)
    });
    fs.writeFileSync(testLockPath, stalePayload);

    const dbStale = new Database(testDbPath);
    record('Test 6.1: Stale kilit tespit edildi ve yeni instance başarıyla açıldı', fs.existsSync(testLockPath) && dbStale.hasLock === true);
    const updatedLock = JSON.parse(fs.readFileSync(testLockPath, 'utf8'));
    record('Test 6.2: Kilit dosyası mevcut sürecin PID bilgisiyle güncellendi', updatedLock.pid === process.pid);
    dbStale.close();
    record('Test 6.3: Stale sonrası açılan instance temizlendi', !fs.existsSync(testLockPath));

    // 7. Bozuk JSON kilit dosyası temizliği testi
    fs.writeFileSync(testLockPath, '{ bozuk json içeriği !!!');
    const dbCorruptLock = new Database(testDbPath);
    record('Test 7.1: Bozuk kilit dosyası temizlenip yeni kilit alındı', fs.existsSync(testLockPath) && dbCorruptLock.hasLock === true);
    dbCorruptLock.close();
    record('Test 7.2: Temizleme tamamlandı', !fs.existsSync(testLockPath));

  } catch (err) {
    record('Kritik test hatasi: ' + err.message, false);
    console.error(err);
  } finally {
    cleanup();
  }

  console.log('\n====================================================');
  console.log(` Toplam Test : ${passed + failed}`);
  console.log(` Basarili    : ${passed}`);
  console.log(` Basarisiz   : ${failed}`);
  console.log('====================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests();
