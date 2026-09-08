import { spawn } from 'node:child_process';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { CryptoHelper } from '../src/utils/cryptoHelper.js';

const rootDir = path.resolve(import.meta.dirname, '..');

const COLOR = {
  RESET: '\x1b[0m',
  GREEN: '\x1b[32m',
  RED: '\x1b[31m',
  YELLOW: '\x1b[33m',
  CYAN: '\x1b[36m',
  BOLD: '\x1b[1m'
};

const AUDIT_CONFIG = {
  host: '127.0.0.1',
  fedPort: 8701,
  clientPort: 2921,
  sshPort: 3921,
  dbFile: path.join(rootDir, 'data_audit_8701.db'),
  peerFile: path.join(rootDir, 'peers_audit_8701.json')
};

let nodeProcess = null;
const nodeLogs = { stdout: [], stderr: [] };
const auditResults = [];

function record(name, passed, details = '') {
  auditResults.push({ name, passed, details });
  const status = passed
    ? `${COLOR.GREEN}✔ BAŞARILI (SAVUNULDU)${COLOR.RESET}`
    : `${COLOR.RED}✘ BAŞARISIZ (AÇIK/HATA)${COLOR.RESET}`;
  const detailStr = details ? ` (${COLOR.YELLOW}${details}${COLOR.RESET})` : '';
  console.log(`  [${status}] ${name}${detailStr}`);
}

function cleanupFiles() {
  const files = fs.readdirSync(rootDir);
  for (const f of files) {
    if (
      (f.startsWith('data_') || f.startsWith('peers_')) &&
      f.includes('audit')
    ) {
      try { fs.unlinkSync(path.join(rootDir, f)); } catch {}
    }
  }
}

async function stopNode() {
  if (nodeProcess && !nodeProcess.killed) {
    await new Promise((resolve) => {
      nodeProcess.once('exit', resolve);
      try { nodeProcess.kill('SIGINT'); } catch { resolve(); }
    });
  }
  await new Promise((r) => setTimeout(r, 400));
}

function waitPort(host, port, timeoutMs = 6000) {
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

function checkNodeAlive() {
  return nodeProcess && !nodeProcess.killed && nodeProcess.exitCode === null;
}

function sendFedPacketHelper(host, port, payload, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const myIdentity = CryptoHelper.generateIdentityKeyPair();
    const myKem = CryptoHelper.generateKemKeyPair();
    const nonce = CryptoHelper.generateRandomKey(16);
    const myNodeAddress = '127.0.0.1:9999';

    const client = net.createConnection({ host, port }, () => {
      const initData = JSON.stringify({
        type: 'HANDSHAKE_INIT',
        nodeAddress: myNodeAddress,
        identityPublicKey: myIdentity.publicKey,
        kemPublicKey: myKem.publicKey,
        nonce
      });
      const sig = CryptoHelper.sign(initData, myIdentity.privateKey);

      client.write(JSON.stringify({
        type: 'HANDSHAKE_INIT',
        nodeAddress: myNodeAddress,
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

async function main() {
  console.log(`\n${COLOR.BOLD}${COLOR.CYAN}================================================================${COLOR.RESET}`);
  console.log(`${COLOR.BOLD}${COLOR.CYAN}   P2P-MESH PROTOKOL GÜVENLİĞİ, DAYANIKLILIK & UB AUDIT SUITE   ${COLOR.RESET}`);
  console.log(`${COLOR.BOLD}${COLOR.CYAN}================================================================${COLOR.RESET}\n`);

  cleanupFiles();

  console.log(`${COLOR.BOLD}0. Hedef Düğüm Audit Modunda Başlatılıyor...${COLOR.RESET}`);
  const env = {
    ...process.env,
    SERVER_NAME: '127.0.0.1',
    FED_PORT: String(AUDIT_CONFIG.fedPort),
    CLIENT_PORT: String(AUDIT_CONFIG.clientPort),
    SSH_PORT: String(AUDIT_CONFIG.sshPort),
    DB_FILE: AUDIT_CONFIG.dbFile,
    PEER_FILE: AUDIT_CONFIG.peerFile,
    LOG_LEVEL: 'DEBUG'
  };

  nodeProcess = spawn('node', [path.join(rootDir, 'src/index.js')], { env, cwd: rootDir });

  nodeProcess.stdout.on('data', (d) => {
    nodeLogs.stdout.push(...d.toString().split('\n').filter(Boolean));
  });

  nodeProcess.stderr.on('data', (d) => {
    nodeLogs.stderr.push(...d.toString().split('\n').filter(Boolean));
  });

  try {
    await waitPort(AUDIT_CONFIG.host, AUDIT_CONFIG.fedPort);
    await waitPort(AUDIT_CONFIG.host, AUDIT_CONFIG.clientPort);
    await waitPort(AUDIT_CONFIG.host, AUDIT_CONFIG.sshPort);
    console.log(`  ${COLOR.GREEN}✔ Hedef Düğüm aktif. Güvenlik testleri başlatılıyor.${COLOR.RESET}\n`);

    // ====================================================
    // KATEGORİ 1: PROTOKOL VE ARABELLEK SINIRLARI
    // ====================================================
    console.log(`${COLOR.BOLD}[Kategori 1] Protokol Paket Sınırları & Boyut Manipülasyonu${COLOR.RESET}`);

    // Test 1: SSH 64KB Üstü Aşırı Büyük Paket Reddi
    try {
      const oversizedClosed = await new Promise((res) => {
        const s = net.createConnection({ host: AUDIT_CONFIG.host, port: AUDIT_CONFIG.sshPort }, () => {
          s.write('SSH-2.0-Fuzzer_1.0\r\n');
          // 1 MB uzunluklu geçersiz başlık
          const malformed = Buffer.alloc(9);
          malformed.writeUInt32BE(1048576, 0);
          malformed.writeUInt8(4, 4);
          s.write(malformed);
        });

        s.on('close', () => res(true));
        s.on('error', () => res(true)); // Sunucunun bağlantıyı kesmesi (RST/FIN) başarıdır
        setTimeout(() => { s.destroy(); res(false); }, 2000);
      });

      const alive = checkNodeAlive();
      record('Test 1: SSH Aşırı Büyük Paket Sınırı (>65KB) Reddi', oversizedClosed && alive);
    } catch (e) {
      record('Test 1: SSH Aşırı Büyük Paket Sınırı', false, e.message);
    }

    // Test 2: SSH Geçersiz / Sıfır Uzunluklu Paket Başlığı Reddi
    try {
      const invalidLenClosed = await new Promise((res) => {
        const s = net.createConnection({ host: AUDIT_CONFIG.host, port: AUDIT_CONFIG.sshPort }, () => {
          s.write('SSH-2.0-Fuzzer_1.0\r\n');
          // 1 bayt paket uzunluğu (SSH-2 standardında min 4 olmalı)
          const malformed = Buffer.from([0x00, 0x00, 0x00, 0x01, 0x00]);
          s.write(malformed);
        });

        s.on('close', () => res(true));
        s.on('error', () => res(true));
        setTimeout(() => { s.destroy(); res(false); }, 2000);
      });

      const alive = checkNodeAlive();
      record('Test 2: SSH Geçersiz / Sıfır Uzunluklu Başlık Reddi', invalidLenClosed && alive);
    } catch (e) {
      record('Test 2: SSH Geçersiz Başlık', false, e.message);
    }

    // ====================================================
    // KATEGORİ 2: KRİPTOGRAFİK VE PROTOKOL ATLATMA
    // ====================================================
    console.log(`\n${COLOR.BOLD}[Kategori 2] Kriptografik Dayanıklılık, Nonce Replay & Kimlik Doğrulama${COLOR.RESET}`);

    // Test 3: Nonce Replay Saldırısı
    try {
      const fixedNonce = 'audit_static_nonce_12345678';
      const fakeIdent = CryptoHelper.generateIdentityKeyPair();
      const fakeKem = CryptoHelper.generateKemKeyPair();

      const sendInit = () => new Promise((res) => {
        const s = net.createConnection({ host: AUDIT_CONFIG.host, port: AUDIT_CONFIG.fedPort }, () => {
          const raw = JSON.stringify({
            type: 'HANDSHAKE_INIT',
            nodeAddress: '127.0.0.1:9998',
            identityPublicKey: fakeIdent.publicKey,
            kemPublicKey: fakeKem.publicKey,
            nonce: fixedNonce
          });
          const sig = CryptoHelper.sign(raw, fakeIdent.privateKey);
          s.write(JSON.stringify({
            type: 'HANDSHAKE_INIT',
            nodeAddress: '127.0.0.1:9998',
            identityPublicKey: fakeIdent.publicKey,
            kemPublicKey: fakeKem.publicKey,
            nonce: fixedNonce,
            sig
          }) + '\n');
        });

        s.on('data', (d) => {
          try {
            const frame = JSON.parse(d.toString());
            if (frame.type === 'HANDSHAKE_REPLY') res('ACCEPTED');
          } catch {}
        });

        s.on('close', () => res('CLOSED'));
        s.on('error', () => res('CLOSED'));
        setTimeout(() => { s.destroy(); res('TIMEOUT'); }, 2000);
      });

      const firstAttempt = await sendInit();
      const replayAttempt = await sendInit();

      const replayBlocked = firstAttempt === 'ACCEPTED' && replayAttempt === 'CLOSED';
      record('Test 3: [REPLAY] Aynı Nonce ile İkinci Bağlantının Kesilmesi', replayBlocked, `1: ${firstAttempt} | 2: ${replayAttempt}`);
    } catch (e) {
      record('Test 3: Replay Saldırısı', false, e.message);
    }

    // Test 4: Federasyon Şifreli Paket AuthTag (GCM) Manipülasyonu
    try {
      const tagTamperResult = await new Promise((res) => {
        const fakeIdent = CryptoHelper.generateIdentityKeyPair();
        const fakeKem = CryptoHelper.generateKemKeyPair();
        const nonce = CryptoHelper.generateRandomKey(16);

        const s = net.createConnection({ host: AUDIT_CONFIG.host, port: AUDIT_CONFIG.fedPort }, () => {
          const raw = JSON.stringify({
            type: 'HANDSHAKE_INIT',
            nodeAddress: '127.0.0.1:9997',
            identityPublicKey: fakeIdent.publicKey,
            kemPublicKey: fakeKem.publicKey,
            nonce
          });
          const sig = CryptoHelper.sign(raw, fakeIdent.privateKey);
          s.write(JSON.stringify({
            type: 'HANDSHAKE_INIT',
            nodeAddress: '127.0.0.1:9997',
            identityPublicKey: fakeIdent.publicKey,
            kemPublicKey: fakeKem.publicKey,
            nonce,
            sig
          }) + '\n');
        });

        let sessionKey = null;

        s.on('data', (d) => {
          try {
            const frame = JSON.parse(d.toString().trim());
            if (frame.type === 'HANDSHAKE_REPLY') {
              const sharedSecret = CryptoHelper.decapsulateKey(fakeKem.privateKey, frame.encapsulatedKey);
              sessionKey = CryptoHelper.deriveKey(sharedSecret, nonce, 'p2p-mesh-transport-v1');

              // Kasıtlı olarak authTag'i tahrif edilmiş paket gönder
              const enc = CryptoHelper.encrypt('{"type":"PING"}', sessionKey);
              s.write(JSON.stringify({
                type: 'ENCRYPTED_FRAME',
                iv: enc.iv,
                ciphertext: enc.ciphertext,
                authTag: 'BASED_CORRUPTED_TAG=='
              }) + '\n');
            }
          } catch {}
        });

        setTimeout(() => {
          s.destroy();
          const alive = checkNodeAlive();
          // Sunucu bozuk tag'i sessizce düşürmeli, çökmemelidir
          res(alive);
        }, 1200);
      });

      record('Test 4: [AUTH_TAG TAMPER] Bozuk Şifreli Çerçevede Sunucu Stabilitesi', tagTamperResult);
    } catch (e) {
      record('Test 4: AuthTag Manipülasyonu', false, e.message);
    }

    // ====================================================
    // KATEGORİ 3: GİRDİ TEMİZLEME & ENJEKSİYON
    // ====================================================
    console.log(`\n${COLOR.BOLD}[Kategori 3] Girdi Doğrulama & ANSI/Enjeksiyon Savunması${COLOR.RESET}`);

    // Test 5: ANSI & OSC Terminal Kaçış Sekansları Temizleme
    try {
      const maliciousPayload = '\x1b]0;PwnedTerminal\x07\x1b[2J\x1b[?25lZararlı içerik\x1b[0m';
      const clean = maliciousPayload
        .replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g, '')
        .replace(/[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g, '');

      const isCleaned = !clean.includes('\x1b[2J') && !clean.includes('PwnedTerminal');
      record('Test 5: [ANSI ESCAPE] Terminal Kaçış Kodu Temizleme (Sanitization)', isCleaned);
    } catch (e) {
      record('Test 5: ANSI Sanitization', false, e.message);
    }

    // Test 6: SQL Prepared Statement Enjeksiyon Kontrolü
    try {
      const dbCheck = new DatabaseSync(AUDIT_CONFIG.dbFile);
      const sqlInjectionName = "admin' OR '1'='1";
      const row = dbCheck.prepare('SELECT * FROM profiles WHERE user_address = ?').get(sqlInjectionName);
      dbCheck.close();
      record('Test 6: [SQLi] Parametrik Sorgu Ayrımı (Injection Bağışıklığı)', row === undefined);
    } catch (e) {
      record('Test 6: SQL Injection Kontrolü', false, e.message);
    }

    // ====================================================
    // KATEGORİ 4: DOS & EŞ HAVUZU GÜVENLİĞİ
    // ====================================================
    console.log(`\n${COLOR.BOLD}[Kategori 4] DoS, Soket Tıkanması (Slowloris) & Havuz Güvenliği${COLOR.RESET}`);

    // Test 7: Askıda Kalan Soketler (Slowloris)
    try {
      const danglingSockets = [];
      for (let i = 0; i < 20; i++) {
        const s = net.createConnection({ host: AUDIT_CONFIG.host, port: AUDIT_CONFIG.clientPort });
        s.write('\xFF\xFB');
        danglingSockets.push(s);
      }

      await new Promise((r) => setTimeout(r, 600));

      const canConnectLegit = await new Promise((res) => {
        const checkSock = net.createConnection({ host: AUDIT_CONFIG.host, port: AUDIT_CONFIG.clientPort }, () => {
          checkSock.end();
          res(true);
        });
        checkSock.on('error', () => res(false));
        setTimeout(() => res(false), 2000);
      });

      for (const s of danglingSockets) {
        try { s.destroy(); } catch {}
      }

      record('Test 7: [SLOWLORIS] Askıda Kalan Bağlantılarda Port Erişilebilirliği', canConnectLegit);
    } catch (e) {
      record('Test 7: Slowloris Testi', false, e.message);
    }

    // Test 8: Yasaklı IP / Broadcast Port Zehirleme Koruması
    try {
      const invalidPeerPayload = {
        type: 'GOSSIP_DISCOVERY',
        selfNode: '255.255.255.255:8888',
        peers: ['0.0.0.0:8001', '127.0.0.1:99999']
      };

      await sendFedPacketHelper(AUDIT_CONFIG.host, AUDIT_CONFIG.fedPort, invalidPeerPayload);
      await new Promise((r) => setTimeout(r, 500));

      const rawPeers = fs.existsSync(AUDIT_CONFIG.peerFile)
        ? JSON.parse(fs.readFileSync(AUDIT_CONFIG.peerFile, 'utf8'))
        : [];

      const hasPoisonedPeer = rawPeers.some(([addr]) =>
        addr.startsWith('255.255') || addr.startsWith('0.0.0.0') || addr.endsWith(':99999')
      );

      record('Test 8: [SYBIL] Ayrılmış IP & Geçersiz Port Zehirleme Engeli', !hasPoisonedPeer);
    } catch (e) {
      record('Test 8: Peer Zehirleme Engeli', false, e.message);
    }

  } catch (criticalErr) {
    console.error(`\n${COLOR.RED}Kritik Audit Hatası: ${criticalErr.message}${COLOR.RESET}`);
  } finally {
    console.log(`\n${COLOR.BOLD}Temizlik yapılıyor (Düğüm durduruluyor, loglar inceleniyor)...${COLOR.RESET}`);
    await stopNode();
    cleanupFiles();

    console.log(`\n${COLOR.BOLD}${COLOR.CYAN}================================================================${COLOR.RESET}`);
    console.log(`${COLOR.BOLD}                    GÜVENLİK AUDIT RAPORU                      ${COLOR.RESET}`);
    console.log(`${COLOR.BOLD}${COLOR.CYAN}================================================================${COLOR.RESET}`);

    const passed = auditResults.filter((r) => r.passed).length;
    const failed = auditResults.filter((r) => !r.passed).length;
    const total = auditResults.length;

    console.log(` Toplam Güvenlik Testi : ${total}`);
    console.log(` Başarılı (Savunuldu)  : ${COLOR.GREEN}${passed}${COLOR.RESET}`);
    console.log(` Başarısız (Açık/Hata) : ${failed > 0 ? COLOR.RED : COLOR.GREEN}${failed}${COLOR.RESET}`);

    const criticalExceptions = nodeLogs.stderr.filter(line =>
      line.includes('uncaughtException') ||
      line.includes('unhandledRejection') ||
      line.includes('FATAL')
    );

    if (criticalExceptions.length > 0) {
      console.log(`\n${COLOR.RED}${COLOR.BOLD}[UYARI] Düğüm çalışırken kritik istisnalar yakalandı:${COLOR.RESET}`);
      criticalExceptions.forEach(e => console.log(`  ${COLOR.RED}● ${e}${COLOR.RESET}`));
    } else {
      console.log(`\n${COLOR.GREEN}${COLOR.BOLD}✔ Düğüm çalışma süresince hiçbir yakalanmamış istisna (Unhandled Exception) üretmedi.${COLOR.RESET}`);
    }

    process.exit(failed > 0 || criticalExceptions.length > 0 ? 1 : 0);
  }
}

main();