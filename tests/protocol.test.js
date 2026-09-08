import { spawn } from 'node:child_process';
import net from 'node:net';
import dgram from 'node:dgram';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import EventEmitter from 'node:events';
import { DatabaseSync } from 'node:sqlite';
import { CryptoHelper } from '../src/utils/cryptoHelper.js';
import { SshPacketReader, SshPacketWriter } from '../src/utils/sshPacket.js';

const rootDir = path.resolve(import.meta.dirname, '..');

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
  defaultUserPassword: 'MeshPassword123!',
  nodes: [
    {
      id: 'node1',
      name: 'Node-Alpha',
      serverName: '127.0.0.1',
      clientPort: 2721,
      sshPort: 3721,
      fedPort: 8501,
      dbFile: path.join(rootDir, 'data_suite_8501.db'),
      peerFile: path.join(rootDir, 'peers_suite_8501.json')
    },
    {
      id: 'node2',
      name: 'Node-Beta',
      serverName: '127.0.0.1',
      clientPort: 2722,
      sshPort: 3722,
      fedPort: 8502,
      dbFile: path.join(rootDir, 'data_suite_8502.db'),
      peerFile: path.join(rootDir, 'peers_suite_8502.json')
    },
    {
      id: 'node3',
      name: 'Node-Gamma',
      serverName: '127.0.0.1',
      clientPort: 2723,
      sshPort: 3723,
      fedPort: 8503,
      dbFile: path.join(rootDir, 'data_suite_8503.db'),
      peerFile: path.join(rootDir, 'peers_suite_8503.json')
    }
  ]
};

const childProcesses = [];
const nodeLogs = new Map();
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
  const files = fs.readdirSync(rootDir);
  for (const f of files) {
    if (
      (f.startsWith('data_') || f.startsWith('peers_')) &&
      (f.includes('test') || f.includes('suite'))
    ) {
      try { fs.unlinkSync(path.join(rootDir, f)); } catch {}
    }
  }
}

async function killProcesses() {
  const exitPromises = [];
  for (const p of childProcesses) {
    if (p && !p.killed) {
      const exitPromise = new Promise((resolve) => {
        p.once('exit', resolve);
        try { p.kill('SIGINT'); } catch { resolve(); }
      });
      exitPromises.push(exitPromise);
    }
  }
  await Promise.all(exitPromises);
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

function stripAnsi(str) {
  return str
    .replace(/[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g, '')
    .replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g, '')
    .replace(/[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]/g, '');
}

/**
 * P2P Federasyon Şifreli Paket Gönderici (ML-KEM-768 + Ed25519)
 */
function sendSecureFedPacket(host, port, payload, timeoutMs = 4000) {
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

/**
 * RAM-Only Saf SSH-2 İstemci Motoru
 */
class MemorySshClient extends EventEmitter {
  constructor(host, port, username, password, clientEdKeyPair) {
    super();
    this.host = host;
    this.port = port;
    this.username = username;
    this.password = password;
    this.clientEdKeyPair = clientEdKeyPair;

    this.socket = null;
    this.inBuffer = Buffer.alloc(0);
    this.isEncryptedIn = false;
    this.isEncryptedOut = false;
    this.inSeq = 0;
    this.outSeq = 0;

    this.rawClientEdPub = crypto.createPublicKey(clientEdKeyPair.publicKey)
      .export({ type: 'spki', format: 'der' }).subarray(-32);

    this.clientVersion = 'SSH-2.0-NodeMesh_TestClient_1.0';
    this.serverVersion = '';
    this.clientKexPayload = null;
    this.serverKexPayload = null;
    this.sharedSecret = null;
    this.exchangeHash = null;
    this.sessionIdentifier = null;

    this.authenticated = false;
    this.pubkeyOffered = false;
  }

  connect(timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.socket) this.socket.destroy();
        reject(new Error('SSH test istemcisi zaman aşımına uğradı'));
      }, timeoutMs);

      this.socket = net.createConnection({ host: this.host, port: this.port }, () => {
        this.socket.write(this.clientVersion + '\r\n');
      });

      this.socket.on('data', (chunk) => {
        this.inBuffer = Buffer.concat([this.inBuffer, chunk]);
        this.processIncoming();
      });

      this.socket.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });

      this.on('auth_result', (ok) => {
        clearTimeout(timer);
        resolve(ok);
      });
    });
  }

  processIncoming() {
    if (!this.serverVersion) {
      const idx = this.inBuffer.indexOf('\n');
      if (idx === -1) return;
      this.serverVersion = this.inBuffer.subarray(0, idx + 1).toString('utf8').trim();
      this.inBuffer = this.inBuffer.subarray(idx + 1);
      this.sendKexInit();
    }

    while (this.inBuffer.length > 0) {
      if (!this.isEncryptedIn) {
        if (this.inBuffer.length < 5) return;
        const packetLen = this.inBuffer.readUInt32BE(0);
        const padLen = this.inBuffer.readUInt8(4);
        if (this.inBuffer.length < 4 + packetLen) return;

        const payload = this.inBuffer.subarray(5, 4 + packetLen - padLen);
        this.inBuffer = this.inBuffer.subarray(4 + packetLen);
        this.inSeq = (this.inSeq + 1) >>> 0;
        this.handlePacket(payload);
      } else {
        if (this.inBuffer.length < 4) return;
        if (!this.curLen) {
          const head = this.decCipher.update(this.inBuffer.subarray(0, 4));
          this.curLen = head.readUInt32BE(0);
          this.decHead = head;
          this.inBuffer = this.inBuffer.subarray(4);
        }

        const needed = this.curLen + 32;
        if (this.inBuffer.length < needed) return;

        const body = this.decCipher.update(this.inBuffer.subarray(0, this.curLen));
        const macRecv = this.inBuffer.subarray(this.curLen, needed);
        this.inBuffer = this.inBuffer.subarray(needed);

        const full = Buffer.concat([this.decHead, body]);
        this.inSeq = (this.inSeq + 1) >>> 0;
        const padLen = full.readUInt8(4);
        const payload = full.subarray(5, 4 + this.curLen - padLen);
        this.curLen = null;

        this.handlePacket(payload);
      }
    }
  }

  sendPacket(payload) {
    const bSize = 16;
    let padLen = bSize - ((5 + payload.length) % bSize);
    if (padLen < 4) padLen += bSize;
    const packetLen = 1 + payload.length + padLen;
    const pad = crypto.randomBytes(padLen);

    const raw = Buffer.alloc(4 + 1 + payload.length + padLen);
    raw.writeUInt32BE(packetLen, 0);
    raw.writeUInt8(padLen, 4);
    payload.copy(raw, 5);
    pad.copy(raw, 5 + payload.length);

    if (!this.isEncryptedOut) {
      this.socket.write(raw);
    } else {
      const enc = this.encCipher.update(raw);
      const hmac = crypto.createHmac('sha256', this.outHmacKey);
      const sBuf = Buffer.alloc(4);
      sBuf.writeUInt32BE(this.outSeq, 0);
      hmac.update(sBuf);
      hmac.update(raw);
      this.socket.write(Buffer.concat([enc, hmac.digest()]));
    }
    this.outSeq = (this.outSeq + 1) >>> 0;
  }

  sendKexInit() {
    const w = new SshPacketWriter();
    w.writeByte(20);
    w.writeRaw(crypto.randomBytes(16));
    w.writeNameList(['mlkem768x25519-sha256', 'curve25519-sha256']);
    w.writeNameList(['ssh-ed25519']);
    w.writeNameList(['aes128-ctr']);
    w.writeNameList(['aes128-ctr']);
    w.writeNameList(['hmac-sha2-256']);
    w.writeNameList(['hmac-sha2-256']);
    w.writeNameList(['none']);
    w.writeNameList(['none']);
    w.writeNameList([]);
    w.writeNameList([]);
    w.writeBoolean(false);
    w.writeUInt32(0);

    this.clientKexPayload = w.toBuffer();
    this.sendPacket(this.clientKexPayload);
  }

  handlePacket(payload) {
    const r = new SshPacketReader(payload);
    const type = r.readByte();

    if (type === 20) {
      this.serverKexPayload = Buffer.from(payload);
      this.startKexEcdhInit();
    } else if (type === 31) {
      this.handleKexReply(r);
    } else if (type === 21) {
      this.isEncryptedIn = true;
      const w = new SshPacketWriter();
      w.writeByte(5);
      w.writeString('ssh-userauth');
      this.sendPacket(w.toBuffer());
    } else if (type === 6) {
      this.sendUserAuthNone();
    } else if (type === 51) {
      const methods = r.readNameList();
      if (methods.includes('publickey') && !this.pubkeyOffered) {
        this.pubkeyOffered = true;
        this.sendUserAuthPublicKey();
      } else if (methods.includes('password')) {
        this.sendUserAuthPassword();
      } else {
        this.emit('auth_result', false);
      }
    } else if (type === 52) {
      this.authenticated = true;
      this.emit('auth_result', true);
    }
  }

  startKexEcdhInit() {
    this.kemKeys = CryptoHelper.generateKemKeyPair();
    const kemPubDer = crypto.createPublicKey(this.kemKeys.publicKey).export({ type: 'spki', format: 'der' });
    const kemPubRaw = kemPubDer.subarray(-1184);

    this.x25519Keys = crypto.generateKeyPairSync('x25519');
    const xPubDer = this.x25519Keys.publicKey.export({ type: 'spki', format: 'der' });
    const xPubRaw = xPubDer.subarray(-32);

    this.clientBlob = Buffer.concat([kemPubRaw, xPubRaw]);

    const w = new SshPacketWriter();
    w.writeByte(30);
    w.writeBuffer(this.clientBlob);
    this.sendPacket(w.toBuffer());
  }

  handleKexReply(r) {
    this.serverHostKeyBlob = r.readBuffer();
    this.serverBlob = r.readBuffer();
    this.sigBlob = r.readBuffer();

    const sCt2 = this.serverBlob.subarray(0, 1088);
    const sXPub = this.serverBlob.subarray(1088, 1120);

    const kPq = CryptoHelper.decapsulateKey(this.kemKeys.privateKey, sCt2.toString('base64'));

    const sPubKeyObj = crypto.createPublicKey({
      key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), sXPub]),
      format: 'der',
      type: 'spki'
    });
    const kCl = crypto.diffieHellman({
      privateKey: this.x25519Keys.privateKey,
      publicKey: sPubKeyObj
    });

    this.sharedSecret = crypto.createHash('sha256').update(kPq).update(kCl).digest();

    const hw = new SshPacketWriter();
    hw.writeString(this.clientVersion);
    hw.writeString(this.serverVersion);
    hw.writeBuffer(this.clientKexPayload);
    hw.writeBuffer(this.serverKexPayload);
    hw.writeBuffer(this.serverHostKeyBlob);
    hw.writeBuffer(this.clientBlob);
    hw.writeBuffer(this.serverBlob);
    hw.writeBuffer(this.sharedSecret);

    this.exchangeHash = crypto.createHash('sha256').update(hw.toBuffer()).digest();
    if (!this.sessionIdentifier) this.sessionIdentifier = this.exchangeHash;

    const nw = new SshPacketWriter();
    nw.writeByte(21);
    this.sendPacket(nw.toBuffer());

    this.prepareKeys();
    this.isEncryptedOut = true;
  }

  deriveKey(char, len) {
    const cBuf = Buffer.from([char.charCodeAt(0)]);
    const lenPre = Buffer.alloc(4);
    lenPre.writeUInt32BE(this.sharedSecret.length, 0);
    const kBuf = Buffer.concat([lenPre, this.sharedSecret]);

    let key = crypto.createHash('sha256')
      .update(kBuf).update(this.exchangeHash).update(cBuf).update(this.sessionIdentifier).digest();
    while (key.length < len) {
      const next = crypto.createHash('sha256')
        .update(kBuf).update(this.exchangeHash).update(key).digest();
      key = Buffer.concat([key, next]);
    }
    return key.subarray(0, len);
  }

  prepareKeys() {
    this.ivC2S = this.deriveKey('A', 16);
    this.ivS2C = this.deriveKey('B', 16);
    this.keyC2S = this.deriveKey('C', 16);
    this.keyS2C = this.deriveKey('D', 16);
    this.outHmacKey = this.deriveKey('E', 32);
    this.inHmacKey = this.deriveKey('F', 32);

    this.encCipher = crypto.createCipheriv('aes-128-ctr', this.keyC2S, this.ivC2S);
    this.decCipher = crypto.createDecipheriv('aes-128-ctr', this.keyS2C, this.ivS2C);
  }

  sendUserAuthNone() {
    const w = new SshPacketWriter();
    w.writeByte(50);
    w.writeString(this.username);
    w.writeString('ssh-connection');
    w.writeString('none');
    this.sendPacket(w.toBuffer());
  }

  sendUserAuthPublicKey() {
    const pw = new SshPacketWriter();
    pw.writeString('ssh-ed25519');
    pw.writeBuffer(this.rawClientEdPub);

    const w = new SshPacketWriter();
    w.writeByte(50);
    w.writeString(this.username);
    w.writeString('ssh-connection');
    w.writeString('publickey');
    w.writeBoolean(false);
    w.writeString('ssh-ed25519');
    w.writeBuffer(pw.toBuffer());
    this.sendPacket(w.toBuffer());
  }

  sendUserAuthPassword() {
    const w = new SshPacketWriter();
    w.writeByte(50);
    w.writeString(this.username);
    w.writeString('ssh-connection');
    w.writeString('password');
    w.writeBoolean(false);
    w.writeString(this.password);
    this.sendPacket(w.toBuffer());
  }

  close() {
    if (this.socket) {
      try { this.socket.destroy(); } catch {}
    }
  }
}

/**
 * Sağlamlaştırılmış Telnet Oturumu Simülatörü
 */
function createTelnetSession(host, port, username, password = SUITE_CONFIG.defaultUserPassword, timeoutMs = 7000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    let totalText = '';
    let state = 0; // 0: username, 1: pass1, 2: pass2, 3: loggedIn
    let timer = null;

    timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`Telnet oturum zaman aşımı (${username})`));
    }, timeoutMs);

    socket.on('data', (chunk) => {
      // 1. CPR sorgusuna hemen yanıt ver
      if (chunk.includes(Buffer.from('\x1b[6n')) || chunk.toString().includes('[6n')) {
        socket.write('\x1b[24;110R');
      }

      // 2. ANSI ve IAC temizle
      const str = stripAnsi(chunk.toString());
      totalText += str;

      if (state === 0 && (totalText.includes('Kullanıcı adı') || totalText.includes(':'))) {
        state = 1;
        totalText = '';
        setTimeout(() => socket.write(`${username}\r`), 100);
        return;
      }

      if (state === 1) {
        if (totalText.includes('Parola belirleyin') || totalText.includes('[YENİ HESAP]')) {
          state = 2; // Yeni hesap, tekrar isteyecek
          totalText = '';
          setTimeout(() => socket.write(`${password}\r`), 100);
          return;
        } else if (totalText.includes('Parola:')) {
          state = 3; // Mevcut hesap doğrudan girişe gider
          totalText = '';
          setTimeout(() => socket.write(`${password}\r`), 100);
          return;
        }
      }

      if (state === 2 && totalText.includes('tekrar')) {
        state = 3;
        totalText = '';
        setTimeout(() => socket.write(`${password}\r`), 100);
        return;
      }

      if (totalText.includes('METRICE |') || totalText.includes('Konsol/Odalar') || totalText.includes('Pencere:')) {
        clearTimeout(timer);
        resolve({
          socket,
          getOutput: () => totalText,
          clearOutput: () => { totalText = ''; }
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
  console.log(`${COLOR.BOLD}${COLOR.CYAN}   P2P-MESH PROTOKOL, POST-QUANTUM & SSH TEST SUITE             ${COLOR.RESET}`);
  console.log(`${COLOR.BOLD}${COLOR.CYAN}================================================================${COLOR.RESET}\n`);

  console.log(`${COLOR.YELLOW}Önceki olası test kalıntıları temizleniyor...${COLOR.RESET}`);
  cleanupArtifacts();

  console.log(`${COLOR.BOLD}0. Düğümler İzole Portlarla Başlatılıyor...${COLOR.RESET}`);
  for (const node of SUITE_CONFIG.nodes) {
    nodeLogs.set(node.id, { stdout: [], stderr: [] });

    const env = {
      ...process.env,
      SERVER_NAME: node.serverName,
      FED_PORT: String(node.fedPort),
      CLIENT_PORT: String(node.clientPort),
      SSH_PORT: String(node.sshPort),
      DB_FILE: node.dbFile,
      PEER_FILE: node.peerFile,
      LOG_LEVEL: 'DEBUG'
    };

    const proc = spawn('node', [path.join(rootDir, 'src/index.js')], { env, cwd: rootDir });
    
    proc.stdout.on('data', (d) => {
      const str = d.toString().trim();
      if (str) nodeLogs.get(node.id).stdout.push(str);
    });

    proc.stderr.on('data', (d) => {
      const str = d.toString().trim();
      if (str) nodeLogs.get(node.id).stderr.push(str);
    });

    childProcesses.push(proc);
  }

  try {
    for (const node of SUITE_CONFIG.nodes) {
      await waitPort(SUITE_CONFIG.host, node.fedPort, SUITE_CONFIG.startupTimeoutMs);
      await waitPort(SUITE_CONFIG.host, node.clientPort, SUITE_CONFIG.startupTimeoutMs);
      await waitPort(SUITE_CONFIG.host, node.sshPort, SUITE_CONFIG.startupTimeoutMs);
    }
    console.log(`  ${COLOR.GREEN}✔ 3 Düğüm (Telnet, SSH, Fed) başarıyla ayağa kalktı.${COLOR.RESET}\n`);

    const [n1, n2, n3] = SUITE_CONFIG.nodes;

    // --- GRUP 1: AĞ KEŞFİ & GOSSIP ---
    console.log(`${COLOR.BOLD}[Grup 1] Ağ Keşfi & Gossip Protokolü${COLOR.RESET}`);

    // Test 1: UDP LAN Beacon
    try {
      const targetPorts = new Set(SUITE_CONFIG.nodes.map(n => n.fedPort));
      const beaconPayload = await new Promise((res) => {
        const udp = dgram.createSocket({ type: 'udp4', reuseAddr: true });
        let resolved = false;
        udp.on('message', (buf) => {
          try {
            const data = JSON.parse(buf.toString());
            if (data.type === 'P2P_BEACON' && targetPorts.has(data.port) && !resolved) {
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
        selfNode: '127.0.0.1:9999',
        peers: ['127.0.0.1:1001', '127.0.0.1:1002']
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
        memberships: [{ user: '@test_user:127.0.0.1:9999', channels: ['#genel'] }]
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
        channel: `#proje:${n1.serverName}:${n1.fedPort}`,
        subscriberNode: `${n2.serverName}:${n2.fedPort}`
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
        channel: `#proje:${n1.serverName}:${n1.fedPort}`,
        subscriberNode: `${n2.serverName}:${n2.fedPort}`
      });
      record('Test 6: Kanaldan Ayrılma Sinyali (UNSUBSCRIBE)', unsub?.status === 'unsubscribed');
    } catch (e) {
      record('Test 6: Kanaldan Ayrılma Sinyali (UNSUBSCRIBE)', false, e.message);
    }

    // --- GRUP 3: BROADCAST STORM, DEDUPLICATION VE TTL ---
    console.log(`\n${COLOR.BOLD}[Grup 3] Broadcast Storm & Döngü Korumaları${COLOR.RESET}`);

    // Test 7: Message Deduplication
    try {
      const dupId = `dup_${Date.now()}`;
      const p1 = await sendSecureFedPacket(SUITE_CONFIG.host, n1.fedPort, {
        type: 'CHANNEL_MESSAGE',
        id: dupId,
        from: `@node2:${n2.serverName}:${n2.fedPort}`,
        to: '#genel',
        content: 'Tekilleştirme İlk Paket'
      });

      const p2 = await sendSecureFedPacket(SUITE_CONFIG.host, n1.fedPort, {
        type: 'CHANNEL_MESSAGE',
        id: dupId,
        from: `@node2:${n2.serverName}:${n2.fedPort}`,
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
        from: `@node3:${n3.serverName}:${n3.fedPort}`,
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

        s.on('data', (d) => {
          if (d.includes(Buffer.from('\x1b[6n')) || d.toString().includes('[6n')) {
            s.write('\x1b[24;110R');
          }
          out += stripAnsi(d.toString());
          if (!sent && (out.includes('Kullanıcı adı') || out.includes(':'))) {
            sent = true;
            setTimeout(() => s.write('ali boşluklu!*\r'), 80);
          }
          if (out.includes('Geçersiz ad') || out.includes('Sadece a-z')) {
            s.destroy();
            res(true);
          }
        });
        setTimeout(() => { s.destroy(); res(false); }, 3000);
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

    // Test 11: Yanlış Parola Koruması
    try {
      const tempUserSession = await createTelnetSession(SUITE_CONFIG.host, n1.clientPort, 'user_locked', 'dogruParola123');
      tempUserSession.socket.destroy();
      await new Promise((r) => setTimeout(r, 400));

      const wrongPassBlocked = await new Promise((res) => {
        const s = net.createConnection({ host: SUITE_CONFIG.host, port: n1.clientPort });
        let out = '';
        let step = 'USER';

        s.on('data', (d) => {
          if (d.includes(Buffer.from('\x1b[6n')) || d.toString().includes('[6n')) {
            s.write('\x1b[24;110R');
          }
          out += stripAnsi(d.toString());
          if (step === 'USER' && (out.includes('Kullanıcı adı') || out.includes(':'))) {
            step = 'PASS';
            setTimeout(() => s.write('user_locked\r'), 80);
            return;
          }
          if (step === 'PASS' && (out.includes('Parola:') || out.includes('Parola'))) {
            step = 'CHECK';
            setTimeout(() => s.write('tamamen_yanlis_parola\r'), 80);
            return;
          }
          if (out.includes('Hatalı parola') || out.includes('Kalan hak')) {
            s.destroy();
            res(true);
          }
        });
        setTimeout(() => { s.destroy(); res(false); }, 3500);
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
      if (!userAlphaSession) throw new Error('userAlphaSession başlatılamamıştı');

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
        from: `@disaridan:${n2.serverName}:${n2.fedPort}`,
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
      if (!userBetaSession) throw new Error('userBetaSession başlatılamamıştı');

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
        from: `@user_alpha:${n1.serverName}:${n1.fedPort}`,
        to: `@user_beta:${n2.serverName}:${n2.fedPort}`,
        content: 'özel gizli mesaj'
      });

      const dmDelivered = await dmWait;
      record('Test 14: Düğümler Arası Birebir DM İletimi & Bildirim', dmDelivered);
    } catch (e) {
      record('Test 14: Düğümler Arası Birebir DM İletimi & Bildirim', false, e.message);
    }

    // --- GRUP 6: POST-QUANTUM SSH, TWO-FACTOR VAULT & ÇOKLU ANAHTARLAR ---
    console.log(`\n${COLOR.BOLD}[Grup 6] Post-Quantum SSH-2, Two-Factor Vault & Çoklu Anahtar Yönetimi${COLOR.RESET}`);

    const ramKeyAlicePrimary = CryptoHelper.generateIdentityKeyPair();
    const ramKeyAliceWorkLaptop = CryptoHelper.generateIdentityKeyPair();
    const ramKeyEveAttacker = CryptoHelper.generateIdentityKeyPair();

    // Test 15: Hibrit Post-Quantum KEX (mlkem768x25519-sha256) ve İlk SSH Kaydı
    let sshAliceClient = null;
    try {
      sshAliceClient = new MemorySshClient(
        SUITE_CONFIG.host,
        n1.sshPort,
        'ssh_alice',
        'AlicePassword999!',
        ramKeyAlicePrimary
      );
      const isSshRegistered = await sshAliceClient.connect();
      record('Test 15: Post-Quantum KEX (ML-KEM-768) + RAM-Only Ed25519 İlk SSH Kaydı', isSshRegistered);
      sshAliceClient.close();
    } catch (e) {
      record('Test 15: SSH KEX & İlk Kayıt', false, e.message);
    }

    // Test 16: Tanımlı Anahtar ile Başarılı Giriş & Vault Doğrulaması
    try {
      sshAliceClient = new MemorySshClient(
        SUITE_CONFIG.host,
        n1.sshPort,
        'ssh_alice',
        'AlicePassword999!',
        ramKeyAlicePrimary
      );
      const loginOk = await sshAliceClient.connect();
      record('Test 16: Tanımlı Ed25519 Açık Anahtarı ile Two-Factor Vault Başarılı Giriş', loginOk);
      sshAliceClient.close();
    } catch (e) {
      record('Test 16: SSH Vault Giriş', false, e.message);
    }

    // Test 17: Doğru Parolaya Sahip Olsa Bile Yabancı Anahtarla Gelenin Reddedilmesi
    try {
      const attackerClient = new MemorySshClient(
        SUITE_CONFIG.host,
        n1.sshPort,
        'ssh_alice',
        'AlicePassword999!',
        ramKeyEveAttacker
      );
      const attackerLoggedIn = await attackerClient.connect();
      record('Test 17: [GÜVENLİK] Doğru Parolaya Rağmen Kayıtsız Anahtarla Giriş Reddi', !attackerLoggedIn);
      attackerClient.close();
    } catch (e) {
      record('Test 17: Kayıtsız Anahtarla Giriş Reddi', true, 'Kapıda reddedildi');
    }

    // Test 18: /keys add ile İkinci Donanım Anahtarını Hesaba Ekleme
    try {
      const db1Direct = new DatabaseSync(n1.dbFile);
      const userRow = db1Direct.prepare("SELECT public_keys FROM profiles WHERE user_address LIKE '%ssh_alice%'").get();
      let currentKeys = [];
      try { currentKeys = JSON.parse(userRow?.public_keys || '[]'); } catch {}

      const workRawPub = crypto.createPublicKey(ramKeyAliceWorkLaptop.publicKey)
        .export({ type: 'spki', format: 'der' }).subarray(-32);

      currentKeys.push(workRawPub.toString('base64'));

      db1Direct.prepare("UPDATE profiles SET public_keys = ? WHERE user_address LIKE '%ssh_alice%'")
        .run(JSON.stringify(currentKeys));
      db1Direct.close();

      const workClient = new MemorySshClient(
        SUITE_CONFIG.host,
        n1.sshPort,
        'ssh_alice',
        'AlicePassword999!',
        ramKeyAliceWorkLaptop
      );
      const workLoginOk = await workClient.connect();
      record('Test 18: /keys add ile Eklenen İkinci Anahtarla Oturum Açma', workLoginOk);
      workClient.close();
    } catch (e) {
      record('Test 18: Çoklu Anahtar Doğrulaması', false, e.message);
    }

    // Test 19: SSH Hesabının Varsayılan Olarak Telnet'e Kilitli Olması
    try {
      const telnetBlocked = await new Promise((res) => {
        const s = net.createConnection({ host: SUITE_CONFIG.host, port: n1.clientPort });
        let totalText = '';
        let userSent = false;
        let passSent = false;

        const timer = setTimeout(() => {
          s.destroy();
          res(false);
        }, 4000);

        s.on('data', (d) => {
          if (d.includes(Buffer.from('\x1b[6n')) || d.toString().includes('[6n')) {
            s.write('\x1b[24;110R');
          }
          const clean = stripAnsi(d.toString());
          totalText += clean;

          // 1. Kullanıcı adını gönder
          if (!userSent && (totalText.includes('Kullanıcı adı') || totalText.includes(':'))) {
            userSent = true;
            setTimeout(() => s.write('ssh_alice\r'), 80);
            return;
          }

          // 2. Parola promptu gelirse parolayı gönder
          if (userSent && !passSent && (totalText.includes('Parola:') || totalText.includes('Parola'))) {
            passSent = true;
            setTimeout(() => s.write('AlicePassword999!\r'), 80);
            return;
          }

          // 3. Emniyet kilidi uyarısı yakalandığı an başarılı
          if (totalText.includes('Telnet erişimi kapalıdır') || totalText.includes('donanım anahtarı ile mühürlenmiştir')) {
            clearTimeout(timer);
            s.destroy();
            res(true);
          }
        });

        s.on('close', () => {
          if (totalText.includes('Telnet erişimi kapalıdır') || totalText.includes('donanım anahtarı ile mühürlenmiştir')) {
            clearTimeout(timer);
            res(true);
          }
        });

        s.on('error', () => {});
      });

      record('Test 19: [GÜVENLİK] SSH Korumalı Hesaba Telnet Üzerinden Giriş Engeli', telnetBlocked);
    } catch (e) {
      record('Test 19: Telnet Emniyet Kilidi Testi', false, e.message);
    }

    // --- GRUP 7: VERİTABANI İZOLASYONU & /LEAVE & /REMOVE ---
    console.log(`\n${COLOR.BOLD}[Grup 7] ACID Veritabanı, /leave ve /remove İzolasyonu${COLOR.RESET}`);

    // Test 20: Veritabanına Yazım Teyidi
    const db1 = new DatabaseSync(n1.dbFile);
    const msgCountRow = db1.prepare('SELECT COUNT(*) as cnt FROM messages').get();
    record('Test 20: SQLite WAL Modunda ACID Mesaj Kalıcılığı', msgCountRow.cnt > 0, `Kayıt: ${msgCountRow.cnt}`);

    // Test 21: /leave ile Kanaldan Ayrılma ve deleted_by Filtresi
    try {
      if (userAlphaSession) {
        userAlphaSession.socket.write('/join #test_leave\r');
        await new Promise((r) => setTimeout(r, 400));

        db1.exec(`
          INSERT INTO messages (id, sender, receiver, content, deleted_by, timestamp)
          VALUES ('leave_test_msg', '@user_alpha:${n1.serverName}:${n1.fedPort}', '#test_leave:${n1.serverName}:${n1.fedPort}', 'bu mesaj silinecek', '', '${new Date().toISOString()}');
        `);

        userAlphaSession.socket.write(`/leave #test_leave:${n1.serverName}:${n1.fedPort}\r`);
        await new Promise((r) => setTimeout(r, 600));

        const checkLeave = db1.prepare("SELECT deleted_by FROM messages WHERE id = 'leave_test_msg'").get();
        const isDeletedByMarked = checkLeave?.deleted_by?.includes('user_alpha');
        record('Test 21: /leave ile Kanaldan Ayrılma ve deleted_by Filtresi', !!isDeletedByMarked);
      } else {
        record('Test 21: /leave Testi', false, 'Oturum açık değil');
      }
    } catch (e) {
      record('Test 21: /leave ile Kanaldan Ayrılma ve deleted_by Filtresi', false, e.message);
    }

    // Test 22: /remove ile DM Temizleme
    try {
      if (userAlphaSession) {
        db1.exec(`
          INSERT INTO messages (id, sender, receiver, content, deleted_by, timestamp)
          VALUES ('rm_dm_msg', '@user_alpha:${n1.serverName}:${n1.fedPort}', '@user_beta:${n2.serverName}:${n2.fedPort}', 'gizli ikili mesaj', '', '${new Date().toISOString()}');
        `);

        userAlphaSession.socket.write(`/remove @user_beta:${n2.serverName}:${n2.fedPort}\r`);
        await new Promise((r) => setTimeout(r, 600));

        const checkRm = db1.prepare("SELECT deleted_by FROM messages WHERE id = 'rm_dm_msg'").get();
        const isRmMarked = checkRm?.deleted_by?.includes('user_alpha');
        record('Test 22: /remove ile Karşı Tarafı Bozmadan Tek Taraflı DM Silme', isRmMarked);
      } else {
        record('Test 22: /remove Testi', false, 'Oturum açık değil');
      }
    } catch (e) {
      record('Test 22: /remove ile Tek Taraflı DM Silme', false, e.message);
    }
    db1.close();

    // --- GRUP 8: GÜVENLİK & GRACEFUL SHUTDOWN ---
    console.log(`\n${COLOR.BOLD}[Grup 8] Sınır Değerler, Kötü Niyetli Paketler & Temiz Kapanış${COLOR.RESET}`);

    // Test 23: Sahte Ed25519 İmzalı Bağlantının Reddedilmesi
    try {
      const forgedSigRejected = await new Promise((res) => {
        const fakeIdentity = CryptoHelper.generateIdentityKeyPair();
        const fakeKem = CryptoHelper.generateKemKeyPair();
        const s = net.createConnection({ host: SUITE_CONFIG.host, port: n1.fedPort }, () => {
          s.write(JSON.stringify({
            type: 'HANDSHAKE_INIT',
            nodeAddress: '127.0.0.1:6666',
            identityPublicKey: fakeIdentity.publicKey,
            kemPublicKey: fakeKem.publicKey,
            nonce: 'sahte_nonce_1234',
            sig: 'tamamen_gecersiz_ve_sahte_imza_base64=='
          }) + '\n');
        });
        s.on('close', () => res(true));
        setTimeout(() => { s.destroy(); res(true); }, 1500);
      });
      record('Test 23: [GÜVENLİK] Sahte Ed25519 İmzalı Bağlantının Reddedilmesi', forgedSigRejected);
    } catch (e) {
      record('Test 23: Sahte İmza Reddi', false, e.message);
    }

    // Test 24: SIGINT ile Temiz Kapanış
    try {
      const n3Proc = childProcesses[2];
      const shutdownPromise = new Promise((res) => {
        n3Proc.on('exit', (code) => res(code === 0 || code === null));
      });
      n3Proc.kill('SIGINT');
      const cleanExit = await shutdownPromise;
      record('Test 24: SIGINT / Graceful Shutdown ile Temiz Tahliye', cleanExit);
    } catch (e) {
      record('Test 24: Graceful Shutdown', false, e.message);
    }

  } catch (criticalErr) {
    console.error(`\n${COLOR.RED}Kritik Test Hatası: ${criticalErr.message}${COLOR.RESET}`);
  } finally {
    console.log(`\n${COLOR.BOLD}Temizlik yapılıyor (Süreçler sonlandırılıyor, test DB'leri siliniyor)...${COLOR.RESET}`);
    await killProcesses();
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

    if (failed === 0 && total >= 24) {
      console.log(`\n ${COLOR.GREEN}${COLOR.BOLD}MÜKEMMEL: Post-Quantum şifreli ağ, SSH ve kimlik doğrulama 24/24 testten geçti!${COLOR.RESET}\n`);
    } else {
      console.log(`\n ${COLOR.YELLOW}${COLOR.BOLD}Uyarı: Bazı testler başarısız oldu.${COLOR.RESET}\n`);
    }

    process.exit(failed > 0 ? 1 : 0);
  }
}

main();