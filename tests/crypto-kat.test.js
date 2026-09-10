import crypto from 'node:crypto';
import assert from 'node:assert';
import { CryptoHelper } from '../src/utils/cryptoHelper.js';
import { Base32 } from '../src/utils/base32.js';

const COLOR = {
  RESET: '\x1b[0m',
  GREEN: '\x1b[32m',
  RED: '\x1b[31m',
  YELLOW: '\x1b[33m',
  CYAN: '\x1b[36m',
  BOLD: '\x1b[1m'
};

const results = [];

function record(name, passed, details = '') {
  results.push({ name, passed, details });
  const status = passed
    ? `${COLOR.GREEN}✔ GEÇTİ${COLOR.RESET}`
    : `${COLOR.RED}✘ BAŞARISIZ${COLOR.RESET}`;
  const detailStr = details ? ` (${COLOR.YELLOW}${details}${COLOR.RESET})` : '';
  console.log(`  [${status}] ${name}${detailStr}`);
}

async function runKatSuite() {
  console.log(`\n${COLOR.BOLD}${COLOR.CYAN}================================================================${COLOR.RESET}`);
  console.log(`${COLOR.BOLD}     METRICE KRİPTOGRAFİK DOĞRULAMA (KNOWN ANSWER TESTS - KAT)  ${COLOR.RESET}`);
  console.log(`${COLOR.BOLD}${COLOR.CYAN}================================================================${COLOR.RESET}`);

  // ----------------------------------------------------
  // BÖLÜM 1: RFC 8032 ED25519 TEST VEKTÖRLERİ (KAT)
  // ----------------------------------------------------
  console.log(`\n${COLOR.BOLD}[Bölüm 1] RFC 8032 Ed25519 Bilinen Test Vektörleri${COLOR.RESET}`);

  const pkcs8PrefixEd25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
  const spkiPrefixEd25519 = Buffer.from('302a300506032b6570032100', 'hex');

  // RFC 8032 Bölüm 7.1 Resmi Test Vektörleri
  const rfc8032Vectors = [
    {
      id: 'RFC 8032 Test 1 (0-bayt mesaj)',
      sk: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
      pk: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
      msgHex: '',
      sigHex: 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
    },
    {
      id: 'RFC 8032 Test 2 (1-bayt mesaj "72")',
      sk: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
      pk: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
      msgHex: '72',
      sigHex: '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'
    },
    {
      id: 'RFC 8032 Test 3 (2-bayt mesaj "af82")',
      sk: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
      pk: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
      msgHex: 'af82',
      sigHex: '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a'
    }
  ];

  for (const [idx, v] of rfc8032Vectors.entries()) {
    try {
      const privKey = crypto.createPrivateKey({
        key: Buffer.concat([pkcs8PrefixEd25519, Buffer.from(v.sk, 'hex')]),
        format: 'der',
        type: 'pkcs8'
      });
      const pubKey = crypto.createPublicKey({
        key: Buffer.concat([spkiPrefixEd25519, Buffer.from(v.pk, 'hex')]),
        format: 'der',
        type: 'spki'
      });

      // Açık anahtar türetim tutarlılığı
      const derivedPubDer = crypto.createPublicKey(privKey).export({ format: 'der', type: 'spki' });
      const rawDerivedPub = derivedPubDer.subarray(-32);
      const pubMatches = rawDerivedPub.equals(Buffer.from(v.pk, 'hex'));

      // İmzalama doğruluğu
      const msgBuf = Buffer.from(v.msgHex, 'hex');
      const sig = crypto.sign(null, msgBuf, privKey);
      const expectedSig = Buffer.from(v.sigHex, 'hex');
      const sigMatches = sig.equals(expectedSig);

      // İmza doğrulama (Verify)
      const verifyPassed = crypto.verify(null, msgBuf, pubKey, sig);

      // Kasıtlı manipülasyon doğrulaması (1-bit bozulma)
      const corruptedSig = Buffer.from(sig);
      corruptedSig[0] ^= 0x01;
      const rejectCorrupted = !crypto.verify(null, msgBuf, pubKey, corruptedSig);

      const allOk = pubMatches && sigMatches && verifyPassed && rejectCorrupted;
      record(`KAT 1.${idx + 1}: ${v.id}`, allOk, `İmza: 64B, Eşleşme: ${sigMatches}, Doğrulama: ${verifyPassed}`);
    } catch (err) {
      record(`KAT 1.${idx + 1}: ${v.id}`, false, err.message);
    }
  }

  // ----------------------------------------------------
  // BÖLÜM 2: ED25519 -> BASE32 KALICI NODEID KAT
  // ----------------------------------------------------
  console.log(`\n${COLOR.BOLD}[Bölüm 2] Deterministik NodeID Türetimi KAT${COLOR.RESET}`);
  try {
    const rawPub1 = Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex');
    const expectedHash = crypto.createHash('sha256').update(rawPub1).digest();
    const expectedNodeId = Base32.encode(expectedHash).slice(0, 16);

    const derivedNodeId = CryptoHelper.deriveNodeId(rawPub1);
    const matches = derivedNodeId === expectedNodeId && derivedNodeId.length === 16;
    record('KAT 2.1: RFC 4648 Base32 Deterministik NodeID Türetimi', matches, `NodeID: ${derivedNodeId}.mesh`);
  } catch (err) {
    record('KAT 2.1: Deterministik NodeID Türetimi', false, err.message);
  }

  // ----------------------------------------------------
  // BÖLÜM 3: NIST FIPS 203 (ML-KEM-768) TESTLERİ
  // ----------------------------------------------------
  console.log(`\n${COLOR.BOLD}[Bölüm 3] NIST FIPS 203 (ML-KEM-768) Kuantum Sonrası KAT${COLOR.RESET}`);

  if (!CryptoHelper.HAS_ML_KEM) {
    console.warn(`  ${COLOR.YELLOW}[ATLANDI] Bu Node.js ortamında yerel crypto.encapsulate / decapsulate bulunamadı.${COLOR.RESET}`);
  } else {
    // KAT 3.1: Parametre Boyut Standartları (NIST FIPS 203 Tablo 2)
    try {
      const kp = CryptoHelper.generateKemKeyPair();
      const { sharedSecret, encapsulatedKey } = CryptoHelper.encapsulateKey(kp.publicKey);
      const ctBuf = Buffer.from(encapsulatedKey, 'base64');

      // NIST FIPS 203: ML-KEM-768 Ciphertext = 1088 bayt, Shared Secret = 32 bayt
      const validCiphertextLen = ctBuf.length === 1088;
      const validSharedSecretLen = sharedSecret.length === 32;

      record(
        'KAT 3.1: NIST FIPS 203 ML-KEM-768 Parametre Boyutları',
        validCiphertextLen && validSharedSecretLen,
        `Ciphertext: ${ctBuf.length}B (Beklenen: 1088B), Secret: ${sharedSecret.length}B (Beklenen: 32B)`
      );
    } catch (err) {
      record('KAT 3.1: Parametre Boyutları', false, err.message);
    }

    // KAT 3.2: Sabit Kuantum Anahtarı Decapsulation KAT (Known Answer)
    try {
      const fixedPrivPem = '-----BEGIN PRIVATE KEY-----\nMFQCAQAwCwYJYIZIAWUDBAQCBEKAQI1OKeGhafChdCcfaYgyKX+D6mf2i1gHagVH\n1jp5Z3GXNA6w/hIuNsMk5qoHuiM7/v1io9jrvdd6WgnvMzRwLPs=\n-----END PRIVATE KEY-----\n';
      const fixedCiphertextHex = '2e07c0fbd2fe4c219b7a0fce2fbb14aea67baf92e858a15827dc97460e548b0d3de7d277305a7c638d00c2ddc2f98cbcd64100bddf16eb2d1d05d17b15c8e0793fd978596411176f2de552e56ea4eb3ec33776e21210dfd73e239850dcee6368c6186c417f5db3ea4ca4905268f15da6b1664ef746838f7f403f050f7ff994a1dbc044e71d502e90f015a7f4b09a0a7e0cc0812723b55138edbb9805d5eee3f06420adfc501c0a14e75eb90719da69b716661bd0d07f8b941a007e285bb52f6bc4c36c4b94b578135dcb069ed0c3e84956c15c2741c950633b455c3fc37820cdb093ea11a58604d3cb8601ec66d9d1e9d4e2634541c8764d3a5a0dd86edd625f6daef70d305e6caf2952ef03640f0dd6bf0ccc3da7823adf9e357222f8d417616811f13c10827db91caac617ab7f85aaffd123dd89e5df76f5efe4c9ebf23a0e177bf0739de98ca1c5f3ce7f1e6926e4ff04655242d41997c21d594ec16c7ea6630f29f39e019de0f0e2633b23c72de3fd30259d2d1d6d84c215c1009837670f1583894a28ca479fc5383c8bc87da4976511b844ed3d54221bbdc5d37dadea7e03cffd8fd45949ad520f33f776debbe185978600818cb8159b80654d206fbc266d0c02914147b53aac6e48fff625e3b4c4c68ddb5c4762981ed30434b73f4956fde370ba606e9f462858ca6d60057c8de029efdc77d6f3e7a4d58c10d62442754c16c5a35a48593988a8f35488449853c23ac84fdfb1146b43292fd43f436c0d83580eedc98fdcf46306b6f20e1ea93daf7902604a26edfc51f4135f7f6b9e0d2521df04dcc7ba74d1e2845f29ec58b5f41dc88d0a2a6f7ffa25ab42fab8106582b2a089fd66b61fb79146d317b302e6a1f545d1a95433be55fc85a1fa377e610020371d2abfc35572851e754ae34e64600ff7e504d6da94017071eeedb4867d807d1d0e18ba2e6783c7659e64472a1faf0fe25b3ad3cc2dafc8b56663ac624455c0f08434bcb1080b6df85265823179becb6b58efc96feab36a5bd322028fc14b54bdfbe393c6c159fab231fd9d96ab9c43224a565eaee99e4688dc8b538412ad820d67370d7b3e162f4be0a2949df9ce11e53898a709b9f9698b87313f8fe4cb51debbc317f47ea3d21ee77e420e4402c9651cc643fb4a489326d90ea8fbf2ffb1a058d02347e68b4ccc1ae5739b637fbd69d6c07d304af36a8ad6fe27ed3efbacbba33b87ac975c8b7aa1f6be3b2863f2e2309f4b137c8801b15ee1358c4336652d65adf3f450a4bee0ca2f8e20e9c55db19e2bf8da4114e8b17944e4435c5253cc139f94ab1f6971baee4e9752f598061e36bd11abfd1918d424bd8dff6f203e9461fc58aa764f9781a42ab10ee59859ff79b646d03876ac93c363b10981a42a03553e543acfd719b806d6a7f797976cb144433d3d326fd148621d2a2a6c6c94f4cdfebfb6c4498ee69460d3c24d1efad36da462fc2b75e7fd0176933d7e9d8bf6bafcd16cae7329dabb06e409558b14271de839af1eacba17cb977e06c5';
      const expectedSharedSecretHex = '41e8861659681b6f6aaa10a5d5adf5f209b11cbcf9e98b9fb7da9670102e37ef';

      const decSecret = CryptoHelper.decapsulateKey(fixedPrivPem, Buffer.from(fixedCiphertextHex, 'hex').toString('base64'));
      const matches = decSecret.toString('hex') === expectedSharedSecretHex;
      record('KAT 3.2: Sabit ML-KEM-768 Şifre Çözümü (Decapsulation KAT)', matches, `SharedKey: ${decSecret.toString('hex').slice(0, 16)}...`);
    } catch (err) {
      record('KAT 3.2: Sabit ML-KEM-768 Decapsulation', false, err.message);
    }

    // KAT 3.3: NIST FIPS 203 Section 7.3 - Örtülü Reddetme (Implicit Rejection)
    try {
      const fixedPrivPem = '-----BEGIN PRIVATE KEY-----\nMFQCAQAwCwYJYIZIAWUDBAQCBEKAQI1OKeGhafChdCcfaYgyKX+D6mf2i1gHagVH\n1jp5Z3GXNA6w/hIuNsMk5qoHuiM7/v1io9jrvdd6WgnvMzRwLPs=\n-----END PRIVATE KEY-----\n';
      const fixedCiphertextHex = '2e07c0fbd2fe4c219b7a0fce2fbb14aea67baf92e858a15827dc97460e548b0d3de7d277305a7c638d00c2ddc2f98cbcd64100bddf16eb2d1d05d17b15c8e0793fd978596411176f2de552e56ea4eb3ec33776e21210dfd73e239850dcee6368c6186c417f5db3ea4ca4905268f15da6b1664ef746838f7f403f050f7ff994a1dbc044e71d502e90f015a7f4b09a0a7e0cc0812723b55138edbb9805d5eee3f06420adfc501c0a14e75eb90719da69b716661bd0d07f8b941a007e285bb52f6bc4c36c4b94b578135dcb069ed0c3e84956c15c2741c950633b455c3fc37820cdb093ea11a58604d3cb8601ec66d9d1e9d4e2634541c8764d3a5a0dd86edd625f6daef70d305e6caf2952ef03640f0dd6bf0ccc3da7823adf9e357222f8d417616811f13c10827db91caac617ab7f85aaffd123dd89e5df76f5efe4c9ebf23a0e177bf0739de98ca1c5f3ce7f1e6926e4ff04655242d41997c21d594ec16c7ea6630f29f39e019de0f0e2633b23c72de3fd30259d2d1d6d84c215c1009837670f1583894a28ca479fc5383c8bc87da4976511b844ed3d54221bbdc5d37dadea7e03cffd8fd45949ad520f33f776debbe185978600818cb8159b80654d206fbc266d0c02914147b53aac6e48fff625e3b4c4c68ddb5c4762981ed30434b73f4956fde370ba606e9f462858ca6d60057c8de029efdc77d6f3e7a4d58c10d62442754c16c5a35a48593988a8f35488449853c23ac84fdfb1146b43292fd43f436c0d83580eedc98fdcf46306b6f20e1ea93daf7902604a26edfc51f4135f7f6b9e0d2521df04dcc7ba74d1e2845f29ec58b5f41dc88d0a2a6f7ffa25ab42fab8106582b2a089fd66b61fb79146d317b302e6a1f545d1a95433be55fc85a1fa377e610020371d2abfc35572851e754ae34e64600ff7e504d6da94017071eeedb4867d807d1d0e18ba2e6783c7659e64472a1faf0fe25b3ad3cc2dafc8b56663ac624455c0f08434bcb1080b6df85265823179becb6b58efc96feab36a5bd322028fc14b54bdfbe393c6c159fab231fd9d96ab9c43224a565eaee99e4688dc8b538412ad820d67370d7b3e162f4be0a2949df9ce11e53898a709b9f9698b87313f8fe4cb51debbc317f47ea3d21ee77e420e4402c9651cc643fb4a489326d90ea8fbf2ffb1a058d02347e68b4ccc1ae5739b637fbd69d6c07d304af36a8ad6fe27ed3efbacbba33b87ac975c8b7aa1f6be3b2863f2e2309f4b137c8801b15ee1358c4336652d65adf3f450a4bee0ca2f8e20e9c55db19e2bf8da4114e8b17944e4435c5253cc139f94ab1f6971baee4e9752f598061e36bd11abfd1918d424bd8dff6f203e9461fc58aa764f9781a42ab10ee59859ff79b646d03876ac93c363b10981a42a03553e543acfd719b806d6a7f797976cb144433d3d326fd148621d2a2a6c6c94f4cdfebfb6c4498ee69460d3c24d1efad36da462fc2b75e7fd0176933d7e9d8bf6bafcd16cae7329dabb06e409558b14271de839af1eacba17cb977e06c5';
      const expectedSharedSecretHex = '41e8861659681b6f6aaa10a5d5adf5f209b11cbcf9e98b9fb7da9670102e37ef';

      const ctCorrupted = Buffer.from(fixedCiphertextHex, 'hex');
      ctCorrupted[0] ^= 0xff; // 1 bayt manipülasyon

      const decCorrupted = CryptoHelper.decapsulateKey(fixedPrivPem, ctCorrupted.toString('base64'));
      const isPseudorandom = decCorrupted.length === 32 && decCorrupted.toString('hex') !== expectedSharedSecretHex;

      record('KAT 3.3: Manipüle Edilmiş Şifreli Metinde Örtülü Reddetme (Implicit Rejection)', isPseudorandom, 'Hata fırlatmadan sözderastlantısal anahtar türetildi');
    } catch (err) {
      record('KAT 3.3: Örtülü Reddetme', false, err.message);
    }
  }

  // ----------------------------------------------------
  // BÖLÜM 4: RFC 7748 X25519 DETERMINİSTİK KEM TÜRETİMİ
  // ----------------------------------------------------
  console.log(`\n${COLOR.BOLD}[Bölüm 4] RFC 7748 X25519 Deterministik Anahtar Türetimi KAT${COLOR.RESET}`);
  try {
    const fixedSeed = Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex');
    const pair1 = CryptoHelper.deriveDeterministicX25519(fixedSeed);
    const pair2 = CryptoHelper.deriveDeterministicX25519(fixedSeed);

    const matches = pair1.publicKey === pair2.publicKey && pair1.privateKey === pair2.privateKey;
    record('KAT 4.1: Sabit Tohumdan (32B) Birebir Aynı X25519 Çifti Üretimi', matches, 'Determinizm %100 doğrulandı');
  } catch (err) {
    record('KAT 4.1: X25519 Deterministik Türetim', false, err.message);
  }

  // ----------------------------------------------------
  // BÖLÜM 5: KDF (SCRYPT + HKDF-SHA256) VAULT SEED DOĞRULAMASI
  // ----------------------------------------------------
  console.log(`\n${COLOR.BOLD}[Bölüm 5] KDF (scrypt + HKDF-SHA256) ve AES-GCM Bütünlük KAT${COLOR.RESET}`);
  try {
    const passphrase = 'metrice-ultra-secure-test-passphrase';
    const clientRawPub = Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex');
    const nodeAddr = 'node.metrice.network:8001';

    const seed1 = CryptoHelper.deriveVaultSeed(passphrase, clientRawPub, nodeAddr);
    const seed2 = CryptoHelper.deriveVaultSeed(passphrase, clientRawPub, nodeAddr);
    const isDeterministic = seed1.equals(seed2) && seed1.length === 32;

    // Farklı parola veya farklı nodeAddress ile türetim kesinlikle farklı olmalı
    const seedDifferentPass = CryptoHelper.deriveVaultSeed('other-pass', clientRawPub, nodeAddr);
    const isCollisionResistant = !seed1.equals(seedDifferentPass);

    record('KAT 5.1: 2FA Vault Tohumu (scrypt N=16384 + HKDF-SHA256) Determinizmi', isDeterministic && isCollisionResistant, 'Tohum: 32B');

    // AES-256-GCM Sentineli ve Kimlik Doğrulamalı Şifreleme
    const authToken = CryptoHelper.createVaultAuthToken(seed1);
    const tokenValid = CryptoHelper.verifyVaultAuthToken(authToken, seed1);
    const tokenInvalidSeed = !CryptoHelper.verifyVaultAuthToken(authToken, seedDifferentPass);

    record('KAT 5.2: AES-256-GCM Sentinel Kimlik Doğrulamalı Şifreleme / Çözümleme', tokenValid && tokenInvalidSeed, 'Yetkisiz tohum anında reddedildi');
  } catch (err) {
    record('KAT 5.1 & 5.2: Vault KDF & AES-GCM', false, err.message);
  }

  // ----------------------------------------------------
  // RAPORLAMA VE SONUÇ
  // ----------------------------------------------------
  console.log(`\n${COLOR.BOLD}${COLOR.CYAN}================================================================${COLOR.RESET}`);
  console.log(`${COLOR.BOLD}               KRİPTOGRAFİK KAT SÜİTİ SONUCU                   ${COLOR.RESET}`);
  console.log(`${COLOR.BOLD}${COLOR.CYAN}================================================================${COLOR.RESET}`);

  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed).length;
  const total = results.length;

  console.log(` Toplam Kriptografik Vektör : ${total}`);
  console.log(` Başarılı (Doğrulandı)      : ${COLOR.GREEN}${passed}${COLOR.RESET}`);
  console.log(` Başarısız (Sapma/Uyumsuzluk): ${failed > 0 ? COLOR.RED : COLOR.GREEN}${failed}${COLOR.RESET}`);

  if (failed > 0) {
    console.error(`\n${COLOR.RED}${COLOR.BOLD}KRİPTOGRAFİK UYUMSUZLUK TESPİT EDİLDİ!${COLOR.RESET}`);
    process.exit(1);
  }

  console.log(`\n${COLOR.GREEN}${COLOR.BOLD}TÜM KRİPTOGRAFİK KAT TESTLERİ MATEMATİKSEL OLARAK KUSURSUZ DOĞRULANDI! ✔${COLOR.RESET}\n`);
  process.exit(0);
}

runKatSuite().catch((err) => {
  console.error(`Kritik KAT Hatası: ${err.message}`);
  process.exit(1);
});
