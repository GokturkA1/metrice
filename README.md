# Metrice v2.1.5

Metrice, harici bağımlılık içermeyen (Zero External Dependencies), doğrudan Node.js çekirdek kütüphaneleri (`node:crypto`, `node:net`, `node:dgram`, `node:sqlite`, `node:dns`) üzerinde çalışan, kuantum sonrası kriptografi (Post-Quantum Cryptography) ve Tor benzeri çok katmanlı yönlendirme (Onion Routing) mimarisine sahip dağıtık eşler arası (P2P) ağ protokolüdür.

Sistem; NIST FIPS 203 ML-KEM-768 anahtar kapsülleme, Ed25519 tabanlı RFC 4648 Base32 düğüm kimliklendirmesi, AutoNAT konsensüsü, CGNAT arkasındaki uçlar için Rendezvous ters tünelleri ve yerleşik bellek içi SSH-2 sunucusu içermektedir.

---

## Mimari ve Temel Bileşenler

### 1. Düğüm Kimliği ve Kriptografik Adresleme
- Her düğüm kalıcı bir Ed25519 anahtar çifti barındırır.
- Açık anahtarın SHA-256 özetinin ilk 10 baytı (80 bit) RFC 4648 Base32 ile kodlanarak 16 karakterlik düğüm kimliği (`NodeID`) oluşturulur (`^[a-z2-7]{16}$`).
- Ağ üzerindeki adresleme IP/Port bağımsız `.mesh` sanal alan adlarıyla sağlanır:
  - Kullanıcı Adresi: `@kullanici:NodeID.mesh`
  - Federe Kanal: `#kanal:NodeID.mesh`
  - Küresel Ağ Kanalı: `#genel`

### 2. AutoNAT ve Port Yönlendirme Tespiti
- Düğümler el sıkışma esnasında karşı eşe gözlemlenen IP adresini (`observedAddress`) aktarır.
- Farklı eşlerden en az iki tutarlı bildirim alındığında yansıtılan IP (Reflected IP) konsensüsü sağlanır.
- Düğüm, eş düğümlerden birine rastgele nonce içeren `DIALBACK_REQUEST` paketi iletir.
- Eş, gelen isteğin soket düzeyindeki IP adresine (`socket.remoteAddress`) geri bağlantı dener. Bağlantı başarılı ise düğüme `CAP_RELAY`, aksi durumda `CAP_EDGE` rolü atanır.
- SSRF Koruması: `DIALBACK_REQUEST` gövdesindeki hedef IP adresi dikkate alınmaz; doğrudan TCP bağlantısının fiziksel adresi sabitlenir. RFC 1918 ve döngüsel (loopback) adreslere diyal-geri engellenir.

### 3. Rendezvous ve CGNAT Ters Tünelleri
- NAT veya güvenlik duvarı arkasındaki `EDGE` düğümleri, açık internete erişimi olan en az iki `RELAY` düğümüne kalıcı ters TCP tüneli açar.
- Tünel bağlantısı, `RENDEZVOUS_BIND` paketi içerisindeki Ed25519 imzası ile doğrulanır.
- Güvenlik duvarı oturum tablolarının açık tutulması için 30 saniye aralıklarla tek baytlık `0x09` (PING) ve `0x0A` (PONG) denetim paketleri iletilir.
- Bir röle üzerinde açılabilecek aktif tünel sayısı kaynak kısıtı amacıyla en fazla 64 ile sınırlandırılmıştır.

### 4. 3-Hop Teleskopik Post-Quantum Soğan Yönlendirme (Onion Routing)
- Ağ topolojisi ve paket akışının gizlenmesi amacıyla 3 atlamalı (Giriş, Röle, Çıkış) anonim devreler kurulur.
- Her atlamada NIST FIPS 203 uyumlu ML-KEM-768 (Kyber-768) algoritması ile anahtar kapsülleme gerçekleştirilir ve simetrik oturum anahtarları türetilir.
- Trafik Analizi ve DPI Koruması: Tüm soğan hücreleri (`ONION_CELL`) sabit 2048 bayt boyutunda tutulur (Uniform Cell Padding). Ham kullanıcı yükü azami 768 bayt (MAX_ONION_PAYLOAD) ile sınırlandırılır.
- Hücreler açık metin taşınmaz; taşıma katmanında AES-256-GCM ile şifrelenmiş `ENCRYPTED_FRAME` blokları içerisinde iletilir.

### 5. Dağıtık Varlık (Presence) ve SQLite Yönlendirme
- Düğümler varlık ve kanal aboneliklerini Ed25519 ile imzalanmış `PRESENCE_ANNOUNCE` paketleriyle dedikodu (gossip) mekanizması üzerinden yayar.
- Düğümlerin ham IP adresleri gossip paketlerinde yer almaz; duyurular alan adı veya `.mesh` kimliği üzerinden yapılır.
- Yönlendirme bilgileri bellekte önbelleğe alınır ve SQLite veritabanındaki `routing_table` tablosuna kaydedilir. 60 saniye boyunca yenilenmeyen kayıtlar temizlenir (TTL).

### 6. Bellek İçi SSH-2 Sunucusu ve İki Faktörlü Kasa Doğrulaması (2FA Vault)
- Harici SSH arka plan süreci (daemon) gerekmeksizin saf JavaScript ile yazılmış SSH-2 sunucusu barındırır.
- Yapılandırılabilir Kimlik: Sunucu kimlik dizgesi (`sshServerVersion`) konfigürasyon üzerinden ayarlanabilir (varsayılan: `SSH-2.0-Metrice_2.1.5`).
- Donanım Anahtarı Bağlama: Kullanıcı parolası, istemcinin Ed25519 açık anahtarı ile tuzlanarak Scrypt (N=16384, r=8, p=1) ve HKDF-SHA256 algoritmalarından geçirilir. Kayıtlı Ed25519 anahtarı olmaksızın doğru parola girilse dahi kimlik doğrulanamaz.

---

## Kurulum ve Çalıştırma

### Gereksinimler
- Node.js v22.0.0 veya üzeri (ML-KEM-768 tam donanım hızlandırması için Node.js v24+ önerilir).
- İşletim Sistemi: Linux, macOS, BSD, Windows.
- Harici paket bağımlılığı bulunmamaktadır (`npm install` gerekmez).

```bash
git clone git@github.com:GokturkA1/metrice.git
cd metrice
node src/index.js
```

---

## Dağıtım Modelleri

Metrice; VDS sunucuları, Docker/Podman konteynerleri, ters vekiller (Nginx, Traefik, HAProxy) ve tünelleme servisleri (Cloudflared, Ngrok) ile uyumludur.

### 1. Genel IP Üzerinde RELAY Düğümü (VDS)
```bash
SERVER_NAME="relay1.metrice.network" \
FED_PORT=8001 \
SSH_PORT=2224 \
CLIENT_PORT=2222 \
MESH_ROLE=RELAY \
node src/index.js
```

### 2. Docker / Podman Konteyner Dağıtımı
Konteyner içi ağ köprülerinde IP doğrulama toleransı sağlamak için `TRUST_PROXY=true` kullanılır:
```bash
docker run -d \
  --name metrice-node \
  -e SERVER_NAME="node.example.com" \
  -e TRUST_PROXY=true \
  -e FED_PORT=8001 \
  -e SSH_PORT=2224 \
  -p 8001:8001 \
  -p 2224:2224 \
  -v $(pwd)/data:/app/data \
  node:24-alpine node src/index.js
```

### 3. Ters Vekil ve Tünelleme Arkasında Dağıtım (Cloudflared / Ngrok)
```bash
TRUST_PROXY=true \
SERVER_NAME="mesh.domain.com" \
SSH_SERVER_VERSION="SSH-2.0-SecureMesh_2.0" \
node src/index.js
```

---

## Yapılandırma Parametreleri

Tüm parametreler ortam değişkenleri (`process.env`) veya `src/config/index.js` üzerinden yapılandırılabilir:

| Parametre | Ortam Değişkeni | Varsayılan | Açıklama |
| :--- | :--- | :--- | :--- |
| `serverName` | `SERVER_NAME` | `'localhost'` | Düğümün genel alan adı veya ana makine adresi |
| `clientPort` | `CLIENT_PORT` | `2222` | Telnet TUI dinleme TCP portu |
| `sshPort` | `SSH_PORT` | `2224` | Post-Quantum SSH-2 sunucusu dinleme TCP portu |
| `federationPort` | `FED_PORT` | `8001` | P2P Federasyon ve Onion dinleme TCP portu |
| `sshServerVersion` | `SSH_SERVER_VERSION` | `'SSH-2.0-Metrice_2.1.5'` | SSH sunucusu protokol kimlik dizgesi |
| `meshRole` | `MESH_ROLE` | `'EDGE'` | Düğüm rolü (`'RELAY'` veya `'EDGE'`) |
| `maxRendezvousTunnels`| `MAX_RENDEZVOUS_TUNNELS` | `64` | Bir RELAY düğümünün kabul edeceği azami ters tünel sayısı |
| `rendezvousKeepaliveInterval` | `RENDEZVOUS_KEEPALIVE_MS` | `30000` | Ters tünel denetim aralığı (0x09/0x0A PING-PONG ms) |
| `presenceTtl` | `PRESENCE_TTL_MS` | `60000` | Yönlendirme tablosu varlık süresi (ms) |
| `circuitTtl` | `CIRCUIT_TTL_MS` | `600000` | Onion devreleri yaşam süresi (ms) |
| `uniformCellSize` | `UNIFORM_CELL_SIZE` | `2048` | Sabit soğan hücresi boyutu (bayt) |
| `secureBufferLimit` | `SECURE_BUFFER_LIMIT` | `65536` | Çerçeveleme tampon üst sınırı (64 KB) |
| `trustProxy` | `TRUST_PROXY` | `false` | Vekil sunucu arkasında IP doğrulama toleransı |
| `strictPq` | `STRICT_PQ` | `false` | Klasik algoritmaları tamamen engelleme modu |
| `dbFile` | `DB_FILE` | `./data_<PORT>.db` | SQLite veritabanı dosya yolu |
| `peerCacheFile` | `PEER_FILE` | `./peers_<PORT>.json` | Bilinen eşler önbellek dosya yolu |
| `logLevel` | `LOG_LEVEL` | `'DEBUG'` | Günlük kayıt seviyesi (`DEBUG`, `INFO`, `WARN`, `ERROR`) |

---

## Kullanım ve Komut Arayüzü

### 1. SSH Bağlantısı (Önerilen)
```bash
ssh -p 2224 kullanici_adi@sunucu_adresi
```
İlk bağlantıda yerel Ed25519 açık anahtarı hesaba otomatik olarak bağlanır.

### 2. Telnet Bağlantısı (Yerel Testler)
```bash
telnet sunucu_adresi 2222
```

### 3. TUI Komutları
Terminal arayüzünde komut satırından çalıştırılabilecek yönergeler:

- `/join #kanal:NodeID.mesh`: Uzak düğüm kanalına abone olur.
- `/leave #kanal`: Belirtilen kanaldan ayrılır.
- `/remove @kullanici`: Seçili özel sohbet geçmişini siler.
- `/msg @hedef <mesaj>`: Hedef kullanıcıya doğrudan şifreli mesaj iletir.
- `/keys add <ssh-ed25519 ...>`: Hesaba ek Ed25519 açık anahtarı kaydeder.
- `/keys list`: Kayıtlı açık anahtarları listeler.
- `/status`: Düğüm rolü, kimlik ve tünel durumunu görüntüler.
- `/help`: Kullanılabilir komutları listeler.
- `/quit`: Oturumu sonlandırır.

---

## Protokol Paket Formatları

### Handshake (`HANDSHAKE_INIT` / `HANDSHAKE_REPLY`)
```json
{
  "type": "HANDSHAKE_INIT",
  "nodeAddress": "host:port",
  "identityPublicKey": "base64_ed25519_pubkey",
  "kemPublicKey": "base64_kyber768_pubkey",
  "nonce": "16_byte_hex",
  "sig": "ed25519_signature"
}
```

### AutoNAT Dialback (`DIALBACK_REQUEST` / `DIALBACK_CONFIRM`)
```json
{
  "type": "DIALBACK_REQUEST",
  "targetPort": 8001,
  "nonce": "16_byte_hex"
}
```

### Rendezvous Bağlantısı (`RENDEZVOUS_BIND` / `RENDEZVOUS_ACK`)
```json
{
  "type": "RENDEZVOUS_BIND",
  "nodeId": "16_char_base32",
  "identityPublicKey": "base64_ed25519_pubkey",
  "timestamp": 1788732000,
  "nonce": "16_byte_hex",
  "sig": "ed25519_signature"
}
```

### Onion Devreleri (`CIRCUIT_CREATE`, `CIRCUIT_EXTEND`, `ONION_CELL`)
```json
{
  "type": "ONION_CELL",
  "circuitId": "16_byte_hex",
  "iv": "base64_aes_gcm_iv",
  "authTag": "base64_tag",
  "ciphertext": "base64_encrypted_payload",
  "pad": "000... (Toplam 2048 bayt)"
}
```

---

## Doğrulama ve Testler

Sistem bütünlüğü iki kapsamlı test süiti ile doğrulanır:

```bash
# 1. Metrice v2.1.5 Spesifikasyon ve Güvenlik Süiti
node v2_test_suite.js

# 2. Protokol, Post-Quantum, SSH-2 ve Veritabanı Süiti (24 Test)
node comprehensive_test_suite.js
```

Testler; Base32 türetimi, AutoNAT konsensüsü, DoS tampon limitleri, ML-KEM-768 soğan yönlendirmesi, SSRF önlemleri ve Two-Factor SSH kimlik doğrulamasını uçtan uca kapsar.

---

## Lisans

Bu proje GNU General Public License v3.0 (GPLv3) altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakınız.