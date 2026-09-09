# Metrice v2.5.2

Metrice, harici bağımlılık içermeyen (Zero External Dependencies), doğrudan Node.js çekirdek kütüphaneleri (`node:crypto`, `node:net`, `node:dgram`, `node:sqlite`, `node:dns`) üzerinde çalışan, kuantum sonrası kriptografi (Post-Quantum Cryptography) ve Tor benzeri çok katmanlı yönlendirme (Onion Routing) mimarisine sahip dağıtık eşler arası (P2P) ağ protokolüdür.

Sistem; NIST FIPS 203 ML-KEM-768 anahtar kapsülleme, Ed25519 tabanlı RFC 4648 Base32 düğüm kimliklendirmesi, AutoNAT konsensüsü, CGNAT arkasındaki uçlar için Rendezvous ters tünelleri, çoklu röle transit köprülemesi (EDGE Transit Routing / `CAP_EDGE_TRANSIT`), Layer 4 HAProxy PROXY Protocol v1 & v2 desteği ve yerleşik bellek içi SSH-2 sunucusu içermektedir.

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
- Eş, gelen isteğin soket düzeyindeki IP adresine (`socket.realRemoteAddress || socket.remoteAddress`) geri bağlantı dener. Bağlantı başarılı ise düğüme `CAP_RELAY`, aksi durumda `CAP_EDGE` rolü atanır.
- SSRF Koruması: `DIALBACK_REQUEST` gövdesindeki hedef IP adresi dikkate alınmaz; doğrudan TCP bağlantısının fiziksel adresi sabitlenir. RFC 1918 ve döngüsel (loopback) adreslere diyal-geri engellenir.

### 3. Rendezvous, CGNAT Ters Tünelleri ve EDGE Transit Routing (CAP_EDGE_TRANSIT)
- NAT veya güvenlik duvarı arkasındaki `EDGE` düğümleri, açık internete erişimi olan birden fazla `RELAY` düğümüne kalıcı ters TCP tüneli açar (`maxEdgeRendezvousRelays`, varsayılan 4).
- Tünel bağlantısı, `RENDEZVOUS_BIND` paketi içerisindeki Ed25519 imzası ile doğrulanır.
- Güvenlik duvarı oturum tablolarının açık tutulması için 30 saniye aralıklarla tek baytlık `0x09` (PING) ve `0x0A` (PONG) denetim paketleri iletilir.
- Bir röle üzerinde açılabilecek aktif tünel sayısı kaynak kısıtı amacıyla en fazla 64 ile sınırlandırılmıştır (`maxRendezvousTunnels`).
- **Dinamik Rol Yükseltme (`CAP_EDGE_TRANSIT`):** En az 2 bağımsız röleye ters tünel kuran ve `ALLOW_EDGE_ROUTING=true` yapılandırmasına sahip bir EDGE düğümü dinamik olarak `CAP_EDGE_TRANSIT` rolüne yükseltilir. Bu düğümler, doğrudan birbirine erişemeyen röleler ve uçlar arasında ters tünel üzerinden iki yönlü paket geçişi (In-and-Out reverse tunnel bridging) sağlar.
- **Homojen Dedikodu Köprüleme:** Transit uç düğümler, bağlı oldukları röleler arasında varlık anonslarını (`PRESENCE_ANNOUNCE`) ve küresel `#genel` kanal mesajlarını döngü oluşturmayacak şekilde kross-köprüler (`ALLOW_EDGE_GOSSIP=true`).

### 4. 3-Hop Teleskopik Post-Quantum Soğan Yönlendirme (Onion Routing)
- Ağ topolojisi ve paket akışının gizlenmesi amacıyla 3 atlamalı (Giriş, Röle/Transit, Çıkış) anonim devreler kurulur.
- Devre kurma havuzuna (`relayPool`) hem omurga `RELAY` düğümleri hem de `CAP_EDGE_TRANSIT` yeteneğine sahip ara uç düğümleri dahil edilerek yönlendirme çeşitliliği artırılır.
- Her atlamada NIST FIPS 203 uyumlu ML-KEM-768 (Kyber-768) algoritması ile anahtar kapsülleme gerçekleştirilir ve simetrik oturum anahtarları türetilir.
- Trafik Analizi ve DPI Koruması: Tüm soğan hücreleri (`ONION_CELL`) sabit 2048 bayt boyutunda tutulur (Uniform Cell Padding). Ham kullanıcı yükü azami 768 bayt (MAX_ONION_PAYLOAD) ile sınırlandırılır.
- Hücreler açık metin taşınmaz; taşıma katmanında AES-256-GCM ile şifrelenmiş `ENCRYPTED_FRAME` blokları içerisinde iletilir.

### 5. Dağıtık Varlık (Presence) ve SQLite Yönlendirme
- Düğümler varlık ve kanal aboneliklerini Ed25519 ile imzalanmış `PRESENCE_ANNOUNCE` paketleriyle dedikodu (gossip) mekanizması üzerinden yayar.
- Düğümlerin ham IP adresleri gossip paketlerinde yer almaz; duyurular alan adı veya `.mesh` kimliği üzerinden yapılır.
- Yönlendirme bilgileri bellekte önbelleğe alınır ve SQLite veritabanındaki `routing_table` tablosuna kaydedilir. 60 saniye boyunca yenilenmeyen kayıtlar temizlenir (TTL).

### 6. Bellek İçi SSH-2 Sunucusu ve İki Faktörlü Kasa Doğrulaması (2FA Vault)
- Harici SSH arka plan süreci (daemon) gerekmeksizin saf JavaScript ile yazılmış SSH-2 sunucusu barındırır.
- Dinamik Sürüm Sistemi & Yapılandırılabilir Kimlik: Sunucu kimlik dizgesi (`sshServerVersion`) ve sistem sürümü merkezi sürüm sistemi (`src/version.js`) üzerinden `package.json` ile dinamik olarak senkronize edilir (varsayılan: `SSH-2.0-Metrice_2.5.2`), ortam değişkeni veya konfigürasyon üzerinden özelleştirilebilir.
- Donanım Anahtarı Bağlama: Kullanıcı parolası, istemcinin Ed25519 açık anahtarı ile tuzlanarak Scrypt (N=16384, r=8, p=1) ve HKDF-SHA256 algoritmalarından geçirilir. Kayıtlı Ed25519 anahtarı olmaksızın doğru parola girilse dahi kimlik doğrulanamaz.

### 7. HAProxy PROXY Protocol v1 & v2 Desteği ve L4 Güvenliği
- Layer 4 ters vekil sunucuları (HAProxy, Nginx stream, AWS NLB) arkasında çalışan düğümlerin gerçek istemci IP ve portunu (`realRemoteAddress`, `realRemotePort`) şeffaf biçimde elde etmesini sağlar (`USE_PROXY_PROTOCOL=true`).
- Hem metin tabanlı PROXY v1 (`PROXY TCP4/TCP6/UNKNOWN`) hem de 12 baytlık ikili sihirli imzaya sahip PROXY v2 ikili protokolünü sıfır harici bağımlılıkla ayrıştırır.
- **IP Spoofing Koruması:** Yalnızca `PROXY_TRUSTED_IPS` (varsayılan: `127.0.0.1,::1`) listesindeki güvenilir vekillerden gelen PROXY başlıkları kabul edilir. Yetkisiz IP adreslerinden gelen spoofing denemelerinde soket anında kapatılır (`status: REJECT`).
- **Şeffaf Geçiş (Passthrough):** PROXY başlığı içermeyen standart bağlantılar, arta kalan tampon veri (`socket.unshift(remainder)`) akış kuyruğuna geri verilerek sıfır veri kaybıyla doğrudan federasyon, SSH veya Telnet işleyicilerine teslim edilir.

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

### 4. HAProxy / L4 Ters Vekil Arkasında PROXY Protocol ile Dağıtım
HAProxy veya Nginx Stream arkasında çalışan düğümler için örnek HAProxy yapılandırması:

```haproxy
frontend metrice_ssh_in
    bind *:2224
    mode tcp
    default_backend metrice_ssh_nodes

backend metrice_ssh_nodes
    mode tcp
    server srv1 127.0.0.1:2224 send-proxy-v2
```

Düğümün PROXY protokolü desteği ile başlatılması:
```bash
USE_PROXY_PROTOCOL=true \
PROXY_TRUSTED_IPS="127.0.0.1,::1" \
SSH_PORT=2224 \
FED_PORT=8001 \
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
| `publicFederationPort` | `PUBLIC_FED_PORT` | `FED_PORT` (8001) | Dış ağa anons edilen ve dialback yapılan genel federasyon portu |
| `publicSshPort` | `PUBLIC_SSH_PORT` | `SSH_PORT` (2224) | Dış ağa duyurulan genel SSH portu |
| `publicClientPort` | `PUBLIC_CLIENT_PORT` | `CLIENT_PORT` (2222) | Dış ağa duyurulan genel Telnet TUI portu |
| `sshServerVersion` | `SSH_SERVER_VERSION` | `'SSH-2.0-Metrice_2.5.2'` | SSH sunucusu protokol kimlik dizgesi (Sürüm sistemi ile dinamik) |
| `meshRole` | `MESH_ROLE` | `'EDGE'` | Düğüm rolü (`'RELAY'` veya `'EDGE'`) |
| `bootstrapPeers` | `BOOTSTRAP_PEERS` | `''` | Kalıcı başlangıç ve korumalı röle eş listesi (virgülle ayrılmış) |
| `maxRendezvousTunnels`| `MAX_RENDEZVOUS_TUNNELS` | `64` | Bir RELAY düğümünün kabul edeceği azami ters tünel sayısı |
| `rendezvousKeepaliveInterval` | `RENDEZVOUS_KEEPALIVE_MS` | `30000` | Ters tünel denetim aralığı (0x09/0x0A PING-PONG ms) |
| `presenceTtl` | `PRESENCE_TTL_MS` | `60000` | Yönlendirme tablosu varlık süresi (ms) |
| `circuitTtl` | `CIRCUIT_TTL_MS` | `600000` | Onion devreleri yaşam süresi (ms) |
| `uniformCellSize` | `UNIFORM_CELL_SIZE` | `2048` | Sabit soğan hücresi boyutu (bayt) |
| `secureBufferLimit` | `SECURE_BUFFER_LIMIT` | `65536` | Çerçeveleme tampon üst sınırı (64 KB) |
| `trustProxy` | `TRUST_PROXY` | `false` | Vekil sunucu arkasında IP doğrulama toleransı |
| `useProxyProtocol` | `USE_PROXY_PROTOCOL` | `false` | HAProxy PROXY Protocol v1 & v2 ayrıştırma desteği |
| `proxyProtocolTrustedIps` | `PROXY_TRUSTED_IPS` | `'127.0.0.1,::1'` | PROXY başlığı kabul edilecek güvenilir IP'ler |
| `allowEdgeRouting` | `ALLOW_EDGE_ROUTING` | `true` | EDGE düğümlerinde dinamik CAP_EDGE_TRANSIT geçişi |
| `allowEdgeGossip` | `ALLOW_EDGE_GOSSIP` | `true` | Çoklu bağlı röleler arasında homojen varlık köprüleme |
| `maxEdgeRendezvousRelays` | `MAX_EDGE_RENDEZVOUS_RELAYS` | `4` | EDGE düğümünün bağlanacağı azami röle sayısı |
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

### HAProxy PROXY Protocol v1 & v2 (L4 Başlık Formatı)
```text
# PROXY v1 (US-ASCII Text)
PROXY TCP4 203.0.113.195 198.51.100.1 56324 8001\r\n<payload>

# PROXY v2 (12-Bayt Binary Magic + IPv4/IPv6 Adres Bloğu)
\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x11\x00\x0C...<payload>
```

---

## Doğrulama ve Testler

Sistem bütünlüğü `tests/` klasöründeki üç kapsamlı test süiti (toplam 113 test) ile doğrulanır:

```bash
# Tüm test süitlerini sırayla çalıştırmak için:
npm test

# Veya test süitlerini bağımsız çalıştırmak için:
node tests/mesh.test.js      # 1. P2P-Mesh, AutoNAT, Rendezvous, PROXY ve Transit Spesifikasyon Süiti (81 Test)
node tests/protocol.test.js  # 2. Protokol, Ağ Keşfi, Post-Quantum SSH-2 ve Veritabanı Süiti (24 Test)
node tests/security.test.js  # 3. Protokol Güvenliği, Nonce Replay, DoS ve Enjeksiyon Denetim Süiti (8 Test)
```

Testler; Base32 türetimi, AutoNAT konsensüsü, PROXY Protocol v1/v2 ayrıştırma ve IP spoofing koruması, `CAP_EDGE_TRANSIT` dinamik rol yönetimi ve ters tünel kross-köprüleme, DoS tampon limitleri, ML-KEM-768 soğan yönlendirmesi, SSRF önlemleri ve Two-Factor SSH kimlik doğrulamasını uçtan uca kapsar.

---

## Lisans

Bu proje GNU General Public License v3.0 (GPLv3) altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakınız.