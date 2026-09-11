# Metrice v2.6.0

[English](README.md) | [Türkçe](README.tr.md)

Metrice, harici bağımlılık içermeyen (Zero External Dependencies), doğrudan Node.js çekirdek kütüphaneleri (`node:crypto`, `node:net`, `node:dgram`, `node:sqlite`, `node:dns`) üzerinde çalışan, kuantum sonrası kriptografi (Post-Quantum Cryptography) ve Tor benzeri çok katmanlı yönlendirme (Onion Routing) mimarisine sahip dağıtık eşler arası (P2P) ağ protokolüdür.

Sistem; NIST FIPS 203 ML-KEM-768 anahtar kapsülleme, Ed25519 tabanlı RFC 4648 Base32 düğüm kimliklendirmesi, AutoNAT konsensüsü, CGNAT arkasındaki uçlar için Rendezvous ters tünelleri, çoklu röle transit köprülemesi (EDGE Transit Routing / `CAP_EDGE_TRANSIT`), Layer 4 HAProxy PROXY Protocol v1 & v2 desteği ve yerleşik bellek içi SSH-2 sunucusu içermektedir.

---

## Mimari ve Temel Bileşenler

### 1. Düğüm Kimliği ve Kriptografik Adresleme
- **Kalıcı Anahtar Mimarisi:** Her düğüm ilk açılışta `node:crypto` üzerinden kalıcı bir Ed25519 asimetrik kimlik anahtarı çifti (SPKI/PKCS#8 PEM) ve NIST FIPS 203 ML-KEM-768 anahtar çifti üretir; bu anahtarlar SQLite `node_identity` tablosunda kalıcı olarak saklanır.
- **Deterministik NodeID Türetimi:** Açık anahtarın SPKI DER kodlamasından çıkarılan ham 32 baytlık açık anahtarın SHA-256 özeti alınır; bu özetin ilk 10 baytı (80 bit) RFC 4648 Base32 algoritmasıyla dolgusuz (padding-free) ve küçük harfli olarak kodlanarak tam 16 karakterlik küresel düğüm kimliği (`NodeID`) elde edilir (`^[a-z2-7]{16}$`).
- **Sanal `.mesh` Alan Adı İsim Uzayı:** Ağ üzerindeki tüm varlıklar IP ve portlardan bağımsız olarak sanal alan adlarıyla adreslenir:
  - Kullanıcı Doğrudan Adresi: `@kullanici:NodeID.mesh`
  - Federe Kanal Adresi: `#kanal:NodeID.mesh`
  - Küresel Ağ Yayını: `#genel`
  - Yerel Sistem Konsolu: `SYSTEM_CONSOLE` (veya dile göre `SİSTEM_KONSOLU`)
- **İmzalı Paket Bütünlüğü:** Düğümler arası iletilen tüm yönlendirme, tünelleme ve varlık bildirimleri kaynak düğümün Ed25519 özel anahtarı ile imzalanır (`CryptoHelper.sign`) ve hedef düğüm tarafından açık anahtar üzerinden matematiksel olarak doğrulanır (`CryptoHelper.verify`).

### 2. AutoNAT ve Ağ Ulaşılabilirlik Konsensüsü
- **Durum Makinesi:** Düğümler başlangıçta `UNKNOWN` durumundadır; el sıkışma aşamasında `OBSERVING` durumuna geçer ve diyal-geri testleriyle `DIALING` evresinden sonra nihai `CAP_RELAY` ya da `CAP_EDGE` rolünü kazanır.
- **Gözlemlenen Adres Takası (`observedAddress`):** P2P el sıkışması sırasında her düğüm, karşı eşin TCP soketinden okuduğu fiziksel IP ve portunu `observedAddress` alanı üzerinden karşı tarafa raporlar.
- **Yansıtılan Genel IP Konsensüsü:** Farklı eş düğümlerden en az iki tutarlı `observedAddress` bildirimi alındığında, düğüm kendi genel (public) IP adresini konsensüsle tespit eder.
- **Çift Taraflı Diyal-Geri Doğrulaması (`DIALBACK_REQUEST` / `DIALBACK_CONFIRM`):**
  - Ulaşılabilirliğini test etmek isteyen düğüm, rastgele 16 baytlık bir `nonce` ve dinlediği federasyon portunu içeren `DIALBACK_REQUEST` paketi iletir.
  - Testi yürüten eş, paketin geldiği fiziksel TCP soket adresine (`socket.realRemoteAddress || socket.remoteAddress`) doğrudan yeni bir TCP bağlantısı açmayı dener.
  - Karşı taraftan geçerli el sıkışma alındığında `DIALBACK_CONFIRM` döndürülür ve düğüm resmi olarak `CAP_RELAY` unvanını alır; port yönlendirmesi kapalı veya güvenlik duvarı arkasında ise `CAP_EDGE` olarak kalır.
- **SSRF ve IP Manipülasyon Savunması:** `DIALBACK_REQUEST` gövdesine saldırganlar tarafından enjekte edilebilecek harici hedef IP değerleri kesinlikle yok sayılır; yalnızca çekirdek soket katmanının doğruladığı kaynak IP adresi baz alınır. RFC 1918 özel ağ bloklarına (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) ve döngüsel (loopback `127.0.0.0/8`, `::1`) adreslere diyal-geri girişimi soket açılmadan engellenir.

### 3. Rendezvous, CGNAT Ters Tünelleri ve EDGE Transit Routing (CAP_EDGE_TRANSIT)
- **Kalıcı Ters TCP Tünelleri:** Doğrudan dışarıdan gelen bağlantıları kabul edemeyen `EDGE` düğümleri, açık internete erişimi bulunan birden fazla `RELAY` düğümüne kalıcı ters TCP tüneli açar (`maxEdgeRendezvousRelays`, varsayılan: 4).
- **Tünel El Sıkışması ve Güvenliği:** Tünel bağlantısı, `RENDEZVOUS_BIND` paketi içerisindeki `nodeId`, `identityPublicKey`, `timestamp`, 16 baytlık `nonce` ve Ed25519 imzası ile doğrulanır; röle geçerli istekleri `RENDEZVOUS_ACK` ile onaylar.
- **Tek Baytlık Nabız (Keepalive):** NAT oturum tablolarının ve güvenlik duvarı port haritalamalarının düşmesini engellemek için 30 saniye aralıklarla tek baytlık `0x09` (PING) ve `0x0A` (PONG) denetim baytları iletilir; fazladan JSON veya metin yükü oluşturulmaz.
- **Dinamik Rol Yükseltme (`CAP_EDGE_TRANSIT`):** En az 2 bağımsız röleye aktif ters tünel kuran ve `ALLOW_EDGE_ROUTING=true` yapılandırmasına sahip olan bir `EDGE` düğümü, rolünü dinamik olarak `CAP_EDGE_TRANSIT` seviyesine çıkarır.
- **İki Yönlü Ters Tünel Köprüleme (In-and-Out Bridging):** Transit düğüm, doğrudan birbirine erişemeyen ayrık röleler ve arkalarındaki uç düğümler arasında gelen paketleri ters tüneller üzerinden çapraz köprüleyerek ağda aktif bir aktarma omurgası gibi çalışır.
- **Homojen ve Döngüsüz Dedikodu Köprüleme:** Transit uç düğümler, bağlı oldukları farklı röleler arasında varlık anonslarını (`PRESENCE_ANNOUNCE`) ve küresel `#genel` kanal paketlerini tekilleştirme filtreleri sayesinde sonsuz döngüye sokmadan kross-köprüler (`ALLOW_EDGE_GOSSIP=true`).
- **Kaynak Tavanı:** Bir röle üzerinde açılabilecek aktif ters tünel sayısı bellek ve dosya tanımlayıcısı (FD) güvenliği amacıyla en fazla 64 ile sınırlandırılmıştır (`maxRendezvousTunnels`).

### 4. 3-Hop Teleskopik Post-Quantum Soğan Yönlendirme (Onion Routing)
- **3 Atlamalı Anonim Devre Topolojisi:** Kaynak ile hedef arasındaki doğrudan IP ve topoloji izini silmek amacıyla her oturum için üç bağımsız düğümden oluşan teleskopik devreler inşa edilir:
  1. Giriş Koruması (Inbound Guard Düğümü)
  2. Ara Aktarıcı (Relay veya `CAP_EDGE_TRANSIT` Düğümü)
  3. Çıkış Kapısı (Outbound Exit Düğümü)
- **Genişletilmiş Devre Havuzu:** Devre kurma algoritması (`relayPool`), omurga `RELAY` düğümleri ile `CAP_EDGE_TRANSIT` yetenekli uç düğümleri dinamik olarak harmanlayarak devre yolu çeşitliliğini artırır ve trafik analizini imkansızlaştırır.
- **NIST FIPS 203 ML-KEM-768 Anahtar Değişimi:** Devrenin her sekesinde (hop) kuantum sonrası Kyber-768 algoritmasıyla anahtar kapsülleme (`crypto.encapsulate` / `crypto.decapsulate`) yürütülür ve 32 baytlık taze simetrik oturum anahtarları türetilir.
- **Çok Katmanlı Kriptografik Zarf (Layered Onion Peeling):** Kaynak düğüm, iletilecek veriyi sondan başa doğru her düğmenin oturum anahtarıyla AES-256-GCM algoritması üzerinden iç içe sarar. Her ara düğüm yalnızca kendi katmanının şifresini çözer, paketin asıl içeriğini veya nihai hedefini bilmeksizin bir sonraki düğüme devre ID'si (`circuitId`) ile yönlendirir.
- **Sabit Boyutlu Hücre Doldurma (Uniform 2048-Byte Cell Padding):** Derin Paket İncelemesi (DPI) ve paket boyutu parmak izi analizlerini engellemek için tüm soğan hücreleri (`ONION_CELL`) istisnasız sabit 2048 bayt boyutunda iletilir. Kullanıcı veri yükü azami 768 bayt (`MAX_ONION_PAYLOAD`) ile sınırlandırılır; kalan kısım rastgele dolgu ile maskelenir.
- **Devre Yaşam Döngüsü ve Tasfiyesi:** Devreler 10 dakika (`CIRCUIT_TTL_MS = 600000`) sonra bellekten ve SQLite `active_circuits` tablosundan temizlenerek otomatik kapatılır; böylece uzun ömürlü devre dinleme saldırıları engellenir.

### 5. Dağıtık Varlık (Presence) ve SQLite Yönlendirme
- **İmzalı Varlık Bildirimleri:** Düğümler, yerel kullanıcılarının durumunu ve kanal aboneliklerini Ed25519 ile imzalanmış `PRESENCE_ANNOUNCE` paketleriyle ağa bildirir.
- **IP İzolasyonu:** Varlık anonslarında düğümlerin fiziksel IP adresleri kesinlikle paylaşılmaz; eşleşmeler yalnızca sanal alan adları ve `.mesh` kimlikleri üzerinden yürütülür.
- **Dedikodu Fanout ve Paket Tekilleştirme:** Düğümler aldıkları varlık bildirimlerini komşularına yayarken (gossip), son görülen mesaj ID'lerini bellek havuzunda takip ederek mükerrer yayın fırtınalarını (broadcast storm) tamamen engeller.
- **Bilateral Çift Yönlü Senkronizasyon:** İki düğüm arasında yeni bir bağlantı kurulduğunda, her iki taraf da bilinen varlık tablolarını karşılıklı takas eder; yerel kullanıcısı olmasa bile arkasındaki ters tünelli uçların varlıkları kesintisiz aktarılır.
- **SQLite Yönlendirme Kalıcılığı ve TTL:** Öğrenilen yönlendirme rotaları SQLite `routing_table` tablosunda `last_seen` zaman damgasıyla saklanır. 60 saniye (`PRESENCE_TTL_MS`) boyunca tazelenmeyen varlık kayıtları bellekten ve veritabanından otomatik temizlenir.

### 6. Bellek İçi SSH-2 Sunucusu ve İki Faktörlü Kasa Doğrulaması (2FA Vault)
- **Sıfır Bağımlılıklı Gömülü SSH-2:** Harici sistem servislerine (`OpenSSH`, `sshd`) veya native C/C++ bağlayıcılarına ihtiyaç duymaksızın doğrudan Node.js ikili akışları üzerinde çalışan saf JavaScript SSH-2 motoru (RFC 4253, RFC 4252, RFC 4254).
- **Kriptografik Protokol Yığını:**
  - Anahtar Değişimi: `curve25519-sha256`
  - Sunucu Host Anahtarı: `ssh-ed25519`
  - Taşıma Şifrelemesi: `aes128-ctr` veya `aes256-gcm`
- **Dinamik Sürüm Senkronizasyonu:** Sunucu karşılama kimliği (`sshServerVersion`), `package.json` ile dinamik senkronize edilir (`SSH-2.0-Metrice_2.6.0`) ve `SSH_SERVER_VERSION` ortam değişkeni ile tamamen maskelenebilir.
- **Donanım Açık Anahtarı Mühürlemeli İki Faktörlü Kasa (2FA Vault):**
  - Parola asla yalın haliyle işlenmez. Kullanıcı parolası, istemcinin fiziksel Ed25519 açık anahtarından türetilen 32 baytlık tuz (salt) ile birleştirilir.
  - Scrypt (N=16384, r=8, p=1, maxmem 64 MB) algoritmasından geçirilerek anahtar türetilir.
  - Elde edilen anahtar, `metrice-vault-salt:${nodeAddress}` ve `metrice-vault-seed-v2` parametreleriyle HKDF-SHA256 işlemine tabi tutularak 32 baytlık kasa tohumu üretilir.
  - Bu tohumla şifrelenen `METRICE_VAULT_SENTINEL_V1` nöbetçi metni doğrulanır. Kullanıcı parolasını doğru girse dahi, oturum açtığı SSH istemcisinin Ed25519 açık anahtarı veritabanındaki kayıtlı açık anahtarlarla (`public_keys`) eşleşmezse erişim kesin olarak reddedilir.

### 7. HAProxy PROXY Protocol v1 & v2 Desteği ve Layer 4 Güvenliği
- **Şeffaf İstemci IP Çözümlemesi:** Düğümler Layer 4 yük dengeleyiciler (HAProxy, Nginx Stream, AWS NLB, Traefik) arkasında çalıştırıldığında, istemcilerin gerçek fiziksel IP ve port bilgileri (`realRemoteAddress`, `realRemotePort`) PROXY başlığından elde edilir (`USE_PROXY_PROTOCOL=true`).
- **PROXY v1 ve v2 Çift Protokol Desteği:**
  - PROXY v1: US-ASCII metin satırları (`PROXY TCP4/TCP6/UNKNOWN ...\r\n`).
  - PROXY v2: 12 baytlık ikili sihirli imza (`\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A`), sürüm/komut baytı, adres ailesi ve ikili IPv4/IPv6 adres blokları.
- **IP Spoofing Savunması:** PROXY başlığı enjeksiyonu saldırılarına karşı yalnızca `PROXY_TRUSTED_IPS` (varsayılan: `127.0.0.1,::1`) listesindeki güvenilir vekillerden gelen başlıklar kabul edilir. Yetkisiz IP adreslerinden gelen spoofing denemelerinde soket anında kapatılır (`status: REJECT`).
- **Şeffaf Geri Verme (Passthrough Unshift):** PROXY başlığı içermeyen doğrudan istemci bağlantılarında önceden okunan tampon veri akışa geri verilerek (`socket.unshift(remainder)`) sıfır veri kaybıyla federasyon, SSH veya Telnet işleyicilerine yönlendirilir.

### 8. Ayrılmış TCP Sağlık ve Kalp Atışı Sunucusu (Port 8050)
- **Ayrılmış Sağlık Portu (`HEALTH_PORT`):** Docker konteynerleri (`HEALTHCHECK`), Kubernetes liveness/readiness probları ve harici orkestratörler için port 8050 üzerinde bağımsız çalışan hafif bir TCP denetim sunucusu (`src/core/healthServer.js`).
- **Federasyon Trafik İzolasyonu:** Sağlık kontrollerinin P2P federasyon portuna (8001) bağlanması tamamen engellenmiş; böylece her 30 saniyede bir oluşan döngüsel (loopback) log kirliliği ve tünel el sıkışma yükü sıfıra indirilmiştir.
- **Ağ İzolasyonu ve Güvenlik:** Varsayılan olarak yalnızca yerel döngü arayüzüne (`127.0.0.1`) bağlanır; harici denetim sistemleri için `ALLOW_OUTER_HEARTBEAT=true` yapılandırmasıyla `0.0.0.0` dinlemesine açılabilir.
- **Akış Komut Seti:**
  - `PING`: Liveness kontrolü; `PONG\n` yanıtı döner.
  - `HEALTH`: Hızlı veritabanı sorgusu ve çalışma süresi testi; `OK {"status":"healthy",...}\n` döner.
  - `STATUS` / `INFO`: Kapsamlı sistem ve telemetri dökümü (Uptime, RSS ve Heap bellek metrikleri, SQLite WAL durumu, aktif Rendezvous tünel sayıları, aktif Onion devreleri, bilinen ve doğrulanmış eş sayıları, ML-KEM güvenlik durumu).
  - `QUIT`: Soketi temiz bir şekilde sonlandırır.

### 9. Taşıma Katmanı İkili Çerçeveleme, DoS ve Tekrar Oynatma Koruması
- **Tampon Güvenlik Sınırı (`SECURE_BUFFER_LIMIT`):** Taşıma katmanında satır sonu (`\n`) ayracı olmaksızın 64 KB (`SECURE_BUFFER_LIMIT = 65536` bayt) tampon sınırını aşan veya geçersiz formatta veri akıtan bağlantılar bellek tüketim saldırılarına (Slowloris/OOM) karşı anında imha edilir (`socket.destroy()`).
- **Kriptografik Nonce Havuzu (Anti-Replay):** Her el sıkışma ve tünel bağlama paketinde 16 baytlık kriptografik rastgele anahtar (`nonce`) kullanılır. Görülmüş olan nonce'lar bellek içi zaman damgalı bir havuzda izlenir; aynı nonce ile gelen mükerrer paketler derhal düşürülür.
- **Zaman Damgası Sapma Denetimi (Timestamp Skew Defense):** Paketlerin zaman damgaları sistem saatiyle karşılaştırılır; tolerans dışındaki gecikmiş paketler veya geleceğe dönük saat manipülasyonları reddedilir.
- **`ENCRYPTED_FRAME` Taşıma Zarfı:** Hassas P2P mesajları ağ üzerinde 12 baytlık IV, 16 baytlık kimlik doğrulama etiketi (Auth Tag) ve şifreli veri yükünden oluşan AES-256-GCM bloklarıyla authenticated encryption güvencesinde taşınır.

### 10. Kalıcı SQLite Depolama Mimarisi ve Çevrimdışı İleti Kuyruğu (Outbox)
- **Sıfır Bağımlılıklı `node:sqlite` Motoru:** Harici npm sürücüsü veya C++ derlemesi gerektirmeyen, doğrudan Node.js çekirdeğindeki `DatabaseSync` üzerinde çalışan yerel veritabanı mimarisi.
- **WAL Modu ve Yüksek Eşzamanlılık:** `PRAGMA journal_mode = WAL;` ve `PRAGMA synchronous = NORMAL;` pragma yapılandırmaları ile okuma ve yazma kilitlenmeleri önlenir, yüksek IOPS performansı sağlanır.
- **Kapsamlı Şema Düzeni:**
  - `node_identity`: Kalıcı Ed25519 ve ML-KEM-768 anahtar çiftleri.
  - `profiles`: Kullanıcı kontakları, parola hash'i, kayıtlı açık anahtarlar (`public_keys`), KEM anahtarı ve Telnet erişim izinleri.
  - `messages`: Özel sohbet ve kanal mesaj geçmişi, E2EE bayrakları ve kullanıcı bazlı silinme kayıtları.
  - `trusted_keys`: Doğrulanmış eş açık anahtarları.
  - `routing_table`: Dinamik eş yönlendirme rotaları ve TTL kayıtları.
  - `active_circuits`: 3-hop devre sekme eşlemeleri ve simetrik anahtarlar.
  - `outbox`: Çevrimdışı eşlere gönderilen bekleyen iletiler.
- **Çevrimdışı İleti Kuyruğu (Outbox Engine):** Çevrimdışı bir kullanıcıya mesaj gönderildiğinde ileti `outbox` tablosuna alınır. İlgili kullanıcının çevrimiçi varlık bildirimi (`PRESENCE_ANNOUNCE`) ağa ulaştığında veya artan aralıklarla (exponential backoff) otomatik yeniden deneme döngüsüyle mesaj teslim edilir ve kuyruktan silinir.

### 11. Çok Dilli Etkileşimli TUI ve ANSI Terminal Oturum Motoru
- **Saf JavaScript ANSI/VT100 Motoru:** Harici UI çerçeveleri (blessed, ink) olmaksızın ANSI kaçış dizileriyle çalışan imleç yönetimi, renk motoru ve ekran tamponu denetleyicisi (`src/utils/ansi.js`).
- **Terminal Oturum Yönetimi (`TerminalSession`):** Hem Telnet NVT (RFC 854) hem de SSH-2 PTY oturumlarını şeffaf biçimde soyutlayan çift katmanlı oturum motoru (`src/core/terminalSession.js`).
- **Modüler Komut Kayıt Defteri (`CommandRegistry`):** Tüm TUI komutları (`/join`, `/msg`, `/keys`, `/status`, `/who`, `/peers`, `/help` vb.) `src/commands/modules/` altında bağımsız modüller olarak yapılandırılmıştır; oturum yetkilendirme (`requireAuth`) ve parametre ayrıştırması otomatik yürütülür.
- **Tam Çift Dilli Yerelleştirme (`I18n`):** Sistem logları, terminal arayüzü, karşılama ekranları ve hata mesajları Türkçe (`src/locales/tr.js`) ve İngilizce (`src/locales/en.js`) dil sözlükleri üzerinden dinamik olarak sunulur.

### 12. Telnet Güvenlik Bariyeri ve Erişim Denetimi
- **Açık Metin Parola Koruması:** Parolaların yerel ağda veya açık internette koklanmasını (sniffing) engellemek amacıyla kullanıcı profillerine `allow_telnet` güvenlik bayrağı yerleştirilmiştir.
- **Varsayılan Kısıtlama ve SSH Üzerinden Yetkilendirme:** Kullanıcılar varsayılan olarak Telnet üzerinden parola girişi yapamaz; Telnet erişimi yalnızca güvenli ve şifreli SSH-2FA oturumu içerisinden `/allowtelnet` komutu çalıştırılarak aktif edilebilir.

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

### 2. Docker ve Docker Compose ile Dağıtım (Kalıcı Veri Garantili)

Metrice, en iyi güvenlik pratiklerine (Rootless `node` kullanıcısı, TCP sağlık denetimi, otomatik `VOLUME ["/app/data"]` kalıcılığı) göre hazırlanmış [Dockerfile](Dockerfile) ve [docker-compose.yml](docker-compose.yml) içerir.

> **Önemli (Veri Kalıcılığı):** SQLite veritabanı (`data_8001.db`) ve eş önbelleği (`peers_8001.json`) konteyner içindeki `/app/data/` dizinine yönlendirilmiştir. Ana makinenin `./data` dizini bu konuma bağlandığı için imaj her yeniden derlendiğinde (`docker build`) veya güncellendiğinde kullanıcı profilleri, açık anahtarlar ve mesaj geçmişi kesinlikle silinmez, korunur.

#### Yöntem A: Docker Compose ile Başlatma (Önerilen)
```bash
# 1. Düğümü arka planda derleyip başlatın:
docker compose up -d --build

# 2. Canlı logları izleyin:
docker compose logs -f

# 3. Durdurmak için:
docker compose down
```

#### Yöntem B: Bağımsız Docker CLI ile Başlatma
```bash
# 1. Güvenli imajı derleyin:
docker build -t metrice .

# 2. Kalıcı veri dizinini oluşturun ve izinleri ayarlayın (UID 1000 node kullanıcısı):
mkdir -p data
chown -R 1000:1000 data 2>/dev/null || true

# 3. Kalıcı hacim ve ortam değişkenleriyle çalıştırın:
# (Not: SERVER_NAME zorunlu değildir; AutoNAT genel IP'yi otomatik belirler)
docker run -d \
  --name metrice-node \
  --restart always \
  -e TRUST_PROXY=true \
  -e MESH_ROLE=RELAY \
  -e FED_PORT=8001 \
  -e SSH_PORT=2224 \
  -e CLIENT_PORT=2222 \
  -e DB_FILE=/app/data/data_8001.db \
  -e PEER_FILE=/app/data/peers_8001.json \
  -p 8001:8001 \
  -p 2224:2224 \
  -p 2222:2222 \
  -v $(pwd)/data:/app/data \
  metrice
```

#### Yöntem C: Hazır İmajı Çekerek Çalıştırma (GitHub Container Registry)
Kaynak kodu derlemekle uğraşmadan doğrudan GitHub Container Registry (GHCR) üzerinden çoklu mimarili (`linux/amd64` ve `linux/arm64`) resmi imajı çekebilirsiniz:
```bash
# Resmi imajı çekin:
docker pull ghcr.io/gokturka1/metrice:latest

# Doğrudan GHCR imajı ile başlatın:
docker run -d \
  --name metrice-node \
  --restart always \
  -e TRUST_PROXY=true \
  -e MESH_ROLE=RELAY \
  -e FED_PORT=8001 \
  -e SSH_PORT=2224 \
  -e CLIENT_PORT=2222 \
  -e DB_FILE=/app/data/data_8001.db \
  -e PEER_FILE=/app/data/peers_8001.json \
  -p 8001:8001 \
  -p 2224:2224 \
  -p 2222:2222 \
  -v $(pwd)/data:/app/data \
  ghcr.io/gokturka1/metrice:latest
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
| `publicFederationPort` | `PUBLIC_FED_PORT` / `FED_PUBLIC_PORT` | `FED_PORT` (8001) | Dış ağa anons edilen ve dialback yapılan genel federasyon portu |
| `publicSshPort` | `PUBLIC_SSH_PORT` / `SSH_PUBLIC_PORT` | `SSH_PORT` (2224) | Dış ağa duyurulan genel SSH portu |
| `publicClientPort` | `PUBLIC_CLIENT_PORT` / `CLIENT_PUBLIC_PORT` | `CLIENT_PORT` (2222) | Dış ağa duyurulan genel Telnet TUI portu |
| `healthPort` | `HEALTH_PORT` | `8050` | TCP Sağlık ve Kalp Atışı (Heartbeat) dinleme portu |
| `allowOuterHeartbeat` | `ALLOW_OUTER_HEARTBEAT` | `false` | TCP Sağlık portunu dış ağa (`0.0.0.0`) açma izni (Varsayılan: Yalnızca `127.0.0.1`) |
| `sshServerVersion` | `SSH_SERVER_VERSION` | `'SSH-2.0-Metrice_2.6.0'` | SSH sunucusu protokol kimlik dizgesi (Sürüm sistemi ile dinamik) |
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

### TCP Health & Heartbeat Protokolü (Port 8050)
```text
# Liveness Kontrolü:
İstemci: PING\n
Sunucu : PONG\n

# Hızlı Sağlık Kontrolü (Health Probe):
İstemci: HEALTH\n
Sunucu : OK {"status":"healthy","uptime":3600,"database":"healthy","timestamp":1789139924935}\n

# Ayrıntılı Telemetri Dökümü:
İstemci: STATUS\n
Sunucu : {"status":"healthy","version":"2.6.0","serverName":"relay1.metrice.network","nodeAddress":"...","meshRole":"RELAY","uptimeSeconds":3600,"timestamp":1789139924935,"database":{"status":"healthy","walMode":true},"federation":{"port":8001,"activeRendezvousTunnels":4,"maxRendezvousTunnels":64,"activeCircuits":2},"peers":{"totalKnown":12,"verified":8},"quantumSecurity":{"mlkem768":true,"strictPq":false},"memory":{"rssMb":42.5,"heapUsedMb":18.2}}\n

# Oturumu Sonlandırma:
İstemci: QUIT\n
```

---

## Doğrulama ve Testler

Sistem bütünlüğü `tests/` klasöründeki altı kapsamlı test süiti (toplam 154 test) ve GitHub Actions CI/CD boru hattı ile doğrulanır:

```bash
# Tüm test süitlerini sırayla çalıştırmak için:
npm test

# Veya test süitlerini bağımsız çalıştırmak için:
node tests/mesh.test.js       # 1. P2P-Mesh, AutoNAT, Rendezvous, PROXY ve Transit Spesifikasyon Süiti (83 Test)
node tests/protocol.test.js   # 2. Protokol, Ağ Keşfi, Post-Quantum SSH-2 ve Veritabanı Süiti (24 Test)
node tests/security.test.js   # 3. Protokol Güvenliği, Nonce Replay, DoS, SSRF ve PROXY Spoofing Süiti (10 Test)
node tests/presence.test.js   # 4. Presence Senkronizasyonu, Dedikodu, Yarış Koruması & Proxy Keepalive (8 Test)
node tests/crypto-kat.test.js # 5. Kriptografik KAT (RFC 8032, NIST FIPS 203, KDF) Doğrulama Süiti (10 Test)
node tests/health.test.js     # 6. TCP Sağlık ve Kalp Atışı (Health & Heartbeat) Protokol Süiti (19 Test)
```

Testler; Base32 türetimi, AutoNAT konsensüsü, PROXY Protocol v1/v2 ayrıştırma ve IP spoofing koruması, `CAP_EDGE_TRANSIT` dinamik rol yönetimi ve ters tünel kross-köprüleme, DoS tampon limitleri, ML-KEM-768 soğan yönlendirmesi, SSRF önlemleri, Two-Factor SSH kimlik doğrulaması ve ağ genelinde anlık varlık senkronizasyonunu uçtan uca kapsar.

Ayrıca projeye entegre edilen GitHub Actions boru hattı ile her push ve PR anında:
- `Node.js 24.x` ve `Node.js 26.x` sürümlerinde test matrisi,
- `Oxlint` bağımsız statik kod analizi (`--deny-warnings`),
- Sıfır harici npm bağımlılığı (Zero-Dependency) denetimi,
- `Docker` imaj derleme ve konteyner ayağa kalkma doğrulaması,
- `CodeQL` statik uygulama güvenlik testi (SAST)
otomatik olarak yürütülür.

---

## Lisans

Bu proje GNU General Public License v3.0 (GPLv3) altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakınız.