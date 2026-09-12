# Metrice Mimari Geliştirme ve Performans Yol Haritası (Roadmap)

## Genel Hedef
Sıfır dış bağımlılık (Zero-Dependency) ve kuantum sonrası kriptografi (PQC) standartlarını koruyarak, Metrice düğümlerini yüksek ağ trafiğine, kaynak kısıtlarına ve DoS girişimlerine karşı esnek, ölçeklenebilir ve yüksek performanslı bir mimariye kavuşturmak.

---

## Faz 1: Donanım Tabanlı Dinamik Kapasite ve Davranışsal Hız Sınırlayıcı (Rate Limiter)

### 1. Dinamik Tünel ve Kaynak Kapasitesi (Adaptive Resource Capacity)
- Sabit `MAX_RENDEZVOUS_TUNNELS = 64` tavanı yerine sunucu donanımına duyarlı otomatik kota:
  - CPU çekirdek sayısı (`os.cpus().length`) ve toplam bellek (`os.totalmem()`) parametrelerine göre hesaplama.
  - Düşük kaynaklı sunucularda (örneğin 512 MB - 1 GB VPS) tavanın otomatik 16-32 seviyesine çekilerek bellek yetersizliği (Out-of-Memory / OOM) riskinin önlenmesi.
  - Güçlü sunucularda (4-16 çekirdek, 8+ GB RAM) 128-256 tünele kadar güvenli ölçeklenme.
  - Ortam değişkeni (`MAX_RENDEZVOUS_TUNNELS`) ile manuel tavan belirleme seçeneğinin korunması.

### 2. Davranışsal İtibar ve Jeton Kovası Hız Sınırlayıcı (Token-Bucket Rate Limiter)
- IP ve NodeID başına hafif, bellek içi jeton kovası (Token Bucket / Leaky Bucket) motoru.
- **Node 26 `crypto.hash` ile Akışsız Hızlı Özetleme:** `crypto.createHash('sha256')` stream nesnesi ve GC baskısı yaratmadan, doğrudan C++ katmanında çalışan tek seferlik `crypto.hash('sha256', ipOrNodeId)` fonksiyonu ile mikrosaniyeler altında hız sınırı anahtarı çıkarma.
- **`node:net` Yerel `BlockList` ve `SocketAddress` ile C++ Hızında Filtreleme:** Harici kütüphane veya yavaş RegExp sorgulamaları yerine, Node.js yerleşik `net.BlockList` yapısı ile `O(1)` karmaşıklığında IP ve CIDR alt ağ (`addSubnet`) engellemesi.
- Anormal trafik profillerinin tespiti:
  - Aşırı hızlı diyal-geri (`DIALBACK_REQUEST`) talepleri,
  - Hatalı (malformed) veya geçersiz ikili çerçeve tekrarları,
  - Hızlı soket açma-kapama (`reconnect spam`) döngüleri.
- Kademeli Yaptırım Mekanizması:
  - Seviye 1: Soket düzeyinde yapay gecikme (Throttling).
  - Seviye 2: `net.BlockList` üzerinden geçici IP/Peer karantinası (Jail).
  - Seviye 3: `PeerManager` güven puanının (`score`) düşürülmesi ve havuzdan tahliye (`Eviction`).

### 3. Bağlantı Kabul Denetimi ve Yük Yönlendirme (Admission Control & REDIRECT Load Balancing)
Bir `RELAY` düğümüne gelen tünel (`RENDEZVOUS_BIND`) veya bağlantı talepleri için 3 aşamalı karar mekanizması:
- **1. ACCEPT (Kabul):** Düğümün tünel kapasitesi müsaitse (`rendezvousTunnels.size < maxTunnels`) ve kural ihlali yoksa tünel kabul edilir, `RENDEZVOUS_ACK` döndürülür ve oturum başlatılır.
  - **Ayrıntılı Çekirdek TCP Keep-Alive Denetimi:** Standart `setKeepAlive` yerine modern `net.connect` / `net.createServer` parametreleri (`keepAlive: true`, `keepAliveInitialDelay: 10000`, `keepAliveInterval`, `keepAliveProbes`) ile CGNAT tablolarının kapandığı mobil/ev ağlarında yanıtsız (zombie) tünellerin uygulama katmanı ping trafiğine gerek kalmadan işletim sistemi çekirdeği düzeyinde tespiti.
  - **Dual-Stack Happy Eyeballs (`autoSelectFamily: true`, `autoSelectFamilyAttemptTimeout: 150`):** RFC 8305 algoritmasıyla IPv6/IPv4 çift yığınlı eş bağlantılarında en düşük gecikmeli soketi otomatik seçme.
- **2. REDIRECT (Yönlendirme):** Röle kapasitesi doluysa (`rendezvousTunnels.size >= maxTunnels`), istemci bağlantısı doğrudan kesilmez. Röle kendi SQLite `routing_table` tablosundaki en düşük gecikmeli, doğrulanmış ve müsait 2-3 alternatif RELAY veya EDGE_TRANSIT düğümünün imzalı adresini içeren bir `RENDEZVOUS_REDIRECT` paketi döner:
  ```json
  {
    "status": "redirect",
    "relays": ["relay2.metrice.network:8001", "edge-transit1.domain.com:8001"]
  }
  ```
  `EDGE` istemcisi rastgele arama yapmak yerine doğrudan önerilen bu röleye bağlanarak ağ yükünü dengeli biçimde dağıtır.
  - **Node 26 SQLite Changeset Replikasyonu:** Röleler arası yönlendirme tablosu delta takasında `node:sqlite` Session Extension (`createSession()` / `applyChangeset()`) kullanılarak SQL sorgusu üretmeden 36 baytlık ikili changeset formatında verimli senkronizasyon.
- **3. REJECT (TCP RST ile Reddetme ve Karantina):** Geçersiz Ed25519/ML-DSA imza, bozuk ikili çerçeve, sahte NodeID veya nonce replay saldırısı tespit edilirse soket klasik `socket.destroy()` yerine doğrudan `socket.resetAndDestroy()` çağrısıyla kapatılır:
  - İşletim sistemi çekirdeğine doğrudan **TCP RST (Reset)** paketi gönderilir.
  - Standart FIN-ACK el sıkışması ve soketin `TIME_WAIT` durumunda çekirdekte asılı kalması engellenir; soket tablosu ve dosya tanıtıcıları (file descriptors) derhal serbest bırakılır.
  - Saldırgan eşin güven puanı sıfırlanır, IP adresi `net.BlockList` karantinasına eklenir.

### 4. Periyodik Sistem Sağlık ve Kaynak Denetleyicisi (Watchdog)
- Arka planda periyodik (örneğin 60 saniyede bir) çalışan hafif iç durum kontrolü:
  - Karşı tarafı kopmuş ancak soket düzeyinde asılı kalmış yetim tünellerin kapatılması.
  - Süresi dolmuş geçici Onion devre anahtarlarının ve nonce kayıtlarının temizlenmesi.
  - **Node 26 `node:sqlite` Kullanıcı Tanımlı Fonksiyonları (`db.function()`):** V8 motoruna satırları çekip döngüde filtrelemek yerine, SQLite motoruna doğrudan C++ hızında çalışan `db.function('is_peer_expired', ...)` fonksiyonu eklenerek süresi dolmuş kayıtların tek sorguda (`DELETE FROM routing_table WHERE is_peer_expired(last_seen, ?) = 1`) sıfır bellek yüküyle temizlenmesi.
  - **`db.setAuthorizer()` ile Motor Düzeyinde Güvenlik:** Yetkisiz veya beklenmeyen SQL sorgularının ve tablo manipülasyonlarının doğrudan SQLite motoru seviyesinde engellenmesi.
  - SQLite WAL dosya boyutunun izlenip gerektiğinde `wal_checkpoint` işletilmesi.
  - Düğümün bellek ve kaynak sızıntılarına karşı kesintisiz ve kararlı çalışmasının sağlanması.

### 5. Ingress Tüneli Arkasındaki Uç Düğümler İçin Kısmi Röle Desteği: `EDGE_TRANSIT` Rolü ve `PUBLIC_SERVER_NAME`
Doğrudan genel statik IP adresine veya port yönlendirmesine sahip olmayan ancak Cloudflare Tunnel (`cloudflared`), ngrok, bore vb. bir ters proxy/ingress aracılığıyla dışarıdan erişilebilen tüm `EDGE` düğümlerinin ağa transit kapasitesi sağlaması:
- **Tüm EDGE Düğümleri İçin Genel Mimari:**
  - Bu yetenek yalnızca belirli bir istemci moduyla sınırlı değildir; tünel/ingress arkasında çalışan ve `PUBLIC_SERVER_NAME` tanımlanmış tüm `EDGE` düğümleri için geçerlidir.
- **Asimetrik Çıkış ve Giriş Yönlendirmesi (Asymmetric Egress / Ingress Routing):**
  - **Dışarı Çıkış (Outbound / Egress):** Düğüm ağdaki diğer düğümlere veya birincil röleye bağlanırken paketleri doğrudan kendi fiziksel yerel ağı ve IP adresi üzerinden çıkarır; standart bir `EDGE` gibi ana `RELAY` düğümüne ters tünel (`RENDEZVOUS_BIND`) açık tutarak ağ federasyonuna bağlı kalır.
  - **İçeri Giriş (Inbound / Ingress):** Diğer eşlerden gelen doğrudan TCP bağlantılarını ise Cloudflare Tunnel veya harici ingress tünelinin yönlendirdiği yerel dinleyici portu (`MESH_PORT`) üzerinden kabul eder.
- **Dış Erişim Alan Adı Tanımlaması (`PUBLIC_SERVER_NAME` / `SERVER_NAME_PUBLIC`):**
  - Ortam değişkeni üzerinden tünelin dışarıdan erişilebilen genel alan adı veya host:port bilgisi tanımlanır (Örn: `PUBLIC_SERVER_NAME='edge-ingress.domain.com:8001'`).
  - Düğüm ayağa kalktığında bu değişkeni algılayarak kısmi röle modunu (`Partial Relay`) etkinleştirir.
- **Dedikodu (Gossip) Yayılımı ve Yetenek Anonsu (Capability Gossip):**
  - Düğüm birincil röleye bağlandığında veya ağda dedikodu yayılımı (`PEER_ANNOUNCE` / `PEER_EXCHANGE`) yaptığında, kendisini `isTransit: true` bayrağı ve `publicServerName` tünel adresiyle tanıtır.
  - Röleler ve komşu eşler kendi SQLite `routing_table` kayıtlarında bu düğümü "Erişilebilir Transit Uç Düğüm" olarak indeksler.
- **EDGE Düğümler İçin Alternatif Röle ve Yük Dağıtımı:**
  - Standart `EDGE` düğümleri, ana röleler dolu olduğunda (`RENDEZVOUS_REDIRECT` aldıklarında) ya da daha düşük gecikmeli bir alternatif gerektiğinde bu `EDGE_TRANSIT` düğümlerine bağlanarak ters tünel açabilir veya onları Onion devrelerinde ara transit atlama (intermediate hop) olarak kullanabilir.
  - Böylece merkezi rölelerin üzerindeki bağlantı ve bant genişliği yükü, topluluğun ingress tünelleri arkasındaki sunucuları üzerinden dengeli biçimde dağıtılır.

---

## Faz 2: İkili Çerçeveleme, Öncelik Kuyruğu ve Kuantum Sonrası Anahtar Yenileme (Wire Protocol & PQC Double Ratchet)

### 1. Çok Kademeli Öncelik Kuyruğu (PriorityQueue)
Trafik yönetimini düzenleyen ve gecikmeyi minimize eden 4 kademeli paket öncelik modeli:
- **Kademe 1 (CRITICAL - Sıfır Gecikme):**
  - Onion Yönlendirme Hücreleri (`ONION_CELL`).
  - Rendezvous ters tünel veri aktarım paketleri (In-and-Out bridging).
  - Bu paketler beklemeden sokete iletilir.
- **Kademe 2 (HIGH - Etkileşimli Öncelik):**
  - Post-Quantum ML-KEM-768 El Sıkışmaları (`HANDSHAKE_INIT` / `REPLY`).
  - SSH-2 Terminal TUI tuş vuruşları ve kontrol sinyalleri.
- **Kademe 3 (NORMAL - Standart Veri):**
  - Uçtan uca şifreli doğrudan mesajlar (`DIRECT_MESSAGE`).
  - Federe ve küresel kanal mesaj paketleri.
- **Kademe 4 (LOW - Arka Plan İşleri):**
  - Varlık (`Presence`) anonsları ve Gossip yayılımı.
  - Outbox yeniden deneme döngüleri.
  - SQLite WAL temizliği, indeksleme ve süresi dolmuş devre kayıtlarının silinmesi.

### 2. İkili İletim Protokolü: JSON ve Base64 Dönüşümü (Binary Framing)
- `SecureChannel` ve `OnionRouter` üzerinde metinsel JSON ayrıştırma ve Base64 dolgusunun (`pad: '000...'`) kaldırılması:
  - Base64 kodlamasının getirdiği %33 bant genişliği ve bellek ek yükünün ortadan kaldırılması.
  - V8 motorundaki string tahsisatı (allocation) ve çöp toplayıcı (GC) baskısının engellenmesi.
  - **Node 26 TC39 Standart İkili Metotları:** `Uint8Array.prototype.toBase64()`, `Uint8Array.fromBase64()`, `Uint8Array.prototype.toHex()` ve `Uint8Array.fromHex()` metotlarının benimsenmesi; string veya harici tampon tahsisatı olmaksızın doğrudan V8 C++ hızında sıfır-kopya (zero-allocation) ikili/hex dönüşümleri.
- **Sabit 2048 Baytlık İkili Onion Hücresi (Binary Onion Cell):**
  - Doğrudan `Uint8Array` / `Buffer.allocUnsafe(2048)` üzerinde çalışan ikili çerçeve:
    ```text
    +--------------+---------------+-------------------+------------------+
    | Magic (1B)   | Type (1B)     | Payload Len (2B)  | Nonce / CID (16B)|
    | 0x4D ('M')   | 0x10          | Big-Endian uint16 | 16 Bayt Devre ID |
    +--------------+---------------+-------------------+------------------+
    | IV (12B)     | Auth Tag (16B)| Ciphertext (Var)  | Random Pad (Var) |
    | GCM IV       | GCM Tag       | Şifreli Gövde     | Toplam: 2048 B   |
    +--------------+---------------+-------------------+------------------+
    ```
  - Kalan dolgu baytlarının deterministik olmayan kriptografik rastgele verilerle (`crypto.randomFillSync`) doldurularak trafik analizi ve paket boyutu takibine karşı koruma sağlanması.
- `src/core/federation.js` içindeki metin biriktirme döngüsü yerine doğrudan ikili akış (`socket.read(2048)`) mimarisine geçilmesi.
- **Çekirdek TCP Tampon Denetimleri (`setRecvBufferSize` / `setSendBufferSize`):** Sabit 2048 baytlık hücrelerin aktarımında işletim sisteminin yüksek TCP soket tamponları tahsis etmesini önlemek amacıyla `socket.setRecvBufferSize(65536)` ve `socket.setSendBufferSize(65536)` (64 KB) sınırlarının getirilmesi; bellek şişmesinin (buffer bloat) engellenmesi.
- **`AbortSignal` ile Bağlantı ve Devre İptali:** 3 atlamalı onion devresi kurarken veya rendezvous tüneli açarken `net.connect({ ..., signal: abortController.signal })` ile zaman aşımına uğrayan soket denemelerinin işletim sistemi soket tablosundan temizlenmesi.

### 3. Kuantum Sonrası Çift Mandallama: İleriye Dönük Gizlilik (PQC Double Ratchet)
- Doğrudan mesajlaşmada her mesaj için yalnızca tekil anahtar üretmek yerine çift mandallama (Double Ratchet) mimarisi:
  - **Simetrik KDF Zinciri (Symmetric KDF Chain):** Her mesaj iletiminde simetrik oturum anahtarı bir HKDF zinciri ile yenilenir (`K_(i+1) = HKDF(K_i)`) ve önceki oturum anahtarı bellekten silinir.
  - **Asimetrik KEM Ratchet (PQC KEM Ratchet):** Her N mesajda bir veya oturum yeniden kurulduğunda taraflar yeni tek kullanımlık ML-KEM-768 açık anahtarları takas ederek anahtar çiftini yeniler.
- **Kullanıcı Mesaj Geçmişi Güvenliği:**
  - Alınan ve çözülen mesajlar kullanıcının yerel şifreli SQLite veritabanında saklanmaya devam eder; kullanıcılar geçmiş mesajlarını okuyabilir.
  - Ağ iletim katmanında eski anahtarlar silindiği için, gelecekte bir anahtar ele geçirilse dahi geçmişte kaydedilen şifreli paketlerin deşifre edilmesi engellenir (Forward Secrecy).

### 4. Dağıtık Zaman Senkronizasyonu ve Çok Katmanlı Düğüm Keşfi (Time Consensus & Multi-Tier Discovery)
- Harici NTP sunucusu gereksinimini ortadan kaldıran eşler arası medyan zaman senkronizasyonu:
  - P2P el sıkışmalarında (`HANDSHAKE_INIT` / `REPLY`) ve keepalive sinyallerinde eşler yerel zaman damgalarını bildirir.
  - Düğüm, bağlı olduğu doğrulanmış eşlerin bildirdiği zaman farklarını bir kayan pencerede toplayarak medyan kaymayı hesaplar:
    `Delta_offset = median({T_peer_i - T_local})`
  - İşletim sistemi saatine dokunulmaz; protokol içi paket doğrulama, devre TTL ve nonce kontrolleri sanal `MeshTime` (`now() = BigInt(Date.now()) + offset`) ve `process.hrtime.bigint()` (monotonik süre) üzerinden yürütülür.
  - Replay attack zaman kayması toleransı sanal `MeshTime` sayesinde sıkı bir güvenlik aralığına çekilir.
- **Çok Katmanlı Otonom Keşif (Multi-Tier Discovery):**
  - **1. Aşama (Yerel Önbellek):** Yerel Eş Önbelleği (`peers_<PORT>.json`) ile dış ağa istek yapmadan son bilinen doğrulanmış eşlerle başlama.
  - **2. Aşama (Yerel Ağ Keşfi):** UDP Broadcast / Multicast LAN keşfi (harici internet erişimi olmadan yerel ağdaki düğümleri bulma).
  - **3. Aşama (Gossip Protokolü):** Bağlı eşlerden mantıksal saat (Lamport Time) ve `PEER_EXCHANGE` protokolü ile dinamik eş listesi edinme.
  - **4. Aşama (Yedek DNS Bootstrap):** DNS TXT kaydı sorgulama (Yalnızca diğer aşamalar sonuç vermezse ve `ALLOW_DNS_BOOTSTRAP=true` ise ikincil yedek olarak kullanılır; birincil zorunluluk değildir).

### 5. NIST FIPS 204 ML-DSA ve NIST FIPS 205 SLH-DSA Hibrit Kuantum Sonrası Kimlik Modeli
- Shor algoritması karşısında klasik Ed25519 eliptik eğri imzalarının kırılma riskine karşı Node 26 `node:crypto` yerel NIST FIPS 204 ve FIPS 205 tam kuantum sonrası imza desteği:
  - **FIPS 204 (ML-DSA-65 / Dilithium):** `crypto.generateKeyPairSync('ml-dsa-65')`, `crypto.sign()` ve `crypto.verify()` ile P2P oturumlarında tam kafes tabanlı (lattice-based) kuantum dirençli dijital imza.
  - **FIPS 205 (SLH-DSA-SHA2-128s / SPHINCS+):** Durumsuz (stateless) hash tabanlı imzalama ile kök admin ve kritik kimlik doğrulamalarında alternatif PQC imza seçeneği.
- **Hibrit NodeID Türetimi ve SHA-256 Görev Ayrımı:**
  - 1.952 baytlık ML-DSA açık anahtarını URL ve adres olarak doğrudan kullanmak yerine, Node 26 `crypto.hash` ile özetlenerek Base32 ile 16 karaktere sıkıştırılması:
    `NodeID = Base32(crypto.hash('sha256', Ed25519_Pub || ML-DSA-65_Pub))[0..16]`
  - SHA-256; adres sıkıştırma, Merkle Tree blok doğrulaması (Faz 6) ve HKDF anahtar türetiminde kullanılırken, ML-DSA kimlik doğrulaması ve imza sahteciliği korumasını üstlenir.
- El sıkışma (`HANDSHAKE_INIT`) ve `RENDEZVOUS_BIND` paketlerinde hibrit çift imza (Dual Signature) doğrulaması. Klasik algoritmaların yetersiz kalması durumunda dahi kimlik taklidi engellenir.

---

## Faz 3: Elastik ve Dinamik İşçi Havuzu (Elastic Dynamic Worker Thread Pool)

### 1. Elastik Ölçeklenen İşçi Havuzu (Auto-Scaling Thread Pool)
- Node.js yerleşik `node:worker_threads` altyapısı üzerinde, salt kripto ile sınırlı olmayan genel amaçlı elastik işçi havuzu mimarisi.
- Dinamik Genişleme ve Küçülme Mantığı:
  - **Taban Kapasite (Min Workers):** Sistem boştayken kaynak tüketmemek adına asgari sayıda (örneğin 1 veya 2) işçi çalışır.
  - **Tepe Kapasite (Max Workers):** İş kuyruğu eşik değerleri aştığında CPU çekirdek sayısına kadar dinamik yeni işçi thread üretilir.
  - **Otomatik Daralma (Auto-Shrink / Idle Eviction):** Belirlenen süre (`idleTimeout`) boyunca iş almayan fazla işçiler bellek tasarrufu için temiz bir şekilde sonlandırılır.
- **`reusePort: true` (`SO_REUSEPORT`) ile Çekirdek Düzeyinde Yük Dağıtımı:** Desteklenen Linux ortamlarında `net.createServer({ reusePort: true })` etkinleştirilerek aynı portu birden fazla bağımsız işçi thread'in doğrudan dinlemesi; gelen TCP bağlantılarının işletim sistemi çekirdeği tarafından doğrudan işçiler arasında paylaştırılması (ana Event Loop üzerinde sıfır proxy yükü).

### 2. İşçi Havuzuna Devredilecek Görev Türleri (Task Types)
- **Kriptografik Hesaplamalar:**
  - NIST FIPS 203 ML-KEM-768 anahtar kapsülleme ve deşifreleme.
  - Çok atlamalı onion şifre çözümü (Multi-Hop Onion Decryption).
  - SSH-2FA Kasası Scrypt (N=16384, r=8, p=1) anahtar türetim hesaplamaları.
- **Veri Dönüşümü ve Güvenlik Doğrulamaları:**
  - Büyük boyutlu ikili çerçevelerin doğrulanması ve parsing işlemleri.
  - Toplu Ed25519 / ML-DSA-65 imza kontrolleri.
- **Arka Plan Analitik ve Rota Hesaplamaları:**
  - Ağ topolojisi, en kısa rota ve devre seçim metriklerinin arka planda hesaplanması.

### 3. Paylaşımlı Bellek Eş Durum Tablosu: `SharedPeerState` (`SharedArrayBuffer` + `Atomics`) ve Sıfır-Kopya Veri Transferi
- **Paylaşımlı Bellek Eş Durum Tablosu (`SharedPeerState`):**
  - Ana Event Loop ile işçi thread'ler arasında her metrik güncellemesinde `postMessage` ile veri kopyalamak ve serileştirmek yerine, tek bir `SharedArrayBuffer` üzerinden kilitlenmesiz (lock-free) doğrudan bellek paylaşımı.
  - Eş başına 32 baytlık sabit bellek yuvası (Slot):
    - `[0..3]`: Eş İtibar Puanı (Int32, `Atomics.add` ile doğrudan güncelleme)
    - `[4..7]`: Token Bucket Hız Sınırı Jetonları (Int32, `Atomics.compareExchange` ile atomik tüketim)
    - `[8..15]`: Son Görülme Zamanı (BigInt64, `Atomics.store` ile epoch ms kaydı)
    - `[16..19]`: Hata Sayacı (Int32, `Atomics.add`)
    - `[20..31]`: Replay Önleme Nonce Değeri (12 Bayt)
  - İşçi thread'ler ana döngüyü bloke etmeden mikrosaniyeler içinde eş puanlarını ve hız sınırlarını denetler.
- **Node 26 `Atomics.pause()` ve `Atomics.waitAsync()` ile Kilitlenmesiz Koordinasyon:**
  - **`Atomics.pause()` ile CPU Döngü Optimizasyonu:** İşçi thread'lerdeki meşgul bekleme (busy-wait) veya halka tampon (ring buffer) çekişme döngülerinde `Atomics.pause()` yürütülerek donanımsal x86 PAUSE / ARM YIELD CPU komutu verilir; meşgul beklemede işlemci hattı (pipeline) çekişmesi ve gereksiz CPU tüketimi engellenir.
  - **`Atomics.waitAsync()` ile Bloklamasız Asenkron Bildirim:** Node.js ana Event Loop'unda bloklayıcı `Atomics.wait()` çağrılamaz. Node 26 `Atomics.waitAsync()` ile ana thread, `SharedArrayBuffer` üzerindeki durum ve kilit değişimlerini bloklamadan asenkron bir `Promise` üzerinden bekler. İşçi thread `Atomics.notify()` tetiklediğinde ana thread sıfır gecikmeyle mikro-görev kuyruğunda uyanır.
- **Sıfır-Kopya (Zero-Copy) Veri Aktarımı:**
  - Kriptografik hesaplamalar ve büyük paketler için Buffer nesnelerini kopyalamak yerine `ArrayBuffer` transferi (ownership transfer) kullanılarak bellek kopyalama maliyetinin önlenmesi.

### 4. Healthcheck & Heartbeat Telemetri Entegrasyonu (Worker Pool Observability)
- Port 8050 TCP Healthcheck protokolüne (`STATUS` / `INFO` komutları) elastik işçi havuzunun anlık metriklerinin dahil edilmesi:
  ```json
  {
    "workers": {
      "active": 2,
      "idle": 1,
      "total": 3,
      "min": 1,
      "max": 8,
      "queuedTasks": 0,
      "completedTasks": 154
    }
  }
  ```
- Bu sayede orkestratörler ve izleme sistemleri işçi havuzunun doygunluk durumunu TCP üzerinden anlık olarak takip edebilir.

---

## Faz 4: İlk Kurulum Kök Admin Hesabı ve Yerel Yönetim Konsolu (Root Admin Console)

### 1. İlk Açılışta 256-Bit Otomatik Kök Parola Üretimi (Bootstrap Root Token)
- Düğüm ilk kez çalıştırıldığında SQLite veritabanındaki `admin_credentials` tablosu kontrol edilir.
- Kayıt yoksa, `crypto.randomBytes(32)` (256-bit) ile yüksek entropili rastgele bir kök admin parolası üretilir.
- Parola asla açık metin saklanmaz; Scrypt / PBKDF2 ve tuzlama (salt) ile özetlenerek veritabanına yazılır.
- Düğüm başlangıç logunda (Bootstrap Banner) yalnızca bir kez konsola yazdırılır:
  ```text
  ========================================================================
  [GÜVENLİK] DÜĞÜM KÖK ADMİN HESABI BAŞARIYLA OLUŞTURULDU
  Kullanıcı : @admin:<NodeID>.mesh
  İlk Parola: <256-bit-token>
  Erişim    : SSH (Port 2224) veya yerel Telnet TUI (Port 2222) üzerinden girilebilir.
  ========================================================================
  ```

### 2. Erişim ve SSH İlk Girişte Güvenli Donanım Anahtarı Bağlama (TOFU Pubkey Binding)
- Kök admin hesabı ilk kez SSH (Port 2224) veya yerel Telnet TUI (Port 2222) üzerinden giriş yapabilir (Telnet zorunluluğu yoktur).
- **İlk SSH Girişi ve TOFU Anahtar Bağlama:**
  - Yönetici terminalden `ssh @admin@<host> -p <port>` ile bağlanıp konsolda üretilen 256-bitlik ilk parolayı girer.
  - SSH sunucusu bu ilk başarılı oturum açmada istemcinin Ed25519 açık anahtarını (pubkey) yakalar ve kök admin hesabına kalıcı olarak bağlar (Hardware Key Binding).
  - Bu andan itibaren kök admin hesabı Metrice 2FA Kasa mimarisiyle korunur; sonraki girişlerde yalnızca doğru parola yetmez, aynı zamanda bu kaydedilmiş Ed25519 açık anahtarının da eşleşmesi zorunlu hale gelir.
- Bu kök admin hesabı P2P federasyon ağı (Port 8001) üzerinden kesinlikle giriş kabul etmez.

### 3. Yetki Alanı ve Yerel Moderasyon Sınırı (Strict Local Scope)
- Admin yetkisi kesinlikle yalnızca yerel düğüm (local instance) ile sınırlıdır.
- Başka düğümlerin iç işleyişine, yönetim kararlarına veya federasyon politikalarına müdahale edemez.
- Sadece bu düğümün yerel kaynaklarını (yerel soketler, tüneller, devreler, kara liste ve SQLite veritabanı) denetler ve modere eder.

### 4. Mesajlaşma Kısıtı: Yalnızca Diğer Adminlerle İletişim (Admin-To-Admin Only)
- Kök admin hesabı genel kullanıcı sohbetlerine katılamaz; küresel veya federe kanallara (`#genel`, `#general` vb.) mesaj gönderemez.
- Standart son kullanıcılara doğrudan bireysel mesaj atamaz; yetki suistimali ve kimlik taklidi önlenir.
- **Yalnızca** diğer düğümlerin doğrulanmış admin hesaplarına (`@admin:<PeerNodeID>.mesh`) uçtan uca şifreli doğrudan mesaj (E2EE) iletebilir veya alabilir.
- **Düğüm İçi İstisna (Yerel Duyuru):** Kök admin, yalnızca kendi yerel düğümünün `#duyuru` kanalına sistem/bakım duyurusu gönderme yetkisine sahiptir; bu duyurular yalnızca o düğümün yerel kullanıcılarına iletilir.
- Böylece düğüm yöneticileri güvenlik uyarıları, eş bakım bildirimleri ve operasyonel koordinasyon için düğümler arası yönetim ve bildirim kanalı kurar.

### 5. Özel Düğüm Admin, Moderasyon ve Sistem Komut Seti
Yalnızca yetkili admin oturumunda çalışabilen `/admin` komut kümesi:
- `/admin status` : Donanım, bellek, aktif tüneller, kuyruklar ve sistem durumu.
- `/admin peers` : Eş havuzunun anlık puantajı, gecikmeleri ve hata dökümü.
- `/admin ban <IP|NodeID> [süre]` : Kural ihlali yapan eşi/IP'yi kara listeye alma.
- `/admin unban <IP|NodeID>` : Eş veya IP üzerindeki engeli kaldırma.
- `/admin tunnels` : Aktif Rendezvous tünellerinin fiziksel soket detayları.
- `/admin killtunnel <NodeID>` : Belirli bir ters tüneli anında sonlandırma.
- `/admin circuits` : Aktif Onion devrelerinin dökümü ve sonlandırılması.
- `/admin prune` : Süresi dolmuş varlık ve outbox kayıtlarını temizleme.
- `/admin pass <yeni_parola>` : Kök admin parolasını yerel olarak güncelleme.

---

## Faz 5: Başsız İstemci ve Yerel IPC Köprüsü (Headless Edge Daemon & Client IPC)
*(Çekirdek Düğüm Motoru ve Arayüz Katmanı Ayrımı - Core Daemon & UI Decoupling)*

### 1. Yeni Düğüm Rolü (`EDGE_CLIENT`) ve Dinamik Transit Yükseltmesi (`EDGE_CLIENT_TRANSIT`)
- **`MESH_ROLE='EDGE_CLIENT'` (Temel / Varsayılan Mod):**
  - Düğüm, TUI / Telnet / ANSI render katmanını tamamen kapatır (Sıfır render / VT100 yükü).
  - Terminal oturumu başlatmaz; bunun yerine yerel bir IPC soketi (Unix Domain Socket / Windows Named Pipe veya `127.0.0.1` üzerinde yerel TCP IPC portu) açar.
  - Düğümün kendisi **aynı anda hem tam yetkili bir P2P `.mesh` ağ düğümüdür** (Ed25519 kimliği, ML-KEM-768 anahtarı, Rendezvous ters tünelleri, SQLite kalıcılığı) **hem de başka bir aracıya ihtiyacı olmayan tekil bir "Kullanıcı" (`@user:NodeID.mesh`) kimliğidir**.
- **Dinamik Rol Yükseltmesi -> `EDGE_CLIENT_TRANSIT`:**
  - Tıpkı standart `EDGE` düğümlerinde olduğu gibi; eğer düğümde `ALLOW_EDGE_ROUTING=true` ve `ALLOW_EDGE_GOSSIP=true` açılır ve düğüm en az 2 bağımsız röleye bağlanırsa, rol otomatik ve dinamik olarak `EDGE_CLIENT_TRANSIT` seviyesine yükselir.
  - Bu modda düğüm hem kullanıcının masaüstü/mobil arayüzüne yerel IPC üzerinden veri akışı sağlarken hem de diğer uçlar arasında ters tüneller üzerinden paket köprüleyip ağda transit görevi görür.

### 2. Yerel IPC / İstemci Veri Akışı Protokolü (Native UI Data Stream)
ANSI ve VT100 ekran çizim kodları yerine; Masaüstü (Tauri, Electron, Qt) veya Mobil (Flutter, React Native, Swift, Kotlin) uygulamalara JSON-RPC / NDJSON üzerinden saf veri ve olay akışı sağlar:
- **Düğümden Arayüze Olay Bildirimleri (Push Events):**
  - `message_received`: Uçtan uca şifresi çözülmüş temiz mesaj nesnesi.
  - `presence_update`: Rehberdeki kişilerin ve kanalların çevrimiçi durumu.
  - `tunnel_state`: Rendezvous tünel bağlantı ve kopma bildirimleri.
  - `circuit_built`: Yeni kurulan 3-hop Onion devre durum bilgisi.
- **Arayüzden Düğüme Yönetim Komutları (Requests):**
  - `send_message`: Hedef `@kullanıcı` veya `#kanal`'a mesaj gönderme.
  - `join_channel` / `leave_channel`: Kanal abonelik yönetimi.
  - `get_history`: Yerel SQLite veritabanından filtrelenmiş mesaj geçmişi sorgulama.
  - `get_identity`: Düğümün `.mesh` kimlik kartını ve açık anahtarlarını alma.
- **`node:stream` ile Birleştirilebilir Akış Boru Hattı (`stream.compose` / `Duplex.from`):**
  - Yerel IPC soketinden gelen ikili veya metin akışının `stream.compose(socket, framingTransform, ndjsonParser)` yapısıyla modüler bir boru hattında birleştirilmesi.
  - Dahili akış kontrolü (backpressure) ve asenkron yineleme (`for await (const event of stream)`) ile sıfır bellek sızıntılı olay işleme.

### 3. Sanal İntranet (`.mesh`) Veri Akışı ve Güvenlik İzolasyonu
- Mobil veya Masaüstü GUI uygulaması, ağdaki karmaşık P2P topolojisi, kuantum sonrası el sıkışmalar veya CGNAT tünellemesi ile uğraşmaz; yerel soketten arka planda çalışan Metrice Core daemon'a bağlanır.
- IPC erişimi yerel işlem izinleri ve isteğe bağlı yerel oturum jetonu (`IPC Auth Token`) ile korunarak yalnızca yetkili ön yüz uygulamasının düğüm motorunu kontrol etmesi sağlanır.

### 4. İstemci Tipleme Desteği (Comprehensive TypeScript Client Typing)
- `src/types/client.d.ts` altında eksiksiz istemci ve IPC tip tanımları:
  - Olay Tipleri: `ClientMessageReceivedEvent`, `ClientPresenceUpdateEvent`, `ClientTunnelStateEvent`, `ClientCircuitStateEvent`.
  - İstek/Yanıt Sözleşmeleri: `SendMessagePayload`, `SendMessageResult`, `GetHistoryPayload`, `ChannelSubscriptionPayload`, `NodeIdentityInfo`.
  - Tüm tiplerin `src/types/index.d.ts` üzerinden TypeScript IDE'lerine otomatik tamamlama (IntelliSense) sağlayacak şekilde dışa aktarılması.

### 5. Doğrudan Çalışma Zamanı Kütüphane Desteği (Embedded Runtime Library / SDK)
Ayrık bir daemon süreci çalıştırmak yerine Metrice'i doğrudan kendi Node.js, Electron veya backend uygulamasına gömmek (`embedded in-process`) isteyenler için:
```javascript
import { MetriceNode, MetriceClient } from 'metrice';

// 1. Gömülü Çalıştırma Modu (In-Process Runtime):
const node = new MetriceNode({ role: 'EDGE_CLIENT', dbFile: './app.db' });
await node.start();
node.on('message', (msg) => console.log('Gelen:', msg));
await node.sendMessage('@bob:xyz.mesh', 'Merhaba!');

// 2. Ayrı Sürece Bağlanma Modu (Out-of-Process IPC Client):
const client = new MetriceClient({ socketPath: '/tmp/metrice.sock' });
await client.connect();
client.on('message', (msg) => console.log('Gelen:', msg));
```
- **`node:sqlite` In-Memory Anlık Görüntü (`db.serialize()` / `db.deserialize()`):** Gömülü istemci modunda disk I/O yükünü sıfırlamak için `:memory:` veritabanı kullanımı; oturum sonlanırken veya arka plana geçerken `db.serialize()` ile bellek görüntüsünün tek bir Buffer nesnesi olarak kaydedilmesi ve `db.deserialize()` ile kilitlenme olmaksızın geri yüklenmesi.
- Sıfır dış bağımlılıkla geliştiricilerin kendi özel masaüstü, mobil veya CLI uygulamalarını tek satır kodla P2P-Mesh ve kuantum sonrası ağımıza bağlayabilmesi.

---

## Faz 6: P2P Dosya Transferi, Uçtan Uca Şifreli Sesli İletişim, Yerel Duyuru ve Sohbet Kanalları

### 1. Uçtan Uca Şifreli Gerçek Zamanlı Sesli İletişim (E2EE Voice Chat & Low-Latency Audio Streaming)
Masaüstü/mobil IPC istemcisi veya terminal üzerinden çalışan yüksek verimli P2P ses mimarisi:
- **Düşük Gecikmeli İkili Çerçeveleme (VOICE_FRAME):**
  - Ses paketlerinin (Opus / ham PCM ses çerçeveleri) Faz 2'deki Öncelik Kuyruğunda Kademe 1 (CRITICAL - Sıfır Gecikme) ile işlenmesi.
  - Ağ gecikme dalgalanmalarını (jitter) telafi etmek ve paket kayıplarında ses kesintilerini önlemek için sıfır bağımlılıklı hafif bir Jitter Buffer ve Paket Kaybı Gizleme (Packet Loss Concealment - PLC) mantığı.
- **Bire Bir Doğrudan Aramalar ve Çoklu Ses Odaları (1-to-1 Calls & Multipoint Mesh Conference):**
  - Bire bir aramalarda iki düğüm arasında doğrudan UDP/TCP veya Rendezvous ters tünelleri üzerinden noktadan noktaya (P2P) düşük gecikmeli ses iletimi.
  - Grup ses kanallarında (Multipoint Mesh Rooms) her katılımcının sesinin röleler üzerinden diğer dinleyicilere dağıtıldığı, dağıtık seçici iletim (Selective Forwarding) mimarisi.
- **Kuantum Sonrası Oturum Anahtarı Yenileme (PQC Voice Ratchet):**
  - Her sesli çağrı başlangıcında ML-KEM-768 ile yeni ve bağımsız bir simetrik oturum anahtarı türetilmesi.
  - Konuşma esnasında periyodik anahtar yenileme (Rekeying) ile ileri ve geriye dönük gizlilik (Forward Secrecy).

### 2. Kesintisiz ve Parçalı P2P Dosya Gönderimi (Chunked Resumable File Transfer)
Büyük dosyaların (belge, arşiv, ses kaydı, medya vb.) eşler arasında güvenle iletilmesi:
- **Parçalı Blok Ayrıştırma ve Merkle Ağacı Doğrulaması (Merkle Tree):**
  - Dosyaların sabit boyutlu bloklara (64 KB - 512 KB) bölünerek işlenmesi.
  - Tüm blokların SHA-256 / BLAKE özetlerinden oluşan bir Merkle Ağacı kök özeti (Root Hash) ile dosya bütünlüğünün doğrulanması.
  - Alıcının bozuk veya eksik gelen tek bir bloğu tespit edip yalnızca o bloğu yeniden talep edebilmesi.
- **Uçtan Uca Şifreli Blok Aktarımı (E2EE File Chunks):**
  - Her dosya parçasının alıcının kuantum sonrası oturum anahtarıyla şifrelenmesi.
  - Dosya üstverisinin (isim, boyut, MIME türü) yalnızca hedef alıcı tarafından deşifre edilebilmesi; ara rölelerin taşınan içeriği kesinlikle görememesi.
- **Kaldığı Yerden Devam Etme (Resumable Transfer) ve Akış Kontrolü:**
  - Ağ kopması, tünel değişimi veya istemcinin kapanıp açılması durumunda son doğrulanmış bloktan itibaren transferin otomatik devam etmesi.
  - Node.js akış (`node:stream`) altyapısı ve Backpressure mekanizmasıyla alıcının disk yazma hızına göre veri hızının dinamik dengelenmesi; bellek taşmalarının (OOM) önlenmesi.
  - **Soket Tampon Optimizasyonu (`setSendBufferSize` / `setRecvBufferSize`):** Büyük blok aktarımında soket tamponlarının 256 KB olarak ayarlanması ile çekirdek düzeyinde yüksek verimli G/Ç aktarımı.

### 3. Düğüme Özel Salt-Okunur Duyuru Kanalı ve Yerel Topluluk Sohbeti (Node-Local Announce & Local Chat)
Düğüm içi iletişim, yönetim duyuruları ve yerel kullanıcı topluluğu için dış ağa ve federasyona kapalı, yerel düzeyde izole kanal katmanı:
- **Düğüme Özel Salt-Okunur Duyuru Kanalı (`#duyuru`):**
  - **Sıkı Yerel İzolasyon (Strict Node-Local Scope):** Duyurular küresel federasyon ağına veya diğer düğümlere iletilmez; yalnızca bu düğüme bağlı ve kayıtlı yerel kullanıcılar görebilir.
  - **Yalnızca Kök Admin Mesaj Atabilir:** Kanala yalnızca bu düğümün yerel kök admini (`@admin:<NodeID>.mesh`) mesaj yazabilir. Standart kullanıcılar için kanal tamamen salt-okunurdur (read-only); yetkisiz mesaj denemeleri soket düzeyinde reddedilir.
  - Sistem bakım takvimleri, kural güncellemeleri, acil durum uyarıları ve yerel sunucu durum raporları için tek yönlü bilgilendirme akışıdır.
- **Düğüm İçi Yerel Sohbet Kanalı (`#yerel` / `#local`):**
  - **Sadece Yerel Kullanıcılar Arasında:** Yalnızca o düğümde hesabı veya aktif oturumu bulunan kullanıcıların kendi aralarında mesajlaşabileceği hafif yerel topluluk sohbeti.
  - **Dış Federasyon İzolasyonu:** Bu kanaldaki mesajlar P2P ağına veya uzak rölelere iletilmez; tüm trafik sunucunun yerel sınırları içinde kalır (zero federation overhead).
  - Kullanıcıların genel ağ trafiği yaratmadan, gecikmesiz ve güvenli bir şekilde doğrudan sunucu arkadaşlarıyla sohbet edebilmesini sağlar.

---

## Faz 7 (Ekstrem Vizyon Fazı): Özel Mesh IMS / VoWiFi Telekomünikasyon Şebekesi

### 1. Özel SIM / eSIM ve Yerel VoWiFi IMS Çekirdeği (Custom Mesh IMS & Native VoWiFi Dialer Integration)
Telekom operatörlerinden ve merkezi baz istasyonlarından bağımsız, akıllı telefonların yerleşik arama ekranını (native phone dialer) Metrice ağına bağlayan uçtan uca telekomünikasyon köprüsü:
- **Özel SIM / eSIM Profili Desteği:**
  - GSMA standartlarına uyumlu özel eSIM LPA profili veya programlanabilir fiziksel USIM/ISIM kartları (ör. Sysmocom / Osmocom standartları).
  - SIM kartında saklanan kriptografik kimlik, abonenin Metrice `.mesh` adresine (`@kullanıcı:NodeID.mesh`) ve Ed25519 açık anahtarıyla eşleştirilir.
- **Hafif P2P IMS / VoWiFi Ağ Geçidi (P-CSCF & I-CSCF over Mesh):**
  - Telefon Wi-Fi ağına bağlandığında (veya yerel SDR baz istasyonu üzerinden), işletim sisteminin yerleşik VoWiFi (Voice over Wi-Fi) / ePDG yığınını tetiklemesi.
  - Metrice düğümünün yerel ağda bir SIP/IMS kayıtçısı (Registrar & Call Session Control Function) olarak hizmet vermesi.
  - USIM AKA / Milenage kimlik doğrulamasının yerel SQLite ve P2P ağ anahtarları üzerinden gerçekleştirilmesi.
- **Dinamik Numara Tercüme Motoru (ENUM / Number-to-Mesh Translation):**
  - Kullanıcının telefon rehberinden veya tuş takımından çevirdiği standart bir telefon numarasını (örn. `+90 555...` veya özel dahili `7001`) Metrice dizininde doğrudan hedef `.mesh` adresine (`@hedef:RemoteNodeID.mesh`) çözümleme.
  - Ters yönde, dış dünyadan veya diğer ağ üyelerinden gelen `.mesh` çağrılarının kullanıcının telefonunun yerleşik arama arayüzünü tetiklemesi (Native Inbound Call).
  - Kullanıcı arayüzünde ek bir mesajlaşma uygulamasına ihtiyaç kalmadan, doğrudan telefonun ahizesinden konuşarak kuantum sonrası şifreli P2P mesh ses tünelini kullanabilme imkanı.

---

## Kabul ve Uyumluluk Kriterleri
- Sıfır dış npm bağımlılığı kuralı ihlal edilemez (Yalnızca yerleşik çekirdek kütüphaneler: `node:worker_threads`, `node:crypto`, `node:net`, `node:sqlite`, `node:os`, `node:stream`, `node:buffer`).
- Geriye dönük protokol uyumluluğu korunmalıdır (Mevcut v2.6.0 ağı ile kesintisiz çalışma).
- Tüm fazlar kapsamlı birim ve entegrasyon testleri ile doğrulanmalıdır.
