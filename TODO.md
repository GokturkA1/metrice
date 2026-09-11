# Metrice Mimari Geliştirme ve Ağır Sıklet Dayanıklılık Yol Haritası (Roadmap)

## Genel Hedef
Sıfır dış bağımlılık (Zero-Dependency) ve kuantum sonrası kriptografi (PQC) ilkelerini tavizsiz koruyarak, Metrice düğümlerini yüksek ağ trafiğine, kaynak kısıtlarına ve saldırılara karşı ağır sıklet, esnek ve yüksek dayanıklılık seviyesine çıkarmak.

---

## Faz 1: Donanım Tabanlı Dinamik Kapasite ve Davranışsal Hız Sınırlayıcı (Rate Limiter)

### 1. Dinamik Tünel ve Kaynak Kapasitesi (Adaptive Resource Capacity)
- Sabit `MAX_RENDEZVOUS_TUNNELS = 64` tavanı yerine sunucu donanımına duyarlı otomatik kota:
  - CPU çekirdek sayısı (`os.cpus().length`) ve toplam bellek (`os.totalmem()`) parametrelerine göre hesaplama.
  - Düşük kaynaklı sunucularda (örneğin 512 MB - 1 GB VPS) tavanın otomatik 16-32 seviyesine çekilerek OOM (Out-of-Memory) riskinin önlenmesi.
  - Güçlü sunucularda (4-16 çekirdek, 8+ GB RAM) 128-256 tünele kadar güvenli ölçeklenme.
  - Ortam değişkeni (`MAX_RENDEZVOUS_TUNNELS`) ile manuel tavan zorlama seçeneğinin korunması.

### 2. Davranışsal İtibar ve Jeton Kovası Hız Sınırlayıcı (Token-Bucket Rate Limiter)
- IP ve NodeID başına hafif, bellek içi jeton kovası (Token Bucket / Leaky Bucket) motoru.
- Anormal trafik profillerinin tespiti:
  - Aşırı hızlı diyal-geri (`DIALBACK_REQUEST`) talepleri,
  - Hatalı (malformed) veya geçersiz ikili çerçeve tekrarları,
  - Hızlı soket açma-kapama (`reconnect spam`) döngüleri.
- Kademeli Yaptırım Mekanizması:
  - Seviye 1: Soket düzeyinde yapay gecikme (Throttling).
  - Seviye 2: Geçici karantina (Temporary IP/Peer Jail).
  - Seviye 3: `PeerManager` güven puanının (`score`) düşürülmesi ve havuzdan tahliye (`Eviction`).

### 3. Akıllı Tünel Yönlendirmesi ve Tahliyesi (REDIRECT Eviction & Self-Balancing)
- Bir `RELAY` düğümünün tünel kapasitesi dolduğunda (`rendezvousTunnels.size >= maxTunnels`), gelen bağlantı talebini basitçe reddedip istemciyi kapıda bırakmak yerine:
  - Yönlendirme tablosundan kapasitesi müsait ve gecikmesi düşük 2-3 alternatif sağlıklı Relay düğümünü seçme.
  - İstemciye bu adresleri içeren bir `RENDEZVOUS_REDIRECT` paketi iletme.
  - `EDGE` istemcisinin körlemesine denemek yerine anında bu önerilen röleye bağlanarak ağ yükünü otonom şekilde dengelemesi (Self-Balancing Mesh).

### 4. Periyodik Öz-Onarım ve Durum Değişmezleri Denetleyicisi (Self-Healing Watchdog)
- Her 60 saniyede bir sessizce çalışan hafif iç durum sağlık kontrolü:
  - Karşı tarafı kopmuş ancak soket düzeyinde asılı kalmış yetim tünellerin tasfiyesi.
  - Süresi dolmuş geçici Onion devre anahtarlarının ve nonce havuzunun temizliği.
  - SQLite WAL dosya boyutunun izlenip gerektiğinde pasif `wal_checkpoint` çekilmesi.
  - Düğümün bellek ve kaynak sızıntılarına karşı sıfır kesintiyle (zero-downtime) aylarca kararlı çalışmasının garanti edilmesi.

---

## Faz 2: Öncelik Tabanlı Görev ve Paket Çizelgeleyici (Priority Packet Scheduler)

### 1. Çok Kademeli Öncelik Kuyruğu (PriorityQueue)
Tüm paket ve görevlerin tek bir serbest döngüde yarışını engelleyen 4 katmanlı öncelik modeli:
- **Kademe 1 (CRITICAL - Sıfır Gecikme):**
  - Onion Yönlendirme Hücreleri (`ONION_CELL`).
  - Rendezvous ters tünel veri aktarım paketleri (In-and-Out bridging).
  - Bu paketler beklemeden sokete sürülür.
- **Kademe 2 (HIGH - Etkileşimli Öncelik):**
  - Post-Quantum ML-KEM-768 El Sıkışmaları (`HANDSHAKE_INIT` / `REPLY`).
  - SSH-2 Terminal TUI tuş vuruşları ve kontrol sinyalleri.
- **Kademe 3 (NORMAL - Standart Veri):**
  - Uçtan uca şifreli doğrudan mesajlar (`DIRECT_MESSAGE`).
  - Federe ve küresel kanal sohbet paketleri.
- **Kademe 4 (LOW - Arka Plan İşleri):**
  - Varlık (`Presence`) anonsları ve dedikodu (`gossip`) yayılımı.
  - Outbox yeniden deneme döngüleri.
  - SQLite WAL temizliği, indeksleme ve süresi dolmuş devre tasfiyesi.

### 2. Event Loop Nefes Alma Koruması
- Yüksek hacimli varlık anonsları veya veritabanı yazımları altında bile ana Event Loop'un bloke olması önlenir; SSH ve Onion akışlarının gecikmesi (jitter) sıfıra yakın tutulur.

### 3. Kuantum Sonrası Taşıma Mandallaması (Post-Quantum Ratchet & Forward Secrecy)
- Ağ üzerinden iletilen her E2EE doğrudan mesaj için HKDF tabanlı oturum anahtarı mandallama (KDF-chain key ratcheting).
- **Kullanıcı Mesaj Geçmişi Güvenliği:**
  - Alınan ve çözülen mesajlar kullanıcının yerel şifreli SQLite veritabanında kendi profil kasa anahtarıyla kalıcı saklanmaya devam eder; kullanıcılar geçmiş mesajlarını her an eksiksiz okuyabilir.
  - Ağ taşıma katmanında ise her mesajdan sonra eski oturum anahtarı bellekten tamamen silinir; gelecekte bir anahtar ele geçirilse dahi geçmişte ağdan kaydedilmiş şifreli paketler asla deşifre edilemez (Perfect Forward Secrecy).

### 4. DNS ve NTP Bağımsız Çok Katmanlı Otonom Keşif (Autonomous Discovery)
- DNS ve NTP sunucularının merkezi veya sansürlenebilir doğasını zorunlu bağımlılık olmaktan çıkaran çok katmanlı otonom keşif:
  - **1. Katman (Disksel Hafıza):** Yerel Eş Önbelleği (`peers_<PORT>.json`) ile hiçbir dış istek yapmadan son bilinen doğrulanmış eşlerle anında başlama.
  - **2. Katman (Yerel Ağ):** UDP Broadcast / Multicast LAN keşfi (İnternet kesintisinde dahi yerel düğümleri anında bulma).
  - **3. Katman (Ağ İçi Dedikodu):** Bağlı eşlerden mantıksal saat (Lamport Time) ve `PEER_EXCHANGE` protokolü ile dinamik eş listesi edinme.
  - **4. Katman (Opsiyonel / Geri Çekilme):** DNS TXT kaydı sorgulama (Yalnızca diğer katmanlar sonuç vermezse ve `ALLOW_DNS_BOOTSTRAP=true` ise ikincil yedek olarak kullanılır; asla birincil zorunluluk değildir).

---

## Faz 3: Elastik ve Dinamik İşçi Havuzu (Elastic Dynamic Worker Thread Pool)

### 1. Elastik Ölçeklenen İşçi Havuzu (Auto-Scaling Thread Pool)
- Node.js yerleşik `node:worker_threads` altyapısı üzerinde, salt kripto ile sınırlı olmayan genel amaçlı elastik işçi havuzu mimarisi.
- Dinamik Genişleme ve Küçülme Mantığı:
  - **Taban Kapasite (Min Workers):** Sistem boştayken kaynak tüketmemek adına asgari sayıda (örneğin 1 veya 2) işçi çalışır.
  - **Tepe Kapasite (Max Workers):** İş kuyruğu eşik değerleri aştığında CPU çekirdek sayısına kadar dinamik yeni işçi thread üretilir.
  - **Otomatik Daralma (Auto-Shrink / Idle Eviction):** Belirlenen süre (`idleTimeout`) boyunca iş almayan fazla işçiler bellek tasarrufu için temiz bir şekilde sonlandırılır.

### 2. İşçi Havuzuna Devredilecek Görev Türleri (Task Types)
- **Kriptografik Hesaplamalar:**
  - NIST FIPS 203 ML-KEM-768 anahtar kapsülleme ve deşifreleme.
  - Çok atlamalı soğan katmanlarının soyulması (Layered Onion Peeling).
  - SSH-2FA Kasası Scrypt (N=16384, r=8, p=1) ağır anahtar türetimi.
- **Veri Dönüşümü ve Güvenlik Doğrulamaları:**
  - Büyük boyutlu ikili çerçevelerin doğrulanması ve parsing işlemleri.
  - Toplu Ed25519 imza kontrolleri.
- **Arka Plan Analitik ve Rota Hesaplamaları:**
  - Ağ topolojisi, en kısa rota ve devre seçim metriklerinin arka planda hesaplanması.

### 3. Sıfır-Kopya (Zero-Copy) Veri Paylaşımı
- İşçiler ile ana thread arasında devasa Buffer nesnelerini JSON/String serialize etmek yerine `ArrayBuffer` transferi (ownership transfer) veya `SharedArrayBuffer` kullanılarak kopyalama ve bellek tahsis (allocation) maliyetinin sıfıra indirilmesi.

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
- Parola asla açık metin saklanmaz; güçlü tuzlama ile Scrypt / PBKDF2 üzerinden hashlenerek veritabanına yazılır.
- Düğüm başlangıç logunda (Bootstrap Banner) dikkat çekici bir güvenlik çerçevesi içerisinde **yalnızca bir kez** konsola basılır:
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
  - SSH sunucusu bu ilk başarılı oturum açmada istemcinin Ed25519 açık anahtarını (pubkey) yakalar ve kök admin hesabına kalıcı olarak mühürler (Hardware Key Binding).
  - Bu andan itibaren kök admin hesabı Metrice'in 2FA Kasa (Vault) mimarisiyle korunur; sonraki girişlerde yalnızca doğru parola yetmez, aynı zamanda bu kaydedilmiş Ed25519 açık anahtarının da eşleşmesi zorunlu hale gelir.
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
- Böylece düğüm yöneticileri güvenlik uyarıları, eş bakım bildirimleri ve operasyonel koordinasyon için düğümler arası özel bir yönetim hattı (Operational Backchannel) kurar.

### 5. Özel Düğüm Admin, Moderasyon ve Sistem Komut Seti
Yalnızca yetkili admin oturumunda çalışabilen `/admin` komut kümesi:
- `/admin status` : Donanım, bellek, aktif tüneller, kuyruklar ve sistem durumu.
- `/admin peers` : Eş havuzunun anlık puantajı, gecikmeleri ve hata dökümü.
- `/admin ban <IP|NodeID> [süre]` : Kural ihlali yapan eşi/IP'yi kara listeye alma.
- `/admin unban <IP|NodeID>` : Eş veya IP üzerindeki engeli kaldırma.
- `/admin tunnels` : Aktif Rendezvous tünellerinin fiziksel soket detayları.
- `/admin killtunnel <NodeID>` : Belirli bir ters tüneli anında sonlandırma.
- `/admin circuits` : Aktif Onion devrelerinin dökümü ve sonlandırılması.
- `/admin prune` : Süresi dolmuş varlık ve outbox çöplerini derhal tasfiye etme.
- `/admin pass <yeni_parola>` : Kök admin parolasını yerel olarak güncelleme.

---

## Faz 5: Başsız İstemci ve Yerel IPC Köprüsü (Headless Edge Daemon & Client IPC)
*(Tor.exe ile Tor Browser İlişkisi Gibi: Çekirdek Düğüm Motoru + Arayüz Ayrımı)*

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
- Sıfır dış bağımlılıkla geliştiricilerin kendi özel masaüstü, mobil veya CLI uygulamalarını tek satır kodla P2P-Mesh ve kuantum sonrası ağımıza bağlayabilmesi.

---

## Faz 6 (Ekstrem Vizyon Fazı): Özel Mesh IMS / VoWiFi Şebekesi, P2P Dosya Transferi, E2EE Sesli Görüşme, Yerel Duyuru ve Sohbet Kanalları

### 1. Özel SIM / eSIM ve Yerel VoWiFi IMS Çekirdeği (Custom Mesh IMS & Native VoWiFi Dialer Integration)
Telekom operatörlerinden ve merkezi baz istasyonlarından tamamen bağımsız, akıllı telefonların yerleşik arama ekranını (native phone dialer) Metrice ağına bağlayan uçtan uca telekomünikasyon köprüsü:
- **Özel SIM / eSIM Profili Desteği:**
  - GSMA standartlarına uyumlu özel eSIM LPA profili veya programlanabilir fiziksel USIM/ISIM kartları (ör. Sysmocom / Osmocom standartları).
  - SIM kartında saklanan kriptografik kimlik, abonenin Metrice `.mesh` adresine (`@kullanıcı:NodeID.mesh`) ve Ed25519 donanım kimliğine mühürlenir.
- **Hafif P2P IMS / VoWiFi Ağ Geçidi (P-CSCF & I-CSCF over Mesh):**
  - Telefon Wi-Fi ağına bağlandığında (veya yerel SDR baz istasyonu üzerinden), işletim sisteminin yerleşik VoWiFi (Voice over Wi-Fi) / ePDG yığınını tetiklemesi.
  - Metrice düğümünün yerel ağda bir SIP/IMS kayıtçısı (Registrar & Call Session Control Function) olarak hizmet vermesi.
  - USIM AKA / Milenage kimlik doğrulamasının yerel SQLite ve P2P ağ anahtarları üzerinden gerçekleştirilmesi.
- **Dinamik Numara Tercüme Motoru (ENUM / Number-to-Mesh Translation):**
  - Kullanıcının telefon rehberinden veya tuş takımından çevirdiği standart bir telefon numarasını (örn. `+90 555...` veya özel dahili `7001`) Metrice dizininde anında hedef `.mesh` adresine (`@hedef:RemoteNodeID.mesh`) çözümleme.
  - Ters yönde, dış dünyadan veya diğer ağ üyelerinden gelen `.mesh` çağrılarının kullanıcının cebindeki telefonun yerleşik zilini çaldırması (Native Inbound Call).
  - Kullanıcı arayüzünde ek bir mesajlaşma uygulamasına ihtiyaç kalmadan, doğrudan telefonun ahizesinden konuşarak kuantum sonrası şifreli P2P mesh ses tüneline dahil olma deneyimi.

### 2. Uçtan Uca Şifreli Gerçek Zamanlı Sesli İletişim (E2EE Voice Chat & Low-Latency Audio Streaming)
İster IMS/VoWiFi ister masaüstü/mobil IPC istemcisi üzerinden çalışan yüksek verimli P2P ses mimarisi:
- **Düşük Gecikmeli İkili Çerçeveleme (VOICE_FRAME):**
  - Ses paketlerinin (Opus / ham PCM ses çerçeveleri) Faz 2'deki Öncelik Kuyruğunda Kademe 1 (CRITICAL - Sıfır Gecikme) ile işlenmesi.
  - Ağ titreşimlerini (jitter) yok etmek ve paket kaybında sesin kesilmesini önlemek için sıfır bağımlılıklı hafif bir Jitter Buffer ve Paket Kaybı Gizleme (Packet Loss Concealment - PLC) mantığı.
- **Bire Bir Doğrudan Aramalar ve Çoklu Ses Odaları (1-to-1 Calls & Multipoint Mesh Conference):**
  - Bire bir aramalarda iki düğüm arasında doğrudan UDP/TCP veya Rendezvous ters tünelleri üzerinden noktadan noktaya (P2P) düşük gecikmeli ses iletimi.
  - Grup ses kanallarında (Multipoint Mesh Rooms) her katılımcının sesinin röleler üzerinden diğer dinleyicilere dağıtıldığı, sunucusuz miksajsız (Mix-minus routing / Selective Forwarding) dağıtık ses ağı.
- **Kuantum Sonrası Taze Oturum Anahtarları (PQC Voice Ratchet):**
  - Her sesli çağrı başlangıcında ML-KEM-768 ile yeni ve bağımsız bir simetrik oturum anahtarı türetilmesi.
  - Konuşma esnasında periyodik anahtar yenileme (Rekeying) ile geriye dönük mutlak gizlilik (PFS).

### 3. Kesintisiz ve Parçalı P2P Dosya Gönderimi (Chunked Resumable File Transfer)
Büyük dosyaların (belge, arşiv, ses kaydı, medya vb.) doğrudan eşler arasında güvenle taşınması:
- **Akışkan Parçalama ve Merkle Tree Doğrulaması:**
  - Dosyaların sabit boyutlu bloklara (64 KB - 512 KB) bölünerek işlenmesi.
  - Tüm blokların SHA-256 / BLAKE özetlerinden oluşan bir Merkle Tree kök hash'i (Root Hash) ile dosya bütünlüğünün garanti altına alınması.
  - Alıcının bozuk veya eksik gelen tek bir bloğu tespit edip yalnızca o bloğu yeniden talep edebilmesi.
- **Uçtan Uca Şifreli Blok Aktarımı (E2EE File Chunks):**
  - Her dosya parçasının alıcının kuantum sonrası oturum anahtarıyla şifrelenmesi.
  - Dosya üstverisinin (isim, boyut, MIME türü) yalnızca hedef alıcı tarafından deşifre edilebilmesi; ara rölelerin taşınan içeriği kesinlikle görememesi.
- **Kaldığı Yerden Devam Etme (Resumable Transfer) ve Akış Kontrolü:**
  - Ağ kopması, tünel değişimi veya istemcinin kapanıp açılması durumunda son doğrulanmış bloktan itibaren transferin otomatik devam etmesi.
  - Node.js akış (Streams) altyapısı ve Backpressure mekanizmasıyla alıcının disk yazma hızına göre veri hızının dinamik dengelenmesi; bellek taşmalarının (OOM) tamamen önlenmesi.

### 4. Düğüme Özel Salt-Okunur Duyuru Kanalı ve Yerel Topluluk Sohbeti (Node-Local Announce & Local Chat)
Düğüm içi iletişim, yönetim duyuruları ve yerel kullanıcı topluluğu için dış ağa ve federasyona tamamen kapalı, yerel düzeyde izole kanal katmanı:
- **Düğüme Özel Salt-Okunur Duyuru Kanalı (`#duyuru`):**
  - **Sıkı Yerel İzolasyon (Strict Node-Local Scope):** Duyurular asla küresel federasyon ağına, dedikodu (gossip) protokolüne veya diğer düğümlere sızdırılmaz; yalnızca bu düğüme bağlı ve kayıtlı yerel kullanıcılar görebilir.
  - **Yalnızca Kök Admin Mesaj Atabilir:** Kanala yalnızca bu düğümün yerel kök admini (`@admin:<NodeID>.mesh`) mesaj yazabilir. Standart kullanıcılar için kanal tamamen salt-okunurdur (read-only); yetkisiz mesaj denemeleri soket düzeyinde reddedilir.
  - Sistem bakım takvimleri, kural güncellemeleri, acil durum uyarıları ve yerel sunucu durum raporları için tek yönlü resmi bilgilendirme akışıdır.
- **Düğüm İçi Yerel Sohbet Kanalı (`#yerel` / `#local`):**
  - **Sadece Yerel Kullanıcılar Arasında:** Yalnızca o düğümde hesabı veya aktif oturumu bulunan kullanıcıların kendi aralarında mesajlaşabileceği hafif yerel topluluk sohbeti.
  - **Dış Federasyon İzolasyonu:** Bu kanaldaki mesajlar P2P ağına veya uzak rölelere federate edilmez; tüm trafik sunucunun yerel sınırları içinde kalır (zero federation overhead).
  - Kullanıcıların genel ağ trafiği yaratmadan, gecikmesiz ve güvenli bir şekilde doğrudan sunucu arkadaşlarıyla sohbet edebilmesini sağlar.

---

## Kabul ve Uyumluluk Kriterleri
- Sıfır dış npm bağımlılığı kuralı ihlal edilemez (Yalnızca `node:worker_threads`, `node:crypto`, `node:net`, `node:sqlite`, `node:os`).
- Geriye dönük protokol uyumluluğu korunmalıdır (Mevcut v2.6.0 ağı ile kesintisiz çalışma).
- Tüm fazlar kapsamlı birim ve entegrasyon testleri ile doğrulanmalıdır.
