# Metrice

Metrice, harici paket bağımlılığı barındırmayan, tamamen Node.js çekirdek modülleri üzerine inşa edilmiş, kuantum sonrası kriptografi destekli P2P iletişim ve federasyon ağıdır. Sistem; terminal tabanlı çok panelli bir TUI, şifreli gossip federasyonu, yerel SSH-2 sunucusu ve WAL modunda çalışan SQLite veritabanı bileşenlerinden oluşur.

## Temel Özellikler

- Sıfır Bağımlılık: Harici npm paketi içermez. Yalnızca node:crypto, node:net, node:dgram ve node:sqlite gibi standart modüller kullanılır.
- Post-Quantum Güvenlik: Federasyon katmanı ve SSH anahtar değişiminde ML-KEM-768 (Kyber) algoritması kullanılır.
- Çift Katmanlı SSH-2 Sunucusu: Harici SSH sunucusu gerektirmeksizin yerel bellek üzerinde çalışan saf JavaScript SSH-2 uygulaması barındırır.
- 2FA Ephemeral Vault: Scrypt ve HKDF ile donanım açık anahtarı ve parola üzerinden geçici oturum anahtarı türetimi sağlanır.
- ACID Depolama: SQLite WAL modunda yerel mesajlaşma ve profil yönetimi sağlanır.
- Çok Kanallı TUI: Telnet ve SSH üzerinden bağlanılabilen ANSI/VT100 uyumlu üç panelli konsol arayüzü sunar.

## Kurulum ve Çalıştırma

Gereksinim: Node.js sürüm 22.0.0 veya üzeri (ML-KEM-768 tam desteği için Node.js sürüm 24+ önerilir).

Düğümü başlatmak için `node src/index.js` komutu kullanılır.

Ortam değişkenleri ile yapılandırma örneği:
`SERVER_NAME=127.0.0.1 CLIENT_PORT=2222 SSH_PORT=2224 FED_PORT=8001 node src/index.js`

Bağlantı yöntemleri:
- SSH ile bağlantı: `ssh -p 2224 kullanici@127.0.0.1`
- Telnet ile bağlantı: `telnet 127.0.0.1 2222`

## Federasyon ve Ağ Mimarisi

Metrice ağı, merkezi sunucu gerektirmeyen tam dağıtık (P2P) bir yapıya sahiptir. Düğümler kendi aralarında özel şifreli TCP kanalları üzerinden iletişim kurar.

### 1. Dinamik Eş Keşfi (LAN UDP Beacon)
Düğümler yerel ağdaki diğer düğümleri otomatik olarak tespit etmek için periyodik olarak 41234 portuna UDP broadcast yayını yapar.
Gönderilen paket yapısı:
`{"type":"P2P_BEACON","port":8001,"timestamp":1788535418}`
Yayın alan düğüm, göndericinin IP adresini ve ilettiği federasyon portunu eş listesine ekler.

### 2. Şifreli Federasyon El Sıkışması (Secure Channel)
Düğümler arası bağlantı standart TLS yerine post-quantum KEM mekanizması ile korunur:
- Düğüm A, Düğüm B'ye bağlanır ve rastgele tek kullanımlık bir nonce, kendi Ed25519 kimlik anahtarı ve ML-KEM-768 açık anahtarını içeren imzalı bir `HANDSHAKE_INIT` paketi gönderir.
- Düğüm B, gelen imzayı doğrular, ML-KEM açık anahtarını kullanarak 32 baytlık ortak bir sır üretir ve bu sırrı kapsülleyerek `HANDSHAKE_REPLY` paketiyle geri döndürür.
- Her iki düğüm de ortak sır ve nonce değerini HKDF-SHA256 algoritmasından geçirerek 256-bit oturum anahtarı elde eder.
- Ardından akan tüm federasyon verisi AES-256-GCM modunda `ENCRYPTED_FRAME` paketleri halinde taşınır.

### 3. Gossip Protokolü ve Eş Havuzu Yönetimi
Düğümler, ağ tablosunu güncel tutmak için rastgele seçilen eşlerle periyodik olarak haberleşir.
- Paket türü: `GOSSIP_DISCOVERY`
- Düğüm elindeki eş listesinden rastgele örneklem seçerek karşı tarafa iletir.
- Yanıt olarak karşı düğüm kendi bildiği aktif eşleri `GOSSIP_RESPONSE` paketiyle döner.
- Her eş için bir güven skoru tutulur. Başarılı iletişimler skoru artırırken, başarısız iletişimler skoru düşürür. Skoru sıfıra inen düğümler havuzdan çıkarılır.
- Havuz boyutu 250 eş ile sınırlandırılmıştır.

### 4. Kanal Aboneliği ve Mesaj Yönlendirme
- Genel kanallar (#genel) ağ genelinde yayılım gösterir (Broadcast Flood with Deduplication).
- Mesaj paketlerinde döngüleri engellemek amacıyla mesaj kimliği TTL önbelleğinde saklanır. Aynı kimliğe sahip paketler tekrar iletilmez.
- Atlama sınırı (hop) ve paket yaşam süresi (ttl) mekanizması ile ağ yükünün kontrolsüz büyümesi önlenir.
- Özel sunucu kanallarında yalnızca ilgili odaya abone olan düğümlere hedefli dağıtım yapılır (`CHANNEL_SUBSCRIBE` / `CHANNEL_UNSUBSCRIBE`).

## Dizin Yapısı

- `src/commands/`: TUI içi komut modülleri (/join, /leave, /msg, /keys, /allowtelnet vb.).
- `src/config/`: Port, dosya yolları ve çalışma zamanı yapılandırmaları.
- `src/core/clientServer.js`: Telnet sunucusu ve terminal oturum yöneticisi.
- `src/core/federation.js`: Düğümler arası şifreli iletişim ve paket dağıtım motoru.
- `src/core/peerManager.js`: UDP broadcast ve gossip eş havuzu yönetimi.
- `src/core/sshServer.js`: Saf JavaScript SSH-2 protokol motoru ve oturum yönetimi.
- `src/core/terminalSession.js`: Çok panelli TUI render motoru ve girdi ayrıştırıcı.
- `src/locales/`: Çoklu dil ve yerelleştirme desteği.
- `src/storage/database.js`: SQLite WAL depolama ve CRUD sorguları.
- `src/utils/`: ANSI, kriptografi, hata yönetimi ve SSH paket yardımcıları.