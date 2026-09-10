# Metrice Güvenlik Politikası ve Tehdit Modeli (v2.5)

Metrice, geleneksel ağ dinleme, kimlik sahteciliği, yönlendirme zehirleme, derin paket analizi (DPI) ve gelecekteki kuantum bilgisayar tehditlerine (*Harvest Now, Decrypt Later*) karşı sıfır-güven (Zero-Trust) çok katmanlı savunma mimarisi uygular.

---

## Desteklenen Sürümler

| Sürüm | Destek Durumu | Güvenlik Düzeltmeleri |
| :--- | :--- | :--- |
| **2.5.x** | Aktif Destek | Tam Güvenlik Yamaları (PQ ML-KEM-768, Onion, AutoNAT, Presence Sync) |
| **2.4.x** | Aktif Destek | Güvenlik Yamaları |
| **2.0.x - 2.3.x** | Güvenlik Destek Sonu | 2.5.x sürümüne yükseltme önerilir |
| < 2.0.0 | Kullanım Dışı | Desteklenmiyor (v2.x mimarisine yükseltme zorunludur) |

---

## Güvenlik Mimarisi ve Koruma Katmanları

### 1. Post-Quantum Kriptografi (NIST FIPS 203) & Hibrit Taşıma
- **KEM Algoritması**: Tüm eşler arası (P2P) ve federasyon el sıkışmalarında yalnızca **ML-KEM-768 (Kyber-768)** kullanılır. Geleneksel zayıf asimetrik algoritmalar (RSA, DH, salt ECDH) çekirdek katmanda kabul edilmez.
- **Kapsülleme & Paylaşılan Sır**: Alıcı eşin Kyber açık anahtarına yönelik kapsülleme (encapsulation) gerçekleştirilir; dekapulasyon sonucu elde edilen paylaşılan sır (shared secret) simetrik anahtara genişletilir.
- **Simetrik Şifreleme**: 256-bit paylaşılan sır ile **AES-256-GCM** başlatılır. Her pakette 12 baytlık benzersiz IV (Initialization Vector) ve 16 baytlık kimlik doğrulama etiketi (Authentication Tag - GMAC) bulunur.
- **Strict Post-Quantum Modu**: `METRICE_STRICT_PQ=1` (veya `STRICT_PQ=true`) ortam değişkeniyle klasik veya eksik anahtar takasları anında soket düzeyinde reddedilir.

### 2. Çok Katmanlı Tor-Benzeri Onion Routing (3-Hop) & DPI Koruması
- **Anonim Devreler**: Düğümler arasındaki iletişim doğrudan IP yerine en az 3 atlamalı (Giriş / Röle / Çıkış) anonim devreler üzerinden tünellenir.
- **Ters Katmanlı Şifreleme**: Gönderici, paketi çıkıştan başlayarak geriye doğru her aktarım düğümünün açık anahtarıyla şifreler. Her düğüm yalnızca kendi katmanını soyabilir; bir önceki ve bir sonraki atlama haricinde devrenin başını ve sonunu bilemez.
- **Trafik Analizi ve DPI Koruması (Uniform Cell Padding)**:
  - Paket boyutu analizine dayalı parmak izi çıkarma saldırılarını engellemek için tüm Onion hücreleri sabit **2048 bayt** boyuta rastgele dolgu (padding) ile hizalanır. Ham kullanıcı yükü azami 768 bayt ile sınırlandırılır.
  - Veri boyutu ne olursa olsun hat üzerindeki tüm paketler kriptografik olarak ayırt edilemez tek tip (uniform) bloklar halinde iletilir.
- **Devre İzolasyonu & TTL Temizliği**: Devre durumları 10 dakikalık (600.000 ms) zaman aşımına tabidir. Süresi dolan anahtar materyali ve devre eşlemeleri bellekten güvenli biçimde silinir.

### 3. İki Faktörlü Donanım Anahtarı Bağlama (2FA Ephemeral Vault)
- **Kriptografik Anahtar Kısıtlaması**: SSH sunucu katmanında yalnızca modern ve güvenli **Ed25519** açık anahtarları kabul edilir (RSA, DSA veya zayıf ECDSA tamamen engellenmiştir).
- **Parola + Açık Anahtar KDF**: Kullanıcı parolası asla düz metin veya doğrudan hash olarak tutulmaz ve doğrulanmaz:
  $$\text{Salt} = \text{SHA256}(\text{Client\_Ed25519\_PublicKey})$$
  $$\text{Key} = \text{Scrypt}(\text{Password}, \text{Salt}, N=16384, r=8, p=1)$$
- **Kasa Güvenliği**: Parola bilinse dahi, ilişkili Ed25519 açık anahtarına sahip olmayan bir istemci kasayı açamaz veya oturum yetkisi kazanamaz.

### 4. AutoNAT Diyal-Geri Doğrulaması & SSRF / Port Tarama Engelleme
- **IP Sabitleme (Strict Remote Address Pinning)**: AutoNAT doğrulama isteklerinde eşin talep ettiği harici IP parametresi dikkate alınmaz. Yalnızca TCP soketinden çekilen `socket.remoteAddress` üzerinden diyal-geri (dialback) testi yapılır.
- **Özel Ağ (RFC 1918) & Döngü Koruması**:
  - Düğümlerin döngüsel (loopback) veya yerel ağdaki başka servislere proxy olarak kullanılması (SSRF) engellenir.
  - Test portları doğrulanır; 1-1023 arası imtiyazlı sistem portları diyal-geri hedeflerinden hariç tutulur.
- **Zaman Aşımı**: Diyal-geri işlemleri 5 saniyelik agresif zaman aşımı ve kaynak kısıtlaması ile korunur.

### 5. DoS, Bellek Güvenliği ve Tampon (Buffer) Sınırları
- **SecureChannel Çerçeveleme Sınırı**: Parçalı veya kötü niyetli veri akışlarında bellek tüketim saldırılarını (OOM DoS) engellemek amacıyla gelen tampon birikimi **65536 bayt (64 KB)** ile sınırlandırılmıştır. Eşiği aşan soketler derhal kapatılır.
- **Rendezvous Tünel Kapasite Limiti**: NAT arkası düğümler için sağlanan rendezvous tünelleri düğüm başına azami **64 eşzamanlı oturum** ile sınırlandırılmıştır.
- **Eş Havuzu Kısıtlaması**: Düğüm tablosu azami 100 aktif komşu eş ile sınırlandırılmıştır.

### 6. Tekrar Oynatma (Anti-Replay) ve Kimlik Bütünlüğü
- **Nonce Takipçisi (NonceTracker)**: Her el sıkışma ve yönetim paketi 16 baytlık CSPRNG nonce değeri taşır. Son 60 saniye içinde görülmüş olan nonce'lar anında reddedilir.
- **NodeID Doğrulaması**: Düğüm kimlikleri, eşin Ed25519 açık anahtarının SHA-256 özetinin RFC 4648 Base32 kodlamasıdır.

### 7. ANSI Kaçış Koruması ve Enjeksiyon Önleme
- **Terminal Sanitizasyonu**: SSH terminal arayüzüne veya istemci çıktılarına yansıtılan tüm kullanıcı kaynaklı veriler OSC (`\x1b]`), CSI (`\x1b[`), ve kontrol karakterlerinden arındırılır.
- **SQL Enjeksiyon Koruması**: SQLite veritabanı işlemlerinde string birleştirme yasaktır; tüm sorgular parametrize prepared statement'lar üzerinden çalıştırılır.

---

## Kriptografik Anahtar İfşa ve İptal Protokolleri (Key Compromise Protocols)

### 1. Düğüm Düzeyi (Ed25519 ve ML-KEM-768 Düğüm Kimliği İfşası)
Bir düğümün özel anahtarlarının ifşa olması durumunda aşağıdaki acil müdahale adımları izlenmelidir:
1. **Düğümü Durdurun**: Düğüm sürecini (`kill -TERM` veya `docker compose down`) derhal kapatın.
2. **Kimlik Verisini Sıfırlayın**: SQLite veritabanı içerisindeki `node_identity` tablosu sıfırlanmalıdır. Düğüm yeniden başladığında otomatik olarak yeni Ed25519 ve Kyber-768 anahtar çifti oluşturacaktır.
3. **Eş Önbelleklerini Temizleyin**: Düğümün eski Base32 `.mesh` adresini kullanan komşuların eş önbellek dosyalarından (`peers_*.json`) eski kayıt temizlenmelidir.
4. **Yeni Kimliği Duyurun**: Yeni düğüm kimliği aktif edildikten sonra komşu düğümlere yeniden el sıkışma (Federation Handshake) gönderilir.

### 2. Kullanıcı Düzeyi (SSH Ed25519 Anahtar İfşası)
Kullanıcının istemci tarafındaki SSH özel anahtarı çalındığında veya yetkisiz erişim şüphesinde:
1. Yedek bir yetkili anahtarla veya doğrudan konsol erişimiyle terminale bağlanın.
2. `/keys list` komutuyla kayıtlı anahtarları listeleyin.
3. `/keys remove <key_index_veya_pubkey>` komutuyla ifşa olmuş anahtarı kullanıcı profilinden anında silin.
4. Parolanızı `/passwd` (veya ilgili profil komutu) ile değiştirin.

---

## Güvenlik Açığı Bildirimi ve Sorumlu İfşa (Responsible Disclosure)

Metrice güvenliğine katkıda bulunmak isteyen güvenlik araştırmacılarını memnuniyetle karşılıyoruz.

- **Bildirim Kanalı**: Bir güvenlik açığı tespit ettiyseniz, lütfen GitHub üzerinde genel hata kaydı (**Public Issue**) açmayınız.
- **İletişim**: Güvenlik bulgularınızı doğrudan GitHub Security Advisory ("Report a vulnerability") sekmesinden veya proje yöneticilerine şifreli olarak iletiniz.
- **Süreç ve Taahhütler**:
  - **İlk Geri Bildirim**: Bildiriminiz 24 ila 48 saat içerisinde değerlendirilir ve teyit edilir.
  - **Düzeltme & Yama Hedefi**: Kritik ve yüksek dereceli açıklar için azami 7 iş günü içinde yama yayınlanır.
  - **Koordineli Açıklama (Coordinated Disclosure)**: Güvenlik yaması tüm kullanıcılara dağıtılana kadar detayların gizli tutulması rica olunur. Güvenlik bülteninde araştırmacıya teşekkür edilir.
