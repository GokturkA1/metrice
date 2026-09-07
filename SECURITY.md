# Metrice Güvenlik Politikası ve Tehdit Modeli (v2.0)

Metrice, geleneksel ağ dinleme, kimlik sahteciliği, yönlendirme zehirleme, derin paket analizi (DPI) ve gelecekteki kuantum bilgisayar tehditlerine (*Harvest Now, Decrypt Later*) karşı sıfır-güven (Zero-Trust) çok katmanlı savunma mimarisi uygular.

---

## Desteklenen Sürümler

| Sürüm | Destek Durumu | Güvenlik Düzeltmeleri |
| :--- | :--- | :--- |
| **2.1.x** | :white_check_mark: Aktif Destek | Tam Güvenlik Yamaları (PQ, Onion, AutoNAT) |
| **2.0.x** | :white_check_mark: Aktif Destek | Tam Güvenlik Yamaları (PQ, Onion, AutoNAT) |
| < 2.0.0 | :x: Kullanım Dışı | Desteklenmiyor (v2.0'a yükseltme zorunludur) |

---

## Güvenlik Mimarisi ve Koruma Katmanları

### 1. Post-Quantum Kriptografi (NIST FIPS 203) & Hibrit Taşıma
- **KEM Algoritması**: Tüm eşler arası (P2P) ve federasyon el sıkışmalarında yalnızca **ML-KEM-768 (Kyber-768)** kullanılır. Geleneksel zayıf asimetrik algoritmalar (RSA, DH, salt ECDH) çekirdek katmanda kabul edilmez.
- **Kapsülleme & Paylaşılan Sır**: Alıcı eşin Kyber açık anahtarına yönelik kapsülleme (encapsulation) gerçekleştirilir; dekapulasyon sonucu elde edilen paylaşılan sır (shared secret) simetrik anahtara genişletilir.
- **Simetrik Şifreleme**: 256-bit paylaşılan sır ile **AES-256-GCM** başlatılır. Her pakette 12 baytlık benzersiz IV (Initialization Vector) ve 16 baytlık kimlik doğrulama etiketi (Authentication Tag - GMAC) bulunur.
- **Strict Post-Quantum Modu**: `METRICE_STRICT_PQ=1` ortam değişkeniyle klasik veya eksik anahtar takasları anında soket düzeyinde reddedilir.

### 2. Çok Katmanlı Tor-Benzeri Onion Routing (3-Hop) & DPI Koruması
- **Anonim Devreler**: Düğümler arasındaki iletişim doğrudan IP yerine en az 3 atlamalı (Giriş / Röle / Çıkış) anonim devreler üzerinden tünellenir.
- **Ters Katmanlı Şifreleme**: Gönderici, paketi çıkıştan başlayarak geriye doğru her aktarım düğümünün açık anahtarıyla şifreler. Her düğüm yalnızca kendi katmanını soyabilir; bir önceki ve bir sonraki atlama haricinde devrenin başını ve sonunu bilemez.
- **Trafik Analizi ve DPI Koruması (Uniform Cell Padding)**:
  - Paket boyutu analizine dayalı parmak izi çıkarma saldırılarını engellemek için tüm Onion hücreleri sabit **2048 bayt** boyuta PKCS#7 benzeri rastgele dolgu (padding) ile hizalanır. Ham kullanıcı yükü azami 768 bayt ile sınırlandırılır.
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
- **SecureChannel Çerçeveleme Sınırı**:
  - Parçalı veya kötü niyetli veri akışlarında bellek tüketim saldırılarını (OOM DoS) engellemek amacıyla gelen tampon birikimi **65536 bayt (64 KB)** ile sınırlandırılmıştır.
  - Bu eşiği aşan veya 4 baytlık uzunluk başlığına uymayan hatalı paketler derhal `socket.destroy()` ile düşürülür.
- **Rendezvous Tünel Kapasite Limiti**:
  - NAT arkası düğümler için sağlanan rendezvous tünelleri düğüm başına azami **64 eşzamanlı oturum** ile sınırlandırılmıştır.
  - Tünel tablosunun şişirilmesine yönelik DoS denemelerinde `MAX_TUNNELS_REACHED` hatası verilir ve eski/inaktif oturumlar temizlenir.
- **Eş Havuzu Kısıtlaması**: Düğüm tablosu azami 100 aktif komşu eş ile sınırlandırılmıştır.

### 6. Tekrar Oynatma (Anti-Replay) ve Kimlik Bütünlüğü
- **Nonce Takipçisi (NonceTracker)**: Her el sıkışma ve yönetim paketi 16 baytlık CSPRNG (Kriptografik Güvenli Rastgele Sayı) nonce değeri taşır. Son 60 saniye içinde görülmüş olan nonce'lar anında reddedilir.
- **NodeID Doğrulaması**: Düğüm kimlikleri, eşin Ed25519 açık anahtarının SHA-256 özetinin RFC 4648 Base32 kodlamasıdır. Kendisini başka bir düğüm olarak tanıtmaya çalışan veya sahte kimlik üreten istekler açık anahtar imza doğrulamasında düşürülür.

### 7. ANSI Kaçış Koruması ve Enjeksiyon Önleme
- **Terminal Sanitizasyonu**: SSH terminal arayüzüne veya istemci çıktılarına yansıtılan tüm kullanıcı kaynaklı veriler (kullanıcı adları, mesajlar, komut parametreleri) OSC (`\x1b]`), CSI (`\x1b[`), ve ham ANSI kaçış dizilerinden arındırılır. Terminal emülatörlerinin istismar edilmesi (terminal escape injection) engellenir.
- **SQL Enjeksiyon Koruması**: SQLite veritabanı işlemlerinde (`node:sqlite`) string birleştirme kesinlikle yasaktır; tüm sorgular parametrize edilmiş prepared statement'lar üzerinden çalıştırılır.

---

## Güvenlik En İyi Uygulamaları (Best Practices)

1. **SSH Sürüm Maskeleme**:
   - `SSH_SERVER_VERSION` ortam değişkeni ile sunucunuzun versiyon başlığını özelleştirerek otomatik tarayıcıların (shodan, censys vb.) işletim sistemi ve servis tespiti yapmasını zorlaştırabilirsiniz.
2. **Güvenlik Duvarı & Ağ İzolasyonu**:
   - Yalnızca SSH (varsayılan `2222/tcp`) ve Federasyon (varsayılan `9001/tcp`) portlarını dış dünyaya açın.
   - İstemci yönetim arayüzünü (`clientPort: 8080`) ters vekil (Nginx, Traefik vb.) arkasında tutun ve mTLS veya güvenli erişim belirteçleri ile koruyun.
3. **Kök Yetkisi Olmadan Çalıştırma (Rootless)**:
   - Metrice'i imtiyazsız bir kullanıcı hesabı (`metrice` veya `nobody`) veya rootless Docker/Podman konteyneri içerisinde çalıştırınız.

---

## Güvenlik Açığı Bildirimi (Vulnerability Disclosure)

Metrice güvenliğine katkıda bulunmak isteyen araştırmacıları memnuniyetle karşılıyoruz.

- **Bildirim Kanalı**: Bir güvenlik açığı tespit ettiyseniz, lütfen GitHub üzerinde genel hata kaydı (**Public Issue**) açmayınız.
- **İletişim**: Güvenlik bulgularınızı doğrudan GitHub Security Advisory sekmesinden veya e-posta yoluyla proje yöneticilerine şifreli olarak iletiniz.
- **Müdahale Süresi**:
  - İlk geri bildirim ve teyit: **24 - 48 saat**
  - Kritik zafiyetler için yama yayınlama hedefi: **7 gün**
  - Koordineli açıklama (Coordinated Disclosure): Güvenlik yaması yayınlanana kadar detayların gizli tutulması rica olunur.