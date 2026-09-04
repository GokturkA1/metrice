# Güvenlik Politikası

## Desteklenen Sürümler

Güvenlik güncellemeleri yalnızca ana dal (master) üzerindeki en güncel sürüm için yayınlanır.

## Kriptografik Mimari ve Güvenlik Tasarımı

Metrice, ağ düzeyinde dinleme, kimlik sahteciliği ve gelecekteki kuantum bilgisayar tehditlerine karşı çok katmanlı bir savunma modeli uygular.

### 1. Post-Quantum KEM ve Taşıma Katmanı
- Düğümler arası iletişimde yalnızca NIST FIPS 203 uyumlu ML-KEM-768 (Kyber) anahtar kapsülleme algoritması kullanılır.
- Paket gizliliği, KEM ile takas edilen ortak sırdan türetilmiş AES-256-GCM simetrik şifreleme ve kimlik doğrulama etiketi (AuthTag) ile korunur.
- "Şimdi Topla, Sonra Çöz" (Harvest Now, Decrypt Later) saldırılarına karşı tam koruma sağlanır.

### 2. Ephemeral Vault ve Donanım Anahtarı Bağlama (2FA)
- SSH girişlerinde yalnızca Ed25519 algoritması kabul edilir.
- Kullanıcı parolası tek başına doğrulama için yeterli değildir. Parola, istemcinin sunduğu Ed25519 açık anahtarı ile tuzlanarak Scrypt (N=16384, r=8, p=1) algoritmasından geçirilir.
- Elde edilen anahtar HKDF-SHA256 ile birleştirilerek yerel kasa tohumuna dönüştürülür.
- Kayıtlı açık anahtara sahip olmayan bir saldırgan, doğru parolayı bilse dahi oturum açamaz.

### 3. Ağ Korumaları ve Saldırı Engelleme
- Nonce Replay Koruması: Her el sıkışma paketi rastgele tek kullanımlık 16 baytlık bir nonce içerir. Map tabanlı TTL takip mekanizması sayesinde aynı nonce değerine sahip paketler anında kesilir.
- Sybil ve Zehirleme Koruması: 0.0.0.0, 255.255.255.255 veya ayrılmış port bilgisi taşıyan eş tanımları eş havuzuna kabul edilmez.
- Paket Sınır Kontrolleri: SSH ve federasyon katmanında 65536 bayt üzerindeki tüm paketler derhal soket düzeyinde bağlantı sıfırlama (FIN/RST) ile sonlandırılır.
- ANSI / Terminal Sanitization: Terminal arayüzüne gönderilen mesajlar tüm kontrol karakterlerinden ve OSC/CSI kaçış dizilerinden arındırılarak terminal istismarları engellenir.
- SQL Injection Koruması: Veritabanı üzerindeki tüm işlemler node:sqlite modülünün hazırlanmış parametrik ifadeleri (Prepared Statements) ile yürütülür.

## Güvenlik Açığı Bildirimi

Bir güvenlik açığı tespit edilmesi durumunda lütfen genel hata kaydı (public issue) açmak yerine proje yöneticileriyle doğrudan iletişime geçiniz.