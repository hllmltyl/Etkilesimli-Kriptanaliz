================================================================================
          ETKİLEŞİMLİ KRİPTOGRAFİK ALGORİTMA ANALİZ VE GÖRSELLEŞTİRME PLATFORMU
================================================================================

Bu platform; DES, 3-DES, AES, Galois Alanı GF(2^8) aritmetiği, SHA-256 Hash fonksiyonu,
HMAC Mesaj Doğrulama Kodu ve Kriptografik Rastgele Bit Üreteçlerinin (RBG) çalışmasını
adım adım görselleştiren interaktif bir eğitim ve analiz aracıdır.

Uygulama, Windows 98 retro arayüz standartlarına (3D-relief bileşenler, gri-tonlu renk
paleti, MS Sans Serif fontu) ve Matplotlib tabanlı dinamik grafik çizim motoruna sahiptir.

--------------------------------------------------------------------------------
1. GEREKSİNİMLER VE KURULUM
--------------------------------------------------------------------------------
Uygulamanın çalıştırılması için Python 3.x ve aşağıdaki kütüphanelerin yüklü olması gerekir:
- matplotlib
- numpy
- pillow

Sanal ortam aktifken bağımlılıkları kurmak için:
pip install matplotlib numpy pillow

Uygulamayı başlatmak için:
python main.py

--------------------------------------------------------------------------------
2. MODÜLLERİN KULLANIM REHBERİ
--------------------------------------------------------------------------------

A. DES & 3-DES Sekmesi:
   - Girdi Modu Seçimi: Açık metni doğrudan HEX (16 karakter) veya ASCII Metin olarak girebilirsiniz.
   - Plaintext / Anahtarlar: Varsayılan test vektörleri otomatik doldurulur. Kendi değerlerinizi de girebilirsiniz.
   - Algoritma Seçimi: Standart DES (16 tur) veya 3-DES (E-D-E / 3 farklı anahtarlı) seçin.
   - Çalıştırma: "Algoritmayı Başlat" butonuna basın.
   - Adım Kontrolleri: Turlar arasında dolaşmak için "|<" (başlangıç), "<" (geri), ">" (ileri) ve ">|" (sonuç)
     butonlarını kullanın. "Oynat (>" butonu otomatik geçişi başlatır. Kaydırma çubuğu (slider) hız ayarı yapar.
   - Görsel Alan: Feistel ağının sol (L) ve sağ (R) yarısının bölünmesini, F fonksiyonunun subkey ile XOR'lanmasını
     ve veri akışını gösteren bir şema çizilir.

B. AES & GF(2^8) Sekmesi:
   - AES Simülatörü: Açık metin (16-byte) ve anahtarınızı girip başlatın. Her turdaki SubBytes, ShiftRows,
     MixColumns ve AddRoundKey işlemlerinin matris durumlarını ve byte bazlı değişimlerini izleyin.
     AddRoundKey adımında durum matrisi ve o tura ait round anahtarının XOR işlemi yan yana gösterilir.
   - GF(2^8) Hesaplayıcı (Sağ Panel): 
     Byte A ve Byte B alanlarına Hex formatında byte değerleri girin (Örn: 53 ve 05).
     - "Galois Çarpma" seçeneği, Russian Peasant algoritmasının adımlarını ve x^8+x^4+x^3+x+1 polinom indirgemesini gösterir.
     - "S-Box Tersi" seçeneği, byte değerinin önce GF(2^8) üzerindeki çarpımsal tersini bulur, ardından AES afin dönüşüm formülüyle S-Box sonucunu hesaplar.

C. Hash & MAC Sekmesi:
   - SHA-256: Girdi mesajınızı girip başlatın. Adım adım ilerleyerek mesajın pad edilmesini,
     mesaj genişletme kelimelerini (W_t), sabitleri (K_t) ve 8 adet A-H yazmacının 64 tur boyunca dairesel kaymasını izleyin.
   - HMAC-SHA256: Bir kimlik doğrulama anahtarı girin. Adım 1'de K0 anahtarının hazırlanması, ipad/opad XOR adımlarını;
     Adım 2'de iç hash (inner); Adım 3'te ise dış hash (outer) ile nihai MAC kodunun üretim akış şemasını izleyin.

D. RBG Sekmesi:
   - Üretici Seçimi: Blum Blum Shub (BBS - Kriptografik Güvenli) veya Linear Congruential Generator (LCG - Güvensiz) seçin.
   - Parametreler: BBS için p ve q (3 mod 4'e denk) asalları ile seed değerini; LCG için başlangıç seed'ini girin.
   - Çalıştırma: "Bitleri Üret ve Analiz Et" butonuna basarak bit üretimini tetikleyin.
   - Adım İzleme: İlk 20 bitin matematiksel olarak durum formülünden (Örn: X_n^2 mod M) nasıl türetildiğini izleyin.
   - NIST Testleri: Üretilen bitlerin rastgelelik kalitesini ölçen Monobit, Runs ve Serial testlerinin p-değerleri ve
     NIST standartlarına göre geçme/kalma durumları sağ taraftaki grafikle birlikte sunulur.

--------------------------------------------------------------------------------
3. PROJE DOSYA YAPISI
--------------------------------------------------------------------------------
- main.py: Arayüz pencerelerini, sekmeleri ve animasyon zamanlayıcı akışlarını yöneten giriş noktası.
- crypto_logic.py: DES, AES, GF(2^8), SHA-256, HMAC, BBS ve NIST testlerinin matematiksel şifreleme motoru.
- analysis_logic.py: Matplotlib kullanarak verileri grafiksel/görsel şemalara dönüştüren çizim motoru.
- tests.py: Şifreleme motorlarının ve matematik fonksiyonlarının doğruluğunu denetleyen unittest dosyası.
- readme.txt: Bu kullanım kılavuzu.