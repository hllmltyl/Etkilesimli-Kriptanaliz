# Kapsamlı Kullanım Rehberi (Walkthrough)

Bu rehber, **Etkileşimli Kriptografik Algoritma Analiz ve Görselleştirme Platformu**'nun özelliklerini, her bir sekmenin adım adım nasıl kullanılacağını, arayüzdeki kontrollerin işlevlerini ve arka planda dönen kriptografik süreçleri açıklamaktadır.

---

## 🛠️ Kurulum ve Başlatma

Uygulama, standart Python kütüphaneleri (`tkinter`, `math`, `hashlib`, `hmac`) dışında grafik çizimleri için **Matplotlib** ve veri dizilimleri için **Numpy** kullanır. 

### Bağımlılıkları Yükleme
Sanal ortamınızın (.venv) aktif olduğundan emin olun ve terminalde şu komutu çalıştırın:
```powershell
.venv\Scripts\python.exe -m pip install matplotlib numpy pillow
```

### Uygulamayı Çalıştırma
Proje dizininde (`d:\Dosyalar\Mobil\Etkilesimli Kriptanaliz\Kriptanaliz`) arayüzü başlatmak için:
```powershell
.venv\Scripts\python.exe main.py
```

---

## 🖥️ Arayüz Sekmeleri ve Adım Adım Kullanım

Uygulama açıldığında üst menüde 4 sekme ve sağ üst köşede projenin özet kılavuzunu açan **"Oku Beni (Readme)"** butonu yer alır.

```mermaid
graph TD
    Main[main.py: Arayüz Girişi] --> Tab1[DES & 3-DES Analizi]
    Main --> Tab2[AES & GF/2^8/ Alanı]
    Main --> Tab3[Hash & MAC Doğrulama]
    Main --> Tab4[RBG Rastgele Bit Analizi]
    Tab2 --> StandaloneGF[GF/2^8/ Hesap Makinesi]
    Tab4 --> NIST[NIST Rastgelelik Test Paneli]
```

---

### 1️⃣ Sekme: DES & 3-DES Analizi
Bu sekme, 64-bit veri bloklarının Feistel yapısı üzerindeki tur (round) işlemlerini görselleştirir.

#### Adım Adım Kullanım:
1. **Girdi Tipi:** Sol panelden açık metnin formatını seçin. `HEX` (16 karakterlik onaltılık kod) veya `Metin (ASCII)` (8 karakterli düz metin).
2. **Plaintext Girişi:** `Açık Metin (Plaintext)` kutusuna şifrelemek istediğiniz veriyi yazın. (Varsayılan: `0123456789ABCDEF`).
3. **Anahtarları Girme:** 64-bitlik Hex anahtarınızı girin. 3-DES kullanacaksanız Key 1, Key 2 ve Key 3 alanlarının tamamını doldurun. (Örn. Key 1: `133457799BBCDFF1`).
4. **Algoritma Seçimi:** `Standart DES` (16 tur şifreleme) veya `3-DES` (E-D-E / Şifrele - Şifre Çöz - Şifrele) seçeneğini işaretleyin.
5. **Simülasyonu Başlatma:** **"Algoritmayı Başlat / Sıfırla"** butonuna tıklayın. 
6. **Adım Kontrolleri:**
   - **Oynat (>) / Duraklat (||)**: Turları otomatik oynatır.
   - **Hız (ms) Barı**: Oynatma hızını milisaniye cinsinden ayarlar (100 ms - 2 saniye).
   - **`<` ve `>`**: Manuel olarak bir önceki veya bir sonraki tura geçer.
   - **`|<` ve `>|`**: Doğrudan başlangıç turlarına (girdi bloğu ve Initial Permutation) veya son tura (XOR birleştirme ve Final Permutation) atlar.
7. **Görsel Takip:** Matplotlib ekranında Feistel ağının L ve R yarısının ayrılmasını, F fonksiyonunun round subkey ile nasıl harmanlandığını ve sonraki tura nasıl geçtiğini şematik olarak izleyin. Sol paneldeki **"Adım Detayları"** alanından o adımdaki bit dizilimlerini Hex/Bin formatında okuyun.

---

### 2️⃣ Sekme: AES & GF(2^8) Alanı
Bu sekme iki bağımsız alt panelden oluşur: Sol panelde **AES-128 Şifreleme Simülatörü**, sağ panelde ise **Galois Alanı GF(2^8) Hesaplayıcı** yer alır.

#### AES-128 Şifreleme Simülatörü:
1. **Plaintext ve Key Girişi:** 32 karakterlik (16-byte) Hex veya düz metin girdilerini girin. (Varsayılan test vektörleri otomatik olarak yüklüdür).
2. **"AES Şifrelemeyi Başlat"** butonuna basın.
3. Kontrol butonlarını kullanarak AES'in 10 round boyunca gerçekleştirdiği dönüşümleri izleyin:
   - **SubBytes**: Durum matrisindeki her elemanın doğrusal olmayan AES S-Box karşılıkları ile değiştirilmesi (değişen hücreler yeşil renkle vurgulanır).
   - **ShiftRows**: Satırların sola dairesel kaydırılması (satırlar mor renkle vurgulanır).
   - **MixColumns**: Durum matrisinin her bir sütununun GF(2^8) üzerinde özel bir katsayı matrisiyle çarpılması (sarı vurgulama).
   - **AddRoundKey**: Durum matrisi ve round anahtarının XOR'lanması (Ekran 3 matrise bölünür: Mevcut Durum ⊕ Round Anahtarı = Çıktı).

#### Galois Alanı GF(2^8) & S-Box Hesaplayıcı (Sağ Panel):
1. **Byte Girişi:** `Byte A` ve `Byte B` alanlarına Hex formatında iki değer yazın (Örn: `53` ve `05`).
2. **İşlem Seçimi:**
   - **Galois Çarpma (Russian Peasant)**: $GF(2^8)$ üzerinde indirgemeli polinom çarpması yapar.
   - **AES S-Box Tersi & Afin Dönüşüm**: Girilen Byte A değerinin S-box tablosundaki karşılığının matematiksel türetilmesini gösterir.
3. **"Hesapla ve Detaylandır"** butonuna basın.
4. **Matematiksel Akış:** Matplotlib ekranında, çarpma algoritmasının adım adım shift/XOR tablosu veya S-Box'ın GF(2^8) çarpımsal tersini bulup afin dönüşüm matrisiyle ($s = A \cdot x^{-1} + c$) çarptığı adımların detaylı matematiksel ispatı yazdırılır.

---

### 3️⃣ Sekme: Hash & MAC Doğrulama
Mesaj bütünlüğü (integrity) ve kimlik doğrulama (authentication) süreçlerini görselleştirir.

#### Adım Adım Kullanım:
1. **Mesaj ve Anahtar:** `Girdi Mesajı` kısmına istediğiniz metni yazın. HMAC simülasyonu için bir `Kimlik Doğrulama Anahtarı` girin.
2. **Yöntem Seçimi:** `SHA-256` (düz hash) veya `HMAC` (anahtarlı mesaj doğrulama) seçeneğini seçin.
3. **"Hesaplamayı Başlat"** butonuna basın.
4. **SHA-256 Görselleştirmesi:**
   - Adım 1: Mesajın pad edilmesi, 0x80 eklenmesi ve uzunluğun 64-bitlik sona yazılması anlatılır.
   - Adım 2-65: SHA-256'nın 64 sıkıştırma turu boyunca `A, B, C, D, E, F, G, H` yazmaçlarının dairesel kaymasını ve her turdaki $W_t$ (mesaj kelimesi) ve $K_t$ (sabit) karıştırma değerlerini takip edin.
5. **HMAC Görselleştirmesi:**
   - Adım 1: K0 anahtarının hazırlanması, ipad ($K_0 \oplus 0x36$) ve opad ($K_0 \oplus 0x5C$) değerlerinin türetilmesi.
   - Adım 2: İç Hash (Inner Hash) aşaması: $SHA256(ipad\ ||\ Message)$ hesaplanması.
   - Adım 3: Dış Hash (Outer Hash) aşaması: $SHA256(opad\ ||\ InnerHash)$ hesaplanarak nihai MAC kodunun çıkarılması. Akış şeması üzerinde o anki aktif adım yeşil renk ile parlar.

---

### 4️⃣ Sekme: RBG Rastgele Bit Analizi
Bu sekme, güvenli ve güvensiz rastgele bit üreteçlerinin (RBG) matematiksel üretimini ve üretilen bitlerin NIST standartlarına göre istatistiksel analizini yapar.

#### Adım Adım Kullanım:
1. **Üretici Seçimi:** `BBS (CSRPNG Güvenli)` veya `LCG (Güvensiz)` seçin.
2. **Parametreleri Ayarlama:**
   - **LCG için**: Bir başlangıç `Seed` değeri girin.
   - **BBS için**: $p$ ve $q$ asal sayılarını girin (NIST kuralı: primes $\equiv 3 \pmod 4$ olmalıdır. Örn: $p=383$, $q=503$). Bir `Seed` değeri girin.
3. **Bit Adeti:** Üretilecek toplam bit sayısını seçin (Örn: `1000`).
4. **"Bitleri Üret ve Analiz Et"** butonuna tıklayın.
5. **Matematiksel İzleme:** Sol alt paneldeki kontrol tuşlarıyla (`<` ve `>`), üretilen ilk 20 bitin formülasyonunu (Örn: $X_{n+1} = X_n^2 \pmod M$, LSB bit çıktısı) adım adım takip edebilirsiniz.
6. **NIST Test Sonuçları (Sağ Panel):**
   - **Frekans Dağılımı**: Üretilen bitlerin 0 ve 1 adetlerini gösteren sütun grafiği çizilir.
   - **NIST Testleri**: **Monobit (Frequency)**, **Runs (Blok içi değişim)** ve **Serial (Ardışık 2-bit geçişleri)** testlerinin hesaplanan p-değerleri ekrana yazdırılır. NIST standart kuralına göre $p \ge 0.01$ ise testten geçer (Pass), aksi takdirde kalır (Fail). BBS genellikle tüm testlerden geçerken, LCG testlerde başarısız olabilmektedir.

---

## 🔍 Hata Giderme ve İpuçları
* **Hatalı HEX Girdisi:** DES veya AES'te Hex seçiliyken girilen değerlerin sadece `0-9` ve `A-F` karakterlerini içermesine dikkat edin. Aksi halde uygulama uyarı kutusu gösterir.
* **BBS Parametreleri:** BBS'in düzgün çalışması için $p$ ve $q$ sayılarının asal olması ve mod 4'te 3 kalanını vermesi şarttır. Eğer testlerin başarısız olduğunu görürseniz varsayılan değerleri (`p=383`, `q=503`, `seed=10135`) kullanın.
* **Performans Hızı:** SHA-256'nın 64 turunu otomatik oynatırken animasyon hızını `100 ms` veya daha altına alarak hızlıca tamamlayabilirsiniz.