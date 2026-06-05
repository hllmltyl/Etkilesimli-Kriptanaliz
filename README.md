# 🔐 Etkileşimli Kriptografik Algoritma Analiz ve Görselleştirme Platformu

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python Badge">
  <img src="https://img.shields.io/badge/Tkinter-Retro_98-gray?style=for-the-badge" alt="Tkinter Badge">
  <img src="https://img.shields.io/badge/Matplotlib-Visualization-1f538d?style=for-the-badge" alt="Matplotlib Badge">
  <img src="https://img.shields.io/badge/NIST-Statistical_Tests-red?style=for-the-badge" alt="NIST Badge">
</p>

Bu proje; kriptografi eğitiminde en çok zorlanılan karmaşık algoritmaların (DES, AES, SHA-256, HMAC vb.) iç mekanizmalarını ve bunların altında yatan matematiksel teorileri (**özellikle Galois Alanı $GF(2^8)$ işlemlerini**) adım adım, interaktif olarak görselleştiren masaüstü tabanlı bir eğitim platformudur. 

Uygulamanın tamamı **Windows 98 retro masaüstü temasına** (3D-relief bileşenler, gri-tonlu renk paleti, klasik kaydırma çubukları ve MS Sans Serif fontu) sadık kalınarak tasarlanmıştır.

---

## 🚀 Öne Çıkan Özellikler

* **Tur Bazlı Adım İzleme (Step-by-Step Execution):** Tüm algoritmalar için Oynat/Duraklat (Play/Pause), İleri/Geri, Başa/Sona sarma ve animasyon hızı kontrol özellikleri.
* **Detaylı Galois Alanı $GF(2^8)$ Hesaplayıcısı:** Russian Peasant çarpım algoritmasının indirgeme adımları ile AES S-Box türetiminin afin dönüşüm ispatları.
* **NIST Rastgelelik Test Suite:** Blum Blum Shub (BBS) ve LCG üreteçlerinin ürettiği bitleri inceleyen Monobit, Runs ve Serial testleri.
* **Yazmaç Seviyesinde Takip:** SHA-256 dairesel kaymalarında 8 adet A-H yazmacının anlık durum gösterimi.
* **Sıfır Dış Bağımlılık (Zero External Math Library):** Tüm matematiksel ve istatistiksel işlemler (erfc, chi-square p-değerleri) hiçbir harici bilimsel kütüphane kullanılmadan saf Python ile yazılmıştır.

---

## 🖥️ Arayüz Sekmeleri ve Modüller

| Sekme / Modül | Görselleştirilen Aşamalar | Matematiksel Model |
| :--- | :--- | :--- |
| **DES & 3-DES** | Feistel ağı turları, L/R yarılama, subkey XOR'lamaları. | IP, PC1, PC2, E-Permutation, S-Boxes, P-Permutation, FP |
| **AES-128 & GF($2^8$)** | 4x4 durum matrisi güncellemeleri, S-Box ve MixColumns adımları. | Galois Alanı toplama/çarpma, afin dönüşüm, S-box tersi |
| **Hash & MAC** | SHA-256 padding aşaması, 64 sıkıştırma turu. HMAC ipad/opad akışı. | A-H yazmaç dairesel kaymaları, mantıksal XOR/AND maskeleri |
| **RBG & Analiz** | Adım adım bit üretimi, monobit, runs ve serial test grafikleri. | BBS ($X_{n+1} = X_n^2 \bmod M$), LCG, NIST test istatistikleri |

---

## 🛠️ Kurulum ve Çalıştırma

### 1. Depoyu Klonlayın
```bash
git clone https://github.com/hllmltyl/Etkilesimli-Kriptanaliz.git
cd Etkilesimli-Kriptanaliz
```

### 2. Sanal Ortamı Oluşturun ve Aktifleştirin
```bash
python -m venv .venv
# Windows için:
.venv\Scripts\activate
# Linux/macOS için:
source .venv/bin/activate
```

### 3. Gerekli Kütüphaneleri Yükleyin
```bash
pip install matplotlib numpy pillow
```

### 4. Uygulamayı Başlatın
```bash
python main.py
```

---

## 🧪 Birim Testlerin Çalıştırılması

Tüm matematiksel dönüşümlerin, $GF(2^8)$ kütüphanesinin ve şifreleme motorlarının doğruluğu birim testler ile güvence altına alınmıştır. Testleri çalıştırmak için:

```bash
python tests.py
```

---

## 📁 Proje Klasör Yapısı

```txt
📂 Etkilesimli-Kriptanaliz/
├── 📄 main.py            # Arayüz pencerelerini ve animasyon kontrol mekanizmalarını yönetir.
├── 📄 crypto_logic.py    # Şifreleme algoritmalarının ve istatistiksel testlerin şifreleme motoru.
├── 📄 analysis_logic.py  # Matplotlib kütüphanesini kullanarak durum matrislerini ve grafikleri çizen çizim motoru.
├── 📄 tests.py           # Algoritma doğruluğunu denetleyen unittest dosyası.
├── 📄 readme.txt         # Uygulama içinde yer alan "Oku Beni" kılavuz dosyası.
└── 📄 README.md          # Bu GitHub tanıtım belgesi.
```

---

## 🔒 Lisans
Bu proje eğitim amaçlı geliştirilmiş olup MIT Lisansı ile korunmaktadır. Kriptografi dersi final çalışmaları ve sunumlarında referans gösterilerek kullanılabilir.
