# main.py
# -------
# Etkileşimli Kriptografik Algoritma Analiz ve Görselleştirme Platformu
# Tkinter tabanlı Windows 98 retro arayüzü ve Matplotlib grafik entegrasyonu.

import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import os
import sys

# Resource path resolver for development and PyInstaller
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# Import logic modules
from crypto_logic import (
    hex_to_bin, bin_to_hex, bytes_to_hex, hex_to_bytes,
    aes_encrypt_steps, des_encrypt_steps, triple_des_encrypt_steps,
    sha256_steps, hmac_sha256_steps,
    run_lcg, run_bbs, monobit_test, runs_test, serial_test
)
from analysis_logic import (
    plot_aes_state, plot_gf28_mul, plot_des_state,
    plot_sha256_state, plot_hmac_flow, plot_rbg_stats, plot_sbox_calc
)

WIN95_BG = "#c0c0c0" # Classic retro grey

# Custom Placeholder Entry Widget
class PlaceholderEntry(tk.Entry):
    def __init__(self, master=None, placeholder="", color='grey', default_fg='black', **kwargs):
        super().__init__(master, **kwargs)
        self.placeholder = placeholder
        self.placeholder_color = color
        self.default_fg = default_fg
        
        self.bind("<FocusIn>", self._focus_in)
        self.bind("<FocusOut>", self._focus_out)
        self._put_placeholder()
        
    def _put_placeholder(self):
        self.delete(0, tk.END)
        self.insert(0, self.placeholder)
        self.config(fg=self.placeholder_color)
        
    def _focus_in(self, event):
        if self.cget("fg") == self.placeholder_color:
            self.delete(0, tk.END)
            self.config(fg=self.default_fg)
            
    def _focus_out(self, event):
        if not self.get():
            self._put_placeholder()
            
    def get_value(self):
        if self.cget("fg") == self.placeholder_color:
            return ""
        return self.get()
        
    def set_value(self, val):
        self.config(fg=self.default_fg)
        self.delete(0, tk.END)
        self.insert(0, val)

    def set_placeholder(self, text):
        self.placeholder = text
        if self.cget("fg") == self.placeholder_color:
            self._put_placeholder()

class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Etkileşimli Kriptografik Algoritma Analiz ve Görselleştirme Platformu")
        self.geometry("1100x750")
        self.minsize(1000, 700)
        self.configure(bg=WIN95_BG)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Force MS Sans Serif retro look
        self.option_add("*Font", "{MS Sans Serif} 9")
        self.option_add("*Background", WIN95_BG)
        self.option_add("*Button.Relief", "raised")
        self.option_add("*Button.BorderWidth", "2")
        self.option_add("*Entry.Relief", "sunken")
        self.option_add("*Entry.BorderWidth", "2")
        self.option_add("*Entry.Background", "white")
        self.option_add("*Text.Relief", "sunken")
        self.option_add("*Text.BorderWidth", "2")
        self.option_add("*Text.Background", "white")
        self.option_add("*Listbox.Relief", "sunken")
        self.option_add("*Listbox.BorderWidth", "2")
        self.option_add("*Listbox.Background", "white")
        self.option_add("*Menu.Relief", "raised")
        self.option_add("*Menu.BorderWidth", "2")

        # Classic theme
        style = ttk.Style(self)
        try:
            style.theme_use('classic')
        except Exception:
            pass

        # Main frame
        main_frame = tk.Frame(self, bg=WIN95_BG, bd=2, relief=tk.SUNKEN)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Notebook tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Top readme button
        self.btn_readme = tk.Button(main_frame, text="Oku Beni (Readme)", command=self.open_readme)
        self.btn_readme.place(relx=1.0, rely=0.0, anchor="ne", x=-6, y=4)

        # Four tabs
        self.tab_des = tk.Frame(self.notebook, bg=WIN95_BG, bd=2, relief=tk.RAISED)
        self.tab_aes = tk.Frame(self.notebook, bg=WIN95_BG, bd=2, relief=tk.RAISED)
        self.tab_hash = tk.Frame(self.notebook, bg=WIN95_BG, bd=2, relief=tk.RAISED)
        self.tab_rbg = tk.Frame(self.notebook, bg=WIN95_BG, bd=2, relief=tk.RAISED)

        self.notebook.add(self.tab_des, text="DES & 3-DES Analizi")
        self.notebook.add(self.tab_aes, text="AES & GF(2^8) Alanı")
        self.notebook.add(self.tab_hash, text="Hash & MAC Doğrulama")
        self.notebook.add(self.tab_rbg, text="RBG Rastgele Bit Analizi")

        # Setup individual tab layouts
        self.setup_des_tab()
        self.setup_aes_tab()
        self.setup_hash_tab()
        self.setup_rbg_tab()

    def on_closing(self):
        self.quit()
        self.destroy()
        os._exit(0)

    # Reusable Readme reader window
    def open_readme(self):
        readme_win = tk.Toplevel(self)
        readme_win.title("Proje Açıklaması ve Kılavuz")
        readme_win.geometry("650x500")
        readme_win.configure(bg=WIN95_BG)
        
        frame = tk.Frame(readme_win, bg=WIN95_BG, bd=2, relief=tk.SUNKEN)
        frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        
        scrollbar = ttk.Scrollbar(frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        text_widget = tk.Text(frame, wrap=tk.WORD, bd=0, yscrollcommand=scrollbar.set, bg="white", fg="black", font=("{MS Sans Serif}", 9))
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_widget.yview)
        
        readme_path = resource_path("readme.txt")
        if not os.path.exists(readme_path):
            # Write a default description if readme doesn't exist yet
            default_txt = (
                "========================================================================\n"
                "         ETKİLEŞİMLİ KRİPTOGRAFİK ALGORİTMA ANALİZ PLATFORMU\n"
                "========================================================================\n\n"
                "Bu platform, Kriptografi dersi kapsamında DES, 3-DES, AES, Galois Alanları (GF(2^8)),\n"
                "Hash (SHA-256), MAC (HMAC) ve Kriptografik Rastgele Bit Üreteçlerinin (RBG) \n"
                "çalışma mantığını adım adım görselleştirmek ve analiz etmek amacıyla tasarlanmıştır.\n\n"
                "Kılavuz ve Özellikler:\n"
                "--------------------\n"
                "1. DES & 3-DES Sekmesi:\n"
                "   - Kullanıcı kendi girdisini (Metin veya 16-karakterlik Hex) ve anahtarını girebilir.\n"
                "   - Oynat/Duraklat (Play/Pause), İleri/Geri ve Hız Ayarı ile Feistel turlarını izleyebilir.\n"
                "   - L ve R yarılarındaki bit değişimlerini ve XOR adımlarını grafiksel olarak görür.\n\n"
                "2. AES & GF(2^8) Sekmesi:\n"
                "   - AES-128 şifreleme adımlarını (SubBytes, ShiftRows, MixColumns, AddRoundKey) görselleştirir.\n"
                "   - Sütun-bazlı durum (state) matrisini her adımda matris renkleri ile gösterir.\n"
                "   - Sağ taraftaki Galois Alanı Hesaplayıcısı ile iki byte'ın GF(2^8) üzerinde çarpma,\n"
                "     toplama ve S-Box ters alma adımlarının matematiğini adım adım yazdırır.\n\n"
                "3. Hash & MAC Sekmesi:\n"
                "   - SHA-256 algoritmasındaki A-H kayıt (register) akışını gösterir.\n"
                "   - HMAC-SHA256'nın çift katmanlı dış/iç hash ($ipad$/$opad$) şemasını görselleştirir.\n\n"
                "4. RBG Sekmesi:\n"
                "   - Doğrusal Eşlik (LCG) ve Blum Blum Shub (BBS) güvenli rastgele bit üreteçlerini karşılaştırır.\n"
                "   - NIST Monobit (Frekans), Runs (Ardışıklar) ve Serial (2-Bit Geçiş) test sonuçlarını hesaplar.\n"
                "   - Üretilen bitlerin dağılımlarını Matplotlib grafikleri ile raporlar.\n"
            )
            with open(readme_path, "w", encoding="utf-8") as f:
                f.write(default_txt)

        try:
            with open(readme_path, "r", encoding="utf-8") as f:
                content = f.read()
            text_widget.insert("1.0", content)
        except Exception as e:
            text_widget.insert("1.0", f"Hata: readme.txt okunamadı.\n{e}")
            
        text_widget.config(state=tk.DISABLED)

    def create_scrollable_text(self, parent, height=5, width=50):
        frame = tk.Frame(parent, bg=WIN95_BG, bd=2, relief=tk.SUNKEN)
        scrollbar = ttk.Scrollbar(frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text_widget = tk.Text(frame, height=height, width=width, bd=0, yscrollcommand=scrollbar.set, font=("Consolas", 9))
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_widget.yview)
        return frame, text_widget

    # =====================================================================
    # TAB 1: DES & 3-DES ANALYZER
    # =====================================================================
    def setup_des_tab(self):
        self.tab_des.grid_columnconfigure(0, weight=1)
        self.tab_des.grid_columnconfigure(1, weight=2)
        self.tab_des.grid_rowconfigure(0, weight=1)

        # Left panel (Controls & Input)
        left_p = tk.Frame(self.tab_des, bg=WIN95_BG, bd=2, relief=tk.GROOVE)
        left_p.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        
        # Right panel (Visualization canvas)
        right_p = tk.Frame(self.tab_des, bg=WIN95_BG, bd=2, relief=tk.GROOVE)
        right_p.grid(row=0, column=1, sticky="nsew", padx=4, pady=4)
        
        # Grid settings for left panel
        left_p.grid_columnconfigure(0, weight=1)
        
        # Input selection
        tk.Label(left_p, text="DES / 3-DES Girdi ve Ayarlar", font=("{MS Sans Serif}", 10, "bold"), bg=WIN95_BG).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        
        self.des_input_mode = tk.StringVar(value="Hex")
        modes_f = tk.Frame(left_p, bg=WIN95_BG)
        modes_f.grid(row=1, column=0, sticky="w", padx=5)
        tk.Radiobutton(modes_f, text="HEX (16 Karakter)", variable=self.des_input_mode, value="Hex", bg=WIN95_BG).pack(side=tk.LEFT)
        tk.Radiobutton(modes_f, text="Metin (ASCII)", variable=self.des_input_mode, value="Text", bg=WIN95_BG).pack(side=tk.LEFT)

        tk.Label(left_p, text="Açık Metin (Plaintext):", bg=WIN95_BG).grid(row=2, column=0, sticky="w", padx=5, pady=(5, 0))
        self.des_plaintext_ent = PlaceholderEntry(left_p, placeholder="0123456789ABCDEF", width=35)
        self.des_plaintext_ent.grid(row=3, column=0, sticky="ew", padx=5, pady=(0, 5))
        
        # Subkeys Frame
        keys_f = tk.LabelFrame(left_p, text="Anahtarlar (64-bit Hex)", bg=WIN95_BG)
        keys_f.grid(row=4, column=0, sticky="ew", padx=5, pady=5)
        keys_f.grid_columnconfigure(1, weight=1)
        
        tk.Label(keys_f, text="Key 1:", bg=WIN95_BG).grid(row=0, column=0, padx=5, pady=2)
        self.des_k1_ent = PlaceholderEntry(keys_f, placeholder="133457799BBCDFF1", width=25)
        self.des_k1_ent.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
        
        tk.Label(keys_f, text="Key 2 (3-DES):", bg=WIN95_BG).grid(row=1, column=0, padx=5, pady=2)
        self.des_k2_ent = PlaceholderEntry(keys_f, placeholder="1111222233334444", width=25)
        self.des_k2_ent.grid(row=1, column=1, sticky="ew", padx=5, pady=2)
        
        tk.Label(keys_f, text="Key 3 (3-DES):", bg=WIN95_BG).grid(row=2, column=0, padx=5, pady=2)
        self.des_k3_ent = PlaceholderEntry(keys_f, placeholder="5555666677778888", width=25)
        self.des_k3_ent.grid(row=2, column=1, sticky="ew", padx=5, pady=2)

        # Cipher type & direction
        opts_f = tk.Frame(left_p, bg=WIN95_BG)
        opts_f.grid(row=5, column=0, sticky="ew", padx=5, pady=5)
        self.des_cipher_type = tk.StringVar(value="DES")
        tk.Radiobutton(opts_f, text="Standart DES", variable=self.des_cipher_type, value="DES", bg=WIN95_BG).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(opts_f, text="3-DES (E-D-E)", variable=self.des_cipher_type, value="3DES", bg=WIN95_BG).pack(side=tk.LEFT, padx=5)

        self.btn_des_start = tk.Button(left_p, text="Algoritmayı Başlat / Sıfırla", command=self.start_des_simulation)
        self.btn_des_start.grid(row=6, column=0, sticky="ew", padx=5, pady=8)

        # Stepping controls frame
        ctrl_f = tk.LabelFrame(left_p, text="Adım Kontrolleri", bg=WIN95_BG)
        ctrl_f.grid(row=7, column=0, sticky="ew", padx=5, pady=5)
        
        nav_f = tk.Frame(ctrl_f, bg=WIN95_BG)
        nav_f.pack(fill=tk.X, padx=5, pady=2)
        self.btn_des_first = tk.Button(nav_f, text="|<", width=4, command=lambda: self.seek_des(0))
        self.btn_des_first.pack(side=tk.LEFT, padx=2)
        self.btn_des_prev = tk.Button(nav_f, text="<", width=4, command=lambda: self.seek_des(self.des_idx - 1))
        self.btn_des_prev.pack(side=tk.LEFT, padx=2)
        
        self.btn_des_play = tk.Button(nav_f, text="Oynat (>", width=10, command=self.toggle_des_play)
        self.btn_des_play.pack(side=tk.LEFT, padx=2)
        
        self.btn_des_next = tk.Button(nav_f, text=">", width=4, command=lambda: self.seek_des(self.des_idx + 1))
        self.btn_des_next.pack(side=tk.LEFT, padx=2)
        self.btn_des_last = tk.Button(nav_f, text=">|", width=4, command=lambda: self.seek_des(len(self.des_steps)-1))
        self.btn_des_last.pack(side=tk.LEFT, padx=2)
        
        self.lbl_des_step_indicator = tk.Label(ctrl_f, text="Adım: 0 / 0", bg=WIN95_BG, font=("{MS Sans Serif}", 9, "bold"))
        self.lbl_des_step_indicator.pack(pady=2)

        # Animation Speed Slider
        speed_f = tk.Frame(ctrl_f, bg=WIN95_BG)
        speed_f.pack(fill=tk.X, padx=5, pady=2)
        tk.Label(speed_f, text="Hız (ms):", bg=WIN95_BG).pack(side=tk.LEFT)
        self.slider_des_speed = tk.Scale(speed_f, from_=100, to=2000, orient=tk.HORIZONTAL, bg=WIN95_BG, highlightthickness=0)
        self.slider_des_speed.set(1000)
        self.slider_des_speed.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Detailed step log area
        tk.Label(left_p, text="Adım Detayları:", bg=WIN95_BG).grid(row=8, column=0, sticky="w", padx=5, pady=(5, 0))
        f_log, self.txt_des_log = self.create_scrollable_text(left_p, height=8)
        f_log.grid(row=9, column=0, sticky="nsew", padx=5, pady=(0, 5))
        left_p.grid_rowconfigure(9, weight=1)

        # Visualization space
        tk.Label(right_p, text="Feistel Ağı / Blok Durumu Görseli", bg=WIN95_BG, font=("{MS Sans Serif}", 9, "bold")).pack(pady=4)
        self.des_canvas_frame = tk.Frame(right_p, bg="white", bd=2, relief=tk.SUNKEN)
        self.des_canvas_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Step variables
        self.des_steps = []
        self.des_idx = 0
        self.des_playing = False

    def start_des_simulation(self):
        # Stop animation
        self.des_playing = False
        self.btn_des_play.config(text="Oynat (>)")
        
        pt_val = self.des_plaintext_ent.get_value().strip()
        k1 = self.des_k1_ent.get_value().strip()
        k2 = self.des_k2_ent.get_value().strip()
        k3 = self.des_k3_ent.get_value().strip()
        cipher = self.des_cipher_type.get()
        mode = self.des_input_mode.get()

        # Input checks
        if not pt_val or not k1:
            messagebox.showerror("Hata", "Lütfen açık metin ve Key 1 değerlerini girin.")
            return

        # Prepare inputs
        try:
            if mode == "Hex":
                pt_bin = hex_to_bin(pt_val, 64)
            else:
                # String to bin
                pt_bytes = pt_val.encode('utf-8')
                if len(pt_bytes) < 8:
                    pt_bytes = pt_bytes.ljust(8, b'\x00')
                pt_bin = ''.join(f'{x:08b}' for x in pt_bytes[:8])
                
            k1_bin = hex_to_bin(k1, 64)
            k2_bin = hex_to_bin(k2, 64) if k2 else '0'*64
            k3_bin = hex_to_bin(k3, 64) if k3 else '0'*64
        except Exception as e:
            messagebox.showerror("Hata", f"Girdi dönüştürme hatası:\n{e}")
            return

        # Run logic and generate step traces
        if cipher == "DES":
            final_out, self.des_steps = des_encrypt_steps(pt_bin, k1_bin)
        else:
            final_out, self.des_steps = triple_des_encrypt_steps(pt_bin, k1_bin, k2_bin, k3_bin)
            
        self.des_idx = 0
        self.show_des_step()

    def show_des_step(self):
        if not self.des_steps:
            return
        step = self.des_steps[self.des_idx]
        self.lbl_des_step_indicator.config(text=f"Adım: {self.des_idx + 1} / {len(self.des_steps)}")
        
        # Update text log
        self.txt_des_log.config(state=tk.NORMAL)
        self.txt_des_log.delete("1.0", tk.END)
        
        log_text = f"ADIM: {step['name']}\n"
        log_text += f"Tur: {step.get('round', 0)}\n\n"
        log_text += f"Açıklama:\n{step['desc']}\n\n"
        
        if 'bits' in step:
            log_text += f"Blok Durumu (Hex): 0x{bin_to_hex(step['bits'])}\n"
            log_text += f"Blok Durumu (Bin): {step['bits'][:32]}...\n"
        elif 'L' in step and 'R' in step:
            log_text += f"Sol Yarı L: 0x{bin_to_hex(step['L'])} ({step['L']})\n"
            log_text += f"Sağ Yarı R: 0x{bin_to_hex(step['R'])} ({step['R']})\n"
            
        self.txt_des_log.insert("1.0", log_text)
        self.txt_des_log.config(state=tk.DISABLED)
        
        # Render visual diagram
        plot_des_state(self.des_canvas_frame, step)

    def seek_des(self, idx):
        if not self.des_steps:
            return
        if 0 <= idx < len(self.des_steps):
            self.des_idx = idx
            self.show_des_step()

    def toggle_des_play(self):
        if not self.des_steps:
            return
        self.des_playing = not self.des_playing
        if self.des_playing:
            self.btn_des_play.config(text="Duraklat (||)")
            self.animate_des()
        else:
            self.btn_des_play.config(text="Oynat (>)")

    def animate_des(self):
        if not self.des_playing:
            return
        if self.des_idx < len(self.des_steps) - 1:
            self.des_idx += 1
            self.show_des_step()
            delay = self.slider_des_speed.get()
            self.after(delay, self.animate_des)
        else:
            self.des_playing = False
            self.btn_des_play.config(text="Oynat (>)")

    # =====================================================================
    # TAB 2: AES & GALOIS FIELD GF(2^8) EXPLORER
    # =====================================================================
    def setup_aes_tab(self):
        self.tab_aes.grid_columnconfigure((0, 1), weight=1)
        self.tab_aes.grid_rowconfigure(0, weight=1)

        # Left pane: AES Step visualizer
        aes_p = tk.LabelFrame(self.tab_aes, text="AES-128 Şifreleme Simülatörü", bg=WIN95_BG, bd=2, relief=tk.GROOVE)
        aes_p.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        
        # Right pane: GF(2^8) calculator
        gf_p = tk.LabelFrame(self.tab_aes, text="Galois Alanı GF(2^8) & S-Box Hesaplayıcı", bg=WIN95_BG, bd=2, relief=tk.GROOVE)
        gf_p.grid(row=0, column=1, sticky="nsew", padx=4, pady=4)

        # ---------------- AES PANEL INNER LAYOUT ----------------
        aes_p.grid_columnconfigure(0, weight=1)
        
        aes_inp_f = tk.Frame(aes_p, bg=WIN95_BG)
        aes_inp_f.pack(fill=tk.X, padx=5, pady=2)
        
        self.aes_input_mode = tk.StringVar(value="Hex")
        tk.Radiobutton(aes_inp_f, text="HEX Modu", variable=self.aes_input_mode, value="Hex", bg=WIN95_BG).pack(side=tk.LEFT)
        tk.Radiobutton(aes_inp_f, text="ASCII Metin", variable=self.aes_input_mode, value="Text", bg=WIN95_BG).pack(side=tk.LEFT)

        tk.Label(aes_p, text="Açık Metin (16-Byte / 32 Hex):", bg=WIN95_BG).pack(anchor="w", padx=5)
        self.aes_pt_ent = PlaceholderEntry(aes_p, placeholder="00112233445566778899AABBCCDDEEFF", width=40)
        self.aes_pt_ent.pack(fill=tk.X, padx=5, pady=2)
        
        tk.Label(aes_p, text="Anahtar (16-Byte / 32 Hex):", bg=WIN95_BG).pack(anchor="w", padx=5)
        self.aes_key_ent = PlaceholderEntry(aes_p, placeholder="000102030405060708090A0B0C0D0E0F", width=40)
        self.aes_key_ent.pack(fill=tk.X, padx=5, pady=2)

        self.btn_aes_start = tk.Button(aes_p, text="AES Şifrelemeyi Başlat", command=self.start_aes_simulation)
        self.btn_aes_start.pack(fill=tk.X, padx=5, pady=5)

        # Animation buttons
        aes_ctrl = tk.Frame(aes_p, bg=WIN95_BG)
        aes_ctrl.pack(fill=tk.X, padx=5, pady=2)
        
        self.btn_aes_first = tk.Button(aes_ctrl, text="|<", width=4, command=lambda: self.seek_aes(0))
        self.btn_aes_first.pack(side=tk.LEFT, padx=1)
        self.btn_aes_prev = tk.Button(aes_ctrl, text="<", width=4, command=lambda: self.seek_aes(self.aes_idx - 1))
        self.btn_aes_prev.pack(side=tk.LEFT, padx=1)
        self.btn_aes_play = tk.Button(aes_ctrl, text="Oynat (>", width=8, command=self.toggle_aes_play)
        self.btn_aes_play.pack(side=tk.LEFT, padx=1)
        self.btn_aes_next = tk.Button(aes_ctrl, text=">", width=4, command=lambda: self.seek_aes(self.aes_idx + 1))
        self.btn_aes_next.pack(side=tk.LEFT, padx=1)
        self.btn_aes_last = tk.Button(aes_ctrl, text=">|", width=4, command=lambda: self.seek_aes(len(self.aes_steps)-1))
        self.btn_aes_last.pack(side=tk.LEFT, padx=1)
        
        self.lbl_aes_step = tk.Label(aes_p, text="Adım: 0 / 0", bg=WIN95_BG, font=("{MS Sans Serif}", 9, "bold"))
        self.lbl_aes_step.pack(pady=1)

        speed_f = tk.Frame(aes_p, bg=WIN95_BG)
        speed_f.pack(fill=tk.X, padx=5, pady=2)
        tk.Label(speed_f, text="Hız (ms):", bg=WIN95_BG).pack(side=tk.LEFT)
        self.slider_aes_speed = tk.Scale(speed_f, from_=100, to=2000, orient=tk.HORIZONTAL, bg=WIN95_BG, highlightthickness=0)
        self.slider_aes_speed.set(1000)
        self.slider_aes_speed.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Matplotlib frame for AES state matrix
        self.aes_canvas_frame = tk.Frame(aes_p, bg="white", bd=2, relief=tk.SUNKEN)
        self.aes_canvas_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        f_log, self.txt_aes_log = self.create_scrollable_text(aes_p, height=4)
        f_log.pack(fill=tk.X, padx=5, pady=4)

        # ---------------- GF PANEL INNER LAYOUT ----------------
        gf_p.grid_columnconfigure(0, weight=1)
        
        gf_inp_f = tk.Frame(gf_p, bg=WIN95_BG)
        gf_inp_f.pack(fill=tk.X, padx=5, pady=4)
        
        tk.Label(gf_inp_f, text="Byte A (Hex):", bg=WIN95_BG).grid(row=0, column=0, padx=5, pady=2)
        self.gf_a_ent = PlaceholderEntry(gf_inp_f, placeholder="53", width=8)
        self.gf_a_ent.grid(row=0, column=1, padx=5, pady=2)
        
        tk.Label(gf_inp_f, text="Byte B (Hex):", bg=WIN95_BG).grid(row=0, column=2, padx=5, pady=2)
        self.gf_b_ent = PlaceholderEntry(gf_inp_f, placeholder="05", width=8)
        self.gf_b_ent.grid(row=0, column=3, padx=5, pady=2)

        # Operation selection
        self.gf_op = tk.StringVar(value="Mul")
        ops_frame = tk.LabelFrame(gf_p, text="İşlem Seçimi", bg=WIN95_BG)
        ops_frame.pack(fill=tk.X, padx=5, pady=4)
        tk.Radiobutton(ops_frame, text="Galois Çarpma (Russian Peasant)", variable=self.gf_op, value="Mul", bg=WIN95_BG).pack(anchor="w", padx=5)
        tk.Radiobutton(ops_frame, text="AES S-Box Tersi & Afin Dönüşüm", variable=self.gf_op, value="SBox", bg=WIN95_BG).pack(anchor="w", padx=5)

        self.btn_gf_calc = tk.Button(gf_p, text="Hesapla ve Detaylandır", command=self.run_gf_calculation)
        self.btn_gf_calc.pack(fill=tk.X, padx=5, pady=4)

        # Visual layout for GF math
        self.gf_canvas_frame = tk.Frame(gf_p, bg="white", bd=2, relief=tk.SUNKEN)
        self.gf_canvas_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # State vars
        self.aes_steps = []
        self.aes_idx = 0
        self.aes_playing = False

    def start_aes_simulation(self):
        self.aes_playing = False
        self.btn_aes_play.config(text="Oynat (>)")

        pt = self.aes_pt_ent.get_value().strip()
        key = self.aes_key_ent.get_value().strip()
        mode = self.aes_input_mode.get()

        if not pt or not key:
            messagebox.showerror("Hata", "Lütfen açık metin ve anahtar değerlerini girin.")
            return

        try:
            if mode == "Hex":
                pt_bytes = hex_to_bytes(pt)
            else:
                pt_bytes = pt.encode('utf-8')
            key_bytes = hex_to_bytes(key) if len(key) >= 16 else key.encode('utf-8')
        except Exception as e:
            messagebox.showerror("Hata", f"Byte dönüştürme hatası: {e}")
            return

        final_cipher, self.aes_steps = aes_encrypt_steps(pt_bytes, key_bytes)
        self.aes_idx = 0
        self.show_aes_step()

    def show_aes_step(self):
        if not self.aes_steps:
            return
        step = self.aes_steps[self.aes_idx]
        self.lbl_aes_step.config(text=f"Adım: {self.aes_idx + 1} / {len(self.aes_steps)}")

        # Update text log
        self.txt_aes_log.config(state=tk.NORMAL)
        self.txt_aes_log.delete("1.0", tk.END)
        
        log_txt = f"AES İŞLEMİ: {step['name']}\n"
        log_txt += f"Tur (Round): {step['round']}\n\n"
        log_txt += f"Detaylar:\n{step['desc']}\n"
        
        self.txt_aes_log.insert("1.0", log_txt)
        self.txt_aes_log.config(state=tk.DISABLED)

        # Plot state matrix
        plot_aes_state(self.aes_canvas_frame, step)

    def seek_aes(self, idx):
        if not self.aes_steps:
            return
        if 0 <= idx < len(self.aes_steps):
            self.aes_idx = idx
            self.show_aes_step()

    def toggle_aes_play(self):
        if not self.aes_steps:
            return
        self.aes_playing = not self.aes_playing
        if self.aes_playing:
            self.btn_aes_play.config(text="Duraklat (||)")
            self.animate_aes()
        else:
            self.btn_aes_play.config(text="Oynat (>)")

    def animate_aes(self):
        if not self.aes_playing:
            return
        if self.aes_idx < len(self.aes_steps) - 1:
            self.aes_idx += 1
            self.show_aes_step()
            delay = self.slider_aes_speed.get()
            self.after(delay, self.animate_aes)
        else:
            self.aes_playing = False
            self.btn_aes_play.config(text="Oynat (>)")

    def run_gf_calculation(self):
        a_str = self.gf_a_ent.get_value().strip()
        b_str = self.gf_b_ent.get_value().strip()
        op = self.gf_op.get()

        if not a_str:
            messagebox.showerror("Hata", "Lütfen Byte A değerini girin.")
            return

        try:
            val_a = int(a_str, 16)
            val_b = int(b_str, 16) if b_str else 0
        except ValueError:
            messagebox.showerror("Hata", "Lütfen geçerli Hex değerleri yazın (Örn: 53).")
            return

        if op == "Mul":
            plot_gf28_mul(self.gf_canvas_frame, val_a, val_b)
        else:
            plot_sbox_calc(self.gf_canvas_frame, val_a)

    # =====================================================================
    # TAB 3: HASH & MAC INSPECTOR
    # =====================================================================
    def setup_hash_tab(self):
        self.tab_hash.grid_columnconfigure(0, weight=1)
        self.tab_hash.grid_columnconfigure(1, weight=2)
        self.tab_hash.grid_rowconfigure(0, weight=1)

        left_p = tk.Frame(self.tab_hash, bg=WIN95_BG, bd=2, relief=tk.GROOVE)
        left_p.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        
        right_p = tk.Frame(self.tab_hash, bg=WIN95_BG, bd=2, relief=tk.GROOVE)
        right_p.grid(row=0, column=1, sticky="nsew", padx=4, pady=4)
        
        left_p.grid_columnconfigure(0, weight=1)

        tk.Label(left_p, text="Veri Bütünlüğü ve MAC Ayarları", font=("{MS Sans Serif}", 10, "bold"), bg=WIN95_BG).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        
        tk.Label(left_p, text="Girdi Mesajı:", bg=WIN95_BG).grid(row=1, column=0, sticky="w", padx=5)
        self.hash_msg_ent = PlaceholderEntry(left_p, placeholder="Kriptografi ve Uygulamalari Dersi Final Projesi", width=35)
        self.hash_msg_ent.grid(row=2, column=0, sticky="ew", padx=5, pady=(0, 5))
        
        tk.Label(left_p, text="Kimlik Doğrulama Anahtarı (HMAC için):", bg=WIN95_BG).grid(row=3, column=0, sticky="w", padx=5)
        self.hash_key_ent = PlaceholderEntry(left_p, placeholder="GizliAnahtarimiz", width=35)
        self.hash_key_ent.grid(row=4, column=0, sticky="ew", padx=5, pady=(0, 5))

        self.hash_mode = tk.StringVar(value="SHA256")
        mode_f = tk.LabelFrame(left_p, text="Algoritma Tipi", bg=WIN95_BG)
        mode_f.grid(row=5, column=0, sticky="ew", padx=5, pady=5)
        tk.Radiobutton(mode_f, text="SHA-256 (Kriptografik Hash)", variable=self.hash_mode, value="SHA256", bg=WIN95_BG).pack(anchor="w", padx=5)
        tk.Radiobutton(mode_f, text="HMAC-SHA256 (Mesaj Doğrulama)", variable=self.hash_mode, value="HMAC", bg=WIN95_BG).pack(anchor="w", padx=5)

        self.btn_hash_start = tk.Button(left_p, text="Hesaplamayı Başlat / Sıfırla", command=self.start_hash_simulation)
        self.btn_hash_start.grid(row=6, column=0, sticky="ew", padx=5, pady=8)

        # Animation
        ctrl_f = tk.LabelFrame(left_p, text="Adım Kontrolleri", bg=WIN95_BG)
        ctrl_f.grid(row=7, column=0, sticky="ew", padx=5, pady=5)
        
        nav_f = tk.Frame(ctrl_f, bg=WIN95_BG)
        nav_f.pack(fill=tk.X, padx=5, pady=2)
        self.btn_hash_first = tk.Button(nav_f, text="|<", width=4, command=lambda: self.seek_hash(0))
        self.btn_hash_first.pack(side=tk.LEFT, padx=1)
        self.btn_hash_prev = tk.Button(nav_f, text="<", width=4, command=lambda: self.seek_hash(self.hash_idx - 1))
        self.btn_hash_prev.pack(side=tk.LEFT, padx=1)
        self.btn_hash_play = tk.Button(nav_f, text="Oynat (>", width=9, command=self.toggle_hash_play)
        self.btn_hash_play.pack(side=tk.LEFT, padx=1)
        self.btn_hash_next = tk.Button(nav_f, text=">", width=4, command=lambda: self.seek_hash(self.hash_idx + 1))
        self.btn_hash_next.pack(side=tk.LEFT, padx=1)
        self.btn_hash_last = tk.Button(nav_f, text=">|", width=4, command=lambda: self.seek_hash(len(self.hash_steps)-1))
        self.btn_hash_last.pack(side=tk.LEFT, padx=1)
        
        self.lbl_hash_step = tk.Label(ctrl_f, text="Adım: 0 / 0", bg=WIN95_BG, font=("{MS Sans Serif}", 9, "bold"))
        self.lbl_hash_step.pack(pady=2)

        speed_f = tk.Frame(ctrl_f, bg=WIN95_BG)
        speed_f.pack(fill=tk.X, padx=5, pady=2)
        tk.Label(speed_f, text="Hız (ms):", bg=WIN95_BG).pack(side=tk.LEFT)
        self.slider_hash_speed = tk.Scale(speed_f, from_=100, to=2000, orient=tk.HORIZONTAL, bg=WIN95_BG, highlightthickness=0)
        self.slider_hash_speed.set(500)  # Faster defaults for hash
        self.slider_hash_speed.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        tk.Label(left_p, text="Detaylar:", bg=WIN95_BG).grid(row=8, column=0, sticky="w", padx=5, pady=(5, 0))
        f_log, self.txt_hash_log = self.create_scrollable_text(left_p, height=8)
        f_log.grid(row=9, column=0, sticky="nsew", padx=5, pady=(0, 5))
        left_p.grid_rowconfigure(9, weight=1)

        # Visual
        tk.Label(right_p, text="Adım Durumu Görselleştirme", bg=WIN95_BG, font=("{MS Sans Serif}", 9, "bold")).pack(pady=4)
        self.hash_canvas_frame = tk.Frame(right_p, bg="white", bd=2, relief=tk.SUNKEN)
        self.hash_canvas_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # State
        self.hash_steps = []
        self.hash_idx = 0
        self.hash_playing = False

    def start_hash_simulation(self):
        self.hash_playing = False
        self.btn_hash_play.config(text="Oynat (>)")

        msg = self.hash_msg_ent.get_value()
        key = self.hash_key_ent.get_value()
        mode = self.hash_mode.get()

        msg_bytes = msg.encode('utf-8')
        key_bytes = key.encode('utf-8')

        if mode == "SHA256":
            final_res, self.hash_steps = sha256_steps(msg_bytes)
        else:
            final_res, self.hash_steps = hmac_sha256_steps(msg_bytes, key_bytes)
            
        self.hash_idx = 0
        self.show_hash_step()

    def show_hash_step(self):
        if not self.hash_steps:
            return
        step = self.hash_steps[self.hash_idx]
        self.lbl_hash_step.config(text=f"Adım: {self.hash_idx + 1} / {len(self.hash_steps)}")

        self.txt_hash_log.config(state=tk.NORMAL)
        self.txt_hash_log.delete("1.0", tk.END)
        
        log_txt = f"BAŞLIK: {step['name']}\n\n"
        log_txt += f"Açıklama:\n{step['desc']}\n\n"
        
        if 'h' in step:
            h_vals = step['h']
            log_txt += "Yazmaç Değerleri (A-H):\n"
            for i, val in enumerate(h_vals):
                name = chr(ord('A') + i)
                log_txt += f"  {name}: 0x{val:08X}\n"
                
        self.txt_hash_log.insert("1.0", log_txt)
        self.txt_hash_log.config(state=tk.DISABLED)

        # Plot registers or HMAC flowchart
        if self.hash_mode.get() == "SHA256":
            plot_sha256_state(self.hash_canvas_frame, step)
        else:
            plot_hmac_flow(self.hash_canvas_frame, step)

    def seek_hash(self, idx):
        if not self.hash_steps:
            return
        if 0 <= idx < len(self.hash_steps):
            self.hash_idx = idx
            self.show_hash_step()

    def toggle_hash_play(self):
        if not self.hash_steps:
            return
        self.hash_playing = not self.hash_playing
        if self.hash_playing:
            self.btn_hash_play.config(text="Duraklat (||)")
            self.animate_hash()
        else:
            self.btn_hash_play.config(text="Oynat (>)")

    def animate_hash(self):
        if not self.hash_playing:
            return
        if self.hash_idx < len(self.hash_steps) - 1:
            self.hash_idx += 1
            self.show_hash_step()
            delay = self.slider_hash_speed.get()
            self.after(delay, self.animate_hash)
        else:
            self.hash_playing = False
            self.btn_hash_play.config(text="Oynat (>)")

    # =====================================================================
    # TAB 4: RBG & STATISTICAL EVALUATOR
    # =====================================================================
    def setup_rbg_tab(self):
        self.tab_rbg.grid_columnconfigure(0, weight=1)
        self.tab_rbg.grid_columnconfigure(1, weight=2)
        self.tab_rbg.grid_rowconfigure(0, weight=1)

        left_p = tk.Frame(self.tab_rbg, bg=WIN95_BG, bd=2, relief=tk.GROOVE)
        left_p.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        
        right_p = tk.Frame(self.tab_rbg, bg=WIN95_BG, bd=2, relief=tk.GROOVE)
        right_p.grid(row=0, column=1, sticky="nsew", padx=4, pady=4)
        
        left_p.grid_columnconfigure(0, weight=1)

        tk.Label(left_p, text="RBG ve NIST Test Parametreleri", font=("{MS Sans Serif}", 10, "bold"), bg=WIN95_BG).grid(row=0, column=0, sticky="w", padx=5, pady=5)

        # LCG Frame
        lcg_f = tk.LabelFrame(left_p, text="1. Doğrusal Eşlik (LCG) Ayarları", bg=WIN95_BG)
        lcg_f.grid(row=1, column=0, sticky="ew", padx=5, pady=4)
        lcg_f.grid_columnconfigure(1, weight=1)
        tk.Label(lcg_f, text="Tohum (Seed):", bg=WIN95_BG).grid(row=0, column=0, padx=5, pady=2)
        self.lcg_seed_ent = PlaceholderEntry(lcg_f, placeholder="12345", width=15)
        self.lcg_seed_ent.grid(row=0, column=1, sticky="ew", padx=5, pady=2)

        # BBS Frame
        bbs_f = tk.LabelFrame(left_p, text="2. Blum Blum Shub (BBS) Ayarları", bg=WIN95_BG)
        bbs_f.grid(row=2, column=0, sticky="ew", padx=5, pady=4)
        bbs_f.grid_columnconfigure(1, weight=1)
        
        tk.Label(bbs_f, text="Asal p (≡3 mod 4):", bg=WIN95_BG).grid(row=0, column=0, padx=5, pady=2)
        self.bbs_p_ent = PlaceholderEntry(bbs_f, placeholder="383", width=10)
        self.bbs_p_ent.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
        
        tk.Label(bbs_f, text="Asal q (≡3 mod 4):", bg=WIN95_BG).grid(row=1, column=0, padx=5, pady=2)
        self.bbs_q_ent = PlaceholderEntry(bbs_f, placeholder="503", width=10)
        self.bbs_q_ent.grid(row=1, column=1, sticky="ew", padx=5, pady=2)
        
        tk.Label(bbs_f, text="Tohum (Seed coprime M):", bg=WIN95_BG).grid(row=2, column=0, padx=5, pady=2)
        self.bbs_seed_ent = PlaceholderEntry(bbs_f, placeholder="10135", width=10)
        self.bbs_seed_ent.grid(row=2, column=1, sticky="ew", padx=5, pady=2)

        # General generator selection
        gen_sel_f = tk.Frame(left_p, bg=WIN95_BG)
        gen_sel_f.grid(row=3, column=0, sticky="ew", padx=5, pady=5)
        
        self.rbg_gen_choice = tk.StringVar(value="BBS")
        tk.Radiobutton(gen_sel_f, text="BBS (CSRPNG Güvenli)", variable=self.rbg_gen_choice, value="BBS", bg=WIN95_BG).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(gen_sel_f, text="LCG (Güvensiz)", variable=self.rbg_gen_choice, value="LCG", bg=WIN95_BG).pack(side=tk.LEFT, padx=5)

        tk.Label(left_p, text="Üretilecek Bit Adeti (En az 100):", bg=WIN95_BG).grid(row=4, column=0, sticky="w", padx=5)
        self.rbg_count_ent = PlaceholderEntry(left_p, placeholder="1000", width=15)
        self.rbg_count_ent.grid(row=5, column=0, sticky="w", padx=5, pady=(0, 5))

        self.btn_rbg_start = tk.Button(left_p, text="Bitleri Üret ve Analiz Et", command=self.start_rbg_simulation)
        self.btn_rbg_start.grid(row=6, column=0, sticky="ew", padx=5, pady=8)

        # Step-by-step bit mathematical tracing panel
        trace_f = tk.LabelFrame(left_p, text="Adım Adım Bit Hesabı (İlk 20 Adım)", bg=WIN95_BG)
        trace_f.grid(row=7, column=0, sticky="ew", padx=5, pady=5)
        
        nav_f = tk.Frame(trace_f, bg=WIN95_BG)
        nav_f.pack(fill=tk.X, padx=5, pady=2)
        self.btn_rbg_prev = tk.Button(nav_f, text="< Geri", width=6, command=self.prev_rbg_step)
        self.btn_rbg_prev.pack(side=tk.LEFT, padx=5)
        self.lbl_rbg_step = tk.Label(nav_f, text="Adım: 0 / 0", bg=WIN95_BG)
        self.lbl_rbg_step.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.btn_rbg_next = tk.Button(nav_f, text="İleri >", width=6, command=self.next_rbg_step)
        self.btn_rbg_next.pack(side=tk.LEFT, padx=5)

        # Output text details
        tk.Label(left_p, text="Çıktı & Formül Detayı:", bg=WIN95_BG).grid(row=8, column=0, sticky="w", padx=5, pady=(5, 0))
        f_log, self.txt_rbg_log = self.create_scrollable_text(left_p, height=8)
        f_log.grid(row=9, column=0, sticky="nsew", padx=5, pady=(0, 5))
        left_p.grid_rowconfigure(9, weight=1)

        # Right side plotting canvas
        tk.Label(right_p, text="NIST Raporlama ve Dağılım Grafiği", bg=WIN95_BG, font=("{MS Sans Serif}", 9, "bold")).pack(pady=4)
        self.rbg_canvas_frame = tk.Frame(right_p, bg="white", bd=2, relief=tk.SUNKEN)
        self.rbg_canvas_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # State vars
        self.generated_bits = []
        self.rbg_math_steps = []
        self.rbg_idx = 0

    def start_rbg_simulation(self):
        choice = self.rbg_gen_choice.get()
        count_str = self.rbg_count_ent.get_value().strip()

        try:
            count = int(count_str) if count_str else 1000
            if count < 100:
                count = 100
        except ValueError:
            messagebox.showerror("Hata", "Lütfen adet için geçerli bir sayı girin.")
            return

        # Generator implementation calls
        if choice == "LCG":
            seed_str = self.lcg_seed_ent.get_value().strip()
            seed = int(seed_str) if seed_str else 12345
            self.generated_bits, self.rbg_math_steps = run_lcg(seed, count)
        else:
            p_str = self.bbs_p_ent.get_value().strip()
            q_str = self.bbs_q_ent.get_value().strip()
            seed_str = self.bbs_seed_ent.get_value().strip()

            p = int(p_str) if p_str else 383
            q = int(q_str) if q_str else 503
            seed = int(seed_str) if seed_str else 10135

            # Prime and modular checks for BBS
            if p % 4 != 3 or q % 4 != 3:
                messagebox.showwarning("Uyarı", "NIST Kuralı: Blum Blum Shub için p ve q asalları 3 mod 4'e denk olmalıdır (Örn: 383, 503).")
            
            self.generated_bits, self.rbg_math_steps = run_bbs(p, q, seed, count)

        self.rbg_idx = 0
        self.show_rbg_step()
        self.run_randomness_tests()

    def show_rbg_step(self):
        if not self.rbg_math_steps:
            return
        step = self.rbg_math_steps[self.rbg_idx]
        self.lbl_rbg_step.config(text=f"Adım: {self.rbg_idx + 1} / {len(self.rbg_math_steps)}")

        # Log details
        self.txt_rbg_log.config(state=tk.NORMAL)
        self.txt_rbg_log.delete("1.0", tk.END)
        
        log_txt = f"ÜRETİCİ ADIM DETAYI (Adım {step['idx']})\n"
        log_txt += f"Seçilen Yöntem: {self.rbg_gen_choice.get()}\n\n"
        log_txt += f"Formül: {step['formula']}\n"
        log_txt += f"Yeni Durum (State): {step['state']}\n"
        log_txt += f"Üretilen Rastgele Bit: {step['bit']}\n\n"
        
        # Display bit stream preview
        preview = "".join(str(b) for b in self.generated_bits[:100])
        log_txt += f"İlk 100 Bit Dizisi Önizleme:\n{preview}...\n"
        
        self.txt_rbg_log.insert("1.0", log_txt)
        self.txt_rbg_log.config(state=tk.DISABLED)

    def prev_rbg_step(self):
        if self.rbg_idx > 0:
            self.rbg_idx -= 1
            self.show_rbg_step()

    def next_rbg_step(self):
        if self.rbg_idx < len(self.rbg_math_steps) - 1:
            self.rbg_idx += 1
            self.show_rbg_step()

    def run_randomness_tests(self):
        if not self.generated_bits:
            return
        # Calculate NIST p-values and evaluation states
        mono_res = monobit_test(self.generated_bits)
        runs_res = runs_test(self.generated_bits)
        serial_res = serial_test(self.generated_bits)

        # Plot charts to canvas frame
        plot_rbg_stats(self.rbg_canvas_frame, self.generated_bits, mono_res, runs_res, serial_res)

if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()
