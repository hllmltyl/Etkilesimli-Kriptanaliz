import string
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.patches as patches

# Clean up existing widgets in a frame
def clear_frame(frame):
    for widget in frame.winfo_children():
        widget.destroy()

# Common style for retro Windows 98 aesthetics
def apply_win98_style(fig, ax):
    fig.patch.set_facecolor('#c0c0c0')  # Retro grey
    if isinstance(ax, (list, np.ndarray)):
        for a in ax:
            a.set_facecolor('#ffffff')
            a.tick_params(colors='black', labelsize=8)
            for spine in a.spines.values():
                spine.set_edgecolor('#808080')
                spine.set_linewidth(1.5)
    else:
        ax.set_facecolor('#ffffff')
        ax.tick_params(colors='black', labelsize=8)
        for spine in ax.spines.values():
            spine.set_edgecolor('#808080')
            spine.set_linewidth(1.5)

# =====================================================================
# 1. AES STATE MATRIX DRAWING
# =====================================================================

def draw_single_matrix(ax, matrix, title, highlight_cells=None, highlight_color='#aaccff'):
    ax.clear()
    ax.set_title(title, fontsize=9, fontweight='bold', pad=8)
    
    # Hide grid and axes
    ax.axis('off')
    
    # Draw cells
    for r in range(4):
        for c in range(4):
            val = matrix[r][c]
            facecolor = '#ffffff'
            if highlight_cells and (r, c) in highlight_cells:
                facecolor = highlight_color
                
            # Draw rectangle (coordinates: x=c, y=3-r)
            rect = patches.Rectangle(
                (c, 3-r), 1, 1, 
                facecolor=facecolor, 
                edgecolor='#808080', 
                linewidth=1
            )
            ax.add_patch(rect)
            
            # Text inside cell
            ax.text(
                c + 0.5, 3-r + 0.5, 
                f"{val:02X}", 
                ha='center', va='center', 
                fontsize=10, fontweight='bold', fontfamily='monospace'
            )
            
    # Set limits
    ax.set_xlim(0, 4)
    ax.set_ylim(0, 4)
    ax.set_aspect('equal')

def plot_aes_state(master_frame, step_data):
    clear_frame(master_frame)
    
    stage = step_data.get('stage', 'init')
    state = step_data['state']
    title = step_data['name']
    
    fig = plt.Figure(figsize=(6.5, 3.2), dpi=100)
    fig.patch.set_facecolor('#c0c0c0')
    
    if stage == 'addkey':
        # Draw: State + RoundKey = Output
        ax1 = fig.add_subplot(131)
        ax2 = fig.add_subplot(132)
        ax3 = fig.add_subplot(133)
        
        draw_single_matrix(ax1, state, "Mevcut Durum")
        
        key_matrix = step_data.get('key', [[0]*4 for _ in range(4)])
        draw_single_matrix(ax2, key_matrix, "Round Anahtarı", highlight_color='#ffccaa')
        
        # Calculate XOR output to show final state after addroundkey
        xor_result = [[state[r][c] ^ key_matrix[r][c] for c in range(4)] for r in range(4)]
        draw_single_matrix(ax3, xor_result, "XOR Çıktısı", highlight_cells=[(r,c) for r in range(4) for c in range(4)], highlight_color='#ccffcc')
        
    elif stage == 'sub':
        # Draw: Before Sub -> After Sub
        ax1 = fig.add_subplot(121)
        ax2 = fig.add_subplot(122)
        
        # We simulate previous state or just highlight changed bytes
        draw_single_matrix(ax1, state, "Değişim Öncesi")
        draw_single_matrix(ax2, state, "S-Box Sonrası (Değişti)", highlight_cells=[(r,c) for r in range(4) for c in range(4)], highlight_color='#ccffcc')
        
    elif stage == 'shift':
        # Draw shifted state with highlighted row offsets
        ax1 = fig.add_subplot(111)
        # Highlight row shifts: Row 1, 2, 3 in different colors
        h_cells = []
        for r in range(1, 4):
            for c in range(4):
                h_cells.append((r, c))
        draw_single_matrix(ax1, state, "Satır Kaydırma (ShiftRows) Sonucu", highlight_cells=h_cells, highlight_color='#eebbff')
        
    elif stage == 'mix':
        # Draw columns mixed
        ax1 = fig.add_subplot(111)
        # Highlight all mixed columns
        h_cells = [(r, c) for r in range(4) for c in range(4)]
        draw_single_matrix(ax1, state, "Sütun Karıştırma (MixColumns) Sonucu", highlight_cells=h_cells, highlight_color='#ffffcc')
        
    else:
        # Default single matrix
        ax1 = fig.add_subplot(111)
        draw_single_matrix(ax1, state, title)
        
    fig.tight_layout()
    canvas = FigureCanvasTkAgg(fig, master=master_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)

# =====================================================================
# 2. GALOIS FIELD GF(2^8) ARITHMETIC VISUALIZER
# =====================================================================

def plot_gf28_mul(master_frame, a, b):
    clear_frame(master_frame)
    
    fig = plt.Figure(figsize=(6.5, 3.2), dpi=100)
    fig.patch.set_facecolor('#c0c0c0')
    ax = fig.add_subplot(111)
    ax.set_facecolor('#ffffff')
    ax.axis('off')
    
    # Run Russian Peasant multiplication step-by-step and write on screen
    lines = []
    lines.append(f"GF(2^8) Çarpım: 0x{a:02X} * 0x{b:02X} (Polinom Mod: x^8 + x^4 + x^3 + x + 1 / 0x11B)")
    lines.append("--------------------------------------------------------------------------------")
    
    p = 0
    temp_a = a
    temp_b = b
    
    lines.append(f"Başlangıç: A = 0x{temp_a:02X}, B = 0x{temp_b:02X}, Ürün (P) = 0x{p:02X}\n")
    
    for i in range(8):
        bit = temp_b & 1
        act_str = ""
        xor_str = ""
        
        if bit:
            prev_p = p
            p ^= temp_a
            act_str = f"P = P ⊕ A => 0x{prev_p:02X} ⊕ 0x{temp_a:02X} = 0x{p:02X}"
        else:
            act_str = "B'nin LSB'si 0, P değişmedi."
            
        # Shift A and check overflow
        hi_set = temp_a & 0x80
        prev_a = temp_a
        temp_a = (temp_a << 1) & 0xFF
        
        if hi_set:
            temp_a ^= 0x1B
            xor_str = f"A sola kaydırıldı, MSB 1 idi. Modulo indirgeme (⊕ 0x1B): A = 0x{temp_a:02X}"
        else:
            xor_str = f"A sola kaydırıldı, MSB 0 idi. İndirgeme yapılmadı: A = 0x{temp_a:02X}"
            
        lines.append(f"Adım {i+1} (B = {temp_b:08b}):")
        lines.append(f"  -> {act_str}")
        lines.append(f"  -> {xor_str}")
        
        temp_b >>= 1
        if temp_b == 0 and p != 0:
            lines.append("  -> B sıfırlandı, çarpma tamamlanıyor.")
            break
            
    lines.append("--------------------------------------------------------------------------------")
    lines.append(f"Nihai GF(2^8) Çarpım Sonucu: 0x{a:02X} * 0x{b:02X} = 0x{p:02X}")
    
    # Write text to figure
    text_content = "\n".join(lines)
    ax.text(
        0.02, 0.98, text_content, 
        ha='left', va='top', 
        fontsize=8.5, fontfamily='monospace', 
        transform=ax.transAxes, color='black'
    )
    
    fig.tight_layout()
    canvas = FigureCanvasTkAgg(fig, master=master_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)

# =====================================================================
# 3. DES FEISTEL BLOCK DIAGRAM VISUALIZATION
# =====================================================================

def plot_des_state(master_frame, step_data):
    clear_frame(master_frame)
    
    stage = step_data.get('stage', 'init')
    title = step_data['name']
    
    fig = plt.Figure(figsize=(6.5, 3.2), dpi=100)
    fig.patch.set_facecolor('#c0c0c0')
    ax = fig.add_subplot(111)
    ax.set_facecolor('#ffffff')
    ax.axis('off')
    
    # Title
    ax.text(0.5, 0.93, title, ha='center', va='center', fontsize=10, fontweight='bold')
    
    if stage == 'round':
        l_val = step_data.get('L', '0'*32)
        r_val = step_data.get('R', '0'*32)
        subkey = step_data.get('subkey', '0'*48)
        f_out = step_data.get('f_out', '0'*32)
        
        # Display registers
        # Left Register Box
        rect_l = patches.Rectangle((0.1, 0.6), 0.35, 0.15, facecolor='#ccffcc', edgecolor='#808080', linewidth=1.5)
        ax.add_patch(rect_l)
        ax.text(0.275, 0.675, f"L (Sol Yarı)\nHex: {int(l_val, 2):08X}", ha='center', va='center', fontsize=9, fontweight='bold')
        
        # Right Register Box
        rect_r = patches.Rectangle((0.55, 0.6), 0.35, 0.15, facecolor='#ffcccc', edgecolor='#808080', linewidth=1.5)
        ax.add_patch(rect_r)
        ax.text(0.725, 0.675, f"R (Sağ Yarı)\nHex: {int(r_val, 2):08X}", ha='center', va='center', fontsize=9, fontweight='bold')
        
        # Feistel F-Function Box
        rect_f = patches.Rectangle((0.55, 0.3), 0.35, 0.15, facecolor='#ffffcc', edgecolor='#808080', linewidth=1.5)
        ax.add_patch(rect_f)
        ax.text(0.725, 0.375, f"Feistel Fonksiyonu (F)\nSubkey: {int(subkey, 2):012X}", ha='center', va='center', fontsize=8)
        
        # XOR Circle
        xor_circle = patches.Circle((0.275, 0.375), 0.05, facecolor='#ddffdd', edgecolor='#808080', linewidth=1.5)
        ax.add_patch(xor_circle)
        ax.text(0.275, 0.375, "⊕", ha='center', va='center', fontsize=14, fontweight='bold')
        
        # Draw arrows/paths
        # R_prev splits: 
        # 1. goes to L_next (straight down to 0.1)
        # 2. goes to F-Box
        ax.annotate('', xy=(0.725, 0.45), xytext=(0.725, 0.6), arrowprops=dict(arrowstyle="->", color='#808080', lw=1.5))
        ax.annotate('', xy=(0.325, 0.375), xytext=(0.55, 0.375), arrowprops=dict(arrowstyle="->", color='#808080', lw=1.5))
        
        # L_prev goes to XOR
        ax.annotate('', xy=(0.275, 0.425), xytext=(0.275, 0.6), arrowprops=dict(arrowstyle="->", color='#808080', lw=1.5))
        
        # XOR output goes down to next R
        ax.annotate('', xy=(0.275, 0.1), xytext=(0.275, 0.325), arrowprops=dict(arrowstyle="->", color='#808080', lw=1.5))
        
        # Cross-over showing L_next = R_prev
        ax.annotate('', xy=(0.725, 0.1), xytext=(0.725, 0.3), arrowprops=dict(arrowstyle="->", color='#808080', lw=1.5))
        
        # Next round status indicators at the bottom
        ax.text(0.275, 0.05, f"Sonraki L (R_prev)\n{int(r_val, 2):08X}", ha='center', va='center', fontsize=8, color='#555555')
        ax.text(0.725, 0.05, f"Sonraki R (L ⊕ F)\n{(int(l_val, 2) ^ int(f_out, 2)):08X}", ha='center', va='center', fontsize=8, color='#555555')
        
    else:
        # Initial/Final permutation view
        bits = step_data.get('bits', '0'*64)
        ax.text(0.5, 0.6, f"Mevcut Blok (64-bit):\n0x{int(bits, 2):016X}", ha='center', va='center', fontsize=11, fontfamily='monospace', fontweight='bold')
        ax.text(0.5, 0.3, f"Açıklama:\n{step_data['desc']}", ha='center', va='center', fontsize=9, wrap=True)
        
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    
    canvas = FigureCanvasTkAgg(fig, master=master_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)

# =====================================================================
# 4. SHA-256 REGISTERS VISUALIZATION
# =====================================================================

def plot_sha256_state(master_frame, step_data):
    clear_frame(master_frame)
    
    stage = step_data.get('stage', 'init')
    title = step_data['name']
    h_regs = step_data.get('h', [0]*8)
    
    fig = plt.Figure(figsize=(6.5, 3.2), dpi=100)
    fig.patch.set_facecolor('#c0c0c0')
    ax = fig.add_subplot(111)
    ax.set_facecolor('#ffffff')
    ax.axis('off')
    
    ax.text(0.5, 0.93, title, ha='center', va='center', fontsize=9.5, fontweight='bold')
    
    # Draw 8 registers horizontally
    reg_names = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H']
    
    for i in range(8):
        name = reg_names[i]
        val = h_regs[i]
        
        # Draw box
        x = 0.04 + i * 0.115
        rect = patches.Rectangle((x, 0.4), 0.105, 0.3, facecolor='#e6f2ff', edgecolor='#808080', linewidth=1.5)
        ax.add_patch(rect)
        
        ax.text(x + 0.052, 0.62, name, ha='center', va='center', fontsize=11, fontweight='bold', color='#1f538d')
        ax.text(x + 0.052, 0.48, f"{val:08X}", ha='center', va='center', fontsize=7.5, fontfamily='monospace', fontweight='bold', rotation=90)
        
    if stage == 'compress':
        # Show message schedule W_t and K_t at the bottom
        w_curr = step_data.get('w_curr', 0)
        k_curr = step_data.get('k_curr', 0)
        ax.text(0.25, 0.2, f"W[t]: 0x{w_curr:08X}", ha='center', va='center', fontsize=8.5, fontfamily='monospace', fontweight='bold', bbox=dict(facecolor='#ffffcc', alpha=0.5))
        ax.text(0.75, 0.2, f"K[t]: 0x{k_curr:08X}", ha='center', va='center', fontsize=8.5, fontfamily='monospace', fontweight='bold', bbox=dict(facecolor='#ffcccc', alpha=0.5))
        
        # Show arrows of data shifting
        for i in range(7):
            x_start = 0.04 + i * 0.115 + 0.052
            x_end = 0.04 + (i + 1) * 0.115 + 0.052
            # Draw shift arrow from register i to register i+1
            if i != 3: # A->B->C->D and E->F->G->H
                ax.annotate('', xy=(x_end, 0.35), xytext=(x_start, 0.35), arrowprops=dict(arrowstyle="->", color='#808080', connectionstyle="arc3,rad=.5", lw=1))
        
    ax.text(0.5, 0.06, step_data['desc'][:100] + "...", ha='center', va='center', fontsize=8, wrap=True)
    
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    
    canvas = FigureCanvasTkAgg(fig, master=master_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)

# =====================================================================
# 5. HMAC FLOW CHART VISUALIZATION
# =====================================================================

def plot_hmac_flow(master_frame, step_data):
    clear_frame(master_frame)
    
    stage = step_data.get('stage', 'hmac_key')
    title = step_data['name']
    
    fig = plt.Figure(figsize=(6.5, 3.2), dpi=100)
    fig.patch.set_facecolor('#c0c0c0')
    ax = fig.add_subplot(111)
    ax.set_facecolor('#ffffff')
    ax.axis('off')
    
    ax.text(0.5, 0.92, title, ha='center', va='center', fontsize=10, fontweight='bold')
    
    # Draw flowchart blocks
    # Stage 1: Key Pad Block
    c1 = '#ccffcc' if stage == 'hmac_key' else '#ffffff'
    rect1 = patches.Rectangle((0.05, 0.5), 0.25, 0.25, facecolor=c1, edgecolor='#808080', linewidth=1.5)
    ax.add_patch(rect1)
    ax.text(0.175, 0.625, "Adım 1\nK0, ipad, opad\nHesaplama", ha='center', va='center', fontsize=8.5, fontweight='bold')
    
    # Stage 2: Inner Hash Block
    c2 = '#ccffcc' if stage == 'hmac_inner' else '#ffffff'
    rect2 = patches.Rectangle((0.375, 0.5), 0.25, 0.25, facecolor=c2, edgecolor='#808080', linewidth=1.5)
    ax.add_patch(rect2)
    ax.text(0.5, 0.625, "Adım 2\nİç Hash (Inner)\nSHA-256(ipad || Msg)", ha='center', va='center', fontsize=8, fontweight='bold')
    
    # Stage 3: Outer Hash Block
    c3 = '#ccffcc' if stage == 'hmac_outer' else '#ffffff'
    rect3 = patches.Rectangle((0.7, 0.5), 0.25, 0.25, facecolor=c3, edgecolor='#808080', linewidth=1.5)
    ax.add_patch(rect3)
    ax.text(0.825, 0.625, "Adım 3\nDış Hash (Outer)\nSHA-256(opad || i_hash)", ha='center', va='center', fontsize=8, fontweight='bold')
    
    # Draw connector arrows
    ax.annotate('', xy=(0.375, 0.625), xytext=(0.3, 0.625), arrowprops=dict(arrowstyle="->", color='black', lw=1.5))
    ax.annotate('', xy=(0.7, 0.625), xytext=(0.625, 0.625), arrowprops=dict(arrowstyle="->", color='black', lw=1.5))
    
    # Draw explanation text box at the bottom
    ax.text(0.5, 0.2, step_data['desc'], ha='center', va='center', fontsize=8.5, wrap=True, bbox=dict(facecolor='#f2f2f2', edgecolor='#cccccc'))
    
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    
    canvas = FigureCanvasTkAgg(fig, master=master_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)

# =====================================================================
# 6. RBG RANDOMNESS STATISTICAL CHART VISUALIZATION
# =====================================================================

def plot_rbg_stats(master_frame, bits, monobit_res, runs_res, serial_res):
    clear_frame(master_frame)
    
    fig = plt.Figure(figsize=(6.8, 3.2), dpi=100)
    fig.patch.set_facecolor('#c0c0c0')
    
    # Subplot 1: Frequency bar chart (0 vs 1)
    ax1 = fig.add_subplot(121)
    ax1.set_facecolor('#ffffff')
    
    n0 = bits.count(0)
    n1 = bits.count(1)
    
    ax1.bar(['0', '1'], [n0, n1], color=['#c34a4a', '#1f538d'], width=0.5)
    ax1.set_title("Bit Frekans Dağılımı", fontsize=9, fontweight='bold')
    ax1.set_ylabel("Tekrar Sayısı", fontsize=8)
    
    # Add labels on top of bars
    ax1.text(0, n0/2, str(n0), ha='center', va='center', color='white', fontweight='bold')
    ax1.text(1, n1/2, str(n1), ha='center', va='center', color='white', fontweight='bold')
    
    # Subplot 2: Statistical text dashboard
    ax2 = fig.add_subplot(122)
    ax2.set_facecolor('#ffffff')
    ax2.axis('off')
    
    p_mono, pass_mono = monobit_res
    p_runs, pass_runs = runs_res
    p_serial, pass_serial = serial_res
    
    lines = []
    lines.append("NIST RASTGELELİK TEST SONUÇLARI")
    lines.append("-----------------------------------------------------------------")
    lines.append(f"Toplam Üretilen Bit Sayısı: {len(bits)}")
    lines.append("")
    
    st_mono = "BAŞARILI (Pass)" if pass_mono else "BAŞARISIZ (Fail)"
    lines.append(f"1. Monobit (Frekans) Testi:")
    lines.append(f"   p-değeri: {p_mono:.5f} | Sonuç: {st_mono}")
    
    st_runs = "BAŞARILI (Pass)" if pass_runs else "BAŞARISIZ (Fail)"
    lines.append(f"2. Blok İçi Değişim (Runs) Testi:")
    lines.append(f"   p-değeri: {p_runs:.5f} | Sonuç: {st_runs}")
    
    st_serial = "BAŞARILI (Pass)" if pass_serial else "BAŞARISIZ (Fail)"
    lines.append(f"3. Ardışık 2-Bit (Serial) Testi:")
    lines.append(f"   p-değeri: {p_serial:.5f} | Sonuç: {st_serial}")
    
    lines.append("-----------------------------------------------------------------")
    lines.append("NIST Kuralı: p-değeri >= 0.01 ise rastgeledir.")
    
    text_content = "\n".join(lines)
    ax2.text(
        0.05, 0.95, text_content, 
        ha='left', va='top', 
        fontsize=8.5, fontfamily='monospace', 
        transform=ax2.transAxes, color='black'
    )
    
    # Polish border for plots
    for ax in [ax1, ax2]:
        for spine in ax.spines.values():
            spine.set_edgecolor('#808080')
            spine.set_linewidth(1.5)
            
    fig.tight_layout()
    canvas = FigureCanvasTkAgg(fig, master=master_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)

# =====================================================================
# 7. S-BOX STEP DERIVATION VISUALIZATION
# =====================================================================

def plot_sbox_calc(master_frame, b):
    clear_frame(master_frame)
    fig = plt.Figure(figsize=(6.5, 3.2), dpi=100)
    fig.patch.set_facecolor('#c0c0c0')
    ax = fig.add_subplot(111)
    ax.set_facecolor('#ffffff')
    ax.axis('off')
    
    from crypto_logic import gf_inverse, aes_affine_transform
    inv = gf_inverse(b)
    aff = aes_affine_transform(inv)
    
    lines = []
    lines.append(f"AES S-Box Adım Adım Hesaplama: Giriş = 0x{b:02X}")
    lines.append("--------------------------------------------------------------------------------")
    poly_terms = [f"x^{7-i}" for i in range(8) if (b >> (7-i)) & 1]
    poly_str = " + ".join(poly_terms) if poly_terms else "0"
    lines.append(f"Polinom Temsili: {poly_str}")
    lines.append("")
    lines.append(f"Adım 1: GF(2^8) Galois Alanı Çarpımsal Tersi Bulma")
    lines.append(f"  -> Giriş 0x{b:02X} için çarpımsal ters: 0x{inv:02X}")
    if inv != 0:
        lines.append(f"  -> Doğrulama: 0x{b:02X} * 0x{inv:02X} mod (x^8+x^4+x^3+x+1) = 1")
    else:
        lines.append(f"  -> Özel Durum: 0x00 elemanının tersi yine 0x00 olarak tanımlanmıştır.")
    lines.append("")
    lines.append(f"Adım 2: Afin Dönüşüm Uygulama (Affine Transformation)")
    lines.append(f"  -> Ters Değer: 0x{inv:02X} ({inv:08b} ikili tabanda)")
    lines.append(f"  -> Afin Formülü: s_i = inv_i ⊕ inv_(i+4)%8 ⊕ inv_(i+5)%8 ⊕ inv_(i+6)%8 ⊕ inv_(i+7)%8 ⊕ c_i")
    lines.append(f"  -> Sabit c = 0x63 (01100011)")
    lines.append(f"  -> Dönüşüm Çıktısı: 0x{aff:02X} ({aff:08b} ikili tabanda)")
    lines.append("--------------------------------------------------------------------------------")
    lines.append(f"Nihai S-Box Değeri: S_BOX[0x{b:02X}] = 0x{aff:02X}")
    
    text_content = "\n".join(lines)
    ax.text(
        0.02, 0.98, text_content, 
        ha='left', va='top', 
        fontsize=8.5, fontfamily='monospace', 
        transform=ax.transAxes, color='black'
    )
    
    fig.tight_layout()
    canvas = FigureCanvasTkAgg(fig, master=master_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)
