import math
import random

# =====================================================================
# 1. HELPER CONVERSIONS
# =====================================================================

def bytes_to_bin(b):
    return ''.join(f'{x:08b}' for x in b)

def bin_to_bytes(s):
    return bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8))

def hex_to_bin(h, length=64):
    try:
        val = bin(int(h, 16))[2:].zfill(length)
        if len(val) > length:
            val = val[-length:]
        return val
    except ValueError:
        return '0' * length

def bin_to_hex(b):
    return f'{int(b, 2):0{len(b)//4}X}'

def text_to_bytes(t):
    return t.encode('utf-8')

def bytes_to_hex(b):
    return b.hex().upper()

def hex_to_bytes(h):
    try:
        return bytes.fromhex(h)
    except ValueError:
        return b''

# =====================================================================
# 2. GALOIS FIELD GF(2^8) ARITHMETIC (For AES)
# =====================================================================

def gf_add(a, b):
    # GF(2^8) addition is bitwise XOR
    return a ^ b

def gf_mul(a, b):
    # Russian Peasant Multiplication modulo 0x11B (x^8 + x^4 + x^3 + x + 1)
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1B  # 0x11B & 0xFF
        b >>= 1
    return p

def gf_inverse(a):
    if a == 0:
        return 0
    # Brute force search since elements are small
    for i in range(1, 256):
        if gf_mul(a, i) == 1:
            return i
    return 0

def aes_affine_transform(b):
    # AES Affine Transformation: s = A * x^-1 + c
    # c = 0x63 (01100011 in binary, LSB first)
    c = 0x63
    s = 0
    for i in range(8):
        bit = (
            ((b >> i) & 1) ^
            ((b >> ((i + 4) % 8)) & 1) ^
            ((b >> ((i + 5) % 8)) & 1) ^
            ((b >> ((i + 6) % 8)) & 1) ^
            ((b >> ((i + 7) % 8)) & 1) ^
            ((c >> i) & 1)
        )
        s |= (bit << i)
    return s

def aes_sbox_calc(b):
    inv = gf_inverse(b)
    return aes_affine_transform(inv)

# Generate S-Box and Inv S-Box
S_BOX = [aes_sbox_calc(i) for i in range(256)]
INV_S_BOX = [0] * 256
for i, x in enumerate(S_BOX):
    INV_S_BOX[x] = i

# =====================================================================
# 3. AES-128 STATE TRANSFORMATIONS
# =====================================================================

def sub_bytes(state):
    return [[S_BOX[x] for x in row] for row in state]

def inv_sub_bytes(state):
    return [[INV_S_BOX[x] for x in row] for row in state]

def shift_rows(state):
    return [
        state[0][:],
        state[1][1:] + state[1][:1],
        state[2][2:] + state[2][:2],
        state[3][3:] + state[3][:3]
    ]

def inv_shift_rows(state):
    return [
        state[0][:],
        state[1][-1:] + state[1][:-1],
        state[2][-2:] + state[2][:-2],
        state[3][-3:] + state[3][:-3]
    ]

def mix_columns(state):
    # Matrix multiplication over GF(2^8) with:
    # 02 03 01 01
    # 01 02 03 01
    # 01 01 02 03
    # 03 01 01 02
    new_state = [[0]*4 for _ in range(4)]
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        new_state[0][c] = gf_mul(2, s0) ^ gf_mul(3, s1) ^ s2 ^ s3
        new_state[1][c] = s0 ^ gf_mul(2, s1) ^ gf_mul(3, s2) ^ s3
        new_state[2][c] = s0 ^ s1 ^ gf_mul(2, s2) ^ gf_mul(3, s3)
        new_state[3][c] = gf_mul(3, s0) ^ s1 ^ s2 ^ gf_mul(2, s3)
    return new_state

def inv_mix_columns(state):
    # Matrix multiplication over GF(2^8) with:
    # 0e 0b 0d 09
    # 09 0e 0b 0d
    # 0d 09 0e 0b
    # 0b 0d 09 0e
    new_state = [[0]*4 for _ in range(4)]
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        new_state[0][c] = gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3)
        new_state[1][c] = gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3)
        new_state[2][c] = gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3)
        new_state[3][c] = gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3)
    return new_state

def add_round_key(state, round_key):
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]

def key_expansion(key_bytes):
    # Expand 16 bytes key to 11 round keys
    if len(key_bytes) < 16:
        key_bytes = key_bytes.ljust(16, b'\x00')
    elif len(key_bytes) > 16:
        key_bytes = key_bytes[:16]
        
    words = []
    for i in range(4):
        words.append([key_bytes[4*i], key_bytes[4*i+1], key_bytes[4*i+2], key_bytes[4*i+3]])
        
    Rcon = [
        [0x00, 0x00, 0x00, 0x00],
        [0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00],
        [0x04, 0x00, 0x00, 0x00], [0x08, 0x00, 0x00, 0x00],
        [0x10, 0x00, 0x00, 0x00], [0x20, 0x00, 0x00, 0x00],
        [0x40, 0x00, 0x00, 0x00], [0x80, 0x00, 0x00, 0x00],
        [0x1B, 0x00, 0x00, 0x00], [0x36, 0x00, 0x00, 0x00]
    ]
    
    def rot_word(w):
        return w[1:] + w[:1]
        
    def sub_word(w):
        return [S_BOX[x] for x in w]
        
    def xor_words(w1, w2):
        return [x ^ y for x, y in zip(w1, w2)]
        
    for i in range(4, 44):
        temp = words[i-1]
        if i % 4 == 0:
            temp = xor_words(sub_word(rot_word(temp)), Rcon[i // 4])
        words.append(xor_words(words[i-4], temp))
        
    # Reassemble round keys (4x4 matrix per key)
    round_keys = []
    for r in range(11):
        rk_words = words[r*4:(r+1)*4]
        # Transpose words to form a column-major 4x4 matrix
        matrix = [[rk_words[c][r_idx] for c in range(4)] for r_idx in range(4)]
        round_keys.append(matrix)
    return round_keys

# =====================================================================
# 4. AES STEP-BY-STEP RECORDER
# =====================================================================

def aes_encrypt_steps(plaintext_bytes, key_bytes):
    # Ensure 16 bytes
    if len(plaintext_bytes) < 16:
        plaintext_bytes = plaintext_bytes.ljust(16, b'\x00')
    else:
        plaintext_bytes = plaintext_bytes[:16]
        
    # Build initial state column-major
    state = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] = plaintext_bytes[c*4 + r]
            
    round_keys = key_expansion(key_bytes)
    steps = []
    
    # Round 0: AddRoundKey
    steps.append({
        'name': 'Girdi Matrisi (State)',
        'round': 0,
        'state': [row[:] for row in state],
        'desc': 'Şifrelenecek 16 byte veri, 4x4 boyutunda bir durum (state) matrisine sütun-bazlı olarak yerleştirilir.',
        'stage': 'init'
    })
    
    state = add_round_key(state, round_keys[0])
    steps.append({
        'name': 'AddRoundKey (Round 0)',
        'round': 0,
        'state': [row[:] for row in state],
        'desc': 'Round 0: Durum matrisi başlangıç anahtarı (Round Key 0) ile XORlanır.',
        'key': round_keys[0],
        'stage': 'addkey'
    })
    
    # Round 1 to 9
    for r in range(1, 10):
        # SubBytes
        state = sub_bytes(state)
        steps.append({
            'name': f'SubBytes (Round {r})',
            'round': r,
            'state': [row[:] for row in state],
            'desc': f'Round {r}: Durum matrisindeki her bir byte, doğrusal olmayan AES S-Box tablosu kullanılarak değiştirilir.',
            'stage': 'sub'
        })
        
        # ShiftRows
        state = shift_rows(state)
        steps.append({
            'name': f'ShiftRows (Round {r})',
            'round': r,
            'state': [row[:] for row in state],
            'desc': f'Round {r}: Durum matrisinin satırları sola kaydırılır. 1. satır 0, 2. satır 1, 3. satır 2, 4. satır 3 byte kaydırılır.',
            'stage': 'shift'
        })
        
        # MixColumns
        state = mix_columns(state)
        # Record sample GF(2^8) formula calculation for the description
        col_calc = (
            f"MixColumns Galois Alanı GF(2^8) matris çarpımıdır:\n"
            f"Yeni C[0,0] = (02 * S[0,0]) + (03 * S[1,0]) + (01 * S[2,0]) + (01 * S[3,0])\n"
            f"Örnek çarpım: 02 * 0x{state[0][0]:02X} = 0x{gf_mul(2, state[0][0]):02X} (GF mod 0x11B)"
        )
        steps.append({
            'name': f'MixColumns (Round {r})',
            'round': r,
            'state': [row[:] for row in state],
            'desc': f'Round {r}: Sütunlar kendi aralarında karıştırılır. Galois Alanı GF(2^8) üzerinde özel bir matris ile çarpım yapılır.\n\n{col_calc}',
            'stage': 'mix'
        })
        
        # AddRoundKey
        state = add_round_key(state, round_keys[r])
        steps.append({
            'name': f'AddRoundKey (Round {r})',
            'round': r,
            'state': [row[:] for row in state],
            'desc': f'Round {r}: Durum matrisi bu round\'a ait anahtar (Round Key {r}) ile bit düzeyinde XORlanır.',
            'key': round_keys[r],
            'stage': 'addkey'
        })
        
    # Round 10: SubBytes, ShiftRows, AddRoundKey (No MixColumns)
    state = sub_bytes(state)
    steps.append({
        'name': 'SubBytes (Round 10)',
        'round': 10,
        'state': [row[:] for row in state],
        'desc': 'Round 10: Son round için ilk olarak doğrusal olmayan S-Box değişimi uygulanır.',
        'stage': 'sub'
    })
    
    state = shift_rows(state)
    steps.append({
        'name': 'ShiftRows (Round 10)',
        'round': 10,
        'state': [row[:] for row in state],
        'desc': 'Round 10: Satırlar sola dairesel olarak kaydırılır (0, 1, 2 ve 3 byte).',
        'stage': 'shift'
    })
    
    state = add_round_key(state, round_keys[10])
    steps.append({
        'name': 'AddRoundKey (Round 10) - Şifreli Metin',
        'round': 10,
        'state': [row[:] for row in state],
        'desc': 'Round 10: Son round anahtarı ile XORlanır. Elde edilen matris nihai şifreli bloktur.',
        'key': round_keys[10],
        'stage': 'addkey'
    })
    
    # Reassemble ciphertext
    ciphertext = bytearray(16)
    for r in range(4):
        for c in range(4):
            ciphertext[c*4 + r] = state[r][c]
            
    return bytes(ciphertext), steps

# =====================================================================
# 5. DES TABLES & ALGORITHM
# =====================================================================

DES_IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

DES_FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

DES_PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1,  58, 50, 42, 34, 26, 18,
    10, 2,  59, 51, 43, 35, 27,
    19, 11, 3,  60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7,  62, 54, 46, 38, 30, 22,
    14, 6,  61, 53, 45, 37, 29,
    21, 13, 5,  28, 20, 12, 4
]

DES_PC2 = [
    14, 17, 11, 24, 1,  5,
    3,  28, 15, 6,  21, 10,
    23, 19, 12, 4,  26, 8,
    16, 7,  27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

DES_E = [
    32, 1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9,  10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

DES_P = [
    16, 7,  20, 21,
    29, 12, 28, 17,
    1,  15, 23, 26,
    5,  18, 31, 10,
    2,  8,  24, 14,
    32, 27, 3,  9,
    19, 13, 30, 6,
    22, 11, 4,  25
]

DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

DES_SBOX = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

def permute(bits, table):
    return ''.join(bits[i-1] for i in table)

def des_key_schedule(key_bin):
    # key_bin is 64 bits string
    pc1_out = permute(key_bin, DES_PC1)  # 56 bits
    c = pc1_out[:28]
    d = pc1_out[28:]
    
    subkeys = []
    for r in range(16):
        shift = DES_SHIFTS[r]
        c = c[shift:] + c[:shift]
        d = d[shift:] + d[:shift]
        subkey = permute(c + d, DES_PC2)
        subkeys.append(subkey)
    return subkeys

def des_f(r_bits, subkey):
    # r_bits is 32 bits, subkey is 48 bits
    expanded = permute(r_bits, DES_E)
    xored = ''.join('1' if expanded[i] != subkey[i] else '0' for i in range(48))
    
    sbox_out = ""
    for i in range(8):
        block = xored[i*6 : (i+1)*6]
        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)
        val = DES_SBOX[i][row][col]
        sbox_out += f'{val:04b}'
        
    return permute(sbox_out, DES_P)

# =====================================================================
# 6. DES STEP-BY-STEP RECORDER
# =====================================================================

def des_encrypt_steps(plaintext_bin, key_bin):
    # Ensure inputs are binary strings of length 64
    if len(plaintext_bin) < 64:
        plaintext_bin = plaintext_bin.zfill(64)
    else:
        plaintext_bin = plaintext_bin[:64]
        
    if len(key_bin) < 64:
        key_bin = key_bin.zfill(64)
    else:
        key_bin = key_bin[:64]
        
    subkeys = des_key_schedule(key_bin)
    steps = []
    
    steps.append({
        'name': 'Girdi Bloğu',
        'round': 0,
        'bits': plaintext_bin,
        'desc': 'Girdi bloğu 64-bit uzunluğundadır.',
        'stage': 'init'
    })
    
    # Initial Permutation (IP)
    ip_out = permute(plaintext_bin, DES_IP)
    steps.append({
        'name': 'Initial Permutation (IP)',
        'round': 0,
        'bits': ip_out,
        'desc': 'Girdi bloğu bitleri IP matrisine göre yer değiştirilir.',
        'stage': 'ip'
    })
    
    l = ip_out[:32]
    r = ip_out[32:]
    
    # 16 Rounds of Feistel
    for round_idx in range(16):
        prev_l = l
        prev_r = r
        
        # Next L is previous R
        l = prev_r
        
        # Next R is L ^ F(R, Key)
        f_out = des_f(prev_r, subkeys[round_idx])
        r = ''.join('1' if prev_l[i] != f_out[i] else '0' for i in range(32))
        
        steps.append({
            'name': f'Round {round_idx + 1}',
            'round': round_idx + 1,
            'L': l,
            'R': r,
            'subkey': subkeys[round_idx],
            'f_out': f_out,
            'desc': (
                f'Round {round_idx+1}: Feistel yapısı çalıştırılır.\n'
                f'L[{round_idx+1}] = R[{round_idx}]\n'
                f'R[{round_idx+1}] = L[{round_idx}] ⊕ F(R[{round_idx}], Key[{round_idx+1}])\n'
                f'Round Anahtarı: 0x{bin_to_hex(subkeys[round_idx])}\n'
                f'Feistel Fonksiyon Çıktısı F: 0x{bin_to_hex(f_out)}'
            ),
            'stage': 'round'
        })
        
    # Final swap (pre-output is R16 + L16)
    pre_out = r + l
    steps.append({
        'name': '32-Bit Swap (L16, R16)',
        'round': 16,
        'bits': pre_out,
        'desc': '16. round sonrasında sol (L) ve sağ (R) yarılar yer değiştirilerek birleştirilir (R16 || L16).',
        'stage': 'swap'
    })
    
    # Inverse Initial Permutation (FP)
    fp_out = permute(pre_out, DES_FP)
    steps.append({
        'name': 'Final Permutation (IP-1) - Şifreli Metin',
        'round': 16,
        'bits': fp_out,
        'desc': 'Birleştirilmiş bloğa IP-1 (Ters IP) yer değişimi uygulanır. Çıkan 64-bit nihai şifreli bloğu oluşturur.',
        'stage': 'fp'
    })
    
    return fp_out, steps

def triple_des_encrypt_steps(plaintext_bin, k1, k2, k3):
    # 3-DES: Encrypt(k3) -> Decrypt(k2) -> Encrypt(k1) sequence
    # For visualization, we will trace the first DES encryption
    des1_out, steps1 = des_encrypt_steps(plaintext_bin, k1)
    
    # Decrypt with K2: which is same as running DES with reverse keys
    subkeys2 = des_key_schedule(k2)
    # Reverse subkeys for decryption
    subkeys2_rev = subkeys2[::-1]
    
    # Run decryption
    ip_out = permute(des1_out, DES_IP)
    l, r = ip_out[:32], ip_out[32:]
    for round_idx in range(16):
        prev_l, prev_r = l, r
        l = prev_r
        f_out = des_f(prev_r, subkeys2_rev[round_idx])
        r = ''.join('1' if prev_l[i] != f_out[i] else '0' for i in range(32))
    des2_out = permute(r + l, DES_FP)
    
    # Encrypt with K3
    des3_out, _ = des_encrypt_steps(des2_out, k3)
    
    # We prefix steps with 3-DES descriptions
    main_steps = []
    for s in steps1:
        s_copy = s.copy()
        s_copy['name'] = f"3-DES Aşama 1 (DES-K1) -> " + s_copy['name']
        main_steps.append(s_copy)
        
    main_steps.append({
        'name': '3-DES Aşama 2 (DES-K2 De-şifreleme)',
        'round': 17,
        'bits': des2_out,
        'desc': '3-DES Aşama 2: K1 ile şifrelenen blok, K2 anahtarı kullanılarak de-şifrelenir (Decrypt).',
        'stage': 'stage2'
    })
    
    main_steps.append({
        'name': '3-DES Aşama 3 (DES-K3 Şifreleme) - Sonuç',
        'round': 18,
        'bits': des3_out,
        'desc': '3-DES Aşama 3: K2 ile de-şifrelenen blok, K3 anahtarı kullanılarak tekrar şifrelenir (Encrypt). Bu nihai 3-DES çıktısıdır.',
        'stage': 'stage3'
    })
    
    return des3_out, main_steps

# =====================================================================
# 7. SHA-256 PURE PYTHON IMPLEMENTATION & STEP RECORDER
# =====================================================================

SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def sha256_pad(msg_bytes):
    # Padding msg to multiple of 512 bits (64 bytes)
    orig_len_bits = len(msg_bytes) * 8
    msg = bytearray(msg_bytes)
    # Append 0x80 (1 followed by 0s)
    msg.append(0x80)
    # Pad with 0s until congruent to 56 mod 64 (congruent to 448 mod 512 bits)
    while len(msg) % 64 != 56:
        msg.append(0)
    # Append original length as 64-bit big endian integer
    msg.extend(orig_len_bits.to_bytes(8, byteorder='big'))
    return bytes(msg)

def sha256_steps(msg_bytes):
    padded = sha256_pad(msg_bytes)
    
    # Hash values initialization
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19
    
    steps = []
    
    steps.append({
        'name': 'Girdi ve Padding Aşaması',
        'desc': (
            f"Orijinal Mesaj Boyutu: {len(msg_bytes)} byte ({len(msg_bytes)*8} bit).\n"
            f"Padding İşlemi: Mesaj sonuna 1 biti (0x80) eklenir ve 64 byte'ın katından 8 eksik olana kadar sıfırlar konur. "
            f"Son 8 byte'a ise orijinal bit uzunluğu büyük-endian formatında yazılır.\n"
            f"Padding Sonrası Boyut: {len(padded)} byte ({len(padded)*8} bit)."
        ),
        'h': [h0, h1, h2, h3, h4, h5, h6, h7],
        'w_curr': 0,
        'k_curr': 0,
        'round': 0,
        'stage': 'pad'
    })
    
    # Process each 512-bit block
    num_blocks = len(padded) // 64
    for b_idx in range(num_blocks):
        chunk = padded[b_idx*64:(b_idx+1)*64]
        
        # Create message schedule W (64 words of 32-bit)
        w = [0] * 64
        for i in range(16):
            w[i] = int.from_bytes(chunk[i*4:(i+1)*4], byteorder='big')
            
        for i in range(16, 64):
            w_15 = w[i-15]
            s0 = ((w_15 >> 7) | (w_15 << 25)) ^ ((w_15 >> 18) | (w_15 << 14)) ^ (w_15 >> 3)
            w_2 = w[i-2]
            s1 = ((w_2 >> 17) | (w_2 << 15)) ^ ((w_2 >> 19) | (w_2 << 13)) ^ (w_2 >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF
            
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        
        # 64 Rounds compression
        for t in range(64):
            S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + S1 + ch + SHA256_K[t] + w[t]) & 0xFFFFFFFF
            
            S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF
            
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF
            
            # We only record the compression steps for the first block to avoid huge logs
            if b_idx == 0:
                steps.append({
                    'name': f'Sıkıştırma Round {t} (Blok 1)',
                    'desc': (
                        f"Blok 1, Sıkıştırma Round {t}: A-H Yazmaçları güncellenir.\n"
                        f"Mesaj Kelimesi W[{t}]: 0x{w[t]:08X}, Sabit K[{t}]: 0x{SHA256_K[t]:08X}\n"
                        f"Mantıksal Fonksiyonlar: Ch(e,f,g) = 0x{ch:08X}, Maj(a,b,c) = 0x{maj:08X}\n"
                        f"T1 = h + Σ1(e) + Ch(e,f,g) + K[{t}] + W[{t}] = 0x{temp1:08X}"
                    ),
                    'h': [a, b, c, d, e, f, g, h],
                    'w_curr': w[t],
                    'k_curr': SHA256_K[t],
                    'round': t + 1,
                    'stage': 'compress'
                })
                
        # Update hash values
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF
        
        if b_idx == 0 and num_blocks > 1:
            steps.append({
                'name': 'Blok 1 Toplama Sonucu',
                'desc': (
                    f"İlk 512-bitlik bloğun işlenmesi bitti. Ara hash değerleri:\n"
                    f"h0-h7: {h0:08x} {h1:08x} {h2:08x} {h3:08x} {h4:08x} {h5:08x} {h6:08x} {h7:08x}"
                ),
                'h': [h0, h1, h2, h3, h4, h5, h6, h7],
                'w_curr': 0,
                'k_curr': 0,
                'round': 65,
                'stage': 'compress'
            })
            
    steps.append({
        'name': 'Nihai Hash Değeri',
        'desc': (
            f"Tüm blokların sıkıştırma adımları bitti.\n"
            f"Nihai Hash: {h0:08x}{h1:08x}{h2:08x}{h3:08x}{h4:08x}{h5:08x}{h6:08x}{h7:08x}"
        ),
        'h': [h0, h1, h2, h3, h4, h5, h6, h7],
        'w_curr': 0,
        'k_curr': 0,
        'round': 66,
        'stage': 'final'
    })
    
    final_hash = f"{h0:08x}{h1:08x}{h2:08x}{h3:08x}{h4:08x}{h5:08x}{h6:08x}{h7:08x}"
    return final_hash, steps

# =====================================================================
# 8. HMAC-SHA256 IMPLEMENTATION & STEP RECORDER
# =====================================================================

def hmac_sha256_steps(message_bytes, key_bytes):
    # HMAC-SHA256: Hash((Key ^ opad) || Hash((Key ^ ipad) || Message))
    block_size = 64
    
    # If key is longer than block size, hash it
    if len(key_bytes) > block_size:
        key_hash_hex, _ = sha256_steps(key_bytes)
        key_bytes = bytes.fromhex(key_hash_hex)
        
    # Pad key to block size with 0s
    k0 = key_bytes.ljust(block_size, b'\x00')
    
    # Compute ipad and opad XORs
    ipad = bytes(x ^ 0x36 for x in k0)
    opad = bytes(x ^ 0x5c for x in k0)
    
    # Inner block concat: ipad || message
    inner_data = ipad + message_bytes
    inner_hash_hex, inner_steps = sha256_steps(inner_data)
    inner_hash_bytes = bytes.fromhex(inner_hash_hex)
    
    # Outer block concat: opad || inner_hash
    outer_data = opad + inner_hash_bytes
    outer_hash_hex, outer_steps = sha256_steps(outer_data)
    
    steps = []
    
    steps.append({
        'name': 'HMAC Adım 1: Anahtar Hazırlama',
        'desc': (
            f"Girdi Anahtar Boyutu: {len(key_bytes)} byte. Anahtar 64 byte uzunluğuna sıfırlar ile doldurulur.\n"
            f"K0 Anahtarı: 0x{k0.hex().upper()[:32]}...\n\n"
            f"İç pad (ipad) değeri 0x36, dış pad (opad) değeri 0x5C'dir.\n"
            f"K0 ⊕ ipad = 0x{ipad.hex().upper()[:32]}...\n"
            f"K0 ⊕ opad = 0x{opad.hex().upper()[:32]}..."
        ),
        'k0': k0,
        'ipad': ipad,
        'opad': opad,
        'stage': 'hmac_key'
    })
    
    steps.append({
        'name': 'HMAC Adım 2: İç Hash Hesaplama (Inner Hash)',
        'desc': (
            f"İç veri oluşturulur: (K0 ⊕ ipad) || Mesaj.\n"
            f"İç veri boyutu: {len(inner_data)} byte.\n"
            f"İç Veri: 0x{inner_data.hex().upper()[:40]}...\n"
            f"Hesaplanan İç Hash: 0x{inner_hash_hex.upper()}"
        ),
        'inner_data': inner_data,
        'inner_hash': inner_hash_hex,
        'stage': 'hmac_inner'
    })
    
    steps.append({
        'name': 'HMAC Adım 3: Dış Hash Hesaplama (Outer Hash)',
        'desc': (
            f"Dış veri oluşturulur: (K0 ⊕ opad) || İç Hash.\n"
            f"Dış veri boyutu: {len(outer_data)} byte.\n"
            f"Dış Veri: 0x{outer_data.hex().upper()[:40]}...\n"
            f"Nihai HMAC-SHA256: 0x{outer_hash_hex.upper()}"
        ),
        'outer_data': outer_data,
        'hmac': outer_hash_hex,
        'stage': 'hmac_outer'
    })
    
    return outer_hash_hex, steps

# =====================================================================
# 9. RANDOM BIT GENERATION (RBG) & SIMULATION
# =====================================================================

def run_lcg(seed, count=1000):
    # Standard LCG: X_n+1 = (a * X_n + c) mod m
    # Using glibc parameters: a = 1103515245, c = 12345, m = 2^31
    a = 1103515245
    c = 12345
    m = 2**31
    state = seed
    
    bits = []
    math_steps = []
    
    for i in range(count):
        prev = state
        state = (a * state + c) % m
        # Extract LSB or MSB. Let's extract LSB for simulation
        bit = state & 1
        bits.append(bit)
        
        if i < 20:  # Record first 20 math steps
            math_steps.append({
                'idx': i + 1,
                'formula': f"X_{i+1} = ({a} * {prev} + {c}) mod {m}",
                'state': state,
                'bit': bit
            })
            
    return bits, math_steps

def run_bbs(p, q, seed, count=1000):
    # Blum Blum Shub (BBS): X_n+1 = X_n^2 mod M
    # M = p * q, where p and q are prime numbers congruent to 3 mod 4
    M = p * q
    state = (seed * seed) % M
    
    bits = []
    math_steps = []
    
    for i in range(count):
        prev = state
        state = (state * state) % M
        # Output is the parity bit or LSB. Let's use LSB (state % 2)
        bit = state % 2
        bits.append(bit)
        
        if i < 20:  # Record first 20 math steps
            math_steps.append({
                'idx': i + 1,
                'formula': f"X_{i+1} = ({prev}^2) mod {M}",
                'state': state,
                'bit': bit
            })
            
    return bits, math_steps

# =====================================================================
# 10. NIST STATISTICAL TESTS FOR RANDOMNESS
# =====================================================================

def monobit_test(bits):
    # Monobit Test (Frequency Test)
    n = len(bits)
    if n == 0:
        return 0.0, False
    # Convert bits to +1 and -1
    s_n = sum(1 if x == 1 else -1 for x in bits)
    s_obs = abs(s_n) / math.sqrt(n)
    # P-value = erfc(s_obs / sqrt(2))
    p_val = math.erfc(s_obs / math.sqrt(2.0))
    # Passed if p_val >= 0.01
    return p_val, p_val >= 0.01

def runs_test(bits):
    # Runs Test
    n = len(bits)
    if n == 0:
        return 0.0, False
    
    # Step 1: Pre-test: Frequency test proportion
    pi = sum(bits) / n
    # If proportion is not near 0.5, test fails automatically
    if abs(pi - 0.5) >= (2.0 / math.sqrt(n)):
        return 0.0, False
        
    # Step 2: Compute observed runs
    # Run is defined as consecutive identical bits
    v_obs = 1
    for i in range(n - 1):
        if bits[i] != bits[i+1]:
            v_obs += 1
            
    # Step 3: Compute P-value
    numerator = abs(v_obs - 2.0 * n * pi * (1.0 - pi))
    denominator = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)
    
    if denominator == 0:
        return 0.0, False
        
    s = numerator / denominator
    p_val = math.erfc(s)
    return p_val, p_val >= 0.01

def serial_test(bits):
    # Serial Test (Overlapping 2-bit transition test)
    n = len(bits)
    if n < 4:
        return 0.0, False
        
    # Count frequencies of single bits (0 and 1)
    n0 = bits.count(0)
    n1 = bits.count(1)
    
    # Count frequencies of 2-bit blocks (overlapping)
    # We append the first bit to the end to make it circular (per NIST spec)
    cbits = bits + [bits[0]]
    n00, n01, n10, n11 = 0, 0, 0, 0
    for i in range(n):
        block = (cbits[i], cbits[i+1])
        if block == (0, 0): n00 += 1
        elif block == (0, 1): n01 += 1
        elif block == (1, 0): n10 += 1
        elif block == (1, 1): n11 += 1
        
    # Compute psi_0^2 and psi_1^2 statistics
    # psi_0^2 = (4 / n) * (n00^2 + n01^2 + n10^2 + n11^2) - (2 / n) * (n0^2 + n1^2) + 1
    sum_n2_2 = n00**2 + n01**2 + n10**2 + n11**2
    sum_n2_1 = n0**2 + n1**2
    
    psi_1_sq = (4.0 / n) * sum_n2_2 - (2.0 / n) * sum_n2_1 + 1.0
    
    # Approximate P-value using Chi-square distribution with 2 degrees of freedom
    # P-value = exp(-psi_1_sq / 2)
    p_val = math.exp(-psi_1_sq / 2.0)
    return p_val, p_val >= 0.01
