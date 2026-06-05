import unittest
import hashlib
import hmac
import math
import random
from crypto_logic import (
    gf_add, gf_mul, gf_inverse, aes_affine_transform, aes_sbox_calc,
    aes_encrypt_steps, des_encrypt_steps, triple_des_encrypt_steps,
    sha256_steps, hmac_sha256_steps,
    run_lcg, run_bbs, monobit_test, runs_test, serial_test
)

class TestCryptographicLogic(unittest.TestCase):

    def test_gf_arithmetic(self):
        # Addition in GF(2^8) is XOR
        self.assertEqual(gf_add(0x57, 0x83), 0x57 ^ 0x83)
        self.assertEqual(gf_add(0x00, 0xFF), 0xFF)
        
        # Multiplication in GF(2^8) (standard examples)
        # 0x57 * 0x02 = 0xAE
        self.assertEqual(gf_mul(0x57, 0x02), 0xAE)
        # 0x57 * 0x04 = 0x47 (0xAE * 2 = 0x15C ^ 0x1B = 0x147 & 0xFF = 0x47)
        self.assertEqual(gf_mul(0x57, 0x04), 0x47)
        # 0x57 * 0x08 = 0x8E
        self.assertEqual(gf_mul(0x57, 0x08), 0x8E)
        
        # Inverse in GF(2^8)
        # 0x53 inverse is 0xCA (or check that in * inv == 1)
        for val in range(1, 256):
            inv = gf_inverse(val)
            self.assertEqual(gf_mul(val, inv), 1)
        # 0 inverse is 0
        self.assertEqual(gf_inverse(0), 0)

    def test_sbox_calculation(self):
        # S-Box value for 0x53 is 0xED
        self.assertEqual(aes_sbox_calc(0x53), 0xED)
        # S-Box value for 0x00 is 0x63
        self.assertEqual(aes_sbox_calc(0x00), 0x63)

    def test_aes_encrypt_steps(self):
        # Test AES encrypt steps output length and final block length
        pt = b"AES_TEST_BLOCK_1"  # 16 bytes
        key = b"AES_SECRET_KEY_1"  # 16 bytes
        cipher, steps = aes_encrypt_steps(pt, key)
        
        self.assertEqual(len(cipher), 16)
        # 1 init + 1 round 0 addkey + 9 turs * 4 sub-steps + 1 round 10 * 3 sub-steps = 41 steps
        self.assertEqual(len(steps), 41)
        self.assertEqual(steps[0]['name'], 'Girdi Matrisi (State)')
        self.assertEqual(steps[-1]['name'], 'AddRoundKey (Round 10) - Şifreli Metin')

    def test_des_encrypt_steps(self):
        # DES 64-bit plaintext and key
        pt_bin = '0' * 64
        key_bin = '0' * 64
        cipher_bin, steps = des_encrypt_steps(pt_bin, key_bin)
        
        self.assertEqual(len(cipher_bin), 64)
        # init, IP, 16 rounds, swap, FP = 20 steps
        self.assertEqual(len(steps), 20)
        self.assertEqual(steps[0]['name'], 'Girdi Bloğu')
        self.assertEqual(steps[1]['name'], 'Initial Permutation (IP)')
        self.assertEqual(steps[-1]['name'], 'Final Permutation (IP-1) - Şifreli Metin')

    def test_sha256_correctness(self):
        msg = b"Hello, cryptoworld!"
        hash_res, steps = sha256_steps(msg)
        
        # Compare with Python's hashlib.sha256
        expected = hashlib.sha256(msg).hexdigest()
        self.assertEqual(hash_res, expected)
        # Check that steps were recorded
        self.assertTrue(len(steps) > 2)

    def test_hmac_sha256_correctness(self):
        msg = b"HMAC authentication message"
        key = b"MyHmacSecretKey"
        hmac_res, steps = hmac_sha256_steps(msg, key)
        
        # Compare with Python's hmac library
        expected = hmac.new(key, msg, hashlib.sha256).hexdigest()
        self.assertEqual(hmac_res, expected)
        self.assertEqual(len(steps), 3)

    def test_randomness_nist_calculations(self):
        # Run tests on a known highly non-random sequence (all zeros)
        zeros = [0] * 1000
        p_mono, pass_mono = monobit_test(zeros)
        self.assertFalse(pass_mono)  # Must fail
        self.assertLess(p_mono, 0.01)

        # Run tests on a known random sequence
        # We simulate a balanced coin toss sequence
        random.seed(42)
        rand_bits = [random.randint(0, 1) for _ in range(1000)]
        p_m, pass_m = monobit_test(rand_bits)
        p_r, pass_r = runs_test(rand_bits)
        p_s, pass_s = serial_test(rand_bits)
        
        # Check that a true random sequence has a high probability of passing
        # (Though technically it can fail, with seed 42 it should pass)
        self.assertTrue(pass_m)
        self.assertTrue(pass_r)
        self.assertTrue(pass_s)

if __name__ == "__main__":
    unittest.main()
