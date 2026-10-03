# 各检测维度独立测试，验证去重行为，确认模糊匹配捕获混淆S-box且无误报泛滥
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crypto_detector import (
    CryptoDetector, CryptoFinding, detect_by_magic_constants,
    detect_by_structure, detect_by_api_strings, detect_hardware_accel,
    _bmh_search, _match_full_sbox, _fuzzy_match_sbox, _dedup,
)
from src.constants import AES_SBOX, SM4_SBOX, SHA256_IV, CHACHA20_CONSTANTS

Z = bytes(1)  # 单零字节，避免源码中含嵌入空字符


class TestBoyerMooreHorspool:
    def test_exact_match_start(self):
        assert _bmh_search(b'hello world', b'hello') == 0

    def test_exact_match_mid(self):
        assert _bmh_search(b'xxhelloyy', b'hello') == 2

    def test_no_match(self):
        assert _bmh_search(b'abcdef', b'xyz') == -1

    def test_empty_pattern(self):
        assert _bmh_search(b'data', b'') == -1

    def test_multi_hit(self):
        data = b'ABABAB'
        positions = []
        pos = _bmh_search(data, b'AB')
        while pos != -1:
            positions.append(pos)
            pos = _bmh_search(data, b'AB', pos + 1)
        assert positions == [0, 2, 4]


class TestSboxMatching:
    def test_exact_aes_sbox(self):
        data = Z * 100 + AES_SBOX + Z * 100
        assert _match_full_sbox(data, AES_SBOX, 100)

    def test_exact_wrong_offset(self):
        data = Z * 100 + AES_SBOX
        assert not _match_full_sbox(data, AES_SBOX, 99)

    def test_fuzzy_perfect_match(self):
        data = Z * 64 + AES_SBOX + Z * 64
        is_match, dist, ent = _fuzzy_match_sbox(data, AES_SBOX, 64)
        assert is_match
        assert dist == 0
        assert ent > 0.99

    def test_fuzzy_small_variation(self):
        data = bytearray(Z * 64 + AES_SBOX + Z * 64)
        data[64 + 10] ^= 0x01
        data[64 + 100] ^= 0x80
        data[64 + 200] ^= 0x04
        is_match, dist, ent = _fuzzy_match_sbox(bytes(data), AES_SBOX, 64)
        assert is_match
        assert dist == 3

    def test_fuzzy_large_variation_rejected(self):
        import random
        rng = random.Random(42)
        random_block = bytes(rng.randint(0, 255) for _ in range(256))
        is_match, dist, _ = _fuzzy_match_sbox(random_block, AES_SBOX, 0)
        assert not is_match
        assert dist > 4


class TestMagicConstantDetection:
    def test_aes_sbox_detected(self):
        data = Z * 200 + AES_SBOX + Z * 200
        findings = detect_by_magic_constants(data)
        aes_hits = [f for f in findings if f.algorithm == 'AES' and 'S-box' in f.evidence]
        assert len(aes_hits) >= 1
        assert aes_hits[0].confidence >= 0.98

    def test_sm4_sbox_detected(self):
        data = bytes(SM4_SBOX)
        findings = detect_by_magic_constants(data)
        sm4 = [f for f in findings if f.algorithm == 'SM4']
        assert len(sm4) >= 1

    def test_sha256_iv_detected(self):
        iv_bytes = b''.join(w.to_bytes(4, 'big') for w in SHA256_IV)
        data = Z * 50 + iv_bytes + Z * 50
        findings = detect_by_magic_constants(data)
        sha = [f for f in findings if f.algorithm == 'SHA-256']
        assert len(sha) >= 1

    def test_chacha20_detected(self):
        data = Z * 100 + CHACHA20_CONSTANTS + Z * 100
        findings = detect_by_magic_constants(data)
        chacha = [f for f in findings if f.algorithm == 'ChaCha20']
        assert len(chacha) >= 1

    def test_no_sbox_false_positive(self):
        import random
        rng = random.Random(1337)
        data = bytes(rng.randint(0, 255) for _ in range(10000))
        const_findings = detect_by_magic_constants(data)
        sbox_hits = [f for f in const_findings if 'S-box' in f.evidence]
        assert len(sbox_hits) == 0


class TestApiStringDetection:
    def test_openssl_evp_detected(self):
        strings = ['EVP_EncryptInit_ex', 'some_random_string']
        findings = detect_by_api_strings(strings)
        openssl = [f for f in findings if 'OpenSSL' in f.algorithm]
        assert len(openssl) >= 1

    def test_libsodium_detected(self):
        strings = ['crypto_secretbox_easy', 'other_stuff']
        findings = detect_by_api_strings(strings)
        sodium = [f for f in findings if f.algorithm == 'libsodium']
        assert len(sodium) >= 1

    def test_no_match_on_irrelevant(self):
        strings = ['printf', 'malloc', 'free', 'main']
        findings = detect_by_api_strings(strings)
        assert len(findings) == 0


class TestHardwareAccelDetection:
    def test_aesni_opcode_found(self):
        from src.constants import AESNI_OPCODES
        data = Z * 50 + AESNI_OPCODES + Z * 50
        found = detect_hardware_accel(data)
        assert 'AES-NI' in found

    def test_no_accel_in_empty(self):
        found = detect_hardware_accel(Z * 1000)
        assert len(found) == 0


class TestDedup:
    def test_dedup_same_algo_nearby(self):
        findings = [
            CryptoFinding(algorithm='AES', confidence=0.8, evidence='a', location=100),
            CryptoFinding(algorithm='AES', confidence=0.9, evidence='b', location=108),
        ]
        merged = _dedup(findings)
        assert len(merged) == 1
        assert merged[0].confidence == 0.9

    def test_dedup_different_algo_same_spot(self):
        findings = [
            CryptoFinding(algorithm='AES', confidence=0.8, evidence='a', location=100),
            CryptoFinding(algorithm='SM4', confidence=0.8, evidence='b', location=102),
        ]
        merged = _dedup(findings)
        assert len(merged) == 2


class TestCryptoDetectorIntegration:
    def test_scan_bytes_detects_aes(self):
        data = Z * 200 + AES_SBOX + Z * 200
        result = CryptoDetector.scan_bytes(data)
        aes_hits = [r for r in result if r['algorithm'] == 'AES']
        assert len(aes_hits) >= 1

    def test_fuzzy_detection_in_scan_bytes(self):
        data = bytearray(Z * 200 + AES_SBOX + Z * 200)
        data[200 + 50] ^= 0x03
        data[200 + 120] ^= 0x80
        data[200 + 210] ^= 0x10
        result = CryptoDetector.scan_bytes(bytes(data))
        aes_hits = [r for r in result if r['algorithm'] == 'AES']
        assert len(aes_hits) >= 1
