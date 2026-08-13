"""Tests for crypto_traffic_decrypt — TLS parsing, key extraction, decryption fallback."""

import os
import sys
import struct
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crypto_traffic_decrypt import (
    CryptoTrafficAnalyzer, KeyExtractor, TrafficDecryptor,
    KeyMaterial, DecryptionResult,
    extract_keys, decrypt_traffic, analyze_traffic,
    EncryptionType, KeySourceType,
)


def _make_tls_client_hello():
    """Build a minimal TLS 1.2 ClientHello record."""
    # TLS record header: content_type=22 (handshake), version=0x0303 (TLS 1.2)
    record = struct.pack(">BHH", 22, 0x0303, 0)

    # Handshake header: type=1 (client_hello), length placeholder
    handshake = struct.pack(">B", 1) + b"\x00" + struct.pack(">H", 0)

    # ClientHello body
    client_version = struct.pack(">H", 0x0303)
    random_bytes = b"\x00" * 32
    session_id = b"\x00"  # zero-length session ID
    # cipher suites: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
    cipher_suites = struct.pack(">H", 2) + struct.pack(">H", 0xC02F)
    compression = b"\x01\x00"  # 1 method: null

    body = client_version + random_bytes + session_id + cipher_suites + compression

    # Fix up lengths
    total = len(handshake) + len(body)
    record = struct.pack(">BHH", 22, 0x0303, total) + handshake + body
    return record


class TestTrafficAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = CryptoTrafficAnalyzer()

    def test_tls_handshake_detection(self):
        data = _make_tls_client_hello()
        results = self.analyzer.analyze(data)
        self.assertGreater(len(results), 0)
        ssl = [r for r in results if r.protocol == "ssl_handshake"]
        self.assertGreater(len(ssl), 0)

    def test_ssh_banner_detection(self):
        data = b'\x00' * 10 + b'SSH-2.0-OpenSSH_8.9' + b'\x00' * 10
        results = self.analyzer.analyze(data)
        self.assertTrue(any(r.protocol == "ssh_banner" for r in results))

    def test_no_encrypted_traffic(self):
        data = b'plain text without any protocol markers'
        results = self.analyzer.analyze(data)
        self.assertEqual(len(results), 0)

    def test_tls_cipher_suite_parsing(self):
        data = _make_tls_client_hello()
        results = self.analyzer.analyze(data)
        ssl = [r for r in results if r.protocol == "ssl_handshake"]
        if ssl:
            self.assertIn("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                          ssl[0].cipher_suites)


class TestKeyExtractor(unittest.TestCase):

    def setUp(self):
        self.extractor = KeyExtractor()

    def test_string_pattern_extraction(self):
        # Pattern requires key= or KEY= immediately followed by = or :
        data = b'key="ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"'
        keys = self.extractor.extract(data)
        self.assertGreater(len(keys), 0)

    def test_no_keys_in_empty(self):
        keys = self.extractor.extract(b"")
        self.assertEqual(len(keys), 0)

    def test_key_minimum_length(self):
        """Keys shorter than 16 bytes must be filtered out."""
        data = b'key = "short"'
        keys = self.extractor.extract(data)
        self.assertEqual(len(keys), 0,
                         "Keys < 16 bytes should be filtered")


class TestTrafficDecryptor(unittest.TestCase):

    def setUp(self):
        self.decryptor = TrafficDecryptor()

    def test_no_key(self):
        result = self.decryptor.decrypt(b"data", None)
        self.assertFalse(result.success)
        self.assertIn("no key", result.error)

    def test_key_too_short(self):
        result = self.decryptor.decrypt(b"data", b"short")
        self.assertFalse(result.success)
        self.assertIn("too short", result.error)

    def test_xor_fallback(self):
        """With no crypto lib installed, XOR fallback should still succeed."""
        data = b"hello world!!!"  # 16 bytes
        key = b"A" * 16  # exactly 16 bytes
        result = self.decryptor.decrypt(data, key)
        # XOR fallback always works
        self.assertTrue(result.success)

    def test_keymaterial_input(self):
        km = KeyMaterial(key=b"A" * 16)
        result = self.decryptor.decrypt(b"data12345678901", km)
        self.assertTrue(result.success)


class TestConvenienceFunctions(unittest.TestCase):

    def test_extract_keys(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'KEY = "abcdefghijklmnopqrstuvwxyz123456"')
            tmp = f.name
        try:
            keys = extract_keys(tmp)
            self.assertIsInstance(keys, list)
        finally:
            os.unlink(tmp)

    def test_decrypt_traffic_empty(self):
        result = decrypt_traffic(b"data", None)
        self.assertIsInstance(result, DecryptionResult)

    def test_analyze_traffic_fn(self):
        data = _make_tls_client_hello()
        results = analyze_traffic(data)
        self.assertIsInstance(results, list)


if __name__ == '__main__':
    unittest.main()
