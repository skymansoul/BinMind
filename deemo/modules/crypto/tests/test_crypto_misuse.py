# crypto_misuse 单元测试
# 各检测类别独立测试，不依赖整体 .scan() 方法。便于归因失败，新增类别时避免级联中断。
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crypto_misuse import (
    CryptoMisuseDetector, CryptoMisuse, Misuse,
    detect_crypto_misuse, scan_for_weak_random, scan_for_hardcoded_secrets,
    SEVERITY,
)

Z = bytes(1)
PAD = bytes([0xAA]) * 100


class TestCryptoMisuseClass:
    def test_add_and_iterate(self):
        cm = CryptoMisuse()
        cm.add(Misuse('WEAK_KEY', 'DES', '0x100', 'test key', 'CRITICAL'))
        cm.add(Misuse('WEAK_HASH', 'MD5', '0x200', 'test hash', 'HIGH'))
        assert len(cm) == 2
        assert len(list(cm)) == 2

    def test_filter_by_severity(self):
        # by_severity 返回 >= 阈值的条目。CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1, INFO=0
        cm = CryptoMisuse()
        items = [
            Misuse('WEAK_KEY', 'DES', '0x100', 'k', 'CRITICAL'),
            Misuse('WEAK_HASH', 'MD5', '0x200', 'h', 'HIGH'),
            Misuse('WEAK_RNG', 'rand', '0x300', 'r', 'MEDIUM'),
            Misuse('HARDCODED_SALT', 'N/A', '0x400', 's', 'LOW'),
            Misuse('ECB_ARTIFACT', 'N/A', '0x500', 'e', 'INFO'),
        ]
        for d in items:
            cm.add(d)
        # CRITICAL=4 阈值: 仅严重度4 (仅CRITICAL) -> 1
        assert len(cm.by_severity('CRITICAL')) == 1
        # HIGH=3 阈值: CRITICAL + HIGH -> 2
        assert len(cm.by_severity('HIGH')) == 2
        # MEDIUM=2 阈值: CRITICAL + HIGH + MEDIUM -> 3
        assert len(cm.by_severity('MEDIUM')) == 3
        # LOW=1: 除INFO外全部 -> 4
        assert len(cm.by_severity('LOW')) == 4
        # 无参数时默认 'MEDIUM'
        assert len(cm.by_severity()) == 3

    def test_severity_mapping(self):
        assert SEVERITY['CRITICAL'] == 4
        assert SEVERITY['HIGH'] == 3
        assert SEVERITY['MEDIUM'] == 2
        assert SEVERITY['LOW'] == 1
        assert SEVERITY['INFO'] == 0


class TestWeakKeyDetection:
    def test_weak_des_key_at_start(self):
        detector = CryptoMisuseDetector()
        weak_key = bytes.fromhex('0101010101010101')
        data = weak_key + Z * 1000
        result = detector.scan(data)
        weak_keys = [m for m in result if m.type == 'WEAK_KEY']
        assert len(weak_keys) >= 1
        assert all(m.severity == 'CRITICAL' for m in weak_keys)

    def test_no_weak_key_in_clean_data(self):
        detector = CryptoMisuseDetector()
        data = b'\xDE\xAD\xBE\xEF' * 250
        result = detector.scan(data)
        weak_keys = [m for m in result if m.type == 'WEAK_KEY']
        assert len(weak_keys) == 0


class TestStaticIVDetection:
    def test_zero_iv_detected(self):
        detector = CryptoMisuseDetector()
        data = Z * 16 + PAD
        result = detector.scan(data)
        ivs = [m for m in result if m.type == 'STATIC_IV']
        assert len(ivs) >= 1

    def test_sequential_iv_detected(self):
        detector = CryptoMisuseDetector()
        data = bytes(range(16)) + PAD
        result = detector.scan(data)
        ivs = [m for m in result if m.type == 'STATIC_IV']
        assert len(ivs) >= 1


class TestHardcodedSaltDetection:
    def test_deadbeef_salt_detected(self):
        detector = CryptoMisuseDetector()
        data = Z * 50 + b'deadbeef' + Z * 50
        result = detector.scan(data)
        salts = [m for m in result if m.type == 'HARDCODED_SALT']
        assert len(salts) >= 1

    def test_no_salt_in_random_data(self):
        detector = CryptoMisuseDetector()
        import random
        rng = random.Random(777)
        data = bytes(rng.randint(0x41, 0x5A) for _ in range(5000))
        result = detector.scan(data)
        salts = [m for m in result if m.type == 'HARDCODED_SALT']
        assert len(salts) == 0


class TestConvenienceFunctions:
    def test_scan_for_weak_random(self):
        data = b'rand' + Z * 100
        result = scan_for_weak_random(data)
        assert any(m.type == 'WEAK_RNG' for m in result)

    def test_detect_crypto_misuse_nonexistent_file(self):
        result = detect_crypto_misuse('/nonexistent/file/for/testing.bin')
        assert len(result) == 0

    def test_scan_for_hardcoded_secrets(self):
        data = Z * 16 + b'password' + Z * 50
        result = scan_for_hardcoded_secrets(data)
        assert any(m.type == 'HARDCODED_SALT' for m in result)
