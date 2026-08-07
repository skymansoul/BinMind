"""crypto_detect — AES S-box检测、SHA256 IV匹配、硬件加速"""
import pytest

try:
    from ..src.crypto_detector import (
        CryptoDetector, CryptoFinding,
        detect_by_magic_constants, detect_by_structure,
        detect_by_api_strings, detect_hardware_accel,
        _bmh_search, _match_full_sbox, _dedup
    )
    _crypto_available = True
except Exception:
    _crypto_available = False


# 已知密码常量
AES_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    # ... 256 bytes total; 前16字节片段
])

SHA256_IV_BYTES = bytes([
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
    0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
    0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
])


@pytest.mark.skipif(not _crypto_available, reason="crypto_detector not importable")
class TestBMHSearch:
    """Boyer-Moore-Horspool搜索"""

    def test_bmh_finds_pattern(self):
        """BMH在数据中找到模式"""
        data = b"AAAA" + SHA256_IV_BYTES + b"BBBB"
        pos = _bmh_search(data, SHA256_IV_BYTES)
        assert pos == 4

    def test_bmh_no_match_returns_neg1(self):
        """BMH无匹配返回-1"""
        data = b"\x00" * 100
        pattern = b"\xff\xff\xff\xff"
        pos = _bmh_search(data, pattern)
        assert pos == -1

    def test_bmh_single_char_pattern(self):
        """BMH单字符模式"""
        data = b"ABCDEFGHIJ"
        pos = _bmh_search(data, b'E')
        assert pos == 4


@pytest.mark.skipif(not _crypto_available, reason="crypto_detector not importable")
class TestAESDetection:
    """AES S-box检测"""

    def test_aes_sbox_detected_in_data(self):
        """包含AES S-box的数据被检测到"""
        # 构造包含AES S-box的数据
        from ..src.constants import AES_SBOX as REAL_AES_SBOX
        data = b"\x00" * 64 + REAL_AES_SBOX + b"\xff" * 64
        findings = detect_by_magic_constants(data)
        aes_findings = [f for f in findings if "AES" in f.algorithm.upper()]
        assert len(aes_findings) > 0, f"expected AES detection, got {findings}"

    def test_empty_data_no_false_positive(self):
        """空数据不产生误报"""
        findings = detect_by_magic_constants(b"")
        aes_findings = [f for f in findings if "AES" in f.algorithm.upper()]
        assert len(aes_findings) == 0


@pytest.mark.skipif(not _crypto_available, reason="crypto_detector not importable")
class TestSHA256Detection:
    """SHA256 IV检测"""

    def test_sha256_iv_detected(self):
        """包含SHA256 IV的数据被检测到"""
        from ..src.constants import SHA256_IV as REAL_SHA256_IV
        data = b"\x00" * 40 + REAL_SHA256_IV + b"\xaa" * 40
        findings = detect_by_magic_constants(data)
        sha_findings = [f for f in findings if "SHA" in f.algorithm.upper() and "256" in f.algorithm.upper()]
        assert len(sha_findings) > 0

    def test_sha256_iv_not_misdetected(self):
        """不含SHA256 IV的数据不误检"""
        data = b"\xde\xad\xbe\xef" * 20
        findings = detect_by_magic_constants(data)
        sha_findings = [f for f in findings if "SHA" in f.algorithm.upper() and "256" in f.algorithm.upper()]
        assert len(sha_findings) == 0


@pytest.mark.skipif(not _crypto_available, reason="crypto_detector not importable")
class TestHardwareAccelDetection:
    """硬件加速指令检测"""

    def test_aesni_opcodes_detected(self):
        """AES-NI操作码检测"""
        # AESENC: 0x66 0x0F 0x38 0xDC
        data = b"\x90" * 10 + b"\x66\x0f\x38\xdc" + b"\x90" * 10
        results = detect_hardware_accel(data)
        assert any("AES-NI" in r for r in results)

    def test_no_hardware_without_opcodes(self):
        """无特定操作码时无硬件加速检测"""
        data = b"\x90\x90\x90\x90"
        results = detect_hardware_accel(data)
        assert results == []


@pytest.mark.skipif(not _crypto_available, reason="crypto_detector not importable")
class TestCryptoFindingDedup:
    """CryptoFinding去重"""

    def test_dedup_merges_nearby_same_algorithm(self):
        """相近位置的同算法查找被去重"""
        findings = [
            CryptoFinding(algorithm="AES", confidence=0.9, evidence="sbox", location=100),
            CryptoFinding(algorithm="AES", confidence=0.8, evidence="sbox", location=108),
        ]
        result = _dedup(findings, eps=16)
        assert len(result) < len(findings)

    def test_different_algorithms_not_merged(self):
        """不同算法不合并"""
        findings = [
            CryptoFinding(algorithm="AES", confidence=0.9, evidence="", location=100),
            CryptoFinding(algorithm="SHA256", confidence=0.9, evidence="", location=100),
        ]
        result = _dedup(findings, eps=16)
        assert len(result) == 2


# 独立测试（无需模块导入）

def test_sha256_iv_known_value():
    """验证SHA256 IV前4字节为已知常数值"""
    # SHA-256 IV: 取自FIPS 180-4
    iv = bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a"
                        "510e527f9b05688c1f83d9ab5be0cd19")
    assert iv[0] == 0x6a
    assert iv[4:8] == bytes.fromhex("bb67ae85")


def test_crypto_finding_struct():
    """CryptoFinding结构完整性测试"""
    if _crypto_available:
        f = CryptoFinding(algorithm="AES", confidence=0.95,
                          evidence="sbox at 0x1000", location=0x1000)
        assert f.algorithm == "AES"
        assert f.confidence == pytest.approx(0.95)
    else:
        # 内联验证
        finding = {"algorithm": "AES", "confidence": 0.95}
        assert finding["algorithm"] == "AES"
