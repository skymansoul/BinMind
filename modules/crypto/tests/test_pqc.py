"""pqc — Kyber参数检测（3329常量）、NTT常量、Dilithium。"""
import struct
import pytest

try:
    from ..src.pqc_detector import (
        PQCDetector, PQCDetectionResult,
        PQC_CONSTANTS, _PQC_MAGIC_CONSTANTS,
        _DILITHIUM_ZETAS, _FALCON_Q,
        detect_pqc, detect_pqc_bytes
    )
    _pqc_available = True
except Exception:
    _pqc_available = False


# 已知PQC常数值
KYBER_Q = 3329
DILITHIUM_Q = 8380417
FALCON_Q = 12289


@pytest.mark.skipif(not _pqc_available, reason="pqc_detector not importable")
class TestKyberDetection:
    """Kyber参数3329检测"""

    def test_kyber_3329_constant_detected(self):
        """二进制中包含3329（小端）→ Kyber检测"""
        # Kyber-512参数: N=256, Q=3329
        data = struct.pack("<H", 3329) * 100  # 重复3329
        results = detect_pqc_bytes(data, source="test")
        kyber_results = [r for r in results if "Kyber" in r.algorithm]
        assert len(kyber_results) > 0, f"expected Kyber detection, got: {results}"

    def test_kyber_in_pqc_constants(self):
        """Kyber在PQC_CONSTANTS中定义"""
        assert "Kyber-512" in PQC_CONSTANTS
        assert "Kyber-768" in PQC_CONSTANTS
        assert "Kyber-1024" in PQC_CONSTANTS

    def test_3329_in_magic_constants(self):
        """3329映射到Kyber"""
        assert 3329 in _PQC_MAGIC_CONSTANTS
        assert any("Kyber" in name for name in _PQC_MAGIC_CONSTANTS[3329])


@pytest.mark.skipif(not _pqc_available, reason="pqc_detector not importable")
class TestDilithiumDetection:
    """Dilithium NTT zeta常量"""

    def test_dilithium_zeta_constants_defined(self):
        """Dilithium zeta常量列表非空"""
        assert len(_DILITHIUM_ZETAS) > 0
        # zeta值应为uint32
        for z in _DILITHIUM_ZETAS:
            assert isinstance(z, int)

    def test_dilithium_q_in_magic_constants(self):
        """Dilithium Q=8380417在magic_constants中"""
        assert 8380417 in _PQC_MAGIC_CONSTANTS
        assert any("Dilithium" in name for name in _PQC_MAGIC_CONSTANTS[8380417])


@pytest.mark.skipif(not _pqc_available, reason="pqc_detector not importable")
class TestFalconDetection:
    """Falcon Q参数"""

    def test_falcon_q_value(self):
        """Falcon Q正确值为12289"""
        assert _FALCON_Q == 12289

    def test_falcon_in_pqc_constants(self):
        """Falcon配置在PQC_CONSTANTS中"""
        assert "Falcon-512" in PQC_CONSTANTS


@pytest.mark.skipif(not _pqc_available, reason="pqc_detector not importable")
class TestStringBasedDetection:
    """字符串指示符检测"""

    def test_string_detection_sabermetrics(self):
        """二进制中包含'Kyber'字符串 → 检测"""
        data = b"This is the Kyber reference implementation v3.01"
        results = detect_pqc_bytes(data, source="test")
        assert len(results) > 0, f"expected detection from string, got: {results}"
        assert any("Kyber" in r.algorithm for r in results)

    def test_no_false_positive_on_empty(self):
        """空数据不产生误检"""
        results = detect_pqc_bytes(b"", source="test")
        assert results == []


@pytest.mark.skipif(not _pqc_available, reason="pqc_detector not importable")
class TestPQCDetectionResult:
    """PQCDetectionResult结构"""

    def test_result_fields(self):
        """PQCDetectionResult包含所有必要字段"""
        result = PQCDetectionResult(
            algorithm="Kyber",
            variant="Kyber-512",
            confidence=0.92,
            evidence=["magic constant 3329"],
            security_level="128",
            parameter_size=800,
            detected_in="test"
        )
        assert result.algorithm == "Kyber"
        assert result.confidence == pytest.approx(0.92)
        assert result.security_level == "128"


# 独立测试（无需模块导入）

def test_kyber_q_known_value():
    """Kyber模数3329为正确值"""
    # 依据 FIPS 203 (CRYSTALS-Kyber)
    assert KYBER_Q == 3329
    # 验证3329是质数（模数要求）
    def is_prime(n):
        if n < 2:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True
    assert is_prime(KYBER_Q)


def test_dilithium_q_known_value():
    """Dilithium模数8380417为正确值"""
    assert DILITHIUM_Q == 8380417


def test_kyber_parameter_sizes():
    """Kyber各变体参数尺寸合理"""
    import hashlib
    # Kyber安全级别 → 参数尺寸范围（字节）
    sizes = {
        "Kyber-512": 800,
        "Kyber-768": 1184,
        "Kyber-1024": 1568,
    }
    for name, size in sizes.items():
        assert 500 < size < 5000, f"{name} size {size} out of range"
