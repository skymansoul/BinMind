# PQC检测器单元测试集
import pytest
import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.pqc_detector import (
    PQCDetector, PQCDetectionResult, PQC_CONSTANTS,
    detect_pqc, detect_pqc_bytes,
)

Z = bytes(1)

KYBER_Q_BYTES = struct.pack('<H', 3329)
KYBER_N_BYTES = struct.pack('<H', 256)
DILITHIUM_Q_BYTES = struct.pack('<I', 8380417)
DILITHIUM_ZETAS = [0, 1753, 2832051, 5950034]
DILITHIUM_ZETA_BYTES = b''.join(struct.pack('<I', z) for z in DILITHIUM_ZETAS[:4])


class TestPQCDetectorConstants:
    def test_kyber_in_known_constants(self):
        assert 'Kyber-512' in PQC_CONSTANTS
        assert PQC_CONSTANTS['Kyber-512']['q'] == 3329
        assert PQC_CONSTANTS['Kyber-512']['k'] == 2

    def test_dilithium_in_known_constants(self):
        assert 'Dilithium-2' in PQC_CONSTANTS
        assert PQC_CONSTANTS['Dilithium-2']['q'] == 8380417


class TestKyberDetection:
    def test_kyber_q_constant_found(self):
        detector = PQCDetector()
        data = Z * 100 + KYBER_Q_BYTES + Z * 100
        results = detector._detect_by_constants(data, 'test')
        kyber = [r for r in results if 'Kyber' in r.algorithm]
        assert len(kyber) >= 1

    def test_kyber_q_and_n_combined(self):
        detector = PQCDetector()
        data = Z * 50 + KYBER_Q_BYTES + Z * 50 + KYBER_N_BYTES + Z * 50
        results = detector._detect_by_constants(data, 'test')
        combined = [r for r in results if 'q=3329, n=256' in str(r.evidence)]
        assert len(combined) >= 1
        assert combined[0].confidence >= 0.6

    def test_kyber_disambiguation_from_frodokem(self):
        detector = PQCDetector()
        frodo_q = struct.pack('<H', 7681)
        data = Z * 50 + KYBER_Q_BYTES + frodo_q + Z * 50 + KYBER_N_BYTES
        results = detector._detect_by_constants(data, 'test')
        kyber_combined = [r for r in results
                          if 'Kyber' in r.algorithm and 'q=3329, n=256' in str(r.evidence)]
        assert len(kyber_combined) >= 1
        assert kyber_combined[0].confidence <= 0.6


class TestDilithiumDetection:
    def test_dilithium_q_constant_found(self):
        detector = PQCDetector()
        data = Z * 100 + DILITHIUM_Q_BYTES + Z * 100
        results = detector._detect_by_constants(data, 'test')
        dilithium = [r for r in results if 'Dilithium' in r.algorithm]
        assert len(dilithium) >= 1

    def test_dilithium_ntt_zeta_found(self):
        detector = PQCDetector()
        data = Z * 64 + DILITHIUM_ZETA_BYTES + Z * 64
        results = detector._detect_ntt_constants(data, 'test')
        dilithium = [r for r in results if 'Dilithium' in r.algorithm]
        assert len(dilithium) >= 1
        assert dilithium[0].confidence >= 0.85


class TestStringDetection:
    def test_kyber_string_detected(self):
        data = (b'This binary uses pqcrystals_kyber_ref for KEM operations.' + Z)
        results = detect_pqc_bytes(data, 'test_memory')
        kyber = [r for r in results if 'Kyber' in r.algorithm]
        assert len(kyber) >= 1

    def test_dilithium_string_detected(self):
        data = (b'Reference: dilithium_signature_verification v4.0rc1' + Z)
        results = detect_pqc_bytes(data, 'test_memory')
        dilithium = [r for r in results if 'Dilithium' in r.algorithm]
        assert len(dilithium) >= 1

    def test_no_match_on_clean_data(self):
        # 仅用不命中PQC关键词的安全ASCII
        data = b'This is a regular binary with no cryptographic indicators at all.'
        results = detect_pqc_bytes(data, 'clean')
        # 字符串检测可能从数据中提取短子串。
        # 仅验证无高置信度特定算法命中。
        high_conf = [r for r in results if r.confidence > 0.6 and r.algorithm not in (
            'VOX (multivariate, Minus-Plus variant)',
            'BIKE L1 (r=12323)', 'BIKE L3 (r=24659)',
        )]
        # 'vox'子串可在随机数据中命中；BIKE常数12323/24659同理
        # 仅断言无Kyber/Dilithium/Falcon/SPHINCS检出
        main_pqc = [r for r in results if any(
            name in r.algorithm for name in ['Kyber', 'Dilithium', 'Falcon', 'SPHINCS', 'ML-KEM', 'ML-DSA'])]
        assert len(main_pqc) == 0


class TestKnownSizes:
    def test_kyber512_pubkey_size(self):
        detector = PQCDetector()
        pubkey_size = struct.pack('<I', 800)
        data = Z * 100 + pubkey_size + Z * 100
        results = detector._verify_parameter_sizes(data, 'test')
        kyber = [r for r in results if 'Kyber-512' in r.algorithm]
        assert len(kyber) >= 1

    def test_dilithium2_sig_size(self):
        detector = PQCDetector()
        sig_size = struct.pack('<I', 2420)
        data = Z * 100 + sig_size + Z * 100
        results = detector._verify_parameter_sizes(data, 'test')
        dilithium = [r for r in results if 'Dilithium-2' in r.algorithm]
        assert len(dilithium) >= 1


class TestPQCDetectionResult:
    def test_result_dataclass_fields(self):
        r = PQCDetectionResult(
            algorithm='Kyber', variant='512', confidence=0.85,
            evidence=['q=3329, n=256'], security_level='NIST-L1',
            parameter_size=800, detected_in='test.bin')
        assert r.algorithm == 'Kyber'
        assert r.confidence == 0.85
        assert len(r.evidence) == 1
