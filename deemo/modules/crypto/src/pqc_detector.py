"""
后量子密码检测器: 识别原生二进制中的 PQC 算法签名。
检测策略: 字符串匹配、魔术常量、NTT zeta值、参数大小启发式。

NIST 标准 (2024年8月):
  FIPS 203 -- ML-KEM   (Kyber)
  FIPS 204 -- ML-DSA   (Dilithium)
  FIPS 205 -- SLH-DSA  (SPHINCS+)
  FIPS 206 -- FN-DSA   (Falcon, 预计 2026 年底)

NIST 第4轮 KEM (遴选预计 2026-2027):
  BIKE, Classic McEliece, HQC

2026-07: 新增 BIKE (QC-MDPC) 参数检测, HQC tensor code 常量,
Classic McEliece Goppa 多项式 OID/n/t 参数, NTRU Prime sntrup761
检测 (Streamlined NTRU Prime 字符串标记), Falcon fft/fftg tree
检测, 优化 3329 (Kyber) vs 7681 (FrodoKEM) 歧义消除 -- 使用上下文证据。

已知局限: SPHINCS+ 检测高度依赖字符串匹配; 误报率偏高。
"""

import struct
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Set, Tuple, Optional

from .utils import safeReadBytes
# from .config import getConfig  # 保留: 置信度阈值后续可能移至 config

_log = logging.getLogger(__name__)

PQC_CONSTANTS: dict = {
    "Kyber-512":   {"security_level": "NIST-L1", "recommended": True,  "k": 2, "n": 256, "q": 3329, "eta": 3},
    "Kyber-768":   {"security_level": "NIST-L3", "recommended": True,  "k": 3, "n": 256, "q": 3329, "eta": 2},
    "Kyber-1024":  {"security_level": "NIST-L5", "recommended": True,  "k": 4, "n": 256, "q": 3329, "eta": 2},
    "Dilithium-2":   {"security_level": "NIST-L2", "recommended": True,  "n": 256, "q": 8380417, "tau": 39},
    "Dilithium-3":   {"security_level": "NIST-L3", "recommended": True,  "n": 256, "q": 8380417, "tau": 49},
    "Dilithium-5":   {"security_level": "NIST-L5", "recommended": True,  "n": 256, "q": 8380417, "tau": 60},
    "SPHINCS+-128s": {"security_level": "NIST-L1", "recommended": False, "hash": "SHAKE256", "n": 16, "h": 63, "d": 7},
    "SPHINCS+-128f": {"security_level": "NIST-L1", "recommended": False, "hash": "SHAKE256", "n": 16, "h": 66, "d": 22},
    "SPHINCS+-192s": {"security_level": "NIST-L3", "recommended": False, "hash": "SHAKE256", "n": 24, "h": 63, "d": 7},
    "SPHINCS+-192f": {"security_level": "NIST-L3", "recommended": False, "hash": "SHAKE256", "n": 24, "h": 66, "d": 22},
    "SPHINCS+-256s": {"security_level": "NIST-L5", "recommended": False, "hash": "SHAKE256", "n": 32, "h": 64, "d": 8},
    "SPHINCS+-256f": {"security_level": "NIST-L5", "recommended": False, "hash": "SHAKE256", "n": 32, "h": 68, "d": 17},
    "Falcon-512":    {"security_level": "NIST-L1", "recommended": False, "n": 512, "sigmasq": 1.55},
    "Falcon-1024":   {"security_level": "NIST-L5", "recommended": False, "n": 1024, "sigmasq": 1.55},
    # 第4轮 KEM 候选 (尚未标准化)
    "BIKE-L1":       {"security_level": "NIST-L1", "recommended": False, "type": "QC-MDPC", "r": 12323, "n0": 2},
    "BIKE-L3":       {"security_level": "NIST-L3", "recommended": False, "type": "QC-MDPC", "r": 24659, "n0": 2},
    "BIKE-L5":       {"security_level": "NIST-L5", "recommended": False, "type": "QC-MDPC", "r": 40973, "n0": 2},
    "HQC-128":       {"security_level": "NIST-L1", "recommended": False, "type": "tensor code", "n": 17669, "n1": 46, "n2": 384},
    "HQC-192":       {"security_level": "NIST-L3", "recommended": False, "type": "tensor code", "n": 35851, "n1": 56, "n2": 640},
    "HQC-256":       {"security_level": "NIST-L5", "recommended": False, "type": "tensor code", "n": 57637, "n1": 90, "n2": 640},
    "Classic-McEliece-348864":  {"security_level": "NIST-L1", "recommended": False, "type": "Goppa", "n": 3488, "k": 2720, "t": 64},
    "Classic-McEliece-460896":  {"security_level": "NIST-L3", "recommended": False, "type": "Goppa", "n": 4608, "k": 3360, "t": 96},
    "Classic-McEliece-6688128": {"security_level": "NIST-L5", "recommended": False, "type": "Goppa", "n": 6688, "k": 5024, "t": 128},
    "sntrup761":     {"security_level": "NIST-L1", "recommended": False, "type": "NTRU Prime"},
}

_PQC_MAGIC_CONSTANTS = {
    3329:    ["Kyber (ML-KEM)"],
    7681:    ["Kyber-90s variant", "NewHope", "FrodoKEM-640"],
    8380417: ["Dilithium"],
    12289:   ["NewHope-1024", "FrodoKEM-976"],
    32768:   ["FrodoKEM-640"],
    65536:   ["FrodoKEM"],
    2049:    ["NTRUPrime"],
    4591:    ["NTRUPrime", "sntrup761"],
    # 第4轮常量
    12323:   ["BIKE L1 (r=12323)"],
    24659:   ["BIKE L3 (r=24659)"],
    40973:   ["BIKE L5 (r=40973)"],
    17669:   ["HQC-128 (n=17669)"],
    35851:   ["HQC-192 (n=35851)"],
    57637:   ["HQC-256 (n=57637)"],
    3488:    ["Classic McEliece (n=3488)"],
    4608:    ["Classic McEliece (n=4608)"],
    6688:    ["Classic McEliece (n=6688)"],
    # Falcon NTT: Falcon-512 使用 n=512 (2^9), Falcon-1024 使用 n=1024 (2^10)
    512:     ["Falcon-512 (n=512 FFT degree)"],
    1024:    ["Falcon-1024 (n=1024 FFT degree)"],
}

_DILITHIUM_ZETAS = [0, 1753, 2832051, 5950034, 2434870, 5883200, 5786105, 5855364]

# Falcon fft tree 常量 (双倍 NTT 常量, modulus q=12289, n=512/1024)
# Falcon q = 12 * 1024 + 1 = 12289, Falcon-1024 同样使用 q=12289 基于 NTRU-style NTT
_FALCON_Q = 12289

_KNOWN_SIZES = {
    800:  ("Kyber-512",  "public key"),
    1184: ("Kyber-768",  "public key"),
    1568: ("Kyber-1024", "public key"),
    768:  ("Kyber-512",  "ciphertext"),
    1088: ("Kyber-768",  "ciphertext"),
    1312: ("Dilithium-2", "public key"),
    1952: ("Dilithium-3", "public key"),
    2592: ("Dilithium-5", "public key"),
    2420: ("Dilithium-2", "signature"),
    3293: ("Dilithium-3", "signature"),
    4595: ("Dilithium-5", "signature"),
    64:   ("SPHINCS+-128s", "secret key"),
    96:   ("SPHINCS+-192s", "secret key"),
    128:  ("SPHINCS+-256s", "secret key"),
    # BIKE 公钥大小 (n0 * r / 8 向上取整)
    3082:  ("BIKE-L1", "public key"),
    6166:  ("BIKE-L3", "public key"),
    10244: ("BIKE-L5", "public key"),
    # HQC 公钥大小
    2249:  ("HQC-128", "public key"),
    4522:  ("HQC-192", "public key"),
    7245:  ("HQC-256", "public key"),
    # Classic McEliece 公钥大小 = k*(n-k)/8 bytes
    261120: ("Classic-McEliece-348864", "public key"),
    524160: ("Classic-McEliece-460896", "public key"),
    1044992: ("Classic-McEliece-6688128", "public key"),
}


@dataclass
class PQCDetectionResult:
    algorithm: str
    variant: str = ""
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    security_level: str = ""
    parameter_size: int = 0
    detected_in: str = ""


# 类型别名 -- 兼容旧版导入路径
PQCAnalysisResult = PQCDetectionResult
PQCAlgorithm = PQCDetectionResult


class PQCDetector:
    """扫描二进制中的 PQC 算法签名, 基于常量匹配和结构启发式."""

    _STRING_INDICATORS = {
        "pqcrystals": ("Kyber/Dilithium", "pqclean reference implementation"),
        "kyber": ("Kyber", ""),
        "dilithium": ("Dilithium", ""),
        "sphincs": ("SPHINCS+", ""),
        "falcon": ("Falcon", ""),
        "frodokem": ("FrodoKEM", ""),
        "ml-kem": ("ML-KEM", "NIST FIPS 203"),
        "ml-dsa": ("ML-DSA", "NIST FIPS 204"),
        "slh-dsa": ("SLH-DSA", "NIST FIPS 205"),
        "fn-dsa": ("FN-DSA", "NIST FIPS 206 (draft)"),
        "hqc": ("HQC", "NIST alternate KEM (2025)"),
        "sntrup": ("Streamlined NTRU Prime", ""),
        "ntruhrss": ("NTRU HRSS", ""),
        "classic mceliece": ("Classic McEliece", ""),
        "saber": ("SABER", "NIST round 3 finalist"),
        "ntt_layer": ("NTT-based", "Likely Kyber or Dilithium"),
        "poly_reduce": ("PQC polynomial arithmetic", ""),
        "shake128_absorb": ("SHAKE128", "PQC hash primitive"),
        "shake256_absorb": ("SHAKE256", "PQC hash primitive"),
        # FIPS-203/204/205 OID 片段 (ASN.1)
        "2.16.840.1.101.3.4": ("NIST PQC algorithm OID", ""),
        # 第4轮候选字符串
        "bike": ("BIKE", "NIST round 4 KEM"),
        "qc_mdpc": ("BIKE (QC-MDPC)", ""),
        "goppa": ("Classic McEliece (Goppa)", ""),
        "mceliece": ("Classic McEliece", ""),
        "reed-solomon": ("HQC (tensor/Reed-Solomon code)", ""),
        "reed_muller": ("HQC (Reed-Muller code)", ""),
        "tensor_code": ("HQC (tensor code)", ""),
        "ntruprime": ("NTRU Prime", ""),
        "streamlined ntru prime": ("Streamlined NTRU Prime", ""),
        "falcon_fft": ("Falcon (FFT)", ""),
        "falcon_fftg": ("Falcon (FFT+Gaussian)", ""),
        # NIST 附加签名候选
        "aimer": ("AIMer (MPC-in-the-Head signature)", "NIST additional signatures"),
        "faest": ("FAEST (VOLE-based signature)", "NIST additional signatures"),
        "haetae": ("HAETAE (lattice-based, Korean PQC)", "NIST additional signatures round 2"),
        "hawk": ("HAWK (lattice-based w/ rejection sampling)", "NIST additional signatures"),
        "sqisign": ("SQISign (isogeny-based signature)", "NIST additional signatures"),
        "uov": ("UOV (unbalanced oil-vinegar, multivariate)", "NIST additional signatures"),
        "mayo": ("MAYO (multivariate, UOV variant)", "NIST additional signatures"),
        "cross": ("CROSS (MPC-in-the-Head, syndrome decoding)", "NIST additional signatures"),
        "smaug": ("SMAUG (lattice-based, Korean PQC)", "NIST additional signatures"),
        "perk": ("PERK (MPC-in-the-Head, permuted kernels)", "NIST additional signatures"),
        "mirith": ("MIRITH (MPC-in-the-Head, MinRank problem)", "NIST additional signatures"),
        "ryde": ("RYDE (MPC-in-the-Head, syndrome decoding)", "NIST additional signatures"),
        "sdf": ("SDF (syndrome decoding in the head)", "NIST additional signatures"),
        "tuov": ("TUOV (triangular UOV, multivariate)", "NIST additional signatures"),
        "vox": ("VOX (multivariate, Minus-Plus variant)", "NIST additional signatures"),
    }

    def __init__(self):
        pass

    def scan_file(self, path: str) -> List[PQCDetectionResult]:
        raw = safeReadBytes(path)
        if raw is None:
            _log.error("Cannot read %s", path)
            return []

        results: List[PQCDetectionResult] = []
        results.extend(self._detect_by_strings(raw, path))
        results.extend(self._detect_by_constants(raw, path))
        results.extend(self._detect_ntt_constants(raw, path))
        results.extend(self._verify_parameter_sizes(raw, path))
        results.extend(self._detect_falcon_constants(raw, path))

        # 按 (algorithm, variant) 去重 -- 保留首次出现
        seen: Set[Tuple[str, str]] = set()
        unique = []
        for r in results:
            key = (r.algorithm, r.variant)
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return unique

    def _detect_by_strings(self, data: bytes, source: str) -> List[PQCDetectionResult]:
        results: List[PQCDetectionResult] = []
        text = data.decode("ascii", errors="ignore").lower()

        for keyword, (algo, note) in self._STRING_INDICATORS.items():
            idx = text.find(keyword)
            if idx >= 0:
                ctx = data[max(0, idx - 10):idx + len(keyword) + 30]
                evidence = [f"String: '{ctx.decode('ascii', errors='replace').strip()}'"]
                if note:
                    evidence.append(note)
                results.append(PQCDetectionResult(
                    algorithm=algo, confidence=0.7, evidence=evidence, detected_in=source))
        return results

    def _detect_by_constants(self, data: bytes, source: str) -> List[PQCDetectionResult]:
        results: List[PQCDetectionResult] = []
        for val, algorithms in _PQC_MAGIC_CONSTANTS.items():
            for fmt in ("<H", ">H", "<I", ">I"):
                try:
                    packed = struct.pack(fmt, val)
                except struct.error:
                    continue  # 值超出格式宽度 -- 跳过此编码
                if packed in data:
                    for algo in algorithms:
                        results.append(PQCDetectionResult(
                            algorithm=algo, confidence=0.5,
                            evidence=[f"Constant {val} found as {fmt}"],
                            detected_in=source))
                    break  # 每个常量值匹配一种格式即足够

        # Kyber 特定启发式: q=3329 + n=256 同时出现 -> 强烈指示 Kyber
        if struct.pack("<H", 3329) in data and struct.pack("<H", 256) in data:
            # 歧义消除: 3329 也匹配 FrodoKEM-640, 但 256 是 Kyber 特有
            kyber_ctx = 0.8 if struct.pack("<H", 7681) not in data else 0.6
            results.append(PQCDetectionResult(
                algorithm="Kyber", confidence=kyber_ctx,
                evidence=["Kyber params (q=3329, n=256)"],
                security_level="NIST-L1+", detected_in=source))

        # Classic McEliece: Goppa 多项式参数 t=64,96,128 与 n≈3488,4608,6688
        for t_val, n_val, label in [(64, 3488, "348864"), (96, 4608, "460896"), (128, 6688, "6688128")]:
            if struct.pack("<H", t_val) in data and struct.pack("<H", n_val) in data:
                results.append(PQCDetectionResult(
                    algorithm=f"Classic McEliece", variant=f"{label}",
                    confidence=0.75,
                    evidence=[f"Goppa: n={n_val}, t={t_val}"],
                    security_level="NIST-L1+" if t_val <= 64 else "NIST-L3+",
                    detected_in=source))

        # BIKE: r 参数 (质数) 12323, 24659, 40973
        for r_val, level in [(12323, "L1"), (24659, "L3"), (40973, "L5")]:
            if struct.pack("<H", r_val) in data or struct.pack("<I", r_val) in data:
                results.append(PQCDetectionResult(
                    algorithm=f"BIKE", variant=f"Level {level}",
                    confidence=0.55,
                    evidence=[f"BIKE QC-MDPC: r={r_val}"],
                    security_level=f"NIST-{level}", detected_in=source))

        return results

    def _detect_ntt_constants(self, data: bytes, source: str) -> List[PQCDetectionResult]:
        results: List[PQCDetectionResult] = []
        zeta_bytes = b"".join(struct.pack("<I", z) for z in _DILITHIUM_ZETAS[:4])
        if zeta_bytes in data:
            results.append(PQCDetectionResult(
                algorithm="Dilithium", confidence=0.85,
                evidence=["Dilithium NTT zeta constants detected"],
                security_level="NIST-L2+", detected_in=source))
        return results

    def _verify_parameter_sizes(self, data: bytes, source: str) -> List[PQCDetectionResult]:
        results: List[PQCDetectionResult] = []
        for size, (algo, desc) in _KNOWN_SIZES.items():
            if struct.pack("<I", size) in data:
                results.append(PQCDetectionResult(
                    algorithm=algo, confidence=0.6, parameter_size=size,
                    evidence=[f"Known {desc} = {size} bytes"],
                    detected_in=source))
        return results

    def _detect_falcon_constants(self, data: bytes, source: str) -> List[PQCDetectionResult]:
        """
        Falcon 使用 NTRU-style NTT 在环 Z_q[x]/(x^n+1) 上, q=12289。
        常量 (q-1)/2 = 6144, FFT bit-reversal 表, 高斯采样器 sigma 以不可变数据常量形式存在。
        """
        results: List[PQCDetectionResult] = []
        # Falcon q=12289 检测
        q_bytes = struct.pack("<H", _FALCON_Q)
        if q_bytes in data:
            # Falcon 使用 q=12289, n=512 或 n=1024
            has_n512 = struct.pack("<H", 512) in data
            has_n1024 = struct.pack("<H", 1024) in data
            variant = ""
            if has_n512 and has_n1024:
                variant = "512+1024"
            elif has_n512:
                variant = "512"
            elif has_n1024:
                variant = "1024"
            if variant:
                results.append(PQCDetectionResult(
                    algorithm="Falcon", variant=variant, confidence=0.65,
                    evidence=["Falcon NTRU NTT: q=12289", f"n={variant}"],
                    security_level="NIST-L1" if "512" in variant else "NIST-L5",
                    detected_in=source))
        return results


# ---- 便捷入口 ----

def detect_pqc(path: str) -> List[PQCDetectionResult]:
    return PQCDetector().scan_file(path)

def detect_pqc_bytes(data: bytes, source: str = "memory") -> List[PQCDetectionResult]:
    det = PQCDetector()
    results = det._detect_by_strings(data, source)
    results.extend(det._detect_by_constants(data, source))
    results.extend(det._detect_ntt_constants(data, source))
    results.extend(det._verify_parameter_sizes(data, source))
    results.extend(det._detect_falcon_constants(data, source))
    return results


__all__ = ["PQCDetector", "PQCDetectionResult", "PQCAnalysisResult",
           "PQCAlgorithm", "PQC_CONSTANTS", "detect_pqc", "detect_pqc_bytes"]
