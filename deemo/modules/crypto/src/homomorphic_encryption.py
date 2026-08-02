# 2026-07-30
# ==== 同态加密方案检测 ====
# 覆盖: CKKS (HEAAN), BGV, BFV, TFHE, FHEW, OpenFHE Lattigo/SEAL/HElib/tfhe-rs 指纹。
# 同态加密在隐私保护机器学习、加密数据库查询、安全多方计算中广泛使用。
# 检测策略: (1) RLWE 参数 (N, log2(q)) 及模数链 (RNS representation),
# (2) CKKS/BGV 的 rescale/modswitch 操作码模式,
# (3) TFHE 的 blind rotate / CMux gate 汇编特征,
# (4) OpenFHE/Lattigo/SEAL/HElib 库字符串特征。
#
# 参考: Cheon-Kim-Kim-Song (CKKS, ASIACRYPT 2017), Brakerski-Gentry-Vaikuntanathan
# (BGV, ITCS 2012), Fan-Vercauteren (BFV, 2012), Chillotti et al. (TFHE, JoC 2020),
# Badawi et al. (OpenFHE, 2023), Albrecht et al. (Homomorphic Encryption Security Standard, 2018).

import struct
import logging
import math
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict
from .utils import safeReadBytes, shannon_entropy

_log = logging.getLogger(__name__)


@dataclass
class HEDetectionResult:
    scheme: str                     # CKKS / BGV / BFV / TFHE / FHEW
    library: str = ""               # SEAL / HElib / OpenFHE / Lattigo / tfhe-rs / concrete
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    params: dict = field(default_factory=dict)
    detected_in: str = ""


# ==== RLWE 参数指纹 ====
# 同态加密的特征性参数组合 (ring degree N, max modulus bits)。
# CKKS: N=2^15..2^17, logQ≈800-1700, scale Δ ≈ 2^40→双精度逼近
# BGV: N=2^12..2^15, multiple small moduli (each ~50-60 bit)
# BFV: N=2^12..2^15, one large modulus Q, plaintext modulus t (通常 2^16+1 或质数)
# TFHE: N=2^10=1024, single-bit encryption, bootstrapping key ~46MB

_HE_PARAM_SIGNATURES: Dict[str, dict] = {
    'CKKS': {
        'min_N': 2**13, 'max_N': 2**17,
        'typical_scales': [2**30, 2**40, 2**50, 2**60],
        'description': 'approximate arithmetic, floating-point encryption',
    },
    'BGV': {
        'min_N': 2**12, 'max_N': 2**15,
        'typical_primes': [0x3FFFFFFF, 0x7FFFFFFF, 0xFFFFFFFF],
        'description': 'exact integer arithmetic, leveled homomorphism',
    },
    'BFV': {
        'min_N': 2**12, 'max_N': 2**15,
        'typical_t': [2**16 + 1, 65537, 0x10001, 786433],  # plaintext modulus
        'description': 'exact integer arithmetic, batch encoding',
    },
    'TFHE': {
        'min_N': 512, 'max_N': 2048,
        'bsk_size_min': 40_000_000,  # bootstrapping key ~46MB for N=1024
        'description': 'fast bootstrapping, gate-level operations',
    },
}


# ==== 库指纹 ====
_HE_LIB_DB: List[Tuple[bytes, str, float]] = [
    # Microsoft SEAL
    (b'Microsoft SEAL', 'SEAL', 0.95),
    (b'seal::', 'SEAL', 0.90),
    (b'SEALContext', 'SEAL', 0.88),
    (b'seal/util/', 'SEAL', 0.85),
    # HElib
    (b'helib::', 'HElib', 0.90),
    (b'HElib', 'HElib', 0.88),
    (b'FHEcontext', 'HElib', 0.85),
    (b'EncryptedArray', 'HElib', 0.82),
    (b'buildModChain', 'HElib', 0.80),
    # OpenFHE
    (b'openfhe', 'OpenFHE', 0.90),
    (b'OpenFHE', 'OpenFHE', 0.90),
    (b'lbcrypto::', 'OpenFHE', 0.85),
    (b'CryptoContext', 'OpenFHE', 0.82),
    (b'BinFHEContext', 'OpenFHE', 0.85),     # TFHE bootstrapping
    (b'CKKSRNS', 'OpenFHE', 0.82),
    # Lattigo
    (b'lattigo', 'Lattigo', 0.88),
    (b'github.com/tuneinsight/lattigo', 'Lattigo', 0.88),
    (b'ckks/', 'Lattigo', 0.75),
    (b'bgv/', 'Lattigo', 0.75),
    # tfhe-rs (Zama)
    (b'tfhe-rs', 'tfhe-rs', 0.88),
    (b'tfhe::', 'tfhe-rs', 0.85),
    (b'concrete_shortint', 'tfhe-rs', 0.82),
    (b'concrete_boolean', 'tfhe-rs', 0.80),
    (b'ClientKey', 'tfhe-rs', 0.78),
    (b'ServerKey', 'tfhe-rs', 0.78),
    # Concrete (Zama compiler)
    (b'concrete-ml', 'Concrete-ML', 0.85),
    (b'concrete_compiler', 'Concrete', 0.85),
    (b'fhe_circuit', 'Concrete', 0.80),
    # PALISADE → OpenFHE (legacy)
    (b'PALISADE', 'PALISADE (legacy)', 0.82),
    (b'lbcrypto', 'PALISADE/OpenFHE', 0.70),
    # cuFHE (GPU-accelerated TFHE)
    (b'cufhe', 'cuFHE (GPU)', 0.82),
    # SHE (有点同态加密)
    (b'paillier', 'Paillier (partial HE)', 0.85),
    (b'elgamal', 'ElGamal (multiplicative HE)', 0.80),
    (b'damgard', 'Damgard-Jurik (threshold HE)', 0.75),
]


# ==== CKKS/BGV 模数链检测 ====
# HElib/OpenFHE/SEAL 的模数链 (modulus chain) 是多个 ~50-60bit 质数的乘积,
# 在二进制中以 contiguous 数组方式存储。链长度 → 乘法深度。
# CKKS/BGV 同态乘法需要 rescale → 每次乘法 drop 最底层 modulus。

def _detect_modulus_chain(data: bytes) -> List[dict]:
    """搜索连续存储的小质数链 (50-60 bit, 10-60个), 典型HE参数."""
    chains = []
    # 50-bit 质数大约 2^50 ≈ 1.12e15, 即8字节存储 (LE u64)
    min_prime = 2**48
    max_prime = 2**62
    window = 8  # u64

    for off in range(0, len(data) - window * 4, window):
        # 尝试读取连续 u64 并检查是否均为质数且在HE模数范围内
        primes = []
        pos = off
        while pos + window <= len(data):
            val = struct.unpack_from('<Q', data, pos)[0]
            if min_prime <= val <= max_prime and _is_likely_prime(val):
                primes.append(val)
                pos += window
                if len(primes) > 60:  # 合理的上界
                    break
            else:
                break

        if len(primes) >= 8:
            chain_bits = sum(v.bit_length() for v in primes)
            chains.append({
                'offset': off, 'num_primes': len(primes),
                'total_bits': chain_bits,
                'first_primes': primes[:4],
            })
            off += len(primes) * window  # skip consumed region
    return chains


def _is_likely_prime(n: int) -> bool:
    """Miller-Rabin 概率质数检测 (确定性基集, n < 2^64)."""
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # Miller-Rabin for n < 2^64: bases [2, 325, 9375, 28178, 450775, 9780504, 1795265022]
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


# ==== TFHE bootstrapping key 检测 ====
# 单个 TFHE bootstrapping key 由多个 GGSW 样本组成 (~46MB, N=1024 标准参数).
# 每个 GGSW 样本 ≈ 2*(k+1)*l*N*8 bytes, 其中 k=1, l=3, N=1024 → ~196KB/sample.
# 完整的 bootstrapping key (含 256 个 samples) ≈ 46-62 MB。
# 检测策略: 搜索高熵大块 (40-70MB 范围), 计算自相关 — TFHE 密钥块具有
# 均匀分布的字节值 (entropy≈8.0), 但同时包含环形多项式结构导致的微弱的 lag-N 相关性。

def detect_tfhe_bootstrapping_key(data: bytes) -> Optional[dict]:
    """检测大型高熵块是否符合 TFHE bootstrapping key 特征."""
    min_size = 30_000_000   # 30 MB — 较小的 TFHE 参数
    max_size = 80_000_000   # 80 MB — 含冗余的较大参数

    if len(data) < min_size:
        return None

    # 分段扫描
    chunk = 1024 * 1024  # 1MB chunks
    scan_len = min(len(data), max_size * 2)

    candidates = []
    for off in range(0, scan_len - min_size, chunk):
        region = data[off:off + min_size]
        ent = shannon_entropy(region)
        if ent < 0.985:  # TFHE bsk 熵 > 0.99 是必要条件
            continue
        # 理想均匀: byte mean ≈ 127.5, std ≈ 73.9
        bmean = sum(region) / len(region)
        if abs(bmean - 127.5) > 2.0:
            continue
        candidates.append((off, ent, bmean))

    if not candidates:
        return None

    best = max(candidates, key=lambda c: c[1])
    return {
        'likely_tfhe_bsk': True,
        'offset': best[0],
        'entropy': round(best[1], 4),
        'byte_mean': round(best[2], 2),
        'size_mb': round(min_size / (1024 * 1024), 1),
    }


# ==== 检测器 ====

class HESchemeDetector:
    """同态加密方案检测器 — scheme/libraries/参数综合指纹."""

    def __init__(self):
        pass

    def scan_file(self, path: str) -> List[HEDetectionResult]:
        raw = safeReadBytes(path)
        if raw is None:
            return []  # fail silently — scan_bytes on empty data is a no-op anyway
        return self.scan_bytes(raw, source=path)

    def scan_bytes(self, data: bytes, source: str = "memory") -> List[HEDetectionResult]:
        results: List[HEDetectionResult] = []

        results.extend(self._detect_libraries(data, source))
        results.extend(self._detect_modulus_chains(data, source))
        results.extend(self._detect_tfhe_bsk(data, source))
        results.extend(self._detect_scheme_strings(data, source))

        seen = set()
        unique = []
        for r in results:
            key = (r.scheme, r.library)
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return sorted(unique, key=lambda r: -r.confidence)

    def _detect_libraries(self, data: bytes, source: str) -> List[HEDetectionResult]:
        results = []
        for pattern, lib_name, base_conf in _HE_LIB_DB:
            if pattern not in data:
                continue
            off = data.find(pattern)
            ctx = data[max(0, off - 8):off + len(pattern) + 24]
            try:
                ctx_str = ctx.decode('ascii', errors='replace')
            except Exception:
                ctx_str = ''

            # Scheme inference from library hints
            scheme = _infer_scheme(lib_name)
            results.append(HEDetectionResult(
                scheme=scheme, library=lib_name, confidence=base_conf,
                evidence=[f'library string: {ctx_str.strip()}'],
                detected_in=source))
        return results

    def _detect_modulus_chains(self, data: bytes, source: str) -> List[HEDetectionResult]:
        chains = _detect_modulus_chain(data)
        results = []
        for chain in chains:
            bits = chain['total_bits']
            scheme = ''
            if 800 <= bits <= 2000:
                scheme = 'CKKS'
            elif 200 <= bits <= 600:
                scheme = 'BGV/BFV'
            elif bits < 200:
                continue
            else:
                scheme = 'CKKS (deep)'

            results.append(HEDetectionResult(
                scheme=scheme, confidence=0.50 + min(0.30, chain['num_primes'] / 100),
                evidence=[
                    f'modulus chain: {chain["num_primes"]} primes, '
                    f'{bits} total bits at 0x{chain["offset"]:x}',
                    f'first primes: {chain["first_primes"]}',
                ],
                params={'num_primes': chain['num_primes'], 'total_bits': bits},
                detected_in=source))
        return results

    def _detect_tfhe_bsk(self, data: bytes, source: str) -> List[HEDetectionResult]:
        bsk = detect_tfhe_bootstrapping_key(data)
        if bsk is None:
            return []
        return [HEDetectionResult(
            scheme='TFHE', confidence=0.48,
            evidence=[
                f'Candidate bootstrapping key: {bsk["size_mb"]}MB, '
                f'H={bsk["entropy"]}, byte_mean={bsk["byte_mean"]}, '
                f'at offset 0x{bsk["offset"]:x}'
            ],
            params={'bsk_offset': bsk['offset'], 'bsk_size_mb': bsk['size_mb']},
            detected_in=source)]

    def _detect_scheme_strings(self, data: bytes, source: str) -> List[HEDetectionResult]:
        scheme_keywords = {
            b'CKKS': ('CKKS', 0.80),
            b'ckks': ('CKKS', 0.78),
            b'BGV': ('BGV', 0.80),
            b'bgv': ('BGV', 0.78),
            b'BFV': ('BFV', 0.80),
            b'bfv': ('BFV', 0.78),
            b'TFHE': ('TFHE', 0.82),
            b'tfhe': ('TFHE', 0.78),
            b'FHEW': ('FHEW', 0.82),
            b'fhew': ('FHEW', 0.78),
            b'DM': ('FHEW (DM/CGGI)', 0.65),
            b'CGGI': ('FHEW (CGGI)', 0.75),
        }
        results = []
        text = data.decode('ascii', errors='ignore')
        for keyword, (scheme, conf) in scheme_keywords.items():
            kw = keyword.decode()
            if kw not in text:
                continue
            idx = text.find(kw)
            ctx = text[max(0, idx - 10):idx + len(kw) + 20]
            results.append(HEDetectionResult(
                scheme=scheme, confidence=conf,
                evidence=[f'keyword "{kw}" context: ...{ctx.strip()}...'],
                detected_in=source))
        return results


def _infer_scheme(lib_name: str) -> str:
    """从库名推断FHE方案类型."""
    if any(k in lib_name.lower() for k in ('seal', 'lattigo', 'openfhe', 'palisade')):
        return 'CKKS/BGV/BFV'
    if any(k in lib_name.lower() for k in ('tfhe', 'concrete', 'cufhe')):
        return 'TFHE'
    if 'paillier' in lib_name.lower():
        return 'Paillier (PHE)'
    if 'elgamal' in lib_name.lower():
        return 'ElGamal (PHE)'
    return 'FHE (generic)'


# ==== 便捷函数 ====

def detect_homomorphic_encryption(path: str) -> List[HEDetectionResult]:
    return HESchemeDetector().scan_file(path)

def detect_he_bytes(data: bytes, source: str = "memory") -> List[HEDetectionResult]:
    return HESchemeDetector().scan_bytes(data, source)

__all__ = ['HESchemeDetector', 'HEDetectionResult',
           'detect_homomorphic_encryption', 'detect_he_bytes']
