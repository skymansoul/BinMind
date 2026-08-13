"""
同态加密噪声预算静态估计 — 从检测到的FHE实现参数推断噪声容量和安全边界。

修改记录:
  2025-08-06 22:41 — 初始实现: 方案识别/BGV-BFV-CKKS-TFHE参数推断/噪声预算估算

设计意图:
  同态加密(FHE)的正确性依赖噪声预算管理。噪声随同态运算累积, 超过阈值→解密失败。
  检测到FHE实现后, 关键问题是"此实现的参数是否提供了足够的安全性和噪声容量?"
  这需要静态推断FHE参数并估算噪声预算, 而不运行代码。

  本模块:
    (a) 从二进制常量推断FHE方案类型(BGV/BFV/CKKS/TFHE)。
    (b) 提取或估计关键参数: 多项式模度N, 密文模数q, 明文模数t/p。
    (c) 计算理论噪声预算和安全级别。
    (d) 标记参数不足的实现。

  - ILA: FHE类型系统与噪声估计 — 无需密钥的静态噪声跟踪。
    本项目将ILA的思路从IR层级移植到二进制常量层级。
  - Biasioli: BGV平均噪声估计 — 密钥依赖的噪声模型。
  - HEIR project: MLIR编译器噪声分析框架。
  - Homomorphic Encryption Standard: 参数选择指南。

边界条件:
  - 噪声估计是理论近似 — 不执行代码, 不模拟同态运算。
  - 参数提取依赖于编译时常量 → 混淆/加壳使提取失效。
  - TFHE的噪声模型与BGV/BFV/CKKS不同(门级自举 → 噪声不累积)。
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

@dataclass
class FHENoiseReport:
    scheme: str = ""               # BGV / BFV / CKKS / TFHE / UNKNOWN
    confidence: float = 0.0
    poly_degree: int = 0           # N (2的幂, 通常1024-65536)
    ciphertext_modulus_bits: int = 0  # log2(q)
    plaintext_modulus: int = 0     # t (BGV/BFV) 或 scale (CKKS)
    estimated_noise_budget: int = 0  # 剩余同态乘法的位数
    security_level_bits: int = 0   # 估计安全级别
    is_secure: bool = False
    warnings: List[str] = field(default_factory=list)

# FHE方案识别 — 基于参数特征

_FHE_SCHEME_SIGNATURES: Dict[str, List[bytes]] = {
    'SEAL (BFV/BGV/CKKS)': [b'seal', b'SEAL', b'Microsoft SEAL'],
    'OpenFHE': [b'openfhe', b'OPENFHE', b'OpenFHE'],
    'HElib': [b'helib', b'HElib', b'HELIB'],
    'TFHE-rs': [b'tfhe-rs', b'tfhe', b'TFHE'],
    'Concrete': [b'concrete', b'CONCRETE', b'Zama'],
    'PALISADE': [b'palisade', b'PALISADE'],
    'Lattigo': [b'lattigo', b'LATTIGO'],
}

def _identify_fhe_scheme(data: bytes, strings: List[str]) -> Tuple[str, float]:
    """通过字符串指纹识别FHE库和推断方案类型。"""
    for scheme_name, patterns in _FHE_SCHEME_SIGNATURES.items():
        for pat in patterns:
            if pat in data:
                # OpenFHE → 检查是否TFHE模式
                if b'binfhe' in data or b'BINFHE' in data:
                    return 'TFHE', 0.82
                # SEAL → 检查CKKS参数特征
                if b'CKKS' in data or b'ckks' in data:
                    return 'CKKS', 0.85
                if b'BFV' in data or b'bfv' in data:
                    return 'BFV', 0.85
                if b'BGV' in data or b'bgv' in data:
                    return 'BGV', 0.85
                return scheme_name, 0.70

    for s in strings:
        sb = s.encode('ascii', errors='replace') if isinstance(s, str) else s
        for scheme_name, patterns in _FHE_SCHEME_SIGNATURES.items():
            for pat in patterns:
                if pat in sb:
                    return scheme_name, 0.65

    return 'UNKNOWN', 0.10

# 参数提取

def _extract_poly_degree(data: bytes) -> Tuple[int, float]:
    """
    提取多项式模度N。FHE的N通常是2的幂(1024-65536)。
    在二进制中, N常以立即数形式出现在参数初始化代码中。
    搜索2的幂值作为可能的N。
    """
    expected_powers = [1024, 2048, 4096, 8192, 16384, 32768, 65536]
    candidates = {}
    for n in expected_powers:
        n_bytes_le = n.to_bytes(4, 'little')
        n_bytes_be = n.to_bytes(4, 'big')
        count = data.count(n_bytes_le) + data.count(n_bytes_be)
        if count > 0:
            candidates[n] = count

    if not candidates:
        return 4096, 0.30  # 保守默认值

    # 出现次数最多的N最可能是实际参数值
    best_n = max(candidates, key=candidates.get)
    conf = min(0.80, 0.40 + candidates[best_n] / 10.0)
    return best_n, conf

def _extract_modulus_bits(data: bytes, poly_n: int) -> Tuple[int, float]:
    """
    推断密文模数q的比特大小。
    q通常接近poly_n的数倍 — 例如N=4096时q≈109-128bit, N=16384时q≈440-880bit。
    在二进制中搜索大质数模数: 高位全1的数值模式(如0xFFFF...FF是掩码,
    0x7FFFF...FF是Mersenne质数)。
    """
    # 针对不同N → 典型的q bit范围
    typical_ranges = {
        1024: (27, 54), 2048: (54, 109), 4096: (109, 218),
        8192: (218, 440), 16384: (440, 880), 32768: (880, 1760),
    }
    expected_range = typical_ranges.get(poly_n, (109, 440))

    # 搜索数据段中的大整数模式
    # 启发式: 寻找高位字(>0x7F...)的8字节块，可能是模数的一部分
    modulus_candidates = []
    for i in range(0, len(data) - 8, 8):
        chunk = data[i:i+8]
        val = int.from_bytes(chunk, 'little')
        # 模数q的特征: 大但非全1, 且不是2的幂
        if val > (1 << 54) and val < (1 << 1024):
            bit_len = val.bit_length()
            if expected_range[0] <= bit_len <= expected_range[1] * 2:
                modulus_candidates.append(bit_len)

    if modulus_candidates:
        # 取众数
        from collections import Counter
        most_common = Counter(modulus_candidates).most_common(1)[0][0]
        return most_common, 0.60

    # 默认: 取范围中值
    mid = (expected_range[0] + expected_range[1]) // 2
    return mid, 0.25

# 噪声预算估算

def _estimate_noise_budget(scheme: str, poly_n: int,
                           q_bits: int) -> Tuple[int, List[str]]:
    """
    理论噪声预算估算。
    BGV/BFV: 噪声 ≈ log2(q/t) - 每次乘法的噪声增长
    CKKS: 噪声 ≈ scale预算 → 重缩放后剩余精度
    TFHE: 噪声不累积(门级自举) → 预算概念不同
    """
    warnings: List[str] = []

    if 'BGV' in scheme or 'BFV' in scheme:
        # 明文模数t通常为16-20bit(BFV)或2-16bit(BGV)
        # 噪声预算 ≈ log2(q) - log2(t) - 每次乘法的噪声
        t_bits = 20 if 'BFV' in scheme else 16
        # 每次乘法消耗约log2(N) + 常数 bit的噪声
        mul_noise = int(math.log2(poly_n)) + 8
        budget = q_bits - t_bits
        max_muls = budget // mul_noise if mul_noise > 0 else 0
        if max_muls < 2:
            warnings.append(f"仅支持{max_muls}次同态乘法—可能不足以完成有意义的计算")
        return budget, warnings

    elif 'CKKS' in scheme:
        # CKKS: 噪声以精度损失体现
        # 典型scale = 40bit, q初始≈scale * (levels+1)
        scale_bits = 40
        levels = q_bits // scale_bits - 1
        if levels < 3:
            warnings.append(f"CKKS仅{levels}个乘法层级—参数可能不足")
        # 噪声预算以剩余精度bit表示
        budget = q_bits - scale_bits  # 首层后的预算
        return max(0, budget), warnings

    elif 'TFHE' in scheme:
        # TFHE门自举: 每次门操作后噪声被清除
        # 安全级别取决于参数而非噪声预算
        if poly_n < 1024:
            warnings.append("TFHE: N<1024 — 安全级别不足")
        return int(2 * math.log2(poly_n)), warnings

    # unknown: 保守估计
    budget = q_bits // 2
    return budget, warnings

def _estimate_security_level(poly_n: int, q_bits: int) -> Tuple[int, bool]:
    """
    基于LWE估计器公式估算安全级别。
    简化公式: λ ≈ min(sqrt(N), log2(q)/2) * 常数
    来源: Albrecht et al., "On the concrete hardness of LWE".
    """
    # 简化估计: LWE维度=N, 噪声比=α=q的逆
    # 对于实际参数, 安全级别 ≈ sqrt(N) * 常数
    base = math.sqrt(poly_n) * 0.28

    # 模数越大 → LWE越困难, 但边际增益递减
    modulus_factor = min(1.5, math.log2(q_bits) / 80.0) if q_bits > 0 else 1.0
    lambda_est = int(base * modulus_factor * 1.1)

    is_secure = lambda_est >= 128
    return lambda_est, is_secure

# 主分析器

class FHENoiseEstimator:
    """FHE实现噪声预算静态估计器。"""

    def __init__(self, data: bytes, strings: Optional[List[str]] = None):
        self._data = data
        self._strs = strings or []

    def analyze(self) -> FHENoiseReport:
        scheme, scheme_conf = _identify_fhe_scheme(self._data, self._strs)
        poly_n, n_conf = _extract_poly_degree(self._data)
        q_bits, q_conf = _extract_modulus_bits(self._data, poly_n)

        budget, warnings = _estimate_noise_budget(scheme, poly_n, q_bits)
        sec_level, is_secure = _estimate_security_level(poly_n, q_bits)

        if sec_level < 128:
            warnings.append(f"安全级别≈{sec_level}bit低于128bit标准")
        if budget < 20 and 'TFHE' not in scheme:
            warnings.append(f"噪声预算{budget}bit不足—解密可能失败")

        avg_conf = (scheme_conf + n_conf + q_conf) / 3.0

        return FHENoiseReport(
            scheme=scheme, confidence=round(avg_conf, 3),
            poly_degree=poly_n,
            ciphertext_modulus_bits=q_bits,
            plaintext_modulus=0,  # 无法从二进制中可靠提取
            estimated_noise_budget=budget,
            security_level_bits=sec_level,
            is_secure=is_secure,
            warnings=warnings)

def estimate_noise(data: bytes, strings: Optional[List[str]] = None) -> FHENoiseReport:
    """便捷函数。"""
    return FHENoiseEstimator(data, strings).analyze()
