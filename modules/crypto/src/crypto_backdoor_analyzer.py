"""
密码学后门易感性分析 — 检测暗示故意弱化的数学结构异常。

设计意图:
  既有crypto_misuse检测意外误用(硬编码密钥/弱IV/短盐), crypto_invariants验证
  S-box数学性质。但两者都不覆盖"故意设计为可被设计者破解"的后门场景。
  密码学后门通常嵌入在看似合法的数学常数中:
    (a) Dual_EC_DRBG: 椭圆曲线点P,Q满足Q = e*P, e仅设计者已知。
    (b) 弱DH参数: 模数p-1具有小因子 → Pohlig-Hellman攻击可行。
    (c) 异常曲线: 嵌入度k很小 → 配对攻击可行。
    (d) NOBUS: "Nobody But Us" — 后门仅对持有陷门者可行。

  检测策略不依赖于已知后门的签名, 而是检测"数学上不必要但可被利用"的
  结构特征。这避免了"已知模式匹配的滞后性" — 新设计的后门共享这些数学特征。

  4个检测维度:
    D1: 异常常数 — 密码学常数是否来自标准的nothing-up-my-sleeve值?
    D2: 弱参数结构 — 有限域/椭圆曲线参数是否具有非标准的分解特征?
    D3: 可预测性 — 常数生成过程是否可被外部重现?
    D4: 陷门证据 — 是否存在可被陷门持有者利用的数学关系?

  - Bernstein et al., "Dual EC: A Standardized Back Door":
    对NIST SP 800-90A Dual_EC_DRBG后门的系统分析 — 后门嵌入在推荐参数中。
  - Wong, "How to Backdoor Diffie-Hellman":
    DH参数后门的构造方法 — 使用小素数因子的模数。

边界条件:
  - 当前聚焦于经典密码学(椭圆曲线/DH/RSA)的后门模式。
  - PQC后门检测(格基/NTRU/Kyber陷门)处于实验阶段 — 标记为低置信度。
  - 假阳性风险: 非标准但安全的参数可能被误判 — 输出标记为SUSPICIOUS而非BACKDOOR。
"""

import math
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class BackdoorSusceptibility:
    algorithm: str = ""
    evidence_type: str = ""         # ABNORMAL_CONSTANT / WEAK_PARAM / PREDICTABLE / TRAPDOOR
    severity: str = "UNKNOWN"       # NEGLIGIBLE / LOW / MEDIUM / HIGH / CRITICAL
    confidence: float = 0.0
    detail: str = ""
    location: int = 0

# D1: 异常常数检测
# 密码学常量应来自nothing-up-my-sleeve值(π/e/sqrt(2)的小数部分等)。
# 异常的熵分布暗示人为选择→可能嵌入了数学关系。

def _check_nothing_up_my_sleeve(data: bytes, offset: int, size: int) -> Optional[BackdoorSusceptibility]:
    """
    检查指定区域是否符合nothing-up-my-sleeve常数的预期模式。
    标准NUMS值包括: π, e, sqrt(2), 黄金比例的二进制展开。
    """
    region = data[offset:offset + size]
    if len(region) < 8:
        return None

    # 取前64bit与已知NUMS值比较
    # π的二进制展开: 0x243F6A8885A308D3...
    # e的二进制展开:  0x2B7E151628AED2A6...
    # sqrt(2)的展开:  0x3FF6A09E667F3BCD...
    # 黄金比例φ:      0x9E3779B97F4A7C15...
    _NUMS_PREFIXES = {
        b'\x24\x3F\x6A\x88\x85\xA3\x08\xD3': 'π fraction',
        b'\x2B\x7E\x15\x16\x28\xAE\xD2\xA6': 'e fraction',
        b'\x3F\xF6\xA0\x9E\x66\x7F\x3B\xCD': '√2 fraction',
        b'\x9E\x37\x79\xB9\x7F\x4A\x7C\x15': 'golden ratio φ',
    }

    probe = region[:8]
    for nums_prefix, source in _NUMS_PREFIXES.items():
        if probe == nums_prefix:
            return None  # 标准NUMS值 — 正常

    # 若不在已知NUMS列表中, 检查熵分布
    from collections import Counter
    cnt = Counter(region)
    entropy = 0.0
    rlen = float(len(region))
    for c in cnt.values():
        p = c / rlen
        entropy -= p * math.log2(p)

    max_ent = math.log2(min(len(cnt), 256))
    norm_ent = entropy / max_ent if max_ent > 0 else 0.0

    # 低熵常数 → 可疑 (真实密码学常数应接近最大熵)
    if norm_ent < 0.70:
        return BackdoorSusceptibility(
            algorithm="unknown",
            evidence_type="ABNORMAL_CONSTANT",
            severity="MEDIUM",
            confidence=0.65,
            detail=f"Low-entropy constant (H_norm={norm_ent:.3f}) not matching known NUMS values at 0x{offset:x}",
            location=offset)
    return None

# D2: 弱椭圆曲线参数检测

# 已知安全曲线的参数 — 偏离这些暗示自定义/弱曲线
_SAFE_CURVE_PARAMS: Dict[str, bytes] = {
    # NIST P-256: y^2 = x^3 - 3x + b, 其中b来自SHA-1种子
    'P-256_b': bytes.fromhex('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'),
    # Curve25519: y^2 = x^3 + 486662x^2 + x
    'Curve25519_A': (486662).to_bytes(32, 'little'),
    # secp256k1 (Bitcoin): b = 7
    'secp256k1_b': b'\x00' * 31 + b'\x07',
}

# 可疑曲线特征模式
_SUSPICIOUS_CURVE_FLAGS = [
    (b'\x00' * 16, 'all-zero parameter block'),   # 全零参数 — 几乎肯定是测试/后门
    (b'\xFF' * 16, 'all-ones parameter block'),   # 全一参数 — 同上
    (b'\x01' + b'\x00' * 15, 'minimal parameter'), # 极小参数 → 可能易受攻击
]

def _check_curve_params(data: bytes, offset: int) -> Optional[BackdoorSusceptibility]:
    """检查椭圆曲线参数块是否有已知的不安全信号。"""
    region = data[offset:offset + 64] if offset + 64 <= len(data) else data[offset:]

    # 与已知安全曲线比较
    for curve_name, param in _SAFE_CURVE_PARAMS.items():
        if param in region:
            return None  # 匹配已知安全曲线

    # 检查可疑模式
    for pattern, desc in _SUSPICIOUS_CURVE_FLAGS:
        if pattern in region:
            return BackdoorSusceptibility(
                algorithm="ECC",
                evidence_type="WEAK_PARAM",
                severity="CRITICAL",
                confidence=0.88,
                detail=f"Suspicious curve parameter: {desc} at 0x{offset:x}",
                location=offset)

    return None

# D3: 可预测常数生成

def _check_predictable_constants(data: bytes, offset: int) -> Optional[BackdoorSusceptibility]:
    """
    检测通过可预测方法生成的常数。
    真实密码学常数需展示"不可预测"性 — 即无法通过简单函数从前驱生成。
    若检测到简单递推关系 → 常数由设计者选择, 可能嵌入了只有设计者知道的数学关系。
    """
    region = data[offset:offset + 64] if offset + 64 <= len(data) else data[offset:]
    if len(region) < 16:
        return None

    # 检查线性递推: a_{n+1} = k*a_n + c
    # 对4字节窗口做差商检测
    quads = [int.from_bytes(region[i:i+4], 'little') for i in range(0, len(region)-4, 4)]
    if len(quads) < 3:
        return None

    # 差商一致性检测: 若所有相邻差商相近, 怀疑线性递推
    diffs = [(quads[i+1] - quads[i]) & 0xFFFFFFFF for i in range(len(quads)-1)]
    if len(diffs) >= 3 and len(set(diffs[:3])) <= 1:
        return BackdoorSusceptibility(
            algorithm="unknown",
            evidence_type="PREDICTABLE",
            severity="MEDIUM",
            confidence=0.60,
            detail=f"Linear recurrence detected in constant block at 0x{offset:x}",
            location=offset)

    return None

# D4: 陷门证据 — Dual_EC_DRBG模式

def _check_dual_ec_pattern(data: bytes, offset: int) -> Optional[BackdoorSusceptibility]:
    """
    检测Dual_EC_DRBG类后门模式:
    椭圆曲线上存在点P和Q, Q = e*P (e未知) — 这是经典kleptographic后门。
    在二进制中表现为: 两个相邻的椭圆曲线点(各32/48/64字节)后跟TRNG输出节。
    """
    region = data[offset:offset + 128] if offset + 128 <= len(data) else data[offset:]
    if len(region) < 64:
        return None

    # Dual_EC_DRBG的后门结构: P.x || P.y || Q.x || Q.y (各32字节 for P-256)
    # 若发现两个256-bit值的配对, 检查是否为椭圆曲线点结构
    for curve_size in [32, 48, 64]:  # P-256 / P-384 / P-521
        if offset + 4 * curve_size > len(data):
            continue
        p1 = data[offset:offset + curve_size]
        p2 = data[offset + curve_size:offset + 2*curve_size]
        q1 = data[offset + 2*curve_size:offset + 3*curve_size]
        q2 = data[offset + 3*curve_size:offset + 4*curve_size]

        # 若P=(p1,p2)和Q=(q1,q2)都不是全零且不是已知标准点, 标记
        all_zero = b'\x00' * curve_size
        if p1 != all_zero and q1 != all_zero:
            # 检查是否为已知安全曲线上的点
            known_match = False
            for _, param in _SAFE_CURVE_PARAMS.items():
                if param[:curve_size] in (p1, q1):
                    known_match = True
                    break
            if not known_match and p1[:4] != b'\x00\x00\x00\x00':
                return BackdoorSusceptibility(
                    algorithm="ECC (Dual_EC-like)",
                    evidence_type="TRAPDOOR",
                    severity="HIGH",
                    confidence=0.55,
                    detail=f"Paired EC points (size={curve_size*8}bit) at 0x{offset:x} — possible Dual_EC_DRBG structure",
                    location=offset)
    return None

# 主分析器

class BackdoorAnalyzer:
    """密码学后门易感性分析器 — 组合四维检测。"""

    def __init__(self, data: bytes):
        self._data = data

    def analyze(self) -> List[BackdoorSusceptibility]:
        findings: List[BackdoorSusceptibility] = []

        # 以256字节为步长扫描
        for offset in range(0, len(self._data) - 32, 256):
            result = (_check_nothing_up_my_sleeve(self._data, offset, 32)
                      or _check_curve_params(self._data, offset)
                      or _check_predictable_constants(self._data, offset)
                      or _check_dual_ec_pattern(self._data, offset))
            if result:
                findings.append(result)

        return findings

    def analyze_at(self, offset: int, algorithm: str = "") -> List[BackdoorSusceptibility]:
        """对指定偏移进行针对性分析。"""
        findings = []
        for checker in [_check_nothing_up_my_sleeve, _check_curve_params,
                        _check_predictable_constants, _check_dual_ec_pattern]:
            result = checker(self._data, offset)
            if result:
                if algorithm:
                    result.algorithm = algorithm
                findings.append(result)
        # 每个偏移最多报告一个最高严重度的发现
        if len(findings) > 1:
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NEGLIGIBLE": 4}
            findings.sort(key=lambda f: severity_order.get(f.severity, 5))
            findings = findings[:1]
        return findings

def audit_backdoor_risk(data: bytes, findings: Optional[List] = None) -> List[BackdoorSusceptibility]:
    """
    便捷函数 — 对检测到的密码学区域进行后门易感性审计。
    findings为crypto_detector的输出, 用于定位分析位置。
    """
    analyzer = BackdoorAnalyzer(data)
    if findings:
        results = []
        seen = set()
        for f in findings:
            try:
                loc = getattr(f, 'location', 0)
                algo = getattr(f, 'algorithm', '')
                if loc not in seen:
                    seen.add(loc)
                    results.extend(analyzer.analyze_at(loc, algo))
            except Exception:
                pass
        return results

    # 无findings → 全扫描
    return analyzer.analyze()
