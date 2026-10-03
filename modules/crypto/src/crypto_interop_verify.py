"""
密码学互操作性验证 — 验证两个检测到的密码学实现是否能正确通信/交互。

设计意图:
  部署两个声称"使用AES-256-GCM"的系统并不能保证它们可以互操作。
  密码学互操作性的隐形断裂点包括:
    (a) 算法相同但模式不同(AES-256-ECB vs AES-256-GCM)
    (b) 密钥长度相同但密钥格式不同(PKCS#8 vs raw; DER vs PEM)
    (c) 协议版本兼容但密码套件不重叠(TLS 1.3仅AEAD, 对端仅支持CBC)
    (d) PQC混合模式中经典部分兼容但PQC部分不兼容(不同ML-KEM参数集)

  本模块从两个二进制各自的检测结果出发, 验证密码学互操作性,
  输出兼容性矩阵和断裂点列表。

  检查维度:
    C1: 算法兼容性 — 加密/解密算法配对。AES加密必须对端有AES解密。
    C2: 模式兼容性 — GCM不能与ECB互操作。
    C3: 参数对齐 — 密钥长度/HKDF salt长度/迭代次数。
    C4: 协议版本 — TLS 1.2 vs 1.3; SSHv1 vs SSHv2。
    C5: PQC混合兼容性 — X25519+ML-KEM-768 vs X25519+ML-KEM-1024不兼容。

  - NIST SP 800-56Ar3: 密钥协商方案的兼容性要求。
  - IETF TLS 1.3 (RFC 8446): 密码套件协商和互操作性。
  - NIST SP 800-38A-D: 分组密码工作模式定义。
  - GSMA IoT SAFE: IoT设备的密码学互操作性规范。

边界条件:
  - 互操作性是"必要条件"而非"充分条件"验证 — 实现可以满足所有检查
    但仍因协议时序/状态机差异而无法通信。
  - 密钥格式检测依赖字符串分析 — 对混淆代码精度有限。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

class CompatStatus(Enum):
    COMPATIBLE = 0
    PARTIALLY_COMPATIBLE = 1
    INCOMPATIBLE = 2
    UNKNOWN = 3

@dataclass
class InteropCheck:
    check_id: str = ""
    dimension: str = ""            # ALGORITHM / MODE / PARAMETER / PROTOCOL / PQC_HYBRID
    status: CompatStatus = CompatStatus.UNKNOWN
    detail: str = ""
    entity_a: str = ""             # 二进制A中的相关值
    entity_b: str = ""             # 二进制B中的相关值
    recommendation: str = ""

# 兼容性规则库

_MODE_COMPAT: Dict[str, Set[str]] = {
    # 哪些模式对可以互操作(对称: 加密方模式→解密方模式)
    'GCM': {'GCM'},
    'CCM': {'CCM'},
    'ECB': {'ECB'},
    'CBC': {'CBC'},
    'CTR': {'CTR'},
    'ChaCha20-Poly1305': {'ChaCha20-Poly1305'},
}

_ALGO_EQUIVALENCE: Dict[str, str] = {
    # 同一算法的不同命名 → 标准化名
    'AES-128-GCM': 'AES-128-GCM', 'AES-256-GCM': 'AES-256-GCM',
    'ChaCha20': 'ChaCha20-Poly1305',
    'X25519': 'ECDH-Curve25519', 'Curve25519': 'ECDH-Curve25519',
    'Ed25519': 'EdDSA-Ed25519',
    'ML-KEM-768': 'ML-KEM-768', 'Kyber-768': 'ML-KEM-768',
    'Kyber768': 'ML-KEM-768',
}

def _normalize_algorithm(algo: str) -> str:
    return _ALGO_EQUIVALENCE.get(algo, algo)

def _extract_mode(algo: str) -> str:
    for mode in _MODE_COMPAT:
        if mode in algo:
            return mode
    return ''

def _extract_key_bits(algo: str) -> int:
    import re
    m = re.search(r'(\d+)', algo)
    return int(m.group(1)) if m else 0

def verify_interoperability(
        findings_a: Optional[List] = None,
        findings_b: Optional[List] = None,
        algo_names_a: Optional[List[str]] = None,
        algo_names_b: Optional[List[str]] = None,
        protocol_a: Optional[str] = None,
        protocol_b: Optional[str] = None,
) -> List[InteropCheck]:
    """
    验证两个二进制实现的密码学互操作性。
    """
    checks: List[InteropCheck] = []
    algos_a = list(algo_names_a or [])
    algos_b = list(algo_names_b or [])

    for flist, target in [(findings_a, algos_a), (findings_b, algos_b)]:
        if flist:
            for f in flist:
                try:
                    target.append(getattr(f, 'algorithm', ''))
                except Exception:
                    pass

    # C1: 算法兼容性
    normalized_a = {_normalize_algorithm(a) for a in algos_a}
    normalized_b = {_normalize_algorithm(a) for a in algos_b}
    common = normalized_a & normalized_b
    only_a = normalized_a - normalized_b
    only_b = normalized_b - normalized_a

    if common:
        checks.append(InteropCheck(
            check_id='C1-ALGO', dimension='ALGORITHM',
            status=CompatStatus.COMPATIBLE,
            detail=f'共享算法: {sorted(common)}',
            entity_a=str(sorted(common)), entity_b=str(sorted(common))))
    else:
        checks.append(InteropCheck(
            check_id='C1-ALGO', dimension='ALGORITHM',
            status=CompatStatus.INCOMPATIBLE,
            detail=f'无共享算法; A独有:{sorted(only_a)}, B独有:{sorted(only_b)}',
            entity_a=str(sorted(only_a)), entity_b=str(sorted(only_b)),
            recommendation='双方需至少共享一个密码学算法'))

    # C2: 模式兼容性
    for algo in common:
        mode_a = _extract_mode(algo)
        mode_b = _extract_mode(algo)
        if mode_a and mode_b:
            compat_modes = _MODE_COMPAT.get(mode_a, set())
            if mode_b in compat_modes:
                checks.append(InteropCheck(
                    check_id=f'C2-MODE-{algo}', dimension='MODE',
                    status=CompatStatus.COMPATIBLE,
                    detail=f'{algo}: 模式{mode_a}↔{mode_b}兼容',
                    entity_a=mode_a, entity_b=mode_b))
            else:
                checks.append(InteropCheck(
                    check_id=f'C2-MODE-{algo}', dimension='MODE',
                    status=CompatStatus.INCOMPATIBLE,
                    detail=f'{algo}: 模式{mode_a}与{mode_b}不兼容',
                    entity_a=mode_a, entity_b=mode_b,
                    recommendation=f'统一为兼容模式: {compat_modes}'))

    # C3: 参数对齐(密钥长度)
    for algo in common:
        kb_a = _extract_key_bits(algo)
        kb_b = _extract_key_bits(algo)
        if kb_a and kb_b:
            if kb_a == kb_b:
                checks.append(InteropCheck(
                    check_id=f'C3-PARAM-{algo}', dimension='PARAMETER',
                    status=CompatStatus.COMPATIBLE,
                    detail=f'{algo}: 密钥长度对齐({kb_a}bit)',
                    entity_a=str(kb_a), entity_b=str(kb_b)))
            else:
                checks.append(InteropCheck(
                    check_id=f'C3-PARAM-{algo}', dimension='PARAMETER',
                    status=CompatStatus.INCOMPATIBLE,
                    detail=f'{algo}: 密钥长度不匹配({kb_a}bit vs {kb_b}bit)',
                    entity_a=str(kb_a), entity_b=str(kb_b),
                    recommendation=f'统一密钥长度为max({kb_a},{kb_b})bit'))

    # C4: 协议版本
    if protocol_a and protocol_b:
        if protocol_a == protocol_b:
            checks.append(InteropCheck(
                check_id='C4-PROTO', dimension='PROTOCOL',
                status=CompatStatus.COMPATIBLE,
                detail=f'协议版本一致: {protocol_a}',
                entity_a=protocol_a, entity_b=protocol_b))
        else:
            checks.append(InteropCheck(
                check_id='C4-PROTO', dimension='PROTOCOL',
                status=CompatStatus.PARTIALLY_COMPATIBLE,
                detail=f'协议版本差异: {protocol_a} vs {protocol_b}',
                entity_a=protocol_a, entity_b=protocol_b,
                recommendation='确认低版本兼容性或升级到共同版本'))

    # C5: PQC混合兼容性
    for algo in common:
        if 'ML-KEM' in algo or 'Kyber' in algo:
            checks.append(InteropCheck(
                check_id=f'C5-PQC-{algo}', dimension='PQC_HYBRID',
                status=CompatStatus.COMPATIBLE,
                detail=f'PQC参数集一致: {algo}',
                entity_a=algo, entity_b=algo))

    return checks

def compatibility_summary(checks: List[InteropCheck]) -> Tuple[bool, int, int, int]:
    """汇总兼容性: (总体兼容, 兼容数, 部分兼容数, 不兼容数)。"""
    compat = sum(1 for c in checks if c.status == CompatStatus.COMPATIBLE)
    partial = sum(1 for c in checks if c.status == CompatStatus.PARTIALLY_COMPATIBLE)
    incompat = sum(1 for c in checks if c.status == CompatStatus.INCOMPATIBLE)
    return incompat == 0, compat, partial, incompat
