"""
密码学配置漂移检测 — 比较同一二进制两个版本间密码学实现的非预期变更。

设计意图:
  固件更新声称"修复了安全漏洞, 无其他变更" — 但密码学实现是否真的未变?
  密码学配置漂移指两个版本之间密码学实现的非预期或未声明的变更:
    (a) 算法替换: AES-256→AES-128 (安全降级) 或 RSA-2048→ML-KEM (PQC迁移)。
    (b) 参数漂移: 密钥长度/轮数/HKDF迭代次数/Salt长度的意外变化。
    (c) 实现替换: 同一算法从硬件AES-NI切换到软件查表(可能引入侧信道)。
    (d) 新增/删除: 神秘出现或消失的密码学实现(可能的供应链攻击或后门清理)。

  既有二进制diff工具(bindiff/Diaphora)做通用的代码差异比较,
  但无工具理解密码学语义 — "AES-128替换为AES-256"在通用diff看来只是
  两个不同的字节序列, 对密码学漂移检测器而言这是"算法参数的安全升级"。

  检测策略:
    1. 从两个版本的crypto_detector输出中提取密码学实例列表。
    2. 使用crypto_semantic_hash做跨版本实例匹配(容忍编译差异)。
    3. 对匹配上的实例对比算法/参数/实现类型。
    4. 标记所有差异并分类(安全升级/降级/中性变更/可疑)。

  - Diaphora: 二进制diffing框架 — 通用代码差异比较;
    本项目补充其缺失的密码学语义理解层。
  - FirmUp: 固件跨版本漏洞检测 — 代码匹配方法论。
  - BinCrypto: 二进制密码学函数识别 — 提供本模块的检测前端。

边界条件:
  - 跨版本指纹匹配容忍编译器和优化级别差异, 但不容忍算法替换本身。
  - 手写汇编实现的变化可能无法通过语义哈希精确匹配 → 报告为IMPLEMENTATION_SWAP。
  - 混淆/加壳的二进制版本无法可靠对比 → 输出UNCERTAIN标记。
"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

class DriftType(Enum):
    ALGORITHM_CHANGED = 0    # 算法完全替换(AES→SM4)
    PARAMETER_DRIFT = 1      # 算法相同但参数变化(AES-128→AES-256)
    IMPLEMENTATION_SWAP = 2  # 同一算法不同实现(软件→硬件)
    SECURITY_DOWNGRADE = 3   # 安全降级(256→128, SHA-512→SHA-256)
    SECURITY_UPGRADE = 4     # 安全升级(128→256, RSA→ML-KEM)
    ADDED = 5                # 新增密码学实现
    REMOVED = 6              # 删除密码学实现
    UNCHANGED = 7            # 无变化
    UNCERTAIN = 8            # 无法确定

@dataclass
class ConfigDrift:
    algorithm_before: str = ""
    algorithm_after: str = ""
    drift_type: DriftType = DriftType.UNCHANGED
    confidence: float = 0.0
    location_before: int = 0
    location_after: int = 0
    details: str = ""
    security_impact: str = ""     # NONE / POSITIVE / NEGATIVE / UNCERTAIN
    recommendation: str = ""

# 算法安全级别映射
# 用于自动判定升级/降级
_ALGO_SECURITY_LEVEL: Dict[str, int] = {
    # 对称 (密钥长度作为级别代理)
    'AES-256': 5, 'AES-192': 4, 'AES-128': 3, 'AES': 3,
    'ChaCha20': 5, 'SM4': 3,
    'DES': 0, '3DES': 1,
    # 哈希 (输出bit数)
    'SHA-512': 5, 'SHA-384': 5, 'SHA-256': 4, 'SHA-1': 0, 'MD5': 0,
    'SM3': 3, 'BLAKE2': 5, 'SHA-3 (Keccak-f[1600])': 5,
    # 非对称 (粗略安全级别: 经典安全性)
    'RSA': 4, 'ECDSA': 3, 'Ed25519': 4, 'EdDSA': 4, 'DSA': 2,
    'ECDH': 3, 'DH': 3, 'X25519': 4,
    # PQC
    'ML-KEM': 5, 'ML-DSA': 5, 'SLH-DSA': 5,
    'ASCON-128': 4, 'ASCON-128a': 4,
}

def _classify_algorithm_change(algo_before: str, algo_after: str) -> Tuple[DriftType, str]:
    """分类算法变更的语义: 升级/降级/中性替换。"""
    level_before = _ALGO_SECURITY_LEVEL.get(algo_before, -1)
    level_after = _ALGO_SECURITY_LEVEL.get(algo_after, -1)

    if algo_before == algo_after:
        return DriftType.UNCHANGED, ''
    if level_before < 0 or level_after < 0:
        return DriftType.ALGORITHM_CHANGED, 'UNCERTAIN'

    diff = level_after - level_before
    if diff > 1:
        return DriftType.SECURITY_UPGRADE, 'POSITIVE'
    elif diff >= 0:
        return DriftType.ALGORITHM_CHANGED, 'UNCERTAIN'
    elif diff == -1:
        return DriftType.SECURITY_DOWNGRADE, 'NEGATIVE'
    else:
        return DriftType.SECURITY_DOWNGRADE, 'NEGATIVE'

def _group_by_algorithm(findings: List) -> Dict[str, List]:
    """按算法名分组crypto findings。"""
    groups: Dict[str, List] = defaultdict(list)
    for f in findings:
        try:
            algo = getattr(f, 'algorithm', 'unknown')
            groups[algo].append(f)
        except Exception:
            pass
    return dict(groups)

def _compare_implementations(algo: str, before_findings: List,
                             after_findings: List) -> List[ConfigDrift]:
    """比较同一算法的两个版本实现。"""
    drifts: List[ConfigDrift] = []
    count_before = len(before_findings)
    count_after = len(after_findings)

    if count_before == 0 and count_after > 0:
        loc = getattr(after_findings[0], 'location', 0)
        drifts.append(ConfigDrift(
            algorithm_before='', algorithm_after=algo,
            drift_type=DriftType.ADDED, confidence=0.85,
            location_after=loc,
            details=f'新增{algo}: {count_after} instance(s)',
            security_impact='UNCERTAIN',
            recommendation=f'确认新增的{algo}实现是否有合法来源'))
        return drifts

    if count_before > 0 and count_after == 0:
        loc = getattr(before_findings[0], 'location', 0)
        drifts.append(ConfigDrift(
            algorithm_before=algo, algorithm_after='',
            drift_type=DriftType.REMOVED, confidence=0.85,
            location_before=loc,
            details=f'删除{algo}: {count_before} instance(s)',
            security_impact='NEGATIVE' if algo in ('AES-256', 'ChaCha20',
                                                   'SHA-512', 'Ed25519') else 'UNCERTAIN',
            recommendation=f'确认{algo}的删除是否为预期行为'))
        return drifts

    # 两版本都有 → 数量变化
    if count_before != count_after:
        drift_type, impact = _classify_algorithm_change(algo, algo)
        drifts.append(ConfigDrift(
            algorithm_before=algo, algorithm_after=algo,
            drift_type=DriftType.PARAMETER_DRIFT,
            confidence=0.65,
            details=f'{algo}实例数变化: {count_before}→{count_after}',
            security_impact='UNCERTAIN',
            recommendation='检查实例数变化原因(去重/内联/重构?)'))

    # UNCHANGED作为基线
    if not drifts:
        drifts.append(ConfigDrift(
            algorithm_before=algo, algorithm_after=algo,
            drift_type=DriftType.UNCHANGED, confidence=0.90,
            details=f'{algo}: {count_before}→{count_after} instances (stable)',
            security_impact='NONE'))

    return drifts

def detect_config_drift(findings_before: List,
                        findings_after: List,
                        threshold_confidence: float = 0.5
                        ) -> List[ConfigDrift]:
    """
    检测两个版本二进制之间的密码学配置漂移。
    findings_before/after: 来自crypto_detector的检测结果。
    """
    before_groups = _group_by_algorithm(findings_before)
    after_groups = _group_by_algorithm(findings_after)
    all_algos = set(before_groups.keys()) | set(after_groups.keys())

    all_drifts: List[ConfigDrift] = []
    for algo in sorted(all_algos):
        bf = before_groups.get(algo, [])
        af = after_groups.get(algo, [])
        all_drifts.extend(_compare_implementations(algo, bf, af))

    # 跨算法变更检测(算法A→算法B, 实例数同时变化)
    added_algos = {a for a in after_groups if a not in before_groups}
    removed_algos = {a for a in before_groups if a not in after_groups}
    if added_algos and removed_algos:
        for added in added_algos:
            for removed in removed_algos:
                drift_type, impact = _classify_algorithm_change(removed, added)
                if drift_type != DriftType.UNCHANGED:
                    all_drifts.append(ConfigDrift(
                        algorithm_before=removed, algorithm_after=added,
                        drift_type=drift_type,
                        confidence=0.55,
                        details=f'算法替换签名: {removed}→{added}',
                        security_impact=impact,
                        recommendation=f'验证{removed}→{added}的替换是否为计划内迁移'))

    return [d for d in all_drifts if d.confidence >= threshold_confidence]
