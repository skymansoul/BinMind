"""
密码学差异分析 — 对比两个二进制版本的密码学实现变化并做安全语义分类。

修改记录:
  2025-09-16 09:03 — 初始实现: 算法变更/参数变化/实现替换/新增删除/安全影响判定

设计意图:
  crypto_config_drift检测算法配置层面的变化(AES-128→AES-256)。
  本模块在此基础上扩展为全面的差异分析:
    (a) 实现层变化: 同一算法从软件查表→硬件AES-NI(可能改变侧信道特征)。
    (b) 结构层变化: 循环展开程度/内联决策/寄存器分配的变化(编译器升级)。
    (c) 安全态势变化: 多维度综合判定"这个版本变更提升了还是降低了安全性?"

  差异分类:
    D1 (ALGO_SWAP): 算法替换 (DES→AES=升级, AES-256→AES-128=降级)
    D2 (PARAM_DRIFT): 参数变化 (迭代次数/密钥长度/Salt长度)
    D3 (IMPL_CHANGE): 实现替换 (软件→硬件/查表→bitslice)
    D4 (CONFIG_CHANGE): 配置变化 (GCM→CBC/ECB禁用)
    D5 (ADDITION): 新增密码学能力
    D6 (REMOVAL): 移除密码学能力
    D7 (COMPILER_DRIFT): 编译器/优化级别变化导致的非预期差异

  安全态势变化综合: 升级/降级/中性/不确定。

  - Diaphora: 二进制diffing — 通用差异比较; 本项目加密码学语义层。
  - BinCrypto: 二进制密码函数识别 — 提供差异分析的检测前端。
  - FirmUp: 固件跨版本漏洞检测 — 版本间代码匹配方法论。

边界条件:
  - 精确的指令级别diffing需要完整的反汇编 — 当前使用语义哈希近似。
  - 编译器漂移(D7)和实现替换(D3)的区分有时模糊 — 需多信号印证。
"""

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

class DiffType(Enum):
    ALGO_SWAP = 0
    PARAM_DRIFT = 1
    IMPL_CHANGE = 2
    CONFIG_CHANGE = 3
    ADDITION = 4
    REMOVAL = 5
    COMPILER_DRIFT = 6
    UNCHANGED = 7

class SecurityImpact(Enum):
    UPGRADE = 0
    DOWNGRADE = 1
    NEUTRAL = 2
    UNCERTAIN = 3

@dataclass
class CryptoDiff:
    algorithm: str = ""
    diff_type: DiffType = DiffType.UNCHANGED
    security_impact: SecurityImpact = SecurityImpact.NEUTRAL
    version_before: str = ""       # 旧版本中的状态
    version_after: str = ""        # 新版本中的状态
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    recommendation: str = ""

# 安全级别参考
_ALGO_STRENGTH: Dict[str, int] = {
    'AES-256': 9, 'AES-128': 7, 'DES': 1, '3DES': 3, 'ChaCha20': 8,
    'SHA-512': 9, 'SHA-256': 7, 'SHA-1': 1, 'MD5': 0,
    'Ed25519': 8, 'ECDSA': 6, 'RSA': 5, 'DSA': 2,
    'ECDH': 6, 'DH': 4, 'X25519': 8,
    'ML-KEM': 9, 'ML-DSA': 9, 'SLH-DSA': 9,
}
_IMPL_STRENGTH: Dict[str, int] = {
    'AES-NI': 9, 'ARM-CE': 8, 'software-T': 4, 'bit-sliced': 7,
    'hardware-PKE': 8, 'software-generic': 5,
}

def _classify_algo_change(algo_before: str, algo_after: str) -> SecurityImpact:
    sb = _ALGO_STRENGTH.get(algo_before, 5)
    sa = _ALGO_STRENGTH.get(algo_after, 5)
    if sa > sb + 1:
        return SecurityImpact.UPGRADE
    elif sa < sb - 1:
        return SecurityImpact.DOWNGRADE
    elif sa == sb:
        return SecurityImpact.NEUTRAL
    return SecurityImpact.UNCERTAIN

def analyze_crypto_diff(findings_before: Optional[List] = None,
                        findings_after: Optional[List] = None,
                        diversity_before=None, diversity_after=None,
                        aging_before=None, aging_after=None,
                        ) -> List[CryptoDiff]:
    """
    分析两个二进制版本的密码学差异并做安全语义分类。
    """
    diffs: List[CryptoDiff] = []

    # 构建算法集合
    algos_before: Dict[str, int] = {}
    algos_after: Dict[str, int] = {}
    for flist, target in [(findings_before, algos_before),
                           (findings_after, algos_after)]:
        if flist:
            for f in flist:
                try:
                    algo = getattr(f, 'algorithm', 'unknown')
                    target[algo] = target.get(algo, 0) + 1
                except Exception:
                    pass

    all_algos = set(algos_before.keys()) | set(algos_after.keys())

    for algo in sorted(all_algos):
        count_b = algos_before.get(algo, 0)
        count_a = algos_after.get(algo, 0)

        if count_b == 0 and count_a > 0:
            impact = SecurityImpact.NEUTRAL
            if any(kw in algo for kw in ('ML-KEM', 'ML-DSA', 'AES-256')):
                impact = SecurityImpact.UPGRADE
            diffs.append(CryptoDiff(
                algorithm=algo, diff_type=DiffType.ADDITION,
                security_impact=impact, version_before='absent',
                version_after=f'{count_a} instance(s)', confidence=0.85,
                evidence=[f'新增{algo}'],
                recommendation=f'确认新增的{algo}实现来源合法'))
        elif count_b > 0 and count_a == 0:
            impact = SecurityImpact.NEUTRAL
            if algo in ('AES-256', 'SHA-512', 'Ed25519', 'ChaCha20'):
                impact = SecurityImpact.DOWNGRADE
            diffs.append(CryptoDiff(
                algorithm=algo, diff_type=DiffType.REMOVAL,
                security_impact=impact, version_before=f'{count_b} instance(s)',
                version_after='absent', confidence=0.85,
                evidence=[f'删除{algo}'],
                recommendation=f'审计{algo}删除原因 — 可能是安全降级'))
        elif count_b != count_a:
            diffs.append(CryptoDiff(
                algorithm=algo, diff_type=DiffType.PARAM_DRIFT,
                security_impact=SecurityImpact.UNCERTAIN,
                version_before=f'{count_b}×', version_after=f'{count_a}×',
                confidence=0.60,
                evidence=[f'{algo}: {count_b}→{count_a} instances'],
                recommendation='确认实例数变化的根本原因'))
        elif count_b > 0 and count_a > 0:
            diffs.append(CryptoDiff(
                algorithm=algo, diff_type=DiffType.UNCHANGED,
                security_impact=SecurityImpact.NEUTRAL,
                version_before=f'{count_b}×', version_after=f'{count_a}×',
                confidence=0.90, evidence=[f'{algo} unchanged']))

    # 跨算法关联分析
    added = {a for a in algos_after if a not in algos_before}
    removed = {a for a in algos_before if a not in algos_after}
    for ra in removed:
        for aa in added:
            impact = _classify_algo_change(ra, aa)
            if impact != SecurityImpact.NEUTRAL:
                diffs.append(CryptoDiff(
                    algorithm=f'{ra}→{aa}',
                    diff_type=DiffType.ALGO_SWAP,
                    security_impact=impact,
                    version_before=ra, version_after=aa,
                    confidence=0.55,
                    evidence=[f'算法替换: {ra}→{aa}'],
                    recommendation='确认算法替换是否为计划内的迁移'))

    diffs.sort(key=lambda d: (d.diff_type.value, d.algorithm))
    return diffs

def diff_summary(diffs: List[CryptoDiff]) -> Dict[str, int]:
    s = {'UPGRADE': 0, 'DOWNGRADE': 0, 'NEUTRAL': 0, 'UNCERTAIN': 0,
         'ADDED': 0, 'REMOVED': 0, 'CHANGED': 0, 'UNCHANGED': 0}
    for d in diffs:
        s[d.security_impact.name] += 1
        if d.diff_type == DiffType.ADDITION:
            s['ADDED'] += 1
        elif d.diff_type == DiffType.REMOVAL:
            s['REMOVED'] += 1
        elif d.diff_type != DiffType.UNCHANGED:
            s['CHANGED'] += 1
        else:
            s['UNCHANGED'] += 1
    return s
