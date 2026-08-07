"""
Dempster-Shafer 多源证据融合引擎 — 二进制漏洞分析置信度统一。

问题定义:
  多个分析模块对同一发现给出独立置信度，彼此可能矛盾。
  简单平均或最大值丢弃了不确定性信息—矛盾本身是信号。

D-S 理论在此场景的优势:
  1. 显式建模 ignorance (Θ 全集) — 区分"证据支持X"和"尚未评估X"
  2. 冲突度量化 — 高冲突触发人工介入而非静默融合
  3. 无需先验分布 — 比贝叶斯更适合安全分析中先验数据稀缺的场景

mass 函数按分析源特化 (见 evidence_mass_functions.py):
  - 静态分析 → 模式匹配精确度 + 已知误报率修正
  - 动态 fuzz → 崩溃复现+覆盖率双信号
  - LLM 推理 → 温度+多轮一致性, ignorance 下限最高
  - 符号执行 → 路径约束满足率, solver 超时显著提升 ignorance

  Shafer A Mathematical Theory of Evidence — D-S 理论基础
  Sentz & Ferson Combination of Evidence in D-S Theory — 组合规则

修改记录:
  创建 2026-08-01 — D-S 核心 (组合规则, 融合入口, 冲突矩阵)
  2026-08-03 — mass 函数拆分至 evidence_mass_functions.py
"""

import math
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any, Dict, List, Optional, Tuple

_EPSILON = 1e-6

@dataclass
class EvidenceSource:
    """单个分析源的证据—mass映射。"""
    source_name: str
    mass_v: float
    mass_not_v: float
    mass_theta: float = 0.0
    confidence: float = 0.0

    def __post_init__(self):
        total = self.mass_v + self.mass_not_v + self.mass_theta
        if total > 1.0 + _EPSILON:
            self.mass_v /= total
            self.mass_not_v /= total
            self.mass_theta /= total

    def is_valid(self) -> bool:
        total = self.mass_v + self.mass_not_v + self.mass_theta
        return abs(total - 1.0) < 0.01

def _dempster_combine(m1: Dict[str, float], m2: Dict[str, float]) -> Dict[str, float]:
    """
    Dempster 组合规则: m12(A) = Σ_{B∩C=A} m1(B)·m2(C) / (1-K)。
    K=1 时回退为 m1 — 完全冲突时保持信息不丢失。
    """
    combined: Dict[str, float] = {}
    K = 0.0
    for b, mb in m1.items():
        if mb < _EPSILON: continue
        for c, mc in m2.items():
            if mc < _EPSILON: continue
            prod = mb * mc
            if b == 'Θ': intersection = c
            elif c == 'Θ': intersection = b
            elif b == c: intersection = b
            else: K += prod; continue
            combined[intersection] = combined.get(intersection, 0.0) + prod
    if abs(K - 1.0) < _EPSILON:
        return dict(m1)
    norm = 1.0 - K
    return {k: v / norm for k, v in combined.items()}

def _source_to_bpa(src: EvidenceSource) -> Dict[str, float]:
    bpa = {}
    if src.mass_v > _EPSILON: bpa['V'] = src.mass_v
    if src.mass_not_v > _EPSILON: bpa['¬V'] = src.mass_not_v
    if src.mass_theta > _EPSILON: bpa['Θ'] = src.mass_theta
    return bpa

def fuse_evidence(sources: List[EvidenceSource]) -> Dict[str, Any]:
    """
    多源 D-S 融合入口。级联 Dempster 组合 ≥2 个证据源。

    返回: {belief_v, plausibility_v, conflict, ignorance, combined_mass,
           fusion_count, warning}
    冲突度 >0.7 → warning 提示人工复核。
    """
    if not sources:
        return {'belief_v': 0.0, 'plausibility_v': 1.0, 'conflict': 0.0,
                'ignorance': 1.0, 'combined_mass': {'Θ': 1.0},
                'fusion_count': 0, 'warning': None}
    if len(sources) == 1:
        src = sources[0]
        bpa = _source_to_bpa(src)
        return {'belief_v': src.mass_v, 'plausibility_v': src.mass_v + src.mass_theta,
                'conflict': 0.0, 'ignorance': src.mass_theta,
                'combined_mass': bpa, 'fusion_count': 1, 'warning': None}

    current = _source_to_bpa(sources[0])
    total_conflict = 0.0
    for src in sources[1:]:
        b2 = _source_to_bpa(src)
        K = 0.0
        for b, mb in current.items():
            for c, mc in b2.items():
                if b != 'Θ' and c != 'Θ' and b != c:
                    K += mb * mc
        total_conflict = max(total_conflict, K)
        current = _dempster_combine(current, b2)

    belief_v = current.get('V', 0.0)
    plausibility_v = belief_v + current.get('Θ', 0.0)
    ignorance = current.get('Θ', 0.0)

    warning = None
    if total_conflict > 0.7:
        warning = f"证据冲突度 {total_conflict:.2f} >0.7 — 分析模块间存在实质性分歧"
    elif total_conflict > 0.4:
        warning = f"证据冲突度 {total_conflict:.2f} 偏高 — 融合结果可用但应标注低置信度"

    return {
        'belief_v': round(belief_v, 6), 'plausibility_v': round(plausibility_v, 6),
        'conflict': round(total_conflict, 6), 'ignorance': round(ignorance, 6),
        'combined_mass': {k: round(v, 6) for k, v in current.items()},
        'fusion_count': len(sources), 'warning': warning,
    }

def conflict_matrix(sources: List[EvidenceSource]) -> List[List[float]]:
    """两两冲突矩阵 K_ij。高K的行→与其他源分歧最大的模块。"""
    n = len(sources)
    matrix = [[0.0] * n for _ in range(n)]
    for i, j in combinations(range(n), 2):
        bpa_i, bpa_j = _source_to_bpa(sources[i]), _source_to_bpa(sources[j])
        k = 0.0
        for b, mb in bpa_i.items():
            for c, mc in bpa_j.items():
                if b != 'Θ' and c != 'Θ' and b != c:
                    k += mb * mc
        matrix[i][j] = round(k, 6)
        matrix[j][i] = matrix[i][j]
    return matrix
