# 修改记录:
# 2025-08-14 09:12 — 初始实现：语义签名兼容性矩阵 + 二分图最优匹配
# 2025-08-15 14:33 — 增加风险惩罚项，避免将不匹配的补丁强行指派

"""Patch Applicability Resolver — 异构 fleet 的补丁适用性求解。

问题：一个组织维护 N 台运行同一软件不同版本的机器。
M 个补丁各自针对特定版本构建。手工匹配 N×M 矩阵不可扩展。

本模块自动构建兼容性矩阵并求解最优指派：
  1. 对每个 binary 提取目标函数的语义签名画像
  2. 对每个 patch 提取其参考函数的语义签名画像
  3. 计算 pairwise 兼容性分数（来自 PatchPresenceTester 的加权 Jaccard）
  4. 构建二分图，求解最大权重匹配
  5. 对未匹配的 binary 输出风险分级（无补丁可匹配时的替代建议）

算法：
  bipartite matching 使用 Hungarian 算法（Kuhn-Munkres），O(n³)。
  对 n≤200 的服务器群，秒级求解。

与现有工具的差异：
  - SCCM/WSUS/Satellite 基于版本号字符串匹配，不做二进制语义分析
  - 本模块在二进制语义层面对比补丁目标与 fleet binary → 不依赖版本字符串
  - 典型场景：10 个 binary 变体（同软件不同编译器/优化级别），
    3 个补丁各针对其中某变体 → 自动找出最优匹配和风险缺口
"""

import math
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


class ApplicabilityTier(str, Enum):
    DIRECT_MATCH = "direct_match"           # 语义签名完全兼容
    COMPATIBLE = "compatible"               # 高置信度兼容（≥0.75）
    TOLERABLE = "tolerable"                 # 可接受但需验证（0.50-0.75）
    RISKY = "risky"                         # 低置信度（<0.50）
    NO_MATCH = "no_match"                   # 无可匹配补丁
    ARCHITECTURE_MISMATCH = "arch_mismatch" # 不同 ISA


@dataclass
class FleetBinary:
    """fleet 中单个 binary 的描述。"""
    binary_id: str
    binary_path: str = ""
    architecture: str = "x86_64"       # x86_64 | aarch64 | mips64
    compiler: str = ""                 # gcc | clang | msvc
    opt_level: str = ""                # O0 | O1 | O2 | O3 | Os
    version_string: str = ""           # 人工版本标识（可选，不依赖）
    target_functions: Set[str] = field(default_factory=set)
    # 此 binary 中可被补丁的函数名集合
    function_profiles: Dict[str, float] = field(default_factory=dict)
    # {function_name: semantic_similarity_score} — 来自 PPT 的匹配


@dataclass
class PatchCandidate:
    """单个候选补丁的描述（用于适用性计算）。"""
    patch_id: str
    target_architecture: str = "x86_64"
    target_compiler: str = ""
    target_functions: Set[str] = field(default_factory=set)
    # 补丁修改的函数名集合
    reference_signatures: Dict[str, str] = field(default_factory=dict)
    # {function_name: compact_signature_hash}


@dataclass
class ApplicabilityScore:
    """单个 (patch, binary) 对的适用性评分。"""
    patch_id: str
    binary_id: str
    tier: ApplicabilityTier = ApplicabilityTier.NO_MATCH
    # 函数级匹配分数
    function_scores: Dict[str, float] = field(default_factory=dict)
    # {改动的函数 → 与目标 binary 中对应函数的相似度}
    aggregate_score: float = 0.0        # 0..1，所有函数分数的调和均值
    architecture_compatible: bool = True
    compiler_compatible: bool = True
    risk_factors: List[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class ApplicabilityMatrix:
    """完整的补丁适用性矩阵。"""
    binaries: List[FleetBinary] = field(default_factory=list)
    patches: List[PatchCandidate] = field(default_factory=list)
    scores: List[List[ApplicabilityScore]] = field(default_factory=list)
    # scores[i][j] = patch_i 对 binary_j 的适用性

    optimal_assignments: List[Tuple[str, str, float]] = field(default_factory=list)
    # [(patch_id, binary_id, score), ...]
    uncovered_binaries: List[str] = field(default_factory=list)
    # 无可匹配补丁的 binary
    unused_patches: List[str] = field(default_factory=list)
    # 未指派给任何 binary 的补丁

    def to_dict(self) -> Dict:
        return {
            'binaries': len(self.binaries),
            'patches': len(self.patches),
            'assignments': [
                {'patch': p, 'binary': b, 'score': round(s, 3)}
                for p, b, s in self.optimal_assignments
            ],
            'uncovered': self.uncovered_binaries,
            'unused': self.unused_patches,
        }


# ── 兼容性计算器 ──────────────────────────────────────────────────

class ApplicabilityCalculator:
    """计算补丁与目标 binary 的兼容性评分。

    不依赖版本字符串，基于函数级语义签名匹配。
    与 PatchPresenceTester 集成：复用其 SemanticSignatureExtractor。

    评分公式：
      per function:  Jaccard_weighted(reference_signatures, binary_function_signatures)
      aggregate:     调和均值 of all function scores（惩罚极端低分项）
      tier:          aggregate ∈ [0.85, 1.0] → DIRECT_MATCH
                       [0.75, 0.85) → COMPATIBLE
                       [0.50, 0.75) → TOLERABLE
                       [0.0,  0.50) → RISKY
    """

    # 架构兼容性矩阵：patch target → fleet binary 能否应用
    _ARCH_COMPAT = {
        ('x86_64', 'x86_64'): True,
        ('x86_64', 'x86'): False,   # 64-bit patch 不能用于 32-bit binary
        ('x86', 'x86_64'): False,
        ('aarch64', 'aarch64'): True,
        ('arm64', 'arm64'): True,
        ('aarch64', 'arm64'): True,  # ARM64 变体间兼容
        ('arm64', 'aarch64'): True,
    }

    def __init__(self):
        self._min_score_threshold = 0.35  # 低于此分数的函数视为不匹配

    def compute_pair(self, patch: PatchCandidate,
                     binary: FleetBinary) -> ApplicabilityScore:
        """计算单个 (patch, binary) 对的适用性。"""
        score = ApplicabilityScore(
            patch_id=patch.patch_id,
            binary_id=binary.binary_id,
        )

        # 架构兼容性检查
        arch_pair = (patch.target_architecture, binary.architecture)
        score.architecture_compatible = self._ARCH_COMPAT.get(
            arch_pair, patch.target_architecture == binary.architecture)
        if not score.architecture_compatible:
            score.tier = ApplicabilityTier.ARCHITECTURE_MISMATCH
            score.risk_factors.append(
                f"ISA 不兼容: patch={patch.target_architecture}, binary={binary.architecture}")
            score.recommendation = "需要跨架构 port 或寻找目标架构的补丁版本"
            return score

        # 编译器兼容性（软约束：降低分数但不阻止）
        score.compiler_compatible = (
            not patch.target_compiler or not binary.compiler or
            patch.target_compiler.lower() == binary.compiler.lower())
        if not score.compiler_compatible:
            score.risk_factors.append(
                f"编译器差异: patch={patch.target_compiler}, binary={binary.compiler}")

        # 函数级匹配
        if not patch.target_functions:
            score.tier = ApplicabilityTier.NO_MATCH
            score.recommendation = "补丁无目标函数信息"
            return score

        func_scores = {}
        for func in patch.target_functions:
            binary_score = binary.function_profiles.get(func, 0.0)
            func_scores[func] = binary_score

        score.function_scores = func_scores

        # 聚合：调和均值（惩罚极端低分）
        valid_scores = [s for s in func_scores.values() if s > 0]
        if not valid_scores:
            score.aggregate_score = 0.0
            score.tier = ApplicabilityTier.NO_MATCH
            score.recommendation = "所有目标函数在 binary 中均未找到对应签名"
            return score

        hm = self._harmonic_mean(valid_scores)
        score.aggregate_score = hm

        # 编译器惩罚
        if not score.compiler_compatible:
            hm *= 0.85

        # 分级
        if hm >= 0.85:
            score.tier = ApplicabilityTier.DIRECT_MATCH
            score.recommendation = "可直接应用，兼容性高"
        elif hm >= 0.75:
            score.tier = ApplicabilityTier.COMPATIBLE
            score.recommendation = "建议应用前做一次差分执行验证"
        elif hm >= 0.50:
            score.tier = ApplicabilityTier.TOLERABLE
            score.recommendation = "需要人工审查函数级差异后决定"
        else:
            score.tier = ApplicabilityTier.RISKY
            score.recommendation = "高风险：建议寻找此 binary 版本的专用补丁"

        return score

    def compute_matrix(self, patches: List[PatchCandidate],
                       binaries: List[FleetBinary]) -> ApplicabilityMatrix:
        """构建完整的 N×M 兼容性矩阵。"""
        matrix = ApplicabilityMatrix(binaries=list(binaries),
                                      patches=list(patches))
        scores = []
        for patch in patches:
            row = []
            for binary in binaries:
                row.append(self.compute_pair(patch, binary))
            scores.append(row)
        matrix.scores = scores
        return matrix

    @staticmethod
    def _harmonic_mean(values: List[float]) -> float:
        """调和均值：H = n / Σ(1/x_i)。"""
        if not values:
            return 0.0
        # 避免除零
        inv_sum = sum(1.0 / max(v, 1e-6) for v in values)
        return len(values) / inv_sum if inv_sum > 0 else 0.0


# ── 二分图最优匹配 ────────────────────────────────────────────────

class HungarianSolver:
    """Hungarian 算法（Kuhn-Munkres）求解最大权重二分图匹配。

    输入：cost_matrix[i][j] = 补丁 i 指派给 binary j 的分数（0..1）。
    输出：最优指派列表 (patch_idx, binary_idx, score)。
    未匹配的项单独列出。

    复杂度 O(n³)，n ≤ 200 可行。
    """

    def solve(self, cost_matrix: List[List[float]]
              ) -> Tuple[List[Tuple[int, int, float]], List[int], List[int]]:
        """求解最大权重匹配。

        返回: (assignments, unmatched_patches, unmatched_binaries)
        """
        n_patches = len(cost_matrix)
        n_binaries = len(cost_matrix[0]) if cost_matrix else 0

        if n_patches == 0 or n_binaries == 0:
            return [], list(range(n_patches)), list(range(n_binaries))

        # 转换为最小化问题（Hungarian 默认求最小）
        max_cost = 1.0
        # 补全为方阵
        n = max(n_patches, n_binaries)
        costs = []
        for i in range(n):
            row = []
            for j in range(n):
                if i < n_patches and j < n_binaries:
                    # 分数越高 → cost 越低
                    row.append(max_cost - cost_matrix[i][j])
                else:
                    row.append(max_cost + 0.1)  # 虚拟节点，高 cost
            costs.append(row)

        # Hungarian 算法
        assignment = self._hungarian(costs)

        # 过滤有效指派（分数 > 最低阈值）
        min_score = 0.30
        result = []
        matched_p = set()
        matched_b = set()
        for i, j in enumerate(assignment):
            if i < n_patches and j < n_binaries:
                score = cost_matrix[i][j]
                if score >= min_score:
                    result.append((i, j, score))
                    matched_p.add(i)
                    matched_b.add(j)

        unmatched_p = [i for i in range(n_patches) if i not in matched_p]
        unmatched_b = [j for j in range(n_binaries) if j not in matched_b]

        return result, unmatched_p, unmatched_b

    def _hungarian(self, cost: List[List[float]]) -> List[int]:
        """标准 Hungarian 算法实现。"""
        n = len(cost)
        u = [0.0] * (n + 1)
        v = [0.0] * (n + 1)
        p = [0] * (n + 1)
        way = [0] * (n + 1)

        for i in range(1, n + 1):
            p[0] = i
            j0 = 0
            minv = [float('inf')] * (n + 1)
            used = [False] * (n + 1)
            while True:
                used[j0] = True
                i0 = p[j0]
                delta = float('inf')
                j1 = 0
                for j in range(1, n + 1):
                    if not used[j]:
                        cur = cost[i0 - 1][j - 1] - u[i0] - v[j]
                        if cur < minv[j]:
                            minv[j] = cur
                            way[j] = j0
                        if minv[j] < delta:
                            delta = minv[j]
                            j1 = j
                for j in range(n + 1):
                    if used[j]:
                        u[p[j]] += delta
                        v[j] -= delta
                    else:
                        minv[j] -= delta
                j0 = j1
                if p[j0] == 0:
                    break
            while True:
                j1 = way[j0]
                p[j0] = p[j1]
                j0 = j1
                if j0 == 0:
                    break

        # p[j] = 指派到列 j 的行索引
        result = [-1] * n
        for j in range(1, n + 1):
            if p[j] != 0:
                result[p[j] - 1] = j - 1
        return result


# ── 便捷函数 ──────────────────────────────────────────────────────

def resolve_applicability(patches: List[PatchCandidate],
                          binaries: List[FleetBinary]) -> ApplicabilityMatrix:
    """一键适用性矩阵构建 + 最优匹配求解。"""
    calc = ApplicabilityCalculator()
    matrix = calc.compute_matrix(patches, binaries)

    # 构建 cost 矩阵并求解
    cost_m = []
    for row in matrix.scores:
        cost_m.append([s.aggregate_score for s in row])

    solver = HungarianSolver()
    assignments, unmatched_p, unmatched_b = solver.solve(cost_m)

    matrix.optimal_assignments = [
        (patches[pi].patch_id, binaries[bi].binary_id, score)
        for pi, bi, score in assignments
    ]
    matrix.uncovered_binaries = [binaries[bi].binary_id for bi in unmatched_b]
    matrix.unused_patches = [patches[pi].patch_id for pi in unmatched_p]

    return matrix
