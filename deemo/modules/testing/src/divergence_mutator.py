# 引擎分叉引导的变异生成器 — 利用跨引擎覆盖差异驱动输入变异
#
# 核心问题:
#   differential_tester.py 比较不同引擎对同一输入的输出差异,
#   但差异结果是被动观察的——不反馈给变异策略。这意味着:
#     a) 变异是盲目的 (uniform random), 浪费大量fuzzing预算
#     b) 产生输出差异的输入字节被忽视, 而非被重点变异
#     c) 各引擎的覆盖差异 (同一输入不同引擎覆盖了不同代码路径)
#        未被利用为变异信号
#
#   GraphFuzz 证明: 领域特定的反馈信号可达4000×加速。
#   AccuOracle 用解释器-JIT分叉做差分oracle。
#
# 本模块的方法 — 覆盖分叉驱动的变异:
#   1. 对同一输入在多个引擎上执行, 收集各引擎的覆盖边集
#   2. 计算覆盖分叉: 引擎A独有但B没有的边 + 反之
#   3. 定位分叉源: 哪些输入字节导致了覆盖路径的分叉?
#      (使用 subreg_taint 追踪: 字节→分支指令的因果关系)
#   4. 按分叉贡献度加权变异概率: 高分叉贡献的字节获得更多变异
#   5. 定向变异: 对高分叉字节做精确变异 (arith/bitflip) 而非随机 havoc
#
# 技术依据:
#   GraphFuzz — 算法特定反馈替代覆盖;
#     本项目取其"特定反馈信号"概念但以跨引擎分叉作为反馈
#   AccuOracle — 分叉仲裁层消除误报;
#     本项目取其分叉检测思想但用于变异引导而非oracle判定

from __future__ import annotations

import hashlib
import math
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# 桥接 subreg_taint.py: taint_map 参数格式为 Dict[int, Set[int]]
# (byte_offset → {covered_edge_ids}), 由 SubRegTaintTracker 的
# byte_taint_vector() 方法的调用方自行构建后传入。
# 桥接 differential_tester.py: coverage_by_engine 为引擎名→覆盖边集合,
# 由 DiffTester 的执行结果中提取后传入。


@dataclass
class EngineCoverage:
    """单个引擎对单次输入的覆盖快照"""
    engine_name: str
    covered_edges: Set[int] = field(default_factory=set)
    total_edges: int = 0
    new_edges_found: int = 0


@dataclass
class DivergenceProfile:
    """单个输入在各引擎上的覆盖分叉画像"""
    input_hash: str = ""
    input_size: int = 0
    # 各引擎的覆盖
    engine_coverages: Dict[str, EngineCoverage] = field(
        default_factory=dict)
    # 分叉边: 仅被部分引擎覆盖的边
    divergent_edges: Set[int] = field(default_factory=set)
    divergence_ratio: float = 0.0
    # 逐字节的分叉贡献度
    byte_divergence_score: Dict[int, float] = field(
        default_factory=dict)


@dataclass
class MutationPlan:
    """变异计划——描述对输入的哪些位置做何种变异"""
    byte_scores: Dict[int, float] = field(default_factory=dict)
    top_offsets: List[int] = field(default_factory=list)
    # 推荐变异类型
    recommended_ops: List[str] = field(default_factory=list)


class DivergenceGuidedMutator:
    """分叉引导的变异器。

    典型用法:
        mutator = DivergenceGuidedMutator()
        # 对每个输入收集各引擎的覆盖:
        profile = mutator.build_profile(input_data, {
            'ghidra': ghidra_coverage_edges,
            'ida': ida_coverage_edges,
        }, taint_map)
        # 生成变异计划:
        plan = mutator.plan_mutation(profile)
        # 按计划执行变异:
        mutated = mutator.mutate(input_data, plan)
    """

    def __init__(self, divergence_threshold: float = 0.05):
        """
        divergence_threshold: 分叉比率低于此值的输入视为"无分叉",
        做常规变异而非分叉引导变异。
        """
        self._threshold = divergence_threshold
        self._history: List[DivergenceProfile] = []

    def build_profile(self, input_data: bytes,
                       coverage_by_engine: Dict[str, Set[int]],
                       taint_map: Optional[Dict[int, Set[int]]] = None,
                       ) -> DivergenceProfile:
        """构建分叉画像——计算各引擎的覆盖差异

        taint_map: byte_offset → {covered_edges}  (来自 subreg_taint 或
          手动指定——若为None则所有字节等权)
        """
        inp_hash = hashlib.sha256(input_data).hexdigest()[:12]
        profile = DivergenceProfile(
            input_hash=inp_hash,
            input_size=len(input_data),
        )

        engines = list(coverage_by_engine.keys())
        if len(engines) < 2:
            profile.divergent_edges = set()
            return profile

        for name, edges in coverage_by_engine.items():
            profile.engine_coverages[name] = EngineCoverage(
                engine_name=name,
                covered_edges=set(edges),
                total_edges=len(edges),
            )

        # 计算分叉边: 至少一个引擎覆盖、至少一个引擎未覆盖
        all_edges: Set[int] = set()
        for ec in profile.engine_coverages.values():
            all_edges |= ec.covered_edges

        for edge in all_edges:
            covering_engines = sum(
                1 for ec in profile.engine_coverages.values()
                if edge in ec.covered_edges)
            if 0 < covering_engines < len(engines):
                profile.divergent_edges.add(edge)

        total = len(all_edges)
        profile.divergence_ratio = (
            len(profile.divergent_edges) / max(1, total))

        # 逐字节分叉贡献度
        if taint_map:
            profile.byte_divergence_score = self._compute_byte_scores(
                profile, taint_map, len(input_data))
        else:
            # 无污点数据时: 所有字节等权
            n = max(1, len(input_data))
            profile.byte_divergence_score = {
                i: profile.divergence_ratio / n for i in range(n)}

        self._history.append(profile)
        return profile

    def plan_mutation(self, profile: DivergenceProfile,
                       top_k: int = 10) -> MutationPlan:
        """从分叉画像生成变异计划——重点变异高分叉贡献的字节"""
        plan = MutationPlan(byte_scores=dict(profile.byte_divergence_score))

        # 若分叉率低 → 常规变异
        if profile.divergence_ratio < self._threshold:
            plan.recommended_ops = ['havoc_random', 'bitflip_1_1']
            plan.top_offsets = list(range(
                min(64, profile.input_size)))
            return plan

        # 高分歧 → 分叉引导变异
        sorted_offsets = sorted(
            profile.byte_divergence_score.items(),
            key=lambda x: -x[1])

        plan.top_offsets = [off for off, _ in sorted_offsets[:top_k]]

        # 选择变异类型
        if profile.divergence_ratio > 0.3:
            # 高分歧: 精确变异以保持分叉属性
            plan.recommended_ops = ['arith_8', 'arith_16', 'bitflip_1_1']
        else:
            # 中等分歧: 混合策略
            plan.recommended_ops = ['arith_8', 'bitflip_2_2', 'dict_insert']

        return plan

    def mutate(self, data: bytes, plan: MutationPlan,
                rng_seed: Optional[int] = None) -> bytes:
        """按变异计划对输入执行变异"""
        import random as _rnd
        rng = _rnd.Random(rng_seed)
        buf = bytearray(data)

        if not plan.top_offsets:
            return bytes(buf)

        # 对每个高分叉字节执行一次变异
        for off in plan.top_offsets:
            if off >= len(buf):
                continue
            op = rng.choice(plan.recommended_ops) if plan.recommended_ops else 'bitflip_1_1'

            if op.startswith('bitflip'):
                bit = rng.randint(0, 7)
                buf[off] ^= (1 << bit)
            elif op.startswith('arith'):
                delta = rng.choice([-35, -1, 1, 35])
                buf[off] = (buf[off] + delta) & 0xFF
            elif op == 'dict_insert' and len(buf) > off + 2:
                # 用常见边界值替换
                vals = [0x00, 0xFF, 0x7F, 0x80]
                buf[off] = rng.choice(vals)
            else:
                buf[off] = rng.randint(0, 255)

        return bytes(buf)

    def _compute_byte_scores(self, profile: DivergenceProfile,
                              taint_map: Dict[int, Set[int]],
                              input_size: int) -> Dict[int, float]:
        """计算每个输入字节对覆盖分叉的贡献度

        核心公式:
          score(byte_i) = |taint_map[i] ∩ divergent_edges| / |divergent_edges|
          即: 字节i污染的边中有多少是分叉边
        """
        scores: Dict[int, float] = {}
        div_count = len(profile.divergent_edges)

        if div_count == 0:
            for i in range(input_size):
                scores[i] = 0.0
            return scores

        for i in range(input_size):
            tainted = taint_map.get(i, set())
            if not tainted:
                scores[i] = 0.0
                continue
            overlap = len(tainted & profile.divergent_edges)
            scores[i] = overlap / div_count

        # 归一化: 确保所有分数之和 ≈ 1.0
        total = sum(scores.values())
        if total > 0:
            scores = {k: v / total for k, v in scores.items()}

        return scores

    def stats(self) -> Dict[str, Any]:
        if not self._history:
            return {"profiles": 0}
        avg_div = sum(p.divergence_ratio for p in self._history) / len(self._history)
        return {
            "profiles": len(self._history),
            "avg_divergence_ratio": round(avg_div, 4),
            "high_divergence_count": sum(
                1 for p in self._history if p.divergence_ratio > 0.2),
        }

    def reset(self) -> None:
        self._history.clear()


def quick_mutate(input_data: bytes,
                  coverage_by_engine: Dict[str, Set[int]],
                  taint_map: Optional[Dict[int, Set[int]]] = None,
                  ) -> bytes:
    """便捷入口: 一步完成画像→计划→变异"""
    mutator = DivergenceGuidedMutator()
    profile = mutator.build_profile(input_data, coverage_by_engine, taint_map)
    plan = mutator.plan_mutation(profile)
    return mutator.mutate(input_data, plan)
