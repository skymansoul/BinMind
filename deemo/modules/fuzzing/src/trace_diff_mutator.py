"""差分跟踪制导变异器 — 基于成功/失败执行轨迹分叉点的精确变异。

在约束推断变异器 (constraint_inference_mutator.py) 的基础上，本模块关注一个
正交问题: 已知一个输入通过格式校验 (trace_success) 和另一个输入被格式校验拒绝
(trace_fail)，两者在哪个执行点分叉？分叉点附近的输入字节即为"格式敏感的决策字节"。

两阶段:
Phase 1 (Diff): 对 success 和 fail 两条 trace 做最⻓公共子序列对齐，
  标记第一条不一致的基本块 (bifurcation point) 和附近的基本块序列。
Phase 2 (Mutate): 对分叉点附近的基本块所依赖的输入字节进行精确变异——不盲目
  翻位，而是在识别出的"格式决策区域"内施加受控的小扰动。

与 constraint_inference 的分工:
- constraint_inference: 从"修改某字节→解析失败率"中推断字节角色 (LENGTH/MAGIC/...)
- trace_diff (本模块): 从"两条轨迹在哪里分叉"中定位决策点，指导变异方向
前者回答"这是什么字段"，后者回答"我应该变异哪里来发现新行为"。

- ChainFuzz: 跨层差分定向 fuzz，
  使用 LCS 对齐 + 分叉点识别来 guide mutation。
  本项目将 USENIX 论文的 idea 从"供应链跨层"适配到"单层格式校验变异的决策定位"。
- ProFuzzer: 基于执行反馈的敏感字节定位，
  本项目用 trace diff 替代其 probe-based 方法，在格式校验路径较⻓时更高效。
"""

from __future__ import annotations

import struct
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

class TraceNode(str, Enum):
    """Trace 节点的类型标记。"""
    BASIC_BLOCK = "bb"
    FUNCTION_CALL = "call"
    EDGE = "edge"

@dataclass
class TraceEntry:
    """单条执行轨迹的一步——存储基本块标识和该步访问的输入字节区间。"""
    node_id: str                      # 基本块地址或函数名 (用于对齐)
    node_type: TraceNode = TraceNode.BASIC_BLOCK
    input_bytes_touched: List[int] = field(default_factory=list)  # 输入字节偏移列表
    depth: int = 0

@dataclass
class BifurcationPoint:
    """轨迹分叉点——两条 trace 在此处开始不同。"""
    index: int                        # 在较短 trace 中的索引
    success_node: str                 # success trace 在该位置的基本块
    fail_node: str                    # fail trace 在该位置的基本块
    input_bytes_involved: List[int]   # 分叉附近被访问的输入字节 (候选变异目标)
    divergence_distance: int = 0      # 分叉后多少步内保持不同
    confidence: float = 0.5           # 多次采样后该分叉点保持稳定的比例

@dataclass
class TraceDiffResult:
    """一次差分分析的结果。"""
    success_trace_len: int
    fail_trace_len: int
    aligned_pairs: int               # LCS 对齐的公共步数
    bifurcation_points: List[BifurcationPoint] = field(default_factory=list)
    # 每个输入字节的"决策影响力"分数 (越高表示该字节越可能导致分叉)
    byte_influence: Dict[int, float] = field(default_factory=dict)

class TraceDiffMutator:
    """差分跟踪制导变异器。

    用法:
        mutator = TraceDiffMutator()
        mutator.record_trace_pair(trace_ok, trace_fail, input_bytes)
        diff = mutator.analyze()
        # diff.byte_influence 为每字节的决策影响力，用于指导变异器
        mutated = mutator.bifurcation_surgery(original_input, diff)
    """

    def __init__(self, min_confidence: float = 0.6, max_bifurcation_points: int = 8):
        self._min_confidence = min_confidence
        self._max_bifurcations = max_bifurcation_points
        # 多次采样累积: 每个 (success_node, fail_node) 对的出现次数
        self._bifurcation_histogram: Dict[Tuple[str, str], int] = defaultdict(int)
        self._total_pairs: int = 0
        self._last_diff: Optional[TraceDiffResult] = None

    def record_trace_pair(self,
                           trace_success: List[TraceEntry],
                           trace_fail: List[TraceEntry],
                           total_input_len: int = 0):
        """记录一对成功/失败轨迹。多次调用累积后 analyze() 输出稳定分叉点。"""
        self._total_pairs += 1
        # LCS 对齐
        lcs_indices = self._lcs_align(trace_success, trace_fail)
        # 找到第一个分叉
        bif_idx = self._find_first_bifurcation(trace_success, trace_fail, lcs_indices)
        if bif_idx is not None:
            succ_node = trace_success[bif_idx].node_id if bif_idx < len(trace_success) else "end"
            fail_node = trace_fail[bif_idx].node_id if bif_idx < len(trace_fail) else "end"
            self._bifurcation_histogram[(succ_node, fail_node)] += 1

# LCS 对齐
    @staticmethod
    def _lcs_align(a: List[TraceEntry], b: List[TraceEntry]
                    ) -> List[Tuple[int, int]]:
        """返回两轨迹的最长公共子序列索引对 [(i, j), ...]。
        匹配标准: node_id 相同。"""
        m, n = len(a), len(b)
        # DP 表: dp[i][j] = LCS length for a[:i], b[:j]
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if a[i - 1].node_id == b[j - 1].node_id:
                    dp[i][j] = dp[i - 1][j - 1] + 1
                else:
                    dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

        # 回溯
        pairs: List[Tuple[int, int]] = []
        i, j = m, n
        while i > 0 and j > 0:
            if a[i - 1].node_id == b[j - 1].node_id:
                pairs.append((i - 1, j - 1))
                i -= 1
                j -= 1
            elif dp[i - 1][j] >= dp[i][j - 1]:
                i -= 1
            else:
                j -= 1
        pairs.reverse()
        return pairs

# 分叉点检测
    @staticmethod
    def _find_first_bifurcation(a: List[TraceEntry], b: List[TraceEntry],
                                 lcs: List[Tuple[int, int]]) -> Optional[int]:
        """找到第一条不在 LCS 中的位置 (即分叉起点)。"""
        lcs_set = set(lcs)
        max_len = min(len(a), len(b))
        for idx in range(max_len):
            pair = (idx, idx)
            if pair not in lcs_set:
                return idx
        # 若所有对齐位置都一致，但在末尾一条轨迹更长
        if len(a) != len(b):
            return max_len
        return None

# 分析
    def analyze(self) -> TraceDiffResult:
        """基于累积的采样数据输出稳定的分叉点与字节影响力评分。"""
        result = TraceDiffResult(
            success_trace_len=0, fail_trace_len=0, aligned_pairs=0,
        )
        if self._total_pairs == 0:
            return result

        bifurcations: List[BifurcationPoint] = []
        byte_influence: Dict[int, float] = defaultdict(float)

        # 按出现频率排序——高频分叉点更可信
        sorted_bif = sorted(
            self._bifurcation_histogram.items(),
            key=lambda x: x[1], reverse=True
        )

        for idx, ((s_node, f_node), count) in enumerate(sorted_bif):
            if idx >= self._max_bifurcations:
                break
            conf = count / self._total_pairs
            if conf < self._min_confidence:
                continue
            bp = BifurcationPoint(
                index=idx,
                success_node=s_node,
                fail_node=f_node,
                input_bytes_involved=[],   # 需调用方填入
                confidence=round(conf, 3),
            )
            bifurcations.append(bp)
            # 分叉点本身的 input_bytes_involved 贡献影响力
            for byte_off in bp.input_bytes_involved:
                byte_influence[byte_off] += conf

        result.bifurcation_points = bifurcations
        result.byte_influence = dict(byte_influence)
        result.aligned_pairs = sum(self._bifurcation_histogram.values())
        self._last_diff = result
        return result

# 分叉手术
    def bifurcation_surgery(self, data: bytes,
                             diff: Optional[TraceDiffResult] = None,
                             perturbation_range: int = 4
                             ) -> Tuple[bytes, List[int]]:
        """对分叉点涉及的高影响力字节进行微扰动。

        与全量 havoc 变异不同: 只变异 byte_influence 中得分最高的几个字节，
        且每次仅做 ±1 的微扰动 (或翻转 1 bit)，而非大幅随机修改。
        这使变异聚焦于"格式决策边界"附近。

        若无有效的 diff 数据，回退到单字节翻转。
        """
        d = diff or self._last_diff
        if d is None or not d.byte_influence:
            # 回退: 随机单字节翻转
            if not data:
                return data, []
            raw = bytearray(data)
            pos = __import__('random').randint(0, len(raw) - 1)
            raw[pos] ^= (1 << __import__('random').randint(0, 7))
            return bytes(raw), [pos]

        # 按影响力降序选字节
        ranked = sorted(d.byte_influence.items(), key=lambda x: x[1], reverse=True)
        top_bytes = [off for off, _ in ranked[:self._max_bifurcations] if 0 <= off < len(data)]

        if not top_bytes:
            return data, []

        raw = bytearray(data)
        affected: List[int] = []
        import random

        for byte_off in top_bytes:
            # 微扰动策略: 随机选择 ±1, ±2, 或 flip 1 bit
            strategy = random.choice(['inc', 'dec', 'bitflip'])
            if strategy == 'inc' and raw[byte_off] < 0xFF:
                raw[byte_off] += random.randint(1, min(3, 0xFF - raw[byte_off]))
            elif strategy == 'dec' and raw[byte_off] > 0:
                raw[byte_off] -= random.randint(1, min(3, raw[byte_off]))
            else:
                raw[byte_off] ^= (1 << random.randint(0, 7))
            affected.append(byte_off)

            # 对相邻字节也做轻量扰动 (格式字段常连续)
            for delta in range(1, perturbation_range):
                for sign in (-1, 1):
                    nb = byte_off + delta * sign
                    if 0 <= nb < len(raw) and nb not in affected:
                        if random.random() < 0.3:  # 30% 概率扰动邻居
                            raw[nb] ^= (1 << random.randint(0, 7))
                            affected.append(nb)

        return bytes(raw), affected

    def reset(self):
        self._bifurcation_histogram.clear()
        self._total_pairs = 0
        self._last_diff = None
