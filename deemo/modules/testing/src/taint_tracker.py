# 2026-08-02
# 污点追踪引擎 — 输入字节→程序状态的轻量 taint 传播
# 核心应用场景:
#   1. 标记哪些输入字节影响了新覆盖边的分支条件 → 偏重变异
#   2. 追踪输入字节到敏感操作（malloc size, memcpy len, 数组索引）的流向
#   3. 基于 taint 的种子评分：taint 覆盖面广的种子值得更多变异预算
#
# 参考:
#   ZTaint-Havoc (Jung et al. 2024): Zero-execution taint inference
#     from Havoc mutations — 无插桩，通过变异反馈推断 taint
#   Scalable Language Agnostic Taint Tracking (Shi et al. CCS 2021)
#   Angora (Chen & Chen. CCS 2019): 字节级梯度追踪 + taint 约束
#   REDQUEEN (Aschermann et al. NDSS 2019): input-to-state 推演
#   FITS (Zheng et al. USENIX 2024): Inferring Intermediate Taint
#     Sources for IoT Firmware
import math
import hashlib
from typing import List, Dict, Set, Tuple, Optional, Any
from collections import defaultdict, Counter
from dataclasses import dataclass, field


@dataclass
class TaintLabel:
    """单个字节的污点标签: 该字节对哪些程序状态产生了影响。"""
    byte_offset: int                # 输入中的偏移
    affected_edges: Set[int]        # 受此字节影响的边 ID
    affected_comparisons: int = 0   # 参与的分支比较数
    mutation_sensitivity: float = 0.0  # [0,1] 变异敏感度: 修改此字节的概率
    influence_count: int = 0        # 累积影响力计数


class TaintTracker:
    """轻量污点追踪器 — 基于输入-覆盖率反馈推断字节影响力。

    工作原理 (ZTaint-Havoc / REDQUEEN 风格):
    1. baseline: 执行原始输入，记录覆盖边集 E_base
    2. 对输入做单字节变异 (byte[i] XOR 0x01) → 执行，记录 E_mut
    3. 若 E_mut ≠ E_base → 该字节影响了分支决策 → taint 激活
    4. 累积多轮 → 每个字节的 taint 强度 = 该字节导致覆盖变化的次数

    优势: 无需重新编译目标、无需插桩、无需符号执行。
    劣势: 精度低于动态污点引擎 (如 DECAF/TEMU)，但开销可接受。"""

    def __init__(self, input_size: int = 0, decay_factor: float = 0.95):
        """
        decay_factor: 历史影响力的指数衰减因子。
        旧 taint 信息随时间衰减, 避免过时的热点字节永久锁定变异预算。"""
        self._labels: Dict[int, TaintLabel] = {}
        self._decay = decay_factor
        self._baseline_edges: Set[int] = set()
        self._total_trials = 0
        self._active_offsets: Set[int] = set()

        if input_size > 0:
            self.resize(input_size)

    def resize(self, size: int) -> None:
        for i in range(size):
            if i not in self._labels:
                self._labels[i] = TaintLabel(byte_offset=i,
                                             affected_edges=set())

    # ---- 基线 ----
    def set_baseline(self, edge_set: Set[int]) -> None:
        self._baseline_edges = set(edge_set)
        self._active_offsets.clear()

    # ---- 变异反馈 ----
    def observe_mutation(self, byte_offset: int,
                         new_edge_set: Set[int]) -> bool:
        """对 offset 处做单字节变异，观察覆盖率变化。
        返回 True 表示此字节影响了程序行为（taint）。"""
        if byte_offset not in self._labels:
            self._labels[byte_offset] = TaintLabel(byte_offset=byte_offset,
                                                   affected_edges=set())

        label = self._labels[byte_offset]
        new_edges = new_edge_set - self._baseline_edges
        lost_edges = self._baseline_edges - new_edge_set

        if new_edges or lost_edges:
            label.affected_edges.update(new_edges)
            label.affected_edges.update(lost_edges)
            label.influence_count += 1
            self._active_offsets.add(byte_offset)
            self._total_trials += 1
            return True

        self._total_trials += 1
        return False

    def observe_havoc(self, original_input: bytes,
                      mutated_input: bytes,
                      original_edges: Set[int],
                      mutated_edges: Set[int]) -> List[int]:
        """对一次 Havoc 变异的整体反馈: 比较变异前后所有差异字节的影响。
        返回被确认为 taint 的偏移列表。"""
        if len(original_input) != len(mutated_input):
            return []

        new_edges = mutated_edges - original_edges
        if not new_edges:
            return []

        # 标记所有差异字节为潜在 taint 源
        tainted = []
        for i, (ba, bb) in enumerate(zip(original_input, mutated_input)):
            if ba != bb:
                self._labels[i] = TaintLabel(
                    byte_offset=i,
                    affected_edges=set(new_edges),
                    affected_comparisons=1,
                    mutation_sensitivity=0.5,
                    influence_count=self._labels[i].influence_count + 1
                    if i in self._labels else 1)
                tainted.append(i)

        return tainted

    # ---- 查询 ----
    def is_tainted(self, offset: int) -> bool:
        label = self._labels.get(offset)
        return label is not None and label.influence_count > 0

    def taint_score(self, offset: int) -> float:
        """返回该偏移的 taint 强度 [0, 1]。
        强度 = 影响计数 / 该字节总试验次数 (加平滑)。"""
        label = self._labels.get(offset)
        if label is None or label.influence_count == 0:
            return 0.0
        # Laplace 平滑: (k+1)/(n+2)
        return min(1.0, (label.influence_count + 1) /
                   max(1, self._total_trials + 2) * 256)

    def hot_offsets(self, top_k: int = 16) -> List[int]:
        """返回 taint 强度最高的 K 个偏移。"""
        scored = [(off, self.taint_score(off))
                  for off in self._labels]
        scored.sort(key=lambda x: -x[1])
        return [off for off, _ in scored[:top_k] if _ > 0]

    def cold_offsets(self, threshold: float = 0.05) -> List[int]:
        """返回 taint 极低的偏移（可能是 padding/固定值）。"""
        return [off for off in self._labels
                if self.taint_score(off) < threshold]

    # ---- 敏感度计算 ----
    def compute_sensitivity(self, input_size: int) -> List[float]:
        """返回每个偏移的变异敏感度 [0, 1]。
        高敏感度 → 该字节修改很可能改变程序行为 → 应更频繁变异。"""
        if input_size > len(self._labels):
            self.resize(input_size)

        scores = [0.0] * input_size
        for off in range(input_size):
            scores[off] = self.taint_score(off)

        # L1 归一化（避免全零）
        total = sum(scores) or 1.0
        return [s / total for s in scores]

    # ---- 衰减 ----
    def decay(self) -> None:
        """指数衰减所有字节的历史影响力。
        旧热点随时间冷却，避免过拟合到早期执行路径。"""
        for label in self._labels.values():
            label.influence_count = int(
                label.influence_count * self._decay)
            if label.influence_count == 0:
                label.affected_edges.clear()

    # ---- taint 种子评分 ----
    def score_seed(self, input_data: bytes) -> float:
        """基于 taint 覆盖面评估种子质量。
        得分 = 高 taint 字节数 / 总字节数 → [0, 1]。
        高得分 → 大部分输入字节都与程序行为相关 → 好种子。"""
        if not input_data:
            return 0.0
        tainted_count = sum(
            1 for i in range(len(input_data))
            if self.is_tainted(i))
        return tainted_count / len(input_data)

    def coverage_of_taint(self, input_data: bytes) -> Set[int]:
        """返回此输入覆盖的所有受 taint 影响的边集合。"""
        covered_edges: Set[int] = set()
        for i in range(len(input_data)):
            label = self._labels.get(i)
            if label:
                covered_edges.update(label.affected_edges)
        return covered_edges

    # ---- 报告 ----
    def stats(self) -> Dict[str, Any]:
        return {
            'total_trials': self._total_trials,
            'tainted_offsets': sum(
                1 for off in self._labels
                if self._labels[off].influence_count > 0),
            'total_offsets': len(self._labels),
            'hot_offsets_top10': self.hot_offsets(10),
            'cold_offsets_count': len(self.cold_offsets()),
            'active_offsets': len(self._active_offsets),
        }


class TaintGuidedMutator:
    """污点引导的变异策略: 高 taint 偏移用精确变异 (算术+/-, 位翻转),
    低 taint 偏移用破坏性变异 (块删除、随机覆写)。
    变异预算按 taint 强度加权分配。"""

    def __init__(self, tracker: TaintTracker):
        self._tracker = tracker
        self._sensitivity: List[float] = []

    def update_sensitivity(self, input_size: int) -> None:
        self._sensitivity = self._tracker.compute_sensitivity(input_size)

    def mutate(self, data: bytearray) -> bytearray:
        """对 bytearray 做 taint 引导的变异。"""
        import random as _rnd

        if not self._sensitivity or len(data) != len(self._sensitivity):
            self.update_sensitivity(len(data))

        # 变异预算: 总字节数的 5% (min 1, max 16)
        budget = max(1, min(16, len(data) // 20))
        for _ in range(budget):
            # 按 taint 敏感度加权选择偏移
            idx = _weighted_pick(self._sensitivity, _rnd)
            if idx < 0 or idx >= len(data):
                continue

            # 高敏感度 → 精确变异；低敏感度 → 破坏性变异
            sens = self._sensitivity[idx] if idx < len(self._sensitivity) else 0.5
            if sens > 0.3 / max(1, len(data)):
                # 精确变异
                delta = _rnd.choice([-1, 1, -32, 32, -128, 128])
                data[idx] = (data[idx] + delta) & 0xFF
            else:
                # 破坏性变异: 写入 interesting values
                interesting = [0x00, 0x01, 0xFF, 0x7F, 0x80,
                              0xFE, 0x0A, 0x0D, 0x20, 0x25, 0x6E]
                data[idx] = _rnd.choice(interesting)

        return data

    def mutate_block(self, data: bytearray,
                     start: int, end: int) -> bytearray:
        """对 [start, end) 区域做集中变异 — 该区域为高 taint 热点区。"""
        import random as _rnd
        for i in range(start, min(end, len(data))):
            if _rnd.random() < 0.3:  # 30% 的单字节变异率
                data[i] ^= (1 << _rnd.randint(0, 7))
        return data


def _weighted_pick(weights: List[float], rng) -> int:
    """加权随机选择索引。weights 为空 → uniform。"""
    if not weights:
        return -1
    total = sum(weights)
    if total <= 0:
        return rng.randint(0, len(weights) - 1)
    r = rng.random() * total
    acc = 0.0
    for i, w in enumerate(weights):
        acc += w
        if r <= acc:
            return i
    return len(weights) - 1


# 便捷入口: 对一个种子集做一轮 taint 分析
def one_round_taint_analysis(
        tracker: TaintTracker,
        execute_func,  # (bytes) → Set[int] 边集
        seed: bytes) -> Tuple[bytes, List[int]]:
    """对单个种子做一轮 taint 分析: 逐字节变异, 观察覆盖变化。
    返回 (变异后的种子, 被确认有影响的偏移列表)。"""
    if not seed:
        return seed, []

    baseline_edges = execute_func(seed)
    tracker.set_baseline(baseline_edges)
    tracker.resize(len(seed))

    influenced = []
    for i in range(len(seed)):
        mutant = bytearray(seed)
        mutant[i] ^= 0x01  # 单比特翻转
        new_edges = execute_func(bytes(mutant))
        if tracker.observe_mutation(i, new_edges):
            influenced.append(i)

    return bytes(mutant if influenced else seed), influenced
