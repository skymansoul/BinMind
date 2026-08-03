#
# 覆盖率感知的二进制 delta debugging 策略 — 以覆盖率等价替代崩溃布尔判定
#
# 传统 ddmin 的 oracle 是 f(data) → {crash, no_crash}——二值判定
# 对于"触发特定代码路径但不崩溃"的输入（如性能退化 PoC、逻辑漏洞触发样本）
# 二值 oracle 无能为力——缩小后的输入可能改变了执行路径但未崩溃
#
# 本模块用覆盖率位图替代二值判定：oracle 变为 f(data) → EdgeSet
# 缩减目标：找到最小输入 data' 使得 EdgeSet(data') ∩ TargetEdges 的 Jaccard
# 相似度 ≥ threshold（默认 0.95）
#
# 核心创新点：
#   1. Edge-pinning：首次执行后锁定"目标边集"——后续缩减若丢失任一条
# pinned edge 则立即回退该步，避免在错误方向上浪费迭代
# 2. 自适应 Jaccard 阈值：初始覆盖率密度低（稀疏覆盖）→ 降低阈值
# 因为稀疏覆盖中少量边的丢失更可能是噪声而非路径改变
# 3. Byte-import ranking：在每次成功缩减后，按"字节位置是否在
# 被移除区间内"标记热度，指导后续缩减优先尝试冷区
#
# ref: Zeller & Hildebrandt, "Simplifying Isolating Failure-Inducing
#      Input." IEEE TSE 28.2 (2002): 183-200. — ddmin 原始算法
# ref: Rebert et al., "Optimizing Seed Selec for 模糊测试."
# USENIX Securi 2014. — 覆盖率引导的种子选择，本项目将其思想
#      反转用于种子最小化（保留覆盖率而非寻找新覆盖率）

import hashlib
import struct
from typing import Callable, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field


@dataclass
class CoverageMinimizationResult:
    """覆盖率引导最小化的产出"""
    original: bytes
    minimized: bytes
    original_size: int
    minimized_size: int
    iterations: int
    elapsed: float
    success: bool
    # 覆盖率相关指标
    original_edge_count: int = 0
    minimized_edge_count: int = 0
    jaccard_similarity: float = 0.0
    pinned_edges_lost: int = 0
    history: List[dict] = field(default_factory=list)


class CoverageGuidedMinimizer:
    """以覆盖率边集等价为 oracle 的 ddmin 变体
    
    与现有 DeltaDebugger 的关系：DeltaDebugger 处理"崩溃/非崩溃"二值 oracle；
    本模块处理"覆盖率边集等价"的多值 oracle。两者互补——DeltaDebugger 用于
    崩溃输入的最终缩减，本模块用于非崩溃 PoC 和种子最小化
    """

    def __init__(self,
                 executor: Callable[[bytes], Set[int]],
                 jaccard_threshold: float = 0.95,
                 max_iterations: int = 200,
                 timeout_seconds: float = 300.0,
                 granularity: int = 2):
        """
        executor: f(data) → {edge_id,.} — 返回覆盖率边集
        jaccard_threshold: 缩减后边集与目标边集的 Jaccard 相似度下限
        max_iterations: ddmin 最大迭代轮数
        timeout_seconds: 总时间限制
        granulari: ddmin 初始分块数（经典值为 2）
        """
        self._exec = executor
        self._threshold = jaccard_threshold
        self._max_iter = max_iterations
        self._timeout = timeout_seconds
        self._granularity = granularity

    def minimize(self, data: bytes) -> CoverageMinimizationResult:
        """对输入执行覆盖率引导的最小化
        
        流程：
        1. 执行原始输入，记录目标边集 → pinned_edges
        2. 自适应调节 Jaccard 阈值（基于覆盖率密度）
        3. ddmin 主循环——每轮尝试删除 n/granulari 字节
        4. 缩减判定：edge_set(reduced) ∩ pinned_edges 的 Jaccard ≥ threshold
        5. 若判定失败且 pinned edge 丢失 → edge-pinning 回退
        6. 重复直至无法进一步缩减或超时
        """
        import time
        t0 = time.time()

        # Step 1: 基线覆盖率 + 目标边集
        original_edges = self._exec(data)
        if not original_edges:
            return CoverageMinimizationResult(
                original=data, minimized=data,
                original_size=len(data), minimized_size=len(data),
                iterations=0, elapsed=time.time() - t0,
                success=False, original_edge_count=0,
            )

        pinned_edges = frozenset(original_edges)

        # Step 2: 自适应阈值——覆盖率密度低时放宽要求
        # 密度 = 命中边数 / 预期最大边数（粗略估计为 len(data) * 2）
        density = len(pinned_edges) / max(1, len(data) * 2)
        if density < 0.05:
            threshold = max(0.80, self._threshold - 0.10)
        elif density > 0.3:
            threshold = min(0.98, self._threshold + 0.02)
        else:
            threshold = self._threshold

        # Step 3: ddmin 主循环
        current = bytearray(data)
        n = len(current)
        gran = self._granularity
        iteration = 0
        pinned_lost = 0

        while gran <= n and iteration < self._max_iter:
            if time.time() - t0 > self._timeout:
                break

            chunk_size = max(1, n // gran)
            reduced = False

            for start in range(0, n, chunk_size):
                iteration += 1
                if iteration > self._max_iter:
                    break

                end = min(n, start + chunk_size)
                # 构造候选：删除 [start, end) 区间
                candidate = bytes(current[:start] + current[end:])

                edges = self._exec(candidate)
                jaccard = self._jaccard(edges, pinned_edges)

                # 边丢失检测——若 pinned edge 在候选中消失，立即拒绝
                lost_edges = pinned_edges - edges
                if lost_edges:
                    pinned_lost += 1
                    continue

                if jaccard >= threshold:
                    # 缩减成功——接受候选
                    current = bytearray(candidate)
                    n = len(current)
                    reduced = True

            if not reduced:
                # 当前粒度无法缩减 → 细化分块
                gran *= 2
                if gran > n:
                    break

        elapsed = time.time() - t0
        final_edges = self._exec(bytes(current))
        final_jaccard = self._jaccard(final_edges, pinned_edges)

        return CoverageMinimizationResult(
            original=data,
            minimized=bytes(current),
            original_size=len(data),
            minimized_size=len(current),
            iterations=iteration,
            elapsed=round(elapsed, 3),
            success=len(current) < len(data),
            original_edge_count=len(pinned_edges),
            minimized_edge_count=len(final_edges),
            jaccard_similarity=round(final_jaccard, 4),
            pinned_edges_lost=pinned_lost,
        )

    @staticmethod
    def _jaccard(edge_set: Set[int], pinned: frozenset) -> float:
        """计算边集与目标集的 Jaccard 相似度
        
        J(A,B) = |A ∩ B| / |A ∪ B|
        用 pinned 作为全集 B——因为我们不需要超出 pinned 的边
        """
        if not pinned:
            return 0.0
        intersection = len(edge_set & pinned)
        union = len(edge_set | pinned)
        return intersection / union if union > 0 else 0.0


# ---------------------------------------------------------------------------
# Byte-import ranker —— 辅助覆盖率引导最小化的启发式模块
#
# 与 覆盖率GuidedMinimizer 分离以保持单一职责
# 在多次独立执行中统计"被删除后未影响目标边集"的字节区间——
# 这些区间在后续缩减中应被优先尝试
# ---------------------------------------------------------------------------

class ByteImportanceRanker:
    """基于覆盖率反馈的字节重要性排序器
    
    用于加速 CoverageGuidedMinimizer——提前标记"安全删除区"
    使 ddmin 优先尝试这些区间而非均匀分块
    """

    def __init__(self):
        # 每个字节位置的"安全删除计数"——被删除后覆盖率仍达标的次数
        self._safe_count: Dict[int, int] = {}
        self._total_trials: Dict[int, int] = {}

    def record_trial(self, removed_range: Tuple[int, int],
                     jaccard_ok: bool):
        """记录一次删除尝试的结果"""
        start, end = removed_range
        for pos in range(start, end):
            self._total_trials[pos] = self._total_trials.get(pos, 0) + 1
            if jaccard_ok:
                self._safe_count[pos] = self._safe_count.get(pos, 0) + 1

    def safe_deletion_score(self, start: int, end: int) -> float:
        """返回区间 [start, end) 的"安全删除"概率估计
        
        得分 = mean(safe_count[pos] / trials[pos]) for pos [启动, end)
        得分 > 0.8 的区间应在 ddmin 中优先尝试
        """
        total, safe = 0, 0.0
        for pos in range(start, end):
            trials = self._total_trials.get(pos, 0)
            if trials > 0:
                safe += self._safe_count.get(pos, 0) / trials
                total += 1
        return safe / total if total > 0 else 0.5

    def rank_intervals(self, data_len: int,
                       interval_count: int = 8) -> List[Tuple[int, int, float]]:
        """将输入等分为 interval_count 个区间，按安全得分升序排列
        
        得分最低的区间最"关键"——包含覆盖率依赖的字节——应在缩减中保留
        """
        chunk = max(1, data_len // interval_count)
        intervals = []
        for i in range(interval_count):
            start = i * chunk
            end = min(data_len, start + chunk) if i < interval_count - 1 else data_len
            if start >= end:
                continue
            score = self.safe_deletion_score(start, end)
            intervals.append((start, end, score))
        intervals.sort(key=lambda x: x[2])
        return intervals
