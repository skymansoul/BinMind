"""
堆溢出置信度多因子评分器 — 五维正交评分: 分配器/路径/模式/上下文/区间.

用加权几何平均合并 (非算术平均): 几何平均惩罚接近0的维度, 适合"一票否决"场景.
每个维度输出 0~1 独立分数, 几何平均越近0 → 越可能FP, 越近1 → 越可能TP.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from analysis.interval_domain import Interval
@dataclass
class ConfidenceFactors:
    """各维度的独立置信度因子。"""
    allocator_score: float = 0.5     # 分配器语义
    path_score: float = 0.5          # 路径可达性
    pattern_score: float = 0.5       # 写入模式
    context_score: float = 0.5       # 上下文
    interval_score: float = 0.5      # 区间分析

    def combined(self, weights: Optional[List[float]] = None) -> float:
        """加权几何平均合并各维度分数。

        默认等权重 [1, 1, 1, 1, 1]。
        可以通过 weights 调整各维度的重要性。
        """
        if weights is None:
            weights = [1.0] * 5
        factors = [
            self.allocator_score, self.path_score,
            self.pattern_score, self.context_score, self.interval_score,
        ]
        # 处理零值: 几何平均不能有零
        eps = 1e-6
        weighted = [(max(f, eps) ** w) for f, w in zip(factors, weights)]
        product = 1.0
        for v in weighted:
            product *= v
        return product ** (1.0 / sum(weights))

    def is_false_positive(self, threshold: float = 0.3) -> bool:
        """综合分数低于阈值 → 判定为误报。"""
        return self.combined() < threshold

    def is_true_positive(self, threshold: float = 0.7) -> bool:
        """综合分数高于阈值 → 判定为真阳性。"""
        return self.combined() > threshold

class HeapConfidenceScorer:
    """多因子置信度评分器。

    每个维度独立评分, 最后合并。
    评分原则: 信号越明确分数越极端 (0或1), 信号越模糊越靠近0.5 (中性)。
    """

    def __init__(self, platform: str = "x86_64"):
        self._platform = platform
        if platform == "x86_64":
            self._alignment = 16
            self._min_chunk = 32
        elif platform == "x86":
            self._alignment = 8
            self._min_chunk = 16
        else:
            self._alignment = 16
            self._min_chunk = 32

    # 维度 1: 分配器语义

    def score_allocator(
        self, alloc_size: int, write_offset: int, write_size: int,
    ) -> float:
        """基于 glibc 分配器语义评分。

        写入在对齐填充区内 → 低分(FP倾向); 远超分配大小 → 高分(TP倾向)。
        """
        if alloc_size <= 0 or write_offset < 0:
            return 0.5

        aligned = self._align_up(alloc_size)
        effective = max(self._min_chunk, aligned)
        total_write = write_offset + max(write_size, 4)

        # 写入在分配的有效范围内 → 很可能是误报
        if total_write <= alloc_size:
            return 0.15
        # 写入在对齐填充区内 → 可能是误报
        if total_write <= aligned:
            return 0.25
        if total_write <= effective:
            return 0.35
        # 明确超出有效大小 → 真阳性信号
        if total_write > effective + 16:
            return 0.85
        if total_write > effective:
            return 0.70
        return 0.50

    # 维度 2: 路径可达性

    def score_path(
        self, safe_paths: int, unsafe_paths: int, total_paths: int,
    ) -> float:
        """基于路径分析结果评分。

        全路径安全 → 低分(FP); 存在不安全路径 → 高分(TP)
        """
        if total_paths == 0:
            return 0.5
        unsafe_ratio = unsafe_paths / total_paths
        if unsafe_ratio == 0:
            return 0.20
        if unsafe_ratio < 0.25:
            return 0.35
        if unsafe_ratio < 0.5:
            return 0.55
        if unsafe_ratio < 0.75:
            return 0.70
        return 0.85

    # 维度 3: 写入模式

    def score_pattern(
        self, store_offsets: List[int], alloc_size: int,
    ) -> float:
        """基于写入偏移的分布模式评分。

        连续低偏移 → 结构体字段(FP); 随机跳跃 → 可疑; 单一大偏移 → 高度可疑
        """
        if not store_offsets:
            return 0.5

        # 检查是否是连续递增的偏移
        is_sequential = True
        sorted_offsets = sorted(store_offsets)
        for i in range(1, len(sorted_offsets)):
            if sorted_offsets[i] - sorted_offsets[i-1] > 16:
                is_sequential = False
                break

        max_offset = max(store_offsets)
        if max_offset < alloc_size * 0.5:
            return 0.25
        if is_sequential and max_offset < alloc_size:
            return 0.30
        if is_sequential:
            return 0.40
        if max_offset > alloc_size * 2:
            return 0.80
        if max_offset > alloc_size:
            return 0.65
        return 0.50

    # 维度 4: 上下文

    _SAFE_FUNC_PREFIXES = {
        'init_', 'setup_', 'create_', 'alloc_', 'new_',
        'construct_', 'build_', 'make_', 'clone_',
    }
    _WRAPPER_PATTERNS = {'wrapper_', '_wrap', '_stub', '_helper'}

    def score_context(self, func_name: str, alloc_func: str) -> float:
        """基于函数名和上下文语义评分。

        安全模式(低分→FP): 初始化/构造, memset清零, 包装函数.
        危险模式(高分→TP): 解析/反序列化, 字符串处理函数.
        """
        fn_lower = func_name.lower()

        # 安全前缀
        for prefix in self._SAFE_FUNC_PREFIXES:
            if fn_lower.startswith(prefix):
                return 0.30

        # 解析函数 → 危险
        if any(kw in fn_lower for kw in ('parse', 'read_', 'decode', 'deserialize',
                                           'unpack', 'recv', 'copy_')):
            return 0.75

        # strcpy/memcpy 相关
        if any(kw in fn_lower for kw in ('strcpy', 'strcat', 'sprintf',
                                           'memcpy', 'strncpy')):
            return 0.70

        # 包装函数 → 中性偏安全
        for pat in self._WRAPPER_PATTERNS:
            if pat in fn_lower:
                return 0.40

        return 0.50

    # 维度 5: 区间分析

    def score_interval(self, alloc_interval: Interval,
                       total_write: int) -> float:
        """基于区间分析结果评分。

        区间能证明安全 → 误报 (低分)
        区间无法排除溢出 → 真阳性可能 (高分)
        """
        if alloc_interval.is_top():
            return 0.65  # 完全未知 → 偏向保留
        if alloc_interval.is_bottom():
            return 0.50

        lo = alloc_interval.lo
        hi = alloc_interval.hi

        # 上界能容纳: 安全
        if hi is not None and total_write <= hi:
            if lo is not None and total_write <= lo:
                return 0.15  # 确定安全
            return 0.30  # 可能安全
        # 下界也超出: 一定溢出
        if lo is not None and total_write > lo:
            return 0.85  # 确定溢出
        # 上界不足以容纳: 倾向溢出
        if hi is not None and total_write > hi:
            return 0.75

        return 0.50

    # 综合评分

    def score(
        self,
        alloc_size: int,
        write_offset: int,
        write_size: int,
        store_offsets: Optional[List[int]] = None,
        func_name: str = "",
        alloc_func: str = "malloc",
        safe_paths: int = 0,
        unsafe_paths: int = 1,
        total_paths: int = 1,
        alloc_interval: Optional[Interval] = None,
    ) -> ConfidenceFactors:
        """综合评分 —— 对所有维度打分并返回 ConfidenceFactors。"""
        if store_offsets is None:
            store_offsets = [write_offset]

        if alloc_interval is None:
            alloc_interval = Interval.const(alloc_size)

        return ConfidenceFactors(
            allocator_score=self.score_allocator(
                alloc_size, write_offset, write_size),
            path_score=self.score_path(
                safe_paths, unsafe_paths, total_paths),
            pattern_score=self.score_pattern(
                store_offsets, alloc_size),
            context_score=self.score_context(func_name, alloc_func),
            interval_score=self.score_interval(
                alloc_interval, write_offset + max(write_size, 4)),
        )

    def _align_up(self, size: int) -> int:
        return ((size + self._alignment - 1) // self._alignment) * self._alignment

# 便捷函数

def classify_heap_overflows(
    candidates: list,  # list[HeapOverflowCandidate]
    ir_lines: Optional[List[str]] = None,
    func_name: str = "",
) -> list:
    """对堆溢出候选列表做置信度分类, 附加 factors 属性并标记 verdict."""
    scorer = HeapConfidenceScorer()
    classified = []

    for c in candidates:
        factors = scorer.score(
            alloc_size=c.alloc_site.size_arg,
            write_offset=c.overflow_store.offset,
            write_size=c.overflow_store.store_size,
            func_name=func_name,
            alloc_func=c.alloc_site.alloc_func,
        )
        combined = factors.combined()
        if factors.is_false_positive():
            verdict = "FP_LIKELY"
        elif factors.is_true_positive():
            verdict = "TP_LIKELY"
        else:
            verdict = "UNCERTAIN"

        # 附加到候选对象的 metadata
        c.confidence_factors = factors
        c.combined_confidence = combined
        c.verdict = verdict

        if verdict != "FP_LIKELY":
            classified.append(c)

    return classified

__all__ = ['ConfidenceFactors', 'HeapConfidenceScorer',
           'classify_heap_overflows']
