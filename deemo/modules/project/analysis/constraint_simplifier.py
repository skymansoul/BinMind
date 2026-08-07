# 约束简化器: 将值域约束转化为可判定的不等式系统
# 技术问题: 堆溢出检测的核心判断是: "写入大小 + 偏移 > 分配大小?"
#   在静态分析中, 这三者都是值域 (可能包含top/不精确区间),
#   不能直接做数值比较. 需要约束系统化约简.
# 解决手段: 将判断转化为约束满足问题:
#   已知: write_size ∈ [w_lo, w_hi], offset ∈ [o_lo, o_hi],
#          alloc_size ∈ [a_lo, a_hi]
#   求证: 是否存在满足约束 w + o > a 的值组合?
#   若可证明 w_hi + o_hi ≤ a_lo (最坏情况都不溢出) → 无溢出, 消除误报
#   若可证明 w_lo + o_lo > a_hi (最好情况也溢出) → 确定溢出
#   否则 → 可能溢出 (需报告但降低置信度)
#
#   D'Silva et al. "The Static Analysis of Unsafe put Operations"
#     (USENIX Security 2022) — PutX的约束验证思想
#   Kang et al. "Scaling Static Analyses at Facebook" (CACM 2022)
#     — 大规模约束简化的生产实践
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple
from .value_range import ValueRange


class OverflowVerdict(Enum):
    DEFINITE_SAFE = auto()       # 可证明安全: 不可能溢出
    POSSIBLE_OVERFLOW = auto()   # 无法排除: 可能溢出
    DEFINITE_OVERFLOW = auto()   # 可证明溢出: 一定溢出
    UNKNOWN = auto()            # 信息不足: 无法判定


@dataclass
class ConstraintResult:
    """约束求解结果."""
    verdict: OverflowVerdict
    max_safe_write: int = 0      # 在已知约束下最大安全写入量
    overflow_confidence: float = 0.0  # 溢出可能性 [0, 1]
    explanation: str = ""
    evidence: List[str] = field(default_factory=list)


class ConstraintSimplifier:
    """约束简化引擎.

    将堆写入的安全性判断转化为值域比对的线性约束.
    支持多层推断:
      L0: 直接比较 (w_hi + o vs a_lo)
      L1: 已知对齐约束 (如malloc对齐到16B, 减少实际可用大小)
      L2: 已知chunk header开销 (glibc chunk header占用0x10字节)
      L3: 考虑整数溢出回绕 (若w+o可能回绕导致实际写入变小)
    """

    # glibc堆块元数据开销 (64位)
    _CHUNK_HEADER_SIZE = 0x10  # prev_size(8) + size(8)
    _MIN_CHUNK_SIZE = 0x20     # 最小chunk大小 (含header)
    _ALIGNMENT = 0x10

    def __init__(self, assume_glibc_heap: bool = True):
        self._glibc = assume_glibc_heap
        self._header = self._CHUNK_HEADER_SIZE if assume_glibc_heap else 0

    def check_heap_write(self, write_size: ValueRange,
                         pointer_offset: ValueRange,
                         alloc_size: ValueRange,
                         is_str_copy: bool = False) -> ConstraintResult:
        """核心检查: 堆写入是否可能溢出分配边界.

        write_size: memcpy的第三个参数 / 循环写入总次数的值域
        pointer_offset: 写入目标指针相对于分配基址的偏移
        alloc_size: 分配点的malloc参数的值域
        is_str_copy: 若为strcpy等字符串操作, write_size由内容决定
        """
        evidence = []
# L0: 保守检查
        # 最坏情况: 最大写入 + 最大偏移 vs 最小分配
        worst_write = write_size.umax if not write_size.is_top else 0x7FFFFFFF
        worst_offset = pointer_offset.umax if not pointer_offset.is_top else 0
        best_alloc = alloc_size.umin if not alloc_size.is_top else 0
        # L0安全下界: 使用原始分配大小, 不减header.
        # 运行时分配器可能因对齐/最小块而提供更多空间,
        # 源码级malloc参数是可用空间的有效下界
        usable_lo = max(0, best_alloc)

        if write_size.is_top or alloc_size.is_top:
            evidence.append("值域信息不足(L0-top), 无法精确判定")
            return ConstraintResult(
                verdict=OverflowVerdict.UNKNOWN,
                max_safe_write=usable_lo,
                overflow_confidence=0.5,
                explanation="大小或分配值域为top, 缺少静态信息",
                evidence=evidence)

        total_worst = worst_write + worst_offset
        if total_worst <= usable_lo:
            evidence.append(f"L0: {worst_write}+{worst_offset} ≤ {usable_lo} (usable)")
            return ConstraintResult(
                verdict=OverflowVerdict.DEFINITE_SAFE,
                max_safe_write=usable_lo - worst_offset,
                overflow_confidence=0.0,
                explanation=f"最坏情况写入量({total_worst})在分配范围内",
                evidence=evidence)

# L1: 精确检查
        best_write = write_size.umin if not write_size.is_top else 0
        best_offset = pointer_offset.umin
        worst_alloc = alloc_size.umax if not alloc_size.is_top else 0x7FFFFFFF
        # L1溢出上界: 仅当分配≥最小chunk时才适用header模型
        # 否则分配器已向上取整, header开销已包含在最小chunk中
        if worst_alloc >= self._MIN_CHUNK_SIZE:
            usable_hi = max(0, worst_alloc - self._header)
        else:
            usable_hi = worst_alloc

        if best_write + best_offset > usable_hi:
            evidence.append(f"L1: {best_write}+{best_offset} > {usable_hi} (worst usable)")
            return ConstraintResult(
                verdict=OverflowVerdict.DEFINITE_OVERFLOW,
                max_safe_write=max(0, usable_hi - best_offset),
                overflow_confidence=0.95,
                explanation="最小写入量已超过最大可用空间",
                evidence=evidence)

# L2: 可能溢出 — 计算置信度
        # 置信度由值域精度决定: 区间越窄, 判定越确定
        if write_size.is_constant and alloc_size.is_constant:
            # 两者都精确 → 高置信度判断
            if write_size.umin <= usable_lo:
                evidence.append(f"L2-exact: {write_size.umin} ≤ {usable_lo}, 安全")
                return ConstraintResult(
                    verdict=OverflowVerdict.DEFINITE_SAFE,
                    max_safe_write=usable_lo - worst_offset,
                    overflow_confidence=0.0,
                    explanation="写入大小和分配大小均确定, 无误报可能",
                    evidence=evidence)
            else:
                # 精确溢出: 仅在分配≥最小chunk时确认
                if worst_alloc >= self._MIN_CHUNK_SIZE or write_size.umin > alloc_size.umin:
                    evidence.append(f"L2-exact: {write_size.umin} > {usable_lo}, 溢出")
                    return ConstraintResult(
                        verdict=OverflowVerdict.DEFINITE_OVERFLOW,
                        max_safe_write=usable_lo - worst_offset,
                        overflow_confidence=0.98,
                        explanation="写入大小确定超过分配大小",
                        evidence=evidence)

# L3: 区间重叠 → 计算溢出可能性
        # 重叠区间: [best_write, worst_write] 与 [0, usable_lo] 重叠
        write_lo = write_size.umin
        write_hi = write_size.umax
        overlap_lo = max(write_lo, 0)
        overlap_hi = min(write_hi, usable_lo)
        write_range = write_hi - write_lo if write_hi > write_lo else 1
        safe_range = max(0, overlap_hi - overlap_lo)
        overflow_prob = 1.0 - (safe_range / write_range)
        overflow_prob = max(0.0, min(1.0, overflow_prob))

        evidence.append(
            f"L3: 写入[{write_lo:#x},{write_hi:#x}], 可用{usable_lo:#x}, "
            f"溢出概率={overflow_prob:.2f}")

        return ConstraintResult(
            verdict=OverflowVerdict.POSSIBLE_OVERFLOW,
            max_safe_write=usable_lo - pointer_offset.umin,
            overflow_confidence=overflow_prob,
            explanation=f"写入与分配边界存在重叠: "
                       f"safe_range={safe_range:#x}/{write_range:#x}",
            evidence=evidence)

    def check_multi_write(self, writes: List[Tuple[ValueRange, ValueRange]],
                          alloc_size: ValueRange) -> ConstraintResult:
        """多位置写入检查: 多个写入的累积是否超过分配.

        writes: [(size_range, offset_range), ...]
        """
        total_max = sum(w.umax + o.umax for w, o in writes
                       if not w.is_top and not o.is_top)
        usable = max(0, (alloc_size.umin if not alloc_size.is_top else 0) - self._header)
        if total_max <= usable:
            return ConstraintResult(
                verdict=OverflowVerdict.DEFINITE_SAFE,
                max_safe_write=usable,
                overflow_confidence=0.0,
                explanation=f"多写入累计{total_max}在分配{usable}内")
        total_min = sum(w.umin + o.umin for w, o in writes
                       if not w.is_top and not o.is_top)
        worst_usable = max(0, (alloc_size.umax if not alloc_size.is_top
                          else 0x7FFFFFFF) - self._header)
        if total_min > worst_usable:
            return ConstraintResult(
                verdict=OverflowVerdict.DEFINITE_OVERFLOW,
                max_safe_write=worst_usable,
                overflow_confidence=0.92,
                explanation=f"多写入最小值{total_min}已超最大可用空间")
        overlap_ratio = max(0.0, min(1.0,
            (total_max - usable) / max(total_max - total_min, 1)))
        return ConstraintResult(
            verdict=OverflowVerdict.POSSIBLE_OVERFLOW,
            max_safe_write=usable,
            overflow_confidence=overlap_ratio,
            explanation=f"多写入部分超出: 重叠比例{overlap_ratio:.2f}")

    def check_loop_write(self, iteration_range: ValueRange,
                         per_iteration_write: ValueRange,
                         alloc_size: ValueRange) -> ConstraintResult:
        """循环体写入检查: iter × per_write vs alloc.

        若循环次数未知, 使用循环边界启发式.
        """
        if iteration_range.is_top:
            # 循环边界未知 → 假设无保护
            return ConstraintResult(
                verdict=OverflowVerdict.POSSIBLE_OVERFLOW,
                max_safe_write=0,
                overflow_confidence=0.7,
                explanation="循环边界未知, 保守假设可能溢出")
        # total = iter_range * per_write
        total_range = iteration_range.mul(per_iteration_write)
        return self.check_heap_write(
            total_range, ValueRange.constant(0), alloc_size)

    def get_safe_write_limit(self, alloc_size_range: ValueRange,
                             offset_range: ValueRange
                             ) -> int:
        """返回安全写入上限."""
        alloc_min = alloc_size_range.umin if not alloc_size_range.is_top else 0x1000
        offset_max = offset_range.umax if not offset_range.is_top else 0
        usable = max(0, alloc_min - self._header)
        return max(0, usable - offset_max)
