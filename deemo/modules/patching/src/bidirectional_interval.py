# 创建: 2024-09-05
# 双向区间交汇验证 — alloc可用区间 × write取值区间 的溢出判定
"""既有求解器(OverflowSatisfiabilitySolver)只用alloc单侧区间对比单一
write常量。当write_size未知(=0)时, "alloc.lower >= 0" 恒真 → 误判
cannot_overflow, 导致真实溢出被滤掉(召回崩塌)并虚增FP过滤率。

本模块引入写侧区间后做双向交汇:
  A = alloc请求区间, 经ptmalloc可用空间映射 → [u_low, u_high]
  W = write取值区间 [w_low, w_high] (w_high未知时按taint处理)

判定:
  u_low  >= w_high  → 确定不溢出 (FP)
  u_high <  w_low   → 确定溢出   (TP)
  区间重叠           → may-overflow, 置信度由taint与守卫共同决定
  w_high不可知       → 不得判cannot_overflow, 回退taint判定

设计依据: 区间抽象是路径敏感性的廉价近似, 双向交汇
比单向(仅alloc侧)多消除"write侧受守卫收紧"的误报。
"""

import re
from typing import Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class BidirectionalVerdict:
    """双向交汇判定结果。"""
    will_overflow: bool = False
    may_overflow: bool = False
    cannot_overflow: bool = False
    confidence: float = 0.0
    reason: str = ""
    write_high: int = 0
    usable_low: int = 0


class BidirectionalIntervalVerifier:
    """alloc可用区间 × write区间 的溢出判定器。"""

    def __init__(self):
        from .heap_allocator_model import AllocSizeCalculator, PTMALLOC64
        self._calc = AllocSizeCalculator(PTMALLOC64)

    def verify(self, alloc_lower: int, alloc_upper: int,
               write_low: int, write_high: int,
               write_known: bool, write_tainted: bool,
               alloc_tainted: bool, alloc_has_bound: bool,
               alloc_size_is_constant: bool = False
               ) -> BidirectionalVerdict:
        """交汇判定。

        参数:
          alloc_lower/alloc_upper: 请求大小区间
          write_low/write_high: 写侧取值区间
          write_known: 写侧上界是否可知
          write_tainted: 写侧是否受外部输入控制
          alloc_tainted/alloc_has_bound: alloc侧状态
        """
        # 映射为ptmalloc实际可用区间
        usable_low = self._calc.request_to_usable(alloc_lower)
        usable_high = self._calc.request_to_usable(alloc_upper)
        verdict = BidirectionalVerdict(
            write_high=write_high, usable_low=usable_low)

        # 写侧上界不可知 → 不得判cannot_overflow
        if not write_known:
            return self._unknown_write_verdict(
                alloc_upper, alloc_tainted, alloc_has_bound, write_tainted,
                verdict)

        # 上界已知: 精确判定
        if usable_low >= write_high:
            verdict.cannot_overflow = True
            verdict.confidence = 0.92
            verdict.reason = (
                f'可用下界{usable_low}B ≥ 写侧上界{write_high}B → 不溢出')
            return verdict

        if usable_high < write_low:
            verdict.will_overflow = True
            verdict.may_overflow = True
            verdict.confidence = 0.90
            verdict.reason = (
                f'可用上界{usable_high}B < 写侧下界{write_low}B → 必定溢出')
            return verdict

        # 区间重叠 → 可能溢出
        verdict.may_overflow = True
        if alloc_tainted and not alloc_has_bound:
            verdict.confidence = 0.55
            verdict.reason = (
                f'alloc受控无界与write区间[{write_low},{write_high}]重叠 → 可能溢出')
        elif alloc_tainted and alloc_has_bound:
            verdict.confidence = 0.20
            verdict.reason = (
                f'alloc受控有界与write区间[{write_low},{write_high}]重叠 → 风险低')
        else:
            verdict.confidence = 0.10
            verdict.reason = 'alloc常量与write区间重叠, 实际取决于可用空间'
        return verdict

    def _unknown_write_verdict(self, alloc_upper: int,
                               alloc_tainted: bool, alloc_has_bound: bool,
                               write_tainted: bool,
                               verdict: BidirectionalVerdict
                               ) -> BidirectionalVerdict:
        """写侧上界不可知时的保守判定。"""
        # FIXME: 写侧完全不可知时依赖taint启发式, 未做调用点实参区间推断
        # 写侧不可知 + alloc有界且边界小 → 不能排除溢出但置信度低
        if write_tainted:
            verdict.may_overflow = True
            if alloc_tainted and not alloc_has_bound:
                verdict.confidence = 0.50
                verdict.reason = 'write受控且上界不可知, alloc受控无界 → 潜在溢出'
            elif alloc_has_bound:
                verdict.confidence = 0.30
                verdict.reason = 'write上界不可知, alloc有界 → 无法排除溢出'
            else:
                verdict.confidence = 0.35
                verdict.reason = 'write上界不可知 → 潜在溢出'
            return verdict
        # 写侧不可知且非taint: 常量alloc+常量write均已知时, 此路径罕见
        verdict.may_overflow = False
        verdict.cannot_overflow = False
        verdict.confidence = 0.10
        verdict.reason = 'write信息不足, 保守不判溢出'
        return verdict
