# 写侧检查集成 — 在既有Filter链中插入双向区间交汇验证
"""既有Filter 4在 w_size==0 时调用 OverflowSatisfiabilitySolver,
  其判定 "alloc.lower >= 0 → cannot_overflow" 恒真, 导致真实溢出被误滤。
  本模块在Filter 4前拦截 w_size==0 的pair:
    1. 用WriteIntervalTracker提取写侧区间
    2. 用BidirectionalIntervalVerifier做双向交汇判定
    3. 返回可注入_analyze_pair的verdict, 原逻辑分支保持不变

设计决策:
  - 仅当写侧未知(无法提取常量)时介入, 不影响已知常量write的原有判定
  - 双向交汇的"不可判"结果 → 交给原Filter 4的taint逻辑兜底
"""

import logging
from typing import Dict, Optional
from dataclasses import dataclass

_log = logging.getLogger(__name__)


@dataclass
class WriteSideCheckResult:
    """写侧检查结果, 供_analyze_pair注入。"""
    activated: bool = False      # 是否介入
    finding_update: Dict = None  # 对finding的字段更新
    final_verdict: Optional[str] = None  # 'vulnerable' | 'fp' | None(继续)


class WriteSideCheck:
    """写侧区间检查器 — 处理 w_size==0 的pair。"""

    def __init__(self):
        from .write_interval_tracker import WriteIntervalTracker
        from .bidirectional_interval import BidirectionalIntervalVerifier
        self._tracker = WriteIntervalTracker()
        self._verifier = BidirectionalIntervalVerifier()

    def run(self, asm_lines, alloc, size_c, w, is_tainted,
            effective_lower, effective_upper,
            alloc_func_name: str = "") -> WriteSideCheckResult:
        """执行写侧检查。

        返回WriteSideCheckResult:
          - activated=True且final_verdict='vulnerable' → 判定为TP
          - activated=True且final_verdict='fp' → 判定为FP
          - 其他 → 继续原Filter链
        """
        # CRT内部代码不做深度分析(与detector一致)
        if alloc_func_name and (alloc_func_name.startswith('_')
                                or alloc_func_name in _CRT_KNOWN):
            return WriteSideCheckResult(activated=False)

        wint = self._tracker.trace(asm_lines, w['line'], w['func'])
        # 写侧上界已知(常量或受守卫收紧) → 双向交汇
        if wint.is_known:
            verdict = self._verifier.verify(
                alloc_lower=effective_lower,
                alloc_upper=effective_upper,
                write_low=wint.low, write_high=wint.high,
                write_known=True, write_tainted=wint.is_tainted,
                alloc_tainted=is_tainted,
                alloc_has_bound=size_c.has_explicit_bound,
                alloc_size_is_constant=alloc.size_is_constant)
            if verdict.cannot_overflow:
                return WriteSideCheckResult(
                    activated=True,
                    finding_update={
                        'is_false_positive': True,
                        'fp_source': 'write_side_bounds',
                        'confidence': verdict.confidence,
                        'severity': 'NONE',
                        'reason': f'[write-side] {verdict.reason}',
                        'write_size': wint.high,
                    },
                    final_verdict='fp')
            if verdict.will_overflow:
                return WriteSideCheckResult(
                    activated=True,
                    finding_update={
                        'is_vulnerable': True,
                        'confidence': verdict.confidence,
                        'severity': 'HIGH',
                        'overflow_bytes': max(0, wint.low - effective_upper),
                        'reason': f'[write-side] {verdict.reason}',
                        'write_size': wint.low,
                    },
                    final_verdict='vulnerable')
            # 区间重叠 → 返回置信度更新, 继续原链
            return WriteSideCheckResult(
                activated=True,
                finding_update={
                    'confidence_hint': verdict.confidence,
                    'write_size': wint.high,
                    'reason': f'[write-side] {verdict.reason}',
                })

        # 写侧上界不可知 + 写侧受控(外部输入):
        # 原Filter 4 solve(..., 0, False) 会因 alloc.lower>=0 恒真而误判
        # cannot_overflow, 把真实溢出滤成FP。此处拦截: 按taint语义判定。
        # alloc是否受界: 用路径收紧后的effective_upper判断,
        # 守卫(cmp+jcc)将上界收窄至256的样本不得判为"无界受控"。
        default_upper = 2**31 - 1
        alloc_effectively_bounded = (
            size_c.has_explicit_bound or effective_upper < default_upper)
        if wint.is_tainted:
            if is_tainted and not alloc_effectively_bounded:
                return WriteSideCheckResult(
                    activated=True,
                    finding_update={
                        'is_vulnerable': True,
                        'confidence': 0.55,
                        'severity': 'HIGH',
                        'reason': (f'[write-side] write受控且上界不可知, '
                                   f'alloc受控无界 → 潜在溢出'),
                    },
                    final_verdict='vulnerable')
            if is_tainted and alloc_effectively_bounded:
                # alloc有界但write不可知 → 无法排除溢出, 低置信
                return WriteSideCheckResult(
                    activated=True,
                    finding_update={
                        'confidence_hint': 0.25,
                        'reason': '[write-side] write上界不可知, alloc有界',
                    })
            # write受控但alloc为常量 → 原逻辑已能判定, 不介入
            return WriteSideCheckResult(activated=False)
        return WriteSideCheckResult(activated=False)


_CRT_KNOWN = {
    'duplicate_ppstrings', 'do_pseudo_reloc', 'mark_section_writable',
    'restore_modified_sections', 'register_frame_ctor', 'check_managed_app',
    'dtoa_lock', 'dtoa_lock_cleanup', 'dtoa_unlock', 'safe_flush',
    'fallback_IsDBCSLeadByteEx', 'init_fpreg_ldouble', '__write_memory',
    '_pei386_runtime_relocator', '_gnu_exception_handler', 'bitstob',
    'b2d_D2A',
}
