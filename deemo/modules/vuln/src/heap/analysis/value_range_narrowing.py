"""值区间守卫窄化 — 利用路径守卫条件将 TOP 区间约束为有限区间.

创建: 2024-09-27

核心算法:
  给定 malloc size 参数的值区间 SInterval 和该寄存器在调用前的路径守卫集合,
  通过 intersect(interval, guard_constraint) 将 TOP ([0, 2^32]) 窄化为具体上界.

设计决策:
  - 为什么在 backward_trace 后、FP filter 前做窄化:
    backward_trace 收集值流 (def-use chain), 但不会利用 cmp+jcc 控制流信息。
    在 trace 完成后用守卫条件做二次约束, 是"path-sensitive without path explosion"
    策略 — 仅在已识别出的 alloc site 上追加控制流信息, 不增加搜索空间。
  - 为什么同时保留原始区间和窄化后区间:
    语义特征提取需要两者: 原始区间用于判断"值流推断的精度",
    窄化区间用于"实际可用空间"计算。两者不一致时 (守卫约束>值流上界),
    守卫条件更可信 (因为它是运行时的外部约束)。
  - 保守性保证: 对同一 reg 的多条守卫取 intersection (最紧约束),
    即使包含不可达路径的守卫, 更紧的约束只会导致更多"安全"判定,
    漏报风险为零 (safe→unsafe 不会发生, unsafe→safe 被守卫阻止)。

  - CRYPTOSS: taint+guard dual scoring — 借鉴其守卫置信度加权
  - AbstractInterpretation: 区间抽象 + 条件窄化 — 理论根基
  - VSA refinement: lazy constraint solving for conditional narrowing
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .interval_domain import SInterval
from .path_guard_collector import (
    PathGuard, GuardOp, collect_guards, guards_for_insn)

@dataclass
class NarrowedValue:
    """窄化后的值区间 — 原始区间 + 守卫窄化区间 + 元数据."""
    original: SInterval         # backward_trace 的原始结果
    narrowed: SInterval         # 守卫窄化后的结果
    guards_applied: List[PathGuard]  # 应用的守卫列表
    narrowing_effect: str = ""  # 窄化效果描述: 'tight', 'mild', 'none'

    @property
    def was_improved(self) -> bool:
        """窄化是否有实质性改善."""
        return (self.original.is_top and not self.narrowed.is_top) or \
               (self.narrowed.max_possible() < self.original.max_possible())

    @property
    def improvement_ratio(self) -> float:
        """窄化比率: narrowed.hi / original.hi (≤1.0, 越小越好)."""
        if self.original.is_top:
            return 0.01  # TOP→有限 = 巨大改善
        if self.original.max_possible() == 0:
            return 1.0
        return min(1.0, self.narrowed.max_possible() /
                   max(1, self.original.max_possible()))

def apply_guard_to_interval(interval: SInterval,
                            guard: PathGuard) -> SInterval:
    """将单条路径守卫应用到 SInterval, 返回窄化后的新区间.

    语义: 若 guard.reg 在本路径上满足 guard.op guard.const,
    则 interval 被限定到该约束范围内。

    例如: interval=TOP, guard=(rcx ≤ 64) → [0, 64]
          interval=[32, 256], guard=(rcx ≥ 64) → [64, 256]
    """
    if interval.is_top:
        lo, hi = 0, 0xFFFFFFFF
    elif interval.is_bot:
        return interval
    else:
        lo, hi = interval.lo, interval.hi

    c = guard.const
    signed = guard.is_signed

    if guard.op == GuardOp.LE:
        hi = min(hi, c)
    elif guard.op == GuardOp.LT:
        hi = min(hi, c - 1)
    elif guard.op == GuardOp.GE:
        lo = max(lo, c)
    elif guard.op == GuardOp.GT:
        lo = max(lo, c + 1)
    elif guard.op == GuardOp.EQ:
        lo = max(lo, c)
        hi = min(hi, c)
    elif guard.op == GuardOp.NE:
        # ≠ 不缩小区间 (单条 ≠ 不提供上/下界)
        pass

    if lo > hi:
        return SInterval.bot()

    # 有符号语义: 若 lo 为负数 (有符号下界), 保守取 0
    if signed and lo < 0:
        lo = 0

    # 若区间未变化, 返回原值
    if (not interval.is_top) and lo == interval.lo and hi == interval.hi:
        return interval

    new_stride = interval.stride if not interval.is_top else 1
    return SInterval.range_lo_hi(lo, hi, stride=new_stride)

def intersect_guards(reg: str, interval: SInterval,
                     guards: List[PathGuard],
                     insn_addr: int = 0) -> SInterval:
    """应用 reg 的所有守卫到区间, 返回最紧约束 (conservative intersect).

    多条守卫的语义: 每条独断在各自的 fallthrough 路径上成立,
    我们取其 INTERSECTION (最紧上界 + 最高下界) — 这是 conservative
    under-approximation: 窄化后的区间 ≤ 真实运行区间.

    路径互斥性处理: 同一 cmp 的 fallthrough 和 jump 方向在运行时互斥,
    不应同时 intersect。通过 cmp_addr 和 coverage_range 判定当前指令
    所在路径, 只选择方向一致的守卫.

    例: guards = [rcx ≤ 128, rcx ≤ 64] → narrowed = [0, 64]
    """
    # 按 cmp_addr 分组 — 同一 cmp 的互斥守卫只选方向匹配者
    cmp_groups: Dict[int, List[PathGuard]] = {}
    ungrouped: List[PathGuard] = []
    for g in guards:
        if g.reg != reg:
            continue
        ca = getattr(g, 'cmp_addr', 0)
        if ca:
            cmp_groups.setdefault(ca, []).append(g)
        else:
            ungrouped.append(g)

    # 对每个 cmp 组, 按 insn_addr 的 coverage_range 归属选择唯一守卫
    selected: List[PathGuard] = list(ungrouped)
    for ca, group in cmp_groups.items():
        chosen = None
        if insn_addr:
            for g in group:
                cr = getattr(g, 'coverage_range', None)
                if cr is not None and cr[0] <= insn_addr <= cr[1]:
                    chosen = g
                    break
        if chosen is None:
            # 无明确归属 — 保守取 fallthrough 方向
            for g in group:
                if g.fallthrough:
                    chosen = g
                    break
        if chosen is None and group:
            chosen = group[0]
        if chosen is not None:
            selected.append(chosen)

    result = interval
    for g in selected:
        if g.fallthrough:
            result = apply_guard_to_interval(result, g)
            if result.is_bot:
                break
    return result

class ValueRangeNarrower:
    """利用路径守卫窄化值区间 — 将 'size unknown' 转为 'size ≤ bound'.

    使用方式:
      narrow_alloc_size(alloc_insn_addr, size_interval, guards)
        → NarrowedValue

    集成点: 在 heap_overflow_detector.py 的 analyze() 中,
    对每个 alloc site 调用, 替换原始的 size_interval。
    """

    def __init__(self, reg_hint: Optional[str] = None):
        """reg_hint: malloc size 参数所在寄存器 (默认: 自动从 instructions 推断)."""
        self._reg_hint = reg_hint
        self._stats: Dict[str, int] = {
            'total_attempted': 0, 'successfully_narrowed': 0,
            'tight_narrowing': 0, 'mild_narrowing': 0,
            'no_change': 0,
        }

    def narrow_alloc_size(self,
                          alloc_insn_addr: int,
                          size_interval: SInterval,
                          guards: List[PathGuard],
                          param_reg: str = 'rcx',
                          ) -> NarrowedValue:
        """窄化 malloc size 的值区间。

        参数: alloc_insn_addr malloc 调用指令的地址,
        size_interval backward_trace 得到的原始 size 区间,
        guards 从当前函数收集的所有路径守卫, param_reg size
        参数寄存器 (x64 Microsoft: rcx, SystemV: rdi);
        返回 NarrowedValue with original + narrowed intervals。
        """
        self._stats['total_attempted'] += 1

        # 查询 alloc site 附近的守卫
        nearby_guards = guards_for_insn(guards, alloc_insn_addr)

        # 提取与 param_reg 相关的守卫
        relevant = nearby_guards.get(param_reg, [])

        # 若 alloc 指令地址与 cmp 地址相差较远, 也尝试模糊匹配
        if not relevant:
            for g in guards:
                if g.reg == param_reg and g.fallthrough:
                    relevant.append(g)

        if not relevant:
            self._stats['no_change'] += 1
            return NarrowedValue(
                original=size_interval, narrowed=size_interval,
                guards_applied=[], narrowing_effect='none')

        # 应用守卫 intersection — 传入 alloc 地址做路径互斥判定
        narrowed = intersect_guards(param_reg, size_interval, relevant,
                                    insn_addr=alloc_insn_addr)

        # 判定窄化效果
        if narrowed.is_bot:
            # 守卫矛盾 → 保留原始区间 (保守)
            narrowed = size_interval
            effect = 'none'
        elif size_interval.is_top and not narrowed.is_top:
            if narrowed.hi <= 256:
                effect = 'tight'
                self._stats['tight_narrowing'] += 1
            else:
                effect = 'mild'
                self._stats['mild_narrowing'] += 1
        elif not size_interval.is_top and narrowed.hi < size_interval.hi:
            ratio = narrowed.hi / max(1, size_interval.hi)
            if ratio <= 0.5:
                effect = 'tight'
                self._stats['tight_narrowing'] += 1
            else:
                effect = 'mild'
                self._stats['mild_narrowing'] += 1
        else:
            effect = 'none'

        if effect != 'none':
            self._stats['successfully_narrowed'] += 1

        return NarrowedValue(
            original=size_interval,
            narrowed=narrowed,
            guards_applied=relevant,
            narrowing_effect=effect)

    def narrow_write_size(self,
                          write_insn_addr: int,
                          write_size_interval: SInterval,
                          guards: List[PathGuard],
                          size_reg: str = 'r8',
                          ) -> NarrowedValue:
        """窄化 memcpy/memset 的 size 参数区间.

        与 narrow_alloc_size 对称: 约束写入量, 用于证明"写入不超过分配量".
        """
        return self.narrow_alloc_size(
            write_insn_addr, write_size_interval, guards, size_reg)

    @property
    def stats(self) -> dict:
        d = dict(self._stats)
        total = max(1, d['total_attempted'])
        d['narrowing_rate'] = round(d['successfully_narrowed'] / total, 3)
        return d

    def clear(self) -> None:
        for k in self._stats:
            self._stats[k] = 0

def narrow_with_dual_regs(alloc_addr: int, interval: SInterval,
                          guards: List[PathGuard],
                          ) -> Tuple[NarrowedValue, str]:
    """双 ABI 守卫窄化: 同时对 rcx (MS x64) 和 rdi (System V) 尝试.

    返回 (更好的 NarrowedValue, 使用的寄存器名).
    """
    narrower = ValueRangeNarrower()
    rcx_nv = narrower.narrow_alloc_size(alloc_addr, interval, guards, 'rcx')
    rdi_nv = narrower.narrow_alloc_size(alloc_addr, interval, guards, 'rdi')

    # 选择窄化更紧的结果
    rcx_hi = rcx_nv.narrowed.max_possible()
    rdi_hi = rdi_nv.narrowed.max_possible()
    if rcx_hi < rdi_hi:
        return rcx_nv, 'rcx'
    else:
        return rdi_nv, 'rdi'
