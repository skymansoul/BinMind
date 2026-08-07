# analysis/allocator_slack — FC-VRA 阶段C2: 分配器松弛的区间化建模
# 核心创新点: 将 heap_layout_model 的"常量请求→对齐后可用空间"扩展到
# 区间请求 [lo, hi] → 可用空间区间 [usable_lo, usable_hi]。
# 现有 HLM (heap_layout_model) 仅对 alloc_range.is_const 生效,
# 一旦分配量是变量区间 (如 n 字节, n∈[16,4096]) 便退化,
# 导致大量本可判安全的区间被保留为告警 — 误报。
#
# 核心关系:
#   可用下界 = usable_size_min(alloc_lo)   — 请求最小时实际可用的最小值
#   可用上界 = usable_size_max(alloc_hi)   — 请求最大时含切分余量的最大值
# 安全判定 (保守): write_hi ≤ usable_lo ⇒ 必然不溢出
# 危险判定 (保守): write_lo > usable_hi ⇒ 必然溢出
# 其余 → 不确定, 交下游 (守卫/污点) 裁决。
#
# 对齐语义参照 glibc checked_request2size, 与值域分析的区间运算结合。

from __future__ import annotations
from typing import Tuple
from value_range_analyzer import ValueRange
from heap_layout_model import get_allocator_model

def usable_range_for_alloc(alloc_lo: float, alloc_hi: float,
                           arch: str = "x86_64") -> Tuple[float, float]:
    """分配请求区间 [alloc_lo, alloc_hi] → 可用用户空间区间。

    返回 (usable_lo, usable_hi)。∞ 表示无法上界 (未对齐模型不适用)。
    """
    model = get_allocator_model(arch)
    if alloc_lo == float("-inf"):
        # 下界未知: 无法给出可用下界 → 退回 top
        usable_lo = float("-inf")
    else:
        usable_lo = float(model.usable_size_min(max(int(alloc_lo), 0)))

    if alloc_hi == float("inf"):
        usable_hi = float("inf")
    else:
        usable_hi = float(model.usable_size_max(max(int(alloc_hi), 0)))
    return usable_lo, usable_hi

def verdict_with_slack(
    alloc_range: ValueRange, write_range: ValueRange,
    arch: str = "x86_64",
) -> Tuple[bool, float, str]:
    """区间化的对齐感知判定。

    返回: (is_overflow, confidence, reason)
    confidence >0.5 → 倾向溢出; <0.15 → 倾向安全。
    """
    if alloc_range.is_bottom or write_range.is_bottom:
        return (False, 0.05, "约束冲突→路径不可达")
    if alloc_range.is_top and write_range.is_top:
        return (False, 0.30, "双方未知→无法判定")

    # 双方皆常量的精确路径委托原 HLM (避免行为回归)
    if alloc_range.is_const and write_range.is_const:
        model = get_allocator_model(arch)
        ov, conf, reason = model.check_overflow_under_alignment(
            alloc_range.const_value, write_range.const_value)
        return (ov, conf, reason)

    usable_lo, usable_hi = usable_range_for_alloc(
        alloc_range.lo, alloc_range.hi, arch)

    wlo, whi = write_range.lo, write_range.hi

    # 必然安全: 写入上限 ≤ 可用下界
    if whi != float("inf") and usable_lo != float("-inf") and whi <= usable_lo:
        return (False, 0.04,
                f"write≤{int(whi)}B ≤ 可用下界{int(usable_lo)}B"
                f"(alloc[{alloc_range}]→slack)→安全")
    # 必然溢出: 写入下界 > 可用上界
    if wlo != float("inf") and usable_hi != float("inf") and wlo > usable_hi:
        return (True, 0.90,
                f"write≥{int(wlo)}B > 可用上界{int(usable_hi)}B"
                f"(alloc[{alloc_range}])→溢出")
    # 保守可安全: 写入上限 ≤ 可用上界且写入下界 ≤ 可用下界 → 部分重叠
    if (whi != float("inf") and usable_hi != float("inf")
            and whi <= usable_hi and wlo <= usable_lo):
        return (False, 0.12,
                f"write[{wlo},{whi}] 与 slack 区间部分重叠→低置信安全")
    if write_range.is_top:
        return (True, 0.50, f"写入量未知, 分配={alloc_range}→保守可疑")
    if alloc_range.is_top:
        return (False, 0.35, "分配大小未知→保守安全")
    return (False, 0.30,
            f"区间交叠方向不明: alloc={alloc_range} write={write_range}")

if __name__ == "__main__":
    t = [("malloc(64)+write(128)", ValueRange.const(64), ValueRange.const(128)),
         ("malloc(16..64)+write(≤32)", ValueRange(16, 64), ValueRange(0, 32)),
         ("malloc(≤64)+write(>112)", ValueRange(0, 64), ValueRange(113, 256)),
         ("malloc(≤64)+write(∞)", ValueRange(0, 64), ValueRange.top())]
    for name, ar, wr in t:
        print(name, "→", verdict_with_slack(ar, wr))
