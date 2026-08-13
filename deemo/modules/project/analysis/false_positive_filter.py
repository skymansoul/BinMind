# 误报过滤器: 多重证据链证明写入安全, 消除根源性误报
# 核心创新: 不仅比较写入量vs分配量, 而是通过四层递进证据证明安全:
#   L0: 分配器行为修正 — malloc(n)实际可用>n (size-class对齐)
#   L1: 结构体字段偏移 — 写入struct.field不溢出包含struct的分配
#   L2: 编译期常数传播 — 若写入量和分配量都是编译期常数, 直接判定
#   L3: 跨函数边界 — 调用者保证了参数合法性 (如snprintf的n参数)
# 与传统方法的区别: 模式匹配工具从不考虑这些因素,
#   因此在遇到 malloc(64)+memset(ptr, 0, 128) 这种模式时
#   一定报警. 本模块通过L0→L3递进证明, 只在无法证明安全时才报警.
#
#   Heelan et al. "Automatic Heap Layout Manipulation"
#     — 精确的堆分配器行为建模
#   Gershuni et al. "Simple and Precise Static Analysis of Untrusted
#     Linux Kernel Extensions" — 内核级别的保守分析
#   Arzt et al. "FlowDroid: Precise Context, Flow, Field, Object-sensitive
#     and Lifecycle-aware Taint Analysis"
#     — 多层精度递进的思想
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

from .value_range import ValueRange
from .heap_allocator_model import HeapAllocatorModel, AllocatorFamily


class FilterVerdict(Enum):
    KEEP = auto()           # 保留此发现 (非误报)
    FILTER_SAFE = auto()    # 可证明安全 → 过滤掉 (消除误报)
    FILTER_NOISE = auto()   # CRT/启动代码噪声 → 过滤掉
    DEMOTE = auto()         # 降级 (保持但降低严重性)


@dataclass
class FilterResult:
    """过滤判断结果."""
    verdict: FilterVerdict
    reason: str
    confidence: float = 1.0
    original_severity_change: Optional[str] = None  # e.g. "HIGH→MEDIUM"


class FalsePositiveFilter:
    """多层误报过滤器.

    设计原理: '递进证明' — 每层用一种独立的证据类型尝试证明安全.
    各层按精度从高到低排列, 高精度层命中后立即返回, 不再检查低精度层.
    层之间的独立性意味着: 即使某一层失效, 其他层仍然有效.
    """

    def __init__(self, allocator_model: Optional[HeapAllocatorModel] = None):
        self._alloc = allocator_model or HeapAllocatorModel(
            AllocatorFamily.GENERIC)
        # 过滤统计
        self._stats: Dict[str, int] = {
            'L0_allocator_corrected': 0,
            'L1_struct_offset_safe': 0,
            'L2_compile_time_safe': 0,
            'L3_cross_func_guarantee': 0,
            'noise_crt': 0,
            'total_checked': 0,
        }

    def check(self,
              write_size: ValueRange,
              write_offset: ValueRange,
              alloc_size: ValueRange,
              function_name: str = "",
              sink_func: str = "",
              alloc_func: str = "malloc",
              is_crt_context: bool = False,
              known_struct_offset: Optional[int] = None,
              ) -> FilterResult:
        """主过滤接口: 依次检查四层证据, 返回过滤判定.

        参数语义与 ConstraintSimplifier.check_heap_write 一致,
        额外添加:
          is_crt_context: 调用点是否在CRT启动代码中
          known_struct_offset: 若已知是结构体字段写入, 偏移量
        """
        self._stats['total_checked'] += 1

        # 0. CRT噪声过滤
        if is_crt_context:
            if write_size.is_top or write_size.umax > 0x10000:
                self._stats['noise_crt'] += 1
                return FilterResult(
                    FilterVerdict.FILTER_NOISE,
                    f"CRT噪声: {function_name}中的大写入({write_size.umax}B)是启动代码副作用")

        # 若信息不足 → 不应用任何过滤 (避免过度过滤导致漏报)
        if write_size.is_top or alloc_size.is_top:
            return FilterResult(FilterVerdict.KEEP, "值域信息不足, 保守不过滤")

        w_max = write_size.umax
        w_min = write_size.umin
        o_max = write_offset.umax if not write_offset.is_top else 0
        a_min = alloc_size.umin
        a_max = alloc_size.umax

# L0: 分配器行为修正
        # 使用真实分配器模型 (而非朴素的请求大小)
        # 这是消除 "malloc(50)+写60B→实际64B块→不应报警" 类误报的关键
        actual_usable = self._alloc.get_usable_size(a_min)
        safe_bound_l0 = max(0, actual_usable - o_max)
        if w_max <= safe_bound_l0 and actual_usable > a_min:
            self._stats['L0_allocator_corrected'] += 1
            return FilterResult(
                FilterVerdict.FILTER_SAFE,
                f"L0分配器修正: malloc({a_min})→实际可用{actual_usable}B "
                f"(+{actual_usable - a_min}B对齐空间), "
                f"写入{w_max}B(偏移{o_max})在{safe_bound_l0}B内",
                confidence=0.95)

# L1: 结构体字段偏移安全
        # 若写入的是结构体内部的字段, 且字段偏移+字段大小≤分配大小,
        # 则写入安全 (即使分配大小看起来小, 但整个结构体更大的分配已完成)
        if known_struct_offset is not None and o_max > 0:
            # 若写入从known_struct_offset开始, 写w_max, 且offset+w_max≤a_min,
            # 说明写入完全在结构体内部, 安全
            if known_struct_offset + w_max <= a_max:
                # 需要更严格: 偏移必须是确定值
                if write_offset.is_constant:
                    self._stats['L1_struct_offset_safe'] += 1
                    return FilterResult(
                        FilterVerdict.FILTER_SAFE,
                        f"L1结构体偏移: 写入偏移{o_max}(字段偏移)"
                        f"+写入{w_max}B≤分配{a_max}B, 结构体内写入安全",
                        confidence=0.90)

# L2: 编译期常数传播 → 精确比较
        # 若写入量和分配量都是编译期常数, 直接做整数比较
        # 这是最精确的情况 (不需要值域分析的近似)
        if write_size.is_constant and alloc_size.is_constant:
            exact_w = write_size.constant_value
            exact_a = alloc_size.constant_value
            if exact_w <= exact_a:
                self._stats['L2_compile_time_safe'] += 1
                return FilterResult(
                    FilterVerdict.FILTER_SAFE,
                    f"L2编译期常数: 写入{exact_w}B≤分配{exact_a}B, 确定安全",
                    confidence=0.99)
            # else: 精确溢出, 应保持HIGH/CRITICAL — 不在这层处理

# L3: 跨函数边界保证
        # 若sink是snprintf/strncpy等自带边界检查的函数,
        # 且写入大小参数是常数且在分配范围内 → 安全
        if sink_func in ('snprintf', 'strncpy', 'memccpy',
                         '__memcpy_chk', '__memmove_chk'):
            if w_max <= a_min:
                self._stats['L3_cross_func_guarantee'] += 1
                return FilterResult(
                    FilterVerdict.FILTER_SAFE,
                    f"L3边界保证: {sink_func}自带大小限制, "
                    f"写入{w_max}B≤分配{a_min}B",
                    confidence=0.85)

        # 无法证明安全 → 保留发现
        return FilterResult(FilterVerdict.KEEP, "无法在任一证据层证明安全, 保留")

    def check_demote(self,
                     write_size: ValueRange,
                     alloc_size: ValueRange,
                     is_input_controlled: bool) -> FilterResult:
        """检查是否应将严重性降级.

        即使无法完全过滤, 某些情况应降低严重性:
        - 分配器实际可用空间远大于请求量 → 溢出概率低
        - 写入量仅略微超出请求量 → 可能只是边界检查宽松
        """
        if write_size.is_top or alloc_size.is_top:
            return FilterResult(FilterVerdict.KEEP, "")

        a_min = alloc_size.umin
        actual = self._alloc.get_usable_size(a_min)
        w_max = write_size.umax

        # 若实际可用空间≥写入量, 但L0层触发了其他条件 → 降级
        if w_max <= actual and actual > a_min:
            return FilterResult(
                FilterVerdict.DEMOTE,
                f"分配器提供了足够空间 (请求{a_min}B→实际{actual}B≥写入{w_max}B)",
                original_severity_change="→MEDIUM")

        return FilterResult(FilterVerdict.KEEP, "")

    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    def reset_stats(self):
        for k in self._stats:
            self._stats[k] = 0
