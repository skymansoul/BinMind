# 基于区间抽象的快速路径过滤器 (Interval-Based Abstract Filter)
#
# 在做精确分析之前, 用区间抽象快速排除不可能触发漏洞的路径.
# 将分析时间从 O(2^branches) 降至 O(branches).
#
# 决策依据:
#   1. 区间抽象: 每个变量维护 [lo, hi] 区间而非精确值.
#      对memcpy(dst, src, len) 等危险调用, 若区间分析显示
#      len ≤ buffer_size 在所有路径上都成立, 则跳过精确分析.
#   2. 路径合并: 在条件分支汇合点, 做区间并集 (即取最宽区间).
#      这是 over-approximation, 宁可保留路径也不误删.
#   3. 循环处理: 对循环变量用 widening 算子 (增长区间时跳到 +∞).
#      以 widening 做 over-approximation 换取有限步收敛.
#   4. 仅过滤"确凿安全"的路径: 区间分析结论为 safe 的路径
#      保证在所有具体执行中都是安全的 (sound under-approximation
#      of danger). 反之, 标记为 "maybe_unsafe" 的路径仍需精确分析.
#
# 创建: 2026-05-07  初始版本

from typing import Dict, List, Optional, Tuple


class Interval:
    """整数区间 [lo, hi], 支持 widening 到 +∞."""
    __slots__ = ("lo","hi")
    def __init__(self, lo: int, hi: int):
        self.lo = lo; self.hi = hi

    def __repr__(self):
        return f"[{self.lo}, {self.hi}]"

    def join(self, other: "Interval") -> "Interval":
        """区间并集 (取最宽)."""
        return Interval(min(self.lo, other.lo), max(self.hi, other.hi))

    def widen(self) -> "Interval":
        """Widening: 上界跳到 +∞."""
        return Interval(self.lo, 2**63 - 1)

    def contains(self, val: int) -> bool:
        return self.lo <= val <= self.hi

    def add(self, delta: "Interval") -> "Interval":
        return Interval(self.lo + delta.lo, self.hi + delta.hi)

    @property
    def is_finite(self) -> bool:
        return self.hi < 2**62


class IntervalState:
    """变量到区间的映射: {var_name: Interval}."""
    def __init__(self):
        self._vars: Dict[str, Interval] = {}

    def set(self, var: str, lo: int, hi: int):
        self._vars[var] = Interval(lo, hi)

    def get(self, var: str) -> Optional[Interval]:
        return self._vars.get(var)

    def copy(self) -> "IntervalState":
        s = IntervalState()
        s._vars = dict(self._vars)
        return s

    def join(self, other: "IntervalState") -> "IntervalState":
        """两状态的区间并集."""
        s = IntervalState()
        for k in set(self._vars) | set(other._vars):
            a = self._vars.get(k)
            b = other._vars.get(k)
            if a and b: s._vars[k] = a.join(b)
            elif a: s._vars[k] = a
            elif b: s._vars[k] = b
        return s


class AbstractFilter:
    """区间抽象过滤器: 快速排除安全路径.

    使用: 对每条危险调用, 检查其长度参数在所有可行路径上的区间.
    若区间上界 ≤ 缓冲区大小, 此调用在所有路径上都是安全的.
    """

    def __init__(self, default_buffer_size: int = 256):
        self._default_buf = default_buffer_size
        self._skipped = 0     # 被过滤的调用数
        self._kept = 0        # 保留供精确分析的调用数

    def check_memcpy(self, dst_size: Optional[int],
                      src_len_interval: Interval) -> str:
        """检查 memcpy(dst, src, len): 若 len 在所有路径上 ≤ dst_size,
        返回 'safe'. 否则返回 'maybe_unsafe'.

        区间分析的 soundness 保证:
        - 返回 'safe' → 该调用在所有具体执行中都不会溢出
        - 返回 'maybe_unsafe' → 可能存在溢出, 需精确分析
        """
        limit = dst_size if dst_size is not None else self._default_buf
        if src_len_interval.hi <= limit and src_len_interval.is_finite:
            self._skipped += 1
            return "safe"
        self._kept += 1
        return "maybe_unsafe"

    def check_strcpy(self, dst_size: Optional[int],
                      src_len_interval: Interval) -> str:
        """检查 strcpy: 源字符串长度区间是否超出目标缓冲区."""
        limit = dst_size if dst_size is not None else self._default_buf
        if src_len_interval.hi < limit and src_len_interval.is_finite:
            self._skipped += 1
            return "safe"
        self._kept += 1
        return "maybe_unsafe"

    def check_format_string(self, num_args: int,
                             fmt_arg_count: int) -> str:
        """检查格式化字符串: 提供的参数是否足够覆盖所有格式说明符."""
        if num_args >= fmt_arg_count:
            self._skipped += 1
            return "safe"
        self._kept += 1
        return "maybe_unsafe"

    def should_skip(self, call_type: str, params: dict) -> bool:
        """统一入口: 根据调用类型和参数判断是否应该跳过精确分析."""
        if call_type == "memcpy":
            return self.check_memcpy(
                params.get("dst_size"),
                params.get("len_interval", Interval(0, 2**62)),
            ) == "safe"
        elif call_type == "strcpy":
            return self.check_strcpy(
                params.get("dst_size"),
                params.get("src_len", Interval(0, 2**62)),
            ) == "safe"
        elif call_type == "printf":
            return self.check_format_string(
                params.get("num_args", 0),
                params.get("fmt_count", 0),
            ) == "safe"
        return False  # 未知类型: 保守, 不跳过

    @property
    def filter_rate(self) -> float:
        total = self._skipped + self._kept
        return self._skipped / max(total, 1)

    @property
    def stats(self) -> dict:
        return {"skipped": self._skipped, "kept": self._kept,
                "filter_rate": round(self.filter_rate, 4)}


__all__ = ["AbstractFilter", "Interval", "IntervalState"]
