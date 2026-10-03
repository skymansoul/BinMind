# analysis/value_range_analyzer — 抽象值范围传播引擎
# 从源代码或反编译伪代码中提取变量的 min/max 范围,
# 并沿着赋值、算术运算、函数调用进行区间传播。
# 区间抽象域在内存操作验证中有完备性权衡; 值流追踪是降低堆溢出误报的核心。
# 不与全符号执行竞争, 而是用粗略但快速的区间推导
#     筛掉"绝对不会溢出"的情况, 缩小符号执行需要验证的范围
#
# 设计决策:
#   - 使用 affine 区间 [lo, hi] 而非 full polyhedra: 避免 O(n^3) 复杂度
#   - stride 信息 (模对齐) 保留为扩展点, 当前仅用 lo/hi
#   - 乘法退化为 widest-need: 两区间相乘时取最宽结果, 宁可漏报不误报

from __future__ import annotations
from typing import Dict, List, Optional, Tuple
import re
import math

class ValueRange:
    """仿射区间抽象域 [lo, hi]; ±inf 表示无界; bottom 表示空集。"""

    __slots__ = ("lo", "hi", "is_bottom")

    def __init__(self, lo: float = float("-inf"), hi: float = float("inf"),
                 is_bottom: bool = False):
        self.lo = float(lo)
        self.hi = float(hi)
        self.is_bottom = is_bottom
        if self.lo > self.hi and not self.is_bottom:
            self.is_bottom = True

    def __repr__(self) -> str:
        if self.is_bottom: return "⊥"
        if self.lo == float("-inf") and self.hi == float("inf"): return "⊤"
        return f"[{self._f(self.lo)}, {self._f(self.hi)}]"

    @staticmethod
    def _f(v: float) -> str:
        if v == float("inf"): return "+∞"
        if v == float("-inf"): return "-∞"
        return str(int(v)) if v == int(v) else f"{v:.1f}"

    @staticmethod
    def const(v: int) -> "ValueRange": return ValueRange(v, v)

    @staticmethod
    def top() -> "ValueRange": return ValueRange()

    @staticmethod
    def bottom() -> "ValueRange": return ValueRange(is_bottom=True)

    @property
    def is_top(self) -> bool:
        return not self.is_bottom and self.lo == float("-inf") and self.hi == float("inf")

    @property
    def is_const(self) -> bool:
        return not self.is_bottom and self.lo == self.hi and abs(self.lo) != float("inf")

    @property
    def const_value(self) -> Optional[int]:
        return int(self.lo) if self.is_const else None

    def add(self, o: "ValueRange") -> "ValueRange":
        if self.is_bottom or o.is_bottom: return ValueRange.bottom()
        if self.is_top or o.is_top: return ValueRange.top()
        return ValueRange(self.lo + o.lo, self.hi + o.hi)

    def sub(self, o: "ValueRange") -> "ValueRange":
        if self.is_bottom or o.is_bottom: return ValueRange.bottom()
        if self.is_top or o.is_top: return ValueRange.top()
        return ValueRange(self.lo - o.hi, self.hi - o.lo)

    def mul(self, o: "ValueRange") -> "ValueRange":
        if self.is_bottom or o.is_bottom: return ValueRange.bottom()
        if self.is_top or o.is_top: return ValueRange.top()
        b = [self.lo * o.lo, self.lo * o.hi, self.hi * o.lo, self.hi * o.hi]
        return ValueRange(min(b), max(b))

    def join(self, o: "ValueRange") -> "ValueRange":
        if self.is_bottom: return o
        if o.is_bottom: return self
        return ValueRange(min(self.lo, o.lo), max(self.hi, o.hi))

    def meet(self, o: "ValueRange") -> "ValueRange":
        if self.is_bottom or o.is_bottom: return ValueRange.bottom()
        lo, hi = max(self.lo, o.lo), min(self.hi, o.hi)
        return ValueRange.bottom() if lo > hi else ValueRange(lo, hi)

    def widen_to(self, o: "ValueRange") -> "ValueRange":
        """经典的 widening with threshold: 扩展到新边界或跳至 inf。"""
        if self.is_bottom: return o
        if o.is_bottom: return self
        nl = o.lo if o.lo < self.lo else (float("-inf") if o.lo < self.lo - 1024 else self.lo)
        nh = o.hi if o.hi > self.hi else (float("inf") if o.hi > self.hi + 1024 else self.hi)
        return ValueRange(nl, nh)

def extract_value_ranges(code: str) -> Dict[str, ValueRange]:
    """从 C 源码提取变量值范围。识别: #define/常量赋值/算术运算/malloc/strlen。"""
    ranges: Dict[str, ValueRange] = {}
    sizeof_map = {"char": 1, "short": 2, "int": 4, "long": 4, "long long": 8,
                  "float": 4, "double": 8, "void*": 4, "size_t": 4,
                  "void *": 4, "char*": 4, "int*": 4, "struct": 8}

# define MACRO VALUE
    for m in re.finditer(r"#define\s+(\w+)\s+(\d+)\b", code):
        ranges[m.group(1)] = ValueRange.const(int(m.group(2)))

    # int x = N / unsigned x = N / size_t x = N;
    for m in re.finditer(r"\b(?:int|unsigned|size_t|uint\d+_t|u?int\d+_t)\s+(\w+)\s*=\s*(\d+)\s*;", code):
        ranges[m.group(1)] = ValueRange.const(int(m.group(2)))

    # x = N; (N 为数字)
    for m in re.finditer(r"(\w+)\s*=\s*(\d+)\s*;", code):
        if m.group(1) not in ranges:
            ranges[m.group(1)] = ValueRange.const(int(m.group(2)))

    # x = y * sizeof(T)
    for m in re.finditer(r"(\w+)\s*=\s*(\w+)\s*\*\s*sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)\s*;", code):
        rv = ranges.get(m.group(2), ValueRange.top())
        ranges[m.group(1)] = rv.mul(ValueRange.const(sizeof_map.get(m.group(3).strip(), 4)))

    # x = y + z / x = y - z / x = y * z;
    for m in re.finditer(r"(\w+)\s*=\s*(\w+)\s*([+\-*])\s*(\w+)\s*;", code):
        ra = ranges.get(m.group(2), ValueRange.top())
        rb = ranges.get(m.group(4), ValueRange.top())
        op = m.group(3)
        ranges[m.group(1)] = ra.add(rb) if op == "+" else (ra.sub(rb) if op == "-" else ra.mul(rb))

    # x = y; (变量复制)
    for m in re.finditer(r"(\w+)\s*=\s*(\w+)\s*;", code):
        if m.group(1) not in ranges and m.group(2) in ranges:
            ranges[m.group(1)] = ranges[m.group(2)]

    # atoi(argv[n]) / (cast)atoi(argv[n]) → unbounded
    for m in re.finditer(r"(\w+)\s*=\s*(?:\(\s*\w+(?:\s*\*)?\s*\)\s*)?atoi\s*\(\s*argv\s*\[", code):
        ranges[m.group(1)] = ValueRange.top()

    # malloc/calloc/realloc: 处理变量名/宏名/数字字面量/乘法表达式
    for m in re.finditer(
        r"(?:malloc|calloc|realloc)\s*\(\s*(\w+(?:\s*\*\s*\w+)?)\s*\)", code):
        arg = m.group(1).strip()
        if "*" in arg:
            parts = [p.strip() for p in arg.split("*")]
            ra = _parse_arg(parts[0], ranges)
            rb = _parse_arg(parts[1], ranges) if len(parts) > 1 else ValueRange.const(1)
            ranges["__malloc_size__"] = ra.mul(rb)
        else:
            ranges["__malloc_size__"] = _parse_arg(arg, ranges)

    # recv/read/fread 返回值 → [0, +∞)
    for m in re.finditer(r"(\w+)\s*=\s*(?:recv|read|fread)\s*\(", code):
        ranges[m.group(1)] = ValueRange(0, float("inf"))

    # strlen → [0, 65536]
    # TODO: 三目表达式与函数返回值未纳入区间建模, 守卫钳制场景依赖 guard_dominance 兜底
    for m in re.finditer(r"(\w+)\s*=\s*strlen\s*\(\s*(\w+)\s*\)", code):
        ranges[m.group(1)] = ValueRange(0, 65536)

    return ranges

def _parse_arg(arg: str, ranges: Dict[str, ValueRange]) -> ValueRange:
    """将 malloc/memcpy 的参数文本解析为 ValueRange:
    支持: 数字字面量 / #define 宏 / 已知变量 / sizeof 表达式。"""
    try:
        return ValueRange.const(int(arg))
    except ValueError:
        pass
    if arg in ranges:
        return ranges[arg]
    return ValueRange.top()

def apply_constraint(ranges: Dict[str, ValueRange], var: str,
                     op: str, value: int) -> Dict[str, ValueRange]:
    """应用数值约束 (来源: if/while 条件)。op ∈ {lt, le, gt, ge, eq, ne}。"""
    result = dict(ranges)
    if var not in result: return result
    rv = result[var]
    if rv.is_bottom or rv.is_top: return result
    _map = {"lt": (float("-inf"), value - 1), "le": (float("-inf"), value),
            "gt": (value + 1, float("inf")), "ge": (value, float("inf")),
            "eq": (value, value)}
    if op in _map:
        result[var] = rv.meet(ValueRange(_map[op][0], _map[op][1]))
    return result

def range_to_size_class(r: ValueRange, alloc_hint: Optional[int] = None) -> str:
    """值范围→堆溢出风险类别: SAFE_BOUNDED / POSSIBLE_OVERFLOW / UNCERTAIN。"""
    if r.is_bottom or r.is_top: return "UNCERTAIN"
    if alloc_hint is not None and r.hi <= alloc_hint: return "SAFE_BOUNDED"
    return "POSSIBLE_OVERFLOW"

def check_heap_overflow_by_range(
    alloc_range: ValueRange, write_range: ValueRange,
    alignment: int = 16, min_chunk_size: int = 32,
) -> Tuple[bool, float, str]:
    """核心判定: 分配范围 vs 写入范围 → (是否溢出, 置信度, 原因)。"""
    if alloc_range.is_bottom or write_range.is_bottom:
        return (False, 0.05, "约束冲突→路径不可达")
    if alloc_range.is_top and write_range.is_top:
        return (False, 0.30, "双方范围均未知→无法判定")
    # alloc > write 且差值 ≥ alignment → 安全
    if (not alloc_range.is_top and not write_range.is_top and
            alloc_range.lo > write_range.hi + alignment):
        return (False, 0.02, f"alloc({alloc_range})≫write({write_range})→安全余量充足")
    # alloc.lo >= write.hi → malloc对齐补足
    if (not alloc_range.is_top and not write_range.is_top and
            alloc_range.lo >= write_range.hi):
        return (False, 0.08, f"alloc({alloc_range})≥write({write_range})→对齐补足→安全")
    # alloc.hi < write.lo → 明确溢出
    if (not alloc_range.is_top and not write_range.is_top and
            alloc_range.hi < write_range.lo):
        return (True, 0.92, f"alloc({alloc_range})<write({write_range})→明确溢出")
    # 范围重叠 → 部分溢出
    if (not alloc_range.is_top and not write_range.is_top and
            alloc_range.lo < write_range.lo <= alloc_range.hi < write_range.hi):
        return (True, 0.65, f"alloc({alloc_range})与write({write_range})重叠→可能溢出")
    if alloc_range.is_top:
        return (False, 0.35, "分配大小未知→保守安全")
    if write_range.is_top:
        return (True, 0.50, f"写入量未知,分配={alloc_range}→保守可疑")
    return (False, 0.25, f"范围重叠方向不明: alloc={alloc_range} write={write_range}")

def compute_effective_alloc_size(requested: int, alignment: int = 16,
                                  min_chunk: int = 32) -> int:
    """glibc malloc 有效用户可用空间: align_up(max(request, min_user), alignment)。
    x86_64: min_user=16, alignment=16; i386: min_user=8, alignment=8。"""
    min_user = min_chunk - 16  # MINSIZE - 2*SIZE_SZ
    return ((max(requested, min_user) + alignment - 1) // alignment) * alignment
