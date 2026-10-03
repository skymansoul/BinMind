# I-GUARD — 整数溢出三阶段检测 (符号阈值 + 值域传播守卫窄化 + 循环归纳).
#
# 决策逻辑:
#   阶段1 符号阈值: 提取 var = operand * constant (含 sizeof) 乘积,
#     阈值 threshold = SIZE_MAX / constant, 超过即溢出.
#     乘积链图 (ProductChainGraph) worklist 传播到 fixpoint, 覆盖
#     a=b*4; c=a+8; d=c*2 的非平凡链.
#   阶段2 值域传播: 正向区间传播 + 守卫窄化 (refine_by_guard) +
#     Abort 守卫 (if(a*b<a) abort / __builtin_*_overflow) +
#     Domain 窄化 (无符号回绕为定义行为).
#   阶段3 循环归纳: Cousot 式 widening/narrowing —
#     基础归纳变量 i=i±stride, 循环头 widening 到 bound,
#     累积器 sum+=val 的溢出风险 sum ∈ [init, init+iters*per_iter].
#   保守: 不能证明安全→保留.
#
#   本文件实现 I-GUARD 核心管线: 符号化辅助 → 符号化阈值 → 乘积链图
#   → 值域传播验证 → 循环归纳.


from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


# 符号化辅助

_SIZEOF_MAP = {
    'int': 4, 'unsigned': 4, 'unsigned int': 4, 'uint32_t': 4,
    'long': 8, 'unsigned long': 8, 'uint64_t': 8,
    'size_t': 8, 'ssize_t': 8, 'ptrdiff_t': 8,
    'short': 2, 'unsigned short': 2, 'uint16_t': 2,
    'char': 1, 'unsigned char': 1, 'uint8_t': 1,
    'float': 4, 'double': 8,
    'void*': 8, 'char*': 8, 'int*': 8,
    'long long': 8, 'unsigned long long': 8,
    '__int128': 16, '__uint128_t': 16,
}

_SIZEMAX = {
    'x86': 0xFFFFFFFF,
    'x86_64': 0xFFFFFFFFFFFFFFFF,
    'arm32': 0xFFFFFFFF,
    'aarch64': 0xFFFFFFFFFFFFFFFF,
    'mips32': 0xFFFFFFFF,
    'default': 0xFFFFFFFFFFFFFFFF,
}


def find_overflow_guards(source: str, operand_var: str,
                         threshold: int) -> List[str]:
    """查找针对 operand_var 的溢出守卫.
    模式: if(var > SIZE_MAX/sizeof) / __builtin_mul_overflow / if(var > MAX/C)
    """
    guards = []
    guard1 = re.compile(
        rf'if\s*\(\s*{re.escape(operand_var)}\s*[><=]+\s*(\d+)\s*\)',
        re.IGNORECASE)
    guard2 = re.compile(
        r'__builtin_(?:[su])?mul[l]?_overflow\s*\(', re.IGNORECASE)
    guard3 = re.compile(
        rf'if\s*\(\s*{re.escape(operand_var)}\s*>\s*\w*MAX\s*/\s*(\w+)',
        re.IGNORECASE)

    for i, line in enumerate(source.splitlines()):
        m1 = guard1.search(line)
        if m1 and int(m1.group(1)) <= threshold:
            guards.append(f"line {i}: {line.strip()[:80]}")
        if guard2.search(line):
            guards.append(f"line {i}: __builtin_mul_overflow guard")
        if guard3.search(line):
            guards.append(f"line {i}: {line.strip()[:80]}")
    return guards


def infer_var_range(source: str, var: str, platform: str) -> Tuple[int, int]:
    """从源码推断变量的可能范围 [lo, hi]."""
    lo, hi = 0, -1  # -1 = unknown

    if re.search(rf'{re.escape(var)}\s*=\s*atoi', source):
        hi = 0x7FFFFFFF
    elif re.search(rf'{re.escape(var)}\s*=\s*strtol', source):
        hi = 0x7FFFFFFFFFFFFFFF if '64' in platform else 0x7FFFFFFF
    elif re.search(rf'{re.escape(var)}\s*=\s*ato[lf]', source):
        hi = 0x7FFFFFFFFFFFFFFF

    m = re.search(rf'{re.escape(var)}\s*=\s*(\d+)\s*;', source)
    if m:
        lo = hi = int(m.group(1))

    for m in re.finditer(
            rf'if\s*\(\s*{re.escape(var)}\s*<\s*(\d+)\s*\)', source):
        hi = min(hi, int(m.group(1)) - 1) if hi >= 0 else int(m.group(1)) - 1
    for m in re.finditer(
            rf'if\s*\(\s*{re.escape(var)}\s*>\s*(\d+)\s*\)', source):
        lo = max(lo, int(m.group(1)) + 1)
    return lo, hi


def _is_user_controlled(source: str, var: str) -> bool:
    """判断变量是否用户可控 (atoi/strtol/argv/fgets/recv/read/getenv)."""
    patterns = [
        rf'{re.escape(var)}\s*=\s*atoi', rf'{re.escape(var)}\s*=\s*strtol',
        rf'{re.escape(var)}\s*=\s*argv', rf'fgets\s*\([^)]*{re.escape(var)}',
        rf'recv\s*\([^)]*{re.escape(var)}', rf'read\s*\([^)]*{re.escape(var)}',
        rf'getenv\s*\(.*{re.escape(var)}',
    ]
    return any(re.search(p, source) for p in patterns)


def _has_length_check(source: str, var: str) -> bool:
    """检查是否有针对 var 的边界检查."""
    return bool(re.search(
        rf'if\s*\(\s*{re.escape(var)}\s*[><=]+', source))


def assess_overflow(operand_var: str, threshold: int,
                    guards: List[str], var_lo: int, var_hi: int,
                    source: str) -> Tuple[str, float]:
    """综合判定溢出风险. 保守: 不能证明安全→保留."""
    if guards:
        return "SAFE", 0.15
    if var_hi >= 0 and var_hi <= threshold:
        return "SAFE", 0.20
    if var_lo > threshold:
        return "OVERFLOW", 0.90
    if _is_user_controlled(source, operand_var):
        if _has_length_check(source, operand_var):
            return "LIKELY_OVERFLOW", 0.50
        return "OVERFLOW", 0.80
    return "UNCERTAIN", 0.40


def is_in_alloc_context(source: str, var: str, line_no: int) -> bool:
    """检查 var 是否在分配上下文中使用 (后续5行内有 malloc(var))."""
    lines = source.splitlines()
    for i in range(line_no, min(line_no + 5, len(lines))):
        if re.search(rf'(?:malloc|calloc|realloc)\s*\(\s*{re.escape(var)}',
                     lines[i]):
            return True
    return False


# 符号化阈值

@dataclass
class SymbolicProduct:
    """符号化乘法表达式: result = var * constant."""
    result_var: str           # 结果变量名 (如 alloc_size)
    operand_var: str          # 符号变量 (如 count)
    constant: int             # 常量因子 (如 sizeof(int) = 4)
    line_no: int = 0


@dataclass
class OverflowThreshold:
    """溢出阈值分析结果."""
    product: SymbolicProduct
    threshold: int            # SIZE_MAX / constant → 超过此值则溢出
    size_max: int             # 使用的 SIZE_MAX
    var_range_lo: int = 0     # 符号变量的当前下界
    var_range_hi: int = -1    # 符号变量的当前上界 (-1 = 未知)
    is_guarded: bool = False  # 是否有显式溢出守卫
    guard_condition: str = ""  # 守卫条件描述
    verdict: str = ""         # SAFE | LIKELY_OVERFLOW | OVERFLOW | UNCERTAIN
    confidence: float = 0.5


class IntOverflowSymbolicAnalyzer:
    """整数溢出符号化分析器: 符号化乘积追踪 + 溢出阈值分析."""

    def __init__(self, platform: str = "x86_64"):
        self._platform = platform
        self._size_max = _SIZEMAX.get(platform, _SIZEMAX['default'])

    def analyze_mul_overflow(
        self, source_code: str, func_name: str = "",
    ) -> List[OverflowThreshold]:
        """分析源码中所有乘法溢出风险."""
        results = []
        products = self._extract_symbolic_products(source_code)

        for sp in products:
            threshold = self._compute_threshold(sp)
            guards = find_overflow_guards(source_code, sp.operand_var,
                                          threshold)
            var_lo, var_hi = infer_var_range(source_code, sp.operand_var,
                                             self._platform)
            verdict, confidence = assess_overflow(
                sp.operand_var, threshold, guards, var_lo, var_hi,
                source_code)

            results.append(OverflowThreshold(
                product=sp, threshold=threshold, size_max=self._size_max,
                var_range_lo=var_lo, var_range_hi=var_hi,
                is_guarded=len(guards) > 0,
                guard_condition="; ".join(guards) if guards else "",
                verdict=verdict, confidence=confidence,
            ))

        return results

    def _extract_symbolic_products(self, source: str) -> List[SymbolicProduct]:
        """提取所有 'var = operand * constant' 形式的乘法表达式."""
        products = []
        sz_pat = re.compile(
            r'(\w+)\s*=\s*(\w+)\s*\*\s*sizeof\s*\(\s*(\w+(?:\s*\*)?)\s*\)'
            r'|(\w+)\s*=\s*sizeof\s*\(\s*(\w+(?:\s*\*)?)\s*\)\s*\*\s*(\w+)',
            re.IGNORECASE)

        for i, line in enumerate(source.splitlines()):
            for m in sz_pat.finditer(line):
                if m.group(1):
                    result_var, operand_var = m.group(1), m.group(2)
                    type_name = m.group(3).strip()
                else:
                    result_var, operand_var = m.group(4), m.group(6)
                    type_name = m.group(5).strip()

                elem_size = _SIZEOF_MAP.get(type_name.lower(), 0)
                if elem_size > 0 and operand_var not in ('argc',):
                    products.append(SymbolicProduct(
                        result_var=result_var, operand_var=operand_var,
                        constant=elem_size, line_no=i))

        # var = a * CONST (非sizeof形式)
        const_mul_pat = re.compile(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\d+)\s*;?$')
        for i, line in enumerate(source.splitlines()):
            for m in const_mul_pat.finditer(line):
                result_var, operand_var = m.group(1), m.group(2)
                const_val = int(m.group(3))
                if is_in_alloc_context(source, result_var, i):
                    products.append(SymbolicProduct(
                        result_var=result_var, operand_var=operand_var,
                        constant=const_val, line_no=i))

        return products

    def _compute_threshold(self, sp: SymbolicProduct) -> int:
        """溢出阈值: SIZE_MAX / constant. 超过此值则 product 溢出."""
        if sp.constant == 0:
            return self._size_max
        return self._size_max // sp.constant


def analyze_int_overflow_symbolic(
    source_code: str, platform: str = "x86_64",
) -> List[OverflowThreshold]:
    analyzer = IntOverflowSymbolicAnalyzer(platform)
    return analyzer.analyze_mul_overflow(source_code)


# 乘积链图

@dataclass
class ProductEdge:
    """乘积图中的边: var = other * const (或 other = var * const)."""
    src: str          # 源变量
    dst: str          # 目标变量
    multiplier: int   # 乘数因子
    line_no: int = 0


class ProductChainGraph:
    """构建变量间的乘法依赖图, 用于 worklist 传播溢出约束."""

    def __init__(self):
        self._adj: Dict[str, List[ProductEdge]] = {}
        self._rev: Dict[str, List[ProductEdge]] = {}
        self._nodes: Set[str] = set()

    def add_edge(self, src: str, dst: str, multiplier: int, line: int = 0):
        """添加乘积边: dst = src * multiplier."""
        e = ProductEdge(src=src, dst=dst, multiplier=multiplier, line_no=line)
        self._adj.setdefault(src, []).append(e)
        self._rev.setdefault(dst, []).append(e)
        self._nodes.add(src)
        self._nodes.add(dst)

    def build_from_source(self, source: str) -> 'ProductChainGraph':
        """从源码构建乘积链图 (识别 a = b * k 模式)."""
        lines = source.splitlines()
        mul_re = re.compile(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\d+)\s*;?')
        sz_re = re.compile(
            r'(\w+)\s*=\s*(\w+)\s*\*\s*sizeof\s*\(\s*(\w+(?:\s*\*)?)\s*\)',
            re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            for m in mul_re.finditer(line):
                dst, src, k = m.group(1), m.group(2), int(m.group(3))
                self.add_edge(src, dst, k, i)
            for m in sz_re.finditer(line):
                dst, src, tp = m.group(1), m.group(2), m.group(3).strip()
                k = _SIZEOF_MAP.get(tp.lower(), 0)
                if k > 0:
                    self.add_edge(src, dst, k, i)
        return self

    def sources(self) -> Set[str]:
        """入度为0的源变量 (外部输入)."""
        return {n for n in self._nodes
                if n not in self._rev or len(self._rev.get(n, [])) == 0}

    def sinks(self) -> Set[str]:
        """出度为0的汇变量 (最终分配)."""
        return {n for n in self._nodes
                if n not in self._adj or len(self._adj.get(n, [])) == 0}

    def predecessors(self, var: str) -> List[ProductEdge]:
        return self._rev.get(var, [])

    def successors(self, var: str) -> List[ProductEdge]:
        return self._adj.get(var, [])

    def __contains__(self, var: str) -> bool:
        return var in self._nodes

    def __len__(self) -> int:
        return len(self._nodes)


class ProductChainPropagator:
    """Worklist-based constraint propagation over ProductChainGraph.

    Propagation: if a ∈ [lo_a, hi_a] and b = a * k,
    then b ∈ [lo_a * k, hi_a * k] (monitor for wrap-around).
    """

    def __init__(self, graph: ProductChainGraph,
                 size_max: int = 0xFFFFFFFFFFFFFFFF):
        self._g = graph
        self._smax = size_max
        self._ranges: Dict[str, Tuple[int, int]] = {}

    def propagate(self,
                  seeds: Dict[str, Tuple[int, int]],
                  max_iter: int = 50) -> Dict[str, Tuple[int, int]]:
        """从种子变量出发, worklist 传播范围约束."""
        self._ranges = dict(seeds)
        worklist = deque(seeds.keys())
        iters = 0

        while worklist and iters < max_iter:
            var = worklist.popleft()
            iters += 1
            if var not in self._ranges:
                continue
            lo, hi = self._ranges[var]

            for edge in self._g.successors(var):
                dst_lo = lo * edge.multiplier
                dst_hi = min(hi * edge.multiplier, self._smax)
                # 溢出检测: 乘法回绕 → 置顶
                if dst_lo > dst_hi:
                    dst_hi = self._smax

                old = self._ranges.get(edge.dst)
                if old is None:
                    self._ranges[edge.dst] = (dst_lo, dst_hi)
                    worklist.append(edge.dst)
                else:
                    # Lattice join ⊔: 取最宽区间
                    new_lo = min(old[0], dst_lo)
                    new_hi = max(old[1], dst_hi)
                    if (new_lo, new_hi) != old:
                        self._ranges[edge.dst] = (new_lo, new_hi)
                        worklist.append(edge.dst)

        return dict(self._ranges)

    def get_range(self, var: str) -> Optional[Tuple[int, int]]:
        return self._ranges.get(var)


def _collect_path_multipliers(graph: ProductChainGraph,
                              sink: str) -> Dict[str, int]:
    """回溯乘积链, 计算每个源变量到 sink 的累积乘数."""
    multipliers: Dict[str, int] = {sink: 1}
    worklist = deque([sink])

    while worklist:
        cur = worklist.popleft()
        cur_mult = multipliers[cur]
        for edge in graph.predecessors(cur):
            new_mult = cur_mult * edge.multiplier
            if edge.src not in multipliers:
                multipliers[edge.src] = new_mult
                worklist.append(edge.src)
            else:
                # ⊔: take the larger multiplier (worst case)
                multipliers[edge.src] = max(multipliers[edge.src], new_mult)

    sources = graph.sources()
    return {k: v for k, v in multipliers.items() if k in sources}


def analyze_product_chain_deep(source: str,
                               platform: str = "x86_64") -> List:
    """深度乘积链分析: 构建乘积图 → worklist传播 → 阈值判定.

    这是 I-GUARD 加深后的主入口, 替代简单的 regex→除法 流水线.
    """
    sizemax = _SIZEMAX.get(platform, _SIZEMAX['default'])
    graph = ProductChainGraph().build_from_source(source)

    results = []
    analyzer = IntOverflowSymbolicAnalyzer(platform)

    for sink in graph.sinks():
        path_multipliers = _collect_path_multipliers(graph, sink)
        if not path_multipliers:
            continue

        for src_var, path_mult in path_multipliers.items():
            if path_mult == 0:
                continue
            threshold = sizemax // path_mult
            guards = find_overflow_guards(source, src_var, threshold)
            var_lo, var_hi = infer_var_range(source, src_var, platform)
            verdict, confidence = assess_overflow(
                src_var, threshold, guards, var_lo, var_hi, source)

            sp = SymbolicProduct(
                result_var=sink, operand_var=src_var,
                constant=path_mult, line_no=0)
            results.append(OverflowThreshold(
                product=sp, threshold=threshold, size_max=sizemax,
                var_range_lo=var_lo, var_range_hi=var_hi,
                is_guarded=len(guards) > 0,
                guard_condition="; ".join(guards) if guards else "",
                verdict=verdict, confidence=confidence,
            ))

    return results


def combine_with_value_range(
    symbolic_results: List,
    verifier_results: List[dict],
    code: str = "",
) -> Tuple[List[dict], Dict[str, int]]:
    """融合符号化分析和值范围分析的判定结果.

    策略: 符号化分析作为前置过滤, 值范围分析作为精化.
    """
    stats = {'symbolic_safe': 0, 'symbolic_overflow': 0,
             'vr_safe': 0, 'vr_confirmed': 0, 'total': len(verifier_results)}

    safe_vars = {r.product.result_var for r in symbolic_results
                 if r.verdict == "SAFE"}
    overflow_vars = {r.product.result_var for r in symbolic_results
                     if r.verdict == "OVERFLOW"}

    refined = []
    for f in verifier_results:
        expr = f.get('expr', f.get('expression', ''))
        var_match = re.match(r'(\w+)\s*=', expr) if expr else None
        var = var_match.group(1) if var_match else ""

        if var in safe_vars:
            f['severity'] = 'Info'
            f['confidence'] = 0.10
            f['iof_verdict'] = 'symbolic_safe'
            stats['symbolic_safe'] += 1
        elif var in overflow_vars:
            f['severity'] = 'Critical'
            f['confidence'] = max(f.get('confidence', 0.5), 0.80)
            f['iof_verdict'] = 'symbolic_overflow'
            stats['symbolic_overflow'] += 1
        refined.append(f)

    return refined, stats


# 值域传播验证器

_ABORT_GUARD_RE = re.compile(
    r'if\s*\(\s*(\w+)\s*\*\s*(\w+)\s*<\s*\1\s*\)\s*(?:abort|assert|exit)\s*\(',
    re.IGNORECASE)
_BUILTIN_OVERFLOW_RE = re.compile(
    r'__builtin_(?:[su])?(?:add|sub|mul)l?_overflow\s*\(')
_UNSIGNED_DECL_RE = re.compile(
    r'(?:unsigned|size_t|uint\d+_t|uintptr_t)\s+(\w+)')
_OVERFLOW_DIV_GUARD_RE = re.compile(
    r'if\s*\(\s*(\w+)\s*>\s*(?:INT_MAX|INT32_MAX|UINT_MAX|SIZE_MAX|'
    r'(?:\d+))\s*/\s*(\w+)\s*\)', re.IGNORECASE)


@dataclass
class ValueRange:
    """整数值范围."""
    lo: int = 0
    hi: int = 2**31 - 1
    is_top: bool = False
    is_bottom: bool = False

    @staticmethod
    def const(v: int) -> "ValueRange":
        return ValueRange(lo=v, hi=v)

    @staticmethod
    def top() -> "ValueRange":
        return ValueRange(is_top=True)

    def mul(self, other: "ValueRange") -> "ValueRange":
        """乘法: 取四个角的极值."""
        if self.is_top or other.is_top:
            return ValueRange.top()
        vals = [self.lo * other.lo, self.lo * other.hi,
                self.hi * other.lo, self.hi * other.hi]
        return ValueRange(lo=min(vals), hi=max(vals))

    def add(self, other: "ValueRange") -> "ValueRange":
        if self.is_top or other.is_top:
            return ValueRange.top()
        return ValueRange(lo=self.lo + other.lo, hi=self.hi + other.hi)

    def may_overflow(self, bits: int = 32) -> bool:
        """是否可能超过 bit 位有符号/无符号上限."""
        if self.is_top:
            return True
        max_val = (1 << bits) - 1
        return self.hi > max_val or self.lo < 0

    def refine_by_guard(self, op: str, bound: int) -> "ValueRange":
        """用守卫条件精化范围."""
        if self.is_top:
            return self
        if op == 'lt':  # <
            return ValueRange(lo=self.lo, hi=min(self.hi, bound - 1))
        elif op == 'le':  # <=
            return ValueRange(lo=self.lo, hi=min(self.hi, bound))
        elif op == 'gt':  # >
            return ValueRange(lo=max(self.lo, bound + 1), hi=self.hi)
        elif op == 'ge':  # >=
            return ValueRange(lo=max(self.lo, bound), hi=self.hi)
        return self

    def __repr__(self) -> str:
        if self.is_top:
            return "TOP"
        return f"[{self.lo}, {self.hi}]"


@dataclass
class IntOverflowVerdict:
    """整数溢出判定."""
    expr: str
    func_name: str
    call_site: int
    range_before_guard: ValueRange
    range_after_guard: ValueRange
    may_overflow: bool
    is_guarded: bool
    confidence: float
    reason: str


class IntOverflowVerifier:
    """基于值范围传播的整数溢出验证."""

    _GUARD_PATS = [
        (r'if\s*\(\s*(\w+)\s*<\s*(\d+)\s*\)', 'lt'),
        (r'if\s*\(\s*(\w+)\s*<=\s*(\d+)\s*\)', 'le'),
        (r'if\s*\(\s*(\w+)\s*>\s*(\d+)\s*\)', 'gt'),
        (r'if\s*\(\s*(\w+)\s*>=\s*(\d+)\s*\)', 'ge'),
        (r'(\w+)\s*=\s*min\s*\(\s*\w+\s*,\s*(\d+)\s*\)', 'le'),
        (r'(\w+)\s*=\s*max\s*\(\s*\w+\s*,\s*(\d+)\s*\)', 'ge'),
    ]

    def __init__(self):
        self._var_ranges: Dict[str, ValueRange] = {}
        self._guards: Dict[str, List[Tuple[str, int]]] = {}

    def clear(self):
        self._var_ranges.clear()
        self._guards.clear()

    def propagate(self, insns: List[Tuple[int, str]]):
        """在伪代码行上做值范围正向传播."""
        for addr, text in insns:
            tl = text.strip()
            # var = const
            m = re.match(r'(\w+)\s*=\s*(\d+)\s*;?$', tl)
            if m:
                self._var_ranges[m.group(1)] = ValueRange.const(int(m.group(2)))
                continue
            # var = other
            m = re.match(r'(\w+)\s*=\s*(\w+)\s*;?$', tl)
            if m:
                src = self._var_ranges.get(m.group(2))
                if src:
                    self._var_ranges[m.group(1)] = ValueRange(lo=src.lo, hi=src.hi)
                continue
            # var = a * b
            m = re.match(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)\s*;?$', tl)
            if m:
                a = self._var_ranges.get(m.group(2), ValueRange.top())
                b = self._var_ranges.get(m.group(3), ValueRange.top())
                self._var_ranges[m.group(1)] = a.mul(b)
                continue
            # var = a + const
            m = re.match(r'(\w+)\s*=\s*(\w+)\s*\+\s*(\d+)\s*;?$', tl)
            if m:
                a = self._var_ranges.get(m.group(2), ValueRange.top())
                self._var_ranges[m.group(1)] = a.add(
                    ValueRange.const(int(m.group(3))))
                continue

            # 守卫模式
            for pat, op in self._GUARD_PATS:
                gm = re.match(pat, tl)
                if gm:
                    var, val = gm.group(1), int(gm.group(2))
                    self._guards.setdefault(var, []).append((op, val))
                    break

    def verify(self, expr: str, func_name: str = "",
               call_site: int = 0) -> IntOverflowVerdict:
        """验证 a*b 或 a 是否可能溢出 (含守卫精化)."""
        mul_m = re.match(r'(\w+)\s*\*\s*(\w+)', expr)
        if mul_m:
            a_name, b_name = mul_m.group(1), mul_m.group(2)
            a_range = self._var_ranges.get(a_name, ValueRange.top())
            b_range = self._var_ranges.get(b_name, ValueRange.top())
            raw_range = a_range.mul(b_range)
        else:
            raw_range = self._var_ranges.get(expr, ValueRange.top())

        guarded_range = raw_range
        is_guarded = False
        if expr in self._guards or mul_m:
            target_var = expr if expr in self._guards else (
                mul_m.group(1) if mul_m and mul_m.group(1) in self._guards
                else None)
            if target_var:
                for op, bound in self._guards[target_var]:
                    guarded_range = guarded_range.refine_by_guard(op, bound)
                    is_guarded = True

        may_ovf = guarded_range.may_overflow()

        if not may_ovf and not raw_range.is_top:
            confidence = 0.05
            reason = f"值范围 {guarded_range} 在安全边界内"
        elif may_ovf and is_guarded:
            confidence = 0.40
            reason = f"被守卫但范围 {guarded_range} 仍可能溢出"
        elif may_ovf and not raw_range.is_top:
            confidence = 0.75
            reason = f"值范围 {guarded_range} 可能溢出 {2**31-1}"
        else:
            confidence = 0.35
            reason = "值范围未知"

        return IntOverflowVerdict(
            expr=expr, func_name=func_name, call_site=call_site,
            range_before_guard=raw_range,
            range_after_guard=guarded_range,
            may_overflow=may_ovf,
            is_guarded=is_guarded,
            confidence=confidence,
            reason=reason,
        )

    def check_abort_guard(self, code: str, ops: List[str]) -> bool:
        """if(a*b < a) abort() | __builtin_*_overflow → 运行时崩溃而非可利用溢出."""
        return bool(_ABORT_GUARD_RE.search(code) or
                    _BUILTIN_OVERFLOW_RE.search(code) or
                    _OVERFLOW_DIV_GUARD_RE.search(code))

    def is_unsigned_domain(self, code: str, ops: List[str]) -> bool:
        """检测操作数是否均为无符号类型 (unsigned wrap 是定义行为)."""
        unsigned_vars: Set[str] = set()
        for m in _UNSIGNED_DECL_RE.finditer(code):
            unsigned_vars.add(m.group(1))
        for m in re.finditer(r'(?:size_t|uintptr_t)\s+(\w+)', code):
            unsigned_vars.add(m.group(1))
        return bool(ops and all(
            op in unsigned_vars for op in ops if op and not op.isdigit()))

    def verify_candidates(self, findings: List[dict], code: str = ""
                          ) -> Tuple[List[dict], Dict[str, int]]:
        """批量验证检测器候选: 值范围+abort+domain → 综合判定."""
        stats = {'safe_guarded': 0, 'safe_bounded': 0,
                 'safe_domain': 0, 'confirmed': 0, 'uncertain': 0}
        refined = []
        for f in findings:
            expr = f.get('expr', f.get('expression', ''))
            ops = re.findall(r'[a-zA-Z_]\w*', expr) if expr else []
            v = self.verify(expr, f.get('function', ''))
            has_abort = self.check_abort_guard(code, ops)
            is_unsigned = self.is_unsigned_domain(code, ops)
            desc = str(f.get('description', ''))
            in_alloc = any(op in desc for op in ['malloc', 'calloc', 'realloc'])

            if not v.may_overflow:
                f['severity'] = 'Info'
                f['confidence'] = 0.05
                f['iov_verdict'] = 'safe_bounded'
                f['iov_reason'] = v.reason
                stats['safe_bounded'] += 1
            elif has_abort:
                f['severity'] = 'Low'
                f['confidence'] = 0.25
                f['iov_verdict'] = 'safe_guarded'
                f['iov_reason'] = 'abort/builtin overflow guard'
                stats['safe_guarded'] += 1
            elif is_unsigned and not in_alloc:
                f['severity'] = 'Low'
                f['confidence'] = 0.30
                f['iov_verdict'] = 'safe_domain'
                f['iov_reason'] = 'unsigned domain: wrap is defined'
                stats['safe_domain'] += 1
            elif v.may_overflow and not v.is_guarded:
                f['severity'] = 'Critical'
                f['confidence'] = 0.85
                f['iov_verdict'] = 'confirmed'
                f['iov_reason'] = v.reason
                stats['confirmed'] += 1
            else:
                f['iov_verdict'] = 'uncertain'
                f['iov_reason'] = v.reason
                stats['uncertain'] += 1
            refined.append(f)
        return refined, stats


def verify_int_overflow_candidates(findings: List[dict], code: str = ""
                                   ) -> Tuple[List[dict], Dict[str, int]]:
    return IntOverflowVerifier().verify_candidates(findings, code)


# 循环归纳

class InductionKind(Enum):
    """归纳变量类型."""
    BASIC = "BASIC"       # i = i + c (或 i = i - c)
    DERIVED = "DERIVED"   # j = a*i + b (依赖基础归纳变量)
    ACCUMULATOR = "ACCUM"  # sum += x (循环累积)


@dataclass
class InductionVar:
    """循环归纳变量."""
    name: str
    kind: InductionKind
    init_val: int = 0          # 初始值
    stride: int = 1            # 步长 (+1 或 -1)
    bound_var: str = ""        # 绑定变量 (如 loop 的 n)
    bound_val: int = -1        # 绑定值 (-1=未知)
    bound_op: str = "<"        # 绑定操作符 (< <= > >=)
    derived_from: str = ""     # 派生来源 (用于 DERIVED 类型)
    derived_coef: int = 1      # 派生系数 c1
    derived_offset: int = 0    # 派生偏移 c2
    line_no: int = 0

    @property
    def max_iterations(self) -> int:
        """最大迭代次数 (基于守卫条件)."""
        if self.bound_val < 0:
            return -1  # 未知
        if self.stride == 0:
            return 0
        if self.bound_op in ('<', '<='):
            n = self.bound_val - self.init_val
            if self.bound_op == '<':
                n -= 1
            if self.stride > 0:
                return max(0, n // self.stride + 1)
            else:
                return -1  # stride<0 时 bound 下界
        return -1


@dataclass
class LoopInfo:
    """循环信息."""
    start_line: int            # 循环开始行
    end_line: int              # 循环结束行
    header_line: int           # 循环头行 (for/while)
    induction_vars: Dict[str, InductionVar] = field(default_factory=dict)
    accumulators: Dict[str, InductionVar] = field(default_factory=dict)
    guard_condition: str = ""  # 守卫条件文本
    body_lines: List[str] = field(default_factory=list)

    @property
    def has_known_bound(self) -> bool:
        return any(v.bound_val >= 0 for v in self.induction_vars.values())


@dataclass
class LoopOverflowRisk:
    """循环溢出风险评估."""
    loop: LoopInfo
    var_name: str              # 可能溢出的变量
    var_kind: str              # induction | accumulator
    max_value: int             # 循环后最大可能值
    overflow_threshold: int    # 溢出阈值
    risk_level: str = "UNKNOWN"
    confidence: float = 0.5
    reason: str = ""


_FOR_LOOP_RE = re.compile(
    r'for\s*\(\s*(.*?)\s*;\s*(.*?)\s*;\s*(.*?)\s*\)\s*\{',
    re.IGNORECASE | re.DOTALL)
_WHILE_LOOP_RE = re.compile(
    r'while\s*\(\s*(.+?)\s*\)\s*\{', re.IGNORECASE)
_INDUCTION_ADD_RE = re.compile(
    r'(\w+)\s*(\+|\-)=\s*(\d+)\s*;?')
_INDUCTION_ASSIGN_RE = re.compile(
    r'(\w+)\s*=\s*(\w+)\s*([+\-])\s*(\d+)\s*;?')
_ACCUM_RE = re.compile(
    r'(\w+)\s*\+=\s*(\w+)\s*;?')
_GUARD_RE = re.compile(
    r'(\w+)\s*(<|<=|>|>=|!=)\s*(\w+)')


def _find_matching_brace(lines: List[str], start: int) -> int:
    """括号匹配找对应的 }."""
    depth = 0
    started = False
    for j in range(start, len(lines)):
        for ch in lines[j]:
            if ch == '{':
                depth += 1
                started = True
            elif ch == '}':
                depth -= 1
        if started and depth == 0:
            return j
    return start + 50  # 回退


def _parse_guard_for(cond: str, var: str) -> Tuple[str, int, str]:
    """解析守卫条件中针对 var 的边界.

    返回 (bound_var, bound_val, bound_op).
    """
    for m in _GUARD_RE.finditer(cond):
        left, op, right = m.group(1), m.group(2), m.group(3)
        if left == var:
            try:
                return right, int(right), op
            except ValueError:
                return right, -1, op  # 符号边界 (如 n)
        elif right == var:
            rev_op = {'<': '>', '<=': '>=', '>': '<', '>=': '<=', '!=': '!='}
            try:
                return left, int(left), rev_op.get(op, op)
            except ValueError:
                return left, -1, rev_op.get(op, op)
    return "", -1, ""


def _extract_induction_vars(loop: LoopInfo, init: str,
                            cond: str, update: str,
                            body_lines: List[str],
                            var_init: Dict[str, int]):
    """从循环的 init/cond/update/body 中提取归纳变量."""

    for m in re.finditer(r'(\w+)\s*=\s*(\d+)\s*;?', init):
        var_init[m.group(1)] = int(m.group(2))

    all_update_lines = [update] if update else []
    if not update:
        all_update_lines = body_lines

    for ul in all_update_lines:
        ul = ul.strip()
        # i++ / ++i / i-- / --i
        for m in re.finditer(r'(?:(\w+)\+\+|(\w+)\-\-)', ul):
            var = m.group(1) or m.group(2)
            stride = 1 if m.group(1) else -1
            init_val = var_init.get(var, 0)
            bound_var, bound_val, bound_op = _parse_guard_for(cond, var)
            loop.induction_vars[var] = InductionVar(
                name=var, kind=InductionKind.BASIC,
                init_val=init_val, stride=stride,
                bound_var=bound_var, bound_val=bound_val,
                bound_op=bound_op, line_no=loop.header_line,
            )

        # i += c / i -= c
        for m in _INDUCTION_ADD_RE.finditer(ul):
            var = m.group(1)
            op = m.group(2)
            stride = int(m.group(3)) * (1 if op == '+' else -1)
            init_val = var_init.get(var, 0)
            bound_var, bound_val, bound_op = _parse_guard_for(cond, var)
            loop.induction_vars[var] = InductionVar(
                name=var, kind=InductionKind.BASIC,
                init_val=init_val, stride=stride,
                bound_var=bound_var, bound_val=bound_val,
                bound_op=bound_op, line_no=loop.header_line,
            )

    # i = i + c / i = i - c (在 body 中)
    for bl in body_lines:
        for m in _INDUCTION_ASSIGN_RE.finditer(bl):
            dst, src, op, val = m.group(1), m.group(2), m.group(3), m.group(4)
            if dst == src and dst not in loop.induction_vars:
                stride = int(val) * (1 if op == '+' else -1)
                init_val = var_init.get(dst, 0)
                bound_var, bound_val, bound_op = _parse_guard_for(cond, dst)
                loop.induction_vars[dst] = InductionVar(
                    name=dst, kind=InductionKind.BASIC,
                    init_val=init_val, stride=stride,
                    bound_var=bound_var, bound_val=bound_val,
                    bound_op=bound_op, line_no=loop.header_line,
                )

    # 累积器: sum += val
    for bl in body_lines:
        for m in _ACCUM_RE.finditer(bl):
            var = m.group(1)
            acc_val = m.group(2)
            init_val = var_init.get(var, 0)
            loop.accumulators[var] = InductionVar(
                name=var, kind=InductionKind.ACCUMULATOR,
                init_val=init_val, stride=1,
                derived_from=acc_val, line_no=loop.header_line,
            )


def extract_loops_from_source(source_code: str,
                              var_init: Dict[str, int]) -> List[LoopInfo]:
    """从源码提取所有循环结构并分析归纳变量."""
    loops = []
    lines = source_code.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()

        # for 循环
        fm = _FOR_LOOP_RE.search(stripped)
        if fm:
            init = fm.group(1).strip() if fm.group(1) else ""
            cond = fm.group(2).strip() if fm.group(2) else ""
            update = fm.group(3).strip() if fm.group(3) else ""

            end = _find_matching_brace(lines, i)
            body_lines = [l.strip() for l in lines[i+1:end]
                          if l.strip() and not l.strip().startswith('//')]

            loop = LoopInfo(
                start_line=i, end_line=end, header_line=i,
                guard_condition=cond,
                body_lines=body_lines,
            )

            _extract_induction_vars(loop, init, cond, update,
                                    body_lines, var_init)
            loops.append(loop)
            continue

        # while 循环
        wm = _WHILE_LOOP_RE.search(stripped)
        if wm:
            cond = wm.group(1).strip()
            end = _find_matching_brace(lines, i)
            body_lines = [l.strip() for l in lines[i+1:end]
                          if l.strip() and not l.strip().startswith('//')]

            loop = LoopInfo(
                start_line=i, end_line=end, header_line=i,
                guard_condition=cond,
                body_lines=body_lines,
            )
            _extract_induction_vars(loop, "", cond, "", body_lines, var_init)
            loops.append(loop)

    return loops


class LoopInductionTracker:
    """循环归纳变量追踪器 — Cousot 式 widening/narrowing."""

    def __init__(self, max_widening: int = 2**31 - 1):
        self._max_widening = max_widening
        self._var_init: Dict[str, int] = {}

    def clear(self):
        self._var_init.clear()

    def extract_loops(self, source_code: str) -> List[LoopInfo]:
        """从源码提取所有循环结构."""
        return extract_loops_from_source(source_code, self._var_init)

    def analyze_overflow_risk(self, loop: LoopInfo,
                               source_code: str = "") -> List[LoopOverflowRisk]:
        """分析单个循环的溢出风险."""
        risks = []
        threshold = self._max_widening

        for name, iv in loop.induction_vars.items():
            max_val = self._compute_max_after_loop(iv)
            min_val = iv.init_val
            risk = self._classify_risk(
                loop, name, "induction", min_val, max_val, threshold)
            risks.append(risk)

        for name, acc in loop.accumulators.items():
            max_per_iter = self._infer_max_per_iter(acc, source_code)
            max_iter = self._get_max_iterations(loop)
            if max_iter > 0:
                max_val = acc.init_val + max_iter * max_per_iter
                risk = self._classify_risk(
                    loop, name, "accumulator", acc.init_val, max_val,
                    threshold)
                risks.append(risk)

        return risks

    def _compute_max_after_loop(self, iv: InductionVar) -> int:
        """计算循环后变量的最大可能值 (widening 到 bound)."""
        if iv.bound_val >= 0:
            if iv.bound_op == '<':
                return iv.bound_val - 1
            elif iv.bound_op == '<=':
                return iv.bound_val
            elif iv.bound_op == '>':
                return self._max_widening
        if iv.stride > 0:
            return self._max_widening
        else:
            return iv.init_val

    def _infer_max_per_iter(self, acc: InductionVar,
                             source_code: str = "") -> int:
        """推断每次迭代的最大累积值."""
        if acc.derived_from:
            try:
                return int(acc.derived_from)
            except ValueError:
                pass
            if source_code:
                m = re.search(
                    rf'{re.escape(acc.derived_from)}\s*=\s*(\d+)\s*;',
                    source_code)
                if m:
                    return int(m.group(1))
        # 无法推断单次累积值 → 视为无界, 保守保留 (不伪造安全结论)
        return self._max_widening

    def _get_max_iterations(self, loop: LoopInfo) -> int:
        """获取循环的最大迭代次数."""
        for iv in loop.induction_vars.values():
            if iv.max_iterations > 0:
                return iv.max_iterations
        # 无已知迭代上界 → 视为无界, 保守保留 (不伪造安全结论)
        return self._max_widening

    def _classify_risk(self, loop: LoopInfo, var_name: str,
                        var_kind: str, min_val: int, max_val: int,
                        threshold: int) -> LoopOverflowRisk:
        """分类溢出风险等级."""
        risk = LoopOverflowRisk(
            loop=loop, var_name=var_name, var_kind=var_kind,
            max_value=max_val, overflow_threshold=threshold,
        )

        if max_val <= threshold:
            risk.risk_level = "SAFE"
            risk.confidence = 0.85
            risk.reason = f"max({max_val}) ≤ threshold({threshold})"
        elif min_val > threshold:
            risk.risk_level = "OVERFLOW"
            risk.confidence = 0.90
            risk.reason = f"min({min_val}) > threshold({threshold}), 必然溢出"
        elif loop.has_known_bound:
            risk.risk_level = "LIKELY_OVERFLOW"
            risk.confidence = 0.60
            risk.reason = (f"max({max_val}) > threshold({threshold}), "
                           f"但受 loop bound 约束, 部分输入溢出")
        else:
            risk.risk_level = "CONDITIONAL"
            risk.confidence = 0.40
            risk.reason = (f"max({max_val}) > threshold, "
                           f"无 loop bound → widening 到 ∞, 需运行时判定")

        return risk


def integrate_loop_analysis_with_iguard(
    source_code: str,
    existing_findings: Optional[List[dict]] = None,
) -> Tuple[List[LoopOverflowRisk], List[dict]]:
    """将循环归纳变量分析注入 I-GUARD 管线."""
    tracker = LoopInductionTracker()
    loops = tracker.extract_loops(source_code)
    all_risks = []
    for loop in loops:
        risks = tracker.analyze_overflow_risk(loop, source_code)
        all_risks.extend(risks)

    enhanced = list(existing_findings) if existing_findings else []

    for risk in all_risks:
        if risk.risk_level in ("OVERFLOW", "LIKELY_OVERFLOW"):
            enhanced.append({
                'source': 'loop_induction',
                'var': risk.var_name,
                'kind': risk.var_kind,
                'max_value': risk.max_value,
                'threshold': risk.overflow_threshold,
                'risk_level': risk.risk_level,
                'confidence': risk.confidence,
                'reason': risk.reason,
                'loop_start': risk.loop.start_line,
                'loop_end': risk.loop.end_line,
            })

    return all_risks, enhanced


__all__ = [
    "SymbolicProduct", "OverflowThreshold", "IntOverflowSymbolicAnalyzer",
    "analyze_int_overflow_symbolic",
    "ProductEdge", "ProductChainGraph", "ProductChainPropagator",
    "analyze_product_chain_deep", "_collect_path_multipliers",
    "combine_with_value_range",
    "ValueRange", "IntOverflowVerdict", "IntOverflowVerifier",
    "verify_int_overflow_candidates",
    "InductionKind", "InductionVar", "LoopInfo", "LoopOverflowRisk",
    "extract_loops_from_source", "LoopInductionTracker",
    "integrate_loop_analysis_with_iguard",
    "_SIZEOF_MAP", "find_overflow_guards", "infer_var_range",
    "assess_overflow",
]
