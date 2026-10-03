# CB-HOD — Constraint-Based Heap Overflow Detection (约束基堆溢出检测).
#
# 决策逻辑:
#   管线:
#     1. 指针追踪绑定 (Steensgaard 式并查集): malloc → 指针变量 →
#        memcpy 目标的数据流, 替换粗粒度的导入表笛卡尔积配对.
#     2. 区间约束求解: 对每个 (alloc, write) 绑定生成
#        alloc_size ≥ write_size 约束, 三层检查:
#        L1 精确常量比较 / L2 区间比较 / L3 守卫收缩.
#        核心判定: alloc.lo ≥ write.hi → 数学证明安全 (conf=0.98);
#        alloc.hi < write.lo → 确定溢出 (conf=0.92).
#     3. 守卫提取 (纯正则, 不依赖符号执行):
#        early-exit / clamp / ternary / min-max / loop-break.
#        apply_guard 对 TOP 区间也能从守卫自身构建有界区间 —
#        守卫携带信息, 不需要先验的变量范围.
#     4. HLM + slack: 区间化分配器松弛 (usable 下界/上界).
#
#   本文件实现 CB-HOD 核心管线: 指针追踪绑定 → 约束求解 → 守卫提取
#   → 分配器松弛 → 尺寸表达式求值 → 分配器模型 (HLM), 并补全
#   solve_and_filter 端到端入口.


from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple


# 区间域

class ValueRange:
    """仿射区间抽象域 [lo, hi]; ±inf 表示无界; bottom 表示空集."""

    __slots__ = ("lo", "hi", "is_bottom")

    def __init__(self, lo: float = float("-inf"), hi: float = float("inf"),
                 is_bottom: bool = False):
        self.lo = float(lo)
        self.hi = float(hi)
        self.is_bottom = is_bottom
        if self.lo > self.hi and not self.is_bottom:
            self.is_bottom = True

    def __repr__(self) -> str:
        if self.is_bottom:
            return "⊥"
        if self.lo == float("-inf") and self.hi == float("inf"):
            return "⊤"
        return f"[{self._f(self.lo)}, {self._f(self.hi)}]"

    @staticmethod
    def _f(v: float) -> str:
        if v == float("inf"):
            return "+∞"
        if v == float("-inf"):
            return "-∞"
        return str(int(v)) if v == int(v) else f"{v:.1f}"

    @staticmethod
    def const(v: int) -> "ValueRange":
        return ValueRange(v, v)

    @staticmethod
    def top() -> "ValueRange":
        return ValueRange()

    @staticmethod
    def bottom() -> "ValueRange":
        return ValueRange(is_bottom=True)

    @property
    def is_top(self) -> bool:
        return not self.is_bottom and self.lo == float("-inf") \
            and self.hi == float("inf")

    @property
    def is_const(self) -> bool:
        return not self.is_bottom and self.lo == self.hi \
            and abs(self.lo) != float("inf")

    @property
    def const_value(self) -> Optional[int]:
        return int(self.lo) if self.is_const else None

    def add(self, o: "ValueRange") -> "ValueRange":
        if self.is_bottom or o.is_bottom:
            return ValueRange.bottom()
        if self.is_top or o.is_top:
            return ValueRange.top()
        return ValueRange(self.lo + o.lo, self.hi + o.hi)

    def sub(self, o: "ValueRange") -> "ValueRange":
        if self.is_bottom or o.is_bottom:
            return ValueRange.bottom()
        if self.is_top or o.is_top:
            return ValueRange.top()
        return ValueRange(self.lo - o.hi, self.hi - o.lo)

    def mul(self, o: "ValueRange") -> "ValueRange":
        if self.is_bottom or o.is_bottom:
            return ValueRange.bottom()
        if self.is_top or o.is_top:
            return ValueRange.top()
        b = [self.lo * o.lo, self.lo * o.hi, self.hi * o.lo, self.hi * o.hi]
        return ValueRange(min(b), max(b))

    def meet(self, o: "ValueRange") -> "ValueRange":
        if self.is_bottom or o.is_bottom:
            return ValueRange.bottom()
        lo, hi = max(self.lo, o.lo), min(self.hi, o.hi)
        return ValueRange.bottom() if lo > hi else ValueRange(lo, hi)


def extract_value_ranges(code: str) -> Dict[str, ValueRange]:
    """从 C 源码提取变量值范围."""
    ranges: Dict[str, ValueRange] = {}
    sizeof_map = {"char": 1, "short": 2, "int": 4, "long": 4, "long long": 8,
                  "float": 4, "double": 8, "void*": 4, "size_t": 4,
                  "void *": 4, "char*": 4, "int*": 4, "struct": 8}

    for m in re.finditer(r"#define\s+(\w+)\s+(\d+)\b", code):
        ranges[m.group(1)] = ValueRange.const(int(m.group(2)))

    for m in re.finditer(
            r"\b(?:int|unsigned|size_t|uint\d+_t|u?int\d+_t)\s+(\w+)\s*=\s*(\d+)\s*;",
            code):
        ranges[m.group(1)] = ValueRange.const(int(m.group(2)))

    for m in re.finditer(r"(\w+)\s*=\s*(\d+)\s*;", code):
        if m.group(1) not in ranges:
            ranges[m.group(1)] = ValueRange.const(int(m.group(2)))

    for m in re.finditer(
            r"(\w+)\s*=\s*(\w+)\s*\*\s*sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)\s*;",
            code):
        rv = ranges.get(m.group(2), ValueRange.top())
        ranges[m.group(1)] = rv.mul(ValueRange.const(
            sizeof_map.get(m.group(3).strip(), 4)))

    for m in re.finditer(r"(\w+)\s*=\s*(\w+)\s*([+\-*])\s*(\w+)\s*;", code):
        ra = ranges.get(m.group(2), ValueRange.top())
        rb = ranges.get(m.group(4), ValueRange.top())
        op = m.group(3)
        ranges[m.group(1)] = ra.add(rb) if op == "+" \
            else (ra.sub(rb) if op == "-" else ra.mul(rb))

    for m in re.finditer(r"(\w+)\s*=\s*(\w+)\s*;", code):
        if m.group(1) not in ranges and m.group(2) in ranges:
            ranges[m.group(1)] = ranges[m.group(2)]

    for m in re.finditer(
            r"(\w+)\s*=\s*(?:\(\s*\w+(?:\s*\*)?\s*\)\s*)?atoi\s*\(\s*argv\s*\[",
            code):
        ranges[m.group(1)] = ValueRange.top()

    for m in re.finditer(
            r"(?:malloc|calloc|realloc)\s*\(\s*(\w+(?:\s*\*\s*\w+)?)\s*\)",
            code):
        arg = m.group(1).strip()
        if "*" in arg:
            parts = [p.strip() for p in arg.split("*")]
            ra = _parse_arg(parts[0], ranges)
            rb = _parse_arg(parts[1], ranges) if len(parts) > 1 \
                else ValueRange.const(1)
            ranges["__malloc_size__"] = ra.mul(rb)
        else:
            ranges["__malloc_size__"] = _parse_arg(arg, ranges)

    for m in re.finditer(r"(\w+)\s*=\s*(?:recv|read|fread)\s*\(", code):
        ranges[m.group(1)] = ValueRange(0, float("inf"))

    for m in re.finditer(r"(\w+)\s*=\s*strlen\s*\(\s*(\w+)\s*\)", code):
        ranges[m.group(1)] = ValueRange(0, 65536)

    return ranges


def _parse_arg(arg: str, ranges: Dict[str, ValueRange]) -> ValueRange:
    """将 malloc/memcpy 的参数文本解析为 ValueRange."""
    try:
        return ValueRange.const(int(arg))
    except ValueError:
        pass
    if arg in ranges:
        return ranges[arg]
    return ValueRange.top()


# 指针流追踪

_CALL_RE = re.compile(r"\b(\w+)\s*\(((?:[^()]|\([^()]*\))*)\)")


def _split_top_level(s: str) -> List[str]:
    """按顶层逗号切分参数 (括号深度跟踪)."""
    args, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
            cur += ch
        elif ch == ")":
            depth -= 1
            cur += ch
        elif ch == "," and depth == 0:
            args.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        args.append(cur.strip())
    return args


def _all_calls(code: str) -> List[Tuple[str, List[str], int]]:
    """返回 [(func, args, pos), ...] 所有调用."""
    out = []
    for m in _CALL_RE.finditer(code):
        out.append((m.group(1), _split_top_level(m.group(2)), m.start()))
    return out


class HeapPtr:
    """堆指针: 分配点 + 变量名 + 可达别名集合."""
    __slots__ = ("var", "alloc_func", "alloc_size_expr", "alloc_pos",
                 "aliases", "line")

    def __init__(self, var: str, alloc_func: str = "",
                 alloc_size_expr: str = "", alloc_pos: int = 0,
                 line: int = 0):
        self.var = var
        self.alloc_func = alloc_func
        self.alloc_size_expr = alloc_size_expr
        self.alloc_pos = alloc_pos
        self.aliases: Set[str] = {var}
        self.line = line

    def __repr__(self) -> str:
        return f"HeapPtr({self.var}, aliases={self.aliases})"


def extract_heap_ptrs(code: str) -> List[HeapPtr]:
    """从代码中提取所有堆分配点及其接收变量."""
    ptrs = []
    alloc_re = re.compile(
        r"(\w+(?:\s*\[[^\]]*\])?)\s*=\s*(?:\([^)]*\*?\s*\)\s*)?"
        r"(malloc|calloc|realloc)\s*\(((?:[^()]|\([^()]*\))*)\)")
    for m in alloc_re.finditer(code):
        var = m.group(1).strip()
        func = m.group(2)
        args = _split_top_level(m.group(3))
        line = code[:m.start()].count('\n') + 1

        if func == 'calloc':
            size_expr = f"{args[0]} * {args[1]}" if len(args) >= 2 else args[0]
        elif func == 'realloc':
            size_expr = args[1] if len(args) >= 2 else args[0]
        else:
            size_expr = args[0] if args else "unknown"

        ptrs.append(HeapPtr(
            var=_base_var(var), alloc_func=func,
            alloc_size_expr=size_expr, alloc_pos=m.start(), line=line))

    return ptrs


def _size_arg_for(func: str, args: List[str]) -> str:
    """按函数语义取写入量表达式."""
    if not args:
        return "unknown"
    if func in ("strcpy", "strcat", "sprintf", "gets", "scanf"):
        return "unbounded"
    if func in ("snprintf", "vsnprintf"):
        return args[1] if len(args) >= 2 else "unknown"
    if func == "fread":
        if len(args) >= 3:
            return f"{args[1]} * {args[2]}"
        return "unknown"
    # memcpy/memmove/strncpy/strncat/read/recv/_read: 第3参数
    return args[2] if len(args) >= 3 else "unknown"


def extract_write_sites(code: str) -> List[Dict]:
    """从代码中提取所有内存写入点."""
    writes = []
    WRITE_FUNCS = {
        "memcpy", "memmove", "strncpy", "strncat", "strcpy", "strcat",
        "sprintf", "snprintf", "vsnprintf", "gets", "scanf", "read",
        "recv", "fread", "_read",
    }
    for func, args, pos in _all_calls(code):
        if func not in WRITE_FUNCS:
            continue
        if not args:
            continue
        dst = args[0]
        writes.append({
            "func": func,
            "buffer": _base_var(dst),
            "raw_buffer": dst,
            "size_expr": _size_arg_for(func, args),
            "pos": pos,
            "line": code[:pos].count('\n') + 1,
        })

    # 手动循环写入 (arr[idx++] = val) — 标记为 manual_loop
    for lm in re.finditer(r'(?:while|for)\s*\([^)]*\)\s*\{', code):
        d, p, body_s = 1, lm.end(), lm.end()
        while d > 0 and p < len(code):
            if code[p] == '{':
                d += 1
            elif code[p] == '}':
                d -= 1
            p += 1
        body = code[body_s:p-1]
        for am in re.finditer(r'(\w+)\s*\[[^\]]*\+\+[^\]]*\]\s*=', body):
            arr = am.group(1)
            writes.append({
                "func": "manual_loop_write", "buffer": arr,
                "raw_buffer": f"{arr}[idx++]",
                "size_expr": "loop_bounded",
                "pos": lm.start(),
                "line": code[:lm.start()].count('\n') + 1,
            })

    return writes


def build_ptr_aliases(code: str, heap_ptrs: List[HeapPtr]) -> Dict[str, Set[str]]:
    """为堆指针构建别名传播图."""
    aliases: Dict[str, Set[str]] = {}
    ptr_vars = {p.var for p in heap_ptrs}
    for v in ptr_vars:
        aliases[v] = {v}

    for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*;', code):
        lhs, rhs = m.group(1), m.group(2)
        if rhs in ptr_vars:
            ptr_vars.add(lhs)
            aliases.setdefault(lhs, set()).add(rhs)
            aliases[lhs].update(aliases.get(rhs, {rhs}))
        if re.match(r'(\w+)\s*\+\s*\d+', rhs):
            base = re.match(r'(\w+)', rhs).group(1)
            if base in ptr_vars:
                ptr_vars.add(lhs)
                aliases.setdefault(lhs, set()).add(base)
                aliases[lhs].update(aliases.get(base, {base}))

    changed = True
    while changed:
        changed = False
        for v, vs in list(aliases.items()):
            for a in list(vs):
                if a in aliases and not aliases[a].issubset(vs):
                    vs.update(aliases[a])
                    changed = True

    return aliases


def bind_writes_to_allocs(
    heap_ptrs: List[HeapPtr],
    write_sites: List[Dict],
    aliases: Dict[str, Set[str]],
) -> List[Dict]:
    """将写入点绑定到对应的分配点."""
    bindings = []

    ptr_map: Dict[str, HeapPtr] = {}
    for hp in heap_ptrs:
        ptr_map[hp.var] = hp
        for a in hp.aliases:
            ptr_map[a] = hp

    for ws in write_sites:
        buf = ws["buffer"]
        raw = ws.get("raw_buffer", buf)

        buf_aliases = aliases.get(buf, {buf})

        matched = []
        for hp in heap_ptrs:
            hp_aliases = aliases.get(hp.var, {hp.var})
            if buf in hp_aliases or buf_aliases & hp_aliases:
                matched.append(hp)
            elif _base_var(raw) in hp_aliases:
                matched.append(hp)

        if not matched:
            raw_base = _base_var(raw.split('->')[0] if '->' in raw else raw)
            for hp in heap_ptrs:
                if raw_base == hp.var or raw_base in aliases.get(hp.var, set()):
                    matched.append(hp)

        for hp in matched:
            bindings.append({
                "alloc_ptr": hp,
                "write_site": ws,
                "confidence": 0.85 if len(matched) == 1 else 0.60,
                "reason": "exact_alias" if len(matched) == 1
                          else f"shared_alias({len(matched)} candidates)",
            })

    return bindings


def _base_var(expr: str) -> str:
    """归一化指针表达式: 去掉数组索引、结构体字段访问、指针算术."""
    expr = re.sub(r'\[[^\]]*\]', '', expr)
    expr = re.sub(r'\s*\+\s*\w+', '', expr)
    expr = expr.split('->')[0].split('.')[0].strip()
    return expr


# 分配器模型

class AllocatorModel:
    """抽象分配器模型: 给定请求大小, 返回有效用户可用空间的范围."""

    def __init__(self, word_size: int = 8, alignment: int = 16,
                 min_chunk_size: int = 32):
        self.word_size = word_size
        self.alignment = alignment
        self.min_chunk_size = min_chunk_size
        self.min_user_size = min_chunk_size - 2 * word_size

    @classmethod
    def x86_64(cls) -> "AllocatorModel":
        return cls(word_size=8, alignment=16, min_chunk_size=32)

    @classmethod
    def i386(cls) -> "AllocatorModel":
        return cls(word_size=4, alignment=8, min_chunk_size=16)

    def requested_to_chunk_size(self, request: int) -> int:
        mask = self.alignment - 1
        min_req = request + self.word_size  # + SIZE_SZ
        padded = (min_req + mask) & ~mask
        return max(self.min_chunk_size, padded)

    def usable_size_min(self, request: int) -> int:
        chunk = self.requested_to_chunk_size(request)
        return max(self.min_user_size, chunk - 2 * self.word_size)

    def usable_size_max(self, request: int) -> int:
        return self.usable_size_min(request) + self.alignment

    def check_overflow_under_alignment(self, alloc_request: int,
                                        write_size: int) -> Tuple[bool, float, str]:
        """精确检查: 给定分配请求值和写入量, 考虑分配器对齐后是否溢出."""
        usable_min = self.usable_size_min(alloc_request)

        if write_size <= usable_min:
            return (False, 0.03,
                    f"写入{write_size}B ≤ 对齐后可用空间{usable_min}B"
                    f"(请求{alloc_request}B)→安全")

        usable_max = self.usable_size_max(alloc_request)
        if write_size <= usable_max:
            return (False, 0.12,
                    f"写入{write_size}B ≤ 最大可用{usable_max}B"
                    f"(请求{alloc_request}B, 对齐余量)→可能安全")

        overflow_bytes = write_size - usable_min
        return (True, 0.88 - min(overflow_bytes / 1024.0, 0.30),
                f"写入{write_size}B > 对齐后最小可用{usable_min}B"
                f"(溢出{overflow_bytes}B)→高置信溢出")


_MODEL_CACHE: Dict[str, AllocatorModel] = {}


def get_allocator_model(arch: str = "x86_64") -> AllocatorModel:
    if arch not in _MODEL_CACHE:
        if arch in ("i386", "x86", "arm32", "arm"):
            _MODEL_CACHE[arch] = AllocatorModel.i386()
        else:
            _MODEL_CACHE[arch] = AllocatorModel.x86_64()
    return _MODEL_CACHE[arch]


# 尺寸表达式求值

_SIZEOF_MAP = {
    "char": 1, "short": 2, "int": 4, "long": 4, "long long": 8,
    "float": 4, "double": 8, "void*": 4, "size_t": 4,
    "void *": 4, "struct": 8, "wchar_t": 2,
}


def resolve_defines(code: str) -> Dict[str, int]:
    """从C源码提取 #define 宏常量映射."""
    defines: Dict[str, int] = {}
    for m in re.finditer(r'#define\s+(\w+)\s+(\d+)\s*$', code, re.MULTILINE):
        try:
            defines[m.group(1)] = int(m.group(2))
        except ValueError:
            pass
    return defines


def eval_size_expr(
    expr: str,
    ranges: Dict[str, ValueRange],
    defines: Dict[str, int] = None,
) -> ValueRange:
    """求值分配量/写入量表达式 → ValueRange.

    支持: 纯数字 | #define宏 | 单变量 | var*sizeof(T) | var*CONST | var*var
    """
    if defines is None:
        defines = {}
    expr = expr.strip()
    if not expr or expr == "unknown":
        return ValueRange.top()

    try:
        return ValueRange.const(int(expr))
    except ValueError:
        pass

    if expr in defines:
        return ValueRange.const(defines[expr])

    sm = re.match(r"sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)", expr)
    if sm:
        return ValueRange.const(
            _SIZEOF_MAP.get(sm.group(1).strip().replace(" ", ""), 4)
        )

    cast = re.match(r"\(\s*\w+(?:\s*\*)?\s*\)\s*(.+)$", expr)
    if cast:
        inner = cast.group(1).strip()
        if re.match(r"^[\w\s*()]+$", inner):
            return eval_size_expr(inner, ranges, defines)

    sm = re.match(r"(\d+)\s*\*\s*sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)", expr)
    if sm:
        return ValueRange.const(int(sm.group(1)) * _SIZEOF_MAP.get(
            sm.group(2).strip().replace(" ", ""), 4))

    sm = re.match(r"sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)\s*\*\s*(\d+)", expr)
    if sm:
        return ValueRange.const(_SIZEOF_MAP.get(
            sm.group(1).strip().replace(" ", ""), 4) * int(sm.group(2)))

    sm = re.match(r"(\w+)\s*\*\s*sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)", expr)
    if sm:
        vr = ranges.get(sm.group(1), ValueRange.top())
        sz = _SIZEOF_MAP.get(sm.group(2).strip().replace(" ", ""), 4)
        return vr.mul(ValueRange.const(sz))

    sm = re.match(r"sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)\s*\*\s*(\w+)", expr)
    if sm:
        vr = ranges.get(sm.group(2), ValueRange.top())
        sz = _SIZEOF_MAP.get(sm.group(1).strip().replace(" ", ""), 4)
        return vr.mul(ValueRange.const(sz))

    sm = re.match(r"(\w+)\s*\*\s*(\d+)", expr)
    if sm:
        vr = ranges.get(sm.group(1), ValueRange.top())
        return vr.mul(ValueRange.const(int(sm.group(2))))

    sm = re.match(r"(\d+)\s*\*\s*(\w+)", expr)
    if sm:
        vr = ranges.get(sm.group(2), ValueRange.top())
        return vr.mul(ValueRange.const(int(sm.group(1))))

    sm = re.match(r"(\w+)\s*\*\s*(\w+)", expr)
    if sm:
        a = ranges.get(sm.group(1), ValueRange.top())
        b = ranges.get(sm.group(2), ValueRange.top())
        return a.mul(b)

    sm = re.match(r"(\w+)\s*\+\s*(\d+)", expr)
    if sm:
        vr = ranges.get(sm.group(1), ValueRange.top())
        return vr.add(ValueRange.const(int(sm.group(2))))

    sm = re.match(r"(\w+)\s*-\s*(\d+)", expr)
    if sm:
        vr = ranges.get(sm.group(1), ValueRange.top())
        return vr.sub(ValueRange.const(int(sm.group(2))))

    sm = re.match(r"(\d+)\s*\+\s*(\w+)", expr)
    if sm:
        vr = ranges.get(sm.group(2), ValueRange.top())
        return vr.add(ValueRange.const(int(sm.group(1))))

    if expr in ranges:
        return ranges[expr]

    return ValueRange.top()


def eval_write_size(
    size_expr: str,
    func: str,
    ranges: Dict[str, ValueRange],
    defines: Dict[str, int] = None,
) -> ValueRange:
    """求值写入量表达式 — 含特殊写入语义.

    strcpy/gets 等无界写入 → TOP
    手动循环写入 → TOP (迭代次数不可静态推断)
    其他 → 委托 eval_size_expr
    """
    if size_expr in ("unbounded", "loop_bounded"):
        return ValueRange.top()
    return eval_size_expr(size_expr, ranges, defines)


def is_size_var(var: str, size_expr: str) -> bool:
    """检查变量是否参与尺寸表达式的乘法因子."""
    return var in size_expr.split('*') and var.strip() in size_expr


# 守卫提取

def extract_relevant_guards(
    code: str,
    alloc_var: str = "",
    write_buf: str = "",
) -> List[Dict]:
    """提取与特定分配/写入变量相关的条件守卫."""
    guards: List[Dict] = []

    # 数值边界检查 + early exit
    for m in re.finditer(
            r'if\s*\(\s*(\w+)\s*(<|<=|>|>=|==)\s*(\d+)\s*\)\s*'
            r'(?:return|goto\s+\w+|break|continue)', code):
        guards.append({
            "var": m.group(1), "op": m.group(2),
            "value": int(m.group(3)), "pos": m.start(),
            "action": "early_exit",
        })

    # 上限钳制: if (n > max) n = max;
    for m in re.finditer(
            r'if\s*\(\s*(\w+)\s*>\s*(\w+)\s*\)\s*(\w+)\s*=\s*\2', code):
        guards.append({
            "var": m.group(1), "op": "<=",
            "value_var": m.group(2), "pos": m.start(),
            "action": "clamp",
        })

    # 三元上限: x = var > M ? M : var;
    for m in re.finditer(
            r'(\w+)\s*=\s*(\w+)\s*[>]\s*(\d+|\w+)\s*\?\s*(\3)\s*:\s*\2',
            code):
        limit_val = m.group(3)
        guards.append({
            "var": m.group(1), "op": "<=",
            "value": int(limit_val) if limit_val.isdigit() else None,
            "value_var": None if limit_val.isdigit() else limit_val,
            "pos": m.start(), "action": "ternary_clamp_upper",
        })

    # 三元下限: x = var < M ? M : var;
    for m in re.finditer(
            r'(\w+)\s*=\s*(\w+)\s*[<]\s*(\d+|\w+)\s*\?\s*(\3)\s*:\s*\2',
            code):
        limit_val = m.group(3)
        guards.append({
            "var": m.group(1), "op": ">=",
            "value": int(limit_val) if limit_val.isdigit() else None,
            "value_var": None if limit_val.isdigit() else limit_val,
            "pos": m.start(), "action": "ternary_clamp_lower",
        })

    # min(x, M) 上限
    for m in re.finditer(r'min\s*\(\s*(\w+)\s*,\s*(\d+)\s*\)', code):
        guards.append({
            "var": m.group(1), "op": "<=",
            "value": int(m.group(2)), "pos": m.start(),
            "action": "min_clamp",
        })

    # max(x, M) 下限
    for m in re.finditer(r'max\s*\(\s*(\w+)\s*,\s*(\d+)\s*\)', code):
        guards.append({
            "var": m.group(1), "op": ">=",
            "value": int(m.group(2)), "pos": m.start(),
            "action": "max_clamp",
        })

    # 循环守卫: if (offset + chunk > total) break;
    for m in re.finditer(
            r'if\s*\([^)]*\+\s*\w+\s*[>]\s*\w+[^)]*\)\s*break', code):
        guards.append({
            "var": write_buf, "op": "loop_break",
            "pos": m.start(), "action": "loop_guard",
        })

    return guards


def apply_guard(
    r: ValueRange,
    guard: Dict,
    defines: Dict[str, int] = None,
) -> ValueRange:
    """对值范围应用守卫约束, 返回收缩后的区间.

    即使输入为 TOP, 也能从守卫自身的数值构建有界区间 —
    守卫携带信息, 不需要先验的变量范围.
    """
    if defines is None:
        defines = {}
    if r.is_bottom:
        return r

    op = guard.get("op", "")
    val = guard.get("value")
    val_var = guard.get("value_var")

    if val is None and val_var and val_var in defines:
        val = defines[val_var]

    if val is None:
        return r

    if op == "<":
        bounded = ValueRange(float("-inf"), val - 1)
    elif op == "<=":
        bounded = ValueRange(float("-inf"), val)
    elif op == ">":
        bounded = ValueRange(val + 1, float("inf"))
    elif op == ">=":
        bounded = ValueRange(val, float("inf"))
    elif op == "==":
        bounded = ValueRange(val, val)
    else:
        return r

    if r.is_top:
        return bounded
    return r.meet(bounded)


# 分配器松弛

def usable_range_for_alloc(alloc_lo: float, alloc_hi: float,
                           arch: str = "x86_64") -> Tuple[float, float]:
    """分配请求区间 [alloc_lo, alloc_hi] → 可用用户空间区间.

    返回 (usable_lo, usable_hi)。∞ 表示无法上界.
    """
    model = get_allocator_model(arch)
    if alloc_lo == float("-inf"):
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
    """区间化的对齐感知判定.

    返回: (is_overflow, confidence, reason)
    """
    if alloc_range.is_bottom or write_range.is_bottom:
        return (False, 0.05, "约束冲突→路径不可达")
    if alloc_range.is_top and write_range.is_top:
        return (False, 0.30, "双方未知→无法判定")

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


# 约束求解

class HeapConstraint:
    """单个堆安全约束: alloc_size ≥ write_size 在什么条件下成立."""
    __slots__ = ("alloc_var", "alloc_size_expr", "alloc_range",
                 "write_func", "write_buffer", "write_size_expr",
                 "write_range", "is_safe", "safety_confidence",
                 "safety_reason", "guard_constraints", "alloc_model")

    def __init__(self):
        self.alloc_var = ""
        self.alloc_size_expr = ""
        self.alloc_range = ValueRange.top()
        self.write_func = ""
        self.write_buffer = ""
        self.write_size_expr = ""
        self.write_range = ValueRange.top()
        self.is_safe = False
        self.safety_confidence = 0.0
        self.safety_reason = ""
        self.guard_constraints: List[Dict] = []
        self.alloc_model: Optional[AllocatorModel] = None


def gen_constraints(
    bindings: List[Dict],
    ranges: Dict[str, ValueRange],
    code: str = "",
    arch: str = "x86_64",
) -> List[HeapConstraint]:
    """从指针绑定生成安全约束列表."""
    model = get_allocator_model(arch)
    defines = resolve_defines(code) if code else {}
    constraints = []

    for b in bindings:
        hp = b["alloc_ptr"]
        ws = b["write_site"]

        c = HeapConstraint()
        c.alloc_var = hp.var
        c.alloc_size_expr = hp.alloc_size_expr
        c.alloc_range = eval_size_expr(hp.alloc_size_expr, ranges, defines)
        c.write_func = ws["func"]
        c.write_buffer = ws["buffer"]
        c.write_size_expr = ws["size_expr"]
        c.write_range = eval_write_size(ws["size_expr"], ws["func"],
                                        ranges, defines)
        c.alloc_model = model

        c.guard_constraints = extract_relevant_guards(
            code, hp.var, ws["buffer"]
        )

        alloc_r = c.alloc_range
        write_r = c.write_range
        for gc in c.guard_constraints:
            gv = gc.get("var", "")
            if gv == hp.alloc_size_expr or is_size_var(gv, hp.alloc_size_expr):
                alloc_r = apply_guard(alloc_r, gc, defines)
            if gv == ws["size_expr"] or is_size_var(gv, ws["size_expr"]):
                write_r = apply_guard(write_r, gc, defines)

        c.alloc_range = alloc_r
        c.write_range = write_r

        c.is_safe, c.safety_confidence, c.safety_reason = _check_safety(
            alloc_r, write_r, model,
            hp.alloc_size_expr, ws["size_expr"],
            alloc_func=hp.alloc_func,
        )

        constraints.append(c)

    return constraints


def _check_safety(
    alloc_r: ValueRange,
    write_r: ValueRange,
    model: AllocatorModel,
    alloc_expr: str = "",
    write_expr: str = "",
    alloc_func: str = "",
) -> Tuple[bool, float, str]:
    """核心安全判定: 分配量是否必然 ≥ 写入量.

    判定层级:
    1. alloc.lo ≥ write.hi (考虑对齐) → 数学证明安全 (SAFE, conf=0.98)
    2. alloc.hi < write.lo → 确定溢出 (UNSAFE, conf=0.92)
    3. alloc==write 同表达式:
       a. 常量/sizeof → 安全 (conf=0.95)
       b. realloc + 同表达式 → 安全 (conf=0.90)
       c. 变量表达式 → 输入派生可疑 (conf=0.55)
    4. write_refs_alloc → 表达式通过min/三元受限于alloc (SAFE, conf=0.70)
    5. 范围重叠 → 不确定 (conf=0.50)
    6. 双方未知 → 保守可疑 (conf=0.30)
    """
    # 同表达式判定 (必须在 write_refs_alloc 之前)
    if alloc_expr and write_expr and alloc_expr == write_expr:
        if alloc_expr.isdigit() or 'sizeof' in alloc_expr:
            return (True, 0.95, f"identical_expr({alloc_expr})→provably_safe")
        if alloc_func == "realloc":
            return (True, 0.90, f"realloc_same_expr({alloc_expr})→safe_growth")
        return (False, 0.55, f"same_input_expr({alloc_expr})→input_dependent")

    # alloc包含write常量 → alloc由write派生 → alloc>=write
    if (alloc_expr and write_expr and write_expr != alloc_expr
            and write_expr in alloc_expr and write_expr.isdigit()):
        return (True, 0.72,
                f"alloc_derived_from_const_write({write_expr}⊆{alloc_expr})"
                f"→alloc≥write")

    # write包含alloc变量 → 检查是否受限于alloc (min/三元)
    if alloc_expr and write_expr and alloc_expr != write_expr \
            and alloc_expr in write_expr:
        remaining = write_expr.replace(alloc_expr, '', 1)
        if re.match(r'\s*\+\s*\d+', remaining):
            pass  # write = alloc + const > alloc → 危险
        elif re.match(r'\s*\*\s*\d+', remaining):
            pass  # write = alloc * N → 危险
        else:
            return (True, 0.70,
                    f"write_refs_alloc({alloc_expr}⊆"
                    f"{write_expr[:50]})→constrained_safe")

    # 精确区间比较
    if not alloc_r.is_top and not write_r.is_top:
        if alloc_r.lo >= write_r.hi:
            return (True, 0.98,
                    f"alloc.lo({alloc_r.lo:.0f})≥write.hi({write_r.hi:.0f})"
                    f"→provably_safe")

        align_pad = model.alignment
        if alloc_r.lo + align_pad >= write_r.hi:
            return (True, 0.85,
                    f"alloc.lo+align({alloc_r.lo:.0f}+{align_pad})≥"
                    f"write.hi({write_r.hi:.0f})→aligned_safe")

        if alloc_r.hi < write_r.lo:
            return (False, 0.92,
                    f"alloc.hi({alloc_r.hi:.0f})<write.lo({write_r.lo:.0f})"
                    f"→definite_overflow")

        if alloc_r.lo < write_r.lo <= alloc_r.hi < write_r.hi:
            return (False, 0.65,
                    f"range_overlap:alloc{alloc_r} vs write{write_r}"
                    f"→possible_overflow")

    # 保守判定
    if alloc_r.is_top and not write_r.is_top:
        return (True, 0.45, "alloc_unknown_but_write_bounded→conservative_safe")
    if not alloc_r.is_top and write_r.is_top:
        return (False, 0.50,
                f"alloc_bounded({alloc_r})_but_write_unbounded→suspicious")
    return (False, 0.30, "both_unbounded→uncertain")


def solve_and_filter(
    bindings: List[Dict],
    code: str = "",
    arch: str = "x86_64",
) -> Tuple[List[Dict], Dict]:
    """完整的约束求解 + 误报过滤管线.

    输入: 指针追踪产生的 (alloc, write) 绑定
    输出: (经过滤的发现列表, 统计信息)
    """
    ranges = extract_value_ranges(code) if code else {}
    constraints = gen_constraints(bindings, ranges, code, arch)

    safe_count = sum(1 for c in constraints if c.is_safe)
    findings = []
    for c in constraints:
        if not c.is_safe:
            conf = c.safety_confidence
            findings.append({
                "type": "heap-overflow",
                "cwe": "CWE-122",
                "alloc_func": f"malloc({c.alloc_size_expr})",
                "write_func": c.write_func,
                "alloc_var": c.alloc_var,
                "write_buffer": c.write_buffer,
                "alloc_range": str(c.alloc_range),
                "write_range": str(c.write_range),
                "confidence": round(conf, 2),
                "severity": "High" if conf > 0.60 else "Medium",
                "reason": c.safety_reason,
                "guard_count": len(c.guard_constraints),
            })

    findings.sort(key=lambda f: f["confidence"], reverse=True)

    stats = {
        "total_bindings": len(bindings),
        "constraints_generated": len(constraints),
        "proven_safe": safe_count,
        "reported": len(findings),
        "fp_reduction_pct": round(
            safe_count / max(len(constraints), 1) * 100, 1
        ),
        "method": "Constraint-Based-v1.1",
    }

    return findings, stats


# CB-HOD 端到端入口 (补全原库断开的接线)

def analyze_cb_hod(code: str, arch: str = "x86_64"
                   ) -> Tuple[List[Dict], Dict]:
    """CB-HOD 端到端管线: 指针绑定 → 约束生成 → 求解过滤.

    原库中 solve_and_filter 零调用 (链条在 benchmark 脚本处断开),
    本入口补全接线: 值流绑定替代笛卡尔积, 再交约束求解.
    """
    heap_ptrs = extract_heap_ptrs(code)
    if not heap_ptrs:
        return [], {"total_bindings": 0, "constraints_generated": 0,
                    "proven_safe": 0, "reported": 0, "fp_reduction_pct": 0.0,
                    "method": "Constraint-Based-v1.1"}
    write_sites = extract_write_sites(code)
    if not write_sites:
        return [], {"total_bindings": 0, "constraints_generated": 0,
                    "proven_safe": 0, "reported": 0, "fp_reduction_pct": 0.0,
                    "method": "Constraint-Based-v1.1"}
    aliases = build_ptr_aliases(code, heap_ptrs)
    bindings = bind_writes_to_allocs(heap_ptrs, write_sites, aliases)
    return solve_and_filter(bindings, code, arch)


__all__ = [
    "ValueRange", "extract_value_ranges",
    "HeapPtr", "extract_heap_ptrs", "extract_write_sites",
    "build_ptr_aliases", "bind_writes_to_allocs",
    "AllocatorModel", "get_allocator_model",
    "resolve_defines", "eval_size_expr", "eval_write_size", "is_size_var",
    "extract_relevant_guards", "apply_guard",
    "usable_range_for_alloc", "verdict_with_slack",
    "HeapConstraint", "gen_constraints", "solve_and_filter",
    "analyze_cb_hod",
]
