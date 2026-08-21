# PSVR-HLM — PSVR 管线 + Heap Layout Model 堆溢出检测 (v3.0).
#
# 决策逻辑:
#   管线 P0→P0.5(源码引导)→P1(VRA+循环感知)→P2(HLM)→P3(PFC)→P4(安全见证).
#   P0: 分配-写入配对 — 源码可用时用值流绑定 (并查集式指针别名传播)
#       替代笛卡尔积, 保证召回下界不变 (真溢出必然"写入目标=分配缓冲区").
#   P0.5: 5 类源码安全模式:
#     identical_safe_expr 0.50 / loop_guard_break 0.45 / ternary_guard 0.45
#     / realloc_grow_safe 0.45 / sizeof_match 0.30.
#   P1: 区间分析 (ValueRange 仿射区间) + 循环累积感知
#       (循环内 x += y 时写入区间拓宽为 unbounded).
#   P2: 分配器对齐建模 (glibc ptmalloc2 chunk=align(req+8,16)).
#   P3: 路径可行性 (守卫强度压制 / 不可达路径降权).
#   P4: 安全见证 (导入表安全变体/FORTIFY 压制置信度).
#
# 本文件为 PSVR-HLM 独立实现, 合并 modules/info/analysis/ 的
# heap_overflow_v2.py + v2_safety_filter.py + value_range_analyzer.py +
# heap_layout_model.py + path_feasibility_check.py + flow_pair_generator.py
# + pointer_tracker.py (仅保留管线调用图所需函数), 仅标准库.

from __future__ import annotations

import math
import re
from typing import Dict, List, Optional, Set, Tuple


# ================= 指针流追踪 (原 pointer_tracker) =================

_CALL_RE = re.compile(
    r"\b(\w+)\s*\(((?:[^()]|\([^()]*\))*)\)")


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
                 alloc_size_expr: str = "", alloc_pos: int = 0, line: int = 0):
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

    # 直接赋值: q = p (p 是堆指针)
    for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*;', code):
        lhs, rhs = m.group(1), m.group(2)
        if rhs in ptr_vars:
            ptr_vars.add(lhs)
            aliases.setdefault(lhs, set()).add(rhs)
            aliases[lhs].update(aliases.get(rhs, {rhs}))
        # 加法表达式: q = p + offset (指针算术, q 仍指向 p 的缓冲区)
        if re.match(r'(\w+)\s*\+\s*\d+', rhs):
            base = re.match(r'(\w+)', rhs).group(1)
            if base in ptr_vars:
                ptr_vars.add(lhs)
                aliases.setdefault(lhs, set()).add(base)
                aliases[lhs].update(aliases.get(base, {base}))

    # 传播闭包
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

        # 如果精确匹配失败, 尝试通过结构体字段匹配
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
    expr = re.sub(r'\s*\+\s*\w+', '', expr)  # 指针算术: buf + offset
    expr = expr.split('->')[0].split('.')[0].strip()
    return expr


# ================= 流相关配对 (原 flow_pair_generator) =================

def _sanitize_expr(expr: str) -> str:
    """去掉空白与多余括号, 作为后续等价比较的前置归一化."""
    return re.sub(r"\s+", "", expr).strip()


class CorrelatedPair:
    """流相关候选对: 分配点 + 写入点 + 各自大小表达式."""

    __slots__ = ("alloc_var", "alloc_func", "alloc_size_expr",
                 "write_func", "write_buffer", "write_size_expr",
                 "binding_conf", "reason", "alloc_line", "write_line",
                 "raw_buffer")

    def __init__(self, alloc_var: str, alloc_func: str, alloc_size_expr: str,
                 write_func: str, write_buffer: str, write_size_expr: str,
                 binding_conf: float, reason: str,
                 alloc_line: int, write_line: int, raw_buffer: str = ""):
        self.alloc_var = alloc_var
        self.alloc_func = alloc_func
        self.alloc_size_expr = alloc_size_expr
        self.write_func = write_func
        self.write_buffer = write_buffer
        self.write_size_expr = write_size_expr
        self.binding_conf = binding_conf
        self.reason = reason
        self.alloc_line = alloc_line
        self.write_line = write_line
        self.raw_buffer = raw_buffer or write_buffer

    def to_dict(self) -> Dict:
        return {
            "alloc_var": self.alloc_var,
            "alloc_func": self.alloc_func,
            "alloc_size_expr": self.alloc_size_expr,
            "write_func": self.write_func,
            "write_buffer": self.write_buffer,
            "raw_buffer": self.raw_buffer,
            "write_size_expr": self.write_size_expr,
            "binding_conf": round(self.binding_conf, 2),
            "reason": self.reason,
            "alloc_line": self.alloc_line,
            "write_line": self.write_line,
        }


def generate_correlated_pairs(code: str) -> List[CorrelatedPair]:
    """C0 主入口: 值流绑定生成候选对."""
    heap_ptrs = extract_heap_ptrs(code)
    if not heap_ptrs:
        return []

    write_sites = extract_write_sites(code)
    if not write_sites:
        return []

    aliases = build_ptr_aliases(code, heap_ptrs)
    bindings = bind_writes_to_allocs(heap_ptrs, write_sites, aliases)

    pairs: List[CorrelatedPair] = []
    for b in bindings:
        hp: HeapPtr = b["alloc_ptr"]
        ws: Dict = b["write_site"]
        conf = b.get("confidence", 0.60)
        reason = b.get("reason", "alias_bind")
        pairs.append(CorrelatedPair(
            alloc_var=hp.var,
            alloc_func=hp.alloc_func or "malloc",
            alloc_size_expr=_sanitize_expr(hp.alloc_size_expr)
            if hp.alloc_size_expr else "unknown",
            write_func=ws.get("func", "memcpy"),
            write_buffer=ws.get("buffer", ""),
            write_size_expr=_sanitize_expr(ws.get("size_expr", "unknown")),
            binding_conf=conf,
            reason=reason,
            alloc_line=hp.line,
            write_line=ws.get("line", 0),
            raw_buffer=ws.get("raw_buffer", ws.get("buffer", "")),
        ))

    pairs.sort(key=lambda p: p.binding_conf, reverse=True)

    # 同一 (缓冲区, 分配变量) 出现多个分配点 (realloc链/遮蔽) → 保留最新分配
    latest: Dict[Tuple[str, str], CorrelatedPair] = {}
    for p in pairs:
        key = (p.write_buffer, p.alloc_var)
        cur = latest.get(key)
        if cur is None or p.alloc_line > cur.alloc_line:
            latest[key] = p
    pairs = sorted(latest.values(), key=lambda p: p.binding_conf, reverse=True)
    return pairs


def correlate_to_v2_pairs(code: str, raw_pairs: List[Dict]) -> List[Dict]:
    """流相关配对 → v2 管线兼容格式 (P0.5-C 集成)."""
    if not code:
        return raw_pairs
    try:
        pairs = generate_correlated_pairs(code)
    except Exception:
        return raw_pairs
    if not pairs:
        return raw_pairs
    converted = []
    for p in pairs:
        wf = p.write_func
        risk = 0.90 if wf in ("gets", "manual_loop_write") else (
            0.85 if wf in ("strcpy", "strcat", "sprintf", "recv") else 0.60)
        converted.append({
            "alloc_func": p.alloc_func,
            "write_func": wf,
            "alloc_size_source": p.alloc_size_expr or "UNKNOWN",
            "write_size_source": p.write_size_expr or "UNKNOWN",
            "overflow_risk": round(min(1.0, risk + 0.2 * (p.binding_conf - 0.5)), 2),
            "reason": "P0.5-C:flow=" + p.reason,
            "same_dll": False,
            "__alloc_expr__": p.alloc_size_expr,
            "__write_expr__": p.write_size_expr,
            "__buffer__": p.write_buffer,
        })
    converted.sort(key=lambda x: x["overflow_risk"], reverse=True)
    return converted


# ================= 区间分析 (原 value_range_analyzer, 调用图所需部分) =================

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

    def join(self, o: "ValueRange") -> "ValueRange":
        if self.is_bottom:
            return o
        if o.is_bottom:
            return self
        return ValueRange(min(self.lo, o.lo), max(self.hi, o.hi))

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
            r"\b(?:int|unsigned|size_t|uint\d+_t|u?int\d+_t)\s+(\w+)\s*=\s*(\d+)\s*;", code):
        ranges[m.group(1)] = ValueRange.const(int(m.group(2)))

    for m in re.finditer(r"(\w+)\s*=\s*(\d+)\s*;", code):
        if m.group(1) not in ranges:
            ranges[m.group(1)] = ValueRange.const(int(m.group(2)))

    for m in re.finditer(
            r"(\w+)\s*=\s*(\w+)\s*\*\s*sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)\s*;", code):
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
            r"(\w+)\s*=\s*(?:\(\s*\w+(?:\s*\*)?\s*\)\s*)?atoi\s*\(\s*argv\s*\[", code):
        ranges[m.group(1)] = ValueRange.top()

    for m in re.finditer(
            r"(?:malloc|calloc|realloc)\s*\(\s*(\w+(?:\s*\*\s*\w+)?)\s*\)", code):
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


def apply_constraint(ranges: Dict[str, ValueRange], var: str,
                     op: str, value: int) -> Dict[str, ValueRange]:
    """应用数值约束 (来源: if/while 条件). op ∈ {lt, le, gt, ge, eq, ne}."""
    result = dict(ranges)
    if var not in result:
        return result
    rv = result[var]
    if rv.is_bottom or rv.is_top:
        return result
    _map = {"lt": (float("-inf"), value - 1), "le": (float("-inf"), value),
            "gt": (value + 1, float("inf")), "ge": (value, float("inf")),
            "eq": (value, value)}
    if op in _map:
        result[var] = rv.meet(ValueRange(_map[op][0], _map[op][1]))
    return result


def check_heap_overflow_by_range(
    alloc_range: ValueRange, write_range: ValueRange,
    alignment: int = 16, min_chunk_size: int = 32,
) -> Tuple[bool, float, str]:
    """核心判定: 分配范围 vs 写入范围 → (是否溢出, 置信度, 原因)."""
    if alloc_range.is_bottom or write_range.is_bottom:
        return (False, 0.05, "约束冲突→路径不可达")
    if alloc_range.is_top and write_range.is_top:
        return (False, 0.30, "双方范围均未知→无法判定")
    if (not alloc_range.is_top and not write_range.is_top and
            alloc_range.lo > write_range.hi + alignment):
        return (False, 0.02,
                f"alloc({alloc_range})≫write({write_range})→安全余量充足")
    if (not alloc_range.is_top and not write_range.is_top and
            alloc_range.lo >= write_range.hi):
        return (False, 0.08,
                f"alloc({alloc_range})≥write({write_range})→对齐补足→安全")
    if (not alloc_range.is_top and not write_range.is_top and
            alloc_range.hi < write_range.lo):
        return (True, 0.92,
                f"alloc({alloc_range})<write({write_range})→明确溢出")
    if (not alloc_range.is_top and not write_range.is_top and
            alloc_range.lo < write_range.lo <= alloc_range.hi < write_range.hi):
        return (True, 0.65,
                f"alloc({alloc_range})与write({write_range})重叠→可能溢出")
    if alloc_range.is_top:
        return (False, 0.35, "分配大小未知→保守安全")
    if write_range.is_top:
        return (True, 0.50, f"写入量未知,分配={alloc_range}→保守可疑")
    return (False, 0.25,
            f"范围重叠方向不明: alloc={alloc_range} write={write_range}")


# ================= 路径可行性 (原 path_feasibility_check, 调用图所需部分) =================

def extract_conditions(code: str) -> List[Dict]:
    """从代码中提取条件约束 (if/while/for)."""
    conds = []
    pat = re.compile(
        r"(?:if|while|for)\s*\(\s*"
        r"(\w+)\s*(<|<=|>|>=|==|!=)\s*"
        r"(\w+)\s*\)"
    )
    for m in pat.finditer(code):
        var, op, rhs = m.group(1), m.group(2), m.group(3)
        try:
            val = int(rhs)
        except ValueError:
            continue  # 忽略非常量比较
        conds.append({
            "var": var, "op": op, "value": val,
            "pos": m.start(), "negated": False,
        })
    return conds


def build_path_constraints(
    code: str,
    target_line: int = -1,
) -> Tuple[Dict[str, ValueRange], List[Dict]]:
    """从代码开头到 target_line, 累积路径约束."""
    ranges: Dict[str, ValueRange] = extract_value_ranges(code)
    infeasible: List[Dict] = []

    conds = extract_conditions(code)
    for c in conds:
        if target_line >= 0 and c["pos"] > target_line:
            continue

        var = c["var"]
        op = c["op"]
        val = c["value"]

        if var in ranges:
            rv = ranges[var]
            if op == "<":
                constrained = rv.meet(ValueRange(float("-inf"), val - 1))
            elif op == "<=":
                constrained = rv.meet(ValueRange(float("-inf"), val))
            elif op == ">":
                constrained = rv.meet(ValueRange(val + 1, float("inf")))
            elif op == ">=":
                constrained = rv.meet(ValueRange(val, float("inf")))
            elif op == "==":
                constrained = rv.meet(ValueRange(val, val))
            else:
                constrained = rv

            if constrained.is_bottom:
                infeasible.append({
                    "var": var, "op": op, "value": val,
                    "reason": f"约束 {var} {op} {val} 与范围 {rv} 冲突",
                })
            else:
                ranges[var] = constrained

    return ranges, infeasible


def check_write_reachability(
    code: str,
    write_func: str = "memcpy",
    alloc_func: str = "malloc",
) -> Dict:
    """检查写入点是否在分配点的可达路径上."""
    result = {
        "reachable": True,
        "has_guard": False,
        "guard_strength": 0.0,
        "overflow_possible": False,
        "confidence": 0.0,
        "reason": "",
    }

    guard_patterns = [
        re.compile(r"if\s*\(\s*(\w+)\s*[><]\s*sizeof\s*\(\s*(\w+)\s*\)"),
        re.compile(r"if\s*\(\s*(\w+)\s*>\s*(\w+)\s*\)\s*\w+\s*=\s*\w+"),
        re.compile(r"if\s*\(\s*(\w+)\s*==\s*0\s*\)\s*return"),
        re.compile(r"if\s*\(\s*(\w+)\s*>\s*(\w+)\s*\)\s*goto\s+\w+"),
    ]

    for pat in guard_patterns:
        if pat.search(code):
            result["has_guard"] = True
            result["guard_strength"] += 0.25

    result["guard_strength"] = min(result["guard_strength"], 1.0)

    ranges = extract_value_ranges(code)
    _, infeasible = build_path_constraints(code)

    alloc_range = ranges.get("__malloc_size__", ValueRange.top())
    write_range = ValueRange.top()
    write_matches = list(re.finditer(
        r"(?:memcpy|strncpy|read|recv)\s*\([^,]+,\s*[^,]+,\s*(\w+)\s*\)", code))
    if write_matches:
        wvar = write_matches[-1].group(1)
        write_range = ranges.get(wvar, ValueRange.top())

    overflow, conf, reason = check_heap_overflow_by_range(
        alloc_range, write_range)

    result["overflow_possible"] = overflow
    result["confidence"] = conf
    result["reason"] = reason

    if infeasible:
        result["reachable"] = False
        result["overflow_possible"] = False
        result["confidence"] = 0.05
        result["reason"] = f"路径不可达: {infeasible[0]['reason']}"

    return result


# ================= 分配器模型 (原 heap_layout_model) =================

class AllocatorModel:
    """抽象分配器模型: 给定请求大小, 返回有效用户可用空间的范围.

    x86_64 (glibc): align=16, min_chunk=32, header=16.
    """

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
        """用户请求 → chunk 整体大小 (含 header)."""
        mask = self.alignment - 1
        min_req = request + self.word_size  # + SIZE_SZ
        padded = (min_req + mask) & ~mask
        return max(self.min_chunk_size, padded)

    def usable_size_min(self, request: int) -> int:
        """用户请求 N 字节时, 最小的可用用户空间."""
        chunk = self.requested_to_chunk_size(request)
        return max(self.min_user_size, chunk - 2 * self.word_size)

    def usable_size_max(self, request: int) -> int:
        """用户请求 N 字节时, 最大的可用用户空间 (保守 +alignment)."""
        return self.usable_size_min(request) + self.alignment

    def check_overflow_under_alignment(self, alloc_request: int,
                                        write_size: int) -> Tuple[bool, float, str]:
        """精确检查: 给定分配请求值和写入量, 考虑分配器对齐后是否溢出.

        返回: (is_overflow, confidence, reason)
        """
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

    def compute_safe_write_limit(self, alloc_request: int) -> int:
        """给定分配请求, 返回保证安全的写入上限 (字节数)."""
        return self.usable_size_min(alloc_request)


_MODEL_CACHE: Dict[str, AllocatorModel] = {}


def get_allocator_model(arch: str = "x86_64") -> AllocatorModel:
    if arch not in _MODEL_CACHE:
        if arch in ("i386", "x86", "arm32", "arm"):
            _MODEL_CACHE[arch] = AllocatorModel.i386()
        else:
            _MODEL_CACHE[arch] = AllocatorModel.x86_64()
    return _MODEL_CACHE[arch]


# ================= 安全见证 (原 v2_safety_filter) =================

_SAFE = {"snprintf", "memcpy_s", "strcpy_s", "strncpy", "strncat",
         "__memcpy_chk", "__sprintf_chk", "__fread_chk", "__recv_chk"}


def _n(fname: str) -> str:
    return fname.lower().rstrip("aw")


def safety_filter(findings: List[Dict], checksec: Dict,
                  imports: Dict) -> List[Dict]:
    """P4 安全性见证过滤: 基于导入表的安全变体与 FORTIFY 证据做置信度压制."""
    api_set = set()
    all_imps = imports.get("all_imports", imports) \
        if isinstance(imports, dict) else {}
    if isinstance(all_imps, dict):
        for funcs in all_imps.values():
            if isinstance(funcs, list):
                api_set.update(_n(f) for f in funcs)
    has_safe = bool(api_set & _SAFE)
    has_fort = checksec.get("fortify") or checksec.get("fortify_source") or \
               any("_chk" in f for f in api_set)
    for f in findings:
        if has_safe:
            f["confidence"] = round(max(0.05, f["confidence"] - 0.25), 2)
        if has_fort:
            f["confidence"] = round(max(0.05, f["confidence"] - 0.15), 2)
    return [f for f in findings if f["confidence"] >= 0.10]


# ================= PSVR-HLM v3.0 管线 (原 heap_overflow_v2) =================

_ALLOC = {"malloc", "calloc", "realloc", "alloca", "__imp_malloc",
          "__imp_calloc", "__imp_realloc",
          "HeapAlloc", "GlobalAlloc", "LocalAlloc"}
_WRITE = {"memcpy", "memmove", "strcpy", "strcat", "strncpy", "strncat",
          "sprintf", "snprintf", "vsprintf", "read", "fread", "recv",
          "gets", "scanf", "fgets", "__imp_memcpy", "__imp_strcpy",
          "__imp_sprintf", "_read", "wcscpy", "_memcpy", "_strcpy"}
_INPUT = {"recv", "read", "fread", "scanf", "gets", "fgets", "recvfrom",
          "recvmsg", "fscanf", "getchar"}


def _source_safety(code: str, af: str, wf: str, alloc_expr: str,
                   write_expr: str, ranges: Dict) -> Tuple[float, str]:
    """P0.5 源码安全模式检测, 返回 (罚分, 依据)."""
    penalty, reasons = 0.0, []
    fn = _n(wf).replace("__imp_", "")
    # 1. 相同表达式 → 常量/sizeof/含sizeof宏=安全; 纯变量同名=危险
    if alloc_expr and write_expr and alloc_expr == write_expr:
        if bool(re.match(r'^(sizeof\s*\(|[0-9]+$)', alloc_expr)) \
                or 'sizeof' in alloc_expr:
            penalty += 0.50
            reasons.append("identical_safe_expr")
    # 2. 循环守卫
    if re.search(r'if\s*\([^)]*\+\s*\w+\s*[>]\s*\w+[^)]*\)\s*break', code):
        penalty += 0.45
        reasons.append("loop_guard_break")
    # 3. 三元守卫/min() 上界
    if re.search(r'[?]\s*\w+\s*:', code) or 'min(' in code:
        penalty += 0.45
        reasons.append("ternary_guard")
    # 4. realloc 安全增长 (写size匹配realloc新size)
    if 'realloc' in code.lower():
        rp, wp = code.lower().find('realloc'), code.lower().find(fn)
        if 0 <= rp < wp:
            rm = re.search(r'realloc\s*\([^,]+,\s*([^,)]+)\s*\)', code)
            if rm and rm.group(1).strip() == write_expr:
                penalty += 0.45
                reasons.append("realloc_grow_safe")
    # 5. sizeof 匹配
    if alloc_expr and write_expr:
        sa = set(re.findall(r'sizeof\s*\(\s*\w+', alloc_expr))
        sw = set(re.findall(r'sizeof\s*\(\s*\w+', write_expr))
        if sa and sa == sw:
            penalty += 0.30
            reasons.append("sizeof_match")
    return penalty, ";".join(reasons)


def _in_loop(code: str, wf: str) -> bool:
    fn = _n(wf).replace("__imp_", "")
    m = re.search(rf'\b{fn}\s*\(', code)
    return bool(m and re.search(r'\b(for|while)\s*\(', code[:m.start()]))


def _has_loop_accumulation(code: str) -> bool:
    return bool(re.search(r'(\w+)\s*\+=\s*(\w+)\s*;', code))


def _make_pairs(imports: Dict, checksec: Dict) -> List[Dict]:
    """P0: 导入配对 (二进制模式)."""
    api_set, dll_funcs = set(), {}
    all_imps = imports.get("all_imports", imports) \
        if isinstance(imports, dict) else {}
    if isinstance(all_imps, dict):
        for dll, funcs in all_imps.items():
            if isinstance(funcs, list):
                ns = {_n(f) for f in funcs}
                api_set.update(ns)
                dll_funcs[dll] = ns
    a_in = {f for f in api_set if f in _ALLOC or
            any(a in f for a in ["malloc", "calloc", "realloc", "heapalloc"])}
    w_in = {f for f in api_set if f in _WRITE or
            any(w in f for w in ["memcpy", "strcpy", "sprintf", "memmove",
                                 "strncpy", "recv", "fread", "gets", "scanf",
                                 "strcat", "snprintf", "fgets"])}
    if not a_in or not w_in:
        return []
    has_inp = bool(api_set & _INPUT)
    has_fort = checksec.get("fortify") or checksec.get("fortify_source") or \
               bool({f for f in api_set if "_chk" in f})
    pairs = []
    for af in sorted(a_in):
        for wf in sorted(w_in):
            risk = 0.85 if has_inp else 0.55
            reason = "P0:pair"
            sd = any(af in fns and wf in fns for fns in dll_funcs.values())
            if sd:
                risk += 0.10
                reason += "+sameDLL"
            if has_fort:
                risk = max(0.05, risk - 0.20)
                reason += "+FORTIFY"
            pairs.append({"alloc_func": af, "write_func": wf,
                          "alloc_size_source": "INPUT_DERIVED" if has_inp
                          else "UNKNOWN",
                          "write_size_source": "INPUT_DERIVED" if has_inp
                          else "UNKNOWN",
                          "overflow_risk": round(min(risk, 1.0), 2),
                          "reason": reason, "same_dll": sd})
    pairs.sort(key=lambda p: p["overflow_risk"], reverse=True)
    return pairs


def _make_pairs_from_code(code: str, checksec: Dict) -> List[Dict]:
    """P0-fallback: 源码直接提取函数对 (无二进制导入时使用)."""
    a_funcs = set(re.findall(
        r'\b(malloc|calloc|realloc|alloca|HeapAlloc)\s*\(', code))
    w_funcs = set(re.findall(
        r'\b(memcpy|memmove|strcpy|strcat|strncpy|strncat|sprintf|'
        r'snprintf|vsprintf|read|fread|recv|gets|scanf|fgets|'
        r'wcscpy|_read|_memcpy|_strcpy)\s*\(', code))
    if not a_funcs:
        return []
    has_inp = bool(re.search(
        r'\b(recv|read|fread|scanf|gets|fgets|fscanf|getchar)\s*\(', code))
    has_fort = checksec.get("fortify") or checksec.get("fortify_source") or \
               bool(re.search(r'\b\w+_chk\s*\(', code))
    pairs = []
    if w_funcs:
        for af in sorted(a_funcs):
            for wf in sorted(w_funcs):
                risk = 0.85 if has_inp else 0.55
                reason = "P0:code_pair"
                if has_fort:
                    risk = max(0.05, risk - 0.20)
                    reason += "+FORTIFY"
                pairs.append({"alloc_func": af, "write_func": wf,
                              "alloc_size_source": "INPUT_DERIVED" if has_inp
                              else "UNKNOWN",
                              "write_size_source": "INPUT_DERIVED" if has_inp
                              else "UNKNOWN",
                              "overflow_risk": round(min(risk, 1.0), 2),
                              "reason": reason, "same_dll": True})
    # 手动逐字节循环写入检测: while/for体内arr[idx++]=...且arr由malloc分配
    for lm in re.finditer(r'(?:while|for)\s*\([^)]*\)\s*\{', code):
        d, p, body_s = 1, lm.end(), lm.end()
        while d > 0 and p < len(code):
            if code[p] == '{':
                d += 1
            elif code[p] == '}':
                d -= 1
            p += 1
        for am in re.finditer(r'(\w+)\s*\[[^\]]*\+\+[^\]]*\]\s*=',
                              code[body_s:p-1]):
            an = am.group(1)
            if an not in a_funcs and re.search(
                    rf'\b{an}\s*=\s*(?:malloc|calloc|realloc)\s*\(', code):
                pairs.append({"alloc_func": "manual_loop_alloc",
                              "write_func": "manual_loop_write",
                              "alloc_size_source": "VARIABLE",
                              "write_size_source": "LOOP_BOUNDED",
                              "overflow_risk": 0.90,
                              "reason": "P0:manual_loop_write",
                              "same_dll": True,
                              "manual_loop_target": an})
    pairs.sort(key=lambda p: p["overflow_risk"], reverse=True)
    return pairs


def _infer_size_expr(code: str, func_name: str, is_alloc: bool) -> str:
    """从源码推断分配/写入大小表达式."""
    fn = _n(func_name).replace("__imp_", "")
    if is_alloc:
        if fn == "calloc":
            m = re.search(
                r"(?:calloc|__imp_calloc)\s*\(\s*([^,]+)\s*,\s*([^,)]+)\s*\)",
                code)
            if m:
                return f"{m.group(1).strip()} * {m.group(2).strip()}"
        if fn == "realloc":
            m = re.search(
                r"(?:realloc|__imp_realloc)\s*\([^,]+,\s*([^,)]+)\s*\)", code)
            if m:
                return m.group(1).strip()
    else:
        if fn in ("memcpy", "memmove", "strncpy", "strncat"):
            m = re.search(
                rf"(?:{fn}|__imp_{fn})\s*\([^,]+,\s*[^,]+,\s*([^,)]+)\s*\)",
                code)
            if m:
                return m.group(1).strip()
        if fn in ("read", "recv", "_read", "fread"):
            m = re.search(
                rf"(?:{fn}|__imp_{fn})\s*\([^,]+,\s*[^,]+,\s*([^,)]+)\s*\)",
                code)
            if m:
                return m.group(1).strip()
        if fn in ("strcpy", "strcat", "sprintf", "gets"):
            return "unbounded"
    # 通用回退
    m = re.search(
        r"(?:malloc|calloc|realloc|__imp_malloc|__imp_calloc|__imp_realloc|"
        r"memcpy|strcpy|sprintf|strncpy|memmove|read|recv|fread)"
        r"\s*\(\s*([^,)]+)\s*\)", code)
    if m:
        if is_alloc:
            return m.group(1).strip()
        m2 = re.search(
            r"(?:memcpy|memmove|strncpy)\s*\([^,]+,\s*[^,]+,\s*([^,)]+)\s*\)",
            code)
        if m2:
            return m2.group(1).strip()
        m3 = re.search(
            r"(?:read|recv|fread)\s*\([^,]+,\s*[^,]+,\s*([^,)]+)\s*\)", code)
        if m3:
            return m3.group(1).strip()
    return "unknown"


def _eval_range(expr: str, ranges: Dict[str, ValueRange]) -> ValueRange:
    expr = expr.strip()
    if expr in ("unbounded", "unknown"):
        return ValueRange.top()
    try:
        return ValueRange.const(int(expr))
    except ValueError:
        pass
    smap = {"char": 1, "short": 2, "int": 4, "long": 4, "long long": 8,
            "float": 4, "double": 8, "void*": 4, "size_t": 4}
    m = re.match(r"sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)", expr)
    if m:
        return ValueRange.const(smap.get(m.group(1).strip().replace(" ", ""), 4))
    m = re.match(r"(\w+)\s*\*\s*(\w+)", expr)
    if m:
        a = _parse_or_top(m.group(1), ranges)
        b = _parse_or_top(m.group(2), ranges)
        return a.mul(b)
    m = re.match(r"(\w+)\s*\*\s*sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)", expr)
    if m:
        t = m.group(2).strip().replace(" ", "")
        return ranges.get(m.group(1), ValueRange.top()).mul(
            ValueRange.const(smap.get(t, 4)))
    return ranges.get(expr, ValueRange.top())


def _parse_or_top(s: str, ranges: Dict[str, ValueRange]) -> ValueRange:
    try:
        return ValueRange.const(int(s))
    except ValueError:
        return ranges.get(s, ValueRange.top())


def detect_heap_overflow_v2(
    code: str = "", imports: Dict = None, strings: List[str] = None,
    checksec: Dict = None, min_confidence: float = 0.25, func_name: str = "",
) -> Dict:
    """PSVR-HLM v3.0 主检测入口."""
    imports = imports or {}
    strings = strings or []
    checksec = checksec or {}
    alloc_model = get_allocator_model(checksec.get("arch", "x86_64"))
    raw_pairs = _make_pairs(imports, checksec)
    if not raw_pairs and code:
        raw_pairs = _make_pairs_from_code(code, checksec)
    if raw_pairs:
        raw_pairs = correlate_to_v2_pairs(code, raw_pairs)
    if not raw_pairs:
        return {"findings": [],
                "stats": {"total": 0, "high_conf": 0, "medium_conf": 0,
                          "low_conf": 0, "avg_confidence": 0},
                "method": "PSVR-HLM-v3.0",
                "pipeline": ["P0: no pairs"], "fp_reduction_pct": 0.0,
                "vra_stats": {"pairs_analyzed": 0, "definitely_safe": 0,
                              "range_checked": 0, "layout_checked": 0},
                "false_positive_mitigations": {}}
    vra_stats = {"pairs_analyzed": len(raw_pairs), "definitely_safe": 0,
                 "range_checked": 0, "layout_checked": 0}
    pipeline_log, findings = [f"P0: {len(raw_pairs)} pairs"], []
    ranges = extract_value_ranges(code) if code else {}
    pipeline_log.append(f"P1(VRA): {len(ranges)} vars" if (code and ranges)
                        else "P1(VRA): skipped (no code)")
    # P0.5: 源码引导 — 惩罚导入中有但源码中无的函数
    sfx = {p for p in ["malloc", "calloc", "realloc", "memcpy", "strcpy",
                       "sprintf", "strncpy", "memmove", "read", "recv",
                       "fread"] if code and re.search(r'\b' + p + r'\s*\(', code)}
    for pair in raw_pairs:
        base_conf, reason_parts = pair["overflow_risk"], [pair.get("reason", "")]
        if code and sfx:
            afn = _n(pair["alloc_func"]).replace("__imp_", "")
            wfn = _n(pair["write_func"]).replace("__imp_", "")
            if afn not in sfx and wfn not in sfx:
                base_conf = max(0.03, base_conf - 0.40)
                reason_parts.append("src:neither")
            elif afn not in sfx:
                base_conf = max(0.03, base_conf - 0.25)
                reason_parts.append(f"src:!{afn}")
        # P1: VRA + 循环感知
        if code and ranges:
            vra_stats["range_checked"] += 1
            is_manual = pair.get("write_func") == "manual_loop_write"
            alloc_expr = pair.get("__alloc_expr__") or \
                _infer_size_expr(code, pair["alloc_func"], True)
            write_expr = "unbounded" if is_manual else \
                (pair.get("__write_expr__") or
                 _infer_size_expr(code, pair["write_func"], False))
            alloc_range = _eval_range(alloc_expr, ranges)
            write_range = ValueRange.top() if is_manual \
                else _eval_range(write_expr, ranges)
            in_loop, loop_widened = (True, True) if is_manual else \
                (_in_loop(code, pair["write_func"]), False)
            if in_loop and _has_loop_accumulation(code):
                # 循环累积: 写入区间拓宽为 unbounded
                write_range = ValueRange(write_range.lo, float("inf"))
                reason_parts.append("loop_accum:write→unbounded")
                loop_widened = True
            overflow, vra_conf, vra_reason = check_heap_overflow_by_range(
                alloc_range, write_range)
            if not overflow and vra_conf < 0.10 and not in_loop:
                vra_stats["definitely_safe"] += 1
                continue
            if not overflow:
                if not loop_widened and not (alloc_range.is_top
                                             and write_range.is_top):
                    base_conf = max(0.03, base_conf - 0.50)
                reason_parts.append(f"VRA:{vra_reason}")
            # P2: HLM
            if alloc_range.is_const and write_range.is_const:
                vra_stats["layout_checked"] += 1
                av, wv = alloc_range.const_value, write_range.const_value
                if av is not None and wv is not None:
                    lo, lc, lr = alloc_model.check_overflow_under_alignment(av, wv)
                    if not lo:
                        base_conf = max(0.03, base_conf - 0.40)
                        reason_parts.append(f"HLM:{lr}")
                    elif lc > 0.70:
                        base_conf = min(0.95, base_conf + 0.10)
                        reason_parts.append(f"HLM:{lr}")
            # P0.5b: 源码安全模式
            sp, sr = _source_safety(code, pair["alloc_func"],
                                    pair["write_func"], alloc_expr,
                                    write_expr, ranges)
            if sp > 0:
                base_conf = max(0.03, base_conf - sp)
                reason_parts.append(f"Safe:{sr}")
        # P3: PFC
        if code:
            pr = check_write_reachability(
                code, pair["write_func"], pair["alloc_func"])
            if pr.get("has_guard"):
                base_conf = max(0.05, base_conf - pr["guard_strength"] * 0.35)
                reason_parts.append(f"PFC:g={pr['guard_strength']:.2f}")
            if not pr.get("reachable", True):
                base_conf = max(0.05, base_conf - 0.50)
                reason_parts.append("PFC:unreach")
        if pair.get("alloc_size_source") == "CONSTANT" and \
                pair.get("write_size_source") == "CONSTANT":
            base_conf = max(0.03, base_conf - 0.35)
        if "calloc" in pair["alloc_func"].lower():
            base_conf = max(0.03, base_conf - 0.05)
        if base_conf >= min_confidence:
            findings.append({"type": "heap-overflow", "cwe": "CWE-122",
                             "alloc_func": pair["alloc_func"],
                             "write_func": pair["write_func"],
                             "alloc_size_source":
                                 pair.get("alloc_size_source", "UNKNOWN"),
                             "write_size_source":
                                 pair.get("write_size_source", "UNKNOWN"),
                             "confidence": round(base_conf, 2),
                             "severity": "High" if base_conf > 0.60
                             else "Medium",
                             "reason": "; ".join(reason_parts),
                             "same_dll": pair.get("same_dll", False)})
    # P4: 安全见证
    if checksec:
        findings = safety_filter(findings, checksec, imports)
    findings.sort(key=lambda f: f["confidence"], reverse=True)
    hi = sum(1 for f in findings if f["confidence"] >= 0.70)
    med = sum(1 for f in findings if 0.35 <= f["confidence"] < 0.70)
    lo = sum(1 for f in findings if f["confidence"] < 0.35)
    fp_red = (1.0 - len(findings) / max(len(raw_pairs), 1)) * 100
    pipeline_log.append(f"Final: {len(findings)}f ({hi}H/{med}M/{lo}L)")
    tot = len(findings)
    return {"findings": findings,
            "stats": {"total": tot, "high_conf": hi, "medium_conf": med,
                      "low_conf": lo,
                      "avg_confidence":
                          round(sum(f["confidence"] for f in findings)
                                / max(tot, 1), 3)},
            "alloc_write_pairs_total": len(raw_pairs),
            "method": "PSVR-HLM-v3.0",
            "pipeline": pipeline_log,
            "fp_reduction_pct": round(fp_red, 1),
            "vra_stats": vra_stats,
            "false_positive_mitigations": vra_stats}


__all__ = [
    "ValueRange", "extract_value_ranges", "check_heap_overflow_by_range",
    "AllocatorModel", "get_allocator_model",
    "check_write_reachability", "build_path_constraints",
    "HeapPtr", "extract_heap_ptrs", "extract_write_sites",
    "build_ptr_aliases", "bind_writes_to_allocs",
    "generate_correlated_pairs", "correlate_to_v2_pairs",
    "safety_filter", "detect_heap_overflow_v2",
]
