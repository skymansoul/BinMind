# analysis/pointer_tracker.py — 轻量级堆指针流追踪
# 追踪 "malloc → 指针变量 → memcpy 目标" 的数据流, 替换粗粒度的导入表配对。
# 核心目的: 消除 P0 中 "malloc+memcpy 共存于导入表" 导致的跨缓冲区误报。
#
# 方法: 基于赋值传播的指针分析, 仅限堆指针:
#   - 识别 malloc/calloc/realloc 的接收变量
#   - 沿着赋值链传播指针身份: p = q; memcpy(p, ...) → memcpy 操作的是 q 的缓冲区
#   - 区分 "同一缓冲区多次写入" 和 "不同缓冲区各自写入"
#
# 理论依据: 堆分配点间不交集 — 区分不同堆分配点是降低误报的核心;
# 指针分析基于并查集式传播, 近线性复杂度。
# 不追求完整指针分析, 只追踪堆分配产生的指针到其消费点。

from __future__ import annotations
from typing import Dict, List, Set, Tuple, Optional
import re

# 带平衡括号的调用匹配 (一层嵌套, 覆盖 sizeof(int)/min(a,b))
_CALL_RE = re.compile(
    r"\b(\w+)\s*\(((?:[^()]|\([^()]*\))*)\)")

def _split_top_level(s: str) -> List[str]:
    """按顶层逗号切分参数 (括号深度跟踪)。"""
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
    """返回 [(func, args, pos), ...] 所有调用。"""
    out = []
    for m in _CALL_RE.finditer(code):
        out.append((m.group(1), _split_top_level(m.group(2)), m.start()))
    return out

class HeapPtr:
    """堆指针: 分配点 + 变量名 + 可达别名集合。"""
    __slots__ = ("var", "alloc_func", "alloc_size_expr", "alloc_pos", "aliases", "line")

    def __init__(self, var: str, alloc_func: str = "", alloc_size_expr: str = "",
                 alloc_pos: int = 0, line: int = 0):
        self.var = var
        self.alloc_func = alloc_func
        self.alloc_size_expr = alloc_size_expr
        self.alloc_pos = alloc_pos
        self.aliases: Set[str] = {var}
        self.line = line

    def __repr__(self) -> str:
        return f"HeapPtr({self.var}, aliases={self.aliases})"

def extract_heap_ptrs(code: str) -> List[HeapPtr]:
    """从代码中提取所有堆分配点及其接收变量。

    覆盖:
    - ptr = malloc(size) / ptr = (type*)malloc(size)
    - ptr = calloc(n, size) / ptr = realloc(old, size)
    - ptr[index] = (type*)malloc(...) — 数组元素分配
    """
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
    """按函数语义取写入量表达式。"""
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
    """从代码中提取所有内存写入点。

    返回每个写入点的: 缓冲区变量、写入函数、写入量表达式、位置。
    """
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
            if code[p] == '{': d += 1
            elif code[p] == '}': d -= 1
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
    """为堆指针构建别名传播图。

    追踪:
    - 直接赋值: q = p; (q 成为 p 的别名)
    - 结构体字段: p->field → 仍指向 p 的缓冲区
    - 数组索引: handlers[id] → 根数组名
    - 函数参数传递: foo(ptr) → 进入另一个函数, 此处不追踪
    """
    # 初始化: 每个堆指针变量已知自己
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
    # FIXME: 别名仅在函数内传播; 跨函数参数/返回值的指针别名未展开, 可能漏检
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
    """将写入点绑定到对应的分配点。

    对每个写入点的 buffer 变量, 查找其别名集合,
    然后找到产生该别名集合中变量的分配点。

    返回 [(alloc_ptr, write_site, confidence), ...]
    """
    bindings = []

    # 构建 var → HeapPtr 映射
    ptr_map: Dict[str, HeapPtr] = {}
    for hp in heap_ptrs:
        ptr_map[hp.var] = hp
        for a in hp.aliases:
            ptr_map[a] = hp

    for ws in write_sites:
        buf = ws["buffer"]
        raw = ws.get("raw_buffer", buf)

        # 直接从别名图找
        buf_aliases = aliases.get(buf, {buf})

        # 查找匹配的分配点
        matched = []
        for hp in heap_ptrs:
            hp_aliases = aliases.get(hp.var, {hp.var})
            # 缓冲区变量属于此分配点的别名集
            if buf in hp_aliases or buf_aliases & hp_aliases:
                matched.append(hp)
            # 或者原始 buffer (带索引) 的基变量匹配
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
                "reason": "exact_alias" if len(matched) == 1 else f"shared_alias({len(matched)} candidates)",
            })

    return bindings

def _base_var(expr: str) -> str:
    """归一化指针表达式: 去掉数组索引、结构体字段访问、指针算术。
    'handlers[id]'→'handlers', 'obj->data'→'obj',
    'buf+offset'→'buf', 'ptr + 8'→'ptr', 'arr[*]'→'arr'"""
    expr = re.sub(r'\[[^\]]*\]', '', expr)
    expr = re.sub(r'\s*\+\s*\w+', '', expr)  # 指针算术: buf + offset
    expr = expr.split('->')[0].split('.')[0].strip()
    return expr

def get_allocation_map(code: str) -> Dict[str, Dict]:
    """对外接口: 返回完整的分配点→缓冲区映射。

    返回: {buffer_name: {alloc_func, size_expr, line, aliases}}
    """
    heap_ptrs = extract_heap_ptrs(code)
    aliases = build_ptr_aliases(code, heap_ptrs)

    result = {}
    for hp in heap_ptrs:
        result[hp.var] = {
            "alloc_func": hp.alloc_func,
            "size_expr": hp.alloc_size_expr,
            "line": hp.line,
            "aliases": sorted(aliases.get(hp.var, {hp.var})),
        }
    return result
