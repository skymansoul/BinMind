"""
结构体数组索引写入检测. 目标模式:

  typedef struct { int h; char d[64]; } Item;
  Item* b = malloc(n * sizeof(Item));
  for (i = 0; i <= n; i++) b[i].h = i;

堆写模式验证的 find_writes 对 `b[i].field = v` 的检测依赖 `arr[const].field`
正则, 变量索引 b[i] 落入 loop_write, 但 loop_write 分支只按字节估算,
未按元素大小 × 索引上界计算 — 导致:
  a) 结构体数组 off-by-one (i<=n, 写 n+1 个元素) 漏检
  b) 正确边界 (i<n) 反被误报为循环溢出

本模块含: 类型大小解析, 循环边界/守卫上界推断, 写入候选收集
(含别名/跨函数解析), 越界判定 (含结构 off-by-one 证明).
"""

import re
from typing import Dict, List, Optional, Tuple

from analysis.heap_write_ext_types import ExtAlloc, ExtResult
from analysis.heap_overflow_src_patterns import _is_comment_or_empty

# 元素大小解析: malloc(n * sizeof(T))
_ELEM_ALLOC_RE = re.compile(
    r'(\w[\w]*)\s*=\s*(?:\(\s*\w[\w]*\s*\*\s*\)\s*)?'
    r'malloc\s*\(\s*(\w+)\s*\*\s*sizeof\s*\(\s*(\w+)\s*\)\s*\)')
# 变量索引结构体字段写: b[i].field = v  /  b[i]->field = v
_STRUCT_IDX_WRITE_RE = re.compile(
    r'(\w[\w]*)\s*\[\s*([^\]\d][^\]]*)\s*\]\s*(?:->|\.)\s*(\w[\w]*)\s*=')
# 常量索引结构体写: p[5].h = v — 索引可为数字
_STRUCT_IDX_CONST_RE = re.compile(
    r'(\w[\w]*)\s*\[\s*(\d+)\s*\]\s*(?:->|\.)\s*(\w[\w]*)\s*=')
# 指针别名带偏移: p = arr + 3
_ALIAS_OFFSET_RE = re.compile(
    r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*\+\s*(\d+)\s*;')
# 变量索引普通元素写: b[i] = v
_ARRAY_IDX_WRITE_RE = re.compile(
    r'(\w[\w]*)\s*\[\s*([^\]\d][^\]]*)\s*\]\s*=')
# 索引上界: for(i=0; i<=N; i++) → 取 N+1;  for(i=0; i<N; i++) → N
_LOOP_LE_RE = re.compile(
    r'for\s*\(\s*(?:int\s+)?(\w+)\s*=\s*0\s*;\s*\1\s*<=\s*(\w+)\s*;')
_LOOP_LT_RE = re.compile(
    r'for\s*\(\s*(?:int\s+)?(\w+)\s*=\s*0\s*;\s*\1\s*<\s*(\w+)\s*;')
# 元素类型大小查询表 (内置)
_BUILTIN_SIZEOF = {
    'char': 1, 'int': 4, 'long': 8, 'short': 2, 'float': 4,
    'double': 8, 'size_t': 8, 'void': 0, 'long long': 8,
    'unsigned': 4, 'unsigned int': 4, 'unsigned long': 8,
    'unsigned char': 1, 'unsigned short': 2, 'long int': 8,
    'bool': 1, '_Bool': 1, 'int8_t': 1, 'uint8_t': 1,
    'int16_t': 2, 'uint16_t': 2, 'int32_t': 4, 'uint32_t': 4,
    'int64_t': 8, 'uint64_t': 8, 'char*': 8, 'void*': 8,
    'int*': 8, 'long*': 8, 'short*': 8, 'float*': 8, 'double*': 8,
    'size_t*': 8, 'uint8_t*': 8, 'uint32_t*': 8, 'uint64_t*': 8,
}


def resolve_elem_size(struct_type: str, lines: List[str],
                      line: int) -> int:
    """解析结构体类型大小. 从 typedef struct 定义累加字段.

    支持两种形态:
      a) 单行: typedef struct { int h; char d[64]; } Item;
      b) 多行: typedef struct { ... } Item;
    含数组字段按 类型*个数 累计; 嵌套结构体按保守估算.
    返回 -1 表示无法解析.
    """
    if struct_type in _BUILTIN_SIZEOF:
        return _BUILTIN_SIZEOF[struct_type]
    # 全文件搜索 typedef struct ... Item 定义
    for i in range(len(lines)):
        t = lines[i].strip()
        if 'typedef' not in t or 'struct' not in t or struct_type not in t:
            continue
        total = 0
        if t.startswith('typedef struct {') and '} ' in t:
            # 单行定义
            body = t[len('typedef struct {'):]
            body = body.split('}')[0]
            total = _sum_fields(body)
            if total > 0:
                return total
            return -1
        # 多行定义
        if 'typedef struct' in t and '{' in t:
            for j in range(i + 1, min(len(lines), i + 60)):
                ft = lines[j].strip()
                if '}' in ft and struct_type in ft:
                    return total if total > 0 else -1
                total += _sum_fields(ft)
            return total if total > 0 else -1
    return -1


def _sum_fields(body: str) -> int:
    """累加字段大小: 解析 `类型 名称[可选长度];` 片段."""
    total = 0
    for m in re.finditer(r'(\w+)\s+(\w+)(?:\[(\d+)\])?\s*;', body):
        base = _BUILTIN_SIZEOF.get(m.group(1), 8)
        n = int(m.group(3)) if m.group(3) else 1
        total += base * n
    return total


def _extract_index_bound(idx_expr: str, write_line: int,
                         lines: List[str]) -> Optional[int]:
    """提取索引上界.

    idx_expr 为循环变量名时, 从包围循环解析:
      i<=N  → N+1 ;  i<N  → N
    N 为常量返回整数; N 为变量则尝试解析其常量赋值.

    TODO: 复合索引表达式 (i*2+1) 直接返回 None 保守保留, 未做
    仿射展开. 多元素步进场景会漏判.
    """
    var = idx_expr.strip()
    if not re.match(r'^[a-zA-Z_]\w*$', var):
        # 复合表达式 (i*2+1) — 暂不支持, 保守
        return None
    for i in range(max(0, write_line - 8), write_line):
        t = lines[i].strip()
        if _is_comment_or_empty(t):
            continue
        m = _LOOP_LE_RE.search(t)
        if m and m.group(1) == var:
            return _bound_int(m.group(2), lines, i) + 1
        m = _LOOP_LT_RE.search(t)
        if m and m.group(1) == var:
            return _bound_int(m.group(2), lines, i)
    return None


def _bound_int(v: str, lines: List[str], line: int) -> int:
    """解析循环上界变量 → 常量 (含 -1 表示未知).

    支持: 数字 / 前文常量赋值 / 守卫上限 if(n<=K) / 函数参数实参.
    """
    if re.match(r'^\d+$', v):
        return int(v)
    for j in range(line - 1, -1, -1):
        t = lines[j].strip()
        if _is_comment_or_empty(t):
            continue
        am = re.search(rf'\b{re.escape(v)}\s*=\s*(\d+)\s*;', t)
        if am:
            return int(am.group(1))
        # 守卫上限: if(n<=K) 或 if(n < K)
        gm = re.search(
            rf'if\s*\(\s*{re.escape(v)}\s*(<=|<)\s*(\d+)\s*\)', t)
        if gm:
            k = int(gm.group(2))
            return k + 1 if gm.group(1) == '<' else k
        # 函数签名参数: v 是某函数参数 → 找调用点实参
        sig_re = re.compile(
            r'^[\w\s\*]+?\b(\w[\w]*)\s*\(([^)]*)\)\s*\{')
        sm = sig_re.match(t)
        if sm:
            params = [p.strip().split()[-1].rstrip('*').strip()
                      for p in sm.group(2).split(',') if p.strip()]
            if v in params:
                idx = params.index(v)
                for k in range(len(lines) - 1, -1, -1):
                    tk = lines[k].strip()
                    cm = re.search(
                        r'\b' + re.escape(sm.group(1)) +
                        r'\s*\(([^;)]*)\)\s*;', tk)
                    if cm:
                        args = [a.strip().lstrip('&').lstrip('*')
                                for a in cm.group(1).split(',')]
                        if idx < len(args):
                            return _bound_int(args[idx], lines, k + 1)
    return -1


def _loop_is_le(write_line: int, var: str, lines: List[str]) -> Optional[bool]:
    """判断包围循环对 var 的比较是否为 <= (off-by-one 信号).

    var 为循环变量 (如 i), 检测 `i<=N` 或 `i<N`.
    返回 True 表示 <=, False 表示 <, None 表示无法确定.
    """
    for i in range(max(0, write_line - 8), write_line):
        t = lines[i].strip()
        if _is_comment_or_empty(t):
            continue
        m = _LOOP_LE_RE.search(t)
        if m and m.group(1) == var:
            return True
        m = _LOOP_LT_RE.search(t)
        if m and m.group(1) == var:
            return False
    return None


def _loop_bound_var(write_line: int, var: str, lines: List[str]
                    ) -> Optional[Tuple[str, bool]]:
    """提取循环上界变量与比较符: 返回 (bound_var, is_le).

    如 `for(i=0; i<=n; i++)` → ('n', True); `for(i=0; i<n; i++)` → ('n', False).
    """
    for i in range(max(0, write_line - 8), write_line):
        t = lines[i].strip()
        if _is_comment_or_empty(t):
            continue
        m = _LOOP_LE_RE.search(t)
        if m and m.group(1) == var:
            return m.group(2), True
        m = _LOOP_LT_RE.search(t)
        if m and m.group(1) == var:
            return m.group(2), False
    return None


def _parse_alloc_elements(lines: List[str], alloc_line: int
                          ) -> Tuple[Optional[int], Optional[str]]:
    """解析 malloc(n * sizeof(T)) → (元素数常量, 元素类型).

    元素数 n 若为变量, 返回 (None, type) 交由结构证明处理.
    """
    if not (0 < alloc_line <= len(lines)):
        return None, None
    t = lines[alloc_line - 1].strip()
    m = _ELEM_ALLOC_RE.search(t)
    if not m:
        return None, None
    count, stype = m.group(2), m.group(3)
    if re.match(r'^\d+$', count):
        return int(count), stype
    return None, stype


def collect_struct_idx_writes(lines: List[str], valid_lines: set
                              ) -> List[Tuple[int, str, str]]:
    """收集结构体数组/普通数组变量索引写: (line, arr, idx_expr).

    支持跨函数与别名偏移:
      - 函数体内写入经调用点实参关联到堆变量
      - `p = arr + 3` 别名 + `p[5].h` 常量索引 → 归一为 arr[8]
    返回三元组 (line, arr_or_alias, idx_expr_or_const_expr).
    """
    out = []
    arg_binds = _build_arg_binds(lines, valid_lines)
    alias_off = _build_alias_offsets(lines, valid_lines)
    for i, line in enumerate(lines, start=1):
        if valid_lines and i not in valid_lines:
            continue
        text = line.strip()
        if _is_comment_or_empty(text):
            continue
        m = _STRUCT_IDX_WRITE_RE.search(text)
        if m:
            arr, idx = m.group(1), m.group(2)
            resolved = _resolve_write_target(arr, i, arg_binds, lines)
            out.append((i, resolved, idx))
            continue
        # 常量索引结构体写: p[5].h — 别名偏移并入索引
        mc = _STRUCT_IDX_CONST_RE.search(text)
        if mc:
            arr, idx = mc.group(1), int(mc.group(2))
            resolved, off = _resolve_alias_offset(arr, alias_off)
            combined = idx + off
            out.append((i, resolved, str(combined)))
            continue
        m = _ARRAY_IDX_WRITE_RE.search(text)
        if m:
            arr, idx = m.group(1), m.group(2)
            resolved = _resolve_write_target(arr, i, arg_binds, lines)
            out.append((i, resolved, idx))
    return out


def _build_alias_offsets(lines: List[str], valid_lines: set
                         ) -> Dict[str, Tuple[str, int]]:
    """提取 `p = arr + 3` 别名偏移: {p: (base, offset)}."""
    offs: Dict[str, Tuple[str, int]] = {}
    for i, t in enumerate(lines):
        ts = t.strip()
        if _is_comment_or_empty(ts):
            continue
        m = _ALIAS_OFFSET_RE.search(ts)
        if m:
            offs[m.group(1)] = (m.group(2), int(m.group(3)))
    return offs


def _resolve_alias_offset(arr: str, alias_off: Dict[str, Tuple[str, int]]
                          ) -> Tuple[str, int]:
    """解析别名基址: arr 若在 alias_off 中, 返回 (base, offset).

    级联: p=arr+3, q=p+2 → q → (arr, 5).
    """
    cur = arr
    total = 0
    seen = set()
    while cur in alias_off and cur not in seen:
        seen.add(cur)
        base, off = alias_off[cur]
        total += off
        cur = base
    return cur, total


def _build_arg_binds(lines: List[str], valid_lines: set
                     ) -> Dict[str, List[str]]:
    """提取函数定义参数名: callee → [param_name, ...].

    供 _resolve_write_target 将函数体内写入目标替换为调用点实参.
    """
    binds: Dict[str, List[str]] = {}
    sig_re = re.compile(
        r'^[\w\s\*]+?\b(\w[\w]*)\s*\(([^)]*)\)\s*\{')
    for i, t in enumerate(lines):
        ts = t.strip()
        if _is_comment_or_empty(ts):
            continue
        m = sig_re.match(ts)
        if m:
            callee = m.group(1)
            if callee in ('main',):
                continue
            params = [p.strip().split()[-1].rstrip('*').strip()
                      for p in m.group(2).split(',') if p.strip()]
            binds[callee] = params
    return binds


def _resolve_write_target(arr: str, write_line: int,
                          arg_binds: Dict[str, List[str]],
                          lines: List[str]) -> Optional[str]:
    """将函数体内写入目标解析为调用点实参变量.

    arr 是某函数参数时, 全文件找该函数调用点, 用实参替换.
    返回原始 arr (非参数时) 或实参变量 (参数时).
    """
    for callee, params in arg_binds.items():
        if arr in params:
            param_idx = params.index(arr)
            for j in range(1, len(lines) + 1):
                t = lines[j - 1].strip()
                if _is_comment_or_empty(t):
                    continue
                cm = re.search(
                    r'\b' + re.escape(callee) + r'\s*\(([^;)]*)\)\s*;', t)
                if cm:
                    args = [a.strip().lstrip('&').lstrip('*')
                            for a in cm.group(1).split(',')]
                    if param_idx < len(args) and \
                            re.match(r'^[a-zA-Z_]\w*$', args[param_idx]):
                        return args[param_idx]
    return arr


def verify_struct_idx(alloc: ExtAlloc, line: int, idx_expr: str,
                      lines) -> Optional[ExtResult]:
    """验证结构体数组变量索引写是否越界.

    alloc.size_expr 形如 `n * sizeof(T)` 时:
      elem_size = sizeof(T)
      索引上界 bound (i<=n → n+1)
      写量字节 = bound * elem_size

    结构性 off-by-one: 分配元素数与循环上界为同一变量 n, 比较符 <= 时,
    写元素数 = n+1 > 分配 n, 恒越界 (与 n 取值无关).
    """
    m = _ELEM_ALLOC_RE.search(
        lines[alloc.line - 1].strip()) if 0 < alloc.line <= len(lines) else None
    elem_size = 1
    alloc_count: Optional[int] = None
    alloc_count_var: Optional[str] = None
    if m:
        alloc_count_var = m.group(2)
        elem_size = resolve_elem_size(m.group(3), lines, alloc.line)
        if elem_size <= 0:
            elem_size = 8
        if re.match(r'^\d+$', alloc_count_var):
            alloc_count = int(alloc_count_var)
    # 结构性 off-by-one: 循环上界 == 分配元素数, 且 i<=bound → 越界 1 元素
    idx_var = idx_expr.strip()
    if re.match(r'^[a-zA-Z_]\w*$', idx_var) and alloc_count_var:
        bv = _loop_bound_var(line, idx_var, lines)
        bound_is_count = False
        if bv is not None:
            if bv[0] == alloc_count_var:
                bound_is_count = True
            elif alloc_count is not None and _bound_int(bv[0], lines, line) == alloc_count:
                bound_is_count = True
        if bv is not None and (bound_is_count or idx_var == alloc_count_var):
            is_le = bv[1]
            if is_le is True:
                # 写 count+1 个元素, 分配 count 个 → 恒越界一个元素
                write_bytes = (alloc_count + 1) * elem_size if alloc_count is not None \
                    else -1
                usable = alloc.usable if alloc.usable > 0 else alloc.size_const
                if alloc_count is not None and write_bytes > usable:
                    return ExtResult(
                        verdict="VULN", alloc_line=alloc.line, write_line=line,
                        var_name=alloc.var, alloc_size=alloc.size_const,
                        write_size=write_bytes, overflow_bytes=write_bytes - usable,
                        confidence=0.90, kind="struct_idx_off_by_one",
                        reason=("'%s': arr[%s] with %s<=%s writes %d+1 elems "
                                "× %dB = %dB > usable %d (structural OOB)"
                                % (alloc.var, idx_var, idx_var, alloc_count_var,
                                   alloc_count, elem_size, write_bytes, usable)))
                if alloc_count is None:
                    return ExtResult(
                        verdict="VULN", alloc_line=alloc.line, write_line=line,
                        var_name=alloc.var, alloc_size=alloc.size_const,
                        write_size=-1, confidence=0.85,
                        kind="struct_idx_off_by_one",
                        reason=("'%s': arr[%s] with %s<=count → writes count+1 "
                                "elems, allocates count → structural OOB"
                                % (alloc.var, idx_var, idx_var)))
            if is_le is False and alloc_count is not None:
                write_bytes = alloc_count * elem_size
                usable = alloc.usable if alloc.usable > 0 else alloc.size_const
                if usable > 0 and write_bytes <= usable:
                    return ExtResult(
                        verdict="SAFE", alloc_line=alloc.line, write_line=line,
                        var_name=alloc.var, alloc_size=alloc.size_const,
                        write_size=write_bytes, confidence=0.92,
                        kind="struct_idx",
                        reason=("'%s': arr[%s] with %s<%s writes %d elems "
                                "× %dB = %dB <= usable %d"
                                % (alloc.var, idx_var, idx_var, alloc_count_var,
                                   alloc_count, elem_size, write_bytes, usable)))
    bound = _extract_index_bound(idx_expr, line, lines)
    if re.match(r'^\d+$', idx_expr.strip()):
        # 常量索引: arr[8] 写第 8 个元素, write_end = (8+1)*elem_size
        const_idx = int(idx_expr.strip())
        bound = const_idx + 1
    if bound is None or bound <= 0:
        return ExtResult(
            verdict="UNCERTAIN", alloc_line=alloc.line, write_line=line,
            var_name=alloc.var, alloc_size=alloc.size_const,
            write_size=-1, confidence=0.35, kind="struct_idx",
            reason="'%s': index '%s' bound unknown"
                   % (alloc.var, idx_expr))
    write_bytes = bound * elem_size
    usable = alloc.usable if alloc.usable > 0 else alloc.size_const
    if usable <= 0 and alloc_count is not None and elem_size > 0:
        # malloc(count*sizeof(T)) 结构推断容量
        usable = alloc_count * elem_size
    if usable <= 0:
        return ExtResult(
            verdict="UNCERTAIN", alloc_line=alloc.line, write_line=line,
            var_name=alloc.var, alloc_size=alloc.size_const,
            write_size=-1, confidence=0.35, kind="struct_idx",
            reason="'%s': alloc size unknown, cannot compare bound %d"
                   % (alloc.var, bound))
    if write_bytes > usable:
        return ExtResult(
            verdict="VULN", alloc_line=alloc.line, write_line=line,
            var_name=alloc.var, alloc_size=alloc.size_const,
            write_size=write_bytes, overflow_bytes=write_bytes - usable,
            confidence=0.85, kind="struct_idx",
            reason=("'%s': malloc(%d) usable=%d, arr[%s] bound=%d "
                    "elem=%dB → %dB write > usable"
                    % (alloc.var, alloc.size_const, usable, idx_expr,
                       bound, elem_size, write_bytes)))
    return ExtResult(
        verdict="SAFE", alloc_line=alloc.line, write_line=line,
        var_name=alloc.var, alloc_size=alloc.size_const,
        write_size=write_bytes, confidence=0.92, kind="struct_idx",
        reason=("'%s': arr[%s] bound=%d elem=%dB → %dB write <= usable %d"
                % (alloc.var, idx_expr, bound, elem_size,
                   write_bytes, usable)))


__all__ = [
    'resolve_elem_size', '_extract_index_bound', '_bound_int',
    '_loop_is_le', '_loop_bound_var', '_parse_alloc_elements',
    'collect_struct_idx_writes', '_build_alias_offsets',
    '_resolve_alias_offset', '_build_arg_binds', '_resolve_write_target',
    'verify_struct_idx',
    '_ELEM_ALLOC_RE', '_STRUCT_IDX_WRITE_RE', '_STRUCT_IDX_CONST_RE',
    '_ALIAS_OFFSET_RE', '_ARRAY_IDX_WRITE_RE', '_LOOP_LE_RE', '_LOOP_LT_RE',
]
