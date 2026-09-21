"""
结构体数组索引写入候选收集. 含别名偏移与跨函数实参解析.

与 heap_write_struct_idx.py 同族, 负责把函数体内写入目标归一为调用点的
实际堆变量, 供越界判定使用.

支持:
  - 函数体内写入经调用点实参关联到堆变量
  - `p = arr + 3` 别名 + `p[5].h` 常量索引 → 归一为 arr[8]
"""

import re
from typing import Dict, List, Optional, Tuple

from analysis.heap_overflow_src_patterns import _is_comment_or_empty
from analysis.heap_write_struct_idx import (
    _STRUCT_IDX_WRITE_RE, _STRUCT_IDX_CONST_RE, _ARRAY_IDX_WRITE_RE,
    _ALIAS_OFFSET_RE,
)


def collect_struct_idx_writes(lines: List[str], valid_lines: set
                              ) -> List[Tuple[int, str, str]]:
    """收集结构体数组/普通数组变量索引写: (line, arr, idx_expr).

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


__all__ = [
    'collect_struct_idx_writes', '_build_alias_offsets',
    '_resolve_alias_offset', '_build_arg_binds', '_resolve_write_target',
]
