"""
PTASM Free-Wrapper 扫描器 — 识别封装 free() 调用的函数。

扫描 C 源码中的函数定义, 检测函数体包含 free(param) 的模式,
将这些函数标记为 "free wrapper", 调用时等价于直接 free 实参。
"""

from __future__ import annotations

import re
from typing import Dict, List

from analysis.ptasm_types import parse_line_operations


_FUNC_DEF_RE = re.compile(
    r'^\s*(?:static\s+)?(?:inline\s+)?'
    r'(?:void|int|char|long|short|float|double|unsigned|signed|size_t|ssize_t'
    r'|uint\w*_t|int\w*_t|\w+\s*\*)\s+'
    r'(\w+)\s*\(([^)]*)\)\s*\{')


def scan_free_wrappers(lines: List[str]) -> Dict[str, int]:
    """扫描函数定义, 识别'free wrapper': 函数体中 free(param) 的函数.

    当这些函数被调用时, 实参等价于被 free.
    例如: free_request(Request *req) { ... free(req); ... }
          → free_request(r) 等价于 free(r).

    返回 {func_name → param_index} dict.
    """
    free_wrappers: Dict[str, int] = {}
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        fm = _FUNC_DEF_RE.match(s)
        if not fm:
            i += 1
            continue

        func_name = fm.group(1)
        params_str = fm.group(2)
        # 提取参数名
        param_names = []
        if params_str.strip():
            for part in params_str.split(','):
                part = part.strip()
                words = part.split()
                if words:
                    pn = words[-1].lstrip('*')
                    param_names.append(pn)

        if not param_names:
            i += 1
            continue

        # 找函数体的闭合括号
        depth = 1
        j = i + 1
        body_end = -1
        while j < len(lines):
            stripped_j = lines[j].strip()
            depth += stripped_j.count('{') - stripped_j.count('}')
            if depth <= 0:
                body_end = j
                break
            j += 1

        if body_end < 0:
            i += 1
            continue

        # 扫描函数体: 检查哪个参数被 free()
        for k in range(i + 1, body_end):
            body_line = lines[k]
            free_ops = parse_line_operations(body_line)
            for op_type, info in free_ops:
                if op_type == 'free':
                    freed_ptr = info['ptr']
                    freed_ptr = re.sub(r'\[[^\]]*\]', '', freed_ptr)
                    for pidx, pname in enumerate(param_names):
                        if freed_ptr == pname or freed_ptr.startswith(pname + '->'):
                            free_wrappers[func_name] = pidx
                            break

        i = body_end + 1

    return free_wrappers
