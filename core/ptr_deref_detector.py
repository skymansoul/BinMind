"""
指针解引用写检测器: 检测 CVE-2021-3156 式字符串迭代循环的扩张溢出。
malloc(strlen(X)+K) 但循环经 *ptr++ 写入超过分配量 → 扩张溢出。
集成于 ir_size_resolver.py 的 add_loop_write_hints() 管线。
"""

from __future__ import annotations
import re
from typing import Dict, List, Optional, Tuple

# 字符串迭代循环: for(s=str; *s; s++)
_STRCHR_FOR = re.compile(
    r'for\s*\(\s*(?:const\s+)?char\s*\*\s*(\w[\w.]*)\s*=\s*'
    r'(\w[\w.]*)\s*;'
    r'\s*\*\1\s*;'
    r'\s*\1\+\+\s*\)')

# 解引用写: *ptr++ = val, *ptr = val (排除 ==, !=, <=, >=)
_PTR_DEREF_WRITE = re.compile(r'\*\s*(\w[\w.]*)\s*(\+\+)?\s*=(?!=)')

# strlen: var = strlen(X);
_STRLEN_ASSIGN = re.compile(
    r'(\w[\w.]*)\s*=\s*strlen\s*\(\s*(\w[\w.]*)\s*\)')

# malloc: var = malloc/calloc/realloc(...)
_RE_MALLOC = re.compile(
    r'(\w[\w.\->]*)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?'
    r'(malloc|calloc|realloc)\s*\(')


def detect_ptr_deref_overflow(source: str, enhanced: List[str],
                              existing_syn_bufs: set,
                              fresh_var_fn) -> None:
    """检测 strchr 循环中 *ptr++ 写入且 ptr 别名 malloc 缓冲区的情况。

    模式: malloc(strlen(X)+K) 且 K<=1, 但循环体每次迭代 >=2 次解引用
    写入 → 扩张溢出。
    """
    lines = source.splitlines()

    # 别名: ptr_var -> malloc_buf_var
    ptr_to_buf: Dict[str, str] = {}
    # malloc 大小: buf_var -> (size_var, size_const)
    malloc_sizes: Dict[str, Tuple[str, int]] = {}
    # strlen: var -> source_str
    strlen_of: Dict[str, str] = {}

    for line in lines:
        s = line.strip()

        slm = _STRLEN_ASSIGN.search(s)
        if slm:
            strlen_of[slm.group(1)] = slm.group(2)

        mm = _RE_MALLOC.search(s)
        if mm:
            buf_var = mm.group(1)
            sz_m = re.search(
                r'(?:malloc|calloc|realloc)\s*\(\s*'
                r'([^,)]*(?:\([^)]*\)[^,)]*)*)\s*[^)]*\)', s)
            if sz_m:
                sz_str = sz_m.group(1).strip()
                add_m = re.match(r'(\w[\w.]*)\s*\+\s*(\d+)', sz_str)
                if add_m:
                    malloc_sizes[buf_var] = (add_m.group(1), int(add_m.group(2)))
                elif re.match(r'^\w[\w.]*$', sz_str):
                    malloc_sizes[buf_var] = (sz_str, 0)

        am = re.search(r'\b(\w[\w.]*)\s*=\s*(\w[\w.]*)\s*;?\s*$', s)
        if am and am.group(2) in malloc_sizes:
            ptr_to_buf[am.group(1)] = am.group(2)

    # 扫描含解引用写入的 strchr 循环
    in_loop = False
    brace_depth = 0
    loop_str_src: Optional[str] = None
    deref_counts: Dict[str, int] = {}

    for line in lines:
        stripped = line.strip()

        sfm = _STRCHR_FOR.search(stripped)
        if sfm:
            in_loop = True
            loop_str_src = sfm.group(2)
            brace_depth = stripped.count('{') - stripped.count('}')
            deref_counts.clear()
            if brace_depth == 0 and not stripped.endswith('{'):
                _count_deref(stripped, ptr_to_buf, deref_counts)
            continue

        if not in_loop:
            continue

        brace_depth += stripped.count('{') - stripped.count('}')

        if brace_depth <= 0:
            _emit_if_overflow(enhanced, deref_counts, ptr_to_buf,
                            malloc_sizes, strlen_of, loop_str_src,
                            fresh_var_fn, existing_syn_bufs)
            in_loop = False
            deref_counts.clear()
            continue

        dwm = _PTR_DEREF_WRITE.search(stripped)
        if dwm and dwm.group(1) in ptr_to_buf:
            deref_counts[dwm.group(1)] = deref_counts.get(dwm.group(1), 0) + 1


def _count_deref(line: str, ptr_to_buf: Dict[str, str],
                 counts: Dict[str, int]) -> None:
    """统计单行循环体中的解引用写入次数。"""
    for dwm in _PTR_DEREF_WRITE.finditer(line):
        if dwm.group(1) in ptr_to_buf:
            counts[dwm.group(1)] = counts.get(dwm.group(1), 0) + 1


def _emit_if_overflow(enhanced: List[str], deref_counts: Dict[str, int],
                      ptr_to_buf: Dict[str, str],
                      malloc_sizes: Dict[str, Tuple[str, int]],
                      strlen_of: Dict[str, str],
                      loop_str_src: Optional[str],
                      fresh_var_fn, existing_syn_bufs: set) -> None:
    """检测到扩张溢出时生成合成 memcpy。"""
    for ptr, count in deref_counts.items():
        if ptr not in ptr_to_buf or count < 2:
            continue
        buf = ptr_to_buf[ptr]
        if buf not in malloc_sizes:
            continue
        sz_var, sz_const = malloc_sizes[buf]
        if sz_var not in strlen_of or sz_const > 1:
            continue
        if strlen_of[sz_var] != loop_str_src:
            continue
        # 已证明: 写入 >= 2*strlen(X), 分配 = strlen(X) + K 且 K<=1
        fv = fresh_var_fn()
        enhanced.append(f'{fv} = {sz_var} * 2;')
        enhanced.append(
            f'memcpy({buf}, <loop_body>, {fv});'
            f'  /* loop_write: deref x{count} */')
        existing_syn_bufs.add(buf)


__all__ = ['detect_ptr_deref_overflow']
