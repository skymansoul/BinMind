"""
Pointer-deref write detector for string-iteration loops.
Detects CVE-2021-3156 style expansion overflow:
  malloc(strlen(X)+K) but loop writes > alloc via *ptr++ in str-iteration.

Integrated into ir_size_resolver.py → add_loop_write_hints() pipeline.
"""

from __future__ import annotations
import re
from typing import Dict, List, Optional, Tuple

# String-iteration loop: for(s=str; *s; s++)
_STRCHR_FOR = re.compile(
    r'for\s*\(\s*(?:const\s+)?char\s*\*\s*(\w[\w.]*)\s*=\s*'
    r'(\w[\w.]*)\s*;'
    r'\s*\*\1\s*;'
    r'\s*\1\+\+\s*\)')

# Deref write: *ptr++ = val, *ptr = val (not ==, !=, <=, >=)
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
    """Detect *ptr++ writes in strchr loops where ptr aliases a malloc buf.

    Pattern: malloc(strlen(X)+K) with K<=1, but loop body has >=2 deref
    writes per iteration → expansion overflow.
    """
    lines = source.splitlines()

    # Alias: ptr_var -> malloc_buf_var
    ptr_to_buf: Dict[str, str] = {}
    # Malloc sizes: buf_var -> (size_var, size_const)
    malloc_sizes: Dict[str, Tuple[str, int]] = {}
    # Strlen: var -> source_str
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

    # Scan for strchr loops with deref writes
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
    """Count deref writes on a single-line loop body."""
    for dwm in _PTR_DEREF_WRITE.finditer(line):
        if dwm.group(1) in ptr_to_buf:
            counts[dwm.group(1)] = counts.get(dwm.group(1), 0) + 1


def _emit_if_overflow(enhanced: List[str], deref_counts: Dict[str, int],
                      ptr_to_buf: Dict[str, str],
                      malloc_sizes: Dict[str, Tuple[str, int]],
                      strlen_of: Dict[str, str],
                      loop_str_src: Optional[str],
                      fresh_var_fn, existing_syn_bufs: set) -> None:
    """Emit synthetic memcpy when expansion overflow detected."""
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
        # Proven: write >= 2*strlen(X), alloc = strlen(X) + K where K<=1
        fv = fresh_var_fn()
        enhanced.append(f'{fv} = {sz_var} * 2;')
        enhanced.append(
            f'memcpy({buf}, <loop_body>, {fv});'
            f'  /* loop_write: deref x{count} */')
        existing_syn_bufs.add(buf)


__all__ = ['detect_ptr_deref_overflow']
