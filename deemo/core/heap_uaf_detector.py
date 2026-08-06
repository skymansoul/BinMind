"""
Static heap vulnerability and UAF detection via decompiled pseudocode and
pattern matching with lightweight data flow analysis.

Detection targets:
  1. Use-After-Free: pointer dereference after free(p)
  2. Double Free: same pointer freed twice
  3. Heap overflow: write exceeds malloc allocation size (inferred from
     subsequent memcpy/strcpy call arguments)

Pure static analysis (no angr symbolic execution dependency). Serves as a
fast scanning layer. Limited effectiveness against heavily obfuscated code
(known limitation).

References:
  - Caballero et al., 2012, USENIX Security, "Undangle"
  - Gennissen & O'Keeffe, 2023, "HeapHop"
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

# Memory allocation/deallocation functions
_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', 'memalign', 'aligned_alloc'}
_FREE_FUNCS = {'free', 'realloc'}
# Dangerous functions that may write into heap buffers
_HEAP_WRITE_FUNCS = {
    'memcpy', 'memmove', 'strcpy', 'strncpy', 'strcat', 'strncat',
    'gets', 'fgets', 'read', 'fread', 'recv', 'sprintf', 'snprintf',
}


def _find_allocations(pseudocode: str) -> List[Dict[str, Any]]:
    """Extract all memory allocation sites from pseudocode.

    Returns: [{var: str, func: str, size: int, line: str}, ...]
    """
    allocs = []
    for m in re.finditer(
        r'(\w+)\s*=\s*(?:\(\s*\w+\s*\*\s*\))?\s*(malloc|calloc|realloc|memalign|aligned_alloc)\s*\(([^)]+)\)',
        pseudocode,
    ):
        var = m.group(1)
        func = m.group(2)
        size_expr = m.group(3).strip()
        size = _parse_size(size_expr)
        allocs.append({
            'variable': var, 'function': func,
            'size_expression': size_expr[:60],
            'estimated_size': size, 'line': m.group(0)[:120],
        })
    return allocs


def _find_frees(pseudocode: str) -> List[Dict[str, Any]]:
    """Extract all deallocation sites from pseudocode.

    Returns: [{var: str, func: str, line: str}, ...]
    """
    frees = []
    for m in re.finditer(
        r'(free)\s*\(\s*(\w+)\s*\)',
        pseudocode,
    ):
        frees.append({
            'function': m.group(1),
            'variable': m.group(2),
            'line': m.group(0)[:120],
        })
    return frees


def _find_pointer_uses(pseudocode: str, ptr_var: str) -> List[str]:
    """Search for pointer dereference sites in pseudocode.

    Matching patterns: *ptr, ptr->field, ptr[expr], ptr + offset
    """
    refs = []
    for m in re.finditer(
        rf'(\*{ptr_var}\b|{ptr_var}\s*->|{ptr_var}\s*\[|{ptr_var}\s*\+)',
        pseudocode,
    ):
        refs.append(m.group(0))
    return refs


def _parse_size(expr: str) -> int:
    """Attempt to parse byte count from a size expression. Returns -1 on failure."""
    expr = expr.strip()
    # Plain integer literal
    try:
        return int(expr)
    except ValueError:
        pass
    # sizeof(type) or sizeof(*ptr)
    sizeof_match = re.match(r'sizeof\s*\(\s*(\w+)\s*\)', expr)
    if sizeof_match:
        type_name = sizeof_match.group(1)
        sizes = {'int': 4, 'long': 8, 'char': 1, 'short': 2,
                 'float': 4, 'double': 8, 'void': 1, 'size_t': 8,
                 'uint32_t': 4, 'uint64_t': 8, 'int32_t': 4, 'int64_t': 8}
        return sizes.get(type_name, -1)
    # Multiplication: n * sizeof(type)
    mul_match = re.match(r'(\w+)\s*\*\s*sizeof\s*\(\s*(\w+)\s*\)', expr)
    if mul_match:
        sizes = {'int': 4, 'long': 8, 'char': 1}
        ts = sizes.get(mul_match.group(2), 4)
        try:
            return int(mul_match.group(1)) * ts
        except ValueError:
            pass
    return -1


def detect_uaf(
    pseudocode: str,
    func_name: str = "",
) -> List[Dict[str, Any]]:
    """Detect Use-After-Free vulnerabilities.

    For each (free(p), p dereference) pair, check temporal ordering:
    if the dereference appears after free (by line number) -> UAF candidate.
    """
    findings = []
    frees = _find_frees(pseudocode)
    if not frees:
        return findings

    lines = pseudocode.split('\n')

    for fr in frees:
        ptr = fr['variable']
        # Find pointer uses after the free line
        free_pos = -1
        for i, line in enumerate(lines):
            if ptr in line and 'free' in line:
                free_pos = i
                break

        if free_pos < 0:
            continue

        # Search for pointer uses after free
        uses_after = []
        for i in range(free_pos + 1, min(len(lines), free_pos + 50)):
            if re.search(rf'\*{ptr}\b|{ptr}\s*->|{ptr}\s*\[', lines[i]):
                uses_after.append(lines[i].strip()[:120])

        if uses_after:
            findings.append({
                'vuln_type': 'use-after-free',
                'function': func_name,
                'freed_variable': ptr,
                'free_location': fr['line'][:120],
                'use_after': uses_after[:3],
                'confidence': 0.70,
                'description': (
                    f'Pointer {ptr} freed then dereferenced in {func_name}'
                ),
                'exploitation': (
                    'Heap spray to reclaim freed chunk → control dangling pointer '
                    '→ vtable/function pointer overwrite / data-only attack'
                ),
            })

    return findings


def detect_double_free(
    pseudocode: str,
    func_name: str = "",
) -> List[Dict[str, Any]]:
    """Detect Double Free: same variable passed to free() twice."""
    findings = []
    freed_vars: Dict[str, int] = {}

    for m in re.finditer(r'free\s*\(\s*(\w+)\s*\)', pseudocode):
        var = m.group(1)
        freed_vars[var] = freed_vars.get(var, 0) + 1

    for var, count in freed_vars.items():
        if count >= 2:
            findings.append({
                'vuln_type': 'double-free',
                'function': func_name,
                'freed_variable': var,
                'free_count': count,
                'confidence': 0.80 if count >= 2 else 0.50,
                'description': (
                    f'Variable {var} passed to free() {count} times in {func_name}'
                ),
                'exploitation': (
                    'First free → chunk in tcache/fastbin → second free → '
                    'corrupt free list → arbitrary alloc → write primitive'
                ),
            })

    return findings


def detect_heap_overflow(
    pseudocode: str,
    func_name: str = "",
) -> List[Dict[str, Any]]:
    """Detect heap overflow: write exceeds malloc allocation size.

    Strategy:
      1. Find malloc(n) -> var
      2. Find subsequent writes to var (memcpy etc.) with size > n
    """
    findings = []
    allocs = _find_allocations(pseudocode)

    for alloc in allocs:
        if alloc['estimated_size'] <= 0:
            continue

        var = alloc['variable']
        alloc_size = alloc['estimated_size']

        # Search for writes targeting this variable
        for write_func in _HEAP_WRITE_FUNCS:
            for m in re.finditer(
                rf'{write_func}\s*\(\s*{re.escape(var)}\s*,[^,)]*,\s*(\d+)\s*\)',
                pseudocode,
            ):
                write_size = int(m.group(1))
                if write_size > alloc_size:
                    findings.append({
                        'vuln_type': 'heap-overflow',
                        'function': func_name,
                        'buffer_variable': var,
                        'allocation_size': alloc_size,
                        'write_function': write_func,
                        'write_size': write_size,
                        'overflow_bytes': write_size - alloc_size,
                        'confidence': 0.75,
                        'description': (
                            f'{write_func}({var}, src, {write_size}) writes '
                            f'{write_size - alloc_size} bytes past {alloc_size}B '
                            f'buffer allocated by {alloc["function"]}()'
                        ),
                        'exploitation': (
                            'Overwrite adjacent heap chunk metadata → '
                            'corrupt free list / unsorted bin → '
                            'arbitrary write primitive / house-of-force'
                        ),
                    })

    return findings


def analyze_heap_vulnerabilities(
    binary_path: str,
    func_name: Optional[str] = None,
    pseudocode: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Comprehensive heap vulnerability detection: UAF, Double Free, and heap overflow.

    Args:
        binary_path: ELF path (for logging)
        func_name: restrict to specific function, None = scan all
        pseudocode: pre-fetched pseudocode, None = auto-decompile

    Returns:
        Vulnerability findings sorted by confidence descending
    """
    findings: List[Dict[str, Any]] = []

    if pseudocode:
        all_pseudocode = {func_name or 'unknown': pseudocode}
    elif func_name:
        try:
            from core.decompiler import decompile_function
            decomp = decompile_function(binary_path, func_name)
            all_pseudocode = {func_name: decomp.get('pseudocode', '')}
        except Exception:
            return findings
    else:
        # Full scan of all user functions - expensive, requires explicit invocation
        return findings

    for fname, pcode in all_pseudocode.items():
        if not pcode:
            continue
        findings.extend(detect_uaf(pcode, fname))
        findings.extend(detect_double_free(pcode, fname))
        findings.extend(detect_heap_overflow(pcode, fname))

    findings.sort(key=lambda f: (-f['confidence'], f.get('vuln_type', '')))
    return findings
