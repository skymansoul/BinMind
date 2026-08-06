# Pipeline-level false-positive filtering for heap overflow detection.
# Called from heap_overflow_pipeline. Distinct from heap_fp_filter.py which
# handles single-detection-point filtering.
import re
from typing import Optional

_GLIBC_ALIGNMENT = 16


def align_up(size: int, alignment: int = _GLIBC_ALIGNMENT) -> int:
    return ((size + alignment - 1) // alignment) * alignment


def filter_alignment_false_positives(candidates: list) -> list:
    kept = []
    for c in candidates:
        alloc_size = c.alloc_site.size_arg
        aligned = align_up(alloc_size)
        store_offset = c.overflow_store.offset
        if store_offset < aligned and not c.overflow_store.offset_is_dynamic:
            continue
        kept.append(c)
    return kept


def filter_realloc_expansion(candidates: list, ir_lines: list[str]) -> list:
    realloc_sizes = _extract_realloc_sizes(ir_lines)
    if not realloc_sizes:
        return candidates
    kept = []
    for c in candidates:
        var = c.alloc_site.result_var
        if var and var in realloc_sizes:
            new_size = realloc_sizes[var]
            if c.overflow_store.offset < align_up(new_size):
                continue
        kept.append(c)
    return kept


def filter_struct_field_access(candidates: list, ir_lines: list[str]) -> list:
    kept = []
    for c in candidates:
        var = c.alloc_site.result_var
        offset = c.overflow_store.offset
        if not var:
            kept.append(c)
            continue
        other_offsets = _collect_store_offsets(ir_lines, var)
        if len(other_offsets) >= 3 and offset in other_offsets:
            c.confidence = max(0.35, c.confidence - 0.25)
        kept.append(c)
    return kept


def apply_fp_filters(candidates: list, ir_lines: list[str]) -> list:
    c1 = filter_alignment_false_positives(candidates)
    c2 = filter_realloc_expansion(c1, ir_lines)
    c3 = filter_struct_field_access(c2, ir_lines)
    return [c for c in c3 if c.confidence >= 0.40]


def _extract_realloc_sizes(ir_lines: list[str]) -> dict[str, int]:
    sizes = {}
    pattern = re.compile(
        r'(\w+)\s*=\s*realloc\s*\(\s*\w+\s*,\s*(\d+)\s*\)',
        re.IGNORECASE)
    for line in ir_lines:
        m = pattern.search(line)
        if m:
            sizes[m.group(1)] = int(m.group(2))
    return sizes


def _collect_store_offsets(ir_lines: list[str], base_var: str) -> set[int]:
    offsets = set()
    for line in ir_lines:
        m = re.search(rf'\[{re.escape(base_var)}\s*\+\s*(\d+)\]', line)
        if m:
            offsets.add(int(m.group(1)))
        m2 = re.search(rf'{re.escape(base_var)}\[(\d+)\]', line)
        if m2:
            offsets.add(int(m2.group(1)))
    return offsets
