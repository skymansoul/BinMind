# Heap false positive filter — integrates taint + constraint analysis
from __future__ import annotations
from typing import List, Dict, Any
from analysis.taint_propagation import detect_heap_overflow, propagate_sizes
from analysis.constraint_simplifier import filter_false_positives, extract_constants

def filter_heap_findings(findings, code, func=""):
    if not findings: return findings
    filtered = filter_false_positives(findings, code)
    return filtered

def batch_filter(all_findings, decompiled_map):
    result = []
    for fr in all_findings:
        func = fr.get("function","")
        code = decompiled_map.get(func,"")
        if not code:
            result.append(fr)
            continue
        if fr.get("type") in ("heap-overflow","heap-buffer-overflow"):
            filtered = filter_heap_findings([fr], code, func)
            result.extend(filtered)
        else:
            result.append(fr)
    return result
