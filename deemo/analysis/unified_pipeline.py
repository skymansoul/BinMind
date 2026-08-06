# [DEPRECATED] — 功能已迁移至 modules/info/analysis/unified_pipeline.py 或 src/unified_pipeline.py
# 若确认无外部引用, 可安全删除
# Unified vulnerability analysis pipeline
# Runs all deep analyzers on decompiled code and merges findings.
from __future__ import annotations
from typing import Dict, List, Any

def analyze_all(code, func_name=''):
    findings = []
    mods = [
        ('analysis.taint_propagation','detect_heap_overflow'),
        ('analysis.int_overflow_detector','detect_int_overflow'),
        ('analysis.double_free_analyzer','detect_double_free'),
        ('analysis.uaf_alias_analyzer','detect_uaf_with_aliases'),
        ('analysis.constraint_simplifier','filter_false_positives'),
    ]
    for mod_name, func_name_mod in mods:
        try:
            mod = __import__(mod_name, fromlist=[func_name_mod])
            fn = getattr(mod, func_name_mod)
            result = fn(code, func_name)
            if isinstance(result, list):
                findings.extend(result)
        except Exception:
            pass
    return findings

def analyze_decompiled_map(decompiled_map):
    all_findings = []
    for func_name, code in decompiled_map.items():
        findings = analyze_all(code, func_name)
        all_findings.extend(findings)
    return all_findings
