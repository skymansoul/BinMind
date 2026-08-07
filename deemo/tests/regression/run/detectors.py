"""
检测器调度 — 四种漏洞类型的C源码检测器薄包装.

2026-08-07: 提取为独立模块.
"""

import re
from typing import Callable, Dict, Tuple


def _extract_var_lower_bound(alloc_expr: str, source: str) -> int:
    """从源码中提取变量下界: if(var<N)var=N → lo=N。返回0表示无下界。"""
    for av in re.findall(r'\b(\w+)\b', alloc_expr):
        for m in re.finditer(
                rf'if\s*\(\s*{av}\s*<\s*(\d+)\s*\)\s*{av}\s*=\s*\1\s*;', source):
            try: return int(m.group(1))
            except ValueError: pass
        for m in re.finditer(
                rf'if\s*\(\s*{av}\s*<=\s*(\d+)\s*\)\s*{av}\s*=\s*\1\s*;', source):
            try: return int(m.group(1))
            except ValueError: pass
    return 0


def run_heap_detector(source: str) -> Tuple[bool, str]:
    """GAPSBV堆溢出检测: 三层过滤 (Tier 0 source_scanner → Tier 1 guard → Tier 2 calloc回填).

    与 cross_type_benchmark.py 完全一致的检测逻辑.
    """
    from tests.source_scanner import extract_heap_ops_c
    from tests.source_classifier import classify_finding, compute_glibc_effective

# 宏提取
    macros = {}
    for line in source.splitlines():
        m = re.match(r'#define\s+(\w+)\s+(\d+)\b', line.strip())
        if m: macros[m.group(1)] = int(m.group(2))

# 约束提取: 变量上界
    var_upper = {}
    for m in re.finditer(r'(\w+)\s*=\s*MIN\s*\(\s*(.+?)\s*,\s*(\d+)\s*\)', source):
        try:
            n = int(m.group(3))
            var_upper[m.group(1)] = min(var_upper.get(m.group(1), n), n)
        except ValueError: pass
    for m in re.finditer(
            r'if\s*\(\s*(\w+)\s*(>)\s*(\w+)\s*\)\s*(\w+)\s*=\s*(\w+)\s*;',
            source, re.IGNORECASE):
        try:
            cap_val = int(m.group(3))
            var_upper[m.group(1)] = min(var_upper.get(m.group(1), cap_val), cap_val)
        except ValueError: pass

# guards: if(var < N) 索引保护
    guards = {}
    for line in source.splitlines():
        s = line.strip()
        m = re.search(r'if\s*\(\s*(\w+)\s*(<=?)\s*(\w+)\s*\)', s)
        if m:
            var, op, bs = m.group(1), m.group(2), m.group(3)
            b = None
            try: b = int(bs)
            except ValueError:
                if bs in macros: b = macros[bs]
            if b is not None:
                if op == '<=': b += 1
                if var not in guards or b < guards[var]: guards[var] = b

# Tier 2: calloc大小回填
    calloc_size = 0
    cm = re.search(
        r'calloc\s*\(\s*(\d+)\s*,\s*sizeof\s*\(\s*(\w+)\s*\)\s*\)',
        source, re.IGNORECASE)
    if cm:
        n = int(cm.group(1))
        type_sizes = {'char':1,'short':2,'int':4,'long':8,'float':4,'double':8}
        calloc_size = n * type_sizes.get(cm.group(2), 4)

    ops = extract_heap_ops_c(source)
    ovf = unc = safe = gflt = 0
    for op in ops:
        cls = classify_finding(op)
        wt = op.get('type', ''); iv = op.get('idx_var', '')

        # guard索引保护
        guarded = False
        if wt == 'array_write' and iv and iv in guards:
            gb = guards[iv]; eff = op.get('alloc_effective', 0)
            if gb > 0 and eff > 0 and gb <= eff: guarded = True; gflt += 1
        if guarded: safe += 1; continue

        if cls == 'SAFE': safe += 1; continue
        if cls == 'OVERFLOW': ovf += 1; continue

        # cls == 'UNCERTAIN' → 约束过滤
        ws = op.get('write_size', 0)
        eff = op.get('alloc_effective', 0)
        alloc_expr = op.get('alloc_size_expr', '')

        if wt == 'array_write' and ws <= 1 and eff == 0 and calloc_size == 0:
            unc += 1; continue
        filtered = False
        for av in re.findall(r'\b(\w+)\b', alloc_expr):
            if av in var_upper and ws > 0:
                ub = var_upper[av]
                if ws <= ub:
                    if eff > 0:
                        if ws <= eff: safe += 1; filtered = True; break
                    else:
                        min_usable = compute_glibc_effective(0)
                        if min_usable <= 0: min_usable = 24
                        if ws <= min_usable: safe += 1; filtered = True; break
        if filtered: continue

        if calloc_size > 0 and ws > 0 and ws <= calloc_size: safe += 1; continue

        if eff > 0 and ws > 0 and ws <= eff:
            uc = op.get('user_controlled', False)
            if uc and op.get('type') == 'array_write':
                pass
            else:
                safe += 1; continue
        unc += 1

    detected = (ovf > 0 or unc > 0)
    detail = f'OVF={ovf} UNC={unc} SAFE={safe} GFLT={gflt}'
    return detected, detail


def run_uaf_detector(source: str) -> Tuple[bool, str]:
    """TARPS+RAP UAF检测: free/use/nullify/realloc模式分析."""
    from tests.uaf_detector import detect_uaf
    result = detect_uaf(source)
    return result['detected'], f"findings={result['count']} free={result['free_count']}"


def run_int_overflow_detector(source: str) -> Tuple[bool, str]:
    """I-GUARD整数溢出检测: 乘/加/移位/窄化/符号混淆."""
    from tests.int_overflow_detector import detect_int_overflow
    result = detect_int_overflow(source)
    return result['detected'], f"findings={result['count']}"


def run_fmt_detector(source: str) -> Tuple[bool, str]:
    """FSCS格式串检测: 五级风险评估 + %n写原语检测."""
    from tests.fmt_detector import detect_format_string
    result = detect_format_string(source)
    return result['detected'], f"calls={result['count']} high_risk={result['high_risk']}"


# 类型→检测器映射
DETECTOR_MAP: Dict[str, Callable] = {
    'heap_overflow': run_heap_detector,
    'uaf': run_uaf_detector,
    'integer_overflow': run_int_overflow_detector,
    'format_string': run_fmt_detector,
}
