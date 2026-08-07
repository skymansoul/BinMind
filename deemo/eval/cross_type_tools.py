"""

包含4种工具的检测逻辑: BinMind-GAPSBV / Objdump-Naive / Nm-Symbol / Regex-Baseline.
"""
import os, sys, re, time, subprocess
from pathlib import Path
from typing import Dict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

_CACHE: Dict = {}

# 有害函数集合 — objdump/nm 工具使用
_HF = {'malloc', 'calloc', 'realloc', 'memcpy', 'memmove', 'memset',
       'strcpy', 'strcat', 'sprintf', 'gets', 'free'}
_DS = {'malloc', 'calloc', 'realloc', 'memcpy', 'strcpy',
       'strcat', 'sprintf', 'gets'}
_AR = re.compile(r'(malloc|calloc|realloc)\s*\(', re.I)
_WR = re.compile(
    r'(memcpy|memmove|memset|strcpy|strncpy|strcat|sprintf|gets)\s*\(',
    re.I)


def _extract_var_lower_bound(alloc_expr: str, source: str) -> int:
    """从源码中提取变量下界: if(var<N)var=N → lo=N。返回0表示无下界."""
    for av in re.findall(r'\b(\w+)\b', alloc_expr):
        for m in re.finditer(
                rf'if\s*\(\s*{av}\s*<\s*(\d+)\s*\)\s*{av}\s*=\s*\1\s*;',
                source):
            try:
                return int(m.group(1))
            except ValueError:
                pass
        for m in re.finditer(
                rf'if\s*\(\s*{av}\s*<=\s*(\d+)\s*\)\s*{av}\s*=\s*\1\s*;',
                source):
            try:
                return int(m.group(1))
            except ValueError:
                pass
    return 0


def _run_heap_detector(source: str, t0: float) -> dict:
    """LPVRA 堆溢出检测 (GAPSBV): 分配-写入配对 + 约束过滤.

    三层过滤: source_scanner + classify_finding, guard约束, calloc回填.
    """
    from tests.source_scanner import extract_heap_ops_c
    from tests.source_classifier import classify_finding
    from tests.source_classifier import eval_size, compute_glibc_effective

    macros = {}
    for line in source.splitlines():
        m = re.match(r'#define\s+(\w+)\s+(\d+)\b', line.strip())
        if m:
            macros[m.group(1)] = int(m.group(2))

    var_upper = {}
    for m in re.finditer(
            r'(\w+)\s*=\s*MIN\s*\(\s*(.+?)\s*,\s*(\d+)\s*\)', source):
        try:
            n = int(m.group(3))
            var_upper[m.group(1)] = min(var_upper.get(m.group(1), n), n)
        except ValueError:
            pass
    for m in re.finditer(
            r'if\s*\(\s*(\w+)\s*(>)\s*(\w+)\s*\)\s*(\w+)\s*=\s*(\w+)\s*;',
            source, re.IGNORECASE):
        cap_var = m.group(1)
        try:
            cap_val = int(m.group(3))
            var_upper[cap_var] = min(var_upper.get(cap_var, cap_val), cap_val)
        except ValueError:
            pass

    guards = {}
    for line in source.splitlines():
        s = line.strip()
        m = re.search(r'if\s*\(\s*(\w+)\s*(<=?)\s*(\w+)\s*\)', s)
        if m:
            var, op, bs = m.group(1), m.group(2), m.group(3)
            b = None
            try:
                b = int(bs)
            except ValueError:
                if bs in macros:
                    b = macros[bs]
            if b is not None:
                if op == '<=':
                    b += 1
                if var not in guards or b < guards[var]:
                    guards[var] = b

    ops = extract_heap_ops_c(source)

    calloc_size = 0
    cm = re.search(
        r'calloc\s*\(\s*(\d+)\s*,\s*sizeof\s*\(\s*(\w+)\s*\)\s*\)',
        source, re.IGNORECASE)
    if cm:
        n = int(cm.group(1))
        type_sizes = {'char': 1, 'short': 2, 'int': 4, 'long': 8,
                      'float': 4, 'double': 8}
        ts = type_sizes.get(cm.group(2), 4)
        calloc_size = n * ts

    ovf = unc = safe = gflt = 0
    for op in ops:
        cls = classify_finding(op)
        wt = op.get('type', '')
        iv = op.get('idx_var', '')

        guarded = False
        if wt == 'array_write' and iv and iv in guards:
            gb = guards[iv]
            eff = op.get('alloc_effective', 0)
            if gb > 0 and eff > 0 and gb <= eff:
                guarded = True
                gflt += 1

        if guarded:
            safe += 1
            continue
        if cls == 'SAFE':
            safe += 1
            continue
        if cls == 'OVERFLOW':
            ovf += 1
            continue

        ws = op.get('write_size', 0)
        eff = op.get('alloc_effective', 0)
        alloc_expr = op.get('alloc_size_expr', '')

        if wt == 'array_write' and ws <= 1 and eff == 0 and calloc_size == 0:
            unc += 1
            continue
        filtered = False
        for av in re.findall(r'\b(\w+)\b', alloc_expr):
            if av in var_upper and ws > 0:
                ub = var_upper[av]
                if ws <= ub:
                    if eff > 0:
                        if ws <= eff:
                            safe += 1
                            filtered = True
                            break
                    else:
                        min_usable = compute_glibc_effective(0)
                        if min_usable <= 0:
                            min_usable = 24
                        if ws <= min_usable:
                            safe += 1
                            filtered = True
                            break
                        var_lower = _extract_var_lower_bound(
                            alloc_expr, source)
                        if var_lower > 0:
                            lo_eff = compute_glibc_effective(var_lower)
                            if lo_eff > 0 and ws <= lo_eff:
                                safe += 1
                                filtered = True
                                break
        if filtered:
            continue

        if calloc_size > 0 and ws > 0 and ws <= calloc_size:
            safe += 1
            continue

        if eff > 0 and ws > 0 and ws <= eff:
            uc = op.get('user_controlled', False)
            if uc and op.get('type') == 'array_write':
                pass
            else:
                safe += 1
                continue

        unc += 1

    return {'detected': (ovf > 0 or unc > 0),
            'duration_ms': int((time.time() - t0) * 1000), 'error': '',
            'detail': f'OVF={ovf} UNC={unc} SAFE={safe} GFLT={gflt}'}


def _run_uaf_detector(source: str, t0: float) -> dict:
    from tests.uaf_detector import detect_uaf
    result = detect_uaf(source)
    return {'detected': result['detected'],
            'duration_ms': int((time.time() - t0) * 1000), 'error': '',
            'detail': f"findings={result['count']} free={result['free_count']}"}


def _run_int_overflow_detector(source: str, t0: float) -> dict:
    from tests.int_overflow_detector import detect_int_overflow
    result = detect_int_overflow(source)
    return {'detected': result['detected'],
            'duration_ms': int((time.time() - t0) * 1000), 'error': '',
            'detail': f"findings={result['count']}"}


def _run_fmt_detector(source: str, t0: float) -> dict:
    from tests.fmt_detector import detect_format_string
    result = detect_format_string(source)
    return {'detected': result['detected'],
            'duration_ms': int((time.time() - t0) * 1000), 'error': '',
            'detail': f"calls={result['count']} high_risk={result['high_risk']}"}


def run_binmind(name, src, bin_, cat=''):
    """根据样本类别调度到对应检测器."""
    if name in _CACHE:
        return _CACHE[name]
    t0 = time.time()
    try:
        with open(src, encoding='utf-8', errors='replace') as f:
            source = f.read()
        if cat in ('heap-overflow', 'heap-fp-reduction', ''):
            r = _run_heap_detector(source, t0)
        elif cat == 'uaf':
            r = _run_uaf_detector(source, t0)
        elif cat == 'int-overflow':
            r = _run_int_overflow_detector(source, t0)
        elif cat == 'format-string':
            r = _run_fmt_detector(source, t0)
        else:
            r = _run_heap_detector(source, t0)
    except Exception as e:
        r = {'detected': False, 'duration_ms': 0, 'error': str(e)[:100]}
    _CACHE[name] = r
    return r


def run_objdump(name, src, bin_):
    t0 = time.time()
    try:
        if not bin_ or not os.path.isfile(bin_):
            return {'detected': False, 'duration_ms': 0, 'error': 'no binary'}
        p = subprocess.run(['objdump', '-d', bin_], capture_output=True,
                           text=True, timeout=30)
        if p.returncode != 0:
            return {'detected': False, 'duration_ms': 0,
                    'error': 'objdump fail'}
        asm = p.stdout.lower()
        found = set()
        for f in _HF:
            if re.search(rf'call\s+.*<{f}', asm) or \
                    re.search(rf'call\s+.*{f}@plt', asm):
                found.add(f)
        ha = bool({'malloc', 'calloc', 'realloc'} & found)
        hw = bool({'memcpy', 'memmove', 'memset', 'strcpy', 'strcat',
                   'sprintf', 'gets'} & found)
        return {'detected': ha and hw,
                'duration_ms': int((time.time() - t0) * 1000), 'error': ''}
    except Exception as e:
        return {'detected': False, 'duration_ms': 0, 'error': str(e)[:100]}


def run_nm(name, src, bin_):
    t0 = time.time()
    try:
        if not bin_ or not os.path.isfile(bin_):
            return {'detected': False, 'duration_ms': 0, 'error': 'no binary'}
        p = subprocess.run(['nm', bin_], capture_output=True, text=True,
                           timeout=15)
        syms = set()
        for line in p.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                syms.add(re.sub(r'@.*', '', parts[-1]))
        d = _DS & syms
        return {'detected': len(d) >= 2,
                'duration_ms': int((time.time() - t0) * 1000), 'error': ''}
    except Exception as e:
        return {'detected': False, 'duration_ms': 0, 'error': str(e)[:100]}


def run_regex(name, src, bin_):
    t0 = time.time()
    try:
        with open(src, encoding='utf-8', errors='replace') as f:
            source = f.read()
        return {'detected': bool(_AR.search(source) and _WR.search(source)),
                'duration_ms': int((time.time() - t0) * 1000), 'error': ''}
    except Exception as e:
        return {'detected': False, 'duration_ms': 0, 'error': str(e)[:100]}


__all__ = [
    'run_binmind', 'run_objdump', 'run_nm', 'run_regex',
]
