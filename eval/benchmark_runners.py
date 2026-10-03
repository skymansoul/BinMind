"""
多工具对比 — 各工具运行器 (BinMind / Objdump / Nm / Regex)。
"""
import os, re, time, subprocess
from typing import Dict


# 共享的守卫推断 (与 pipeline_scanner.infer_guards 一致)

def _infer_guards(source: str) -> dict:
    """从源码推断守卫条件。"""
    macros = {}
    for line in source.splitlines():
        m = re.match(r'#define\s+(\w+)\s+(\d+)\b', line.strip())
        if m:
            macros[m.group(1)] = int(m.group(2))
    guards: Dict[str, int] = {}
    for line in source.splitlines():
        stripped = line.strip()
        m = re.search(r'if\s*\(\s*(\w+)\s*(<=?)\s*(\w+)\s*\)', stripped)
        if m:
            var, op, bound_str = m.group(1), m.group(2), m.group(3)
            bound = None
            try:
                bound = int(bound_str)
            except ValueError:
                if bound_str in macros:
                    bound = macros[bound_str]
            if bound is not None:
                if op == '<=':
                    bound += 1
                if var not in guards or bound < guards[var]:
                    guards[var] = bound
        m2 = re.search(
            r'if\s*\(\s*(\w+)\s*>=\s*(\w+)\s*\)\s*(?:return|exit|goto)',
            stripped,
        )
        if m2:
            var, bound_str = m2.group(1), m2.group(2)
            bound = None
            try:
                bound = int(bound_str)
            except ValueError:
                if bound_str in macros:
                    bound = macros[bound_str]
            if bound is not None:
                if var not in guards or bound < guards[var]:
                    guards[var] = bound
    return guards


# Tool 1: BinMind 仿射边界验证

def run_binmind(name: str, src_path: str, binary_path: str) -> dict:
    """运行 BinMind 仿射边界验证管线: 源码扫描 + 守卫推断 + 分类。"""
    t0 = time.time()
    try:
        from tests.source_scanner import extract_heap_ops_c
        from tests.source_classifier import classify_finding

        with open(src_path, encoding='utf-8', errors='replace') as f:
            source = f.read()
        guard_bounds = _infer_guards(source)

        ops = extract_heap_ops_c(source)
        overflow = uncertain = safe = guard_filtered = 0

        for op in ops:
            cls = classify_finding(op)
            write_type = op.get('type', '')
            idx_var = op.get('idx_var', '')
            guarded = False
            if write_type == 'array_write' and idx_var:
                if idx_var in guard_bounds:
                    gb = guard_bounds[idx_var]
                    eff = op.get('alloc_effective', 0)
                    if gb > 0 and eff > 0 and gb <= eff:
                        guarded = True
                        guard_filtered += 1

            if cls == 'SAFE' or guarded:
                safe += 1
            elif cls == 'OVERFLOW':
                overflow += 1
            else:
                uncertain += 1

        detected = (overflow > 0 or uncertain > 0)
        return {
            'tool': 'BinMind-GAPSBV', 'sample': name,
            'detected': detected, 'overflow': overflow,
            'uncertain': uncertain, 'safe': safe,
            'guard_filtered': guard_filtered,
            'duration_ms': int((time.time() - t0) * 1000),
            'error': '',
        }
    except Exception as e:
        return {
            'tool': 'BinMind-GAPSBV', 'sample': name,
            'detected': False, 'overflow': 0, 'uncertain': 0,
            'safe': 0, 'guard_filtered': 0,
            'duration_ms': int((time.time() - t0) * 1000),
            'error': f'{type(e).__name__}: {str(e)[:200]}',
        }


# Tool 2: Objdump-Naive

_HEAP_FUNCS = {'malloc', 'calloc', 'realloc', 'memcpy', 'memmove', 'memset',
               'strcpy', 'strcat', 'sprintf', 'gets', 'free'}


def run_objdump(name: str, src_path: str, binary_path: str) -> dict:
    """objdump 反汇编 + 堆函数调用检测: 有malloc且有写入函数 → 报。"""
    t0 = time.time()
    try:
        if not binary_path or not os.path.isfile(binary_path):
            return {'tool': 'Objdump-Naive', 'sample': name,
                    'detected': False, 'duration_ms': 0, 'error': 'no binary'}

        proc = subprocess.run(
            ['objdump', '-d', binary_path],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            return {'tool': 'Objdump-Naive', 'sample': name,
                    'detected': False, 'duration_ms': 0,
                    'error': f'objdump failed: {proc.stderr[:100]}'}

        asm = proc.stdout.lower()
        found_funcs = set()
        for func in _HEAP_FUNCS:
            if re.search(rf'call\s+.*<{func}', asm) or \
               re.search(rf'call\s+.*{func}@plt', asm):
                found_funcs.add(func)

        has_alloc = bool({'malloc', 'calloc', 'realloc'} & found_funcs)
        has_write = bool({'memcpy', 'memmove', 'memset', 'strcpy',
                          'strcat', 'sprintf', 'gets'} & found_funcs)
        detected = has_alloc and has_write
        return {
            'tool': 'Objdump-Naive', 'sample': name,
            'detected': detected, 'found_funcs': sorted(found_funcs),
            'duration_ms': int((time.time() - t0) * 1000),
            'error': '',
        }
    except Exception as e:
        return {
            'tool': 'Objdump-Naive', 'sample': name,
            'detected': False, 'duration_ms': int((time.time() - t0) * 1000),
            'error': f'{type(e).__name__}: {str(e)[:200]}',
        }


# Tool 3: Nm-Symbol

_DANGEROUS_SYMS = {'malloc', 'calloc', 'realloc', 'memcpy', 'strcpy',
                   'strcat', 'sprintf', 'gets'}


def run_nm(name: str, src_path: str, binary_path: str) -> dict:
    """nm 符号表扫描: 同时引用malloc+危险函数 → 盲报。"""
    t0 = time.time()
    try:
        if not binary_path or not os.path.isfile(binary_path):
            return {'tool': 'Nm-Symbol', 'sample': name,
                    'detected': False, 'duration_ms': 0, 'error': 'no binary'}

        proc = subprocess.run(
            ['nm', binary_path],
            capture_output=True, text=True, timeout=15,
        )
        if proc.returncode != 0:
            return {'tool': 'Nm-Symbol', 'sample': name,
                    'detected': False, 'duration_ms': 0,
                    'error': f'nm failed: {proc.stderr[:100]}'}

        syms = set()
        for line in proc.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3:
                sym_name = re.sub(r'@.*', '', parts[-1])
                syms.add(sym_name)
            elif len(parts) == 2:
                syms.add(parts[-1])

        dangerous = _DANGEROUS_SYMS & syms
        detected = len(dangerous) >= 2
        return {
            'tool': 'Nm-Symbol', 'sample': name,
            'detected': detected, 'dangerous_syms': sorted(dangerous),
            'duration_ms': int((time.time() - t0) * 1000),
            'error': '',
        }
    except Exception as e:
        return {
            'tool': 'Nm-Symbol', 'sample': name,
            'detected': False, 'duration_ms': int((time.time() - t0) * 1000),
            'error': f'{type(e).__name__}: {str(e)[:200]}',
        }


# Tool 4: Regex-Baseline (纯正则, 无分配器模型/守卫推断)

_ALLOC_SIMPLE = re.compile(r'(malloc|calloc|realloc)\s*\(([^;]+)\)\s*;', re.I)
_WRITE_SIMPLE = re.compile(
    r'(memcpy|memmove|memset|strcpy|strncpy|strcat|sprintf|gets)\s*\(', re.I)


def run_regex_baseline(name: str, src_path: str, binary_path: str) -> dict:
    """纯正则基线: 源码中出现malloc+危险写入 → 盲报。"""
    t0 = time.time()
    try:
        with open(src_path, encoding='utf-8', errors='replace') as f:
            source = f.read()
        has_alloc = bool(_ALLOC_SIMPLE.search(source))
        has_write = bool(_WRITE_SIMPLE.search(source))
        detected = has_alloc and has_write
        return {
            'tool': 'Regex-Baseline', 'sample': name,
            'detected': detected,
            'duration_ms': int((time.time() - t0) * 1000),
            'error': '',
        }
    except Exception as e:
        return {
            'tool': 'Regex-Baseline', 'sample': name,
            'detected': False,
            'duration_ms': int((time.time() - t0) * 1000),
            'error': f'{type(e).__name__}: {str(e)[:200]}',
        }
