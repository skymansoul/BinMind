"""

包含: BinMind CSA / Regex基线 / 启发式 / Angr CFG + 编译辅助 + 指标计算.
"""
import os, re, time, subprocess
from typing import List


# 工具1: BinMind CSA (源码分析)

def run_binmind_csa(source: str, sample_name: str, binary_path: str = '') -> dict:
    """BinMind C源码分析 — 完整管线 (source_scanner + GAPSBV + 守卫推断)."""
    t0 = time.time()
    try:
        from tests.pipeline_scanner import scan_binary
        r = scan_binary(binary_path, None)
        from tests.source_scanner import extract_heap_ops_c
        from tests.source_classifier import classify_finding
        ops = extract_heap_ops_c(source)
        overflow = sum(1 for o in ops if o.get('is_overflow'))
        uncertain = sum(1 for o in ops if not o.get('is_overflow') and classify_finding(o) == 'UNCERTAIN')
        safe = sum(1 for o in ops if classify_finding(o) == 'SAFE')
        detected = overflow > 0 or uncertain > 0
        return {
            'tool': 'BinMind-Full', 'sample': sample_name,
            'detected': detected,
            'candidates': len(ops),
            'overflow': overflow,
            'uncertain': uncertain,
            'safe': safe,
            'duration_ms': (time.time() - t0) * 1000,
        }
    except Exception as e:
        return {'tool': 'BinMind-Full', 'sample': sample_name,
                'detected': False, 'error': str(e)[:200],
                'duration_ms': (time.time() - t0) * 1000}


# 工具2: 纯正则基线 (Flawfinder 类比)

_RE_ALLOC = re.compile(r'(?:malloc|calloc|realloc)\s*\(([^)]+)\)', re.I)
_RE_WRITE = re.compile(
    r'(?:memcpy|memset|memmove|strcpy|strncpy|sprintf)\s*\(([^)]+)\)', re.I)
_RE_SIZE = re.compile(r'\b(\d+)\b')

def run_regex_baseline(source: str, sample_name: str) -> dict:
    """纯正则基线: 找 alloc+write 对, 简单比较数字."""
    t0 = time.time()
    lines = source.splitlines()
    findings = 0
    details = []

    alloc_sizes = []
    for line in lines:
        m = _RE_ALLOC.search(line)
        if m:
            nums = _RE_SIZE.findall(m.group(1))
            for n in nums:
                alloc_sizes.append(int(n))

    for line in lines:
        m = _RE_WRITE.search(line)
        if m:
            nums = _RE_SIZE.findall(m.group(1))
            for n in nums:
                write_n = int(n)
                for alloc_n in alloc_sizes:
                    if write_n > alloc_n:
                        findings += 1
                        details.append(
                            f'write({write_n}) > alloc({alloc_n})')

    detected = findings > 0
    return {
        'tool': 'Regex-Base', 'sample': sample_name,
        'detected': detected, 'findings': findings,
        'details': details[:5],
        'duration_ms': (time.time() - t0) * 1000,
    }


# 工具3: 启发式 (heuristic)

_HEAP_FUNC_RE = re.compile(
    r'(malloc|calloc|realloc|memcpy|memset|memmove|strcpy|sprintf|free)\s*\(',
    re.I)

def run_heuristic(source: str, sample_name: str) -> dict:
    """启发式: 统计堆操作密度, 计算危险评分."""
    t0 = time.time()
    lines = source.splitlines()

    alloc_count = write_count = free_count = 0
    suspicious = 0

    for i, line in enumerate(lines):
        for m in _HEAP_FUNC_RE.finditer(line):
            fname = m.group(1).lower()
            if fname in ('malloc', 'calloc', 'realloc'):
                alloc_count += 1
            elif fname in ('memcpy', 'memset', 'memmove', 'strcpy', 'sprintf'):
                write_count += 1
                if alloc_count > 0:
                    suspicious += 1
            elif fname == 'free':
                free_count += 1

    score = suspicious * 10 + write_count * 2
    detected = score > 0 and alloc_count > 0

    return {
        'tool': 'Heuristic', 'sample': sample_name,
        'detected': detected, 'score': score,
        'alloc_count': alloc_count,
        'write_count': write_count,
        'duration_ms': (time.time() - t0) * 1000,
    }


# 工具4: Angr CFG 快速扫描

def run_angr_if_available(binary_path: str, sample_name: str) -> dict:
    """Angr CFG 扫描 — 仅当binary存在且angr可用."""
    t0 = time.time()
    if not os.path.exists(binary_path):
        return {'tool': 'Angr-CFG', 'sample': sample_name,
                'detected': False, 'error': 'binary not found',
                'duration_ms': (time.time() - t0) * 1000}

    try:
        import angr
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        danger = {'memcpy', 'memmove', 'strcpy', 'sprintf', 'gets', 'scanf'}
        findings = 0
        for func in cfg.functions.values():
            for block in func.blocks:
                for insn in block.capstone.insns:
                    if insn.mnemonic == 'call':
                        try:
                            tgt = cfg.functions.get(insn.operands[0].imm)
                            if tgt and tgt.name in danger:
                                findings += 1
                        except Exception:
                            pass

        return {
            'tool': 'Angr-CFG', 'sample': sample_name,
            'detected': findings > 0,
            'danger_calls': findings,
            'func_count': len(cfg.functions),
            'duration_ms': (time.time() - t0) * 1000,
        }
    except ImportError:
        return {'tool': 'Angr-CFG', 'sample': sample_name,
                'detected': False, 'error': 'angr not installed',
                'duration_ms': (time.time() - t0) * 1000}
    except Exception as e:
        return {'tool': 'Angr-CFG', 'sample': sample_name,
                'detected': False, 'error': str(e)[:200],
                'duration_ms': (time.time() - t0) * 1000}


# 指标计算

def compute_metrics(results: List[dict]) -> dict:
    """计算 TP/FP/TN/FN/Precision/Recall/F1.
    所有CVE样本的 ground truth 均为 True (有漏洞).
    """
    tp = fp = fn = tn = 0
    for r in results:
        detected = r.get('detected', False)
        if detected:
            tp += 1
        else:
            fn += 1

    total = tp + fp + tn + fn
    precision = tp / max(tp + fp, 1)
    recall    = tp / max(tp + fn, 1)
    f1        = 2 * precision * recall / max(precision + recall, 0.001)

    return {
        'total': total, 'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
    }


# 编译辅助

def compile_cve_sample(src_path: str, out_path: str) -> bool:
    """编译单个CVE样本 (gcc)."""
    try:
        result = subprocess.run(
            ['gcc', '-O0', '-g', '-o', out_path, src_path],
            capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except Exception:
        return False


__all__ = [
    'run_binmind_csa', 'run_regex_baseline', 'run_heuristic',
    'run_angr_if_available', 'compute_metrics', 'compile_cve_sample',
]
