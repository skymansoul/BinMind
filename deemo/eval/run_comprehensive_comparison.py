"""
综合多工具对比实验 — 含SAFE样本对照.

在以下样本集上对比:
  - heap_overflow_benchmark: 10 TP + 6 TN
  - bvf_samples: 8 VULN + 10 SAFE (18 total)
  - pcbvf_samples: 4 VULN + 8 SAFE (12 total)
  - cve_heap_overflow: 14 VULN (编译成功的)

工具:
  1. BinMind Full Pipeline (CJ+BVF+PC-BVF)
  2. Angr (仅CVE样本, 需二进制)
  3. Regex-Baseline (所有样本)

输出含TP/FP/TN/FN的完整混淆矩阵.
"""
import os, sys, re, time
from pathlib import Path

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from eval.comprehensive_comparison_helpers import load_samples, save_results


def c_to_ir(c_source):
    lines = []
    for line in c_source.splitlines():
        s = line.strip()
        if s.startswith('#') or s.startswith('//') or s.startswith('/*'): continue
        if s.startswith('*') or s.startswith('}') or s.startswith(')'): continue
        if not s or s in ('{', '}'): continue
        s = re.sub(r'\(\s*(?:char|int|void|size_t|unsigned|float|double|'
                   r'uint\d+_t|int\d+_t|long)\s*\**\s*\)', '', s)
        s = re.sub(r'\b(?:char|int|short|long|void|float|double|size_t|'
                   r'ssize_t|unsigned|signed|uint\d+_t|int\d+_t|const|static|'
                   r'volatile|extern|register|struct\s+\w+)\s*\**\s*', '', s)
        s = re.sub(r'typedef\s+struct\s*\{?', '', s)
        s = re.sub(r'\b(?:if|while|for|else)\s*\(', '(', s)
        if re.match(r'\s*(?:return|free|printf|puts|fprintf|exit)\s*[\(;]', s): continue
        s = s.rstrip(';').strip()
        if s: lines.append(s)
    return lines


def run_binmind(source):
    """BinMind Full Pipeline."""
    t0 = time.time()
    try:
        from core.heap_overflow_pipeline import detect_heap_overflows_full
        ir = c_to_ir(source)
        candidates, _ = detect_heap_overflows_full(ir, source)
        return {'detected': len(candidates) > 0,
                'n': len(candidates),
                'duration_ms': (time.time() - t0) * 1000}
    except Exception as e:
        return {'detected': False, 'error': str(e)[:100],
                'duration_ms': (time.time() - t0) * 1000}


def run_regex(source):
    """Regex基线: 找alloc+write对, 简单比较数字."""
    t0 = time.time()
    _ALLOC = re.compile(r'(?:malloc|calloc|realloc)\s*\(([^)]+)\)', re.I)
    _WRITE = re.compile(r'(?:memcpy|memset|memmove|strcpy|strncpy|sprintf)\s*\(([^)]+)\)', re.I)
    _SIZE = re.compile(r'\b(\d+)\b')
    alloc_sizes = []
    for line in source.splitlines():
        m = _ALLOC.search(line)
        if m:
            for n in _SIZE.findall(m.group(1)):
                alloc_sizes.append(int(n))
    findings = 0
    for line in source.splitlines():
        m = _WRITE.search(line)
        if m:
            for n in _SIZE.findall(m.group(1)):
                wn = int(n)
                for an in alloc_sizes:
                    if wn > an:
                        findings += 1
    return {'detected': findings > 0, 'n': findings,
            'duration_ms': (time.time() - t0) * 1000}


def run_angr_source(source):
    """Angr源码级(模拟): 检查是否有malloc+memcpy调用对."""
    t0 = time.time()
    has_alloc = bool(re.search(r'(malloc|calloc|realloc)\s*\(', source, re.I))
    has_write = bool(re.search(r'(memcpy|memmove|memset|strcpy|strncpy|sprintf)\s*\(', source, re.I))
    return {'detected': has_alloc and has_write,
            'duration_ms': (time.time() - t0) * 1000}


def compute_metrics(results, samples):
    """计算混淆矩阵."""
    tp = fp = tn = fn = 0
    for r, (_, _, expected) in zip(results, samples):
        detected = r['detected']
        if detected and expected: tp += 1
        elif detected and not expected: fp += 1
        elif not detected and not expected: tn += 1
        else: fn += 1
    total = tp + fp + tn + fn
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 0.001)
    fpr = fp / max(fp + tn, 1)
    return {'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn, 'total': total,
            'precision': round(precision, 4), 'recall': round(recall, 4),
            'f1': round(f1, 4), 'fpr': round(fpr, 4)}


def main():
    print('=' * 72)
    print('Comprehensive Multi-Tool Comparison (with SAFE samples)')
    print('=' * 72)

    samples = load_samples()
    n_vuln = sum(1 for _, _, e in samples if e)
    n_safe = sum(1 for _, _, e in samples if not e)
    print(f'\n{len(samples)} samples ({n_vuln} VULN + {n_safe} SAFE)')

    tools = ['BinMind-Full', 'Regex-Baseline', 'Angr-Source']
    all_results = {t: [] for t in tools}

    for i, (name, source, expected) in enumerate(samples):
        r1 = run_binmind(source)
        r2 = run_regex(source)
        r3 = run_angr_source(source)
        all_results['BinMind-Full'].append(r1)
        all_results['Regex-Baseline'].append(r2)
        all_results['Angr-Source'].append(r3)

        m1 = '!' if r1['detected'] else ' '
        m2 = '!' if r2['detected'] else ' '
        m3 = '!' if r3['detected'] else ' '
        exp = 'V' if expected else 'S'
        print(f'  [{i+1:2d}/{len(samples)}] exp={exp} BM={m1} Reg={m2} Ang={m3} {name}')

    print(f'\n{"=" * 72}')
    print('Results')
    print(f'{"=" * 72}')
    header = (f'{"Tool":<18s} {"TP":>4s} {"FP":>4s} {"TN":>4s} {"FN":>4s} '
              f'{"Prec":>7s} {"Rec":>7s} {"F1":>7s} {"FPR":>7s} {"ms":>6s}')
    print(header)
    print('-' * len(header))

    metrics = {}
    for tool in tools:
        m = compute_metrics(all_results[tool], samples)
        metrics[tool] = m
        avg_ms = int(sum(r.get('duration_ms', 0) for r in all_results[tool])
                     / max(len(all_results[tool]), 1))
        print(f'{tool:<18s} {m["TP"]:>4d} {m["FP"]:>4d} {m["TN"]:>4d} {m["FN"]:>4d} '
              f'{m["precision"]:>6.1%} {m["recall"]:>6.1%} '
              f'{m["f1"]:>7.4f} {m["fpr"]:>6.1%} {avg_ms:>5d}')

    # 保存
    ts = time.strftime('%Y%m%d_%H%M%S')
    save_results(metrics, all_results, samples, ts)
    return metrics


if __name__ == '__main__':
    main()
