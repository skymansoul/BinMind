"""
PTASM 端到端基准测试 — Pointer Temporal Automaton State Machine UAF检测.
对 UAF 样本 (正例) 和安全模式样本 (负例) 运行 PTASM 分析,
输出 TP/FP/TN/FN + Precision/Recall/F1 + 逐样本详情.

与 GAPSBV benchmark 保持一致的设计风格.
"""

from __future__ import annotations

import json, os, sys, time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

# 样本发现

UAF_SAMPLE_ROOTS = [
    'tests/cve_samples/uaf',
]

# 正例: 真正的 UAF 漏洞 (应检出)
UAF_POSITIVE_SAMPLES = {
    'uaf_01', 'uaf_02', 'uaf_03', 'uaf_04', 'uaf_05',
    'uaf_06', 'uaf_07', 'uaf_08', 'uaf_15',
}

# 负例: 安全模式 (不应检出 — free后nullify/reassign等)
UAF_NEGATIVE_SAMPLES = {
    'uaf_09', 'uaf_10', 'uaf_11', 'uaf_12', 'uaf_13', 'uaf_14',
}


def discover_uaf_samples() -> Tuple[List[dict], List[dict]]:
    """发现 UAF 正例和负例样本.

    返回:
        (positive_samples, negative_samples)
        每个样本: {'name': str, 'path': str, 'source': str}
    """
    positive = []
    negative = []

    for root_name in UAF_SAMPLE_ROOTS:
        root = os.path.join(BASE, root_name)
        if not os.path.isdir(root):
            continue
        for sd in sorted(Path(root).iterdir()):
            if not sd.is_dir():
                continue
            # 找目录中的第一个 .c 文件
            c_files = list(sd.glob('*.c'))
            if not c_files:
                continue
            sample = {
                'name': sd.name,
                'path': str(sd),
                'source': str(c_files[0]),
            }
            if sd.name in UAF_POSITIVE_SAMPLES:
                positive.append(sample)
            elif sd.name in UAF_NEGATIVE_SAMPLES:
                negative.append(sample)

    return positive, negative


def read_source(path: str) -> str:
    """读取 C 源码."""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except Exception:
        return ""


# 检测引擎

def run_ptasm_detect(code: str) -> Dict:
    """PTASM 检测: 形式化指针时序状态机分析.

    返回:
        {
            detected: bool,
            findings: List[dict],
            stats: dict,
            reason: str,
        }
    """
    result = {
        'detected': False,
        'findings': [],
        'stats': {},
        'reason': '',
    }

    try:
        from analysis.ptasm_engine import PTASMEngine
        engine = PTASMEngine()
        findings, stats = engine.analyze(code)

        result['stats'] = {
            'allocs_found': stats.allocs_found,
            'frees_found': stats.frees_found,
            'uses_found': stats.uses_found,
            'aliases_tracked': stats.aliases_tracked,
            'uaf_confirmed': stats.uaf_confirmed,
            'safe_filtered': stats.safe_filtered,
            'uncertain': stats.uncertain,
            'paths_explored': stats.paths_explored,
        }

        uaf_findings = [f for f in findings if f.uaf_detected]
        if uaf_findings:
            result['detected'] = True
            result['findings'] = [
                {
                    'ptr_name': f.ptr_name,
                    'verdict': f.verdict.value,
                    'free_line': f.free_line,
                    'use_line': f.use_line,
                    'guarded': f.guarded,
                    'aliases': f.aliases_involved,
                    'reason': f.reason,
                }
                for f in uaf_findings
            ]
            result['reason'] = '; '.join(f.reason for f in uaf_findings)
        else:
            safe_findings = [f for f in findings if f.safe]
            if safe_findings:
                result['reason'] = 'SAFE: ' + '; '.join(
                    f'{f.ptr_name} {f.reason}' for f in safe_findings)
            else:
                result['reason'] = 'UNCERTAIN: ' + '; '.join(
                    f'{f.ptr_name} {f.reason}' for f in findings
                ) if findings else 'no tracked pointers'

    except ImportError as e:
        result['reason'] = f'ImportError: {e}'
    except Exception as e:
        result['reason'] = f'Error: {e}'

    return result


def run_baseline_uaf_detect(code: str) -> Dict:
    """基线 UAF 检测: 简单 free→use 正则 (参考 tests/uaf_detector.py).

    返回:
        {detected: bool, count: int, reason: str}
    """
    result = {'detected': False, 'count': 0, 'reason': ''}

    try:
        from tests.uaf_detector import detect_uaf
        findings = detect_uaf(code)
        result['count'] = findings.get('count', 0)
        result['detected'] = findings.get('detected', False)
        if result['detected']:
            lines = [f"{f.get('ptr_var','?')} free@L{f.get('free_line','?')}"
                     f" use@L{f.get('use_line','?')}"
                     for f in findings.get('findings', [])]
            result['reason'] = f'{result["count"]} finding(s): ' + '; '.join(lines[:5])
        else:
            result['reason'] = 'no UAF detected by baseline'
    except ImportError as e:
        result['reason'] = f'ImportError: {e}'
    except Exception as e:
        result['reason'] = f'Error: {e}'

    return result


# 分类与指标

def classify(should_detect: bool, detected: bool) -> str:
    """(期望, 实际) → 分类标签."""
    if should_detect and detected:
        return 'TP'
    if should_detect and not detected:
        return 'FN'
    if not should_detect and detected:
        return 'FP'
    return 'TN'


def compute_metrics(results: List[dict]) -> Dict:
    """从分类结果计算 precision/recall/F1/FPR."""
    tp = sum(1 for r in results if r['class'] == 'TP')
    fp = sum(1 for r in results if r['class'] == 'FP')
    fn = sum(1 for r in results if r['class'] == 'FN')
    tn = sum(1 for r in results if r['class'] == 'TN')

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        'TP': tp, 'FP': fp, 'FN': fn, 'TN': tn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'fp_rate': round(fpr, 4),
        'total': len(results),
    }


# 主入口

def run_benchmark() -> Dict:
    """主入口: 发现样本 → 检测 → 分类 → 输出."""
    positive, negative = discover_uaf_samples()
    total = len(positive) + len(negative)
    print(f'Discovered {len(positive)} UAF (positive) + '
          f'{len(negative)} safe (negative) = {total} samples')

    baseline_results = []
    ptasm_results = []
    all_samples = []

    # 正例: should_detect=True
    for s in positive:
        code = read_source(s['source'])
        if not code:
            continue
        all_samples.append((s, True, code))

    # 负例: should_detect=False
    for s in negative:
        code = read_source(s['source'])
        if not code:
            continue
        all_samples.append((s, False, code))

    for i, (s, should_detect, code) in enumerate(all_samples):
        name = s['name']

        # 基线检测
        b_result = run_baseline_uaf_detect(code)
        b_detected = b_result['detected']
        b_class = classify(should_detect, b_detected)
        baseline_results.append({
            'name': name,
            'class': b_class,
            'detected': b_detected,
            'expected': should_detect,
            'count': b_result['count'],
            'reason': b_result['reason'],
        })

        # PTASM 检测
        e_result = run_ptasm_detect(code)
        e_detected = e_result['detected']
        e_class = classify(should_detect, e_detected)
        ptasm_results.append({
            'name': name,
            'class': e_class,
            'detected': e_detected,
            'expected': should_detect,
            'findings': e_result['findings'],
            'stats': e_result['stats'],
            'reason': e_result['reason'],
        })

        if (i + 1) % 10 == 0:
            print(f'  processed {i + 1}/{total}...')

    b_metrics = compute_metrics(baseline_results)
    p_metrics = compute_metrics(ptasm_results)

    # 计算改进
    fp_reduction = 0.0
    if b_metrics['FP'] > 0:
        fp_reduction = (b_metrics['FP'] - p_metrics['FP']) / b_metrics['FP'] * 100
    fn_reduction = 0.0
    if b_metrics['FN'] > 0:
        fn_reduction = (b_metrics['FN'] - p_metrics['FN']) / b_metrics['FN'] * 100

    output = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'engine': 'PTASM (Pointer Temporal Automaton State Machine)',
        'sample_count': total,
        'positive_samples': len(positive),
        'negative_samples': len(negative),
        'baseline': b_metrics,
        'ptasm': p_metrics,
        'fp_reduction_percent': round(fp_reduction, 1),
        'fn_reduction_percent': round(fn_reduction, 1),
        'f1_improvement': round(p_metrics['f1'] - b_metrics['f1'], 4),
        'details': {
            'baseline': baseline_results,
            'ptasm': ptasm_results,
        },
    }

    # 写入结果文件
    out_path = os.path.join(BASE, 'eval', 'ptasm_benchmark_results.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # 打印摘要
    sep = '-' * 68
    print(f'\n{"="*68}')
    print(f'PTASM UAF Benchmark Results ({total} samples: '
          f'{len(positive)} positive + {len(negative)} negative)')
    print(f'{"="*68}')
    print(f'{"Metric":<20} {"Baseline":>14} {"PTASM":>14} {"Change":>16}')
    print(sep)
    for key, label in [('precision', 'Precision'), ('recall', 'Recall'),
                        ('f1', 'F1 Score'), ('fp_rate', 'FP Rate')]:
        bv = b_metrics[key]
        pv = p_metrics[key]
        ch = pv - bv
        sign = '+' if ch > 0 else ''
        print(f'{label:<20} {bv:>13.4f} {pv:>13.4f} {sign}{ch:>15.4f}')
    print(sep)
    print(f'{"TP":<20} {b_metrics["TP"]:>13} {p_metrics["TP"]:>13}')
    print(f'{"FP":<20} {b_metrics["FP"]:>13} {p_metrics["FP"]:>13}')
    print(f'{"FN":<20} {b_metrics["FN"]:>13} {p_metrics["FN"]:>13}')
    print(f'{"TN":<20} {b_metrics["TN"]:>13} {p_metrics["TN"]:>13}')
    print(sep)
    if fp_reduction != 0:
        print(f'FP Reduction: {fp_reduction:.1f}%')
    if fn_reduction != 0:
        print(f'FN Reduction: {fn_reduction:.1f}%')
    print(f'F1 Improvement: {p_metrics["f1"] - b_metrics["f1"]:+.4f}')
    print(f'\nResults written to: {out_path}')

    # 逐样本详情
    print(f'\n{"─"*68}')
    print('Per-sample detail:')
    print(f'{"─"*68}')
    for b, p in zip(baseline_results, ptasm_results):
        if b['class'] == p['class']:
            status = 'OK'
        elif b['class'] in ('FN', 'FP') and p['class'] in ('TP', 'TN'):
            status = 'UPGRADE'
        else:
            status = 'DEGRADE'
        print(f'  {b["name"]:<20} base={b["class"]:3s} ptasm={p["class"]:3s}  {status}')
        if p['class'] in ('FN', 'FP'):
            print(f'    PTASM reason: {p["reason"][:120]}')

    return output


if __name__ == '__main__':
    run_benchmark()
