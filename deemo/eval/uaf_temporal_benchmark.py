"""
UAF时序路径验证基准测试 — 在12样本C源码基准集上评估TemporalPathVerifier.

对标 eval/gapsbv_ablation.py 的消融框架.
输出: eval/uaf_benchmark_results.json
"""

from __future__ import annotations

import json, os, sys, time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

# UAF C源码样本定义 — 15个C样本
UAF_SAMPLES_DIR = os.path.join(BASE, 'tests', 'vuln_samples', 'uaf')

# Ground truth: (sample_name, is_uaf, category, description)
UAF_GROUND_TRUTH = {
    'uaf_01': (True,  'direct_uaf',      'free后循环中使用已释放指针'),
    'uaf_02': (True,  'cross_func_global','跨函数UAF: free后通过全局变量使用'),
    'uaf_03': (True,  'realloc_uaf',     'realloc移动后使用旧指针'),
    'uaf_04': (True,  'cross_func_global','跨函数UAF: caller free, callee use'),
    'uaf_05': (False, 'safe_list_free',   '链表标准释放模式: h->n在free前缓存(安全)'),
    'uaf_06': (True,  'callback_uaf',    '回调中free后主函数use'),
    'uaf_07': (False, 'safe_array_free', '数组中嵌套指针逐个free后free数组(安全)'),
    'uaf_08': (True,  'tree_uaf',        '树结构free后访问子树指针'),
    'uaf_09': (True,  'double_ptr_uaf',  '双指针: free(*pp)后**pp写入'),
    'uaf_10': (False, 'safe_reuse',      'free后realloc重用变量(安全)'),
    'uaf_11': (False, 'safe_null',       'free后设NULL再检查(安全模式)'),
    'uaf_12': (False, 'safe_guard',      'free前检查且设NULL(安全模式)'),
# 新增 CVE-2025 级样本
    'uaf_16': (True,  'objcache_uaf',    '对象缓存: free后未从链表移除, 查找返回悬垂指针'),
    'uaf_17': (True,  'workqueue_uaf',   '工作队列: 异步任务排队后对象被提前释放'),
    'uaf_18': (True,  'toctou_uaf',      'TOCTOU: check后use前对象被另一路径释放'),
}


@dataclass
class UafSampleResult:
    sample_id: str
    is_uaf: bool          # ground truth
    category: str
    desc: str
    detected: bool        # verifier是否报告UAF
    uaf_count: int        # 报告的UAF数量
    safe_count: int       # 报告的SAFE数量
    uncertain_count: int  # UNCERTAIN数量
    details: List[dict]   # 每个发现的详情
    correct: bool         # detected == is_uaf
    time_ms: float = 0.0


def run_temporal_benchmark() -> Dict:
    """在12样本C源码基准集上运行TemporalPathVerifier."""
    from analysis.uaf_temporal_path_verifier import TemporalPathVerifier

    verifier = TemporalPathVerifier(max_paths=128)
    results: List[UafSampleResult] = []

    for sample_id in sorted(UAF_GROUND_TRUTH.keys()):
        is_uaf, category, desc = UAF_GROUND_TRUTH[sample_id]
        sample_dir = os.path.join(UAF_SAMPLES_DIR, sample_id)
        vuln_c = os.path.join(sample_dir, 'vuln.c')

        if not os.path.exists(vuln_c):
            print(f'  [SKIP] {sample_id}: vuln.c not found')
            continue

        with open(vuln_c, 'r', encoding='utf-8', errors='replace') as f:
            source = f.read()

        t0 = time.time()
        findings = verifier.verify(source)
        elapsed = (time.time() - t0) * 1000

        uaf_findings = [f for f in findings
                        if f.verdict.value == 'UAF']
        safe_findings = [f for f in findings
                         if f.verdict.value == 'SAFE']
        uncertain = [f for f in findings
                     if f.verdict.value == 'UNCERTAIN']

        detected = len(uaf_findings) > 0
        correct = (detected == is_uaf)

        details = []
        for f in findings:
            details.append({
                'verdict': f.verdict.value,
                'ptr': f.ptr_var,
                'free_line': f.free_line,
                'use_line': f.use_line,
                'uaf_paths': f.uaf_paths,
                'safe_paths': f.safe_paths,
                'total_paths': f.total_paths,
                'reason': f.reason,
            })

        sr = UafSampleResult(
            sample_id=sample_id, is_uaf=is_uaf,
            category=category, desc=desc,
            detected=detected,
            uaf_count=len(uaf_findings),
            safe_count=len(safe_findings),
            uncertain_count=len(uncertain),
            details=details,
            correct=correct,
            time_ms=round(elapsed, 2),
        )
        results.append(sr)

    # 汇总
    tp = sum(1 for r in results if r.detected and r.is_uaf)
    tn = sum(1 for r in results if not r.detected and not r.is_uaf)
    fp = sum(1 for r in results if r.detected and not r.is_uaf)
    fn = sum(1 for r in results if not r.detected and r.is_uaf)
    total = len(results)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = (2 * precision * recall / max(0.001, precision + recall))

    stats = {
        'total': total, 'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
        'precision': round(precision, 4), 'recall': round(recall, 4),
        'f1': round(f1, 4),
    }

    report = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'verifier': 'TemporalPathVerifier (BFS≤128 paths)',
        'stats': stats,
        'results': [
            {
                'sample_id': r.sample_id,
                'category': r.category,
                'desc': r.desc,
                'ground_truth': r.is_uaf,
                'detected': r.detected,
                'correct': r.correct,
                'uaf_count': r.uaf_count,
                'safe_count': r.safe_count,
                'uncertain_count': r.uncertain_count,
                'time_ms': r.time_ms,
                'findings': r.details,
            }
            for r in results
        ],
        'fp_samples': [
            r.sample_id for r in results if r.detected and not r.is_uaf
        ],
        'fn_samples': [
            r.sample_id for r in results if not r.detected and r.is_uaf
        ],
    }
    return report


def print_report(report: Dict) -> None:
    """控制台输出UAF基准测试报告."""
    stats = report['stats']
    print(f"\n{'='*72}")
    print(f"UAF Temporal Path Verifier - 12-Sample C Source Benchmark")
    print(f"{'='*72}")
    print(f"\n{'Sample':<10} {'GT':>5} {'Detected':>9} {'OK':>4} "
          f"{'UAF':>4} {'SAFE':>5} {'UNC':>4} {'Time(ms)':>9}  Category")
    print(f"{'-'*72}")
    for r in report['results']:
        gt = 'UAF' if r['ground_truth'] else 'SAFE'
        det = 'UAF' if r['detected'] else 'SAFE'
        ok = 'OK' if r['correct'] else 'ERR'
        print(f"{r['sample_id']:<10} {gt:>5} {det:>9} {ok:>4} "
              f"{r['uaf_count']:>4} {r['safe_count']:>5} "
              f"{r['uncertain_count']:>4} {r['time_ms']:>9.1f}  {r['category']}")

    print(f"\n  Confusion Matrix:")
    print(f"    TP={stats['tp']}  TN={stats['tn']}  FP={stats['fp']}  FN={stats['fn']}")
    print(f"    Precision={stats['precision']:.4f}  "
          f"Recall={stats['recall']:.4f}  F1={stats['f1']:.4f}")

    if report['fp_samples']:
        print(f"\n  FP (误报): {report['fp_samples']}")
        for r in report['results']:
            if r['sample_id'] in report['fp_samples']:
                for f in r['findings']:
                    if f['verdict'] == 'UAF':
                        print(f"    {r['sample_id']}: {f['reason']}")

    if report['fn_samples']:
        print(f"\n  FN (漏报): {report['fn_samples']}")
        for r in report['results']:
            if r['sample_id'] in report['fn_samples']:
                for f in r['findings']:
                    print(f"    {r['sample_id']}: {f}")


def main():
    print('[Step 1] UAF Temporal Path Verifier - 12-Sample Benchmark')
    report = run_temporal_benchmark()
    print_report(report)

    out_path = os.path.join(BASE, 'eval', 'uaf_benchmark_results.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f'\n  JSON → {out_path}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
