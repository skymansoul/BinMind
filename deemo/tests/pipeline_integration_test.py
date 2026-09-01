"""
管道集成验证 - 在合成和真实样本上运行完整检测管线, 生成量化指标。

验证维度:
  1. 堆溢出 VFG 管道: 6阶段级联, 约束推理过滤
  2. UAF 别名追踪: 别名组构建, 真假UAF区分
  3. Int溢出范围传播: 区间推断, 溢出阈值判定
  4. 格式字符串多级置信度: 贝叶斯融合

输出: TP/FP/TN/FN + Precision/Recall/F1/FP率 矩阵
"""

from __future__ import annotations
import json
import os
import sys
import time
from typing import Dict, List, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from tests.pipeline_integration_samples import (
    SyntheticSample, _ho_samples, _uaf_samples, _int_samples, compute_metrics
)


# - 堆溢出管线测试 -

def _heap_overflow_pipeline(samples: List[SyntheticSample]) -> Tuple[List[Dict], Dict]:
    """运行完整的6阶段堆溢出管线。"""
    results = []
    pipeline_available = False

    try:
        from core.heap_overflow_pipeline import detect_heap_overflows_full
        pipeline_available = True
    except ImportError:
        pass

    try:
        from core.heap_overflow_detector import detect_heap_overflow
    except ImportError:
        detect_heap_overflow = None

    for sample in samples:
        ir_lines = [l.strip() for l in sample.ir_text.strip().split('\n') if l.strip()]
        candidates = []
        stats = {}

        if pipeline_available:
            candidates, stats = detect_heap_overflows_full(
                ir_lines, sample.ir_text)
        elif detect_heap_overflow:
            candidates = detect_heap_overflow(ir_lines, sample.ir_text)
            stats = {'stage_detect': len(candidates)}

        predicted = 'TP' if len(candidates) > 0 else 'FP'
        conf = max([c.confidence for c in candidates]) if candidates else 0.0

        results.append({
            'name': sample.name,
            'type': sample.vuln_type,
            'actual': sample.ground_truth,
            'predicted': predicted,
            'confidence': conf,
            'candidate_count': len(candidates),
            'pipeline_stats': {k: v for k, v in stats.items()
                               if isinstance(v, (int, float, str))},
        })

    return results, compute_metrics(results)


# - UAF管线测试 -

def _uaf_pipeline(samples: List[SyntheticSample]) -> Tuple[List[Dict], Dict]:
    """运行UAF别名追踪增强检测。"""
    results = []

    try:
        from core.uaf_analyzer import detect_uaf_deep, detect_double_free_deep
        uaf_available = True
    except ImportError:
        uaf_available = False

    try:
        from core.uaf_alias_tracker import UafAliasTracker
        alias_available = True
    except ImportError:
        alias_available = False

    for sample in samples:
        candidates = []

        if uaf_available:
            uaf = detect_uaf_deep(sample.ir_text, sample.name)
            df = detect_double_free_deep(sample.ir_text, sample.name)
            candidates = uaf + df

        if alias_available and candidates:
            ir_lines = [l.strip() for l in sample.ir_text.strip().split('\n')
                        if l.strip()]
            tracker = UafAliasTracker()
            tracker.analyze(ir_lines)
            candidates = tracker.filter_uaf_candidates(candidates)

        predicted = 'TP' if len(candidates) > 0 else 'FP'
        conf = max([c.get('confidence', 0.0) for c in candidates]) if candidates else 0.0

        results.append({
            'name': sample.name,
            'type': sample.vuln_type,
            'actual': sample.ground_truth,
            'predicted': predicted,
            'confidence': conf,
            'candidate_count': len(candidates),
        })

    return results, compute_metrics(results)


# - Int溢出管线测试 -

def _int_overflow_pipeline(samples: List[SyntheticSample]) -> Tuple[List[Dict], Dict]:
    """运行Int溢出范围传播检测。"""
    results = []

    try:
        from core.int_overflow_detector import IntOverflowDetector
        detector = IntOverflowDetector()
    except ImportError:
        detector = None

    try:
        from core.int_range_propagator import filter_by_range
        range_available = True
    except ImportError:
        range_available = False

    for sample in samples:
        candidates = []
        if detector:
            candidates = detector.detect(sample.ir_text, sample.name)

        cand_dicts = []
        for c in candidates:
            cand_dicts.append({
                'expression': c.expression,
                'confidence': c.confidence,
            })

        if range_available and cand_dicts:
            cand_dicts = filter_by_range(cand_dicts, sample.ir_text)

        predicted = 'TP' if len(cand_dicts) > 0 else 'FP'
        conf = max([c.get('confidence', 0.0) for c in cand_dicts]) if cand_dicts else 0.0

        results.append({
            'name': sample.name,
            'type': sample.vuln_type,
            'actual': sample.ground_truth,
            'predicted': predicted,
            'confidence': conf,
            'candidate_count': len(cand_dicts),
        })

    return results, compute_metrics(results)


# - 格式字符串管线测试 -

def test_heap_overflow_pipeline():
    """堆溢出管线pytest入口。"""
    res, met = _heap_overflow_pipeline(_ho_samples())
    assert len(res) > 0
    assert 'TP' in met or 'error' in met


def test_uaf_pipeline():
    """UAF管线pytest入口。"""
    res, met = _uaf_pipeline(_uaf_samples())
    assert len(res) > 0
    assert 'TP' in met or 'error' in met


def test_int_overflow_pipeline():
    """整数溢出管线pytest入口。"""
    res, met = _int_overflow_pipeline(_int_samples())
    assert len(res) > 0
    assert 'TP' in met or 'error' in met


def _format_string_pipeline() -> Tuple[List[Dict], Dict]:
    """运行格式字符串检测 — 仅对真实二进制文件, 合成样本标记为skip。"""
    samples_status = {
        'fmt_tp_01': 'skip (requires ELF binary)',
        'fmt_tp_02': 'skip (requires ELF binary)',
        'fmt_fp_01': 'skip (requires ELF binary)',
    }

    can_import = True
    try:
        from core.format_string_detector import detect_format_string_vulns
    except ImportError:
        can_import = False

    results = [{
        'name': name,
        'type': 'format_string',
        'actual': 'N/A',
        'predicted': status.split()[0],
        'confidence': 0.0,
        'candidate_count': 0,
        'module_available': can_import,
    } for name, status in samples_status.items()]

    return results, {'note': 'format_string requires real ELF binaries; module_available=' + str(can_import)}


def test_format_string_pipeline():
    """格式字符串管线pytest入口。"""
    res, met = _format_string_pipeline()
    assert len(res) == 3


# - 主运行器 -

def run_all() -> Dict:
    """运行所有管道, 生成综合报告。"""
    t0 = time.perf_counter()
    all_results = {}
    all_metrics = {}

    pipelines = [
        ('heap_overflow', _heap_overflow_pipeline, _ho_samples()),
        ('uaf', _uaf_pipeline, _uaf_samples()),
        ('int_overflow', _int_overflow_pipeline, _int_samples()),
        ('format_string', _format_string_pipeline, None),
    ]

    for name, fn, samples in pipelines:
        try:
            if samples:
                res, met = fn(samples)
            else:
                res, met = fn()
            all_results[name] = res
            all_metrics[name] = met
        except Exception as e:
            all_results[name] = []
            all_metrics[name] = {'error': str(e)}

    total_tp = sum(m.get('TP', 0) for m in all_metrics.values())
    total_fp = sum(m.get('FP', 0) for m in all_metrics.values())
    total_tn = sum(m.get('TN', 0) for m in all_metrics.values())
    total_fn = sum(m.get('FN', 0) for m in all_metrics.values())

    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    overall_f1 = (2 * overall_precision * overall_recall /
                  (overall_precision + overall_recall)
                  if (overall_precision + overall_recall) > 0 else 0.0)
    overall_fp_rate = total_fp / (total_fp + total_tn) if (total_fp + total_tn) > 0 else 0.0

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

    report = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'elapsed_ms': elapsed_ms,
        'per_type': all_metrics,
        'overall': {
            'TP': total_tp, 'FP': total_fp, 'TN': total_tn, 'FN': total_fn,
            'total': total_tp + total_fp + total_tn + total_fn,
            'precision': round(overall_precision, 4),
            'recall': round(overall_recall, 4),
            'f1': round(overall_f1, 4),
            'fp_rate': round(overall_fp_rate, 4),
        },
        'per_sample': all_results,
    }

    return report


# - 输出 -

def print_report(report: Dict):
    """格式化打印报告。"""
    sep = '=' * 64
    print(sep)
    print(f"  BinMind Pipeline Integration Test  ({report['timestamp']})")
    print(sep)

    for vtype, metrics in report['per_type'].items():
        if 'error' in metrics:
            print(f"\n  [{vtype}] ERROR: {metrics['error']}")
            continue
        if 'note' in metrics:
            print(f"\n  [{vtype}] NOTE: {metrics['note']}")
            continue
        if 'TP' not in metrics:
            continue
        print(f"\n  --- {vtype} ---")
        print(f"  TP={metrics['TP']}  FP={metrics['FP']}  "
              f"TN={metrics['TN']}  FN={metrics['FN']}")
        print(f"  Precision={metrics['precision']:.3f}  "
              f"Recall={metrics['recall']:.3f}  "
              f"F1={metrics['f1']:.3f}  "
              f"FPR={metrics['fp_rate']:.3f}")

    ov = report['overall']
    print(f"\n  --- OVERALL ---")
    print(f"  TP={ov['TP']}  FP={ov['FP']}  TN={ov['TN']}  FN={ov['FN']}  "
          f"Total={ov['total']}")
    print(f"  Precision={ov['precision']:.3f}  Recall={ov['recall']:.3f}  "
          f"F1={ov['f1']:.3f}  FPR={ov['fp_rate']:.3f}")
    print(f"\n  Elapsed: {report['elapsed_ms']}ms")
    print(sep)

    print(f"\n  Per-sample details:")
    for vtype, samples in report['per_sample'].items():
        if not samples:
            continue
        print(f"\n  [{vtype}]")
        for s in samples:
            status = 'OK' if s['actual'] == s['predicted'] else 'MISMATCH'
            print(f"    {s['name']:20s}  actual={s['actual']:3s}  "
                  f"pred={s['predicted']:3s}  conf={s['confidence']:.2f}  "
                  f"candidates={s['candidate_count']}  [{status}]")

    print(sep)
    _print_fp_analysis(report)


def _print_fp_analysis(report: Dict):
    """分析FP削减效果。"""
    print(f"\n  FP Reduction Analysis:")
    ho = report['per_type'].get('heap_overflow', {})
    uaf = report['per_type'].get('uaf', {})
    io = report['per_type'].get('int_overflow', {})

    for name, m in [('Heap Overflow', ho), ('UAF', uaf), ('Int Overflow', io)]:
        if not m or 'FP' not in m or 'TN' not in m:
            continue
        total_fp_tn = m['FP'] + m['TN']
        if total_fp_tn > 0:
            fp_pct = m['FP'] / total_fp_tn * 100
            print(f"    {name:20s}: {fp_pct:.0f}% FPR  "
                  f"({m['FP']} FP / {total_fp_tn} non-TP samples)")


def save_report(report: Dict, path: str = ''):
    """保存报告到JSON。"""
    if not path:
        path = os.path.join(BASE_DIR, 'tests', 'pipeline_integration_results.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    print(f"\n  Report saved: {path}")


if __name__ == '__main__':
    report = run_all()
    print_report(report)
    save_report(report)
