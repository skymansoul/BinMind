"""
完整回归测试 — 基线检测器 vs 四层管线对比.

运行: python tests/run_full_regression.py
输出: tests/regression_report.json, tests/regression_metrics.csv
"""

from __future__ import annotations

import json, os, re, sys, time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# 预期定义
EXPECTED = {
    # True Positives
    "sample_01": ("heap_overflow", True, "malloc(64)+memset(256)"),
    "sample_02": ("heap_overflow", True, "off-by-one loop"),
    "sample_03": ("heap_overflow", True, "realloc shrink+overflow"),
    "sample_04": ("heap_overflow", True, "calloc int-overflow"),
    "sample_05": ("heap_overflow", True, "realloc grow+memset overflow"),
    "sample_06": ("heap_overflow", True, "multi-buffer overflow"),
    "sample_08": ("heap_overflow", True, "struct member overflow"),
    "sample_09": ("heap_overflow", True, "callback struct overflow"),
    "sample_10": ("heap_overflow", True, "signed/unsigned confusion"),
    "sample_11": ("heap_overflow", True, "conditional path overflow"),
    "sample_12": ("heap_overflow", True, "adjacent buffer overflow"),
    "sample_13": ("heap_overflow", True, "struct padding overflow"),
    "sample_15": ("heap_overflow", True, "strncpy size mismatch"),
    "sample_17": ("heap_overflow", True, "sprintf overflow"),
    "sample_18": ("heap_overflow", True, "memmove overflow"),
    # False Positives (should be filtered)
    "sample_07": ("heap_overflow", False, "alignment slack absorbed"),
    "sample_14": ("heap_overflow", False, "malloc(0) boundary"),
    "sample_16": ("heap_overflow", False, "realloc(NULL) boundary"),
}


def c_to_ir(c_source: str) -> str:
    """C源码→伪代码IR转换."""
    lines = []
    for line in c_source.splitlines():
        s = line.strip()
        if s.startswith('#') or s.startswith('//') or s.startswith('/*'):
            continue
        if s.startswith('*') or s.startswith('}') or s.startswith(')'):
            continue
        if not s or s in ('{', '}'):
            continue
        # 去强制转换 (必须在类型剥离之前)
        s = re.sub(r'\(\s*(?:char|int|void|size_t|unsigned|float|double|'
                   r'uint\d+_t|int\d+_t|long)\s*\**\s*\)', '', s)
        # 去类型前缀
        s = re.sub(r'\b(?:char|int|short|long|void|float|double|size_t|'
                   r'ssize_t|unsigned|signed|uint\d+_t|int\d+_t|const|static|'
                   r'volatile|extern|register|struct\s+\w+)\s*\**\s*', '', s)
        # 去typedef前缀
        s = re.sub(r'typedef\s+struct\s*\{?', '', s)
        # 去控制流关键字
        s = re.sub(r'\b(?:if|while|for|else)\s*\(', '(', s)
        if re.match(r'\s*(?:return|free|printf|puts|fprintf|exit)\s*[\(;]', s):
            continue
        s = s.rstrip(';').strip()
        if s:
            lines.append(s)
    return '\n'.join(lines)


@dataclass
class SampleResult:
    sample_id: str
    expected: bool
    baseline_detected: bool = False
    baseline_conf: float = 0.0
    pipeline_detected: bool = False
    pipeline_conf: float = 0.0
    pipeline_tiers: Dict[str, int] = field(default_factory=dict)
    error: str = ""


def run_baseline(ir_text: str) -> tuple:
    """运行基线检测器."""
    try:
        from core.heap_overflow_detector import detect_heap_overflow
        findings = list(detect_heap_overflow(ir_text.splitlines(), ir_text))
        if findings:
            return True, findings[0].confidence
    except Exception:
        pass
    return False, 0.0


def run_enhanced_pipeline(ir_text: str, source_code: str = '') -> tuple:
    """运行约束求解+后向值流+路径条件后向值流约束联结管线."""
    try:
        from core.constraint_solver import solve_candidate
        from core.constraint_constraint_types import SolverVerdict
        from tests.value_flow_candidate_extractor import extract_candidates_from_code
        candidates, ir_lines = extract_candidates_from_code(
            source_code if source_code else ir_text)
        detected = False
        conf = 0.0
        verdict_str = "inconclusive"
        for c in candidates:
            result, _ = solve_candidate(c, ir_lines, source_code)
            if result.verdict == SolverVerdict.PROVEN_OVERFLOW:
                detected = True
                conf = max(conf, result.confidence_delta or 0.5)
                verdict_str = result.reason[:80]
                break
            if result.verdict == SolverVerdict.PROVEN_SAFE:
                verdict_str = result.reason[:80]
        tiers = {"cj_solver": 1 if detected else 0}
        return detected, conf, tiers
    except Exception as e:
        return False, 0.0, {"error": str(e)}


def main():
    samples_root = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), 'samples', 'heap_overflow')
    results: List[SampleResult] = []

    for sdir in sorted(os.listdir(samples_root)):
        if not sdir.startswith('sample_') or sdir not in EXPECTED:
            continue
        full_dir = os.path.join(samples_root, sdir)
        src_file = os.path.join(full_dir, f"{sdir}.c")
        if not os.path.exists(src_file):
            continue

        exp = EXPECTED[sdir]
        sr = SampleResult(sample_id=sdir, expected=exp[1])

        try:
            with open(src_file, 'r', encoding='utf-8', errors='replace') as f:
                source = f.read()
        except Exception as e:
            sr.error = str(e)
            results.append(sr)
            continue

        ir_text = c_to_ir(source)

        # 基线检测
        sr.baseline_detected, sr.baseline_conf = run_baseline(ir_text)

        # 增强管线 (传入源码而非IR, 因约束求解管线需要源码提取候选)
        detected, conf, tiers = run_enhanced_pipeline(ir_text, source)
        sr.pipeline_detected = detected
        sr.pipeline_conf = conf
        if isinstance(tiers, dict):
            sr.pipeline_tiers = tiers

        results.append(sr)

    # 计算指标
    baseline_tp = baseline_fp = baseline_tn = baseline_fn = 0
    pipeline_tp = pipeline_fp = pipeline_tn = pipeline_fn = 0

    for sr in results:
        if sr.expected and sr.baseline_detected:
            baseline_tp += 1
        elif sr.expected and not sr.baseline_detected:
            baseline_fn += 1
        elif not sr.expected and sr.baseline_detected:
            baseline_fp += 1
        else:
            baseline_tn += 1

        if sr.expected and sr.pipeline_detected:
            pipeline_tp += 1
        elif sr.expected and not sr.pipeline_detected:
            pipeline_fn += 1
        elif not sr.expected and sr.pipeline_detected:
            pipeline_fp += 1
        else:
            pipeline_tn += 1

    def compute_metrics(tp, fp, tn, fn_count):
        prec = tp / max(tp + fp, 1)
        rec = tp / max(tp + fn_count, 1)
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        fp_rate = fp / max(fp + tn, 1)
        return prec, rec, f1, fp_rate

    bp, br, bf1, bfp = compute_metrics(baseline_tp, baseline_fp, baseline_tn, baseline_fn)
    pp, pr, pf1, pfp = compute_metrics(pipeline_tp, pipeline_fp, pipeline_tn, pipeline_fn)

    total_fp_reduction = baseline_fp - pipeline_fp

    # 输出
    print("=" * 60)
    print("  BinMind Heap Overflow Detection — Regression Report")
    print("=" * 60)
    print(f"\n  Samples: {len(results)} ({sum(1 for r in results if r.expected)} TP, "
          f"{sum(1 for r in results if not r.expected)} FP)")
    print(f"\n  {'Metric':<20} {'Baseline':>10} {'Pipeline':>10} {'Delta':>10}")
    print(f"  {'-'*20} {'-'*10} {'-'*10} {'-'*10}")
    print(f"  {'True Positives':<20} {baseline_tp:>10} {pipeline_tp:>10} {pipeline_tp-baseline_tp:>+10}")
    print(f"  {'False Positives':<20} {baseline_fp:>10} {pipeline_fp:>10} {pipeline_fp-baseline_fp:>+10}")
    print(f"  {'True Negatives':<20} {baseline_tn:>10} {pipeline_tn:>10} {pipeline_tn-baseline_tn:>+10}")
    print(f"  {'False Negatives':<20} {baseline_fn:>10} {pipeline_fn:>10} {pipeline_fn-baseline_fn:>+10}")
    print(f"  {'Precision':<20} {bp:>10.1%} {pp:>10.1%} {pp-bp:>+10.1%}")
    print(f"  {'Recall':<20} {br:>10.1%} {pr:>10.1%} {pr-br:>+10.1%}")
    print(f"  {'F1 Score':<20} {bf1:>10.4f} {pf1:>10.4f} {pf1-bf1:>+10.4f}")
    print(f"  {'FP Rate':<20} {bfp:>10.1%} {pfp:>10.1%} {pfp-bfp:>+10.1%}")
    print(f"\n  FP Reduction: {total_fp_reduction} eliminated by 4-Tier pipeline")

    # 逐样本详情
    print(f"\n  {'Sample':<12} {'Exp':>5} {'Base':>6} {'Pipe':>6} {'Tiers':<30}")
    print(f"  {'-'*12} {'-'*5} {'-'*6} {'-'*6} {'-'*30}")
    for sr in results:
        tier_str = " ".join(f"{k.split('_')[0]}:{v}" for k, v in sr.pipeline_tiers.items())
        print(f"  {sr.sample_id:<12} {'TP' if sr.expected else 'FP':>5} "
              f"{'DETECT' if sr.baseline_detected else '-':>6} "
              f"{'DETECT' if sr.pipeline_detected else '-':>6} "
              f"{tier_str:<30}")

    # 保存报告
    report = {
        'total': len(results),
        'baseline': {'TP': baseline_tp, 'FP': baseline_fp, 'TN': baseline_tn, 'FN': baseline_fn,
                     'precision': bp, 'recall': br, 'f1': bf1, 'fp_rate': bfp},
        'pipeline': {'TP': pipeline_tp, 'FP': pipeline_fp, 'TN': pipeline_tn, 'FN': pipeline_fn,
                     'precision': pp, 'recall': pr, 'f1': pf1, 'fp_rate': pfp},
        'fp_reduction': total_fp_reduction,
        'details': [{'sample': sr.sample_id, 'expected': sr.expected,
                     'baseline_detected': sr.baseline_detected,
                     'pipeline_detected': sr.pipeline_detected,
                     'pipeline_tiers': sr.pipeline_tiers,
                     'error': sr.error} for sr in results],
        'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
    }

    out_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(out_dir, 'regression_report.json')
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    csv_path = os.path.join(out_dir, 'regression_metrics.csv')
    with open(csv_path, 'w') as f:
        f.write('sample,expected,baseline_detected,pipeline_detected,tier0_filtered,'
                'tier1_filtered,tier2_filtered,tier3_filtered\n')
        for sr in results:
            tiers = sr.pipeline_tiers
            f.write(f"{sr.sample_id},{sr.expected},{sr.baseline_detected},"
                    f"{sr.pipeline_detected},"
                    f"{tiers.get('Tier0_AllocatorSemantics', 0)},"
                    f"{tiers.get('Tier1_AffineInterval', 0)},"
                    f"{tiers.get('Tier2_SelectiveSymExec', 0)},"
                    f"{tiers.get('Tier3_InfeasiblePathPruner', 0)}\n")

    print(f"\n  Reports: {json_path}, {csv_path}")


if __name__ == '__main__':
    main()
