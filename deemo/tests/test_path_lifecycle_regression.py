#!/usr/bin/env python3
"""
路径条件对象生命周期回归测试 —路径条件对象生命周期分析.

测试路径条件对象生命周期在 UAF 对象身份图 CONFIRMED判定上执行路径条件感知过滤的能力:
  1. MUTEX_SAFE:  free-use路径互斥 —过滤误报
  2. EARLY_RET:   free后early return —use不可——过滤误报
  3. CONFIRMED:   真实UAF, 路径不互——保持判定
  4. NULLIFY:     free后nullify —SAFE (非UAF)
  5. REASSIGN:    free后reassign —SAFE (非UAF)

预期: 路径条件对象生命周期应在 UAF 对象身份图 CONFIRMED的误报样本上正确降级为SAFE,
      在真实UAF样本上保持CONFIRMED, 零召回损—
"""
import sys, os, json, time
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from analysis.uaf_obj_graph_builder import HoigBuilder
from analysis.uaf_obj_graph_types import UafHoigVerdict
from analysis.uaf_path_lifecycle_bridge import verify_with_pcol
from analysis.uaf_path_lifecycle_verifier import filter_uaf_by_pcol

from tests.test_path_lifecycle_regression_samples import ALL_SAMPLES

passed = 0
failed = 0
fail_details = []


def _check_case(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name}: {detail}")
        fail_details.append((name, detail))


def run_hoig_only(code, name):
    """仅 UAF 对象身份图构建器判定 (不含路径条件对象生命周期)."""
    builder = HoigBuilder()
    _, _, verdicts = builder.build(code, name)
    confirmed = [v for v in verdicts if v.verdict == 'CONFIRMED']
    if confirmed:
        return 'CONFIRMED'
    return 'SAFE'


def run_hoig_pcol(code, name):
    """UAF 对象身份图 + 路径条件对象生命周期联合判定."""
    v = verify_with_pcol(code, name)
    return v.verdict


def run_pcol_regression():
    """路径条件对象生命周期回归测试主入—"""
    global passed, failed

    print("\n" + "=" * 64)
    print("路径条件对象生命周期 Regression Test —Path-Conditioned Object Lifecycle")
    print("=" * 64)

    # Phase 1: UAF 对象身份图-only baseline
    print("\n--- Phase 1: UAF 对象身份图 Baseline (no 路径条件对象生命周期) ---\n")
    hoig_pass = 0
    hoig_fail = 0
    for name, (code, expected) in sorted(ALL_SAMPLES.items()):
        result = run_hoig_only(code, name)
        correct = (result == expected)
        if correct:
            hoig_pass += 1
        else:
            hoig_fail += 1
        status = "OK" if correct else "MISMATCH"
        print(f"  [{status}] {name:<15s} hoig={result:<10s} expected={expected}")

    print(f"\n  UAF 对象身份图-only: {hoig_pass}/{len(ALL_SAMPLES)} correct "
          f"({hoig_fail} mismatches)")

    # Phase 2: UAF 对象身份图 + 路径条件对象生命周期
    print("\n--- Phase 2: UAF 对象身份图 + 路径条件对象生命周期 ---\n")
    for name, (code, expected) in sorted(ALL_SAMPLES.items()):
        result = run_hoig_pcol(code, name)
        correct = (result == expected)
        detail = f"pcol={result}, expected={expected}"
        _check_case(f"{name:<15s} (expect {expected})", correct, detail)

    print(f"\n  UAF 对象身份图+路径条件对象生命周期: {passed}/{passed + failed} correct")

    # Phase 3: 路径条件对象生命周期增量分析
    print("\n--- Phase 3: 路径条件对象生命周期 Incremental Analysis ---\n")
    pcol_filtered = 0
    pcol_kept = 0
    for name, (code, expected) in sorted(ALL_SAMPLES.items()):
        builder = HoigBuilder()
        _, _, verdicts = builder.build(code, name)
        confirmed = [v for v in verdicts if v.verdict == 'CONFIRMED']
        if not confirmed:
            continue
        filtered, stats = filter_uaf_by_pcol(code, confirmed)
        if stats['pcol_filtered'] > 0:
            pcol_filtered += 1
            print(f"  [FILTERED] {name:<15s} "
                  f"triggered={stats['pcol_triggered']} "
                  f"filtered={stats['pcol_filtered']}")
        else:
            pcol_kept += 1
            print(f"  [KEPT]     {name:<15s} "
                  f"triggered={stats['pcol_triggered']} "
                  f"kept={stats['pcol_kept']}")

    print(f"\n  路径条件对象生命周期 filtered: {pcol_filtered}, kept: {pcol_kept}")

    # 总结
    print("\n" + "=" * 64)
    total = passed + failed
    print(f"路径条件对象生命周期 Regression: {passed}/{total} passed, {failed} failed")
    if fail_details:
        print("\nFailures:")
        for name, detail in fail_details:
            print(f"  - {name}: {detail}")
    print("=" * 64)

    return failed == 0


def run_pcol_benchmark():
    """路径条件对象生命周期基准测试 —输出JSON格式的精确指—"""
    results = {}
    tp = fp = tn = fn = 0
    total_time = 0.0

    hoig_tp = hoig_fp = hoig_tn = hoig_fn = 0

    for name, (code, expected) in sorted(ALL_SAMPLES.items()):
        # UAF 对象身份图-only
        t0 = time.perf_counter()
        hoig_result = run_hoig_only(code, name)
        hoig_time = time.perf_counter() - t0

        # UAF 对象身份图+路径条件对象生命周期
        t1 = time.perf_counter()
        pcol_result = run_hoig_pcol(code, name)
        pcol_time = time.perf_counter() - t1
        total_time += pcol_time

        results[name] = {
            'expected': expected,
            'hoig_only': hoig_result,
            'hoig_correct': hoig_result == expected,
            'pcol': pcol_result,
            'pcol_correct': pcol_result == expected,
            'hoig_time_ms': round(hoig_time * 1000, 3),
            'pcol_time_ms': round(pcol_time * 1000, 3),
        }

        # UAF 对象身份图-only metrics
        if expected == 'CONFIRMED' and hoig_result == 'CONFIRMED':
            hoig_tp += 1
        elif expected == 'CONFIRMED' and hoig_result != 'CONFIRMED':
            hoig_fn += 1
        elif expected == 'SAFE' and hoig_result == 'CONFIRMED':
            hoig_fp += 1
        else:
            hoig_tn += 1

        # 路径条件对象生命周期 metrics
        if expected == 'CONFIRMED' and pcol_result == 'CONFIRMED':
            tp += 1
        elif expected == 'CONFIRMED' and pcol_result != 'CONFIRMED':
            fn += 1
        elif expected == 'SAFE' and pcol_result == 'CONFIRMED':
            fp += 1
        else:
            tn += 1

    n = len(ALL_SAMPLES)
    hoig_p = hoig_tp / max(1, hoig_tp + hoig_fp)
    hoig_r = hoig_tp / max(1, hoig_tp + hoig_fn)
    hoig_f1 = 2 * hoig_p * hoig_r / max(0.001, hoig_p + hoig_r)
    hoig_fpr = hoig_fp / max(1, hoig_fp + hoig_tn)

    p = tp / max(1, tp + fp)
    r = tp / max(1, tp + fn)
    f1 = 2 * p * r / max(0.001, p + r)
    fpr = fp / max(1, fp + tn)

    report = {
        'module': '路径条件对象生命周期 (Path-Conditioned Object Lifecycle)',
        'total_samples': n,
        'hoig_only': {
            'tp': hoig_tp, 'fp': hoig_fp, 'tn': hoig_tn, 'fn': hoig_fn,
            'precision': round(hoig_p, 4),
            'recall': round(hoig_r, 4),
            'f1': round(hoig_f1, 4),
            'fpr': round(hoig_fpr, 4),
        },
        'hoig_pcol': {
            'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'precision': round(p, 4),
            'recall': round(r, 4),
            'f1': round(f1, 4),
            'fpr': round(fpr, 4),
        },
        'avg_time_ms': round(total_time / n * 1000, 3),
        'details': results,
    }

    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                           'eval', 'results')
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, 'path_lifecycle_benchmark_results.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print('\n' + '=' * 70)
    print('路径条件对象生命周期 Benchmark Results')
    print('=' * 70)
    print(f'  Total: {n} samples')
    print(f'\n  UAF 对象身份图-only:  TP={hoig_tp} FP={hoig_fp} TN={hoig_tn} FN={hoig_fn}')
    print(f'              P={hoig_p:.4f} R={hoig_r:.4f} '
          f'F1={hoig_f1:.4f} FPR={hoig_fpr:.4f}')
    print(f'\n  UAF 对象身份图+路径条件对象生命周期:  TP={tp} FP={fp} TN={tn} FN={fn}')
    print(f'              P={p:.4f} R={r:.4f} F1={f1:.4f} FPR={fpr:.4f}')
    print(f'\n  Avg Time: {total_time/n*1000:.3f}ms')
    print(f'  Results saved to: {out_path}')
    print('-' * 70)
    for name, r in results.items():
        hoig_s = 'PASS' if r['hoig_correct'] else 'FAIL'
        pcol_s = 'PASS' if r['pcol_correct'] else 'FAIL'
        print(f'  [{hoig_s}/{pcol_s}] {name:<15s} '
              f'hoig={r["hoig_only"]:<10s} '
              f'pcol={r["pcol"]:<10s} '
              f'exp={r["expected"]}')
    print('=' * 70)

    return report


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--benchmark', action='store_true',
                         help='Run full 路径条件对象生命周期 benchmark with JSON output')
    parser.add_argument('--test', action='store_true', default=True,
                        help='Run regression test')
    args = parser.parse_args()

    if args.benchmark:
        run_pcol_benchmark()
    else:
        success = run_pcol_regression()
        sys.exit(0 if success else 1)
