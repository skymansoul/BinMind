"""
一键回归测试 — 运行所有检测器并输出通过/失败汇总。
用法: python run_all_tests.py [--quick]
"""

import json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_unified_benchmark():
    """运行统一三类型基准测试。"""
    from eval.unified_triple_benchmark import run_triple_benchmark
    return run_triple_benchmark()


def check_metrics(summary) -> list:
    """检查关键指标是否达标, 返回问题列表。"""
    issues = []
    type_stats = summary.get('type_stats', {})

    # 格式串召回 ≥ 95%
    fmt = type_stats.get('format_string', {})
    fmt_rec = fmt.get('fmt', 0) / max(1, fmt.get('total', 1)) * 100
    if fmt_rec < 95:
        issues.append(f"Format string recall {fmt_rec:.1f}% < 95% threshold")

    # 整数溢出召回 ≥ 90%
    int_ovf = type_stats.get('integer_overflow', {})
    int_rec = int_ovf.get('int_ovf', 0) / max(1, int_ovf.get('total', 1)) * 100
    if int_rec < 90:
        issues.append(f"Integer overflow recall {int_rec:.1f}% < 90% threshold")

    # 堆溢出召回 ≥ 70%
    heap = type_stats.get('heap_overflow', {})
    heap_rec = heap.get('heap', 0) / max(1, heap.get('total', 1)) * 100
    if heap_rec < 70:
        issues.append(f"Heap overflow recall {heap_rec:.1f}% < 70% threshold")

    # UAF召回 ≥ 40%
    uaf = type_stats.get('uaf', {})
    uaf_rec = uaf.get('uaf', 0) / max(1, uaf.get('total', 1)) * 100
    if uaf_rec < 40:
        issues.append(f"UAF recall {uaf_rec:.1f}% < 40% threshold")

    return issues


def verify_module_imports() -> list:
    """验证所有核心模块可导入。"""
    issues = []
    modules = [
        ('core.path_sensitive_vrf', 'path_sensitive_heap_analysis'),
        ('core.selective_symexec', 'SelectiveSymExec'),
        ('core.heap_expr_parser', 'parse_size_expr'),
        ('core.symbolic_range', 'AffineInterval'),
        ('core.loop_write_detector', 'detect_loop_writes'),
        ('analysis.fmt_constraint_solver', 'analyze_format_calls'),
        ('analysis.int_overflow_vrf', 'detect_integer_overflows'),
        ('analysis.heap_ptr_identity', 'PtrIdentityTracker'),
        ('analysis.heap_buffer_disjointness', 'BufferDisjointness'),
        ('analysis.heap_guard_analyzer', 'GuardAnalyzer'),
        ('analysis.heap_fp_reducer', 'HeapFpReducer'),
    ]
    for mod_name, attr in modules:
        try:
            mod = __import__(mod_name, fromlist=[attr])
            getattr(mod, attr)
        except Exception as e:
            issues.append(f"Import {mod_name}.{attr}: {e}")
    return issues


def verify_line_limits() -> list:
    """验证所有核心模块 ≤300 行。"""
    issues = []
    core_files = [
        'core/path_sensitive_vrf.py',
        'core/selective_symexec.py',
        'core/heap_expr_parser.py',
        'core/symbolic_range.py',
        'core/loop_write_detector.py',
        'core/unified_heap_pipeline.py',
        'analysis/fmt_constraint_solver.py',
        'analysis/int_overflow_vrf.py',
        'analysis/heap_ptr_identity.py',
        'analysis/heap_buffer_disjointness.py',
        'analysis/heap_guard_analyzer.py',
        'analysis/heap_fp_reducer.py',
    ]
    for f in core_files:
        path = os.path.join(os.path.dirname(__file__), f)
        if not os.path.exists(path):
            continue
        with open(path, encoding='utf-8', errors='replace') as fh:
            lines = len(fh.readlines())
        if lines > 300:
            issues.append(f"{f}: {lines} lines exceeds 300-line limit")
    return issues


def main():
    quick = '--quick' in sys.argv
    all_issues = []
    t0 = time.perf_counter()

    print("=" * 60)
    print("BinMind Regression Test Suite — 2026-08-06")
    print("=" * 60)

    # 1. 模块导入检查
    print("\n[1/4] Module imports...")
    imp_issues = verify_module_imports()
    if imp_issues:
        print(f"  FAIL: {len(imp_issues)} import errors")
        for i in imp_issues:
            print(f"    - {i}")
    else:
        print("  OK: all core modules import successfully")
    all_issues.extend(imp_issues)

    # 2. 行数限制检查
    print("\n[2/4] Line limit check (≤300 lines)...")
    line_issues = verify_line_limits()
    if line_issues:
        print(f"  FAIL: {len(line_issues)} files exceed limit")
        for i in line_issues:
            print(f"    - {i}")
    else:
        print("  OK: all core modules within 300-line limit")
    all_issues.extend(line_issues)

    # 3. 统一基准测试
    print(f"\n[3/4] Unified benchmark {'(quick mode)' if quick else ''}...")
    try:
        summary = run_unified_benchmark()
        metric_issues = check_metrics(summary)
        if metric_issues:
            print(f"  WARN: {len(metric_issues)} metrics below threshold")
            for i in metric_issues:
                print(f"    - {i}")
        else:
            print("  OK: all metrics above thresholds")
        all_issues.extend(metric_issues)
    except Exception as e:
        print(f"  FAIL: benchmark crashed — {e}")
        all_issues.append(f"Benchmark crash: {e}")
        summary = None

    # 4. 汇总
    elapsed = time.perf_counter() - t0
    print("\n" + "=" * 60)
    if not all_issues:
        print(f"ALL TESTS PASSED ({elapsed:.1f}s)")
        status = "PASS"
    else:
        passed_critical = len([i for i in all_issues if 'crash' not in str(i).lower()])
        print(f"{len(all_issues)} ISSUES FOUND ({elapsed:.1f}s)")
        for i in all_issues:
            print(f"  - {i}")
        status = "FAIL"
    print("=" * 60)

    # Write report
    report = {
        'status': status,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'elapsed_s': round(elapsed, 1),
        'issues': all_issues,
    }
    report_path = os.path.join(os.path.dirname(__file__), 'tests', 'regression_report.json')
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\nReport: {report_path}")

    return 0 if status == "PASS" else 1


if __name__ == '__main__':
    sys.exit(main())
