# 一键回归测试入口 — 编译→扫描→收集→对比 全流程自动化
"""堆溢出检测回归测试 — 一键运行全流程。

流程:
  1. compile_samples.py — 编译所有CVE样本为debug ELF
  2. run_scanner.py   — 对每个样本运行堆溢出检测
  3. collect_results.py — 汇总结果，计算检出率/误报率
  4. (可选) run_benchmark.py — 多工具对比

用法:
  python tests/run_regression.py              # 全流程
  python tests/run_regression.py --quick       # 快速模式(前5个样本)
  python tests/run_regression.py --no-compile  # 跳过编译(假设已编译)
  python tests/run_regression.py --full-bench  # 包含多工具对比
"""

import os, sys, subprocess, argparse, time

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(TEST_DIR)


def run_step(name: str, cmd: list) -> int:
    """运行单步，打印状态。"""
    print(f"\n{'='*60}")
    print(f"  STEP: {name}")
    print(f"{'='*60}")
    t0 = time.time()
    try:
        r = subprocess.run(cmd, cwd=PROJECT_DIR, timeout=120)
        elapsed = time.time() - t0
        if r.returncode == 0:
            print(f"  [OK] {name} ({elapsed:.1f}s)")
        else:
            print(f"  [FAIL] {name} — exit code {r.returncode}")
        return r.returncode
    except subprocess.TimeoutExpired:
        print(f"  [TIMEOUT] {name}")
        return 1
    except FileNotFoundError as e:
        print(f"  [ERROR] {name} — {e}")
        return 1


def main():
    p = argparse.ArgumentParser(description='Heap overflow regression test suite')
    p.add_argument('--quick', action='store_true', help='Limit to 5 samples')
    p.add_argument('--no-compile', action='store_true', help='Skip compilation')
    p.add_argument('--full-bench', action='store_true', help='Run multi-tool benchmark')
    p.add_argument('--heap-only', action='store_true', help='Only heap overflow samples')
    args = p.parse_args()

    python = sys.executable
    failures = []

    # 编译样本
    if not args.no_compile:
        rc = run_step("1/4 Compile CVE samples", [
            python, os.path.join(TEST_DIR, "compile_samples.py"), "debug"
        ])
        if rc != 0:
            failures.append("compile_samples")

    # 扫描
    scan_cmd = [python, os.path.join(TEST_DIR, "run_scanner.py")]
    if args.quick and not args.heap_only:
        # 快速模式: 扫描前5个有binary的样本
        pass  # run_scanner handles --sample, no global quick flag
    rc = run_step("2/4 Run heap overflow scanner", scan_cmd)
    if rc != 0:
        failures.append("run_scanner")

    # 收集结果
    rc = run_step("3/5 Collect & analyze results", [
        python, os.path.join(TEST_DIR, "collect_results.py")
    ])
    if rc != 0:
        failures.append("collect_results")

    # .5: 消融对比 (基线 vs 写侧区间创新)
    rc = run_step("3.5/5 Ablation (baseline vs write-side)", [
        python, os.path.join(TEST_DIR, "run_ablation.py")
    ])
    if rc != 0:
        failures.append("run_ablation")

    # 多工具对比（可选）
    if args.full_bench:
        bench_cmd = [python, os.path.join(PROJECT_DIR, "eval", "run_benchmark.py")]
        if args.quick:
            bench_cmd.append("--no-packed")
        rc = run_step("4/5 Multi-tool benchmark", bench_cmd)
        if rc != 0:
            failures.append("run_benchmark")

        # 生成图表
        rc = run_step("4a/5 Generate comparison charts", [
            python, os.path.join(PROJECT_DIR, "eval", "plot_comparison.py")
        ])
        if rc != 0:
            failures.append("plot_comparison")

        # 生成LaTeX表格
        rc = run_step("4b/5 Generate LaTeX table", [
            python, os.path.join(PROJECT_DIR, "eval", "gen_latex_table.py")
        ])
        if rc != 0:
            failures.append("gen_latex_table")

    # 汇总
    print(f"\n{'='*60}")
    if failures:
        print(f"  COMPLETED with {len(failures)} failure(s): {', '.join(failures)}")
    else:
        print(f"  ALL STEPS PASSED")
    print(f"{'='*60}")

    # 尝试输出关键指标
    summary_path = os.path.join(TEST_DIR, "scan_results", "metrics_summary.json")
    if os.path.exists(summary_path):
        import json
        with open(summary_path) as f:
            m = json.load(f)
        print(f"\n  Recall (检出率): {m['overall']['recall']}%")
        print(f"  FP Rate (误报率): {m['overall']['fp_rate']}%")
        print(f"  Avg time: {m['overall']['avg_time']}s")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
