"""
回归测试 — 一键入口

编排三阶段流水线:
  1. 样本编译  (SampleCompiler)
  2. 多工具扫描 (ScanScheduler)
  3. 结果汇总  (ResultCollector)

输出:
  - results/regression_results.csv
  - results/regression_summary.json
  - stdout 统计摘要
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, os.path.dirname(PROJECT_ROOT))

from eval.regression.sample_compiler import SampleCompiler, SampleManifest, SAMPLE_ROOTS
from eval.regression.scan_scheduler import ScanScheduler, ScanReport
from eval.regression.result_collector import ResultCollector, ToolMetrics


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description='BinMind Heap Overflow Regression — 一键编译+扫描+汇总',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python -m eval.regression.run_regression
  python -m eval.regression.run_regression --samples-dir tests/samples/heap_overflow
  python -m eval.regression.run_regression --no-angr --timeout 60
  python -m eval.regression.run_regression --output-dir results/my_run
        """.strip(),
    )
    p.add_argument('--samples-dir', nargs='*', default=[],
                   help='额外样本目录 (默认自动发现 SAMPLE_ROOTS)')
    p.add_argument('--output-dir', default='',
                   help='输出目录 (默认 PROJECT_ROOT/results/regression)')
    p.add_argument('--timeout', type=int, default=30,
                   help='单样本单工具超时秒数 (默认 30)')
    p.add_argument('--global-timeout', type=int, default=600,
                   help='全部扫描总超时秒数 (默认 600)')
    p.add_argument('--no-angr', action='store_true', help='禁用 angr')
    p.add_argument('--no-ghidra', action='store_true', help='禁用 Ghidra')
    p.add_argument('--no-compile', action='store_true',
                   help='跳过编译 (使用已有二进制)')
    p.add_argument('--cc', default='gcc', help='C 编译器 (默认 gcc)')
    p.add_argument('--verbose', '-v', action='store_true')
    return p.parse_args()


def _ensure_output_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def main():
    args = _parse_args()
    t_total = time.perf_counter()

    out_dir = args.output_dir or os.path.join(
        PROJECT_ROOT, 'results', 'regression')
    _ensure_output_dir(out_dir)
    csv_path = os.path.join(out_dir, 'regression_results.csv')
    json_path = os.path.join(out_dir, 'regression_summary.json')

    print(f'[regression] output dir: {out_dir}')
    print(f'[regression] timeout: {args.timeout}s/tool, {args.global_timeout}s global')

    # Stage 1: 编译
    t1 = time.perf_counter()

    if args.no_compile:
        print('[stage 1] skipping compilation (--no-compile)')
        manifest = _build_manifest_from_disk(args)
    else:
        print('[stage 1] compiling samples...')
        compiler = SampleCompiler(cc=args.cc)
        results = compiler.compile_all()
        summary = compiler.summary()
        print(f'[stage 1] compiled: {summary["success"]}/{summary["total"]} '
              f'({summary["failed"]} failed) in {summary["total_time_ms"]:.0f}ms')
        if summary['failed']:
            for d in summary['details']:
                if not d['ok']:
                    print(f'  FAIL {d["name"]}: {d["error"]}')
        manifest = compiler.build_manifest()
        # 补充分编译的样本（已有 Makefile 但无 vuln.c 的目录）
        _append_extra_dirs(manifest, args, compiler)

    print(f'[stage 1] {len(manifest)} samples in manifest '
          f'({sum(1 for m in manifest if m.ground_truth is True)} TP-target, '
          f'{sum(1 for m in manifest if m.ground_truth is False)} FP-target)')
    t1_elapsed = (time.perf_counter() - t1) * 1000

    # Stage 2: 扫描
    t2 = time.perf_counter()
    print('[stage 2] scanning samples...')

    scheduler = ScanScheduler(
        timeout_s=args.timeout,
        global_timeout_s=args.global_timeout,
        enable_angr=not args.no_angr,
        enable_ghidra=not args.no_ghidra,
        verbose=args.verbose,
    )
    reports = scheduler.scan_all(manifest)
    scan_summary = scheduler.summary()
    print(f'[stage 2] scanned {scan_summary["samples_scanned"]} samples '
          f'in {scan_summary["total_elapsed_ms"]:.0f}ms')
    for tool_name, ts in scan_summary.get('tools', {}).items():
        print(f'  {tool_name}: {ts["ok"]} ok, {ts["timeout"]} timeout, '
              f'{ts["error"]} error, {ts["skip"]} skip')
    t2_elapsed = (time.perf_counter() - t2) * 1000

    # Stage 3: 汇总
    t3 = time.perf_counter()
    print('[stage 3] collecting results...')

    collector = ResultCollector(manifest, reports)
    collector.collect()
    collector.write_csv(csv_path)
    collector.write_summary_json(json_path)

    print(collector.summary())
    t3_elapsed = (time.perf_counter() - t3) * 1000

    # 汇总
    total_elapsed = (time.perf_counter() - t_total) * 1000
    print(f'\n{"=" * 70}')
    print(f'Pipeline complete in {total_elapsed:.0f}ms')
    print(f'  Stage 1 (compile): {t1_elapsed:.0f}ms')
    print(f'  Stage 2 (scan):    {t2_elapsed:.0f}ms')
    print(f'  Stage 3 (collect): {t3_elapsed:.0f}ms')
    print(f'  CSV:  {csv_path}')
    print(f'  JSON: {json_path}')
    print(f'{"=" * 70}')

    # 返回码: 有任何 FP 则返回 1
    for name, tm in collector.metrics.items():
        if tm.fp > 0:
            return 1
    return 0


def _build_manifest_from_disk(args) -> List[SampleManifest]:
    """跳过编译，从磁盘已有二进制构建清单."""
    compiler = SampleCompiler(cc=args.cc)
    # 先发现目录但不编译
    dirs = compiler.discover_samples()
    manifests = []
    for d in dirs:
        exe = os.path.join(d, 'vuln.exe')
        m = SampleManifest(
            name=os.path.basename(d),
            directory=d,
            source_path=os.path.join(d, 'vuln.c'),
            binary_path=exe if os.path.isfile(exe) else '',
            cve_id=compiler._infer_cve(os.path.basename(d)),
            has_readme=os.path.isfile(os.path.join(d, 'README.md')),
            has_makefile=os.path.isfile(os.path.join(d, 'Makefile')),
            category=compiler._infer_category(d),
            is_fp_sample=('fp_reduction' in d.lower()
                          or os.path.basename(d).startswith('fp_')),
            ground_truth=compiler._infer_ground_truth(os.path.basename(d), d),
        )
        manifests.append(m)
    return manifests


def _append_extra_dirs(
    manifest: List[SampleManifest],
    args,
    compiler: SampleCompiler,
) -> None:
    """追加额外指定的样本目录."""
    extra_dirs = list(args.samples_dir)
    for root in SAMPLE_ROOTS:
        if os.path.isdir(root) and root not in extra_dirs:
            extra_dirs.append(root)
    seen = {m.name for m in manifest}
    for ed in extra_dirs:
        if not os.path.isdir(ed):
            continue
        name = os.path.basename(ed)
        if name in seen:
            continue
        seen.add(name)
        manifest.append(SampleManifest(
            name=name,
            directory=ed,
            source_path=os.path.join(ed, 'vuln.c'),
            binary_path=os.path.join(ed, 'vuln.exe'),
            cve_id=compiler._infer_cve(name),
            has_readme=os.path.isfile(os.path.join(ed, 'README.md')),
            has_makefile=os.path.isfile(os.path.join(ed, 'Makefile')),
            is_fp_sample=('fp_reduction' in ed.lower()
                          or name.startswith('fp_')),
            category=compiler._infer_category(ed),
            ground_truth=compiler._infer_ground_truth(name, ed),
        ))


if __name__ == '__main__':
    sys.exit(main())
