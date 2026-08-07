"""多工具对比基准 — 一键运行所有对比实验.

创建: 2026-06-25
用途: 运行 AVHO-G (本方法) + Angr + QEMU + Ghidra 四个工具,
      生成统一的对比报告和数据可视化.

管线:
  1. regression_suite.py → 产生 AVHO-G 基准结果
  2. angr_explorer.py → 产生 Angr 符号执行结果
  3. qemu_tracer.py → 产生 QEMU 动态追踪结果
  4. ghidra_headless.py → 产生 Ghidra 静态分析结果
  5. plot_comparison.py → 生成图表 + LaTeX 表格

使用方式:
  python run_benchmark.py
  python run_benchmark.py --skip angr,ghidra  # 跳过重工具
  python run_benchmark.py --output-dir results/
"""

import os
import sys
import subprocess
import time
import json
import argparse
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_PROJ = Path(__file__).resolve().parent
_RESULTS = _PROJ / 'results'
_RESULTS.mkdir(parents=True, exist_ok=True)


@dataclass
class ToolResult:
    """单工具实验结果."""
    tool: str = ""
    recall: float = 0.0
    precision: float = 0.0
    f1: float = 0.0
    avg_time_ms: float = 0.0
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0
    n_samples: int = 0
    mode: str = "REAL"  # REAL / ESTIMATED / ERROR
    raw_path: str = ""


@dataclass
class BenchmarkReport:
    """完整基准测试报告."""
    generated: str = ""
    n_samples: int = 0
    ground_truth_pos: int = 0
    ground_truth_neg: int = 0
    tools: List[ToolResult] = field(default_factory=list)
    avho_stats: dict = field(default_factory=dict)


def run_avho_g(samples_dir: str = None) -> ToolResult:
    """运行 AVHO-G (本方法) 基准."""
    print('\n' + '=' * 70)
    print('[1/4] AVHO-G (本方法) — Guard Narrowing + Safety Prover 管线')
    print('=' * 70)

    # 用 regression_suite.py 运行
    reg_script = str(_PROJ.parent / 'test_samples' / 'heap_overflow' / 'regression_suite.py')
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_path = str(_RESULTS / f'avho_{ts}.json')

    cmd = [sys.executable, reg_script, '--report', '--json', json_path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=120, cwd=str(_PROJ.parent))
        print(proc.stdout[-2000:] if len(proc.stdout) > 2000 else proc.stdout)

        # 解析JSON
        if os.path.exists(json_path):
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            m = data.get('metrics', {})
            n = data.get('n_samples', 0)
            avg_t = sum(r.get('elapsed_sec', 0)
                       for r in data.get('results', [])) / max(1, n) * 1000
            # metrics 存的是 0-1 比例, 转为百分比
            recall_pct = round(m.get('recall', 0) * 100, 1)
            precision_pct = round(m.get('precision', 0) * 100, 1)
            f1_scaled = round(m.get('f1', 0) * 100, 1)
            return ToolResult(
                tool='AVHO-G',
                recall=recall_pct,
                precision=precision_pct,
                f1=f1_scaled,
                avg_time_ms=round(avg_t, 1),
                tp=m.get('tp', 0), tn=m.get('tn', 0),
                fp=m.get('fp', 0), fn=m.get('fn', 0),
                n_samples=n, mode='REAL', raw_path=json_path)
        else:
            proc2 = subprocess.run([sys.executable, reg_script],
                                  capture_output=True, text=True,
                                  timeout=120, cwd=str(_PROJ.parent))
            print(proc2.stdout[-2000:] if len(proc2.stdout) > 2000 else proc2.stdout)

    except Exception as e:
        print(f'[!] AVHO-G error: {e}')

    return ToolResult(tool='AVHO-G', mode='ERROR')


def run_angr(samples_dir: str = None) -> ToolResult:
    """运行 Angr 对比."""
    print('\n' + '=' * 70)
    print('[2/4] Angr 符号执行对比')
    print('=' * 70)

    angr_script = str(_PROJ / 'angr_explorer.py')
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    cmd = [sys.executable, angr_script, '--batch']
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=120, cwd=str(_PROJ.parent))
        print(proc.stdout[-1000:] if len(proc.stdout) > 1000 else proc.stdout)

        # 找JSON结果文件
        json_files = sorted(_RESULTS.glob(f'angr_{ts[:8]}*.json'))
        if json_files:
            with open(json_files[-1], 'r', encoding='utf-8') as f:
                data = json.load(f)
            results = data.get('results', [])
            n = len(results)
            n_detected = sum(1 for r in results if r.get('detected'))

            # 基于已知ground truth估计指标
            # TP: 真实溢出且检测到, FP: 安全样本但检测到
            tp = sum(1 for r in results if r.get('detected')
                    and 'safe' not in r.get('sample_id', '').lower()
                    and 'false_positive' not in r.get('sample_id', '').lower())
            fp = sum(1 for r in results if r.get('detected')
                    and ('safe' in r.get('sample_id', '').lower()
                         or 'false_positive' in r.get('sample_id', '').lower()))
            fn_count = sum(1 for r in results if not r.get('detected')
                         and 'safe' not in r.get('sample_id', '').lower()
                         and 'false_positive' not in r.get('sample_id', '').lower())
            tn = sum(1 for r in results if not r.get('detected')
                    and ('safe' in r.get('sample_id', '').lower()
                         or 'false_positive' in r.get('sample_id', '').lower()))

            recall = round(tp / max(1, tp + fn_count) * 100, 1)
            precision = round(tp / max(1, tp + fp) * 100, 1)
            f1 = round(2 * recall * precision / max(1, recall + precision), 1)
            avg_t = sum(r.get('elapsed_sec', 3.2)
                       for r in results) / max(1, n) * 1000

            return ToolResult(
                tool='Angr', recall=recall, precision=precision, f1=f1,
                avg_time_ms=round(avg_t, 1), tp=tp, tn=tn, fp=fp, fn=fn_count,
                n_samples=n, mode=data.get('mode', 'ESTIMATED'),
                raw_path=str(json_files[-1]))
    except Exception as e:
        print(f'[!] Angr error: {e}')

    return ToolResult(tool='Angr', mode='ERROR')


def run_qemu(samples_dir: str = None) -> ToolResult:
    """运行 QEMU 对比."""
    print('\n' + '=' * 70)
    print('[3/4] QEMU 动态追踪对比')
    print('=' * 70)

    qemu_script = str(_PROJ / 'qemu_tracer.py')

    cmd = [sys.executable, qemu_script, '--batch']
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=60, cwd=str(_PROJ.parent))
        print(proc.stdout[-1000:] if len(proc.stdout) > 1000 else proc.stdout)

        # 找JSON结果
        json_files = sorted(_RESULTS.glob('qemu_*.json'))
        if json_files:
            with open(json_files[-1], 'r', encoding='utf-8') as f:
                data = json.load(f)
            results = data.get('results', [])
            n = len(results)
            tp = sum(1 for r in results if r.get('overflow_detected')
                    and 'safe' not in r.get('sample_id', '').lower())
            fp_count = sum(1 for r in results if r.get('overflow_detected')
                         and 'safe' in r.get('sample_id', '').lower())
            fn_count = sum(1 for r in results if not r.get('overflow_detected')
                         and 'safe' not in r.get('sample_id', '').lower())
            tn = sum(1 for r in results if not r.get('overflow_detected')
                    and 'safe' in r.get('sample_id', '').lower())

            recall = round(tp / max(1, tp + fn_count) * 100, 1)
            precision = round(tp / max(1, tp + fp) * 100, 1)
            f1 = round(2 * recall * precision / max(1, recall + precision), 1)
            avg_t = sum(r.get('elapsed_sec', 0.5)
                       for r in results) / max(1, n) * 1000

            return ToolResult(
                tool='QEMU', recall=recall, precision=precision, f1=f1,
                avg_time_ms=round(avg_t, 1), tp=tp, tn=tn, fp=fp, fn=fn_count,
                n_samples=n, mode=data.get('mode', 'ESTIMATED'),
                raw_path=str(json_files[-1]))
    except Exception as e:
        print(f'[!] QEMU error: {e}')

    return ToolResult(tool='QEMU', mode='ERROR')


def run_ghidra(samples_dir: str = None) -> ToolResult:
    """运行 Ghidra 对比."""
    print('\n' + '=' * 70)
    print('[4/4] Ghidra Headless 对比')
    print('=' * 70)

    ghidra_script = str(_PROJ / 'ghidra_headless.py')

    cmd = [sys.executable, ghidra_script, '--batch']
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=60, cwd=str(_PROJ.parent))
        print(proc.stdout[-1000:] if len(proc.stdout) > 1000 else proc.stdout)

        json_files = sorted(_RESULTS.glob('ghidra_*.json'))
        if json_files:
            with open(json_files[-1], 'r', encoding='utf-8') as f:
                data = json.load(f)
            results = data.get('results', [])
            n = len(results)
            tp = sum(1 for r in results if r.get('detected')
                    and 'safe' not in r.get('sample_id', '').lower())
            fp_count = sum(1 for r in results if r.get('detected')
                         and 'safe' in r.get('sample_id', '').lower())
            fn_count = sum(1 for r in results if not r.get('detected')
                         and 'safe' not in r.get('sample_id', '').lower())
            tn = sum(1 for r in results if not r.get('detected')
                    and 'safe' in r.get('sample_id', '').lower())

            recall = round(tp / max(1, tp + fn_count) * 100, 1)
            precision = round(tp / max(1, tp + fp) * 100, 1)
            f1 = round(2 * recall * precision / max(1, recall + precision), 1)
            avg_t = sum(r.get('elapsed_sec', 4.5)
                       for r in results) / max(1, n) * 1000

            return ToolResult(
                tool='Ghidra', recall=recall, precision=precision, f1=f1,
                avg_time_ms=round(avg_t, 1), tp=tp, tn=tn, fp=fp, fn=fn_count,
                n_samples=n, mode=data.get('mode', 'ESTIMATED'),
                raw_path=str(json_files[-1]))
    except Exception as e:
        print(f'[!] Ghidra error: {e}')

    return ToolResult(tool='Ghidra', mode='ERROR')


def run_all(skip: set = None) -> BenchmarkReport:
    """运行全部四个工具的对比."""
    skip = skip or set()

    report = BenchmarkReport(generated=datetime.now().isoformat())

    # 计算ground truth基数
    # 从 run_scanner.py 读取实际的 ground truth
    import importlib.util
    scanner_spec = importlib.util.spec_from_file_location(
        'run_scanner',
        str(_PROJ.parent / 'test_samples' / 'heap_overflow' / 'run_scanner.py'))
    scanner_mod = importlib.util.module_from_spec(scanner_spec)
    scanner_spec.loader.exec_module(scanner_mod)
    gt = getattr(scanner_mod, 'GROUND_TRUTH', {})
    heap_samples = sum(1 for v in gt.values() if v == 'TP')
    safe_samples = sum(1 for v in gt.values() if v == 'TN')
    report.ground_truth_pos = heap_samples
    report.ground_truth_neg = safe_samples
    report.n_samples = heap_samples + safe_samples

    print(f'Ground truth: {report.ground_truth_pos} positive + '
          f'{report.ground_truth_neg} negative = {report.n_samples} heap samples')

    if 'avho' not in skip:
        report.tools.append(run_avho_g())
    if 'angr' not in skip:
        report.tools.append(run_angr())
    if 'qemu' not in skip:
        report.tools.append(run_qemu())
    if 'ghidra' not in skip:
        report.tools.append(run_ghidra())

    # 打印汇总
    print('\n' + '=' * 70)
    print('多工具对比汇总')
    print('=' * 70)
    print(f'{"Tool":25s} {"Recall":>8s} {"Precision":>10s} {"F1":>7s} '
          f'{"Time":>8s} {"Mode":>10s}')
    print('-' * 70)
    for t in report.tools:
        print(f'{t.tool:25s} {t.recall:7.1f}% {t.precision:9.1f}% '
              f'{t.f1:6.1f} {t.avg_time_ms:7.1f}ms {t.mode:>10s}')
    print('=' * 70)

    return report


def save_report(report: BenchmarkReport) -> str:
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = str(_RESULTS / f'benchmark_{ts}.json')
    report_data = {
        'generated': report.generated,
        'n_samples': report.n_samples,
        'ground_truth_pos': report.ground_truth_pos,
        'ground_truth_neg': report.ground_truth_neg,
        'tools': [asdict(t) for t in report.tools],
    }
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    print(f'\n报告: {path}')
    return path


def main():
    parser = argparse.ArgumentParser(description='多工具对比基准测试')
    parser.add_argument('--skip', type=str, default='',
                       help='跳过的工具 (逗号分隔: angr,qemu,ghidra,avho)')
    parser.add_argument('--output-dir', type=str, default=None,
                       help='结果输出目录')
    args = parser.parse_args()

    skip = {s.strip() for s in args.skip.split(',') if s.strip()}

    t0 = time.time()
    report = run_all(skip)
    save_report(report)

    total_t = time.time() - t0
    print(f'\n总耗时: {total_t:.1f}s')

    # 自动生成图表
    try:
        plot_script = str(_PROJ / 'plot_comparison.py')
        subprocess.run([sys.executable, plot_script],
                      capture_output=True, timeout=30,
                      cwd=str(_PROJ.parent))
    except Exception:
        pass


if __name__ == '__main__':
    main()
