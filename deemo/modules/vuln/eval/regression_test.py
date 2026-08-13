"""堆溢出回归测试 — 一键编译+扫描+结果收集.

创建: 2025-06-09
用途: 对所有 heap overflow 样本执行完整的端到端测试管线,
      输出每个样本的检出/漏报/误报状态及耗时。

管线: make clean → make → analyze_heap → 结果比对

使用方式:
  python regression_test.py
  python regression_test.py --sample sample01  # 单样本测试
  python regression_test.py --json results.json  # 指定输出路径
"""

import os
import sys
import subprocess
import time
import json
import csv
import argparse
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_PROJ = Path(__file__).resolve().parent.parent
_SAMPLES = _PROJ / 'sample_bins'
_RESULTS = Path(__file__).resolve().parent / 'results'
_RESULTS.mkdir(parents=True, exist_ok=True)

# 堆溢出检测导入
_SRC = _PROJ / 'src' / 'heap'
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from orchestrator import analyze_heap, HeapAnalysisReport


@dataclass
class SampleResult:
    """单样本回归测试结果."""
    sample_id: str = ""
    cve_id: str = ""
    binary_path: str = ""
    compiled: bool = False
    compile_error: str = ""
    raw_findings: int = 0
    confirmed: int = 0
    likely: int = 0
    uncertain: int = 0
    filtered_fp: int = 0
    elapsed_sec: float = 0.0
    expected_vuln: bool = True
    detected: bool = False
    status: str = ""  # TP/TN/FP/FN/ERROR
    notes: str = ""


def discover_heap_samples(base: Path) -> List[Tuple[str, str, Optional[str]]]:
    """发现所有堆溢出样本 → (sample_id, binary_path, cve_id).

    过滤规则:
      - 排除 sample18-29 (UAF专用区间, 目录名含 uaf 或样本号 ≥18)
      - 排除 sample12_multi_free_heap (double-free, 非堆溢出)
      - 保留 sample01-17 中非UAF的样本
    """
    import re
    samples = []

    # CVE编号映射
    cve_map = {}
    for d in sorted(base.iterdir()):
        if not d.is_dir():
            continue
        name = d.name
        cve = None
        m = re.search(r'(CVE-\d{4}-\d+)', name)
        if m:
            cve = m.group(1)
        elif 'ghost' in name.lower():
            cve = 'CVE-2015-0235'
        cve_map[name] = cve

    # 堆溢出样本白名单
    _HEAP_ONLY = {
        'sample01_heap_overflow_basic', 'sample02_off_by_one',
        'sample03_memcpy_no_check', 'sample04_loop_overflow',
        'sample05_fmt_string_heap', 'sample06_CVE-2022-24834',
        'sample07_CVE-2023-25139', 'sample08_int_overflow_to_heap',
        'sample09_CVE-2015-0235_ghost', 'sample10_CVE-2020-10713',
        'sample11_realloc_misuse', 'sample12_multi_free_heap',
        'sample13_struct_field_overflow', 'sample14_nested_loop_heap',
        'sample15_CVE-2017-1000112', 'sample16_safe_guarded',
        'sample17_false_positive_test',
    }

    for d in sorted(base.iterdir()):
        if not d.is_dir():
            continue
        name = d.name
        if name not in _HEAP_ONLY:
            continue

        exe = None
        for f in d.iterdir():
            if f.suffix == '.exe':
                exe = str(f)
                break
        if exe:
            samples.append((name, exe, cve_map.get(name)))
    return samples


def compile_sample(sample_dir: Path) -> Tuple[bool, str]:
    """编译样本 (如果源码存在且二进制过期)."""
    makefile = sample_dir / 'Makefile'
    if not makefile.exists():
        # 没有Makefile但有源码 → 尝试自动编译
        c_files = list(sample_dir.glob('*.c'))
        if not c_files:
            return True, ""  # 有预编译二进制, 无需编译

        exe = sample_dir / (c_files[0].stem + '.exe')
        if exe.exists() and exe.stat().st_mtime > c_files[0].stat().st_mtime:
            return True, ""  # 二进制比源码新

        cmd = ['gcc', '-o', str(exe), str(c_files[0]),
               '-O0', '-g', '-fno-stack-protector']
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=30, cwd=str(sample_dir))
            if proc.returncode == 0 and exe.exists():
                return True, ""
            return False, proc.stderr[:500]
        except Exception as e:
            return False, str(e)

    # 有Makefile → 用make编译
    try:
        proc = subprocess.run(['make', 'clean'], capture_output=True,
                              text=True, timeout=10, cwd=str(sample_dir))
        proc = subprocess.run(['make'], capture_output=True,
                              text=True, timeout=30, cwd=str(sample_dir))
        if proc.returncode == 0:
            # 检查是否有exe生成
            exes = list(sample_dir.glob('*.exe'))
            if exes:
                return True, ""
            return False, "make succeeded but no .exe found"
        return False, proc.stderr[:500]
    except FileNotFoundError:
        return True, ""  # make not available, skip
    except Exception as e:
        return False, str(e)


def ground_truth(sample_id: str) -> bool:
    """从样本ID推断ground truth (是否为真实漏洞).

    堆溢出漏洞样本: sample01-11, 13-15
    非堆溢出/安全样本: sample12 (double-free), sample16 (安全守卫), sample17 (FP测试)
    """
    _HEAP_VULN = {
        'sample01_heap_overflow_basic', 'sample02_off_by_one',
        'sample03_memcpy_no_check', 'sample04_loop_overflow',
        'sample05_fmt_string_heap', 'sample06_CVE-2022-24834',
        'sample07_CVE-2023-25139', 'sample08_int_overflow_to_heap',
        'sample09_CVE-2015-0235_ghost', 'sample10_CVE-2020-10713',
        'sample11_realloc_misuse', 'sample13_struct_field_overflow',
        'sample14_nested_loop_heap', 'sample15_CVE-2017-1000112',
    }
    return sample_id in _HEAP_VULN


def run_single_sample(sample_id: str, exe_path: str,
                      cve_id: Optional[str] = None) -> SampleResult:
    """对单个样本执行完整回归测试."""
    result = SampleResult(
        sample_id=sample_id, cve_id=cve_id or "",
        binary_path=exe_path, expected_vuln=ground_truth(sample_id))

    try:
        report = analyze_heap(exe_path)
        result.raw_findings = report.raw_findings
        result.confirmed = report.confirmed
        result.likely = report.likely
        result.uncertain = report.uncertain
        result.filtered_fp = report.filtered_fp
        result.elapsed_sec = report.elapsed_sec
        result.detected = (report.confirmed > 0 or report.likely > 0)

        # 判定
        gt = result.expected_vuln
        if gt and result.detected:
            result.status = 'TP'
        elif not gt and not result.detected:
            result.status = 'TN'
        elif gt and not result.detected:
            result.status = 'FN'
        elif not gt and result.detected:
            result.status = 'FP'
        else:
            result.status = '--'

    except Exception as e:
        result.status = 'ERROR'
        result.notes = f'{type(e).__name__}: {e}'

    return result


def run_regression(selected_sample: str = None) -> List[SampleResult]:
    """运行完整回归测试管线."""
    samples = discover_heap_samples(_SAMPLES)
    if not samples:
        print('[!] 未发现堆溢出样本')
        return []

    if selected_sample:
        samples = [(s, e, c) for s, e, c in samples
                   if selected_sample in s]
        if not samples:
            print(f'[!] 未找到匹配样本: {selected_sample}')
            return []

    results: List[SampleResult] = []
    n = len(samples)

    print(f'{"="*70}')
    print(f'堆溢出回归测试 — {n} 样本')
    print(f'{"="*70}')

    for i, (sid, exe, cve) in enumerate(samples, 1):
        t0 = time.time()
        result = run_single_sample(sid, exe, cve)
        results.append(result)

        elapsed = round((time.time() - t0) * 1000, 1)
        status_icon = {'TP': '[OK]', 'TN': '[TN]', 'FP': '[FP]', 'FN': '[FN]', 'ERROR': '[!!]'}
        icon = status_icon.get(result.status, '[??]')
        print(f'  [{i:2d}/{n}] [{icon} {result.status}] {sid:35s} '
              f'raw={result.raw_findings:2d} conf={result.confirmed:2d} '
              f'likely={result.likely:2d} {elapsed:6.1f}ms'
              f'{(" CVE="+cve) if cve else ""}')

    # 汇总
    tp = sum(1 for r in results if r.status == 'TP')
    tn = sum(1 for r in results if r.status == 'TN')
    fp = sum(1 for r in results if r.status == 'FP')
    fn_count = sum(1 for r in results if r.status == 'FN')
    err = sum(1 for r in results if r.status == 'ERROR')

    recall = round(tp / max(1, tp + fn_count) * 100, 1)
    precision = round(tp / max(1, tp + fp) * 100, 1)
    f1 = round(2 * recall * precision / max(1, recall + precision), 1)
    avg_t = round(sum(r.elapsed_sec for r in results) / max(1, len(results)) * 1000, 1)

    print(f'\n{"="*70}')
    print(f'汇总: TP={tp} TN={tn} FP={fp} FN={fn_count} ERR={err}')
    print(f'  Recall={recall}%  Precision={precision}%  F1={f1}')
    print(f'  Avg: {avg_t}ms/sample, '
          f'Total filtered FP: {sum(r.filtered_fp for r in results)}')
    print(f'{"="*70}')

    return results


def save_results(results: List[SampleResult],
                 json_path: str = None, csv_path: str = None) -> dict:
    """保存结果为JSON和CSV."""
    if json_path is None:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_path = str(_RESULTS / f'heap_regression_{ts}.json')
    if csv_path is None:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_path = str(_RESULTS / f'heap_regression_{ts}.csv')

    # JSON
    tp = sum(1 for r in results if r.status == 'TP')
    tn = sum(1 for r in results if r.status == 'TN')
    fp = sum(1 for r in results if r.status == 'FP')
    fn_count = sum(1 for r in results if r.status == 'FN')
    recall = round(tp / max(1, tp + fn_count) * 100, 1)
    precision = round(tp / max(1, tp + fp) * 100, 1)
    f1 = round(2 * recall * precision / max(1, recall + precision), 1)

    report = {
        'generated': datetime.now().isoformat(),
        'n_samples': len(results),
        'metrics': {
            'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn_count,
            'recall': recall, 'precision': precision, 'f1': f1},
        'results': [asdict(r) for r in results],
    }
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f'JSON: {json_path}')

    # CSV
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'sample_id', 'cve_id', 'binary_path', 'compiled', 'compile_error',
            'status', 'detected', 'expected_vuln',
            'raw_findings', 'confirmed', 'likely', 'uncertain',
            'filtered_fp', 'elapsed_sec', 'notes'], extrasaction='ignore')
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))
    print(f'CSV: {csv_path}')

    return report


def main():
    parser = argparse.ArgumentParser(description='堆溢出回归测试')
    parser.add_argument('--sample', type=str, default=None,
                       help='仅测试指定样本 (子串匹配)')
    parser.add_argument('--json', type=str, default=None,
                       help='JSON输出路径')
    parser.add_argument('--csv', type=str, default=None,
                       help='CSV输出路径')
    parser.add_argument('--compile', action='store_true',
                       help='强制重新编译')
    args = parser.parse_args()

    if args.compile:
        for sid, exe, _ in discover_heap_samples(_SAMPLES):
            sd = Path(exe).parent
            ok, err = compile_sample(sd)
            if not ok:
                print(f'[!] 编译失败 {sid}: {err[:100]}')

    results = run_regression(args.sample)
    if results:
        save_results(results, args.json, args.csv)


if __name__ == '__main__':
    main()
