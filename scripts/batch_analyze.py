#!/usr/bin/env python3
"""
批量分析脚本 —— 一键扫描样本目录并生成汇总报告。

遍历指定目录中的二进制文件，对每个文件执行完整的 BinMind 分析管线，
收集结果并生成汇总统计和评估报告。

用法:
    python scripts/batch_analyze.py /samples/ctf/ -o ./batch_results/
    python scripts/batch_analyze.py /samples/ --recursive --parallel --exploit

依赖: BinMind 已安装 (pip install -e .)，radare2 在 PATH 中。
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional

# 确保项目根目录在 path 中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import ensure_dirs
from utils.logging_setup import init_logging

_log = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='batch_analyze',
        description='Batch binary vulnerability analysis',
    )
    p.add_argument('directory', help='directory containing binaries to analyze')
    p.add_argument('-o', '--output', default='./batch_results',
                   help='output directory (default: ./batch_results)')
    p.add_argument('-r', '--recursive', action='store_true',
                   help='recursively scan subdirectories')
    p.add_argument('-p', '--parallel', action='store_true',
                   help='analyze binaries in parallel')
    p.add_argument('--max-funcs', type=int, default=15,
                   help='max functions per binary (default: 15)')
    p.add_argument('--timeout', type=int, default=300,
                   help='timeout per binary in seconds (default: 300)')
    p.add_argument('--exploit', action='store_true',
                   help='enable exploit generation')
    p.add_argument('--symbolic', action='store_true',
                   help='enable symbolic execution')
    p.add_argument('--format', choices=['markdown', 'json'],
                   default='markdown', help='report format')
    p.add_argument('-v', '--verbose', action='store_true',
                   help='debug logging')
    return p


def find_binaries(directory: str, recursive: bool = True) -> List[str]:
    """发现目录中的可分析二进制文件。"""
    from core.binary_info import detect_format

    binaries = []
    for root, dirs, files in os.walk(directory):
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
            if os.path.isfile(fpath):
                if detect_format(fpath) != 'unknown' and not fname.endswith(
                    ('.py', '.c', '.h', '.o', '.a', '.so.0', '.ko', '.dll')
                ):
                    binaries.append(fpath)
        if not recursive:
            break
    return binaries


def analyze_one(
    binary_path: str,
    output_dir: str,
    max_funcs: int,
    enable_symbolic: bool,
    enable_exploit: bool,
    report_format: str,
) -> Dict[str, Any]:
    """
    分析单个二进制文件。

    对每个二进制运行完整管线，记录结果和耗时。
    异常不传播——单个文件失败不影响批量继续。
    """
    from core.binary_info import get_binary_info
    from core.checksec import detect_checksec
    from core.pipeline import run_pipeline

    result = {
        'binary_path': binary_path,
        'filename': os.path.basename(binary_path),
        'status': 'error',
        'error': '',
        'elapsed_sec': 0.0,
        'total_vulns': 0,
        'report_paths': {},
    }

    try:
        binfo = get_binary_info(binary_path)
        checksec = detect_checksec(binary_path)

        result['arch'] = binfo.get('arch', 'unknown')
        result['bits'] = binfo.get('bits', 64)
        result['checksec'] = {
            k: checksec[k] for k in ('nx', 'pie', 'canary', 'relro', 'fortify')
        }

        t0 = time.time()

        if enable_symbolic:
            os.environ['ENABLE_SYMBOLIC'] = 'true'
        if enable_exploit:
            os.environ['EXPLOIT_GEN'] = 'true'

        pipeline_result = run_pipeline(
            binary_path=binary_path,
            max_funcs=max_funcs,
            output_format=report_format,
            parallel=False,
        )

        elapsed = time.time() - t0
        result['elapsed_sec'] = round(elapsed, 1)
        result['total_vulns'] = pipeline_result.get('total_vulns', 0)
        result['report_paths'] = pipeline_result.get('reports', {})
        result['status'] = 'completed' if 'error' not in pipeline_result else 'partial'

    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)
        _log.error("Analysis failed for %s: %s", binary_path, e)

    return result


def generate_summary_report(results: List[Dict], output_dir: str, fmt: str) -> str:
    """生成批量分析的汇总报告。"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    total = len(results)
    completed = sum(1 for r in results if r['status'] in ('completed', 'partial'))
    failed = sum(1 for r in results if r['status'] == 'error')
    total_vulns = sum(r['total_vulns'] for r in results)
    total_time = sum(r['elapsed_sec'] for r in results)

    os.makedirs(output_dir, exist_ok=True)

    if fmt == 'json':
        summary_path = os.path.join(output_dir, f'batch_summary_{timestamp}.json')
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump({
                'timestamp': timestamp,
                'directory': results[0].get('binary_path', '') if results else '',
                'total_binaries': total,
                'completed': completed,
                'failed': failed,
                'total_vulnerabilities': total_vulns,
                'total_time_sec': round(total_time, 1),
                'results': results,
            }, f, indent=2, ensure_ascii=False)
        return summary_path

    # Markdown 汇总
    summary_path = os.path.join(output_dir, f'batch_summary_{timestamp}.md')
    lines = [
        '# BinMind Batch Analysis Report',
        '',
        f'**Generated:** {timestamp}',
        f'**Directory:** `{results[0].get("binary_path", "").rsplit(chr(92), 1)[0] if results else ""}`',
        '',
        '## Summary',
        '',
        f'| Metric | Value |',
        f'|--------|-------|',
        f'| Total Binaries | {total} |',
        f'| Completed | {completed} |',
        f'| Failed | {failed} |',
        f'| Total Vulnerabilities | {total_vulns} |',
        f'| Total Analysis Time | {total_time:.1f}s |',
        f'| Avg Time per Binary | {total_time/max(total,1):.1f}s |',
        '',
        '## Per-Binary Results',
        '',
        '| # | Binary | Arch | Status | Vulns | Time | Protections |',
        '|---|--------|------|--------|-------|------|-------------|',
    ]

    for i, r in enumerate(results, 1):
        cs = r.get('checksec', {})
        prot = (
            f"{'N' if cs.get('nx') else 'n'}"
            f"{'P' if cs.get('pie') else 'p'}"
            f"{'C' if cs.get('canary') else 'c'}"
            f"{cs.get('relro', '?')[0]}"
        )
        status_icon = '✓' if r['status'] == 'completed' else '✗'
        lines.append(
            f"| {i} | `{r['filename']}` | {r.get('arch', '?')} | "
            f"{status_icon} {r['status']} | {r['total_vulns']} | "
            f"{r['elapsed_sec']}s | {prot} |"
        )

    lines.append('')
    lines.append('---')
    lines.append(f'*Report generated by BinMind batch_analyze on {timestamp}*')

    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    return summary_path


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    init_logging('DEBUG' if args.verbose else 'INFO')
    ensure_dirs()

    directory = os.path.abspath(args.directory)
    if not os.path.isdir(directory):
        print(f"error: not a directory: {directory}", file=sys.stderr)
        return 1

    # 发现二进制文件
    binaries = find_binaries(directory, args.recursive)
    if not binaries:
        print(f"No supported binary files found in {directory}")
        return 0

    print(f"\n  BinMind Batch Analysis")
    print(f"  Directory: {directory}")
    print(f"  Binaries:  {len(binaries)}")
    print(f"  Output:    {args.output}")
    print()

    # 分析
    results: List[Dict] = []
    t0 = time.time()

    if args.parallel and len(binaries) > 1:
        max_workers = min(4, len(binaries))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(
                    analyze_one, b, args.output, args.max_funcs,
                    args.symbolic, args.exploit, args.format,
                ): b for b in binaries
            }
            for i, fut in enumerate(as_completed(futures), 1):
                try:
                    r = fut.result()
                    results.append(r)
                    icon = '✓' if r['status'] == 'completed' else '✗'
                    print(
                        f"  [{i}/{len(binaries)}] {icon} {r['filename']} "
                        f"({r['elapsed_sec']}s, {r['total_vulns']} vulns)"
                    )
                except Exception as e:
                    _log.error("Batch worker failed: %s", e)
    else:
        for i, bpath in enumerate(binaries, 1):
            print(f"  [{i}/{len(binaries)}] analyzing {os.path.basename(bpath)}...")
            r = analyze_one(
                bpath, args.output, args.max_funcs,
                args.symbolic, args.exploit, args.format,
            )
            results.append(r)
            icon = '✓' if r['status'] == 'completed' else '✗'
            print(
                f"  [{i}/{len(binaries)}] {icon} {r['filename']} "
                f"({r['elapsed_sec']}s, {r['total_vulns']} vulns)"
            )

    # 生成汇总
    summary_path = generate_summary_report(results, args.output, args.format)

    total_time = time.time() - t0
    print()
    print(f"  Batch complete ({total_time:.1f}s)")
    print(f"  Total vulns found: {sum(r['total_vulns'] for r in results)}")
    print(f"  Summary: {summary_path}")
    print()

    return 0


if __name__ == '__main__':
    sys.exit(main())
