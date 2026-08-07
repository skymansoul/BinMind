#!/usr/bin/env python3
"""
自动化回归测试调度器 — 编译CVE样本、调用扫描器、收集结果。

创建: 2026-04-29 09:15
修改:
  2025-10-07 09:15 — 初始实现: 样本编译/扫描调度/结果聚合/JSON输出

用法:
  python tests/regression/run/regression_runner.py \
    --samples tests/cve_samples/ \
    --scanner binmind.py \
    --output results/regression_$(date +%Y%m%d).json

依赖扫描器的 --json 输出模式。扫描器需支持 --output json 或等效参数。
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)


@dataclass
class SampleResult:
    sample_id: str = ""
    cve_id: str = ""
    vuln_type: str = ""            # buffer_overflow / uaf / format_string
    expected_finding_count: int = 1
    actual_findings: List[Dict] = field(default_factory=list)
    scan_time_sec: float = 0.0
    peak_memory_mb: float = 0.0
    passed: bool = False
    error: str = ""


class RegressionRunner:
    """
    回归测试调度器。
    拆分为三个子模块:
      - SampleCompiler: 编译C样本
      - ScanScheduler: 调用扫描器
      - ResultCollector: 聚合JSON结果
    """

    def __init__(self, samples_dir: str, scanner_bin: str, output_dir: str):
        self.samples_dir = Path(samples_dir)
        self.scanner_bin = scanner_bin
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def discover_samples(self) -> List[Dict[str, str]]:
        """
        发现样本: 每个子目录包含 sample.c + sample.json(元数据)。
        sample.json格式:
          {"cve_id": "CVE-XXXX-XXXXX", "vuln_type": "buffer_overflow",
           "expected_count": 1, "compile_cmd": "gcc -o sample sample.c -no-pie"}
        """
        samples = []
        for entry in sorted(self.samples_dir.iterdir()):
            if not entry.is_dir():
                continue
            meta_file = entry / 'sample.json'
            src_file = entry / 'sample.c'
            if not meta_file.exists() or not src_file.exists():
                _log.debug('skip %s: missing sample.json or sample.c', entry.name)
                continue
            try:
                meta = json.loads(meta_file.read_text())
            except json.JSONDecodeError:
                meta = {}
            samples.append({
                'dir': str(entry),
                'name': entry.name,
                'cve_id': meta.get('cve_id', entry.name),
                'vuln_type': meta.get('vuln_type', 'unknown'),
                'expected_count': meta.get('expected_count', 1),
                'compile_cmd': meta.get('compile_cmd',
                    f'gcc -o {entry.name} sample.c -no-pie -fno-stack-protector'),
            })
        return samples

    def compile_sample(self, sample: Dict) -> Optional[str]:
        """编译单个样本，返回编译产物的路径。"""
        sample_dir = Path(sample['dir'])
        binary_path = sample_dir / sample['name']
        compile_cmd = sample.get('compile_cmd', '')

        _log.info('compiling %s: %s', sample['name'], compile_cmd)
        try:
            result = subprocess.run(
                compile_cmd, shell=True, cwd=str(sample_dir),
                capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                _log.error('compile failed for %s: %s',
                           sample['name'], result.stderr[:200])
                return None
        except subprocess.TimeoutExpired:
            _log.error('compile timeout for %s', sample['name'])
            return None

        if not binary_path.exists():
            return None
        return str(binary_path)

    def run_scan(self, binary_path: str, sample: Dict) -> SampleResult:
        """对单个二进制运行扫描器。"""
        result = SampleResult(
            sample_id=sample['name'],
            cve_id=sample.get('cve_id', ''),
            vuln_type=sample.get('vuln_type', 'unknown'),
            expected_finding_count=sample.get('expected_count', 1))

        start = time.time()
        try:
            proc = subprocess.run(
                [sys.executable, self.scanner_bin, binary_path, '--json'],
                capture_output=True, text=True, timeout=120)
            result.scan_time_sec = round(time.time() - start, 3)

            if proc.returncode != 0 and proc.returncode != 1:
                result.error = f'scanner exit code {proc.returncode}'
                return result

            try:
                scan_output = json.loads(proc.stdout)
            except json.JSONDecodeError:
                # 尝试从混合输出中提取JSON
                result.error = 'scanner output is not valid JSON'
                return result

            # 提取findings(兼容多种输出格式)
            findings = scan_output.get('findings', scan_output.get('results', []))
            result.actual_findings = findings
            result.passed = len(findings) >= result.expected_finding_count

        except subprocess.TimeoutExpired:
            result.scan_time_sec = 120.0
            result.error = 'scan timeout'

        return result

    def run_all(self) -> List[SampleResult]:
        """运行全部样本的回归测试。"""
        samples = self.discover_samples()
        _log.info('discovered %d samples', len(samples))
        results = []

        for sample in samples:
            binary = self.compile_sample(sample)
            if binary is None:
                results.append(SampleResult(
                    sample_id=sample['name'],
                    cve_id=sample.get('cve_id', ''),
                    error='compilation failed'))
                continue

            result = self.run_scan(binary, sample)
            results.append(result)
            _log.info('[%s] %s: %s (%.1fs)',
                      'PASS' if result.passed else 'FAIL',
                      result.sample_id,
                      f'{len(result.actual_findings)}/{result.expected_finding_count} findings',
                      result.scan_time_sec)

        return results

    def export_results(self, results: List[SampleResult],
                        output_file: str = '') -> str:
        """导出结果为JSON。"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = str(self.output_dir / f'regression_{timestamp}.json')

        summary = {
            'timestamp': datetime.now().isoformat(),
            'scanner': self.scanner_bin,
            'total_samples': len(results),
            'passed': sum(1 for r in results if r.passed),
            'failed': sum(1 for r in results if not r.passed and not r.error),
            'errors': sum(1 for r in results if r.error),
            'total_scan_time_sec': round(sum(r.scan_time_sec for r in results), 2),
            'results': [
                {
                    'sample_id': r.sample_id,
                    'cve_id': r.cve_id,
                    'vuln_type': r.vuln_type,
                    'expected': r.expected_finding_count,
                    'actual': len(r.actual_findings),
                    'passed': r.passed,
                    'scan_time_sec': r.scan_time_sec,
                    'error': r.error,
                } for r in results
            ],
        }

        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
        _log.info('results exported to %s', output_file)
        return output_file


def main():
    ap = argparse.ArgumentParser(description='BinMind regression test runner')
    ap.add_argument('--samples', required=True, help='CVE samples directory')
    ap.add_argument('--scanner', default='binmind.py', help='scanner binary')
    ap.add_argument('--output', default='results/', help='output directory')
    ap.add_argument('--verbose', '-v', action='store_true')
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format='%(asctime)s [%(levelname)s] %(message)s')

    runner = RegressionRunner(args.samples, args.scanner, args.output)
    results = runner.run_all()
    out_file = runner.export_results(results)
    print(f'Regression complete: {out_file}')


if __name__ == '__main__':
    main()
