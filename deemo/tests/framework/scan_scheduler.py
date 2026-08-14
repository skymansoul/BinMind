"""
创建: 2026-06-27

扫描调度模块 — 调用 BinMind 检测引擎对编译好的样本进行批量扫描。

独立于 build_samples.py: 可对任意目录中的 ELF 文件执行扫描。
每个样本单独计时, 记录输出供 result_parser 解析。
"""

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BINMIND_MAIN = os.path.join(PROJECT_ROOT, "binmind.py")


@dataclass
class ScanResult:
    sample_name: str
    binary_path: str
    success: bool
    elapsed_sec: float
    findings_count: int
    raw_output: str = ""
    error: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


def scan_single(binary_path: str, timeout_sec: int = 120) -> ScanResult:
    """扫描单个 ELF 文件, 返回 ScanResult。"""
    sample_name = os.path.splitext(os.path.basename(binary_path))[0]
    start = time.time()

    try:
        proc = subprocess.run(
            [sys.executable, BINMIND_MAIN, "analyze", binary_path, "--format", "json"],
            capture_output=True, text=True,
            timeout=timeout_sec, cwd=PROJECT_ROOT,
        )
        elapsed = time.time() - start
        output = proc.stdout + "\n" + proc.stderr

        findings = _count_findings_in_output(output)
        return ScanResult(
            sample_name=sample_name, binary_path=binary_path,
            success=(proc.returncode == 0), elapsed_sec=elapsed,
            findings_count=findings, raw_output=output,
        )
    except subprocess.TimeoutExpired:
        return ScanResult(
            sample_name=sample_name, binary_path=binary_path,
            success=False, elapsed_sec=timeout_sec,
            findings_count=0, error=f"Timeout after {timeout_sec}s",
        )
    except Exception as e:
        return ScanResult(
            sample_name=sample_name, binary_path=binary_path,
            success=False, elapsed_sec=time.time() - start,
            findings_count=0, error=str(e),
        )


def scan_directory(bin_dir: str, timeout_sec: int = 120) -> List[ScanResult]:
    """扫描目录下所有 ELF 文件。"""
    results: List[ScanResult] = []
    for fname in sorted(os.listdir(bin_dir)):
        fpath = os.path.join(bin_dir, fname)
        if os.path.isfile(fpath) and (
            fname.endswith('.elf') or fname.endswith('.exe')
            or _is_elf(fpath) or _is_pe(fpath)
        ):
            result = scan_single(fpath, timeout_sec)
            results.append(result)
            print(f"  [{result.sample_name}]: {result.findings_count} findings "
                  f"in {result.elapsed_sec:.1f}s")
    return results


def _count_findings_in_output(output: str) -> int:
    """从 BinMind 输出中统计 finding 数量。"""
    count = 0
    for marker in ('[FINDING]', 'rule_id', '"type"', 'vulnerability', 'severity'):
        count += output.count(marker)
    return max(0, count)


def _is_elf(filepath: str) -> bool:
    try:
        with open(filepath, 'rb') as f:
            return f.read(4) == b'\x7fELF'
    except Exception:
        return False


def _is_pe(filepath: str) -> bool:
    try:
        with open(filepath, 'rb') as f:
            return f.read(4) == b'MZ\x90\x00'
    except Exception:
        return False


def save_scan_results(results: List[ScanResult], output_path: str) -> None:
    """将扫描结果保存为 JSON。"""
    data = []
    for r in results:
        data.append({
            'sample_name': r.sample_name,
            'binary_path': r.binary_path,
            'success': r.success,
            'elapsed_sec': r.elapsed_sec,
            'findings_count': r.findings_count,
            'error': r.error,
        })
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    bin_dir = sys.argv[1] if len(sys.argv) > 1 else "tests/cve_binaries"
    print(f"Scanning binaries in: {bin_dir}")
    results = scan_directory(bin_dir)
    save_scan_results(results, "tests/scan_results.json")
    total_findings = sum(r.findings_count for r in results)
    total_time = sum(r.elapsed_sec for r in results)
    print(f"Done: {len(results)} samples, {total_findings} findings, "
          f"{total_time:.1f}s total")
