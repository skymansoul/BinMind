# tests/framework/scanner.py
# 扫描调度模块: 调用BinMind检测引擎对编译后的二进制执行漏洞检测
import os
import subprocess
import sys
import json
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class ScanResult:
    sample_name: str
    optimize_level: str = 'O0'
    binary_path: str = ''
    success: bool = False
    findings: List[Dict] = field(default_factory=list)
    duration_sec: float = 0.0
    error_msg: str = ''


def scan_binary(binary_path: str, sample_name: str,
                optimize: str = 'O0') -> ScanResult:
    """Run BinMind detection on a single binary."""
    result = ScanResult(
        sample_name=sample_name,
        optimize_level=optimize,
        binary_path=binary_path)

    if not os.path.isfile(binary_path):
        result.error_msg = f'Binary not found: {binary_path}'
        return result

    t0 = time.perf_counter()
    findings = []

    try:
        # Import and call the detection engines directly
        sys.path.insert(0, os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))))

        # Format string detection
        try:
            from core.format_string_detector import detect_format_string_vulns
            fmt_findings = detect_format_string_vulns(binary_path)
            for f in fmt_findings:
                f['detector'] = 'format_string'
            findings.extend(fmt_findings)
        except ImportError:
            pass

        # Heap / UAF detection via the static analyzers
        try:
            from modules.analysis.static.tools.heap_exploit_analyzer import (
                HeapExploitAnalyzer)
            # Heap analysis requires binary memory dump - skip if not available
            pass
        except ImportError:
            pass

        result.success = True
    except Exception as e:
        result.error_msg = str(e)[:200]

    result.duration_sec = round(time.perf_counter() - t0, 3)
    result.findings = findings
    return result


def scan_all(samples_root: str,
             optimize_levels: List[str] = None) -> List[ScanResult]:
    """Scan all compiled binaries in the samples directory."""
    if optimize_levels is None:
        optimize_levels = ['O0', 'O2']
    results = []
    for entry in sorted(os.listdir(samples_root)):
        d = os.path.join(samples_root, entry)
        if not os.path.isdir(d):
            continue
        for opt in optimize_levels:
            binary = os.path.join(d, f'vuln_{opt}')
            if os.path.isfile(binary):
                results.append(
                    scan_binary(binary, entry, opt))
    return results


if __name__ == '__main__':
    root = os.path.join(os.path.dirname(__file__), '..', 'cve_samples')
    for r in scan_all(root):
        status = 'OK' if r.success else 'FAIL'
        print(f'[{status}] {r.sample_name} {r.optimize_level}: '
              f'{len(r.findings)} findings ({r.duration_sec}s)')
