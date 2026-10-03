"""
扫描调度模块 — 调用检测器对编译后的样本执行分析.

职责: 接收已编译二进制文件列表, 依次运行各检测器, 收集原始输出.
不参与编译或结果评估.
"""

import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional


def run_scanner(binary_path: str,
                detector: str = 'all',
                timeout: int = 60) -> Dict[str, Any]:
    """对单个二进制文件运行指定检测器.

    detector: 'stack' | 'format' | 'heap' | 'all'.
    Returns: {detector_name: {findings, elapsed, success}}.
    """
    results: Dict[str, Any] = {
        'binary': binary_path,
        'detectors': {},
    }

    detectors_to_run = []
    if detector in ('stack', 'all'):
        detectors_to_run.append('stack_overflow')
    if detector in ('format', 'all'):
        detectors_to_run.append('format_string')
    if detector in ('heap', 'all'):
        detectors_to_run.append('heap')

    for det in detectors_to_run:
        t0 = time.time()
        try:
            if det == 'stack_overflow':
                findings = _run_stack_analyzer(binary_path, timeout)
            elif det == 'format_string':
                findings = _run_format_detector(binary_path, timeout)
            elif det == 'heap':
                findings = _run_heap_analyzer(binary_path, timeout)
            else:
                continue
            elapsed = time.time() - t0
            results['detectors'][det] = {
                'findings': findings,
                'elapsed': round(elapsed, 3),
                'success': True,
            }
        except Exception as e:
            results['detectors'][det] = {
                'findings': [],
                'elapsed': round(time.time() - t0, 3),
                'success': False,
                'error': str(e)[:200],
            }
    return results


def _run_stack_analyzer(binary_path: str, timeout: int) -> List[Dict]:
    """调用栈溢出分析器."""
    try:
        from core.stack_overflow_analyzer import analyze_stack_overflow
        result = analyze_stack_overflow(binary_path, '')
        if isinstance(result, dict) and result.get('overflowable'):
            return [{'type': 'stack-overflow', 'function': result.get('function', 'unknown'),
                     'padding': result.get('padding', -1), 'has_canary': result.get('has_canary', True)}]
    except ImportError:
        pass
    return []


def _run_format_detector(binary_path: str, timeout: int) -> List[Dict]:
    """调用格式化字符串检测器."""
    try:
        from core.format_string_detector import detect_format_string_vulns
        findings = detect_format_string_vulns(binary_path)
        return [{'type': 'format-string', 'function': f.get('function', ''),
                 'format_func': f.get('format_func', ''), 'offset': f.get('offset', -1),
                 'confidence': f.get('confidence', 0)} for f in findings]
    except ImportError:
        return []


def _run_heap_analyzer(binary_path: str, timeout: int) -> List[Dict]:
    """调用堆漏洞分析器."""
    try:
        from core.heap_analyzer import analyze_heap_operations
        findings = analyze_heap_operations(binary_path)
        return [{'type': f.get('type', 'heap'), 'function': f.get('function', ''),
                 'description': f.get('description', ''), 'confidence': f.get('confidence', 0)}
                for f in findings]
    except ImportError:
        return []


def scan_directory(sample_dir: str, detector: str = 'all',
                   extensions: tuple = ('.elf', '.out', '')) -> List[Dict]:
    """扫描目录下所有编译后的二进制文件."""
    results = []
    binaries = []
    for root, _, files in os.walk(sample_dir):
        for f in files:
            fpath = os.path.join(root, f)
            is_exe = os.access(fpath, os.X_OK) if os.name != 'nt' else True
            if f.endswith(extensions) and is_exe and not f.endswith('.c'):
                binaries.append(fpath)
    for i, bpath in enumerate(sorted(binaries)):
        print(f'  [{i+1}/{len(binaries)}] scanning {os.path.basename(bpath)}...')
        result = run_scanner(bpath, detector)
        results.append(result)
    return results


if __name__ == '__main__':
    sample_dir = sys.argv[1] if len(sys.argv) > 1 else '../vuln_samples'
    detector = sys.argv[2] if len(sys.argv) > 2 else 'all'
    results = scan_directory(sample_dir, detector)
    print(json.dumps(results, indent=2, default=str))
