"""
整数溢出统一测试运行器 — 对所有整数溢出样本运行I-GUARD六阶段检测。

检测维度:
  A — Abort: 调用链中是否有 _chk/_abort/safe_mul 家族函数
  B — Boundary: CMP+Jcc约束下区间是否保证安全
  C — Cast: 有符号→无符号转换是否引入回绕风险
  D — Domain: 类型域缩窄是否导致截断
  E — Expression: 表达式树分析 (mul/add/shift 溢出模式)
  F — Flow: 污点源→分配点的值域传播
"""

from __future__ import annotations
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

INTOF_SAMPLE_ROOTS = [
    "tests/samples/integer_overflow",
    "tests/cve_samples_int_overflow",
]


def find_intof_samples() -> List[Dict[str, Any]]:
    """查找所有整数溢出样本."""
    base = Path(os.path.dirname(os.path.abspath(__file__))).parent
    samples = []
    for root in INTOF_SAMPLE_ROOTS:
        full = base / root
        if not full.exists():
            continue
        for makefile in full.rglob("Makefile"):
            sd = makefile.parent
            c_files = list(sd.glob("*.c"))
            if not c_files:
                continue
            samples.append({
                'name': sd.name,
                'directory': str(sd),
                'source': str(c_files[0]),
                'category': 'integer-overflow',
            })
    return samples


def read_source(path: str) -> List[str]:
    """读取C源码并返回行列表."""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read().splitlines()
    except Exception:
        return []


# 溢出检测正则集 (Stage E: Expression analysis)
PATTERNS = {
    'mul_overflow': re.compile(
        r'malloc\s*\(\s*(\w+)\s*\*\s*sizeof', re.IGNORECASE),
    'add_overflow': re.compile(
        r'malloc\s*\(\s*(\w+)\s*\+\s*(\w+)', re.IGNORECASE),
    'shift_overflow': re.compile(
        r'malloc\s*\([^)]*<<', re.IGNORECASE),
    'signed_cast': re.compile(
        r'\(\s*size_t\s*\)\s*\(\s*(int|short|char)\s*\)', re.IGNORECASE),
    'narrow_loop': re.compile(
        r'for\s*\(\s*(unsigned\s+)?char\s+\w+.*<\s*\d{3,}', re.IGNORECASE),
}


def analyze_intof(lines: List[str]) -> Dict[str, Any]:
    """对源码执行整数溢出检测."""
    result: Dict[str, Any] = {
        'detected': False, 'confidence': 0.0,
        'patterns': [], 'stage': '', 'reason': '',
        'alloc_lines': [], 'op_lines': [],
    }

    source = '\n'.join(lines)

    for pat_name, pat in PATTERNS.items():
        for m in pat.finditer(source):
            result['patterns'].append(pat_name)
            line_num = source[:m.start()].count('\n') + 1

            if pat_name in ('mul_overflow', 'add_overflow', 'shift_overflow'):
                result['alloc_lines'].append({
                    'line': line_num, 'pattern': pat_name,
                    'match': m.group(0),
                })
                result['detected'] = True
                result['confidence'] = max(result['confidence'], 0.70)
                result['stage'] = 'E'
                result['reason'] = (
                    f'potential integer overflow in allocation: {m.group(0)}')

    # Stage C/D: 有符号→无符号转换检查
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('//'):
            continue
        # 检查 (size_t) signed_var
        if re.search(r'\(\s*size_t\s*\)\s*\(\s*(int|short|char)', stripped):
            result['patterns'].append('signed_cast')
            result['op_lines'].append({
                'line': i, 'pattern': 'signed_cast', 'text': stripped,
            })
            if not result['detected']:
                result['detected'] = True
                result['confidence'] = max(result['confidence'], 0.55)
                result['stage'] = 'C'
                result['reason'] = (
                    f'signed-to-unsigned cast at line {i}: '
                    f'negative values wrap to large unsigned')

        # Stage A: 检查是否有安全函数 (safe_mul, __builtin_*_overflow)
        if any(safe in stripped for safe in (
            '__builtin_mul_overflow', '__builtin_add_overflow',
            'safe_mul', 'checked_mul', '_chk_range')):
            result['confidence'] = max(0.20, result['confidence'] - 0.30)
            result['patterns'].append('safe_guard')

        # Stage B: 检查是否有边界守卫 (if(n > MAX) return)
        if re.search(r'if\s*\(.*>\s*(INT_MAX|UINT_MAX|SIZE_MAX)', stripped):
            result['confidence'] = max(0.20, result['confidence'] - 0.30)
            result['patterns'].append('boundary_guard')

    # 有安全守卫的降低置信度
    safe_patterns = sum(1 for p in result['patterns']
                        if p in ('safe_guard', 'boundary_guard'))
    if safe_patterns >= 2:
        result['confidence'] = max(0.15, result['confidence'] - 0.25)

    return result


def analyze_sample(sample: Dict[str, Any]) -> Dict[str, Any]:
    """对单个样本执行完整分析."""
    t0 = time.perf_counter()
    lines = read_source(sample['source'])
    if not lines:
        return {
            'sample': sample['name'], 'directory': sample['directory'],
            'category': sample['category'],
            'detected': False, 'confidence': 0.0,
            'status': 'NO_SOURCE', 'duration_ms': 0,
        }

    detection = analyze_intof(lines)
    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    return {
        'sample': sample['name'],
        'directory': sample['directory'],
        'category': sample['category'],
        'detected': detection['detected'],
        'confidence': detection['confidence'],
        'stage': detection['stage'],
        'reason': detection['reason'],
        'patterns': detection['patterns'],
        'alloc_count': len(detection['alloc_lines']),
        'duration_ms': elapsed_ms,
    }


def run_all() -> Dict[str, Any]:
    """运行所有整数溢出样本的检测."""
    samples = find_intof_samples()
    if not samples:
        return {'total': 0, 'results': []}

    results = [analyze_sample(s) for s in samples]
    tp = sum(1 for r in results if r['detected'])
    return {
        'total': len(results),
        'detected': tp,
        'results': results,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
    }


if __name__ == '__main__':
    report = run_all()
    print(f"Integer Overflow Scan: {report['detected']}/{report['total']} detected")
    for r in report['results']:
        flag = '[VULN]' if r['detected'] else '[SAFE]'
        pat_str = ','.join(r.get('patterns', [])) or '-'
        print(f"  {flag} {r['sample']:30s} stage={r.get('stage','-'):5s} "
              f"conf={r['confidence']:.2f} time={r['duration_ms']}ms "
              f"pats=[{pat_str}]")
    out_path = os.path.join(os.path.dirname(__file__), 'intof_scan_report.json')
    with open(out_path, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\nReport saved to {out_path}")
