"""
格式化字符串检测统一回归套件 — 类似堆溢出的 run_heap_suite.py.

整合三层检测:
  Level 0: Baseline 正则模式匹配 (printf(var) 直接匹配)
  Level 1: FSCS 评分 (格式说明符 + 用户可控性 + 输出目标)
  Level 2: FCPV 约束传播验证 (三值安全格 + cross-func)

样本集:
  - samples/format_string/sample_fmt_* (15个源码样本, 有 [VULN]/[SAFE] 标注)
  - modules/vuln/detection/src/format/fmt_samples/ (16个二进制样本)

入口: python tests/regression/run_fmt_suite.py
"""
from __future__ import annotations

import json, os, re, sys, time
from pathlib import Path
from typing import Dict, List, Tuple

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from core.fcpv_pipeline import fcpv_filter
from core.fcpv_constraint_types import SafetyLabel


# Ground Truth 提取

# 二进制级样本 ground truth (硬编码, 来自 fmt_regression_runner.py)
_BIN_GROUND_TRUTH: Dict[str, str] = {
    'sample01_direct_fmt_vuln': 'TP',
    'sample02_fmt_str_write_pct_n': 'TP',
    'sample03_indirect_fmt_leak': 'TP',
    'sample04_sprintf_fmt_vuln': 'TP',
    'sample05_fprintf_fmt_vuln': 'TP',
    'sample06_syslog_fmt_vuln': 'TP',
    'sample07_info_leak_stack_read': 'TP',
    'sample08_wrapper_fmt_vuln': 'TP',
    'sample09_fmt_str_const_safe': 'TN',
    'sample10_debug_log_safe': 'TN',
    'sample11_fmt_str_in_rodata_safe': 'TN',
    'sample12_snprintf_bounded_safe': 'TN',
    'sample13_dynamic_fmt_controlled': 'TP',
    'sample14_wide_char_fmt': 'TP',
    'sample15_pct_n_write_primitive': 'TP',
    'sample16_buffered_fmt_leak': 'TP',
}


def extract_src_ground_truth(source: str) -> str:
    """从源码注释提取 ground truth: [VULN] → TP, [SAFE] → TN."""
    if re.search(r'\[VULN\]', source):
        return 'TP'
    if re.search(r'\[SAFE\]', source):
        return 'TN'
    comment = source.split('*/')[0] if '*/' in source else source[:500]
    if re.search(r'VULN|CONFIRMED', comment, re.IGNORECASE):
        return 'TP'
    if re.search(r'SAFE|FILTERED', comment, re.IGNORECASE):
        return 'TN'
    return 'UNKNOWN'


# 三层级检测

_DANGER_FMT_RE = re.compile(
    r'(printf|fprintf|sprintf|snprintf|syslog|dprintf|vprintf)'
    r'\s*\(\s*(\w[\w\[\].]*)\s*[),]', re.IGNORECASE)
_SAFE_FMT_RE = re.compile(
    r'(printf|fprintf|sprintf|snprintf|dprintf|syslog|vprintf)'
    r'\s*\(\s*"', re.IGNORECASE)
_USER_SRC_RE = re.compile(
    r'(argv|fgets|getenv|recv|read|gets|scanf|fread)', re.IGNORECASE)


def detect_baseline(source: str) -> bool:
    """Level 0: 正则模式匹配 — 仅检查 printf(var) 且变量来自用户输入."""
    for line in source.splitlines():
        if _SAFE_FMT_RE.search(line):
            continue
        m = _DANGER_FMT_RE.search(line)
        if m and _USER_SRC_RE.search(source):
            return True
    return False


def detect_fscs(source: str) -> bool:
    """Level 1: FSCS 评分 (使用修复后的评分公式)."""
    try:
        from tests.regression.run.fmt_regression_runner import (
            detect_format_string_vulns, filter_by_fscs_threshold)
        cands = detect_format_string_vulns(source)
        kept, _ = filter_by_fscs_threshold(cands, 3.0)
        return len(kept) > 0
    except Exception:
        return False


def detect_fcpv(source: str) -> Tuple[bool, float, str]:
    """Level 2: FCPV 约束传播验证.

    返回 (has_vuln, confidence, reason).
    """
    r = fcpv_filter(source)
    if r['vuln']:
        v = r['vuln'][0]
        return True, v.confidence, v.reason
    return False, 0.0, ''


# 主回归入口

def run_fmt_suite(verbose: bool = True) -> Dict:
    """运行全量格式串检测回归套件.

    Returns:
        {
            "source_level": {"baseline": metrics, "fscs": metrics, "fcpv": metrics, "per_sample": [...]},
            "binary_level": {"metrics": {...}, "per_sample": [...]},
            "summary": {...}
        }
    """
    results = {}
    src_samples = _collect_source_samples()
    src_results = _scan_source_samples(src_samples, verbose)
    results['source_level'] = src_results
    src_fcpv = src_results.get('fcpv', {})

    if verbose:
        print(f"\n{'='*60}")
        print(f" Format String Detection - Full Regression Report")
        print(f"{'='*60}")
        print(f" Source-level samples: {len(src_samples)}")
        for level in ('baseline', 'fscs', 'fcpv'):
            m = src_results[level]
            print(f"  {level.upper():10s}: P={m['precision']:.4f} R={m['recall']:.4f} "
                  f"F1={m['f1']:.4f} FPR={m['fpr']:.4f} "
                  f"(TP={m['TP']} FP={m['FP']} TN={m['TN']} FN={m['FN']})")
        print()

    json_path = _PROJECT_ROOT / 'eval' / 'results' / 'fmt_suite_results.json'
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2, default=str)
    if verbose:
        print(f"JSON: {json_path}")
    return results


def _collect_source_samples() -> List[Tuple[str, str, str]]:
    """收集源码级样本: (sample_name, source_code, expected).

    设计决策: 从两个目录收集:
      - samples/format_string/sample_fmt_*/vuln.c (15个)
      - modules/vuln/detection/src/format/fmt_samples/sample*/main.c (16个, 取 .c 源码)
    """
    samples = []
    src_dir = _PROJECT_ROOT / 'samples' / 'format_string'
    if src_dir.exists():
        for d in sorted(src_dir.iterdir()):
            if not d.is_dir():
                continue
            for c_file in d.glob('*.c'):
                src = c_file.read_text(encoding='utf-8', errors='replace')
                expected = extract_src_ground_truth(src)
                if expected == 'UNKNOWN':
                    expected = _BIN_GROUND_TRUTH.get(d.name, 'UNKNOWN')
                samples.append((d.name, src, expected))
                break

    bin_dir = _PROJECT_ROOT / 'modules' / 'vuln' / 'detection' / 'src' / 'format' / 'fmt_samples'
    if bin_dir.exists():
        for d in sorted(bin_dir.iterdir()):
            if not d.is_dir():
                continue
            for c_file in d.glob('*.c'):
                src = c_file.read_text(encoding='utf-8', errors='replace')
                expected = _BIN_GROUND_TRUTH.get(d.name, 'UNKNOWN')
                if expected != 'UNKNOWN':
                    samples.append((d.name, src, expected))
                    break
    return samples


def _scan_source_samples(samples: List[Tuple[str, str, str]],
                          verbose: bool) -> Dict:
    """对源码样本运行三层检测."""
    per_sample = []
    for name, src, expected in samples:
        if expected == 'UNKNOWN':
            continue
        is_vuln_expected = (expected == 'TP')

        t0 = time.time()
        bl = detect_baseline(src)
        dt_bl = (time.time() - t0) * 1000

        t0 = time.time()
        fscs = detect_fscs(src)
        dt_fscs = (time.time() - t0) * 1000

        t0 = time.time()
        fcpv_v, fcpv_conf, fcpv_reason = detect_fcpv(src)
        dt_fcpv = (time.time() - t0) * 1000

        def _verdict(detected, expected_vuln):
            if detected and expected_vuln:
                return 'TP'
            if detected and not expected_vuln:
                return 'FP'
            if not detected and expected_vuln:
                return 'FN'
            return 'TN'

        row = {
            'sample': name,
            'expected': expected,
            'baseline': _verdict(bl, is_vuln_expected),
            'fscs': _verdict(fscs, is_vuln_expected),
            'fcpv': _verdict(fcpv_v, is_vuln_expected),
            'fcpv_conf': round(fcpv_conf, 2),
            'fcpv_reason': fcpv_reason[:80] if fcpv_reason else '',
            'time_ms': {'baseline': round(dt_bl, 1),
                        'fscs': round(dt_fscs, 1),
                        'fcpv': round(dt_fcpv, 1)},
        }
        per_sample.append(row)
        if verbose:
            status = 'PASS' if row['fcpv'] == expected else 'FAIL'
            print(f"  {name}... {status} "
                  f"(bl={row['baseline']} fscs={row['fscs']} fcpv={row['fcpv']})")

    def _metrics(level):
        tp = sum(1 for r in per_sample if r[level] == 'TP')
        fp = sum(1 for r in per_sample if r[level] == 'FP')
        tn = sum(1 for r in per_sample if r[level] == 'TN')
        fn = sum(1 for r in per_sample if r[level] == 'FN')
        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r_ = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * p * r_ / (p + r_) if (p + r_) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        return {'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
                'precision': round(p, 4), 'recall': round(r_, 4),
                'f1': round(f1, 4), 'fpr': round(fpr, 4)}

    return {
        'baseline': _metrics('baseline'),
        'fscs': _metrics('fscs'),
        'fcpv': _metrics('fcpv'),
        'per_sample': per_sample,
    }


if __name__ == '__main__':
    print("[1/3] Collecting format string samples...")
    samples = _collect_source_samples()
    print(f"  Found {len(samples)} samples")
    print("[2/3] Running three-level detection...")
    results = run_fmt_suite(verbose=True)
    print("[3/3] Computing metrics...")
    fcpv_m = results['source_level']['fcpv']
    print(f"\n{'='*60}")
    print(f" FCPV Final: P={fcpv_m['precision']} R={fcpv_m['recall']} "
          f"F1={fcpv_m['f1']} FPR={fcpv_m['fpr']}")
    all_pass = (fcpv_m['FP'] == 0 and fcpv_m['FN'] == 0)
    if all_pass:
        print(" All samples passed!")
    else:
        print(f" {fcpv_m['FP']} FP, {fcpv_m['FN']} FN remaining")
