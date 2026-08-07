# 多检测器综合回归测试 — 覆盖堆溢出/UAF/格式化字符串/整数溢出/竞态
"""多检测器回归测试 — 对所有CVE样本运行对应类型检测器, 计算检出率/误报率。

检测器映射:
  heap_overflow → HeapOverflowDetector
  uaf → UnifiedUAFDetector
  format_string → FmtSiteScanner
  integer_overflow → IntOverflowDetector
  race_condition → SharedAccessScanner
  stack_overflow → StackFrameAnalyzer

用法:
  python tests/run_multi_detector.py
  python tests/run_multi_detector.py --type heap_overflow
  python tests/run_multi_detector.py --quick
"""

import os, sys, json, time, subprocess, argparse, re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SAMPLE_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_samples")
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_results")

# 样本→期望漏洞类型的映射 (ground truth)
GROUND_TRUTH = {
    # Heap overflow TPs
    "CVE-2015-0235_ghost_heap_overflow": "heap_overflow",
    "CVE-2016-10191_heap_overflow": "heap_overflow",
    "CVE-2018-1000001_glibc_realpath_heap_overflow": "heap_overflow",
    "CVE-2021-3156_sudo_heap_overflow": "heap_overflow",
    "CVE-2023-27997_fortigate_heap_overflow": "heap_overflow",
    "CVE-2024-21626_runc_heap_overflow": "heap_overflow",
    "CVE-2022-0847_dirty_pipe": "heap_overflow",
    "CVE-2017-18017_tcp_mss": "heap_overflow",
    "CVE-2019-11477_tcp_sack": "heap_overflow",
    "CVE-2016-4971_wget": "heap_overflow",
    "CVE-2014-0160_heartbleed": "heap_overflow",
    "CVE-2025-TP001_tainted_heap_overflow": "heap_overflow",
    "CVE-2025-TP002_unbounded_heap_overflow": "heap_overflow",
    "CVE-2025-TP003_loop_bound": "heap_overflow",
    "CVE-2025-TP004_off_by_one": "heap_overflow",
    "CVE-2025-TP005_calc_error": "heap_overflow",
    "CVE-2025-TP006_direct_taint": "heap_overflow",
    # Heap overflow FPs (应被过滤)
    "CVE-2025-FP001_constant_malloc_safe": "safe",
    "CVE-2025-FP002_guarded_malloc_safe": "safe",
    "CVE-2025-FP003_alignment_safe": "safe",
    # UAF TPs
    "CVE-2019-10149_uaf_exim": "uaf",
    "CVE-2019-15947_uaf": "uaf",
    "CVE-2020-10713_uaf_grub2": "uaf",
    "CVE-2022-0185_uaf_filesystem": "uaf",
    "CVE-2023-0597_uaf_netfilter": "uaf",
    "CVE-2024-1086_uaf_nf_tables": "uaf",
    "CVE-2025-UAF-TP001_intra_stack": "uaf",
    "CVE-2025-UAF-TP002_double_free": "uaf",
    "CVE-2025-UAF-TP003_callback": "uaf",
    "CVE-2025-UAF-TP004_cond_free": "uaf",
    # UAF FP
    "CVE-2025-UAF-FP001_safe_realloc": "safe",
    # Format string TPs
    "CVE-2012-0809_format_string": "format_string",
    "CVE-2025-FMT-TP001_syslog": "format_string",
    "CVE-2025-FMT-TP002_fprintf": "format_string",
    # Format string FP
    "CVE-2025-FMT-FP001_safe_printf": "safe",
    # Race condition TPs
    "CVE-2025-RACE-TP001_shared_global": "race_condition",
    "CVE-2025-RACE-TP002_signal_handler": "race_condition",
    # Race condition FP
    "CVE-2025-RACE-FP001_atomic_safe": "safe",
    # Integer overflow TPs
    "CVE-2025-IO-TP001_mul_overflow": "integer_overflow",
    "CVE-2025-IO-TP002_io2bo_chain": "integer_overflow",
    # Stack overflow
    "CVE-2020-10757_stack_overflow": "stack_overflow",
    # Command injection
    "CVE-2024-21887_cmd_inject": "cmd_injection",
}


def disassemble_binary(binary_path: str) -> list:
    """objdump反汇编。"""
    try:
        r = subprocess.run(
            ["objdump", "-d", "-M", "intel", binary_path],
            capture_output=True, text=True, timeout=30)
        return r.stdout.split('\n') if r.returncode == 0 else []
    except Exception:
        return []


def detect_sample(binary_path: str, sample_name: str, expected_type: str) -> dict:
    """对单个样本运行对应类型的检测器。"""
    t0 = time.time()
    result = {
        'sample': sample_name,
        'expected_type': expected_type,
        'detected': False,
        'confidence': 0.0,
        'time_secs': 0,
        'error': None,
        'details': {},
    }

    asm = disassemble_binary(binary_path)
    if not asm:
        result['error'] = 'disasm failed'
        result['time_secs'] = round(time.time() - t0, 2)
        return result

    try:
        if expected_type == 'heap_overflow' or expected_type == 'safe':
            # 安全样本也用heap detector测试 (应过滤)
            from src.heap_overflow_detector import HeapOverflowDetector
            d = HeapOverflowDetector()
            rpt = d.detect(asm, function_name=sample_name)
            # detected = 有未被过滤的TP告警 (即检测器确认的漏洞)
            result['detected'] = rpt.true_positives > 0
            result['confidence'] = 1.0 - (rpt.fp_reduction_pct / 100.0) if rpt.total_findings else 0
            result['details'] = rpt.to_dict()

        elif expected_type == 'uaf':
            from src.uaf_unified_detector import UnifiedUAFDetector
            d = UnifiedUAFDetector()
            rpt = d.detect(asm, function_name=sample_name)
            result['detected'] = rpt.total_confirmed > 0
            result['confidence'] = rpt.severity.score if hasattr(rpt, 'severity') else 0.5
            result['details'] = rpt.to_dict()

        elif expected_type == 'format_string':
            from src.fmtstr_analyzer import FmtSiteScanner
            s = FmtSiteScanner()
            sites = s.scan(asm)
            dangerous = [s for s in sites if s.is_dangerous]
            result['detected'] = len(dangerous) > 0
            result['confidence'] = max((s.confidence for s in dangerous), default=0)
            result['details'] = {
                'total_sites': len(sites),
                'dangerous': len(dangerous),
                'safe': sum(1 for s in sites if s.fmt_source_type == 'constant'),
                'sites': [{'func': s.func_name, 'source': s.fmt_source_type,
                           'dangerous': s.is_dangerous, 'conf': s.confidence}
                          for s in sites],
            }

        elif expected_type == 'integer_overflow':
            from src.int_overflow_analyzer import IntOverflowDetector
            d = IntOverflowDetector()
            rpt = d.detect(asm, function_name=sample_name)
            result['detected'] = rpt.overflow_count > 0
            result['confidence'] = 0.8 if rpt.io2bo_count > 0 else (0.5 if rpt.overflow_count > 0 else 0)
            result['details'] = rpt.to_dict()

        elif expected_type == 'race_condition':
            from src.race_detector import SharedAccessScanner
            s = SharedAccessScanner()
            accesses, races = s.scan(asm)
            result['detected'] = len(races) > 0
            result['confidence'] = 0.7 if len(races) > 0 else 0
            result['details'] = {
                'total_accesses': len(accesses),
                'race_candidates': len(races),
                'atomic': sum(1 for a in accesses if a.is_atomic),
                'races': [{'addr': r.shared_address, 'write': r.has_write,
                           'locked': r.has_lock_protection} for r in races[:10]],
            }

        elif expected_type == 'stack_overflow':
            from src.stack_overflow_analyzer import StackFrameAnalyzer
            a = StackFrameAnalyzer()
            rpt = a.analyze(asm, function_name=sample_name)
            result['detected'] = rpt.overflow_count > 0
            result['confidence'] = 0.5
            result['details'] = rpt.to_dict() if hasattr(rpt, 'to_dict') else {}

        elif expected_type == 'cmd_injection':
            result['detected'] = False  # 非本模块负责
            result['confidence'] = 0

    except ImportError as e:
        result['error'] = f'import: {e}'
    except Exception as e:
        result['error'] = str(e)[:200]

    result['time_secs'] = round(time.time() - t0, 2)
    return result


def compute_metrics(results: List[dict]) -> dict:
    """按漏洞类型计算检出率和误报率。"""
    by_type = {}
    for r in results:
        vt = r['expected_type']
        if vt not in by_type:
            by_type[vt] = {'total': 0, 'tp': 0, 'fn': 0, 'fp': 0, 'tn': 0}

        by_type[vt]['total'] += 1
        if vt == 'safe':
            # FP样本: detected = FP (误报), not detected = TN (正确过滤)
            if r['detected']:
                by_type[vt]['fp'] += 1
            else:
                by_type[vt]['tn'] += 1
        else:
            # TP样本: detected = TP, not detected = FN
            if r['detected']:
                by_type[vt]['tp'] += 1
            else:
                by_type[vt]['fn'] += 1

    # 计算指标
    for vt, m in by_type.items():
        tp, fn, fp, tn = m['tp'], m['fn'], m['fp'], m['tn']
        m['recall'] = round(tp / (tp + fn) * 100, 1) if (tp + fn) > 0 else 0
        m['precision'] = round(tp / (tp + fp) * 100, 1) if (tp + fp) > 0 else 100
        m['fp_rate'] = round(fp / (fp + tn) * 100, 1) if (fp + tn) > 0 else 0

    return by_type


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--type', help='Only run detector for specific type')
    p.add_argument('--quick', action='store_true', help='Only test 2025 samples')
    p.add_argument('--json', action='store_true', help='Output JSON only')
    args = p.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    results = []
    scanned = 0
    detected = 0

    for d in sorted(os.listdir(SAMPLE_ROOT)):
        if args.quick and not d.startswith('CVE-2025'):
            continue
        sample_dir = os.path.join(SAMPLE_ROOT, d)
        if not os.path.isdir(sample_dir):
            continue
        expected = GROUND_TRUTH.get(d, 'unknown')
        if expected == 'unknown':
            continue
        if args.type and expected != args.type and expected != 'safe':
            continue

        binary = os.path.join(sample_dir, "vuln_debug")
        if not os.path.isfile(binary):
            binary = os.path.join(sample_dir, "vuln_debug.exe")
        if not os.path.isfile(binary):
            continue

        scanned += 1
        r = detect_sample(binary, d, expected)
        results.append(r)
        if r['detected']:
            detected += 1
        status = 'TP' if (r['detected'] and expected != 'safe') else \
                 'FP' if (r['detected'] and expected == 'safe') else \
                 'FN' if (not r['detected'] and expected != 'safe') else 'TN'
        if not args.json:
            err = f" [{r['error']}]" if r['error'] else ""
            print(f"  [{status}] {d} ({expected}) {r['time_secs']}s{err}")

    metrics = compute_metrics(results)

    if not args.json:
        print(f"\n{'='*60}")
        print(f"  SCANNED: {scanned}  |  DETECTED: {detected}")
        print(f"{'='*60}")
        print(f"{'Type':<22} {'Samples':>7} {'TP':>5} {'FN':>5} {'Recall':>7} {'Prec':>7} {'FP%':>6}")
        print(f"{'-'*22} {'-'*7} {'-'*5} {'-'*5} {'-'*7} {'-'*7} {'-'*6}")

        for vt in sorted(metrics.keys()):
            m = metrics[vt]
            if vt == 'safe': continue
            print(f"  {vt:<20} {m['total']:>7} {m['tp']:>5} {m['fn']:>5} "
                  f"{m['recall']:>6.1f}% {m['precision']:>6.1f}% {m['fp_rate']:>5.1f}%")

        # FP汇总
        safety = metrics.get('safe', {})
        fp = safety.get('fp', 0)
        tn = safety.get('tn', 0)
        print(f"  {'safe (FP test)':<20} {safety.get('total', 0):>7} {tn:>5} TN "
              f"{fp:>5} FP {safety.get('fp_rate', 0):>5.1f}% FP rate")

    # 保存结果
    out = {
        'scanned': scanned,
        'detected': detected,
        'metrics': metrics,
        'results': [{k: r[k] for k in ['sample', 'expected_type', 'detected',
                      'confidence', 'time_secs', 'error']} for r in results],
    }
    with open(os.path.join(OUTPUT_DIR, "multi_detector_summary.json"), 'w') as f:
        json.dump(out, f, indent=2)
    print(f"\nResults saved to {OUTPUT_DIR}/multi_detector_summary.json")


if __name__ == '__main__':
    main()
