# 多工具对比基准测试主脚本 — 统一CSV输出
"""对所有堆溢出样本运行 BinMind + Angr + QEMU + Ghidra, 输出统一CSV。

CSV列: sample, variant, tool, detected, tp, fp, fn, time_secs, peak_mem_mb

variant: plain(未加壳) / packed(加壳) — 由packer生成加壳副本。

用法:
  python eval/run_benchmark.py                 # 完整实验(全部样本×2变体)
  python eval/run_benchmark.py --no-packed     # 仅未加壳
  python eval/run_benchmark.py --heap-only     # 仅堆溢出样本
输出: eval/benchmark_results.csv + eval/benchmark_summary.json
"""

import os, sys, json, time, csv, subprocess, argparse, shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
SAMPLE_ROOT = os.path.join(os.path.dirname(__file__), '..', 'tests',
                           'cve_samples')
EVAL_DIR = os.path.dirname(os.path.abspath(__file__))

# 堆溢出正样本与安全样本(ground truth)
HEAP_TP = [
    'CVE-2025-TP001_tainted_heap_overflow',
    'CVE-2025-TP002_unbounded_heap_overflow',
    'CVE-2025-TP003_loop_bound',
    'CVE-2025-TP004_off_by_one',
    'CVE-2025-TP005_calc_error',
    'CVE-2025-TP006_direct_taint',
    'CVE-2025-TP007_cross_func_alloc',
    'CVE-2025-TP008_mul_size',
    'CVE-2025-TP009_indirect_taint',
    'CVE-2025-TP010_loop_write',
    'CVE-2025-TP011_call_ret_size',
    'CVE-2025-TP012_realloc_expand',
    'CVE-2025-TP013_struct_field',
    'CVE-2025-TP014_array_idx',
    'CVE-2025-TP015_chained_arith',
    'CVE-2025-TP016_strlen_offby',
    'CVE-2015-0235_ghost_heap_overflow',
    'CVE-2016-10191_heap_overflow',
    'CVE-2021-3156_sudo_heap_overflow',
    'CVE-2023-27997_fortigate_heap_overflow',
]
HEAP_FP = [
    'CVE-2025-FP001_constant_malloc_safe',
    'CVE-2025-FP002_guarded_malloc_safe',
    'CVE-2025-FP003_alignment_safe',
    'CVE-2025-FP004_and_mask_guard',
    'CVE-2025-FP005_loop_bound_safe',
    'CVE-2025-FP006_minsize_guard',
    'CVE-2025-FP007_cross_call_valid',
    'CVE-2025-FP008_cmova_capped',
]


def find_binaries(heap_only: bool = True) -> list:
    """收集样本二进制。默认仅堆溢出样本(heap_only=True)。"""
    bins = []
    names = HEAP_TP + HEAP_FP if heap_only else None
    for d in sorted(os.listdir(SAMPLE_ROOT)):
        if names and d not in names:
            continue
        if not heap_only and not (
                d.startswith('CVE-2025-TP') or d.startswith('CVE-2025-FP')
                or d.startswith('CVE-2015') or d.startswith('CVE-2016')
                or d.startswith('CVE-2018') or d.startswith('CVE-2021')
                or d.startswith('CVE-2023') or d.startswith('CVE-2024')):
            continue
        p = os.path.join(SAMPLE_ROOT, d, 'vuln_debug.exe')
        if not os.path.isfile(p):
            p = os.path.join(SAMPLE_ROOT, d, 'vuln_debug')
        if os.path.isfile(p):
            bins.append({"name": d, "path": p})
    return bins


def peak_memory_mb() -> float:
    """采样当前进程峰值内存(近似)。"""
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
    except Exception:
        try:
            import ctypes
            from ctypes import wintypes
            class P(ctypes.Structure):
                _fields_ = [('h', wintypes.HANDLE), ('pid', wintypes.DWORD),
                            ('size', wintypes.DWORD)]
            class M(ctypes.Structure):
                _fields_ = [('cb', wintypes.DWORD),
                            ('PageFaultCount', wintypes.DWORD),
                            ('PeakWorkingSetSize', ctypes.c_size_t),
                            ('WorkingSetSize', ctypes.c_size_t),
                            ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
                            ('QuotaPagedPoolUsage', ctypes.c_size_t),
                            ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
                            ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                            ('PagefileUsage', ctypes.c_size_t),
                            ('PeakPagefileUsage', ctypes.c_size_t)]
            m = M()
            m.cb = ctypes.sizeof(M)
            h = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.kernel32.GetProcessMemoryInfo(h, ctypes.byref(m),
                                                           m.cb):
                return m.PeakWorkingSetSize / (1024.0 * 1024.0)
        except Exception:
            pass
    return 0.0


def run_binmind(binary, sample_name, enable_write_side=True):
    """调用BinMind堆溢出检测器。"""
    t0 = time.time()
    try:
        from src.heap_overflow_detector import HeapOverflowDetector
        from src.asm_normalize import normalize_asm_lines
        r = subprocess.run(['objdump', '-d', '-M', 'intel', binary],
                           capture_output=True, text=True, timeout=30)
        lines = normalize_asm_lines(r.stdout.split('\n'))
        det = HeapOverflowDetector(enable_write_side=enable_write_side)
        rep = det.detect(lines, sample_name)
        is_tp_sample = sample_name in HEAP_TP
        # 语义: fp=安全样本上误报警告数, fn=正样本漏检数
        fp = 1 if (not is_tp_sample and rep.true_positives > 0) else 0
        return {"detected": rep.true_positives > 0,
                "tp": rep.true_positives if is_tp_sample else 0,
                "fp": fp,
                "fn": 1 if (is_tp_sample and rep.true_positives == 0) else 0,
                "time": round(time.time() - t0, 2), "error": None}
    except Exception as e:
        return {"detected": False, "tp": 0, "fp": 0, "fn": 0,
                "time": round(time.time() - t0, 2), "error": str(e)[:100]}


def run_external(script, binary, sample_name, args=None):
    """调用外部工具脚本。"""
    t0 = time.time()
    cmd = [sys.executable, os.path.join(EVAL_DIR, script), binary]
    if args:
        cmd.extend(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        data = json.loads(r.stdout) if r.stdout else {}
        is_tp_sample = sample_name in HEAP_TP
        detected = bool(data.get('detected') or data.get('crashed')
                        or data.get('dangerous_sinks'))
        # 语义: tp=正样本检出, fp=安全样本误报, fn=正样本漏检
        return {"detected": detected,
                "tp": 1 if (detected and is_tp_sample) else 0,
                "fp": 1 if (detected and not is_tp_sample) else 0,
                "fn": 1 if (is_tp_sample and not detected) else 0,
                "time": round(time.time() - t0, 2),
                "error": data.get('error', None)}
    except Exception as e:
        return {"detected": False, "tp": 0, "fp": 0, "fn": 0,
                "time": round(time.time() - t0, 2), "error": str(e)[:100]}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--no-packed', action='store_true', help='Skip packed group')
    p.add_argument('--all', action='store_true',
                   help='Run on all samples (default: heap-only)')
    args = p.parse_args()

    binaries = find_binaries(heap_only=not args.all)
    if not binaries:
        print("No binaries found. Run: python tests/compile_samples.py debug")
        return 1

    # 生成加壳副本
    from packer import Packer
    packer = Packer(packed_dir=os.path.join(EVAL_DIR, 'packed'))
    packed_manifest = []
    if not args.no_packed:
        packed_manifest = packer.pack_all(binaries)

    rows = [["sample", "variant", "tool", "detected", "tp", "fp",
             "fn", "time_secs", "peak_mem_mb", "error"]]
    summary = {}

    for b in binaries:
        variants = [('plain', b['path'])]
        for pm in packed_manifest:
            if pm['sample'] == b['name'] and os.path.isfile(pm['packed']):
                variants.append(('packed', pm['packed']))
        for variant, binpath in variants:
            for tool_name, runner in [
                    ("BinMind", lambda bp=b['path']: run_binmind(bp, b['name'])),
                    ("Angr", lambda bp=binpath: run_external(
                        "angr_explorer.py", bp, b['name'])),
                    ("QEMU+Trace", lambda bp=binpath: run_external(
                        "qemu_tracer.py", bp, b['name'])),
                    ("Ghidra", lambda bp=binpath: run_external(
                        "ghidra_headless.py", bp, b['name'])),
            ]:
                r = runner()
                mem = peak_memory_mb()
                rows.append([b["name"], variant, tool_name,
                             str(r.get("detected", False)),
                             str(r.get("tp", 0)), str(r.get("fp", 0)),
                             str(r.get("fn", 0)),
                             str(r.get("time", 0)),
                             f"{mem:.1f}",
                             (r.get("error") or "")[:100]])
                print(f"  [{tool_name:12s}|{variant:6s}] "
                      f"{b['name'][:45]:47s} det={r.get('detected')}")

    csv_path = os.path.join(EVAL_DIR, "benchmark_results.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(rows)

    # 汇总统计: 按样本语义分离
    from collections import defaultdict
    stats = defaultdict(lambda: {'tp_detected': 0, 'tp_total': 0,
                                 'fp_total': 0, 'fp_alarms': 0,
                                 'fn_total': 0, 'time': 0.0, 'n': 0})
    for row in rows[1:]:
        s, variant, tool, det, tp, fp, fn, t, mem, err = row
        key = f"{tool}|{variant}"
        stats[key]['n'] += 1
        stats[key]['time'] += float(t)
        is_tp = s in HEAP_TP
        if is_tp:
            stats[key]['tp_total'] += 1
            if det == 'True':
                stats[key]['tp_detected'] += 1
            else:
                stats[key]['fn_total'] += 1
        else:
            stats[key]['fp_total'] += 1
            if det == 'True':
                stats[key]['fp_alarms'] += 1

    summary = {'total_samples': len(binaries),
               'tp_expected': len(HEAP_TP),
               'fp_expected': len(HEAP_FP),
               'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
               'tools': {}}
    for key, v in stats.items():
        tool, variant = key.split('|')
        total = max(v['n'], 1)
        recall = (v['tp_detected'] / v['tp_total'] * 100
                  if v['tp_total'] else 0)
        fp_rate = (v['fp_alarms'] / v['fp_total'] * 100
                   if v['fp_total'] else 0)
        precision = (v['tp_detected'] / max(v['tp_detected'] + v['fp_alarms'], 1)
                     * 100)
        summary['tools'].setdefault(tool, {})[variant] = {
            'samples': v['n'],
            'tp_expected': v['tp_total'],
            'tp_detected': v['tp_detected'],
            'fn': v['fn_total'],
            'fp_alarms': v['fp_alarms'],
            'recall_pct': round(recall, 1),
            'fp_rate_pct': round(fp_rate, 1),
            'precision_pct': round(precision, 1),
            'avg_time': round(v['time'] / total, 2),
        }

    with open(os.path.join(EVAL_DIR, "benchmark_summary.json"), "w",
              encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"\nCSV saved: {csv_path} ({len(rows)-1} rows)")
    print(f"Summary saved: {os.path.join(EVAL_DIR, 'benchmark_summary.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
