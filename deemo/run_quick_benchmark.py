# BinMind pipeline 堆溢出样本快速基准测试
import sys, os, json, time, subprocess

sys.path.insert(0, '.')
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from core.unified_heap_pipeline import analyze_heap_safety

HEAP_SAMPLES_DIR = "tests/heap_overflow_samples"
OUTPUT_FILE = "eval/results/benchmark_summary.json"
RESULTS_FILE = "eval/results/benchmark_results.json"

# 各样本预期判定（名称→是否应检出）
EXPECTED = {
    'ho_01': True,   # CVE-2021-3156: malloc without escape expansion
    'ho_02': True,   # likely overflow
    'ho_03': True,
    'ho_04': True,
    'ho_05': True,
    'ho_06': True,
    'ho_07': True,
    'ho_08': True,
    'ho_09': True,
    'ho_10': True,
    'ho_11': True,
    'ho_12': True,
    'ho_13': True,
    'ho_14': True,
    'ho_15': True,
}

def scan_sample(sample_dir, sample_name):
    # 用 BinMind 扫描单个样本
    vuln_c = os.path.join(sample_dir, 'vuln.c')
    if not os.path.exists(vuln_c):
        return None

    t0 = time.perf_counter()
    try:
        with open(vuln_c, 'r', encoding='utf-8', errors='replace') as f:
            code = f.read()
    except Exception:
        return None

    try:
        findings, stats = analyze_heap_safety(code, 'main', vuln_c)
    except Exception as e:
        return {
            "tool": "BinMind", "sample": sample_name,
            "findings_total": 0, "findings_definite": 0,
            "findings_possible": 0, "filtered": 0,
            "duration_s": round(time.perf_counter() - t0, 3),
            "success": False, "error": str(e)[:200],
        }

    dt = round(time.perf_counter() - t0, 3)
    definite = sum(1 for f in findings if f.get('verdict') == 'DEFINITE')
    possible = sum(1 for f in findings if f.get('verdict') == 'POSSIBLE')
    detected = definite > 0 or possible > 0

    return {
        "tool": "BinMind", "sample": sample_name,
        "findings_total": len(findings),
        "findings_definite": definite,
        "findings_possible": possible,
        "filtered": stats.get('filtered', 0),
        "detected": detected,
        "duration_s": dt,
        "success": True, "error": "",
    }

def main():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    results = []
    samples_dir = HEAP_SAMPLES_DIR
    if not os.path.isdir(samples_dir):
        print(f"Directory not found: {samples_dir}")
        return

    for dirname in sorted(os.listdir(samples_dir)):
        dirpath = os.path.join(samples_dir, dirname)
        if not os.path.isdir(dirpath):
            continue
        print(f"Scanning {dirname}...", end=" ", flush=True)
        r = scan_sample(dirpath, dirname)
        if r:
            results.append(r)
            verdict = "DETECT" if r['detected'] else "CLEAN"
            print(f"{verdict} ({r['findings_definite']}D/{r['findings_possible']}P/{r['filtered']}F, {r['duration_s']:.2f}s)")
        else:
            print("SKIP (no vuln.c)")

    # 计算指标
    tp = fp = fn = tn = 0
    for r in results:
        name = r['sample']
        should_detect = EXPECTED.get(name, True)
        if should_detect and r['detected']:
            tp += 1
        elif should_detect and not r['detected']:
            fn += 1
        elif not should_detect and r['detected']:
            fp += 1
        else:
            tn += 1

    recall = tp / max(1, tp + fn)
    precision = tp / max(1, tp + fp)
    f1 = 2 * recall * precision / max(0.001, recall + precision)
    fpr = fp / max(1, fp + tn)

    summary = {
        "samples_dir": samples_dir,
        "total_samples": len(results),
        "tools": ["BinMind"],
        "metrics": {
            "BinMind": {
                "TP": tp, "FP": fp, "FN": fn, "TN": tn,
                "recall": round(recall, 3),
                "precision": round(precision, 3),
                "f1": round(f1, 3),
                "false_positive_rate": round(fpr, 3),
                "total_vuln_samples": tp + fn,
                "total_safe_samples": tn + fp,
            }
        },
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    with open(RESULTS_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\nBenchmark summary:")
    print(f"  TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"  Recall={recall:.1%} Precision={precision:.1%} F1={f1:.3f} FPR={fpr:.1%}")
    print(f"  Results: {RESULTS_FILE}")
    print(f"  Summary: {OUTPUT_FILE}")

if __name__ == '__main__':
    main()
