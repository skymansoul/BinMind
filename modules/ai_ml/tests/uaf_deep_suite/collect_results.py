# UAF深度套件——结果收集与对比模块
# 期望: tp_*→检出; fp_*→过滤; 输出benchmark_summary.csv/json
import csv
import json
import sys
from collections import Counter
from pathlib import Path

SCAN_JSON = Path(__file__).parent / "scan_results.json"
CSV_OUT = Path(__file__).parent / "benchmark_summary.csv"
JSON_OUT = Path(__file__).parent / "benchmark_summary.json"


def expected(sample: str) -> bool:
    return sample.startswith("tp_")


def main() -> dict:
    if not SCAN_JSON.exists():
        print("[uaf collect] 缺少 scan_results.json")
        return {}
    rows = json.loads(SCAN_JSON.read_text(encoding="utf-8"))
    tp = fp = tn = fn = 0
    detail = []
    stage = Counter()
    for r in rows:
        exp = expected(r["sample"])
        det = r["detected"]
        if exp and det:
            tp += 1
        elif exp and not det:
            fn += 1
        elif not exp and not det:
            tn += 1
        else:
            fp += 1
        for reason in r.get("reasons", []):
            low = reason.lower()
            if "cross-func" in low:
                stage["cross_function"] += 1
            elif "rebirth" in low or "重生" in low:
                stage["rebirth"] += 1
            elif "path" in low:
                stage["path"] += 1
        detail.append({"sample": f"{r['sample']}_{r['opt']}",
                       "expected": "detect" if exp else "filter",
                       "detected": det, "correct": det == exp,
                       "time_ms": round(r.get("time_ms", 0), 1)})
    n = len(detail)
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    precision = tp / max(1, tp + fp)
    f1 = 2 * precision * recall / max(0.001, precision + recall)
    summary = {"n": n, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
               "recall": round(recall, 4), "fpr": round(fpr, 4),
               "precision": round(precision, 4), "f1": round(f1, 4),
               "stage_hits": dict(stage)}
    with open(CSV_OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["sample", "expected", "detected", "correct", "time_ms"])
        for d in detail:
            w.writerow([d["sample"], d["expected"], d["detected"],
                        d["correct"], d["time_ms"]])
    JSON_OUT.write_text(json.dumps({"summary": summary, "detail": detail},
                                   indent=2), encoding="utf-8")
    print(f"[uaf collect] n={n} TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"  Recall={recall:.1%} FPR={fpr:.1%} Precision={precision:.1%} F1={f1:.3f}")
    return summary


if __name__ == "__main__":
    main()
