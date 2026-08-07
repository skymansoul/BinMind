# 深度样本结果收集与对比模块——与期望真值比对输出指标
# 期望: tp_*→检出; fp_*→过滤
# 输出: tests/deep_suite/benchmark_summary.csv + summary.json
# 附每样本触发阶段(消融证据)

from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List

BASE = Path(__file__).parent.parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

SCAN_JSON = Path(__file__).parent / "scan_results.json"
CSV_OUT = Path(__file__).parent / "benchmark_summary.csv"
JSON_OUT = Path(__file__).parent / "benchmark_summary.json"


def expected(sample: str) -> bool:
    """tp_*期望检出=True; fp_*期望过滤=False"""
    return sample.startswith("tp_")


def collect() -> Dict:
    if not SCAN_JSON.exists():
        print("[collect_results] 缺少 scan_results.json, 先运行 scan_scheduler.py")
        return {}
    rows = json.loads(SCAN_JSON.read_text(encoding="utf-8"))

    per_sample: Dict[str, Dict] = {}
    for r in rows:
        key = f"{r['sample']}_{r['opt']}"
        per_sample[key] = r

    # 阶段触发统计——从reason关键字识别新模块命中
    stage_hits = Counter()
    for r in rows:
        for reason in r.get("reasons", []):
            low = reason.lower()
            if "param_equality" in low:
                stage_hits["param_equality"] += 1
            elif "ppsr" in low or "支配守卫" in low:
                stage_hits["path_resolver"] += 1
            elif "loop_cumulative" in low:
                stage_hits["loop_cumulative"] += 1
            elif "same_source" in low or "same stack" in low:
                stage_hits["same_source"] += 1
            elif "dcg" in low:
                stage_hits["dcg"] += 1
            elif "4-stage" in low or "constraint" in low:
                stage_hits["constraint"] += 1

    tp = fp = tn = fn = 0
    detail = []
    for key, r in sorted(per_sample.items()):
        exp = expected(r["sample"])
        detected = r["detected"]
        if exp and detected:
            tp += 1
        elif exp and not detected:
            fn += 1
        elif not exp and not detected:
            tn += 1
        else:
            fp += 1
        detail.append({
            "sample": key, "expected": "detect" if exp else "filter",
            "detected": detected, "verdicts": r.get("verdicts", []),
            "reasons": r.get("reasons", []), "time_ms": round(r.get("time_ms", 0), 1),
            "correct": detected == exp})
    n = len(detail)
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    precision = tp / max(1, tp + fp)
    f1 = 2 * precision * recall / max(0.001, precision + recall)
    summary = {
        "n": n, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "recall": round(recall, 4), "fpr": round(fpr, 4),
        "precision": round(precision, 4), "f1": round(f1, 4),
        "stage_hits": dict(stage_hits),
    }

    with open(CSV_OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["sample", "expected", "detected", "correct", "time_ms"])
        for d in detail:
            w.writerow([d["sample"], d["expected"], d["detected"],
                        d["correct"], d["time_ms"]])
    JSON_OUT.write_text(json.dumps({
        "summary": summary, "detail": detail}, indent=2), encoding="utf-8")
    print(f"\n[collect_results] n={n}  TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"  Recall={recall:.1%}  FPR={fpr:.1%}  Precision={precision:.1%}  F1={f1:.3f}")
    print(f"  阶段命中: {dict(stage_hits)}")
    return summary


if __name__ == "__main__":
    collect()
