"""分析 heap_overflow 类别的工具对比结果."""
import csv

with open("eval/benchmark_full.csv", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

ho = [r for r in rows if r["category"] == "heap_overflow"]
tools = {}
for r in ho:
    t = r["tool"]
    if t not in tools:
        tools[t] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    gt = r["ground_truth"] == "True"
    pred = r["verdict"] == "OVERFLOW"
    if gt and pred:
        tools[t]["tp"] += 1
    elif gt and not pred:
        tools[t]["fn"] += 1
    elif not gt and pred:
        tools[t]["fp"] += 1
    else:
        tools[t]["tn"] += 1

for t, m in sorted(tools.items()):
    tp, fp, tn, fn = m["tp"], m["fp"], m["tn"], m["fn"]
    p = tp / (tp + fp) if tp + fp else 0
    r = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * p * r / (p + r) if p + r else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    print(f"{t:20s} TP={tp} FP={fp} TN={tn} FN={fn} "
          f"P={p:.4f} R={r:.4f} F1={f1:.4f} FPR={fpr:.4f}")

samples = set(r["sample"] for r in ho)
print(f"Total heap_overflow samples: {len(samples)}")
