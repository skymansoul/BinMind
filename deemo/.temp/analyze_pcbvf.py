#!/usr/bin/env python3
"""分析PC-BVF在40样本中的贡献."""
import json, sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

with open("eval/results/heap_suite_results.json", "r", encoding="utf-8") as f:
    data = json.load(f)

results = data["results"]
metrics = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
pcbvf_triggered = []

for s in results:
    r = s["verdict"]
    e = s["expected_vuln"]
    if r == "VULN" and e:
        metrics["TP"] += 1
    elif r == "VULN" and not e:
        metrics["FP"] += 1
    elif r == "SAFE" and not e:
        metrics["TN"] += 1
    else:
        metrics["FN"] += 1

    sf = s.get("source_findings", [])
    for f in sf:
        reason = f.get("reason", "").lower()
        if "pc-bvf" in reason or "pcbvf" in reason or "path constraint" in reason:
            pcbvf_triggered.append((s["sample"], f.get("reason", "")[:120]))

print("BinMind (含PC-BVF) 40样本结果:")
print(f"  TP={metrics['TP']} FP={metrics['FP']} TN={metrics['TN']} FN={metrics['FN']}")
tp = metrics["TP"]; fp = metrics["FP"]; tn = metrics["TN"]; fn = metrics["FN"]
prec = tp / (tp + fp) if (tp + fp) > 0 else 0
rec = tp / (tp + fn) if (tp + fn) > 0 else 0
f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
print(f"  Precision={prec:.4f} Recall={rec:.4f} F1={f1:.4f} FPR={fpr:.4f}")
print()
print(f"PC-BVF triggered on {len(pcbvf_triggered)} findings:")
for name, reason in pcbvf_triggered:
    print(f"  {name}: {reason}")
