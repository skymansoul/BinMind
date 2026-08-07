"""SGAV regression on old SOSV 15 samples."""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analysis.sgav_pipeline import SGAVVerifier

OLD_DIR = Path(__file__).resolve().parent / "tests" / "cve_samples" / "stack_overflow"
OLD_GT = OLD_DIR / "ground_truth.json"
SOSV_RESULTS = Path(__file__).resolve().parent / "eval" / "sosv_benchmark_results.json"

v = SGAVVerifier()
with open(OLD_GT) as f:
    gt = json.load(f)

results = []
tp = fp = tn = fn = 0
for entry in gt["results"]:
    name = entry["sample"]
    label = entry["ground_truth"]
    vuln_path = OLD_DIR / name / "vuln.c"
    if not vuln_path.exists():
        results.append((name, label, False, "no file"))
        continue
    code = vuln_path.read_text(encoding="utf-8")
    detections = v.verify(code)
    vuln_results = [d for d in detections if d.verdict.value == "VULN"]
    found = len(vuln_results) > 0
    if label == "VULN" and found:
        tp += 1
    elif label == "VULN" and not found:
        fn += 1
    elif label == "SAFE" and found:
        fp += 1
    else:
        tn += 1
    results.append((name, label, found,
                    vuln_results[0].reason if vuln_results else "none"))

p = tp / (tp + fp) if (tp + fp) > 0 else 0
r = tp / (tp + fn) if (tp + fn) > 0 else 0
f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

print(f"Old SOSV 15-sample regression:")
print(f"  TP={tp} FP={fp} TN={tn} FN={fn}")
print(f"  P={p:.4f} R={r:.4f} F1={f1:.4f} FPR={fpr:.4f}")
for name, label, found, reason in results:
    status = "OK" if (found and label == "VULN") or (not found and label == "SAFE") else "FAIL"
    print(f"  [{status}] {name}: gt={label} found={found} ({reason[:60]})")
