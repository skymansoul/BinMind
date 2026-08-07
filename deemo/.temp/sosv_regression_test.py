"""
旧版SOSV 15样本回归测试 — 验证is_recursive/build_func_map修复后无退化.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis.stack_overflow_src_verifier import StackOverflowSrcVerifier

SAMPLE_BASE = Path(__file__).resolve().parent.parent / "tests" / "cve_samples"

# 15样本标签 (1=VULN, 0=SAFE)
LABELS = {
    "stack_overflow_01": "VULN", "stack_overflow_02": "VULN",
    "stack_overflow_03": "VULN", "stack_overflow_04": "VULN",
    "stack_overflow_05": "VULN", "stack_overflow_06": "VULN",
    "stack_overflow_07": "VULN", "stack_overflow_08": "VULN",
    "stack_overflow_09": "VULN", "stack_overflow_10": "VULN",
    "stack_overflow_11": "VULN", "stack_overflow_12": "VULN",
    "stack_overflow_13": "VULN", "stack_overflow_14": "VULN",
    "stack_overflow_15": "SAFE",
}


def main():
    verifier = StackOverflowSrcVerifier()
    tp = fp = tn = fn = 0
    for i in range(1, 16):
        name = f"stack_overflow_{i:02d}"
        path = SAMPLE_BASE / name / "vuln.c"
        if not path.exists():
            print(f"SKIP {name}: no vuln.c")
            continue
        code = path.read_text(encoding="utf-8", errors="replace")
        results = verifier.verify(code)
        found = len(results) > 0
        label = LABELS[name]
        if label == "VULN" and found:
            tp += 1
            status = "TP"
        elif label == "VULN" and not found:
            fn += 1
            status = "FN!!"
        elif label == "SAFE" and found:
            fp += 1
            status = "FP!!"
        else:
            tn += 1
            status = "TN"
        detail = "; ".join(r.reason for r in results) if results else "(none)"
        print(f"  {status:5s} {name}: {detail}")
    p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    print(f"\nTP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"P={p:.4f} R={r:.4f} F1={f1:.4f} FPR={fpr:.4f}")
    if f1 == 1.0 and fpr == 0.0:
        print("PASS: 15/15 F1=1.0 FPR=0.0")
    else:
        print("FAIL: regression detected!")


if __name__ == "__main__":
    main()
