"""
SGAV benchmark — 30样本评估 + 消融实验.
"""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis.sgav_pipeline import SGAVVerifier

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "tests" / "cve_samples" / "stack_overflow_sgav"
GT_PATH = SAMPLE_DIR / "ground_truth.json"

CONFIGS = [
    ("A0_pattern", "仅正则模式匹配"),
    ("A1_alias",   "+别名解析"),
    ("A2_guard",   "+守卫约束"),
    ("A3_range",   "+值范围传播"),
    ("A4_bounded", "+有界API分析"),
    ("full",       "完整SGAV"),
]


def run_benchmark(verifier: SGAVVerifier, config: str = "full") -> dict:
    with open(GT_PATH) as f:
        gt = json.load(f)
    results = []
    tp = fp = tn = fn = 0
    for entry in gt["samples"]:
        name = entry["sample"]
        label = entry["label"]
        vuln_path = SAMPLE_DIR / name / "vuln.c"
        if not vuln_path.exists():
            results.append({"sample": name, "gt": label, "found": False, "error": "no vuln.c"})
            continue
        code = vuln_path.read_text(encoding="utf-8")
        if config == "full":
            detections = verifier.verify(code)
        else:
            detections = verifier.verify_ablated(code, config=config)
        # 判定: 有 VULN verdict 的结果 = found
        vuln_results = [d for d in detections if d.verdict.value == "VULN"]
        found = len(vuln_results) > 0
        # 统计
        if label == "VULN" and found:
            tp += 1
        elif label == "VULN" and not found:
            fn += 1
        elif label == "SAFE" and found:
            fp += 1
        else:
            tn += 1
        results.append({
            "sample": name,
            "gt": label,
            "found": found,
            "num_detections": len(vuln_results),
            "detections": [
                {"line": d.write_line, "buf": d.buf_name,
                 "reason": d.reason, "guard": d.guard_info}
                for d in vuln_results
            ],
        })
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "config": config,
        "total": len(results),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "results": results,
    }


def main():
    verifier = SGAVVerifier()
    all_results = {}
    for config, desc in CONFIGS:
        print(f"\n{'='*60}")
        print(f"Config: {config} ({desc})")
        r = run_benchmark(verifier, config)
        all_results[config] = r
        print(f"  TP={r['tp']} FP={r['fp']} TN={r['tn']} FN={r['fn']}")
        print(f"  P={r['precision']} R={r['recall']} F1={r['f1']} FPR={r['fpr']}")
        # 打印失败样本
        for s in r["results"]:
            if s["gt"] == "VULN" and not s["found"]:
                print(f"  FN: {s['sample']}")
            elif s["gt"] == "SAFE" and s["found"]:
                print(f"  FP: {s['sample']} (detections: {s.get('detections', [])})")
    # 保存完整结果
    out_path = Path(__file__).resolve().parent / "results" / "sgav_benchmark_results.json"
    out_path.parent.mkdir(exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"\nResults saved to: {out_path}")
    # 打印汇总表
    print(f"\n{'='*60}")
    print("Summary:")
    print(f"{'Config':<16} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3} {'P':>6} {'R':>6} {'F1':>6} {'FPR':>6}")
    for config, _ in CONFIGS:
        r = all_results[config]
        print(f"{config:<16} {r['tp']:>3} {r['fp']:>3} {r['tn']:>3} {r['fn']:>3} "
              f"{r['precision']:>6} {r['recall']:>6} {r['f1']:>6} {r['fpr']:>6}")


if __name__ == "__main__":
    main()
