#!/usr/bin/env python
# coding: utf-8
# tests/heap_fp_regression/result_collector.py — 结果收集与对比模块
# 读取 scan_scheduler 的原始 JSON, 对照 ground truth 计算:
#   TP / FP / FN / TN, 检出率(召回), 误报率, F1, 平均耗时, 平均候选对数
# 输出: results/metrics.csv (逐样本) + results/summary.json + 摘要表。
# 判定: 样本级检出 = 该工具在样本上产出 ≥1 个达到阈值置信度的发现。
#   label=tp 且检出 → TP;  label=tp 未检出 → FN
#   label=tn 且检出 → FP;  label=tn 未检出 → TN
# 用法: python result_collector.py [--raw 原始JSON] [--out 输出CSV]

import csv
import json
import sys
from pathlib import Path

_RAW_DEFAULT = Path(__file__).parent / "results" / "raw_scan.json"
_OUT_DIR = Path(__file__).parent / "results"


def load_raw(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build_matrix(raw: dict) -> dict:
    """{tool: {sample: {label, expect, detected, elapsed, pairs}}}"""
    matrix = {}
    for sid, s in raw.get("samples", {}).items():
        label = s.get("label", "unknown")
        expect = s.get("expect_overflow", False)
        for tool, res in s.get("tools", {}).items():
            detected = bool(res.get("detected"))
            matrix.setdefault(tool, {})[sid] = {
                "label": label, "expect": expect, "detected": detected,
                "elapsed_ms": res.get("elapsed_ms", 0),
                "pairs": res.get("pairs", 0),
                "fp_reduction": res.get("fp_reduction_pct", 0.0),
            }
    return matrix


def summarize(matrix: dict) -> list:
    rows = []
    for tool, per_sample in sorted(matrix.items()):
        tp = fp = fn = tn = 0
        time_total = pairs_total = fp_red_total = 0.0
        for sid, m in per_sample.items():
            time_total += m["elapsed_ms"]
            pairs_total += m["pairs"]
            fp_red_total += m["fp_reduction"]
            if m["expect"]:
                if m["detected"]:
                    tp += 1
                else:
                    fn += 1
            else:
                if m["detected"]:
                    fp += 1
                else:
                    tn += 1
        n = tp + fn
        p = tp + fp
        recall = tp / n if n else 0.0
        precision = tp / p if p else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) else 0.0)
        rows.append({
            "tool": tool,
            "samples": len(per_sample), "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "recall_pct": round(recall * 100, 1),
            "fpr_pct": round(fpr * 100, 1),
            "precision_pct": round(precision * 100, 1),
            "f1_pct": round(f1 * 100, 1),
            "avg_time_ms": round(time_total / max(len(per_sample), 1), 1),
            "avg_pairs": round(pairs_total / max(len(per_sample), 1), 1),
            "avg_fp_reduction_pct": round(fp_red_total / max(len(per_sample), 1), 1),
        })
    return rows


def write_per_sample_csv(matrix: dict, path: Path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tool", "sample_id", "label", "expect_overflow",
                    "detected", "elapsed_ms", "candidate_pairs"])
        for tool, per_sample in sorted(matrix.items()):
            for sid in sorted(per_sample):
                m = per_sample[sid]
                w.writerow([tool, sid, m["label"], m["expect"], m["detected"],
                            m["elapsed_ms"], m["pairs"]])


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", default=str(_RAW_DEFAULT))
    parser.add_argument("--outdir", default=str(_OUT_DIR))
    args = parser.parse_args()

    raw = load_raw(Path(args.raw))
    matrix = build_matrix(raw)
    summary = summarize(matrix)
    out_dir = Path(args.outdir)
    out_dir.mkdir(parents=True, exist_ok=True)

    write_per_sample_csv(matrix, out_dir / "metrics.csv")
    with open(out_dir / "summary.json", "w", encoding="utf-8") as f:
        json.dump({"threshold": raw.get("threshold", 0.25), "tools": summary},
                  f, indent=2, ensure_ascii=False)

    print(f"\n{'Tool':<14} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3} "
          f"{'Recall%':>8} {'FPR%':>6} {'Prec%':>6} {'F1%':>6} {'ms':>7} "
          f"{'pairs':>6} {'FPRed%':>7}")
    print("-" * 82)
    for r in summary:
        print(f"{r['tool']:<14} {r['TP']:>3} {r['FP']:>3} {r['FN']:>3} "
              f"{r['TN']:>3} {r['recall_pct']:>7.1f}% {r['fpr_pct']:>5.1f}% "
              f"{r['precision_pct']:>5.1f}% {r['f1_pct']:>5.1f}% "
              f"{r['avg_time_ms']:>6.1f} {r['avg_pairs']:>6.1f} "
              f"{r['avg_fp_reduction_pct']:>6.1f}%")
    print(f"\nper-sample CSV: {out_dir / 'metrics.csv'}")
    print(f"summary JSON:   {out_dir / 'summary.json'}")


if __name__ == "__main__":
    main()
