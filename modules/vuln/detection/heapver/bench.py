# coding: utf-8
#
"""
语料基准运行器。

输入: 样本目录, 每个样本子目录含 main / main.exe / main.asm 之一;
      可选 expected.csv 列 `sample_id,expected` (TP/TN)。
输出: 每样本判定 + TP/TN/FP/FN + Precision/Recall/F1 + 误报削减统计。

判定规则: 存在 OVERFLOW 或 SUSPICIOUS finding → detected=True。
（SUSPICIOUS 计入检出以保障召回; SAFE 全部过滤 → TN 判定。）
"""

import csv
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .pipeline import GASRIPipeline, GASRIReport
from .cli import report_to_dict


def load_expected(samples_dir: str) -> Dict[str, str]:
    """读取 expected.csv, 返回 {sample_id: TP|TN}."""
    gt = {}
    f = Path(samples_dir) / "expected.csv"
    if not f.exists():
        return gt
    with open(f, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            sid = (row.get("sample_id") or "").strip()
            exp = (row.get("expected") or "").strip().upper()
            if sid and exp in ("TP", "TN"):
                gt[sid] = exp
    return gt


def find_binary(sample_dir: Path) -> Optional[Path]:
    for name in ("main", "main.exe"):
        p = sample_dir / name
        if p.exists():
            return p
    return None


def find_asm(sample_dir: Path) -> Optional[Path]:
    for name in ("main.asm", "vuln.asm"):
        p = sample_dir / name
        if p.exists():
            return p
    return None


def run_corpus_benchmark(pipe: GASRIPipeline, samples_dir: str) -> dict:
    root = Path(samples_dir)
    gt = load_expected(samples_dir)
    results = []
    tp = tn = fp = fn = 0
    safe_count = 0
    findings_count = 0
    pairs_count = 0

    dirs = sorted(d for d in root.iterdir()
                  if d.is_dir() and (find_binary(d) or find_asm(d)))
    for d in dirs:
        rep: GASRIReport
        binary = find_binary(d)
        if binary is not None:
            rep = pipe.analyze_binary(str(binary))
        else:
            asm = find_asm(d)
            text = asm.read_text(encoding="utf-8", errors="replace")
            rep = pipe.analyze(text, binary_path=str(asm))
        sid = d.name
        detected = rep.detected
        expected = gt.get(sid, "TP")

        if expected == "TP":
            if detected:
                verdict, tp = "TP", tp + 1
            else:
                verdict, fn = "FN", fn + 1
        else:
            if detected:
                verdict, fp = "FP", fp + 1
            else:
                verdict, tn = "TN", tn + 1

        safe_count += rep.n_safe
        findings_count += len(rep.findings)
        pairs_count += rep.n_pairs

        results.append({
            "sample_id": sid,
            "expected": expected,
            "verdict": verdict,
            "detected": detected,
            "n_pairs": rep.n_pairs,
            "n_safe": rep.n_safe,
            "n_overflow": rep.n_overflow,
            "n_suspicious": rep.n_suspicious,
            "n_findings": len(rep.findings),
            "fp_reduction_pct": rep.fp_reduction_pct,
            "elapsed_ms": rep.elapsed_ms,
            "report": report_to_dict(rep),
        })

    total = tp + tn + fp + fn
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.001, precision + recall)
    fpr = fp / max(1, fp + tn)

    return {
        "n_samples": total,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "total_pairs": pairs_count,
        "total_safe_filtered": safe_count,
        "total_findings": findings_count,
        "fp_reduction_pct": round(safe_count / max(1, pairs_count) * 100, 1),
        "results": results,
    }


__all__ = ["run_corpus_benchmark", "load_expected"]
