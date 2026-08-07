"""
SFOD消融实验 — 量化结构体字段偏移域对CJ管线自主率的提升.

对比方式:
  对60样本运行源级验证器(含SFOD), 统计:
  1. SFOD注入次数: struct field约束被成功注入的样本数
  2. SFOD决定性样本: SFOD注入约束改变了判定结果的样本数
  3. 全量P/R/F1/FPR

实现: 通过monkey-patch临时禁用SFOD, 对比有/无SFOD的判定差异.
"""
from __future__ import annotations
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_DEEMO_ROOT = Path(__file__).resolve().parent.parent  # deemo/
if str(_DEEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(_DEEMO_ROOT))

SAMPLE_DIR = _DEEMO_ROOT / "tests" / "cve_samples" / "heap_overflow"
GROUND_TRUTH_PATH = SAMPLE_DIR / "ground_truth.json"
RESULTS_DIR = _DEEMO_ROOT / "eval" / "results"


def load_ground_truth() -> Dict:
    with open(GROUND_TRUTH_PATH, encoding='utf-8') as f:
        return json.load(f)


def run_src_verifier(source: str) -> List[Dict]:
    """运行HOSV源级检测, 返回findings列表."""
    from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier
    v = HeapOverflowSrcVerifier()
    results = v.verify(source)
    return [{
        "verdict": r.verdict.value,
        "alloc_line": r.alloc_line,
        "write_line": r.write_line,
        "alloc_size": r.alloc_size,
        "write_size": r.write_size,
        "confidence": r.confidence,
        "reason": r.reason,
    } for r in results]


def _compute_metrics(tp, fp, tn, fn):
    p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {"precision": p, "recall": r, "f1": f1, "fpr": fpr}


def run_ablation():
    gt = load_ground_truth()
    samples_info = gt["samples"]

    # 配置A: 无SFOD(禁用inject_sfod_constraints)
    # 配置B: 有SFOD(当前默认)
    configs = {"without_sfod": {}, "with_sfod": {}}

    sample_dirs = sorted([
        d for d in os.listdir(str(SAMPLE_DIR))
        if os.path.isdir(os.path.join(str(SAMPLE_DIR), d))
        and d.startswith("cve_")
    ])

    print("=" * 60)
    print(" SFOD Ablation Experiment (60 samples)")
    print("=" * 60)

    for config_name in ("without_sfod", "with_sfod"):
        enable_sfod = config_name == "with_sfod"

        # 如果禁用SFOD, monkey-patch inject_sfod_constraints为空操作
        if not enable_sfod:
            import core.cj_struct_field as sfod_mod
            _original = sfod_mod.inject_sfod_constraints
            sfod_mod.inject_sfod_constraints = lambda *a, **kw: False
            # 也需要patch collector中的引用
            import core.cj_constraint_collector as coll_mod
            # collector通过from...import引用, 需要重新patch
            # 因为collector在函数内部import, 每次调用都会获取最新版本
            # 所以只需patch模块级别函数即可

        tp, fp, tn, fn = 0, 0, 0, 0
        per_sample = {}

        for sample_name in sample_dirs:
            if sample_name not in samples_info:
                continue

            sample_dir = os.path.join(str(SAMPLE_DIR), sample_name)
            c_files = [f for f in os.listdir(sample_dir) if f.endswith(".c")]
            if not c_files:
                continue

            c_path = os.path.join(sample_dir, c_files[0])
            with open(c_path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()

            expected_vuln = samples_info[sample_name]["expected_vuln"]

            findings = run_src_verifier(source)
            vuln_count = sum(1 for f in findings if f["verdict"] == "VULN")
            detected = vuln_count > 0

            if expected_vuln:
                if detected:
                    tp += 1
                else:
                    fn += 1
            else:
                if detected:
                    fp += 1
                else:
                    tn += 1

            per_sample[sample_name] = {
                "expected_vuln": expected_vuln,
                "detected": detected,
                "vuln_count": vuln_count,
            }

        metrics = _compute_metrics(tp, fp, tn, fn)
        configs[config_name] = {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            **metrics,
            "per_sample": per_sample,
        }

        total = tp + fp + tn + fn
        print(f"\n[{config_name}] Samples={total}")
        print(f"  TP={tp} FP={fp} TN={tn} FN={fn}")
        print(f"  P={metrics['precision']:.4f} R={metrics['recall']:.4f} "
              f"F1={metrics['f1']:.4f} FPR={metrics['fpr']:.4f}")

        # 恢复原始函数
        if not enable_sfod:
            sfod_mod.inject_sfod_constraints = _original

    # 找出SFOD决定性差异的样本
    sfod_decisive = []
    for name in configs["with_sfod"]["per_sample"]:
        a = configs["without_sfod"]["per_sample"].get(name, {})
        b = configs["with_sfod"]["per_sample"].get(name, {})
        if a.get("detected") != b.get("detected"):
            sfod_decisive.append(name)

    print("\n" + "=" * 60)
    print(f" SFOD Decisive Samples: {len(sfod_decisive)}")
    for name in sfod_decisive:
        a = configs["without_sfod"]["per_sample"][name]["detected"]
        b = configs["with_sfod"]["per_sample"][name]["detected"]
        expected = configs["with_sfod"]["per_sample"][name]["expected_vuln"]
        print(f"  {name}: no_sfod={'VULN' if a else 'SAFE'} → "
              f"with_sfod={'VULN' if b else 'SAFE'} "
              f"(expected={'VULN' if expected else 'SAFE'})")

    # 保存结果
    out = {
        "without_sfod": {
            "tp": configs["without_sfod"]["tp"],
            "fp": configs["without_sfod"]["fp"],
            "tn": configs["without_sfod"]["tn"],
            "fn": configs["without_sfod"]["fn"],
            "precision": configs["without_sfod"]["precision"],
            "recall": configs["without_sfod"]["recall"],
            "f1": configs["without_sfod"]["f1"],
            "fpr": configs["without_sfod"]["fpr"],
        },
        "with_sfod": {
            "tp": configs["with_sfod"]["tp"],
            "fp": configs["with_sfod"]["fp"],
            "tn": configs["with_sfod"]["tn"],
            "fn": configs["with_sfod"]["fn"],
            "precision": configs["with_sfod"]["precision"],
            "recall": configs["with_sfod"]["recall"],
            "f1": configs["with_sfod"]["f1"],
            "fpr": configs["with_sfod"]["fpr"],
        },
        "sfod_decisive_samples": sfod_decisive,
    }

    out_path = RESULTS_DIR / "sfod_ablation.json"
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(str(out_path), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"\nResults saved to: {out_path}")


if __name__ == "__main__":
    run_ablation()
