#!/usr/bin/env python3
"""
循环不变式分层证明消融实验 — 隔离循环不变式分层证明在后向值流-INCONCLUSIVE场景的不可替代贡献.

四组配置:
  A. Baseline: 纯pattern检测器, 无约束求解/后向值流/循环不变式分层证明过滤
  B. 约束求解+后向值流(no 循环不变式分层证明/路径条件后向值流/跨上下文分配-写溯源): 后向值流无法判定时保留INCONCLUSIVE
  C. 约束求解+后向值流+循环不变式分层证明(no 路径条件后向值流/跨上下文分配-写溯源): 循环不变式分层证明接管后向值流-INCONCLUSIVE的精确化判定
  D. Full Pipeline: 约束求解+后向值流+循环不变式分层证明+路径条件后向值流+跨上下文分配-写溯源 (完整管线)

循环不变式分层证明的不可替代性验证: 某些样本后向值流返回INCONCLUSIVE,
仅循环不变式分层证明能通过路径谓词/分配器对齐判定安全/溢出.

输出: eval/results/ablation_lsp.json + ablation_lsp.csv + 图表
"""
import json, os, sys, time, csv
from pathlib import Path
from typing import Dict, List, Tuple

_BASE = Path(__file__).resolve().parent.parent
if str(_BASE) not in sys.path:
    sys.path.insert(0, str(_BASE))

try:
    from analysis.uaf_obj_graph_cross_func import HoigCrossFuncVerifier  # noqa
    import analysis.uaf_obj_graph_propagator as _uaf_prop
    if not hasattr(_uaf_prop, 'HoigCrossFuncVerifier'):
        _uaf_prop.HoigCrossFuncVerifier = HoigCrossFuncVerifier
except Exception:
    pass

LSP_SAMPLES_DIR = _BASE / "tests" / "lsp_samples"
RESULTS_DIR = _BASE / "eval" / "results"

from tests.loop_invariant_ground_truth import LSP_EXPECTED
from eval.ablation_loop_invariant_helpers import (
    evaluate_candidates as _evaluate_candidates,
    run_baseline as _run_baseline,
    run_cj_bvf_no_lsp as _run_cj_bvf_no_lsp,
    run_cj_bvf_lsp as _run_cj_bvf_lsp,
    run_full_pipeline as _run_full_pipeline,
    generate_chart,
)



def run_lsp_ablation() -> Tuple[List[Dict], Dict]:
    """在循环不变式分层证明样本集上运行四组消融对比."""
    results = []
    configs = ["Baseline", "CJ+BVF", "CJ+BVF+LSP", "Full"]

    from tests.value_flow_candidate_extractor import extract_candidates_from_code

    for sample_dir in sorted(LSP_SAMPLES_DIR.iterdir()):
        if not sample_dir.is_dir():
            continue
        vuln_c = sample_dir / 'vuln.c'
        if not vuln_c.exists():
            continue
        name = sample_dir.name
        expected = LSP_EXPECTED.get(name)
        if expected is None:
            continue

        code = vuln_c.read_text(encoding='utf-8', errors='replace')
        candidates, ir_lines = extract_candidates_from_code(code)

        base_det = _run_baseline(code, ir_lines)
        bvf_det, bvf_v = _run_cj_bvf_no_lsp(candidates, ir_lines, code)
        lsp_det, lsp_v = _run_cj_bvf_lsp(candidates, ir_lines, code)
        full_det, full_v = _run_full_pipeline(candidates, ir_lines, code)

        row = {
            "sample": name,
            "expected_vuln": expected,
            "n_candidates": len(candidates),
            "Baseline": base_det,
            "CJ+BVF": bvf_det,
            "CJ+BVF+LSP": lsp_det,
            "Full": full_det,
            "bvf_reason": bvf_v,
            "lsp_reason": lsp_v,
            "full_reason": full_v,
        }
        for cfg in configs:
            cnt = row[cfg]
            detected = cnt > 0
            if expected:
                row[f"{cfg}_verdict"] = "VULN" if detected else "MISS"
            elif expected is False:
                row[f"{cfg}_verdict"] = "FP" if detected else "SAFE"
            else:
                row[f"{cfg}_verdict"] = "INCONCLUSIVE"
        results.append(row)

        print(f"  {name}: B={row['Baseline_verdict']} "
              f"BVF={row['CJ+BVF_verdict']} "
              f"LSP={row['CJ+BVF+LSP_verdict']} "
              f"Full={row['Full_verdict']}")

    metrics = _compute_metrics(results, configs)
    return results, metrics


def _compute_metrics(
    results: List[Dict], configs: List[str],
) -> Dict:
    """计算各配置的Precision/Recall/F1/FPR.

    INCONCLUSIVE样本(expected=None)不参与P/R/F1计算.
    """
    metrics = {}
    for cfg in configs:
        tp = fp = tn = fn = 0
        for r in results:
            exp = r["expected_vuln"]
            if exp is None:
                continue
            v = r[f"{cfg}_verdict"]
            if exp:
                if v == "VULN":
                    tp += 1
                else:
                    fn += 1
            else:
                if v == "FP":
                    fp += 1
                else:
                    tn += 1
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        metrics[cfg] = {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
        }
    return metrics


def print_ablation_table(
    results: List[Dict], metrics: Dict,
):
    """打印消融对比表格."""
    configs = ["Baseline", "CJ+BVF", "CJ+BVF+LSP", "Full"]
    print(f"\n{'='*90}")
    print(f" 循环不变式分层证明 Ablation Study: Baseline vs 约束求解+后向值流 vs 约束求解+后向值流+循环不变式分层证明 vs Full Pipeline")
    print(f"{'='*90}")
    n_eval = sum(1 for r in results if r["expected_vuln"] is not None)
    print(f" Samples: {len(results)} ({n_eval} evaluated, "
          f"{len(results)-n_eval} inconclusive-only)")

    print(f"\n{'Config':<16} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} "
          f"{'Prec':>8} {'Recall':>8} {'F1':>8} {'FPR':>8}")
    print("-" * 90)
    for cfg in configs:
        m = metrics[cfg]
        print(f"{cfg:<16} {m['tp']:>4} {m['fp']:>4} {m['tn']:>4} "
              f"{m['fn']:>4} {m['precision']:>8.4f} "
              f"{m['recall']:>8.4f} {m['f1']:>8.4f} "
              f"{m['fpr']:>8.4f}")

    diff = [r for r in results
            if r["CJ+BVF_verdict"] != r["CJ+BVF+LSP_verdict"]]
    if diff:
        print(f"\n 循环不变式分层证明 changes verdicts on {len(diff)} samples "
              f"vs 约束求解+后向值流 (no PC-BVF/CAAWP):")
        for r in diff:
            exp_str = ('VULN' if r['expected_vuln']
                       else 'SAFE' if r['expected_vuln'] is False
                       else 'INCONCLUSIVE')
            print(f"  {r['sample']}: "
                  f"CJ+BVF={r['CJ+BVF_verdict']} -> "
                  f"CJ+BVF+LSP={r['CJ+BVF+LSP_verdict']} "
                  f"(expect={exp_str})")
    else:
        print("\n 循环不变式分层证明 does not change any verdicts vs 约束求解+后向值流.")
    print(f"{'='*90}")


def save_results(results: List[Dict], metrics: Dict):
    """保存结果到CSV和JSON."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    csv_path = RESULTS_DIR / "ablation_lsp.csv"
    with open(csv_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["sample", "expected", "n_candidates",
                     "baseline_det", "cj_bvf_det", "cj_bvf_lsp_det",
                     "full_det",
                     "baseline_v", "cj_bvf_v", "cj_bvf_lsp_v",
                     "full_v",
                     "bvf_reason", "lsp_reason", "full_reason"])
        for r in results:
            w.writerow([r["sample"], r["expected_vuln"],
                        r["n_candidates"],
                        r["Baseline"], r["CJ+BVF"], r["CJ+BVF+LSP"],
                        r["Full"],
                        r["Baseline_verdict"], r["CJ+BVF_verdict"],
                        r["CJ+BVF+LSP_verdict"], r["Full_verdict"],
                        r.get("bvf_reason", ""),
                        r.get("lsp_reason", ""),
                        r.get("full_reason", "")])
    print(f" CSV: {csv_path}")

    json_path = RESULTS_DIR / "ablation_lsp.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump({"results": results, "metrics": metrics}, f, indent=2)
    print(f" JSON: {json_path}")



if __name__ == '__main__':
    print("[循环不变式分层证明 Ablation] Baseline vs 约束求解+后向值流 vs 约束求解+后向值流+循环不变式分层证明")
    print("[1/3] Running on 循环不变式分层证明 samples...")
    results, metrics = run_lsp_ablation()
    print_ablation_table(results, metrics)
    save_results(results, metrics)
    print("\n[2/3] Generating chart...")
    generate_chart(metrics)
    print("[3/3] Done.")
