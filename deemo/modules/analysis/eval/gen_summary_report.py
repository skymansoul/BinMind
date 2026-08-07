# 多创新点精度汇总报告
#
# 汇总三个深挖创新点的实测指标:
#   1. 堆溢出 (AWSC 同源关联) — 主打创新点
#   2. UAF 生命周期追踪
#   3. 格式化字符串
#
# 数据来源: eval/batch_test_heap.py, samples_uaf_safe/run_uaf_benchmark.py,
#           samples_fmt/run_fmt_benchmark.py, samples_awsc/run_awsc_ablation.py,
#           eval/run_benchmark.py 的 JSON 输出.
# 生成: results/innovation_summary.md (可交付报告)
# 创建: 2026-05-11

import json
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = SCRIPT_DIR / "results"
ANALYSIS_RESULTS = SCRIPT_DIR.parents[0] / "results"  # analysis/results


def load(p, alt_dir=None):
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    if alt_dir is not None:
        alt = alt_dir / p.name
        if alt.exists():
            return json.loads(alt.read_text(encoding="utf-8"))
    return None


def fmt_metric(name, tp, fp, tn, fn):
    recall = tp / max(tp + fn, 1)
    prec = tp / max(tp + fp, 1)
    fpr = fp / max(fp + tn, 1)
    return f"| {name} | {tp} | {fp} | {tn} | {fn} | " \
           f"{recall:.1%} | {prec:.1%} | {fpr:.1%} |"


def main():
    lines = []
    lines.append("# 创新点精度汇总报告")
    lines.append("")
    lines.append("> 实测数据, 由各基准脚本真实运行生成. "
                 "时间: " + __import__("time").strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("")

    # 1) 堆溢出 CVE 基准
    heap = load(RESULTS_DIR / "heap_benchmark_binmind.json")
    lines.append("## 1. 堆溢出 — 全量 CVE + FP 安全样本 (主打创新点)")
    lines.append("")
    lines.append("| 指标 | 值 |")
    lines.append("|------|-----|")
    if heap:
        m = heap.get("metrics", {})
        lines.append(f"| 样本数 | CVE {m.get('cve_samples')} + "
                     f"安全 {m.get('fp_safe_samples')} |")
        lines.append(f"| TP / FP / TN / FN | {m.get('tp')} / "
                     f"{m.get('fp')} / {m.get('tn')} / {m.get('fn')} |")
        lines.append(f"| Recall | {m.get('recall')*100:.1f}% |")
        lines.append(f"| Precision | {m.get('precision')*100:.1f}% |")
        lines.append(f"| FPR | {m.get('fpr')*100:.1f}% |")
    lines.append("")

    # 2) AWSC 消融
    awsc = load(RESULTS_DIR / "awsc_ablation.json", ANALYSIS_RESULTS)
    lines.append("### AWSC 消融实验 (同源样本误报抑制)")
    lines.append("")
    lines.append("| 配置 | 安全样本 FPR | 漏洞样本召回 | 过滤误报数 |")
    lines.append("|------|--------------|--------------|------------|")
    if awsc:
        s = awsc.get("summary", {})
        lines.append(f"| 无 AWSC (Stage1-9) | "
                     f"{s.get('fpr_without_awsc',0)*100:.1f}% | "
                     f"{s.get('recall_with_awsc',0)*100:.1f}% | - |")
        lines.append(f"| 有 AWSC (Stage1-10) | "
                     f"{s.get('fpr_with_awsc',0)*100:.1f}% | "
                     f"{s.get('recall_with_awsc',0)*100:.1f}% | "
                     f"{s.get('awsc_total_filtered',0)} |")
    lines.append("")

    # 3) 多工具对比
    comp = load(RESULTS_DIR / "multi_tool_comparison.json")
    lines.append("## 2. 多工具对比 (90 二进制: 45 漏洞 + 45 安全)")
    lines.append("")
    lines.append("| 工具 | TP | FP | TN | FN | Recall | Precision | FPR |")
    lines.append("|------|----|----|----|----|--------|-----------|-----|")
    if comp:
        for tool in ("BinMind", "Angr", "QEMU", "Ghidra"):
            s = comp.get("summary", {}).get(tool)
            if s:
                lines.append(fmt_metric(tool, s.get("tp", 0), s.get("fp", 0),
                                        s.get("tn", 0), s.get("fn", 0)))
    lines.append("")

    # 4) UAF
    uaf = load(RESULTS_DIR / "uaf_precision.json", ANALYSIS_RESULTS)
    lines.append("## 3. UAF 生命周期追踪 (30 vuln + 30 safe)")
    lines.append("")
    lines.append("| 指标 | 值 |")
    lines.append("|------|-----|")
    if uaf:
        s = uaf.get("summary", {})
        lines.append(f"| TP / FP / TN / FN | {s.get('tp')} / "
                     f"{s.get('fp')} / {s.get('tn')} / {s.get('fn')} |")
        lines.append(f"| Recall | {s.get('recall')*100:.1f}% |")
        lines.append(f"| Precision | {s.get('precision')*100:.1f}% |")
        lines.append(f"| FPR | {s.get('fpr')*100:.1f}% |")
    lines.append("")

    # 5) fmt
    fmt_ = load(RESULTS_DIR / "fmt_precision.json", ANALYSIS_RESULTS)
    lines.append("## 4. 格式化字符串 (25 vuln + 4 safe)")
    lines.append("")
    lines.append("| 指标 | 值 |")
    lines.append("|------|-----|")
    if fmt_:
        s = fmt_.get("summary", {})
        lines.append(f"| TP / FP / TN / FN | {s.get('tp')} / "
                     f"{s.get('fp')} / {s.get('tn')} / {s.get('fn')} |")
        lines.append(f"| Recall | {s.get('recall')*100:.1f}% |")
        lines.append(f"| Precision | {s.get('precision')*100:.1f}% |")
        lines.append(f"| FPR | {s.get('fpr')*100:.1f}% |")
    lines.append("")

    out = RESULTS_DIR / "innovation_summary.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"saved: {out}")
    return out


if __name__ == "__main__":
    main()
