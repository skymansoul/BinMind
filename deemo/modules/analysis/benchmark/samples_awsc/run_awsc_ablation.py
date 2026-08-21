# AWSC 消融实验 - 量化同源关联过滤对误报的抑制效果
#
# 对照: BinMind 堆检测器 (含 AWSC Stage10) vs 关闭 AWSC 的基础管线.
# 样本: benchmark/samples_awsc 的 vuln(应检出) 与 safe(应过滤) 配对.
# 指标: 每类样本检出数, 安全样本误报数, AWSC 单独过滤数.
#
# 决策: AWSC 是 finalize 的第10阶段, 关闭它即可获得"无同源过滤"基线,
# 无需改动既有逻辑, 保证消融对比同一管线骨架.

import json
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
# benchmark/samples_awsc/gen_awsc_samples.py 的层级: samples_awsc → benchmark → analysis
PROJECT_ROOT = SCRIPT_DIR.parents[2]
sys.path.insert(0, str(PROJECT_ROOT.parents[0]))  # analysis
sys.path.insert(0, str(PROJECT_ROOT.parents[1]))  # modules
sys.path.insert(0, str(PROJECT_ROOT.parents[2]))  # deemo

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

MANIFEST = SCRIPT_DIR / "awsc_manifest.json"
RESULTS_DIR = SCRIPT_DIR.parents[1] / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def run_detector(binary: str, enable_awsc: bool) -> int:
    """运行堆检测器, 返回 finalize 后存活 finding 数."""
    ins, fmt, main, ranges = disassemble_binary(binary)
    det = HeapOverflowDetector(AllocatorFamily.GLIBC,
                               use_win64_abi="pei" in fmt.lower())
    if main:
        det.set_min_user_addr(main)
    if ranges:
        det.set_user_func_ranges(ranges)
    det.pre_analyze(ins)
    for i in ins:
        det.analyze_instruction(i)

    if not enable_awsc:
        # 临时禁用 Stage10: 直接跳过 awsc_filter, 复现 Stage1-9 管线
        from modules.analysis.static.heap_constraint import Interval
        dedup = det._dedup_by_alloc(det._raw_findings)
        s4 = [f for f in dedup if det._stage4_path_sensitive_check(f)]
        s5 = [f for f in s4 if det._stage5_struct_field_check(f)]
        oct = det._octagon_filter.build_domain(ins)
        s35 = det._octagon_filter.filter(s5, oct)
        s123 = det._fp_filter.filter(s35, ins, det._alloc_tracker)
        expr_map = det._build_sym_expr_map(s123)
        s678 = det._ddssc_filter.filter(
            s123, ins, det._alloc_tracker, det._known_constants, expr_map)
        det._struct_size_tracker.set_instructions(ins)
        det._struct_size_tracker.reset()
        for i in ins:
            det._struct_size_tracker.process(i)
        corr = det._symbolic_correlator.correlate(
            det._struct_size_tracker, det._alloc_tracker)
        s9 = []
        for f in s678:
            reason = det._symbolic_correlator.filter_finding(f, corr)
            if reason:
                continue
            s9.append(f)
        return len(s9)

    findings = det.finalize(ins)
    return len(findings)


def main():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    compiled = [e for e in manifest if e.get("compiled")]
    rows = []

    print("=" * 64)
    print("AWSC Ablation: with-AWSC vs without-AWSC")
    print("=" * 64)

    for e in compiled:
        binary = e["binary"]
        is_vuln = e["is_vuln"]
        with_awsc = run_detector(binary, enable_awsc=True)
        without = run_detector(binary, enable_awsc=False)
        rows.append({
            "name": e["name"], "pattern": e["pattern"], "opt": e["opt"],
            "is_vuln": is_vuln,
            "findings_with_awsc": with_awsc,
            "findings_without_awsc": without,
            "awsc_filtered": max(0, without - with_awsc),
        })
        verdict = "TP" if (is_vuln and with_awsc > 0) else \
            ("TN" if (not is_vuln and with_awsc == 0) else
             ("FP!" if not is_vuln else "FN!"))
        print(f"  {e['name']:<28} with={with_awsc} without={without} "
              f"filtered={without-with_awsc} -> {verdict}")

    # 汇总
    vuln_tp = sum(1 for r in rows if r["is_vuln"] and r["findings_with_awsc"] > 0)
    vuln_total = sum(1 for r in rows if r["is_vuln"])
    safe_tp = sum(1 for r in rows if not r["is_vuln"] and r["findings_with_awsc"] == 0)
    safe_total = sum(1 for r in rows if not r["is_vuln"])
    awsc_filtered_total = sum(r["awsc_filtered"] for r in rows)
    # 无AWSC时的安全样本误报(非零finding即FP)
    fp_without = sum(1 for r in rows if not r["is_vuln"] and r["findings_without_awsc"] > 0)
    fp_with = sum(1 for r in rows if not r["is_vuln"] and r["findings_with_awsc"] > 0)

    summary = {
        "vuln_detected_with_awsc": vuln_tp, "vuln_total": vuln_total,
        "safe_clean_with_awsc": safe_tp, "safe_total": safe_total,
        "fp_without_awsc": fp_without, "fp_with_awsc": fp_with,
        "awsc_total_filtered": awsc_filtered_total,
        "recall_with_awsc": round(vuln_tp / max(vuln_total, 1), 4),
        "fpr_with_awsc": round(fp_with / max(safe_total, 1), 4),
        "fpr_without_awsc": round(fp_without / max(safe_total, 1), 4),
    }

    print("=" * 64)
    print(f"  vuln samples:      {vuln_tp}/{vuln_total} detected (recall "
          f"{summary['recall_with_awsc']:.1%})")
    print(f"  safe samples:      {safe_tp}/{safe_total} clean (FPR "
          f"{summary['fpr_with_awsc']:.1%})")
    print(f"  safe FPR baseline: {summary['fpr_without_awsc']:.1%} "
          f"(without AWSC)")
    print(f"  findings filtered by AWSC: {awsc_filtered_total}")
    print("=" * 64)

    out_path = RESULTS_DIR / "awsc_ablation.json"
    out_path.write_text(json.dumps({
        "summary": summary, "rows": rows,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, indent=2, ensure_ascii=False))
    print(f"results: {out_path}")


if __name__ == "__main__":
    main()
