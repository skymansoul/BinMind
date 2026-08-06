# analysis/heap_false_positive_filter — 堆溢出误报压制过滤器
# 集成污点传播 (taint_propagation) + 约束简化 (constraint_simplifier)
# + 安全性见证 (safety_witness_searcher) 的三重过滤,
# 在保留召回的同时大幅压低误报。
#
# 过滤管线:
#   输入: 原始检测发现列表 (来自 heap_overflow_detector 或 tiered_vuln_detector)
#   F1: 约束检查 — alloc_size 与 copy_size 关系 → 筛掉 ALLOC_GT_COPY
#   F2: 污点确认 — 无 source→sink 污染路径的发现置信度打 6 折
#   F3: 安全见证 — FORTIFY/chk/安全变体存在 → 置信度压制
#   输出: 过滤后的发现列表 + per-filter 统计 (消融实验数据)

from typing import Dict, List, Tuple, Optional

# 路径设置: 确保能访问同级 analysis/ 和 info_collection/src/
import sys, os
_CUR = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_CUR), "info_collection", "src")
for _p in (_CUR, _SRC):
    if _p not in sys.path: sys.path.insert(0, _p)

from taint_propagation import propagate_taint
from constraint_simplifier import classify_constraint, ConstraintType, compute_overflow_score
from safety_witness_searcher import run_full_witness_search
from _shared import extract_api_set


def filter_findings(
    raw_findings: List[Dict],
    imports: Dict,
    strings: List[str] = None,
    checksec: Dict = None,
) -> Dict:
    """三重误报过滤主入口。
    返回 filtered_findings + 逐层统计数据 (供消融实验)。
    """
    # 预处理
    taint = propagate_taint(imports)
    api_set = set()
    all_imps = imports.get("all_imports", imports) if isinstance(imports, dict) else {}
    if isinstance(all_imps, dict):
        for funcs in all_imps.values():
            if isinstance(funcs, list):
                api_set.update(f.lower().rstrip('aw') for f in funcs)
    safety = run_full_witness_search(api_set, imports, checksec or {}, strings or [])

    # 统计计数器
    stats = {"input": len(raw_findings), "after_f1": 0, "after_f2": 0, "after_f3": 0}

    # F1: 约束检查
    after_f1 = []
    for f in raw_findings:
        alloc_func = f.get("alloc_func", "malloc")
        write_func = f.get("write_func", "memcpy")
        constraint = classify_constraint(alloc_func, write_func, strings or [], imports)
        f["constraint"] = constraint.name

        if constraint == ConstraintType.ALLOC_GT_COPY:
            f["filtered_by"] = "F1_constraint_ALLOC_GT_COPY"
            f["confidence"] = round(f["confidence"] * 0.15, 2)
            if f["confidence"] > 0.05:
                after_f1.append(f)
        else:
            after_f1.append(f)
    stats["after_f1"] = len(after_f1)

    # F2: 污点确认
    after_f2 = []
    taint_paths = {p["sink"]: p for p in taint.get("taint_paths", [])}
    for f in after_f1:
        sink = f.get("write_func", f.get("function", ""))
        tp = taint_paths.get(sink)
        if tp:
            f["taint_confidence"] = tp["taint_confidence"]
            if tp["taint_confidence"] < 0.30:
                f["filtered_by"] = "F2_weak_taint"
                f["confidence"] = round(f["confidence"] * 0.55, 2)
        else:
            f["filtered_by"] = "F2_no_taint_path"
            f["confidence"] = round(f["confidence"] * 0.50, 2)
        if f["confidence"] >= 0.10:
            after_f2.append(f)
    stats["after_f2"] = len(after_f2)

    # F3: 安全见证
    after_f3 = []
    safety_score = safety.get("aggregate_safety_score", 0.0)
    safe_alts = safety.get("safe_alternatives", {})
    compiler = safety.get("compiler_mitigations", {})
    for f in after_f2:
        if safety_score > 0.50:
            f["filtered_by"] = "F3_high_safety_score"
            f["confidence"] = round(f["confidence"] * 0.35, 2)
        if safe_alts.get(f.get("write_func", "")):
            f["confidence"] = round(f["confidence"] * 0.50, 2)
        if compiler.get("has_fortify"):
            f["confidence"] = round(f["confidence"] * 0.60, 2)
        if f["confidence"] >= 0.10:
            after_f3.append(f)
    stats["after_f3"] = len(after_f3)

    after_f3.sort(key=lambda x: x["confidence"], reverse=True)

    fp_reduction = (1.0 - stats["after_f3"] / max(stats["input"], 1)) * 100 if stats["input"] > 0 else 0.0

    return {
        "filtered_findings": after_f3,
        "filters_applied": ["F1_constraint", "F2_taint", "F3_safety_witness"],
        "stats": stats,
        "fp_reduction_pct": round(fp_reduction, 1),
        "ablation_data": {
            "no_filter": stats["input"],
            "after_constraint_only": stats["after_f1"],
            "after_constraint_plus_taint": stats["after_f2"],
            "after_all_three": stats["after_f3"],
        },
    }
