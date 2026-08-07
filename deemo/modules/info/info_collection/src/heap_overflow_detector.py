# Created: 2026-07-17 10:30:00
#
# heap_overflow_detector — AC3 (Allocation-Copy Consistency Check)
# 堆溢出检测的核心创新: 不依赖完整污点分析或符号执行,
# 仅通过导入表中的分配-写配对 + size 参数来源分类 + 安全性见证检查,
# 在保留高召回的同时将误报率压低。
#
# 与现有方案的区别:
# BUDAlloc: 运行时检测, 需要实际执行
# EmTaint: 需要 VEX-IR 提升和全量别名分析
# LATTE: LLM 驱动, 需要大模型推理
# 本模块: 仅导入表+字符串+checksec, 零额外依赖, 三层过滤
#
# 三层过滤:
#   L1 (召回层): 分配-写配对识别 → 高召回, 低精度
#   L2 (精化层): size 参数来源分类 + 同 DLL 配对增强 → 中召回, 中精度
#   L3 (过滤层): 安全性见证减权 (FORTIFY/chk 函数/安全变体) → 低召回, 高精度

import math
from typing import Dict, List, Set, Tuple, Optional

from ._shared import extract_api_set as _extract_api_set
from .size_arg_classifier import classify_size_arg, SizeSource
from .allocation_tracker import track_allocation_pairs
from .safety_witness_searcher import (
    search_compiler_mitigations, search_safe_alternatives,
    search_input_validation,
)


def detect_heap_overflow(
    imports: Dict,
    strings: List[str] = None,
    checksec: Dict = None,
    min_confidence: float = 0.25,
) -> Dict:
    """AC3 堆溢出检测主入口。

    返回:
    - findings: 按置信度降序的检测结果列表
    - stats: {total, high_conf(≥0.7), medium_conf(0.35-0.7), low_conf(<0.35)}
    - false_positive_mitigations: 生效的误报压制措施及其效果
    """
    # L1: 分配-写配对识别
    tracker = track_allocation_pairs(imports, strings, checksec)

    if not tracker["pairs"]:
        return {"findings": [], "stats": {"total": 0, "high_conf": 0, "medium_conf": 0, "low_conf": 0},
                "method": "AC3-v1.0", "false_positive_mitigations": []}

    # L2: 精化 — 基于 size 参数来源调整置信度
    api_set = _extract_api_set(imports)
    findings = []

    for pair in tracker["pairs"]:
        base_conf = pair["overflow_risk"]

        # 若 alloc 和 write 同为 CONSTANT → 大幅压低
        if (pair["alloc_size_source"] == "CONSTANT" and
                pair["write_size_source"] == "CONSTANT"):
            base_conf = max(0.05, base_conf - 0.45)

        # 若 alloc 是 calloc (初始化内存) → 轻微压低
        if "calloc" in pair["alloc_func"]:
            base_conf = max(0.05, base_conf - 0.05)

        if base_conf >= min_confidence:
            findings.append({
                "vuln_type": "heap_overflow",
                "alloc_func": pair["alloc_func"],
                "write_func": pair["write_func"],
                "alloc_size_source": pair["alloc_size_source"],
                "write_size_source": pair["write_size_source"],
                "confidence": round(base_conf, 2),
                "reason": pair["reason"],
                "same_dll": pair["same_dll"],
            })

    # L3: 安全性见证过滤
    mitigations = []
    if checksec:
        compiler = search_compiler_mitigations(checksec, api_set)
        safe_alts = search_safe_alternatives(api_set)
        validation = search_input_validation(api_set)

        for f in findings:
            # Fortify + chk 函数 → 压制
            if compiler.get("has_fortify") and compiler.get("chk_function_count", 0) > 0:
                f["confidence"] = round(max(0.05, f["confidence"] - 0.30), 2)
                mitigations.append({"type": "fortify_chk_suppression",
                                    "effect": "confidence -= 0.30",
                                    "affected_functions": f"{f['alloc_func']}/{f['write_func']}"})

            # 安全变体共存 → 压制
            if safe_alts.get(f["write_func"]):
                f["confidence"] = round(max(0.05, f["confidence"] - 0.25), 2)
                mitigations.append({"type": "safe_alternative_suppression",
                                    "effect": "confidence -= 0.25",
                                    "function": f["write_func"]})

            # 输入验证函数存在 → 压制
            if validation.get("validation_count", 0) > 0:
                f["confidence"] = round(max(0.05, f["confidence"] - 0.10), 2)

        # 过滤掉被压制到阈值以下的发现
        findings = [f for f in findings if f["confidence"] >= min_confidence]
        findings.sort(key=lambda f: f["confidence"], reverse=True)

    # 统计
    hi = sum(1 for f in findings if f["confidence"] >= 0.70)
    med = sum(1 for f in findings if 0.35 <= f["confidence"] < 0.70)
    lo = sum(1 for f in findings if f["confidence"] < 0.35)

    return {
        "findings": findings,
        "stats": {"total": len(findings), "high_conf": hi,
                  "medium_conf": med, "low_conf": lo,
                  "avg_confidence": round(sum(f["confidence"] for f in findings) /
                                          max(len(findings), 1), 3)},
        "alloc_write_pairs_total": len(tracker["pairs"]),
        "method": "AC3-v1.0 (Allocation-Copy Consistency Check)",
        "false_positive_mitigations": mitigations,
    }
