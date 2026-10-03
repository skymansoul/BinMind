# core/heap_batch_analyzer.py - 批量堆分析便利函数

from typing import Any, Dict, List, Tuple

from .unified_heap_pipeline import analyze_heap_safety

__all__ = ['analyze_batch']


def analyze_batch(
    code_map: Dict[str, str],
    binary_path: str = "",
) -> Tuple[List[dict], Dict[str, Any]]:
    """批量分析多函数反编译代码。

    code_map: {func_name: decompiled_code}
    """
    all_findings: List[dict] = []
    aggregate_stats: Dict[str, Any] = {
        "functions_analyzed": len(code_map),
        "total_findings": 0,
        "total_confirmed": 0,
        "total_filtered": 0,
        "total_possible": 0,
    }

    for func_name, code in code_map.items():
        findings, stats = analyze_heap_safety(
            code, func_name, binary_path)
        all_findings.extend(findings)
        aggregate_stats["total_findings"] += len(findings)
        aggregate_stats["total_confirmed"] += stats["confirmed"]
        aggregate_stats["total_filtered"] += stats["filtered"]
        aggregate_stats["total_possible"] += stats["possible"]

    return all_findings, aggregate_stats
