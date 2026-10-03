from __future__ import annotations
from typing import Any


def cross_validate(results_a: dict, results_b: dict) -> dict:
    """比较两组检测结果的一致性, 返回一致率与冲突项列表"""
    vulns_a = set(_extract_vuln_keys(results_a))
    vulns_b = set(_extract_vuln_keys(results_b))
    conflicts = []
    only_a = vulns_a - vulns_b
    only_b = vulns_b - vulns_a
    for v in sorted(only_a):
        conflicts.append({"key": v, "source": "a_only"})
    for v in sorted(only_b):
        conflicts.append({"key": v, "source": "b_only"})
    union = vulns_a | vulns_b
    agreement = len(vulns_a & vulns_b) / len(union) if union else 1.0
    return {"agreement": round(agreement, 4), "conflicts": conflicts}


def _extract_vuln_keys(results: dict) -> list[str]:
    """从结果字典提取漏洞标识键 (支持 'vulns' 列表或顶层 dict)"""
    raw = results.get("vulns", results)
    if isinstance(raw, list):
        keys = []
        for item in raw:
            if isinstance(item, dict):
                keys.append(str(item.get("id", item.get("addr", ""))))
            else:
                keys.append(str(item))
        return keys
    if isinstance(raw, dict):
        return list(raw.keys())
    return []
