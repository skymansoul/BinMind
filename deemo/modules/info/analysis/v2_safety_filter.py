# analysis/v2_safety_filter — PSVR-HLM v2 的 P4 安全性见证过滤
# 基于二进制导入表的安全变体与 FORTIFY 证据, 对发现做置信度压制。
# 仅在存在 checksec/imports 证据时生效, 无证据时原样返回。
# 与 FC-VRA 的关系: v2 的 P4 与 FC-VRA 的 C1-C4 相互独立,
# 本模块只服务 v2 管线自身。

from __future__ import annotations
from typing import Dict, List

_SAFE = {"snprintf", "memcpy_s", "strcpy_s", "strncpy", "strncat",
         "__memcpy_chk", "__sprintf_chk", "__fread_chk", "__recv_chk"}


def _n(fname: str) -> str:
    return fname.lower().rstrip("aw")


def safety_filter(findings: List[Dict], checksec: Dict,
                  imports: Dict) -> List[Dict]:
    """P4 安全性见证过滤: 基于导入表的安全变体与 FORTIFY 证据做置信度压制。"""
    api_set = set()
    all_imps = imports.get("all_imports", imports) if isinstance(imports, dict) else {}
    if isinstance(all_imps, dict):
        for funcs in all_imps.values():
            if isinstance(funcs, list):
                api_set.update(_n(f) for f in funcs)
    has_safe = bool(api_set & _SAFE)
    has_fort = checksec.get("fortify") or checksec.get("fortify_source") or \
               any("_chk" in f for f in api_set)
    for f in findings:
        if has_safe:
            f["confidence"] = round(max(0.05, f["confidence"] - 0.25), 2)
        if has_fort:
            f["confidence"] = round(max(0.05, f["confidence"] - 0.15), 2)
    return [f for f in findings if f["confidence"] >= 0.10]
