"""
UAF 跨函数CFG便捷函数 — build_interproc_cfg 和 enhance_tarps_with_interproc.
"""


from typing import Tuple

from analysis.uaf_interproc_cfg import InterProcCFGBuilder
from analysis.uaf_interproc_types import CallGraph


def build_interproc_cfg(source_code: str) -> CallGraph:
    """便捷函数: 从源码构建跨函数调用图."""
    builder = InterProcCFGBuilder()
    return builder.build(source_code)


def enhance_tarps_with_interproc(
    source_code: str,
    alloc_site: int, free_site: int, use_site: int,
) -> Tuple[bool, str]:
    """TARPS 前置增强: 跨函数可达性预筛选.

    在 TARPS 五阶段之前调用本函数:
      - 若跨函数不可达 → 直接判定 SAFE, 跳过 TARPS
      - 若可达 → 继续 TARPS 五阶段分析

    返回 (should_skip_tarps, reason), True 表示确认安全跳过 TARPS。
    """
    builder = InterProcCFGBuilder()
    cg = builder.build(source_code)

    if len(cg.nodes) <= 1:
        return False, "single function — no inter-proc analysis needed"

    lines = source_code.splitlines()
    func_for_site = {}
    for fname, node in cg.nodes.items():
        for line_no in [alloc_site, free_site, use_site]:
            if node.start_line <= line_no <= node.end_line:
                func_for_site[line_no] = fname

    alloc_func = func_for_site.get(alloc_site, "unknown")
    free_func = func_for_site.get(free_site, "unknown")
    use_func = func_for_site.get(use_site, "unknown")

    if alloc_func == free_func == use_func == "unknown":
        return False, "could not locate sites in any function"

    is_reachable, reason = builder.is_cross_func_uaf_reachable(
        alloc_func, free_func, use_func)

    if not is_reachable:
        return True, f"INTERPROC_SAFE: {reason}"
    else:
        return False, f"INTERPROC_REACHABLE: {reason}"


def batch_verify_uaf(candidates: list,
                     insns: list,
                     ir_text: str = "") -> list:
    from analysis.uaf_tarps_verifier import UafTarpsVerifier
    verifier = UafTarpsVerifier()
    results = []
    for alloc_s, free_s, use_s in candidates:
        r = verifier.verify(alloc_s, free_s, use_s, insns, ir_text)
        results.append(r)
    return results
