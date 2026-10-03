"""
管线便捷函数 — 一键运行各漏洞类型的检测管线.

保持单一职责: 对外暴露简洁API.
"""


from typing import Any, List, Optional, Tuple

try:
    from .unified_pipeline import UnifiedPipeline, VulnType, PipelineReport
except ImportError:
    UnifiedPipeline = None  # type: ignore
    VulnType = None  # type: ignore
    PipelineReport = None  # type: ignore


def run_heap_overflow_pipeline(decompiled_text: str, func_name: str = "",
                                ir_lines: Optional[List[str]] = None,
                                insns: Optional[List[Tuple[int, str]]] = None,
                                ) -> Any:
    """运行堆溢出四层管线."""
    if UnifiedPipeline is None:
        return None
    pipeline = UnifiedPipeline()
    return pipeline.run(decompiled_text, func_name,
                        VulnType.HEAP_OVERFLOW, ir_lines, insns)


def run_uaf_pipeline(alloc_sites: List[Tuple[int, int, int]],
                     insns: List[Tuple[int, str]],
                     ir_text: str = "") -> List[Any]:
    """运行 UAF 时序-别名-可达-路径验证 (Type-State Alias Reachability Verification) 五阶段验证."""
    try:
        from .uaf_state_path_verifier import batch_verify_uaf
        return batch_verify_uaf(alloc_sites, insns, ir_text)
    except ImportError:
        return []


def run_format_string_pipeline(
        call_sites: List[Tuple[int, str, str]],
        insns: List[Tuple[int, str]]) -> List[Any]:
    """运行格式化字符串三阶段验证."""
    try:
        from .format_string_verifier import FormatStringVerifier
        verifier = FormatStringVerifier()
        return verifier.verify_all(call_sites, insns)
    except ImportError:
        return []


def run_int_overflow_pipeline(
        exprs: List[Tuple[str, str, int]],
        insns: List[Tuple[int, str]]) -> List[Any]:
    """运行整数溢出值范围验证。

    exprs 为 [(expr, func_name, call_site), ...]。
    """
    try:
        from .int_overflow_verifier import IntOverflowVerifier
        verifier = IntOverflowVerifier()
        verifier.propagate(insns)
        return [verifier.verify(expr, func, site)
                for expr, func, site in exprs]
    except ImportError:
        return []
