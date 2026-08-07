"""格式化字符串检测模块导入 — Verifier/FSTP/DFA/Bridge."""
from analysis.format_string_verifier import (
    FormatStringVerifier, FmtStringVerdict,
)
from analysis.fmt_taint_bridge import refine_fmt_findings
from analysis.fmt_stack_offset import (
    CallingConvention, StackOffsetEstimate, FmtCallSite,
    FormatStackOffsetAnalyzer, infer_fmt_offset,
)
try:
    from analysis.fmt_parser_dfa import (
        FmtDanger, FmtSpec, ParsedFmtString,
        FmtStringParser, classify_fmt_danger,
    )
except ImportError:
    FmtDanger = None  # type: ignore
    FmtSpec = None  # type: ignore
    ParsedFmtString = None  # type: ignore
    FmtStringParser = None  # type: ignore
    classify_fmt_danger = None  # type: ignore
from analysis.format_impact_calculator import (
    compute_exploitability, compute_impact,
    compute_cia_impact, generate_assessment,
)
from analysis.fmt_semantic_taint import (
    SemClass, FstpVerdict, FmtSemanticTaintPropagator,
)

__all__ = [
    'FormatStringVerifier', 'FmtStringVerdict',
    'refine_fmt_findings',
    'CallingConvention', 'StackOffsetEstimate', 'FmtCallSite',
    'FormatStackOffsetAnalyzer', 'infer_fmt_offset',
    'FmtDanger', 'FmtSpec', 'ParsedFmtString',
    'FmtStringParser', 'classify_fmt_danger',
    'compute_exploitability', 'compute_impact',
    'compute_cia_impact', 'generate_assessment',
    'SemClass', 'FstpVerdict', 'FmtSemanticTaintPropagator',
]
