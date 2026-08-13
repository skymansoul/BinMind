"""Fmt-OG — 格式串溯源契约核对 (Origin-Contract Verification).

格式化字符串误报压缩包. 证据链: 常量串安全 (无 %n) > 参数契约
(说明符 ≤ 实参) > 输入源身份 (RETURN 链) > 包装透传溯源 (vprintf
族经函数标签定位 caller 实参). 三态: SUPPRESS / CONFIRM / UNCHANGED.
"""

from .spec_counter import SpecCount, count_specs, required_args
from .verdict import FmtSynthesizer, FmtVerdict, FmtVerdictKind
from .fmt_contract import FmtCall, FmtCallExtractor
from .fmt_compressor import FmtCompressor, FmtResult, FmtStats

__all__ = [
    'SpecCount', 'count_specs', 'required_args',
    'FmtSynthesizer', 'FmtVerdict', 'FmtVerdictKind',
    'FmtCall', 'FmtCallExtractor',
    'FmtCompressor', 'FmtResult', 'FmtStats',
]
