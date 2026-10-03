"""fmt_analysis — 格式串漏洞深度分析: 偏移推断 + %n可达性。"""
from modules.vuln.detection.fmt_analysis.offset_inferrer import (
    infer_fmt_offset, FormatOffset)
