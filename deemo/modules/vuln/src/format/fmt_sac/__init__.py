"""FMT-SAC — Specifier-Argument Consistency 格式化字符串误报抑制.

核心方法论:
  1. 格式串来源五分类 (CONST_RDATA/STACK/HEAP/USER_INPUT/UNKNOWN),
     仅常量构成过滤依据.
  2. 说明符-实参一致性: 常量格式串 + 说明符数 ≤ 实参数 → 过滤;
     常量但不一致 → 参数错误非格式化漏洞, 降级保留.
  3. %n 可写目标增强: sprintf 类 + %n + 非常量来源 → CONFIRMED.

与既有 FMT-SPEC (src/format/fmt_orchestrator) 的关系: FMT-SPEC 做
rdata 提取+污点追踪+CRT 过滤; 本包补充说明符-实参一致性的形式化
验证, 与 PCFV/TOVS 共用值流基础设施.

创建: 2026-05-08
"""
from .types import (FmtSource, SacVerdict, SacRule, Evidence, FmtCall,
                    CallVerdict)
from .fmt_parser import parse_specifiers, extract_rdata_strings
from .source_classify import SourceClassifier
from .arg_consistency import ArgConsistency
from .engine import SacEngine
from .pipeline import SacReport, analyze_fmt_sac

__all__ = [
    "FmtSource", "SacVerdict", "SacRule", "Evidence", "FmtCall",
    "CallVerdict", "parse_specifiers", "extract_rdata_strings",
    "SourceClassifier", "ArgConsistency", "SacEngine",
    "SacReport", "analyze_fmt_sac",
]
