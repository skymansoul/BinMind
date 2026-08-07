"""
格式串污点分析类型定义 — FTV (Format-string Taint Verifier) 共用类型.

包含: 判决枚举/数据类.
"""


from dataclasses import dataclass, field
from enum import Enum
from typing import List


class FmtVerdict(Enum):
    VULN = "VULN"           # 格式串来源可证为用户可控
    SAFE = "SAFE"            # 可证安全 (常量格式串 / 已安全化)
    UNCERTAIN = "UNCERTAIN"  # 无法确定


class FmtSink(Enum):
    """格式串sink函数族 — 所有接受格式串参数的函数."""
    PRINTF = "printf"
    FPRINTF = "fprintf"
    SPRINTF = "sprintf"
    SNPRINTF = "snprintf"
    DPRINTF = "dprintf"
    SYSLOG = "syslog"
    VPRINTF = "vprintf"
    VFPRINTF = "vfprintf"
    VSPRINTF = "vsprintf"
    VSNPRINTF = "vsnprintf"
    ERR = "err"
    WARN = "warn"
    ERRX = "errx"
    WARNX = "warnx"


class TaintSource(Enum):
    """污点源 — 将数据标记为用户可控的来源."""
    FGETS = "fgets"
    GETS = "gets"
    SCANF = "scanf"
    FSCANF = "fscanf"
    SSCANF = "sscanf"
    RECV = "recv"
    RECVFROM = "recvfrom"
    READ = "read"
    ARGV = "argv"
    GETENV = "getenv"
    FREAD = "fread"


@dataclass
class FmtCallSite:
    """格式串调用点."""
    line: int
    sink: FmtSink
    fmt_arg: str           # 格式串参数的文本表达式
    fmt_arg_var: str       # 提取的变量名 (若为变量)
    is_constant: bool      # 格式串是否为字面量
    constant_text: str = ""


@dataclass
class SanitizerSite:
    """安全化调用点 — 输出为已知安全的格式串."""
    line: int
    func: str              # snprintf / sprintf / ...
    output_var: str        # 被赋值的变量
    fmt_is_constant: bool  # 格式串参数自身是否为常量
    constant_fmt: str = ""


@dataclass
class TaintPath:
    """从source到sink的污点传播路径."""
    source: str            # 污点源函数 (fgets/recv/argv...)
    source_line: int
    sink: str              # sink函数 (printf/fprintf...)
    sink_line: int
    var_chain: List[str] = field(default_factory=list)
    sanitized: bool = False
    sanitizer_line: int = 0


@dataclass
class FtvResult:
    """FTV验证结果."""
    verdict: FmtVerdict
    sink_line: int = 0
    sink_func: str = ""
    fmt_arg: str = ""
    taint_paths: List[TaintPath] = field(default_factory=list)
    sanitized_by: str = ""
    reason: str = ""


__all__ = [
    'FmtVerdict', 'FmtSink', 'TaintSource',
    'FmtCallSite', 'SanitizerSite', 'TaintPath', 'FtvResult',
]
