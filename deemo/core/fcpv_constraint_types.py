"""FCPV 约束类型定义 — 格式串约束传播验证器的类型系统。
将格式串漏洞判定建模为三值安全格 (SAFE ≤ UNCERTAIN ≤ VULN, 不确定时取 VULN 侧) 上的约束满足问题;
四类约束: sink (第 N 参数是否非常量)、taint (是否从外部输入可达)、sanitize (是否安全化)、跨函数参数绑定。
只要存在一条未被 sanitize 打断的 taint 路径且 sink 为非常量, 即保守判 VULN。"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional


class SafetyLabel(IntEnum):
    """三值安全格: SAFE < UNCERTAIN < VULN."""
    SAFE = 0
    UNCERTAIN = 1
    VULN = 2

    @staticmethod
    def join(a: 'SafetyLabel', b: 'SafetyLabel') -> 'SafetyLabel':
        """格 join (⊔): 取上界, 保守性保证."""
        return SafetyLabel(max(a.value, b.value))

    @staticmethod
    def meet(a: 'SafetyLabel', b: 'SafetyLabel') -> 'SafetyLabel':
        """格 meet (⊓): 取下界."""
        return SafetyLabel(min(a.value, b.value))


class ConstraintKind(IntEnum):
    """约束种类枚举."""
    SINK = 0       # sink 函数参数性质
    TAINT = 1      # 污点可达性
    SANITIZE = 2   # 安全化
    CROSS_FUNC = 3 # 跨函数绑定


class TaintState(IntEnum):
    """变量污点状态."""
    CLEAN = 0      # 确认不受外部输入影响
    TAINTED = 1    # 确认从外部输入可达
    UNKNOWN = 2    # 无法判定


class SinkType(IntEnum):
    """sink 参数类型."""
    CONSTANT = 0   # 字面量字符串
    VARIABLE = 1   # 变量 (可能安全也可能不安全)
    UNKNOWN = 2    # 无法解析


@dataclass
class FcpvConstraint:
    """FCPV 约束基类."""
    kind: ConstraintKind
    line: int = 0
    var: str = ""
    func: str = ""
    detail: str = ""


@dataclass
class SinkConstraint(FcpvConstraint):
    """sink 约束: printf 族函数第 N 参数."""
    kind: ConstraintKind = field(default=ConstraintKind.SINK, init=False)
    sink_func: str = ""
    fmt_arg: str = ""
    sink_type: SinkType = SinkType.UNKNOWN
    constant_text: str = ""
    arg_index: int = 0


@dataclass
class TaintConstraint(FcpvConstraint):
    """污点约束: 变量从外部输入可达."""
    kind: ConstraintKind = field(default=ConstraintKind.TAINT, init=False)
    source: str = ""        # 输入源 (fgets/argv/getenv/recv...)
    source_line: int = 0
    var_chain: List[str] = field(default_factory=list)


@dataclass
class SanitizeConstraint(FcpvConstraint):
    """安全化约束: 变量经过安全格式化."""
    kind: ConstraintKind = field(default=ConstraintKind.SANITIZE, init=False)
    sanitizer: str = ""     # snprintf/sprintf
    constant_fmt: str = ""  # 安全格式串内容
    sanitizer_line: int = 0


@dataclass
class CrossFuncConstraint(FcpvConstraint):
    """跨函数约束: 参数绑定传播."""
    kind: ConstraintKind = field(default=ConstraintKind.CROSS_FUNC, init=False)
    callee: str = ""        # 被调函数名
    param_index: int = 0   # 形参索引
    caller_arg: str = ""    # 调用者实参
    caller_line: int = 0


@dataclass
class FcpvCandidate:
    """格式串漏洞候选: 一个 sink 调用点 + 关联约束."""
    sink: SinkConstraint
    taints: List[TaintConstraint] = field(default_factory=list)
    sanitizers: List[SanitizeConstraint] = field(default_factory=list)
    cross_funcs: List[CrossFuncConstraint] = field(default_factory=list)
    label: SafetyLabel = SafetyLabel.UNCERTAIN
    confidence: float = 0.0
    reason: str = ""
    var_chain: List[str] = field(default_factory=list)


__all__ = [
    'SafetyLabel', 'ConstraintKind', 'TaintState', 'SinkType',
    'FcpvConstraint', 'SinkConstraint', 'TaintConstraint',
    'SanitizeConstraint', 'CrossFuncConstraint', 'FcpvCandidate',
]
