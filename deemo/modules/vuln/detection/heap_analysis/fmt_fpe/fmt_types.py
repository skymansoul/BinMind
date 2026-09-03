"""FPE 格式溯源类型 — 格式参数溯源标签与判定枚举.

用途: 格式字符串漏洞(Format String)误报削减的溯源侧基础。

设计决策:
  - 溯源标签集: .rdata/.rodata(常量池), argN(函数参数), stack(栈/局部),
    const(立即数/常量地址), unknown(无法确定)。
  - 判定只承认 .rdata/const 为安全: 常量格式串 `printf("...")` 无漏洞;
    argN/stack/unknown 均保守保留, 保证召回。
  - %n 可用性等利用维度不在此模块判定, 仅做溯源等价分类。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class FmtVerdict(Enum):
    SAFE_CONST = 'safe_const'       # 格式串为常量池/常量溯源 → 安全滤除
    VULN_PARAM = 'vuln_param'       # 格式串来自函数参数 → 潜在漏洞
    VULN_LOCAL = 'vuln_local'       # 格式串来自局部/未知 → 保守保留
    UNCERTAIN = 'uncertain'


@dataclass
class FmtCall:
    """一次格式化函数调用."""
    addr: int
    func_name: str
    fmt_func: str        # printf/sprintf/fprintf/...
    fmt_label: str       # 格式参数溯源标签
    fmt_reg: str         # 承载格式参数的寄存器


@dataclass
class FmtVerdictRecord:
    """一次格式调用的 FPE 判定."""
    func_name: str
    addr: int
    fmt_func: str
    fmt_label: str
    verdict: FmtVerdict
    reasoning: str
    confidence: float = 0.5
    fp_probability: float = 0.5


@dataclass
class FuncFmtResult:
    """单函数格式分析结果."""
    name: str
    calls: List[FmtCall] = field(default_factory=list)
    verdicts: List[FmtVerdictRecord] = field(default_factory=list)
