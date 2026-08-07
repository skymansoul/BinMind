"""FMT-SAC 类型定义 — 来源分类/说明符统计/判定结构.

创建: 2026-06-14
设计决策:
  - 来源五分类: CONST_RDATA(常量) / STACK_BUFFER / HEAP_BUFFER /
    USER_INPUT / UNKNOWN. 只有 CONST_RDATA 构成过滤依据.
  - 判定: CONST+一致 → 过滤; CONST+不一致 → POSSIBLE(参数错误,
    非格式化漏洞, 保留低置信); 非常量来源 → CONFIRMED/LIKELY.
"""
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum, auto


class FmtSource(Enum):
    """格式串来源分类."""
    CONST_RDATA = auto()   # .rdata 常量字面量
    STACK_BUFFER = auto()  # 栈缓冲 (可能被用户填充)
    HEAP_BUFFER = auto()   # 堆缓冲 (可能被用户填充)
    USER_INPUT = auto()    # 直接用户输入函数结果
    UNKNOWN = auto()


class SacVerdict(Enum):
    """FMT-SAC 判定."""
    SAFE_FILTERED = auto()   # 常量格式串且说明符-实参一致
    CONFIRMED = auto()       # 非常量来源格式串
    LIKELY = auto()          # 非常量来源但证据较弱
    POSSIBLE = auto()        # 常量但参数不一致 / 无法分类


class SacRule(Enum):
    """判定规则."""
    CONST_MATCH = auto()     # 常量 + 参数一致
    CONST_MISMATCH = auto()  # 常量 + 参数不一致
    NON_CONST_SOURCE = auto()  # 非常量来源
    PCT_N_WRITABLE = auto()  # %n 且输出可写目标
    ARG_COUNT_CHECK = auto() # 说明符计数 vs 实参计数
    UNRESOLVED = auto()


@dataclass
class FmtCall:
    """一个格式化函数调用点."""
    function: str = ""
    addr: int = 0
    fmt_reg: str = ""          # 格式串所在寄存器
    source: FmtSource = FmtSource.UNKNOWN
    source_detail: str = ""
    n_specifiers: int = 0      # 有效说明符数 (含位置参数)
    has_pct_n: bool = False
    n_args: int = 0            # 调用点可见实参数
    writable_out: bool = False # sprintf 类可写输出


@dataclass
class Evidence:
    """单条判定证据."""
    rule: SacRule = SacRule.UNRESOLVED
    detail: str = ""
    confidence: float = 0.0
    extra: dict = field(default_factory=dict)


@dataclass
class CallVerdict:
    """一个调用点的完整判定."""
    sample_id: str = ""
    call: Optional[FmtCall] = None
    verdict: SacVerdict = SacVerdict.POSSIBLE
    evidences: List[Evidence] = field(default_factory=list)
    fp_probability: float = 0.5

    @property
    def is_kept(self) -> bool:
        return self.verdict in (SacVerdict.CONFIRMED, SacVerdict.LIKELY,
                                SacVerdict.POSSIBLE)
