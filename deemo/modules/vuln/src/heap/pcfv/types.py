"""PCFV 类型定义 — 判定枚举与证据数据结构.

创建: 2026-06-19
设计决策:
  - Verdict 五值而非三值: SAFE_FILTERED 需要同时满足"证明安全"与"过滤依据充分"
    两个条件, 与基线三阶段管线相比, 增加了 UNPROVEN 中间态避免"未知即安全".
  - Evidence 链式记录: 每条证据保留规则名+量化参数, 支撑论文消融实验与审计.
"""
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum, auto


class Verdict(Enum):
    """PCFV 判定结果."""
    SAFE_FILTERED = auto()   # 有充分证据证明安全 → 过滤
    CONFIRMED = auto()       # 有充分证据证明溢出 → 确认
    LIKELY = auto()          # 溢出可能但证据不足 → 保留(低置信)
    UNPROVEN = auto()        # 无法判定 → 保守保留(中置信)


class ProofRule(Enum):
    """触发判定的证明规则."""
    GUARD_DOMINANCE = auto()      # 支配守卫窄化区间证明安全
    CONSTANT_BOUNDED = auto()     # 常量偏移+大小在可用范围内
    ALLOC_PADDING = auto()        # 偏移落在分配器舍入padding区
    MIN_CAP = auto()              # min(size, cap) 上限模式
    CONSTANT_OVERFLOW = auto()    # 常量偏移+大小超出可用范围
    TAINTED_OVERFLOW = auto()     # 用户可控偏移超出可用范围
    UNBOUNDED_COPY = auto()       # 无界复制(strcpy类)目标为堆
    LOOP_ACCUMULATE = auto()      # 循环累积写入超界
    ALLOC_SIZE_UNKNOWN = auto()   # 分配大小不可解析
    REALLOC_SHRINK = auto()       # realloc缩小后按新大小判定


class Provenance(Enum):
    """偏移/大小值的来源类型."""
    CONSTANT = auto()      # 立即数或常量传播
    GUARDED = auto()       # 分支守卫窄化
    ENTRY_ARG = auto()     # 函数入口参数
    INPUT_CALL = auto()    # 输入函数返回值
    MEMORY_LOAD = auto()   # 从栈/全局内存加载
    LOOP_IND = auto()      # 循环归纳变量
    UNKNOWN = auto()       # 无法追踪


@dataclass
class ValueInfo:
    """一个操作数的抽象值信息."""
    interval_lo: Optional[int] = None    # 值域下界
    interval_hi: Optional[int] = None    # 值域上界
    is_constant: bool = False            # 是否确定常量
    constant_value: Optional[int] = None
    tainted: Optional[bool] = None       # None=未知, True/False=确定
    taint_confidence: float = 0.0
    provenance: Provenance = Provenance.UNKNOWN
    def_chain_len: int = 0               # 定义链长度(追踪深度证据)
    summary: str = ""


@dataclass
class GuardConstraint:
    """一条候选守卫约束."""
    branch_addr: int = 0
    reg: str = ""
    op: str = ""                 # lt/le/gt/ge/eq/ne
    bound_value: Optional[int] = None
    polarity_taken: bool = True  # 约束在taken边生效
    dominates: bool = False      # 支配性验证结果


@dataclass
class Evidence:
    """单条判定证据."""
    rule: ProofRule = ProofRule.UNBOUNDED_COPY
    detail: str = ""
    confidence: float = 0.0
    extra: dict = field(default_factory=dict)


@dataclass
class FindingVerdict:
    """一个堆访问的完整判定结果."""
    sample_id: str = ""
    function: str = ""
    insn_addr: int = 0
    access_kind: str = "store"          # store/memcpy/strcpy/loop_store
    alloc_site: int = 0
    alloc_size: Optional[int] = None
    usable_size: Optional[int] = None
    offset_info: Optional[ValueInfo] = None
    copy_size_info: Optional[ValueInfo] = None
    verdict: Verdict = Verdict.UNPROVEN
    evidences: List[Evidence] = field(default_factory=list)
    fp_probability: float = 0.5

    @property
    def is_kept(self) -> bool:
        return self.verdict in (Verdict.CONFIRMED, Verdict.LIKELY,
                                Verdict.UNPROVEN)

    @property
    def is_confirmed(self) -> bool:
        return self.verdict == Verdict.CONFIRMED
