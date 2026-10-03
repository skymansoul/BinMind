"""TOVS 类型定义 — 分支敏感时间序验证的结果与候选结构.

创建: 2024-03-09
设计决策:
  - 三值判定与 PCFV 对齐: CONFIRMED(时序成立+身份一致) / POSSIBLE(证据不足,
    保守保留) / SAFE_FILTERED(时序不成立或身份被杀, 有充分证据).
  - 证据链复用 Evidence 模式: 每条判定记录规则+量化参数, 支撑消融.
"""
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum, auto


class TovsVerdict(Enum):
    """TOVS 判定结果."""
    CONFIRMED = auto()    # use 被 free 后支配且指针身份一致
    POSSIBLE = auto()     # 无法证明时序或身份 → 保守保留
    SAFE_FILTERED = auto()  # 时序不成立(分支互斥)或身份被杀 → 过滤


class TovsRule(Enum):
    """触发判定的规则."""
    POST_DOMINANCE = auto()   # use 在 free 后支配路径上 → 时序成立
    EXCLUSIVE_BRANCH = auto() # use 与 free 分支互斥 → 时序不成立
    EARLY_RETURN = auto()     # use 前存在不经过 free 的返回路径
    REDEFINED_PTR = auto()    # free 与 use 间指针身份被覆盖
    IDENTITY_MATCH = auto()   # use 处指针身份与 free 对象一致
    NULL_CHECK_NOT_GUARD = auto()  # NULL检查不构成防护(语义修正)
    UNRESOLVED = auto()       # 无法解析 → 保守


@dataclass
class FreeUsePair:
    """一个 (free, use) 候选对."""
    function: str = ""
    free_addr: int = 0
    use_addr: int = 0
    ptr_reg: str = ""
    ptr_label: str = ""        # malloc@addr 标签
    use_type: str = "write"    # write/read/call_via
    gap: int = 0


@dataclass
class Evidence:
    """单条判定证据."""
    rule: TovsRule = TovsRule.UNRESOLVED
    detail: str = ""
    confidence: float = 0.0
    extra: dict = field(default_factory=dict)


@dataclass
class PairVerdict:
    """一个候选对的完整判定."""
    sample_id: str = ""
    pair: Optional[FreeUsePair] = None
    verdict: TovsVerdict = TovsVerdict.POSSIBLE
    evidences: List[Evidence] = field(default_factory=list)
    fp_probability: float = 0.5

    @property
    def is_kept(self) -> bool:
        return self.verdict in (TovsVerdict.CONFIRMED, TovsVerdict.POSSIBLE)


@dataclass
class ConservativeVerdict:
    """保守保留判定 — UNRESOLVED 不再返回 None, 保留结构化结果供上层消费.

    设计决策:
      - Recall 黑洞根因: verify 返回 None 时上层直接丢弃候选,
        导致条件释放的 UAF 被漏报.
      - 改为返回 ConservativeVerdict, 上层可依据 confidence 决定是否保留.
    """
    rule: TovsRule = TovsRule.UNRESOLVED
    confidence: float = 0.6
    detail: str = ""
    evidence: Optional[Evidence] = None
