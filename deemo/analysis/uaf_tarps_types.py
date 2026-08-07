"""
UAF TARPS 验证数据类型 — TarpsVerdict, TarpsResult, HeapObject.

"""


from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Set


class TarpsVerdict(Enum):
    """TARPS 五阶段判定结果."""
    DEF_FP = "DEF_FP"         # 确定误报 — 五阶段均确认安全
    LIKELY_FP = "LIKELY_FP"    # 很可能误报 — ≥3阶段确认安全
    UNCERTAIN = "UNCERTAIN"    # 不确定 — 保留
    LIKELY_TP = "LIKELY_TP"    # 很可能真阳性 — ≥3阶段确认危险
    DEF_TP = "DEF_TP"          # 确定真阳性 — 五阶段均确认危险


@dataclass
class TarpsResult:
    """TARPS 单候选的逐阶段判定."""
    alloc_site: int
    free_site: int
    use_site: int
    stages: Dict[str, bool] = field(default_factory=dict)
    # True = 该阶段确认危险 (应保留告警)
    # False = 该阶段确认安全 (应过滤)
    verdict: TarpsVerdict = TarpsVerdict.UNCERTAIN
    confidence: float = 0.5
    reason: str = ""


@dataclass
class HeapObject:
    """堆对象生命周期追踪."""
    alloc_addr: int
    alloc_func: str
    freed_at: Optional[int] = None
    aliases: Set[int] = field(default_factory=set)
