"""
守卫条件数据类型 — GuardCondition 和 GuardSet.

纯数据容器, 无外部依赖.
"""


from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class GuardCondition:
    """单个守卫条件: var OP const → 区间约束.

    例: idx < 64  →  GuardCondition('idx', '<', 64) → idx ∈ (-∞, 63]
        n >= 16   →  GuardCondition('n', '>=', 16) → n ∈ [16, +∞)
        size <= 0 →  GuardCondition('size', '<=', 0) → 空区间 (逻辑矛盾)
    """
    var: str
    op: str          # '<', '<=', '>', '>=', '==', '!='
    constant: int
    line: int = 0

    def to_bounds(self) -> Tuple[Optional[int], Optional[int]]:
        """转换为 (lo, hi) 区间, None 表示无界.

        例: '<', 64 → (None, 63); '>=', 16 → (16, None); '==', 0 → (0, 0)
        """
        c = self.constant
        if self.op == '<':
            return (None, c - 1)
        elif self.op == '<=':
            return (None, c)
        elif self.op == '>':
            return (c + 1, None)
        elif self.op == '>=':
            return (c, None)
        elif self.op == '==':
            return (c, c)
        elif self.op == '!=':
            return (None, None)  # 无法单值约束
        return (None, None)

    def is_trivially_safe(self, alloc_size: int) -> bool:
        """检查此守卫是否保证写入安全 (对固定 alloc_size).

        例: GuardCondition('idx', '<', 64) 且 alloc_size=64 → True (idx ≤ 63 < 64)
        """
        lo, hi = self.to_bounds()
        if hi is not None and hi < alloc_size:
            return True
        if lo is not None and lo >= alloc_size:
            return False
        return False


@dataclass
class GuardSet:
    """一个代码位置上的守卫条件集合.

    多个守卫通过逻辑与连接: if(idx >= 0 && idx < 64) → 两个 GuardCondition
    """
    conditions: List[GuardCondition] = field(default_factory=list)
    line: int = 0

    @property
    def is_empty(self) -> bool:
        return len(self.conditions) == 0

    def get_bounds(self) -> Dict[str, Tuple[int, int]]:
        """将所有守卫条件合并为每变量的 (lo, hi) 边界.

        多个条件取交集 (最紧约束):
          idx >= 0 AND idx < 64 → idx ∈ [0, 63]
        """
        result: Dict[str, Tuple[int, int]] = {}
        for gc in self.conditions:
            lo, hi = gc.to_bounds()
            if gc.var not in result:
                result[gc.var] = (lo if lo is not None else 0,
                                  hi if hi is not None else 2**31 - 1)
            else:
                cur_lo, cur_hi = result[gc.var]
                new_lo = max(cur_lo, lo if lo is not None else 0)
                new_hi = min(cur_hi, hi if hi is not None else 2**31 - 1)
                result[gc.var] = (new_lo, new_hi)
        return result
