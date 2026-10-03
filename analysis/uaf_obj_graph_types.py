"""
UAF 对象身份图类型定义 — 堆对象身份图核心数据结构.

与传统指针别名分析的区别:
  指针别名: p=q → p和q是同一指针 (过于保守, 产生误报)
  对象身份: malloc返回的对象有唯一ID, 通过赋值/参数传递/结构体字段传播
          即使指针名不同, 只要追溯到同一malloc → 同一对象

关键概念:
  - ObjectID: 每次malloc/realloc调用的唯一标识 (分配点行号+调用栈)
  - ObjectState: 对象在程序点的生命周期状态
  - IdentityEdge: 对象身份传播边 (p=q → p的对象身份=q的对象身份)
  - ReallocTransition: realloc(old, new_size) → 旧对象身份→新对象身份
"""


from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Set, Tuple


class ObjState(IntEnum):
    """对象生命周期状态格 (三值逻辑)."""
    UNBORN = 0       # 尚未分配
    LIVE = 1         # 已分配, 存活
    FREED = 2        # 已释放, 悬垂
    REINCARNATED = 3 # 通过realloc延续
    NULLIFIED = 4    # 指针置NULL (安全)

    def join(self, other: 'ObjState') -> 'ObjState':
        """路径汇合: 只有完全一致才保持, 否则退化."""
        if self == other:
            return self
        if self == ObjState.UNBORN:
            return other
        if other == ObjState.UNBORN:
            return self
        return ObjState.FREED  # 保守: 任一路径释放 = 对象死亡


@dataclass
class ObjectID:
    """堆对象的唯一标识.

    从 malloc(size) 调用点确定:
      - alloc_line: 分配所在行号
      - alloc_func: 分配所在函数
      - context_hash: 调用上下文哈希 (调用链摘要, 区分同一行在循环中的多次分配)
    """
    alloc_line: int
    alloc_func: str = ""
    context_hash: int = 0   # 循环迭代计数/调用上下文的hash

    def __hash__(self):
        return hash((self.alloc_line, self.alloc_func, self.context_hash))

    def __eq__(self, other):
        if not isinstance(other, ObjectID):
            return False
        return (self.alloc_line == other.alloc_line and
                self.alloc_func == other.alloc_func and
                self.context_hash == other.context_hash)

    def __repr__(self):
        ctx = f'@{self.alloc_func}' if self.alloc_func else ''
        it = f'#{self.context_hash}' if self.context_hash else ''
        return f'Obj(L{self.alloc_line}{ctx}{it})'


@dataclass
class ObjStateAtPoint:
    """对象在某程序点的状态快照."""
    obj_id: ObjectID
    line_no: int
    state: ObjState = ObjState.LIVE
    ptr_names: Set[str] = field(default_factory=set)  # 当前持有此对象的指针名
    free_line: int = -1    # 若FREED, 释放点行号
    realloc_line: int = -1 # 若REINCARNATED, realloc点行号
    aliased_from: str = "" # 通过哪个别名关系获得此对象身份


@dataclass
class IdentityEdge:
    """对象身份的传播边."""
    src_var: str           # 源变量名 (赋值右边)
    dst_var: str           # 目标变量名 (赋值左边)
    obj_id: ObjectID       # 传播的对象身份
    line_no: int
    edge_type: str = ""    # 'direct_assign' | 'field_assign' | 'realloc'


@dataclass
class FuncObjSummary:
    """函数对象摘要 — 用于跨过程分析.

    记录函数对堆对象的影响:
      - allocated: 函数内分配的新对象
      - killed:    函数内释放的对象 (通过IdentityEdge定位)
      - escaped:   逃逸到调用者/全局的对象
      - returned:  返回给调用者的对象
    """
    func_name: str
    allocated: List[ObjectID] = field(default_factory=list)
    killed: List[Tuple[ObjectID, int]] = field(default_factory=list)  # (obj, line)
    escaped: Dict[str, ObjectID] = field(default_factory=dict)  # ptr_name → obj
    returned: Optional[ObjectID] = None
    calls: List[Tuple[str, int]] = field(default_factory=list)  # (callee, line)


@dataclass
class UafHoigVerdict:
    """UAF 对象身份图 UAF判定结果."""
    verdict: str = ""        # CONFIRMED | SAFE | UNCERTAIN
    confidence: float = 0.0
    obj_id: Optional[ObjectID] = None
    free_line: int = -1
    use_line: int = -1
    use_var: str = ""
    free_var: str = ""
    reason: str = ""
    is_cross_func: bool = False  # 是否跨函数UAF


__all__ = [
    'ObjState', 'ObjectID', 'ObjStateAtPoint',
    'IdentityEdge', 'FuncObjSummary', 'UafHoigVerdict',
]
