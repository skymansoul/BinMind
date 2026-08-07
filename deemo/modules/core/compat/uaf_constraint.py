# coding: utf-8
"""
UAF 时间约束系统 — 将堆对象生命周期编码为序关系约束.

核心洞察: UAF 的本质是时间线违规 — 访问事件发生在对象生命周期之外.
将 use-after-free 转化为约束系统:
  - Lifetime(n): [alloc_time, free_time) 区间
  - Use event: use_time 若 ∈ [alloc_time, free_time) → 安全, 否则 → UAF
  - 别名传播: p=q 后, free(p) 等价于 free(q)

方法: 使用区间代数 (Allen's interval algebra) 描述时间关系,
但简化为整数区间 (时间戳) 而非全关系代数.

  - "Unleashing Use-Before-Initialization in the Linux Kernel"
  - "EffectiveSan: Static Detection of Use-After-Free"
  - Allen's Interval Algebra — 仅借鉴 meet 关系, 不做全关系编码
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

class UafEventType(Enum):
    ALLOC = auto()     # malloc/calloc/realloc/new
    FREE = auto()      # free/delete
    USE = auto()       # dereference / mem-access
    ALIAS = auto()     # pointer copy: q = p

@dataclass
class LifetimeInterval:
    """对象生命周期: [alloc_ts, free_ts)."""
    obj_id: str           # 对象标识
    alloc_ts: int = 0     # 分配时间戳 (CFG 层面的拓扑序/指令序)
    free_ts: int = -1     # 释放时间戳 (-1 = 未释放)
    aliases: Set[str] = field(default_factory=set)  # 同一对象的别名集合

    def is_alive_at(self, ts: int) -> bool:
        return self.alloc_ts <= ts and (self.free_ts < 0 or ts < self.free_ts)

    def is_dangling(self, alias: str = '') -> bool:
        """若别名指向已释放对象, 则为悬挂指针."""
        return self.free_ts >= 0

@dataclass
class UafCandidate:
    """UAF 候选: 在某个 use 点访问了已释放的对象."""
    obj_id: str
    use_site: int        # 使用点地址
    free_site: int        # 释放点地址
    alloc_site: int       # 分配点地址
    use_ts: int
    free_ts: int
    alloc_ts: int
    taint_source: str = 'unknown'
    confidence: float = 0.5
    deref_type: str = 'read'  # 'read' | 'write'

class AliasGraph:
    """别名图 — 追踪指针赋值链 p=q → p 和 q 指向同一对象.

    使用 union-find 数据结构维护别名等价类:
    - 每个 obj_id 属于一个等价类
    - alloc(p, obj) → p 的等价类绑定到 obj
    - alias(p, q) → union(p 的等价类, q 的等价类)
    - free(p) → 释放 p 所在等价类的对象
    """

    def __init__(self):
        self._parent: Dict[str, str] = {}   # union-find parent
        self._obj_map: Dict[str, str] = {}  # ptr → obj_id 映射

    def alloc_ptr(self, ptr: str, obj_id: str):
        """记录 ptr 指向 obj."""
        self._parent.setdefault(ptr, ptr)
        self._obj_map[ptr] = obj_id

    def alias(self, p: str, q: str):
        """p = q: 合并两个指针的等价类. 自动注册未出现的指针."""
        self._parent.setdefault(p, p)
        self._parent.setdefault(q, q)
        rp, rq = self._find(p), self._find(q)
        if rp != rq:
            self._parent[rp] = rq
            # 传播对象映射: 若 rp 有绑定对象而 rq 没有
            if rp in self._obj_map and rq not in self._obj_map:
                self._obj_map[rq] = self._obj_map[rp]

    def resolve_ptr(self, ptr: str) -> Optional[str]:
        """返回 ptr 指向的 obj_id (或 None)."""
        if ptr not in self._parent:
            return None
        root = self._find(ptr)
        return self._obj_map.get(root)

    def get_aliases(self, obj_id: str) -> Set[str]:
        """返回所有指向同一 obj_id 的指针."""
        result = set()
        for ptr, root in self._parent.items():
            if self._obj_map.get(self._find(ptr)) == obj_id:
                result.add(ptr)
        return result

    def _find(self, x: str) -> str:
        path = []
        while self._parent.get(x, x) != x:
            path.append(x)
            x = self._parent[x]
        for node in path:
            self._parent[node] = x
        return x

class UafConstraintSystem:
    """UAF 时间约束系统 — 将 UAF 判定转化为区间成员检测.

    输入: 对象生命周期, 别名图, 使用事件列表
    输出: (是否为 UAF, 不可证明安全/不可证明安全的原因)

    判定逻辑:
      1. 若 use_ts ∈ [alloc_ts, free_ts) → 可证明安全
      2. 若 free_ts < 0 (未释放) ∧ use_ts >= alloc_ts → 可证明安全
      3. 若 use_ts >= free_ts ≥ 0 → UAF 可满足
      4. 若 use_ts < alloc_ts → uninitialized use (不同类别, 标记但不算 UAF)
    """

    def __init__(self):
        self._lifetimes: Dict[str, LifetimeInterval] = {}
        self._aliases: AliasGraph = AliasGraph()
        self._events: List[Tuple[int, UafEventType, str, str]] = []
        # (timestamp, event_type, ptr_name, obj_id)

    def add_lifetime(self, lt: LifetimeInterval):
        self._lifetimes[lt.obj_id] = lt

    def add_event(self, ts: int, etype: UafEventType,
                  ptr: str, obj_id: str = ''):
        self._events.append((ts, etype, ptr, obj_id))
        if etype == UafEventType.ALLOC:
            self._aliases.alloc_ptr(ptr, obj_id)
        elif etype == UafEventType.ALIAS:
            # ptr = obj_id (where obj_id is another pointer)
            self._aliases.alias(ptr, obj_id)

    def check_uaf(self, use_site: int, use_ts: int,
                  ptr: str = '') -> Tuple[bool, str, float]:
        """检查一个 use 事件是否为 UAF.

        返回: (is_uaf, reason, confidence).
        """
        # 解析别名 → 找到 use 的真正目标对象
        obj_id = ''
        if ptr and self._aliases.resolve_ptr(ptr):
            obj_id = self._aliases.resolve_ptr(ptr)

        if obj_id and obj_id in self._lifetimes:
            lt = self._lifetimes[obj_id]
            if lt.is_alive_at(use_ts):
                return False, f'{ptr}→{obj_id} 在 use_ts={use_ts} 时仍存活', 0.95

            if lt.free_ts >= 0 and use_ts >= lt.free_ts:
                aliases = self._aliases.get_aliases(obj_id)
                return True, (
                    f'{ptr}→{obj_id} 已在 ts={lt.free_ts} 释放, '
                    f'use_ts={use_ts} 发生在释放之后, '
                    f'别名集={aliases}'), 0.85

            if use_ts < lt.alloc_ts:
                return True, (
                    f'{ptr}→{obj_id} use_ts={use_ts} < alloc_ts={lt.alloc_ts} '
                    f'(未初始化使用)'), 0.70

        # 无精确信息时, 检查直接匹配的 free 事件
        free_ts_before = -1
        free_ts_after = -1
        for ts, etype, ev_ptr, _ in self._events:
            if etype == UafEventType.FREE and (ev_ptr == ptr or ev_ptr == obj_id):
                if ts < use_ts:
                    free_ts_before = max(free_ts_before, ts)
                else:
                    if free_ts_after < 0:
                        free_ts_after = ts
                    free_ts_after = min(free_ts_after, ts)

        if free_ts_before >= 0:
            return True, (
                f'{ptr} 在 ts={free_ts_before} 释放, '
                f'后续 use at ts={use_ts}'), 0.75

        if free_ts_after >= 0:
            return False, (
                f'{ptr} use at ts={use_ts} 在 free at ts={free_ts_after} 之前, '
                f'时序安全'), 0.80

        return False, f'未找到 {ptr} 的 free 事件, 假定安全 (保守)', 0.30

def encode_uaf_lifetime(
    alloc_site: int, free_site: int, use_sites: List[int],
    instruction_order: Dict[int, int],
    ptr_name: str = 'p',
) -> Tuple[UafConstraintSystem, List[UafCandidate]]:
    """从指令序列编码 UAF 约束系统.

    将指令地址映射到时间戳 (拓扑序), 构建生命周期约束.
    返回约束系统和检测到的 UAF 候选列表.
    """
    ucs = UafConstraintSystem()
    obj_id = f'obj_{alloc_site:x}'

    alloc_ts = instruction_order.get(alloc_site, alloc_site)
    free_ts = instruction_order.get(free_site, free_site)

    lt = LifetimeInterval(
        obj_id=obj_id,
        alloc_ts=alloc_ts,
        free_ts=free_ts,
        aliases={ptr_name},
    )
    ucs.add_lifetime(lt)
    ucs.add_event(alloc_ts, UafEventType.ALLOC, ptr_name, obj_id)
    ucs.add_event(free_ts, UafEventType.FREE, ptr_name, obj_id)

    candidates = []
    for use_site in use_sites:
        use_ts = instruction_order.get(use_site, use_site)
        ucs.add_event(use_ts, UafEventType.USE, ptr_name, obj_id)

        is_uaf, reason, conf = ucs.check_uaf(use_site, use_ts, ptr_name)
        if is_uaf:
            candidates.append(UafCandidate(
                obj_id=obj_id, use_site=use_site,
                free_site=free_site, alloc_site=alloc_site,
                use_ts=use_ts, free_ts=free_ts, alloc_ts=alloc_ts,
                confidence=conf,
            ))

    return ucs, candidates

def prove_uaf_infeasible(
    alloc_site: int, free_site: int, use_site: int,
    instruction_order: Dict[int, int],
    ptr_name: str = 'p',
) -> Tuple[bool, str]:
    """便捷判定: 给定 alloc/free/use 位点, UAF 是否可能.

    返回 (UAF 不可行 → True, 解释).
    """
    ucs, candidates = encode_uaf_lifetime(
        alloc_site, free_site, [use_site],
        instruction_order, ptr_name,
    )
    if not candidates:
        return True, '时序约束保证安全 (use 在 free 之前或对象存活期内)'
    c = candidates[0]
    return False, (
        f'UAF 可满足: obj 在 ts={c.free_ts} 释放, '
        f'use at ts={c.use_ts} (置信度={c.confidence:.1%})')
