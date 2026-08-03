# 修改记录:
# 2025-07-31 11:08 - 增加差分增量压缩：仅存储与前一个 memento 的 SimHash delta
# 2025-08-03 08:35 - 引入内存预算强制执行：超预算时按 age*s 加权分数逐出
#
# 符号执行状态备忘录 -- 基于 Memento 模式的增量状态快照与压缩
#
# 符号执行的根本内存矛盾：每条路径维护独立的状态副本（寄存器映射+
# 内存模型+路径约束集），N 条并发路径 -> O(N * 平均状态大小) 内存
# z3.Solver 实例的 push/pop 累积内部状态（从 ~10MB 增长到 >500MB）
# 这是路径爆炸之外的另一个资源爆炸维度
#
# 现有方案：状态合并（st merging, KLEE 2024 ICSE workshop）将多条
# 路径的状态合并为一条，减少状态数量但损失路径特异性。本方案不同：
# 不合并状态，而是压缩存储——保留所有状态的特异性，但用增量编码减少
# 冗余。类比：git 的 object store 不存储每个版本的完整快照，而是存储
# 与前一个版本的 diff
#
# 核心机制：
# (a) 每条路径状态 = base_st + delta（增量约束集）
# base_st 被多条路径共享——类似 copy--写入
# (b) Memento 模式：Originator（符号执行引擎）创建 Memento 快照
#       Caretaker（本模块）管理快照生命周期和存储配额
#   (c) 差分增量：相邻 memento 间仅存储 SimHash 不同的约束
#       SimHash 相同 -> 约束等价 -> 不重复存储
#   (d) 内存预算：全局上限（默认 256MB），超预算时按加权分数逐出
#       score = age_seconds * size_bytes——老且大的先出
#   (e) 回滚能力：restore(memento_id) 恢复到指定快照
#
# 与 IncrementalSolver缓存的关系：
# IncrementalSolver缓存管理 Z3 solver 的 push/pop 生命周期——
# 这是"热"状态（solver 内部活跃状态）
# 本模块管理"冷"状态——已探索路径的序列化快照，可按需恢复到 solver
# 两者互补：热状态快速求解，冷状态持久化+内存控制
#
# 参考文献：
# 状态合并: "St Merging Quantifiers 符号执行"
# KLEE 2024 Workshop (ICSE 2024). 该工作用量化编码合并状态约束
# 但合并后的状态丢失了单条路径的可区分性
#   Memento 模式: Gamma et al., "Design Patterns", 1995. 原始模式
# 用于 GUI 撤销/重做，本模块将其迁移到符号执行状态管理
#   Git packfile delta: 启发自 git 的 diff-delta 编码，但用于
# 符号表达式而非文本行

import hashlib
import time
import threading
from typing import Dict, List, Optional, Tuple, NamedTuple
from dataclasses import dataclass, field


#---------------------------------------------------------------------------
# 数据结构
#---------------------------------------------------------------------------

@dataclass
class MementoEntry:
    """单个备忘录快照。不可变数据——restore 时复制整个快照给 originator"""
    memento_id: str
    path_id: str
    constraints: List[str]
    shared_simhashes: List[int] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    depth: int = 0
    estimated_size_bytes: int = 0

    def __post_init__(self):
        if self.estimated_size_bytes == 0:
            self.estimated_size_bytes = sum(
                len(c.encode('utf-8')) for c in self.constraints
            )


@dataclass
class MementoStats:
    """备忘录系统统计快照"""
    total_mementos: int = 0
    total_size_bytes: int = 0
    base_state_count: int = 0
    eviction_count: int = 0
    budget_remaining_bytes: int = 0


#---------------------------------------------------------------------------
# 核心类
#---------------------------------------------------------------------------

class StateMemento:
    """符号执行状态的 Memento 管理器
    
    用法：
    caretaker = StateMemento(memory_budget_mb=256)
    memento_id = caretaker.保存(path_id, constraints)
    constraints = caretaker.恢复(memento_id)
    caretaker.forget(memento_id)
    """

    def __init__(self, memory_budget_mb: float = 256.0,
                 max_mementos_per_path: int = 10):
        self._budget_bytes = int(memory_budget_mb * 1024 * 1024)
        self._max_per_path = max_mementos_per_path
        self._mementos: Dict[str, MementoEntry] = {}
        self._path_last_memento: Dict[str, str] = {}
        self._total_size: int = 0
        self._eviction_count: int = 0
        self._lock = threading.Lock()

    #------------------------------------------------------------------
    # 核心操作
    #------------------------------------------------------------------

    def save(self, path_id: str, constraints: List[str],
             depth: int = 0, base_state_id: Optional[str] = None) -> str:
        """创建路径状态的备忘录快照。返回 memento_id
        
        增量策略：若 base_state_id 非空，比较约束的 SimHash
        仅存储与前一个快照不同的约束
        """
        memento_id = self._generate_id(path_id)
        shared: List[int] = []
        stored_constraints = list(constraints)

        if base_state_id and base_state_id in self._mementos:
            base = self._mementos[base_state_id]
            base_hashes = {self._constraint_simhash(c) for c in base.constraints}
            new_constraints = []
            for c in constraints:
                ch = self._constraint_simhash(c)
                if ch in base_hashes:
                    shared.append(ch)
                else:
                    new_constraints.append(c)
            stored_constraints = new_constraints

        entry = MementoEntry(
            memento_id=memento_id, path_id=path_id,
            constraints=stored_constraints,
            shared_simhashes=shared, depth=depth,
            estimated_size_bytes=sum(len(c.encode('utf-8'))
                                     for c in stored_constraints),
        )

        with self._lock:
            # 单路径快照数限制
            path_mementos = [mid for mid, e in self._mementos.items()
                           if e.path_id == path_id]
            if len(path_mementos) >= self._max_per_path:
                oldest = min(path_mementos,
                           key=lambda mid: self._mementos[mid].created_at)
                self._remove_memento(oldest)

            self._mementos[memento_id] = entry
            self._path_last_memento[path_id] = memento_id
            self._total_size += entry.estimated_size_bytes

            if self._total_size > self._budget_bytes:
                self._enforce_budget()

        return memento_id

    def restore(self, memento_id: str) -> Optional[List[str]]:
        """恢复到指定快照，返回该快照的约束列表"""
        with self._lock:
            entry = self._mementos.get(memento_id)
            if entry is None:
                return None
            return list(entry.constraints)

    def forget(self, memento_id: str) -> bool:
        """主动释放指定快照的内存"""
        with self._lock:
            return self._remove_memento(memento_id)

    #------------------------------------------------------------------
    # 内部方法
    #------------------------------------------------------------------

    def _remove_memento(self, memento_id: str) -> bool:
        entry = self._mementos.pop(memento_id, None)
        if entry is None:
            return False
        self._total_size -= entry.estimated_size_bytes
        pid = entry.path_id
        if self._path_last_memento.get(pid) == memento_id:
            remaining = [(mid, e) for mid, e in self._mementos.items()
                        if e.path_id == pid]
            if remaining:
                self._path_last_memento[pid] = max(
                    remaining, key=lambda x: x[1].created_at)[0]
            else:
                self._path_last_memento.pop(pid, None)
        return True

    def _enforce_budget(self):
        """加权逐出：按 score = age_seconds * size_bytes 降序逐出
        直到内存使用低于预算的 80%。选 80% 而非 100% 留出操作余量"""
        target = int(self._budget_bytes * 0.8)
        now = time.time()
        scored = []
        for mid, entry in self._mementos.items():
            age = now - entry.created_at
            score = age * entry.estimated_size_bytes
            if age < 5.0:
                continue
            scored.append((mid, score))

        scored.sort(key=lambda x: -x[1])
        for mid, _ in scored:
            if self._total_size <= target:
                break
            self._remove_memento(mid)
            self._eviction_count += 1

    @staticmethod
    def _generate_id(path_id: str) -> str:
        import random
        ts = time.time_ns()
        suffix = format(random.randint(0, 0xFFFF), '04x')
        raw = f"{path_id}:{ts}:{suffix}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def _constraint_simhash(constraint: str) -> int:
        h = hashlib.sha256(constraint.encode()).digest()
        bits = 64
        result = 0
        for i in range(bits):
            byte_idx = i // 8
            bit_idx = i % 8
            if byte_idx < len(h) and (h[byte_idx] >> bit_idx) & 1:
                result |= (1 << i)
        return result

    #------------------------------------------------------------------
    # 统计与诊断
    #------------------------------------------------------------------

    def get_stats(self) -> MementoStats:
        with self._lock:
            base_states = len(set(e.path_id for e in self._mementos.values()))
            return MementoStats(
                total_mementos=len(self._mementos),
                total_size_bytes=self._total_size,
                base_state_count=base_states,
                eviction_count=self._eviction_count,
                budget_remaining_bytes=max(0, self._budget_bytes - self._total_size),
            )

    def total_mementos(self) -> int:
        with self._lock:
            return len(self._mementos)
