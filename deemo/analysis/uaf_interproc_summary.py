"""
UAF跨过程生命周期摘要 — 将函数内局部分析提升到全程序级别。

核心方法:
  1. 为每个函数计算 (KILL, GEN) 摘要对
     - KILL(f): 函数f及其被调用者释放的堆指针集合
     - GEN(f):  函数f及其被调用者分配的堆指针集合
  2. 在调用点应用摘要, 判断指针在调用后是否仍存活
  3. 三值逻辑: ALIVE / FREED / UNKNOWN (保守: UNKNOWN=ALIVE)

与现有TARPS五阶段的关系:
  本标准模块作为Stage 0前置: 在进入级联过滤前, 先通过调用图传播
  全局变量的生命周期状态。TARPS的其他阶段在函数内进一步细化。

局限 (保守性来源):
  - 间接调用目标解析不完整 → 使用CHA (Class Hierarchy Analysis) 保守近似
  - 递归函数摘要用最小不动点 (lfp) 迭代至收敛
  - 链表/树等递归数据结构的释放模式需要形状分析, 本模块不处理
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Set, Tuple


# 三值生命周期状态
# ALIVE=0, FREED=1, UNKNOWN=2 用于格的最小不动点计算

class Lifetime(IntEnum):
    FREED = 0
    ALIVE = 1
    UNKNOWN = 2

    def join(self, other: 'Lifetime') -> 'Lifetime':
        """格join: 最小上界. FREED⊔ALIVE=UNKNOWN."""
        if self == other:
            return self
        return Lifetime.UNKNOWN

    def meet(self, other: 'Lifetime') -> 'Lifetime':
        """格meet: 最大下界."""
        if self == other:
            return self
        if self == Lifetime.UNKNOWN:
            return other
        if other == Lifetime.UNKNOWN:
            return self
        return Lifetime.UNKNOWN


@dataclass
class HeapPtrSummary:
    """单个堆指针的跨过程摘要."""
    ptr_name: str                       # 变量名 (可能是全局名或参数名)
    alloc_site_func: str                # 分配发生的函数
    kill_sites: List[Tuple[str, int]] = field(default_factory=list)
    # (函数名, 行号) 列表 — 释放该指针的位置
    use_sites: List[Tuple[str, int]] = field(default_factory=list)
    # (函数名, 行号) 列表 — 使用该指针的位置
    aliases: Set[str] = field(default_factory=set)
    # 别名集合 (同一等价类中的其他指针名)

    @property
    def is_freed(self) -> bool:
        return len(self.kill_sites) > 0

    @property
    def kill_count(self) -> int:
        return len(self.kill_sites)


@dataclass
class FuncSummary:
    """单个函数的摘要."""
    func_name: str
    kills: Set[str] = field(default_factory=set)     # 此函数释放的指针名集合
    gens: Set[str] = field(default_factory=set)       # 此函数分配的指针名集合
    escapes: Set[str] = field(default_factory=set)    # 逃逸到外部的指针集合
    calls: List[str] = field(default_factory=list)    # 调用的其他函数名列表
    ptr_states: Dict[str, Lifetime] = field(default_factory=dict)
    # 函数出口时各指针的生存状态


class InterProcLifetimeAnalyzer:
    """跨过程生命周期分析引擎.

    使用工作列表算法计算函数摘要的lfp固定点。
    由于Lifetime格高度为2 (FREED→ALIVE→UNKNOWN), 收敛极快。
    """

    def __init__(self):
        self._summaries: Dict[str, FuncSummary] = {}
        self._call_graph: Dict[str, List[str]] = {}   # caller → [callees]
        self._globals: Set[str] = set()
        self._worklist: List[str] = []

    # 摘要构建

    def add_function(self, name: str, summary: FuncSummary):
        """注册函数及其初始摘要."""
        self._summaries[name] = summary
        for callee in summary.calls:
            self._call_graph.setdefault(name, []).append(callee)
        if name not in self._worklist:
            self._worklist.append(name)

    def mark_global(self, var_name: str):
        """标记指针为全局变量."""
        self._globals.add(var_name)

    # 不动点迭代

    def solve(self, max_iter: int = 50):
        """工作列表迭代至收敛.

        每个迭代步骤:
          对worklist中的函数f:
            1. 收集f调用的所有函数的摘要 (kill/gen)
            2. 聚合: kill(f) ∪= kill(callee)  (传递闭包)
            3. 计算入口/出口状态
            4. 若摘要改变, 将所有调用者加入worklist
        """
        iteration = 0
        while self._worklist and iteration < max_iter:
            iteration += 1
            func_name = self._worklist.pop(0)
            if func_name not in self._summaries:
                continue
            old_summary = self._summaries[func_name]
            new_summary = self._compute_summary(func_name)

            if self._summary_changed(old_summary, new_summary):
                self._summaries[func_name] = new_summary
                # 将所有调用者加入worklist
                for caller, callees in self._call_graph.items():
                    if func_name in callees and caller not in self._worklist:
                        self._worklist.append(caller)

    def _compute_summary(self, func_name: str) -> FuncSummary:
        """计算单个函数的完整摘要 (聚合被调用者)."""
        summary = self._summaries[func_name]
        new_kills = set(summary.kills)
        new_gens = set(summary.gens)
        new_ptr_states = dict(summary.ptr_states)

        # 从被调用者继承kills
        for callee in summary.calls:
            if callee in self._summaries:
                callee_summ = self._summaries[callee]
                new_kills.update(callee_summ.kills)
                new_gens.update(callee_summ.gens)

        # 更新指针状态: 若在kills中 → FREED
        for ptr in new_kills:
            if ptr in new_ptr_states:
                new_ptr_states[ptr] = Lifetime.FREED

        return FuncSummary(
            func_name=func_name,
            kills=new_kills,
            gens=new_gens,
            escapes=summary.escapes,
            calls=summary.calls,
            ptr_states=new_ptr_states,
        )

    @staticmethod
    def _summary_changed(old: FuncSummary, new: FuncSummary) -> bool:
        return (old.kills != new.kills or
                old.gens != new.gens or
                old.ptr_states != new.ptr_states)

    # 查询接口

    def query_ptr_state(self, func_name: str, ptr_name: str) -> Lifetime:
        """查询指针在指定函数出口的状态."""
        summ = self._summaries.get(func_name)
        if not summ:
            return Lifetime.UNKNOWN
        return summ.ptr_states.get(ptr_name, Lifetime.UNKNOWN)

    def is_ptr_freed_by(self, func_name: str, ptr_name: str) -> bool:
        """指针是否被指定函数(或其被调用者)释放."""
        summ = self._summaries.get(func_name)
        if not summ:
            return False
        return ptr_name in summ.kills

    def get_globals_freed_by(self, func_name: str) -> Set[str]:
        """返回被指定函数释放的全局变量集合."""
        summ = self._summaries.get(func_name)
        if not summ:
            return set()
        return summ.kills & self._globals
