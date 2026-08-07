# coding: utf-8
"""
路径敏感的轻量抽象解释 — 对堆分配/写入操作沿控制流做抽象求值.

核心方法: 将每个基本块的抽象状态 (alloc_size, write_size) 映射到区间域,
在 CFG 上做迭代不动点计算, widen 循环头以保证终止.
Narrowing 精化阶段委托 narrow_refine.py.

区别于完整抽象解释: 不做值集分析 (VSA), 只在 alloc-size/write-size 两个
维度做关系抽象, 复杂度 O(|V|·|E|) 而非 O(|V|³).

  - Cousot & Cousot 抽象解释框架 — widening/narrowing 操作符
  - ISSTA 2024 "Heap Disjointness" — 堆对象隔离性的组合式证明

误报根因: 现有区间分析 (value_range.py) 仅回溯单条 def-use 链,
无法处理 if-else 分支后的值合并. 本模块在完整 CFG 上传播区间,
可以证明"在两条分支上 alloc_size 均 ≥ write_size"的情况为安全.
"""

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from modules.core.compat.value_range import Interval
from modules.core.compat.cfg_extractor import CFGNode

@dataclass
class AbstractState:
    """每个程序点的抽象状态 — 只追踪与堆溢出相关的两个维度."""
    alloc_size: Interval = field(default_factory=Interval.top)
    write_size: Interval = field(default_factory=Interval.top)
    ptr_id: str = ''
    equal_constraint: bool = False

    def is_bottom(self) -> bool:
        return self.alloc_size.is_bottom or self.write_size.is_bottom

    def join(self, other: 'AbstractState') -> 'AbstractState':
        """两个状态的合并 (lub) — 用于 CFG 汇合点."""
        return AbstractState(
            alloc_size=self.alloc_size.union(other.alloc_size),
            write_size=self.write_size.union(other.write_size),
            ptr_id=self.ptr_id or other.ptr_id,
            equal_constraint=self.equal_constraint and other.equal_constraint,
        )

    def widen(self, other: 'AbstractState') -> 'AbstractState':
        """循环头 widening — 确保不动点计算终止.

        若区间上界在迭代中持续增长, 推到 +∞; 下界持续减小, 推到 0.
        """
        def _widen_interval(a: Interval, b: Interval) -> Interval:
            lo, hi = a.lo, a.hi
            if a.hi >= 0 and b.hi >= 0 and b.hi > a.hi:
                hi = -1  # +∞
            if a.lo >= 0 and b.lo >= 0 and b.lo < a.lo:
                lo = 0
            if a.lo < 0 and b.lo >= 0:
                lo = b.lo
            if a.hi < 0 and b.hi >= 0:
                hi = b.hi
            return Interval(lo, hi)

        return AbstractState(
            alloc_size=_widen_interval(self.alloc_size, other.alloc_size),
            write_size=_widen_interval(self.write_size, other.write_size),
            ptr_id=self.ptr_id or other.ptr_id,
            equal_constraint=False,
        )

    def narrow(self, other: 'AbstractState') -> 'AbstractState':
        """Narrowing 算子 — 在 widen 收敛后恢复精度.

        将 +∞ 边界缩回到上一次迭代的有限值.
        """
        def _narrow_interval(a: Interval, b: Interval) -> Interval:
            lo, hi = a.lo, a.hi
            if a.hi < 0 and b.hi >= 0:
                hi = b.hi
            if a.lo < 0 and b.lo >= 0:
                lo = b.lo
            if a.hi >= 0 and b.hi >= 0:
                hi = min(a.hi, b.hi)
            if a.lo >= 0 and b.lo >= 0:
                lo = max(a.lo, b.lo)
            return Interval(lo, hi)

        return AbstractState(
            alloc_size=_narrow_interval(self.alloc_size, other.alloc_size),
            write_size=_narrow_interval(self.write_size, other.write_size),
            ptr_id=self.ptr_id or other.ptr_id,
            equal_constraint=self.equal_constraint and other.equal_constraint,
        )

@dataclass
class AnalysisResult:
    """路径敏感分析的结果."""
    provably_safe: bool
    alloc_final_interval: str
    write_final_interval: str
    iteration_count: int
    narrow_iterations: int = 0
    widening_points: List[int] = field(default_factory=list)
    detail: str = ''

class PathSensitiveHeapAnalyzer:
    """对单个溢出候选做路径敏感的抽象解释.

    算法 (两阶段):
      1. Widening: 前向传播直到 post-fixpoint
      2. Narrowing: 委托 narrow_refine.run_narrowing_phase() 精化
      3. 检查区间关系: alloc.lo >= write.hi → 安全
    """

    MAX_ITERATIONS = 50
    WIDEN_THRESHOLD = 3  # 延迟扩宽: 等 N 次增长后再 widen (保持短循环精度)

    def __init__(self, cfg_nodes: Optional[Dict[int, CFGNode]] = None):
        self._nodes: Dict[int, CFGNode] = cfg_nodes or {}
        self._states: Dict[int, AbstractState] = {}
        self._iteration = 0
        self._widened: Set[int] = set()
        self._pre_widen_states: Dict[int, AbstractState] = {}
        # 阈值延迟: 记录每个循环头的不稳定增长次数
        self._growth_count: Dict[int, int] = {}

    def add_node(self, node: CFGNode):
        self._nodes[node.addr] = node

    def analyze(
        self, alloc_site: int, write_site: int,
        known_alloc_size: Interval, max_paths: int = 100,
    ) -> AnalysisResult:
        """主分析入口."""
        if alloc_site not in self._nodes or write_site not in self._nodes:
            return AnalysisResult(False, '?', '?', 0, 0, [],
                                  'CFG 节点缺失, 无法分析')

        self._states.clear()
        self._pre_widen_states.clear()
        self._widened.clear()
        self._iteration = 0

        init_state = AbstractState(
            alloc_size=known_alloc_size, write_size=Interval.top())
        worklist = deque([alloc_site])
        self._states[alloc_site] = init_state

# Phase 1: Widening until post-fixpoint
        while worklist and self._iteration < self.MAX_ITERATIONS:
            self._iteration += 1
            addr = worklist.popleft()
            current = self._states.get(addr)
            if current is None or current.is_bottom():
                continue

            node = self._nodes[addr]
            for succ in node.successors:
                new_state = self._transfer(current, node, succ)
                if new_state is None or new_state.is_bottom():
                    continue

                existing = self._states.get(succ)
                if existing is None:
                    self._states[succ] = new_state
                    worklist.append(succ)
                else:
                    if succ in self._widened:
                        # 已达阈值 → 使用 widening 确保终止
                        if succ not in self._pre_widen_states:
                            self._pre_widen_states[succ] = existing
                        merged = existing.widen(new_state)
                    else:
                        merged = existing.join(new_state)
                        # 阈值延迟扩宽: 只有连续稳定增长超过阈值才触发
                        if (self._is_growing(existing, merged) and
                            self._is_loop_header(succ)):
                            cnt = self._growth_count.get(succ, 0) + 1
                            self._growth_count[succ] = cnt
                            if cnt >= self.WIDEN_THRESHOLD:
                                self._pre_widen_states[succ] = existing
                                self._widened.add(succ)

                    if self._state_changed(existing, merged):
                        self._states[succ] = merged
                        worklist.append(succ)

        # ---- Phase 2: Narrowing (delegated to narrow_refine) ----
        narrow_iters = 0
        if self._widened:
            from modules.core.compat.narrow_refine import run_narrowing_phase
            narrow_iters = run_narrowing_phase(
                self, self._widened, self._pre_widen_states)

# Phase 3: 检查最终状态
        final = self._states.get(write_site)
        if final is None:
            return AnalysisResult(False, str(known_alloc_size), '?',
                                  self._iteration, narrow_iters,
                                  list(self._widened), 'write_site 不可达')

        safe = self._prove_safe(final)
        return AnalysisResult(
            provably_safe=safe,
            alloc_final_interval=str(final.alloc_size),
            write_final_interval=str(final.write_size),
            iteration_count=self._iteration,
            narrow_iterations=narrow_iters,
            widening_points=list(self._widened),
            detail=_build_detail(safe, final, narrow_iters),
        )

    def _transfer(self, state: AbstractState, node: CFGNode,
                  succ_addr: int) -> Optional[AbstractState]:
        """转移函数: 根据节点类型更新抽象状态."""
        new = AbstractState(
            alloc_size=state.alloc_size, write_size=state.write_size,
            ptr_id=state.ptr_id, equal_constraint=state.equal_constraint)

        if node.op_type == 'write' and node.write_size > 0:
            new.write_size = Interval.constant(node.write_size)
        elif node.op_type == 'write_bounded' and node.write_size > 0:
            new.write_size = new.write_size.intersect(
                Interval.le(node.write_size))
        elif node.op_type == 'cmp_bounds':
            new.equal_constraint = True

        succ_node = self._nodes.get(succ_addr)
        if succ_node and succ_node.op_type == 'write' and succ_node.write_size > 0:
            new.write_size = new.write_size.intersect(
                Interval.le(succ_node.write_size))

        return new

    def _prove_safe(self, state: AbstractState) -> bool:
        """判定: alloc 下界 ≥ write 上界 → 安全."""
        if state.equal_constraint:
            return True
        a, w = state.alloc_size, state.write_size
        if a.lo >= 0 and w.hi >= 0 and a.lo >= w.hi:
            return True
        if a.is_constant and w.hi >= 0 and w.hi <= a.lo:
            return True
        if w.is_constant and a.lo >= 0 and w.lo <= a.lo:
            return True
        return False

    def _is_growing(self, old: AbstractState, new: AbstractState) -> bool:
        def _growing(a: Interval, b: Interval) -> bool:
            return a.hi >= 0 and b.hi >= 0 and b.hi > a.hi
        return _growing(old.alloc_size, new.alloc_size) or _growing(
            old.write_size, new.write_size)

    def _is_loop_header(self, addr: int) -> bool:
        """改进的循环头检测: 基于回边.

        回边 = predecessor addr > current addr (地址降序 = 跳回).
        同时要求 predecessor 计数 ≥ 2 (汇合点).
        """
        node = self._nodes.get(addr)
        if node is None:
            return False
        has_back_edge = any(p > addr for p in node.predecessors)
        is_merge = len(node.predecessors) >= 2
        return has_back_edge and is_merge

    def _state_changed(self, old: AbstractState, new: AbstractState) -> bool:
        return (str(old.alloc_size) != str(new.alloc_size) or
                str(old.write_size) != str(new.write_size) or
                old.equal_constraint != new.equal_constraint)

def _build_detail(safe: bool, state: AbstractState, narrow_iters: int) -> str:
    prefix = f'[narrow={narrow_iters}] '
    if safe:
        return (f'{prefix}可证明安全: alloc{state.alloc_size} '
                f'包含 write{state.write_size}, eq_constraint={state.equal_constraint}')
    return f'{prefix}无法证明安全: alloc{state.alloc_size} vs write{state.write_size}'

# batch_path_sensitive_filter 已移至 compat/batch_path_filter.py
# 原调用方请改为: from modules.core.compat.batch_path_filter import batch_path_sensitive_filter
