# coding: utf-8
"""
Narrowing 精化阶段 — 在抽象解释的 widening 收敛后, 用 narrowing 算子
将 +inf 边界缩回到有限值, 恢复 widen 造成的精度损失.


参考: Cousot & Cousot — widening/narrowing 操作符.
"""

from typing import Dict, List, Optional, Set, Tuple

from modules.core.compat.value_range import Interval
from modules.core.compat.path_abstract_interpret import (
    AbstractState, PathSensitiveHeapAnalyzer,
)
from modules.core.compat.cfg_extractor import CFGNode


def run_narrowing_phase(
    analyzer: 'PathSensitiveHeapAnalyzer',
    widened_addrs: Set[int],
    pre_widen_states: Dict[int, AbstractState],
    max_narrow_iters: int = 10,
) -> int:
    """在 widen 收敛后执行 narrowing 下降, 返回实际执行的 iteration 数.

    对每个 widen 点:
      1. 取 post_state (widen 后的状态) 和 pre_state (widen 前的状态)
      2. 反复执行 narrow + 传播, 直到不再变化或达到 max_narrow_iters
      3. 将精化后的状态写回 analyzer._states
    """
    total_narrow_iters = 0
    nodes = analyzer._nodes
    states = analyzer._states

    for lp_addr in list(widened_addrs):
        pre_state = pre_widen_states.get(lp_addr)
        post_state = states.get(lp_addr)
        if pre_state is None or post_state is None:
            continue

        narrowed = post_state.narrow(pre_state)
        for _ in range(max_narrow_iters):
            total_narrow_iters += 1
            old = states.get(lp_addr)
            if old is None or not _state_changed(old, narrowed):
                break
            states[lp_addr] = narrowed
            # 沿 CFG 传播 narrowing 后的状态
            _propagate_narrowed(nodes, states, lp_addr, lp_addr, set())
            # 继续 narrow
            next_narrowed = narrowed.narrow(pre_state)
            if not _state_changed(narrowed, next_narrowed):
                break
            narrowed = next_narrowed

    return total_narrow_iters


def _propagate_narrowed(
    nodes: Dict[int, CFGNode],
    states: Dict[int, AbstractState],
    start_addr: int,
    current_addr: int,
    visited: Set[int],
):
    """将 narrowing 后的状态沿 CFG 前向传播.

    与 widening 阶段不同: narrowing 阶段后继的 merge 用 join (不用 widen),
    因为我们已经过了循环头且状态在收缩而非扩张.
    """
    if current_addr in visited:
        return
    visited.add(current_addr)

    node = nodes.get(current_addr)
    if node is None:
        return
    current_state = states.get(current_addr)
    if current_state is None:
        return

    for succ in node.successors:
        # 用分析器的 transfer 函数计算新状态
        new_state = _transfer_basic(current_state, node, succ, nodes)
        if new_state is None:
            continue
        existing = states.get(succ)
        if existing is None:
            states[succ] = new_state
        else:
            # Narrowing 阶段用 join 而非 widen
            merged = existing.join(new_state)
            if _state_changed(existing, merged):
                states[succ] = merged
        _propagate_narrowed(nodes, states, start_addr, succ, visited)


def _transfer_basic(
    state: AbstractState,
    node: CFGNode,
    succ_addr: int,
    nodes: Dict[int, CFGNode],
) -> Optional[AbstractState]:
    """轻量 transfer — 不做 complex branch 分析, 仅传播已知约束."""
    new = AbstractState(
        alloc_size=state.alloc_size, write_size=state.write_size,
        ptr_id=state.ptr_id, equal_constraint=state.equal_constraint)

    if node.op_type == 'write' and node.write_size > 0:
        new.write_size = Interval.constant(node.write_size)
    elif node.op_type == 'write_bounded' and node.write_size > 0:
        new.write_size = new.write_size.intersect(Interval.le(node.write_size))

    succ_node = nodes.get(succ_addr)
    if succ_node and succ_node.op_type == 'write' and succ_node.write_size > 0:
        new.write_size = new.write_size.intersect(Interval.le(succ_node.write_size))

    return new


def _state_changed(old: AbstractState, new: AbstractState) -> bool:
    return (str(old.alloc_size) != str(new.alloc_size) or
            str(old.write_size) != str(new.write_size) or
            old.equal_constraint != new.equal_constraint)
