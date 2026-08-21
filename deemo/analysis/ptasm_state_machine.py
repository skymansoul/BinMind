"""
PTASM 状态机 — 转移规则表 + 单步操作应用。

定义 PtrState 之间的合法转移关系, 以及 _apply_ops 逐操作状态更新。
"""


from typing import Dict, List, Tuple

from analysis.ptasm_types import PtrState


# 转移规则: (当前状态, 操作) → 新状态
# assign_safe: 指针被任何表达式赋值 → 视为重新分配 (保守: 信任程序员意图)
_TRANSITION: Dict[Tuple[PtrState, str], PtrState] = {
    # free
    (PtrState.LIVE, 'free'): PtrState.FREED,
    (PtrState.FREED, 'free'): PtrState.FREED,       # double-free (不变)
    (PtrState.NULLIFIED, 'free'): PtrState.FREED,    # free(NULL) 安全但标记
    (PtrState.REASSIGNED, 'free'): PtrState.FREED,
    # malloc (重新分配)
    (PtrState.LIVE, 'malloc'): PtrState.LIVE,
    (PtrState.FREED, 'malloc'): PtrState.REASSIGNED,
    (PtrState.NULLIFIED, 'malloc'): PtrState.LIVE,
    (PtrState.REASSIGNED, 'malloc'): PtrState.LIVE,
    # nullify (p = NULL)
    (PtrState.LIVE, 'nullify'): PtrState.NULLIFIED,
    (PtrState.FREED, 'nullify'): PtrState.NULLIFIED,
    (PtrState.NULLIFIED, 'nullify'): PtrState.NULLIFIED,
    (PtrState.REASSIGNED, 'nullify'): PtrState.NULLIFIED,
    # use (仅 FREED 状态触发 UAF)
    (PtrState.FREED, 'use'): PtrState.USE_AFTER_FREE,
    # assign (任何赋值给已释放指针 → 视为重新分配)
    (PtrState.FREED, 'assign_target'): PtrState.REASSIGNED,
    (PtrState.NULLIFIED, 'assign_target'): PtrState.NULLIFIED,
    (PtrState.USE_AFTER_FREE, 'assign_target'): PtrState.REASSIGNED,
}

# free/malloc/use 传播到别名, nullify/assign_target 只影响指针自身:
#   q = p; free(p); p = NULL → q 仍然指向已释放内存 (UAF!)
_ALIAS_PROPAGATE_OPS = {'free', 'malloc', 'use'}


def apply_ptr_ops(
    ops: List[Tuple], state: Dict[str, PtrState],
    tracked: str, line_idx: int,
    engine,  # PTASMEngine, 避免循环导入
) -> Tuple[Dict[str, PtrState], str]:
    """应用一行中的操作, 更新状态并返回结果类型.

    返回 (new_state, result), result ∈ {uaf, safe, guard, neutral}.
    """
    st = dict(state)
    result = 'neutral'

    for op_type, info in ops:
        if op_type == 'cond_guard':
            if info.get('ptr') == tracked:
                result = 'guard'
            continue

        # free-wrapper 调用: 若被调函数是 free wrapper, 模拟 free(实参)
        if op_type == 'call':
            func_name = info.get('func', '')
            if func_name in engine._free_wrappers:
                param_idx = engine._free_wrappers[func_name]
                args = info.get('args', [])
                if param_idx < len(args):
                    freed_arg = args[param_idx]
                    # 模拟 free(freed_arg) — 与下方 free 逻辑一致
                    affected = {freed_arg}
                    canonical = engine._find_canonical(freed_arg)
                    affected.add(canonical)
                    if canonical in engine._reverse_alias:
                        affected.update(engine._reverse_alias[canonical])
                    for p in affected:
                        if p not in st:
                            st[p] = PtrState.LIVE
                        cur = st[p]
                        if cur == PtrState.FREED:
                            if p == tracked:
                                result = 'uaf'  # double-free via wrapper
                        else:
                            st[p] = PtrState.FREED
            continue

        ptr = info.get('ptr', '')
        if not ptr:
            # assign: lhs = rhs — 别名传播
            if op_type == 'assign':
                lhs, rhs = info['lhs'], info['rhs']
                if rhs in st:
                    st[lhs] = st[rhs]
                # 若 LHS 是已释放的追踪指针, 任何赋值都视为重新分配
                if lhs == tracked and st.get(lhs) == PtrState.FREED:
                    st[lhs] = PtrState.REASSIGNED
                    result = 'safe'
            continue

        # 展开别名
        if op_type in _ALIAS_PROPAGATE_OPS:
            affected = {ptr}
            canonical = engine._find_canonical(ptr)
            affected.add(canonical)
            if canonical in engine._reverse_alias:
                affected.update(engine._reverse_alias[canonical])
        else:
            affected = {ptr}

        for p in affected:
            if p not in st:
                st[p] = PtrState.LIVE
            cur = st[p]
            trans_key = (cur, op_type)
            if trans_key in _TRANSITION:
                new_state = _TRANSITION[trans_key]
                st[p] = new_state
            # Double-free: free(p) when p is already FREED
            if op_type == 'free' and cur == PtrState.FREED and p == tracked:
                result = 'uaf'
            # 额外: 若被释放的指针被赋值 → 视为重新分配
            if (cur == PtrState.FREED and op_type in ('assign',)):
                st[p] = PtrState.REASSIGNED
                if p == tracked:
                    result = 'safe'

        # 检查追踪指针及其别名的状态
        # 核心规则: 任一同类别名 USE_AFTER_FREE → 整体 UAF
        #           tracked自身 NULLIFIED/REASSIGNED 且无别名UAF → safe
        _check_affected = affected if op_type in _ALIAS_PROPAGATE_OPS else {ptr}
        for p in _check_affected:
            new_state = st.get(p, PtrState.LIVE)
            if new_state == PtrState.USE_AFTER_FREE:
                result = 'uaf'
            elif p == tracked and new_state in (PtrState.NULLIFIED, PtrState.REASSIGNED):
                if result != 'uaf':
                    result = 'safe'

    return st, result
