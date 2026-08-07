"""
PTASM 路径敏感分析器 — 递归分段 + fork/join 分支分析。

对每个追踪指针执行递归控制流分析:
  - if/else 分支处 fork 状态分别分析, 汇合处 join
  - while/for 循环: 在条件行 fork, 分析循环体
  - 保守性: 任一路径 UAF → 报告; 全路径安全 → FILTER
"""


from typing import Dict, List, Set, Tuple

from analysis.ptasm_types import (
    PtrState, PtrInfo, PTASMResult, parse_line_operations,
)
from analysis.ptasm_ctrl_flow import (
    find_branch_bodies, join_ptr_states,
)
from analysis.ptasm_state_machine import apply_ptr_ops


def path_sensitive_analyze(
    lines: List[str],
    ptr_states: Dict[str, PtrInfo],
    engine,  # PTASMEngine, 避免循环导入
) -> List[PTASMResult]:
    """递归分段分析: 线性扫描 + if/else/while分支处fork, 汇合处join.

    与CFG方法相比的优势:
      - 直接处理嵌套控制流 (无需块分割/邻接计算)
      - 分支语义精确 (then vs else 各自独立分析后join)
      - 保守性: 任一路径UAF → 报告; 全路径安全 → FILTER
    """
    results: List[PTASMResult] = []
    tracked_ptrs = {p for p, pi in ptr_states.items()
                   if pi.free_line > 0}
    if not tracked_ptrs:
        return results

    for ptr in tracked_ptrs:
        pi = ptr_states[ptr]
        init_state: Dict[str, PtrState] = {ptr: PtrState.LIVE}
        for alias in engine._all_aliases(ptr):
            if alias not in init_state:
                init_state[alias] = PtrState.LIVE

        uaf_paths = 0
        safe_paths = 0
        total_paths = 0
        uaf_use_line = 0
        guarded = False

        def analyze_segment(start: int, end: int,
                            state: Dict[str, PtrState]) -> Tuple[int, int, int, int, Dict[str, PtrState], bool]:
            """递归分析 [start, end) 行区间.

            Returns: (uaf, safe, total, use_line, final_state, guarded)
            """
            st = dict(state)
            u = 0
            s = 0
            t = 0
            ul = 0
            g = False
            i = start

            while i < end:
                line = lines[i].strip()
                idx = i

                # 检查 if/while/for 条件行
                is_cond = (line.startswith('if ') or line.startswith('if(')
                           or line.startswith('while ') or line.startswith('while(')
                           or line.startswith('for ') or line.startswith('for('))

                if is_cond:
                    then_s, then_e, else_s, else_e, merge = \
                        find_branch_bodies(lines, i)
                    if then_s < 0:
                        i += 1
                        continue

                    # Fork: 两个分支各自独立分析
                    then_u, then_safe, then_t, then_ul, then_st, then_g = \
                        analyze_segment(then_s, then_e, st)
                    u += then_u
                    s += then_safe
                    t += then_t
                    if then_ul:
                        ul = then_ul
                    g = g or then_g

                    if else_s >= 0:
                        else_u, else_safe, else_t, else_ul, else_st, else_g = \
                            analyze_segment(else_s, else_e, st)
                        u += else_u
                        s += else_safe
                        t += else_t
                        if else_ul:
                            ul = else_ul
                        g = g or else_g
                        # Join: 两分支状态做保守汇合
                        all_ptrs = set(list(st.keys()) + list(then_st.keys()) + list(else_st.keys()))
                        for pn in all_ptrs:
                            pre_s = st.get(pn, PtrState.LIVE)
                            then_s = then_st.get(pn, pre_s)
                            else_s2 = else_st.get(pn, pre_s)
                            st[pn] = join_ptr_states(then_s, else_s2)
                    else:
                        # 无else: skip路径状态=st(未变), then路径状态=then_st
                        all_ptrs = set(list(st.keys()) + list(then_st.keys()))
                        for pn in all_ptrs:
                            pre_s = st.get(pn, PtrState.LIVE)
                            then_s = then_st.get(pn, pre_s)
                            st[pn] = join_ptr_states(pre_s, then_s)

                    i = merge if merge > i else i + 1
                    continue

                # 普通语句: 处理操作, 更新状态
                ops = parse_line_operations(line)
                st, result = apply_ptr_ops(ops, st, ptr, idx, engine)
                if result == 'uaf':
                    u += 1
                    t += 1
                    ul = idx + 1
                elif result == 'safe':
                    s += 1
                    t += 1
                elif result == 'guard':
                    g = True
                elif result == 'neutral':
                    t += 1

                i += 1

            return u, s, max(t, 1), ul, st, g

        uaf, safe, total, use_l, final_state, guard = \
            analyze_segment(0, len(lines), init_state)

        uaf_paths = uaf
        safe_paths = safe
        total_paths = total
        uaf_use_line = use_l
        guarded = guard

        # 汇总结果
        r = PTASMResult(
            ptr_name=ptr,
            verdict=ptr_states[ptr].state,
            free_line=pi.free_line,
            use_line=uaf_use_line,
            guarded=guarded,
        )

        if uaf_paths > 0:
            r.uaf_detected = True
            r.verdict = PtrState.USE_AFTER_FREE
            r.reason = (f"UAF confirmed: {ptr} used after free "
                       f"on {uaf_paths}/{total_paths} explored paths "
                       f"(free@L{pi.free_line}, use@L{r.use_line})")
        elif safe_paths > 0:
            r.safe = True
            r.verdict = PtrState.NULLIFIED
            r.reason = (f"SAFE: {ptr} nullified/reassigned on "
                       f"{safe_paths}/{total_paths} paths, 0 UAF paths")
        else:
            r.reason = (f"UNCERTAIN: {ptr} freed@L{pi.free_line}, "
                       f"{uaf_paths}u/{safe_paths}s/{total_paths}t paths")

        aliases = engine._all_aliases(ptr) - {ptr}
        r.aliases_involved = list(aliases)
        if aliases:
            r.reason += f", aliases: {aliases}"

        results.append(r)

    return results
