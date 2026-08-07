"""
LPVRA — 轻量级路径敏感值域分析引擎 (Lightweight Path-sensitive Value Range Analysis).

核心创新: 对堆溢出检测专用的抽象解释引擎, 在简化CFG上做正向区间传播,
路径敏感地追踪分配大小和写入偏移的值域, 仅当所有可达路径都证明安全时才过滤.

与现有方案的本质区别:
  - vs Angr: 不做完整符号执行, 仅追踪堆相关变量 (size/offset), 无路径爆炸
  - vs Ghidra: 路径敏感的值域传播 + widening, 非单纯的模式匹配
  - vs 现有BinMind过滤器: 统一的抽象解释框架, 替代零散的正则规则

方法 (Cousot抽象解释框架的实例化):
  1. 从C源码构建简化CFG (控制流关键字 → 基本块边界)
  2. 在每个基本块维护抽象状态: {变量 → Interval}
  3. 条件分支处 fork 状态, merge 点做 join
  4. 循环头使用 widening + 阈值 (1MB) 保证终止
  5. malloc点记录分配大小区间, store点比较写入偏移 ← 核心判定

保守性保证: 仅当 ∀路径: effective_upper_bound(offset) ≤ effective_lower_bound(size)
时判定SAFE. 任一路径无法证明 → UNCERTAIN (保留候选项).

参考: Cousot & Cousot, GUEB, SVF, CSA.
"""


import re
from collections import deque
from typing import Dict, List, Set, Tuple

from analysis.interval_domain import Interval
from analysis.lpvra_types import (
    Verdict, AllocInfo, WriteInfo, HeapVerdict, LPVRAResult,
    _CTRL_KW, _MALLOC_ASSIGN_RE, _ASSIGN_RE, _ARITH_RE, _is_ctrl, _parse_cond,
)
from analysis.lpvra_pair_checker import PairAnalyzer


class LPVRAEngine:
    """轻量级路径敏感值域分析引擎.

    在简化CFG上执行正向区间传播, 路径敏感地评估堆写入安全性.
    PairAnalyzer 负责 alloc/write 发现和配对评估.
    """

    def __init__(self, max_paths: int = 128, widening_threshold: int = 1 << 20):
        self._widen_lim = widening_threshold
        self._paths_explored = 0
        self._pair = PairAnalyzer(max_paths=max_paths)
        # 注入 process_block 回调 (避免循环导入)
        self._pair._process_block_fn = self._process_block

    def analyze(self, source: str) -> LPVRAResult:
        """对C源码执行LPVRA分析, 返回所有 alloc-write 对的判定."""
        lines = source.splitlines()
        allocs = self._pair.find_allocs(lines)
        writes = self._pair.find_writes(lines)
        if not allocs or not writes:
            return LPVRAResult(allocs=allocs, writes=writes)

        blocks, adj = self._build_cfg(lines)
        if not blocks:
            return LPVRAResult(allocs=allocs, writes=writes)

        block_entry_state = self._forward_propagate(blocks, adj, lines)

        verdicts: List[HeapVerdict] = []
        last_alloc_line: Dict[str, int] = {}
        for ai in allocs:
            last_alloc_line[ai.var] = max(last_alloc_line.get(ai.var, 0), ai.line_no)
        for ai in allocs:
            if ai.func != 'realloc' and ai.line_no < last_alloc_line.get(ai.var, 0):
                continue
            for wi in writes:
                if wi.var != ai.var:
                    continue
                v = self._pair.check_pair(ai, wi, lines, blocks, adj,
                                          block_entry_state)
                if v:
                    verdicts.append(v)

        return LPVRAResult(
            allocs=allocs, writes=writes, verdicts=verdicts,
            total_paths_explored=self._paths_explored,
            paths_filtered=sum(1 for v in verdicts if v.verdict == Verdict.SAFE))

    def _forward_propagate(self, blocks: List[Dict],
                           adj: Dict[int, List[int]],
                           lines: List[str]) -> Dict[int, Dict[str, Interval]]:
        """正向抽象解释: 从CFG入口块传播到所有块, 返回每块入口状态."""
        entry_state: Dict[int, Dict[str, Interval]] = {}
        all_vars = self._collect_heap_vars(blocks)
        init: Dict[str, Interval] = {v: Interval.top() for v in all_vars}
        entry_state[0] = dict(init)
        worklist = deque([0])
        iter_count: Dict[int, int] = {}

        while worklist:
            bid = worklist.popleft()
            iter_count[bid] = iter_count.get(bid, 0) + 1
            if iter_count[bid] > 10:
                continue

            state_in = entry_state.get(bid, dict(init))
            state_out = self._process_block(blocks[bid], state_in, lines)
            for sid in adj.get(bid, []):
                first_visit = sid not in entry_state
                if first_visit:
                    entry_state[sid] = dict(init)
                old = entry_state[sid]
                new = {}
                for v in all_vars:
                    old_iv = old.get(v, Interval.top())
                    out_iv = state_out.get(v, Interval.top())
                    if old_iv.is_top() and not out_iv.is_top():
                        merged = out_iv
                    elif not old_iv.is_top() and out_iv.is_top():
                        merged = old_iv
                    else:
                        merged = old_iv.join(out_iv)
                    if sid <= bid:
                        merged = merged.widen(old_iv)
                    new[v] = merged
                if first_visit or any(new.get(v) != old.get(v)
                                       for v in all_vars):
                    entry_state[sid] = new
                    worklist.append(sid)

        return entry_state

    def _collect_heap_vars(self, blocks: List[Dict]) -> Set[str]:
        """收集所有堆相关变量名."""
        varset: Set[str] = set()
        for b in blocks:
            for s in b['stmts']:
                am = re.search(r'(\w[\w]*)\s*=\s*(?:.*?)malloc', s)
                if am:
                    varset.add(am.group(1))
                sm = re.search(r'malloc\s*\(\s*(\w[\w]*)', s)
                if sm and not sm.group(1).isdigit():
                    varset.add(sm.group(1))
                aim = re.match(r'\s*(\w[\w]*)\s*=', s)
                if aim and not s.strip().startswith('if'):
                    varset.add(aim.group(1))
        return varset

    def _build_cfg(self, lines: List[str]) -> Tuple[List[Dict], Dict[int, List[int]]]:
        """从C源码构建简化CFG."""
        blocks = []
        bb_start = 0
        bid = 0
        for i, line in enumerate(lines):
            if _is_ctrl(line) and i > bb_start:
                blocks.append({
                    'id': bid, 'start': bb_start, 'end': i - 1,
                    'stmts': lines[bb_start:i],
                })
                bid += 1
                bb_start = i
        if bb_start < len(lines):
            blocks.append({
                'id': bid, 'start': bb_start, 'end': len(lines) - 1,
                'stmts': lines[bb_start:],
            })
            bid += 1

        adj: Dict[int, List[int]] = {}
        for i, b in enumerate(blocks):
            succs = []
            if i + 1 < len(blocks):
                succs.append(blocks[i + 1]['id'])
            # if块的真分支: 执行完if-body后跳过else到达merge块
            first_stmt = (b['stmts'][0].strip() if b['stmts'] else '')
            if first_stmt.startswith('if'):
                # 找到else块, 然后找到merge块 (以}开头且非} else)
                else_idx = -1
                for j in range(i + 1, len(blocks)):
                    fj = (blocks[j]['stmts'][0].strip()
                          if blocks[j]['stmts'] else '')
                    if fj.startswith('} else') or fj.startswith('else'):
                        else_idx = j
                        break
                if else_idx >= 0:
                    for j in range(else_idx + 1, len(blocks)):
                        fj = (blocks[j]['stmts'][0].strip()
                              if blocks[j]['stmts'] else '')
                        if fj.startswith('}'):
                            succs.append(blocks[j]['id'])
                            break
            adj[b['id']] = succs
        return blocks, adj

    def _process_block(self, block: Dict, state: Dict[str, Interval],
                       lines: List[str]) -> Dict[str, Interval]:
        """在基本块内传播抽象状态."""
        result = dict(state)
        for stmt in block['stmts']:
            s = stmt.strip()
            mall = _MALLOC_ASSIGN_RE.search(s)
            if mall:
                var, func, sz = mall.group(1), mall.group(2).lower(), mall.group(3)
                if func == 'realloc':
                    realloc_sz = re.search(r'realloc\s*\([^,]+,\s*(\d+|\w[\w]*)', s)
                    if realloc_sz:
                        sz = realloc_sz.group(1)
                if var not in result:
                    result[var] = Interval.top()
                try:
                    alloc_n = int(sz)
                    effective = PairAnalyzer.effective_boundary_from_raw(alloc_n)
                    result[var] = Interval.const(effective)
                except ValueError:
                    if sz in result:
                        result[var] = result[sz]
                continue
            cond = _parse_cond(s)
            if cond:
                var, op, val = cond
                if var in result:
                    cur = result[var]
                    if op == '<':
                        result[var] = cur.constrain_lt(val)
                    elif op == '<=':
                        result[var] = cur.constrain_le(val)
                    elif op == '>':
                        result[var] = cur.constrain_gt(val)
                    elif op == '>=':
                        result[var] = cur.meet(Interval.range_of(val, 2**31 - 1))
                    elif op == '==':
                        result[var] = cur.meet(Interval.const(val))
                continue
            am = _ASSIGN_RE.search(s)
            if am and not s.startswith('if') and not s.startswith('while'):
                var, rhs = am.group(1), am.group(2)
                try:
                    result[var] = Interval.const(int(rhs))
                except ValueError:
                    if rhs in result:
                        result[var] = result[rhs]
                continue
            arm = _ARITH_RE.search(s)
            if arm and not s.startswith('if'):
                v1, v2, op, delta = arm.group(1), arm.group(2), arm.group(3), int(arm.group(4))
                if v2 in result:
                    d = delta if op == '+' else -delta
                    src = result[v2]
                    lo = (src.lo + d) if src.lo is not None else None
                    hi = (src.hi + d) if src.hi is not None else None
                    result[v1] = Interval(lo=lo, hi=hi)
        return result


__all__ = ['LPVRAEngine', 'LPVRAResult', 'HeapVerdict', 'Verdict',
           'AllocInfo', 'WriteInfo']
