from __future__ import annotations

# PSDCP — 路径敏感按需约束传播堆溢出检测器
# 五维度联合短路判定: 分配器语义 / 路径约束 / 循环区间 / 过程间传播 / 多维联合

import re
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from analysis.interval_domain import Interval
from analysis.lpvra_types import Verdict, AllocInfo, WriteInfo, HeapVerdict


# ptmalloc2 常量
_MINSIZE = 32
_MALLOC_ALIGNMENT = 16
_FASTBIN_MAX = 128
_MMAP_THRESHOLD = 1 << 20  # 1MB


def _usable_size(req: int) -> int:
    # glibc ptmalloc2 request2size: 对齐到16, 最小MINSIZE
    if req <= 0:
        return 0
    aligned = ((req + _MALLOC_ALIGNMENT - 1) // _MALLOC_ALIGNMENT) * _MALLOC_ALIGNMENT
    return max(aligned, _MINSIZE)


def _effective_boundary(req: int) -> int:
    # 可用边界 = usable_size - SIZE_SZ(8)
    return _usable_size(req) - 8


# 路径约束: (变量, 操作符, 常量)
class CmpOp(Enum):
    LT = '<'
    LE = '<='
    GT = '>'
    GE = '>='
    EQ = '=='
    NEQ = '!='


@dataclass
class PathConstraint:
    var: str
    op: CmpOp
    val: int

    def negate(self) -> 'PathConstraint':
        # 分支否定: 取 else 路径的约束
        neg = {CmpOp.LT: CmpOp.GE, CmpOp.LE: CmpOp.GT,
               CmpOp.GT: CmpOp.LE, CmpOp.GE: CmpOp.LT,
               CmpOp.EQ: CmpOp.NEQ, CmpOp.NEQ: CmpOp.EQ}
        return PathConstraint(self.var, neg[self.op], self.val)

    def apply(self, iv: Interval) -> Interval:
        if self.op == CmpOp.LT:
            return iv.constrain_lt(self.val)
        if self.op == CmpOp.LE:
            return iv.constrain_le(self.val)
        if self.op == CmpOp.GT:
            return iv.constrain_gt(self.val)
        if self.op == CmpOp.GE:
            return iv.meet(Interval.range_of(self.val, 2**31 - 1))
        if self.op == CmpOp.EQ:
            return iv.meet(Interval.const(self.val))
        return iv


# 阈值加宽序列
_WIDEN_THRESHOLDS = [8, 16, 32, 64, 128, 256, 512, 1024,
                     2048, 4096, 8192, 16384, 32768, 65536,
                     131072, 262144, 524288, 1048576]


def _threshold_widen(iv: Interval) -> Interval:
    # 从预设阈值序列中找最小覆盖上界
    if iv.is_top() or iv.is_bottom():
        return iv
    if iv.hi is None:
        return Interval.top()
    for t in _WIDEN_THRESHOLDS:
        if iv.hi <= t:
            return Interval.range_of(iv.lo or 0, t)
    return Interval.top()


# 循环归纳变量检测
_LOOP_HEADER_RE = re.compile(
    r'for\s*\(\s*(\w[\w]*)\s*=\s*(\d+)\s*;\s*\1\s*(<|<=)\s*(\w[\w]*|\d+)\s*;',
    re.IGNORECASE)

_WHILE_HEADER_RE = re.compile(
    r'while\s*\(\s*(\w[\w]*)\s*(<|<=)\s*(\w[\w]*|\d+)\s*\)',
    re.IGNORECASE)

_INC_RE = re.compile(r'(\w[\w]*)\s*(\+\+|\+=\s*(\d+))')
_DEC_RE = re.compile(r'(\w[\w]*)\s*(--|-=\s*(\d+))')


@dataclass
class LoopInfo:
    var: str
    init_val: int
    bound_var: str
    bound_val: int
    step: int
    is_const_bound: bool


def _detect_loop(header_line: str) -> Optional[LoopInfo]:
    m = _LOOP_HEADER_RE.search(header_line)
    if m:
        var = m.group(1)
        init = int(m.group(2))
        op = m.group(3)
        bound = m.group(4)
        try:
            bv = int(bound)
            is_const = True
        except ValueError:
            bv = 0
            is_const = False
        return LoopInfo(var, init, bound if not is_const else "", bv, 1, is_const)
    m = _WHILE_HEADER_RE.search(header_line)
    if m:
        var = m.group(1)
        bound = m.group(3)
        try:
            bv = int(bound)
            is_const = True
        except ValueError:
            bv = 0
            is_const = False
        return LoopInfo(var, 0, bound if not is_const else "", bv, 1, is_const)
    return None


# 分支深度限制
_MAX_BRANCH_DEPTH = 3
# 过程间递归深度限制
_MAX_INTERPROC_DEPTH = 3
# 每函数缓存上下文上限
_MAX_CONTEXTS = 16


# 过程间摘要
@dataclass
class FuncSummary:
    name: str
    params: List[str]
    # 形参角色: size_ptr / heap_ptr / len_param / unknown
    param_roles: Dict[str, str]
    # 已知常量参数绑定
    const_bindings: Dict[str, int]


_FUNC_DEF_RE = re.compile(
    r'(?:void|int|char|size_t|unsigned|long|short|float|double)\s*\*?\s*(\w[\w]*)\s*\(([^)]*)\)')


def _extract_funcs(lines: List[str]) -> Dict[str, FuncSummary]:
    funcs = {}
    for i, line in enumerate(lines):
        m = _FUNC_DEF_RE.search(line)
        if m and '{' in lines[i] if i < len(lines) else False:
            name = m.group(1)
            params_str = m.group(2).strip()
            if not params_str or params_str == 'void':
                params = []
            else:
                params = [p.strip().split()[-1].lstrip('*')
                          for p in params_str.split(',')]
            roles = {}
            for p in params:
                pl = p.lower()
                if 'size' in pl or 'len' in pl or 'count' in pl or 'n' == pl:
                    roles[p] = 'len_param'
                elif 'buf' in pl or 'ptr' in pl or 'dst' in pl or 'src' in pl:
                    roles[p] = 'heap_ptr'
                else:
                    roles[p] = 'unknown'
            funcs[name] = FuncSummary(name, params, roles, {})
    return funcs


# cmp+jcc 约束提取
_CMP_RE = re.compile(
    r'(?:if|while|for)\s*\(\s*(\w[\w]*)\s*(<|<=|>|>=|==|!=)\s*(\d+)\s*\)')


def _extract_constraints(line: str) -> Optional[PathConstraint]:
    m = _CMP_RE.search(line)
    if m:
        var = m.group(1)
        op_str = m.group(2)
        val = int(m.group(3))
        op_map = {'<': CmpOp.LT, '<=': CmpOp.LE,
                  '>': CmpOp.GT, '>=': CmpOp.GE,
                  '==': CmpOp.EQ, '!=': CmpOp.NEQ}
        return PathConstraint(var, op_map[op_str], val)
    return None


_ALLOC_RE = re.compile(
    r'(\w[\w]*)\s*=\s*(?:\([^)]*\)\s*)?(malloc|calloc|realloc)\s*\(\s*(\d+|\w[\w]*)',
    re.IGNORECASE)

_WRITE_RE = re.compile(
    r'(memcpy|strcpy|strncpy|memset|memmove|sprintf|snprintf|fread|recv|read)\s*\(\s*(\w[\w]*)',
    re.IGNORECASE)

_WRITE_SIZE_RE = re.compile(
    r'(?:memcpy|strncpy|memset|memmove|snprintf|fread|recv|read)'
    r'\s*\([^,]+,\s*[^,]+,\s*(\d+|\w[\w]*)')

_ARRAY_STORE_RE = re.compile(r'(\w[\w]*)\s*\[\s*(\d+|\w[\w]*)\s*\]\s*=')


@dataclass
class PSDCPResult:
    allocs: List[AllocInfo] = field(default_factory=list)
    writes: List[WriteInfo] = field(default_factory=list)
    verdicts: List[HeapVerdict] = field(default_factory=list)
    dim_stats: Dict[str, int] = field(default_factory=dict)


class PSDCPEngine:
    # 五维度联合短路判定引擎
    # D1 分配器语义: usable_size 直接判安全
    # D2 路径约束: cmp+jcc 线性不等式交集
    # D3 循环区间: 阈值加宽+收窄
    # D4 过程间: 有界摘要传播
    # D5 多维联合: 短路 SAFE→过滤

    def __init__(self, max_paths: int = 256,
                 max_branch_depth: int = _MAX_BRANCH_DEPTH,
                 max_interproc: int = _MAX_INTERPROC_DEPTH):
        self._max_paths = max_paths
        self._max_branch = max_branch_depth
        self._max_interproc = max_interproc
        self._func_summaries: Dict[str, FuncSummary] = {}
        self._context_cache: Dict[str, List] = {}
        self._paths_explored = 0

    def analyze(self, source: str) -> PSDCPResult:
        lines = source.splitlines()
        allocs = self._find_allocs(lines)
        writes = self._find_writes(lines)
        if not allocs or not writes:
            return PSDCPResult(allocs=allocs, writes=writes)

        self._func_summaries = _extract_funcs(lines)
        blocks, adj = self._build_cfg(lines)
        if not blocks:
            return PSDCPResult(allocs=allocs, writes=writes)

        # 正向传播: 计算每个块入口的抽象状态
        block_entry_state = self._forward_propagate(blocks, adj, lines)

        verdicts: List[HeapVerdict] = []
        dim_stats: Dict[str, int] = {
            'D1_safe': 0, 'D2_safe': 0, 'D3_safe': 0,
            'D4_safe': 0, 'D5_uncertain': 0, 'D5_overflow': 0,
        }

        for ai in allocs:
            for wi in writes:
                if wi.var != ai.var:
                    continue
                v = self._check_pair(ai, wi, lines, blocks, adj,
                                     block_entry_state, dim_stats)
                if v:
                    verdicts.append(v)

        return PSDCPResult(
            allocs=allocs, writes=writes, verdicts=verdicts,
            dim_stats=dim_stats)

    def _find_allocs(self, lines: List[str]) -> List[AllocInfo]:
        allocs = []
        for i, line in enumerate(lines, start=1):
            m = _ALLOC_RE.search(line)
            if not m:
                continue
            var = m.group(1)
            func = m.group(2).lower()
            sz = m.group(3)
            size_var = ""
            size_const = 0
            try:
                size_const = int(sz)
            except ValueError:
                size_var = sz
            allocs.append(AllocInfo(i, var, func, size_var, size_const))
        return allocs

    def _find_writes(self, lines: List[str]) -> List[WriteInfo]:
        writes = []
        for i, line in enumerate(lines, start=1):
            wm = _WRITE_RE.search(line)
            if wm:
                var = wm.group(2)
                op = wm.group(1).lower()
                size = -1
                size_var = ""
                sz_m = _WRITE_SIZE_RE.search(line)
                if sz_m:
                    try:
                        size = int(sz_m.group(1))
                    except ValueError:
                        size_var = sz_m.group(1)
                writes.append(WriteInfo(i, var, 0, size, op, size_var))
                continue
            am = _ARRAY_STORE_RE.search(line)
            if am:
                var = am.group(1)
                try:
                    offset = int(am.group(2))
                except ValueError:
                    offset = -1
                writes.append(WriteInfo(i, var, offset, 1, 'store'))
        return writes

    def _build_cfg(self, lines: List[str]) -> Tuple[List[Dict], Dict[int, List[int]]]:
        from analysis.lpvra_types import _is_ctrl, build_simple_cfg
        return build_simple_cfg(lines)

    def _forward_propagate(self, blocks: List[Dict],
                           adj: Dict[int, List[int]],
                           lines: List[str]) -> Dict[int, Dict[str, Interval]]:
        # 正向区间传播: 从入口块传播到所有可达块
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
            state_out = self._process_block(blocks[bid], state_in, lines, 0)
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
        varset: Set[str] = set()
        for b in blocks:
            for s in b['stmts']:
                am = re.search(r'(\w[\w]*)\s*=\s*(?:.*?)malloc', s)
                if am:
                    varset.add(am.group(1))
                sm = re.search(r'malloc\s*\(\s*(\w[\w]*)', s)
                if sm and not sm.group(1).isdigit():
                    varset.add(sm.group(1))
                aim = re.match(r'(?:\w+\s+)*(\w[\w]*)\s*=', s)
                if aim and not s.strip().startswith('if'):
                    varset.add(aim.group(1))
        return varset

    def _check_pair(self, ai: AllocInfo, wi: WriteInfo,
                    lines: List[str], blocks: List[Dict],
                    adj: Dict[int, List[int]],
                    block_entry_state: Dict[int, Dict[str, Interval]],
                    dim_stats: Dict[str, int]) -> Optional[HeapVerdict]:
        alloc_block = -1
        write_block = -1
        for b in blocks:
            # alloc/write 行号是 1-based, block start/end 是 0-based
            if b['start'] <= ai.line_no - 1 <= b['end']:
                alloc_block = b['id']
            if b['start'] <= wi.line_no - 1 <= b['end']:
                write_block = b['id']
        if alloc_block < 0 or write_block < 0:
            return None

        # D1: 分配器语义 — 常量分配直接判
        if ai.size_const > 0:
            usable = _usable_size(ai.size_const)
            boundary = _effective_boundary(ai.size_const)
            # offset >= requested && offset+size <= usable → padding 合法
            if wi.offset >= ai.size_const and wi.offset + max(wi.size, 1) <= usable:
                dim_stats['D1_safe'] += 1
                return HeapVerdict(
                    ai.var, ai.line_no, Interval.const(ai.size_const),
                    wi.var, wi.line_no, wi.offset, wi.size,
                    boundary, Verdict.SAFE, 1, 1,
                    "D1: allocator padding safe")
            # offset+size <= usable → 安全
            if wi.size > 0 and wi.offset + wi.size <= usable:
                dim_stats['D1_safe'] += 1
                return HeapVerdict(
                    ai.var, ai.line_no, Interval.const(ai.size_const),
                    wi.var, wi.line_no, wi.offset, wi.size,
                    boundary, Verdict.SAFE, 1, 1,
                    "D1: within usable_size")

        # 同变量大小: alloc(n)+memcpy(,,n) → D1 短路
        if wi.size < 0 and wi.size_var and wi.size_var == ai.size_var:
            if ai.size_const > 0:
                boundary = _effective_boundary(ai.size_const)
                if ai.size_const <= boundary:
                    dim_stats['D1_safe'] += 1
                    return HeapVerdict(
                        ai.var, ai.line_no, Interval.const(ai.size_const),
                        wi.var, wi.line_no, wi.offset, wi.size,
                        boundary, Verdict.SAFE, 1, 1,
                        "D1: same-var size ≤ usable boundary")

        # 路径敏感探索
        safe_count = 0
        overflow_count = 0
        uncertain_count = 0
        total = 0

        init_state: Dict[str, Interval] = dict(
            block_entry_state.get(alloc_block, {}))
        if ai.size_const > 0:
            init_state[ai.var] = Interval.const(ai.size_const)
        elif ai.size_var:
            init_state[ai.size_var] = Interval.top()
            init_state[ai.var] = Interval.top()

        q: deque = deque()
        q.append((alloc_block, dict(init_state), 0))
        visited: Set = set()

        while q and total < self._max_paths:
            cur_bid, state, depth = q.popleft()
            state_key = (cur_bid, depth, tuple(sorted(
                (k, v.lo, v.hi) for k, v in state.items()
                if not v.is_top())))
            if state_key in visited:
                continue
            visited.add(state_key)

            if cur_bid == write_block:
                # 路径不可达: 约束矛盾导致区间为空, 跳过
                if any(v.is_bottom() for v in state.values()):
                    continue
                # 先处理当前块, 使块内赋值反映到状态中
                wb = blocks[cur_bid] if cur_bid < len(blocks) else None
                eval_state = (self._process_block(wb, state, lines, depth)
                              if wb is not None else state)
                v = self._evaluate_multi_dim(
                    ai, wi, eval_state, lines, dim_stats)
                if v == Verdict.SAFE:
                    safe_count += 1
                elif v == Verdict.OVERFLOW:
                    overflow_count += 1
                else:
                    uncertain_count += 1
                total += 1
                continue

            b = blocks[cur_bid] if cur_bid < len(blocks) else None
            if b is None:
                continue
            # 检查是否为条件分支块 — fork 状态
            first_stmt = (b['stmts'][0].strip() if b['stmts'] else '')
            pc = _extract_constraints(first_stmt) if first_stmt.startswith('if') else None

            if pc is not None and depth < self._max_branch:
                # 真分支: 应用约束
                true_state = dict(state)
                if pc.var in true_state:
                    true_state[pc.var] = pc.apply(true_state[pc.var])
                true_state = self._process_block(b, true_state, lines, depth + 1)
                for sid in adj.get(cur_bid, []):
                    q.append((sid, dict(true_state), depth + 1))

                # 假分支: 应用否定约束
                false_state = dict(state)
                npc = pc.negate()
                if npc.var in false_state:
                    false_state[npc.var] = npc.apply(false_state[npc.var])
                # 假分支跳过 if-body, 直接到 else 或 merge 块
                for sid in adj.get(cur_bid, []):
                    if sid != (blocks[cur_bid + 1]['id']
                               if cur_bid + 1 < len(blocks) else -1):
                        q.append((sid, dict(false_state), depth + 1))
                # 也探索假分支的直接后继
                if cur_bid + 1 < len(blocks):
                    false_state_proc = self._process_block(
                        blocks[cur_bid + 1], false_state, lines, depth + 1)
                    # 假分支的后续块
                    for sid in adj.get(blocks[cur_bid + 1]['id'], []):
                        q.append((sid, dict(false_state_proc), depth + 1))
            else:
                new_state = self._process_block(b, state, lines, depth)
                for sid in adj.get(cur_bid, []):
                    q.append((sid, dict(new_state), depth))

        boundary = _effective_boundary(ai.size_const) if ai.size_const > 0 else 0
        alloc_iv = (Interval.const(ai.size_const) if ai.size_const > 0
                     else init_state.get(ai.size_var, Interval.top()))

        if total == 0:
            return HeapVerdict(
                ai.var, ai.line_no, alloc_iv,
                wi.var, wi.line_no, wi.offset, wi.size,
                boundary, Verdict.UNCERTAIN, 0, 0,
                "no reachable paths")

        if safe_count == total and total > 0:
            return HeapVerdict(
                ai.var, ai.line_no, alloc_iv,
                wi.var, wi.line_no, wi.offset, wi.size,
                boundary, Verdict.SAFE, safe_count, total,
                f"all {safe_count}/{total} paths safe")

        if overflow_count == total:
            dim_stats['D5_overflow'] += 1
            return HeapVerdict(
                ai.var, ai.line_no, alloc_iv,
                wi.var, wi.line_no, wi.offset, wi.size,
                boundary, Verdict.OVERFLOW, 0, total,
                f"{overflow_count}/{total} paths overflow")

        dim_stats['D5_uncertain'] += 1
        return HeapVerdict(
            ai.var, ai.line_no, alloc_iv,
            wi.var, wi.line_no, wi.offset, wi.size,
            boundary, Verdict.UNCERTAIN, safe_count, total,
            f"mixed: {safe_count}s/{overflow_count}o/{uncertain_count}u")

    def _process_block(self, block: Dict, state: Dict[str, Interval],
                       lines: List[str], depth: int) -> Dict[str, Interval]:
        result = dict(state)
        # 按 ; 分割子语句, 剥离大括号/函数声明前缀
        sub_stmts: List[str] = []
        for stmt in block['stmts']:
            clean = stmt
            # 剥离函数声明前缀: void f(){... → ...
            brace = clean.find('{')
            if brace >= 0:
                clean = clean[brace + 1:]
            clean = clean.replace('{', '').replace('}', '')
            parts = clean.split(';')
            for p in parts:
                p = p.strip()
                if p:
                    sub_stmts.append(p)
        for s in sub_stmts:

            # D3: 循环归纳变量 — 阈值加宽
            loop = _detect_loop(s)
            if loop:
                if loop.is_const_bound and loop.bound_val > 0:
                    result[loop.var] = Interval.range_of(
                        loop.init_val, loop.bound_val - 1)
                else:
                    result[loop.var] = _threshold_widen(
                        Interval.range_of(loop.init_val, 1 << 16))
                continue

            # D2: 路径约束收集
            pc = _extract_constraints(s)
            if pc:
                if pc.var in result:
                    result[pc.var] = pc.apply(result[pc.var])
                continue

            # malloc 赋值
            m = _ALLOC_RE.search(s)
            if m:
                var = m.group(1)
                sz = m.group(3)
                try:
                    n = int(sz)
                    result[var] = Interval.const(_usable_size(n))
                except ValueError:
                    if sz in result:
                        result[var] = result[sz]
                continue

            # 算术赋值
            am = re.match(r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*([+\-])\s*(\d+)\s*;?', s)
            if am and not s.startswith('if'):
                v1, v2, op, delta = (am.group(1), am.group(2),
                                     am.group(3), int(am.group(4)))
                if v2 in result:
                    d = delta if op == '+' else -delta
                    src = result[v2]
                    lo = (src.lo + d) if src.lo is not None else None
                    hi = (src.hi + d) if src.hi is not None else None
                    result[v1] = Interval(lo=lo, hi=hi)
                continue

            # 简单赋值 (含可选类型前缀: int n = 64; / n = 64;)
            am2 = re.match(r'(?:\w+\s+)*(\w[\w]*)\s*=\s*(\d+|\w[\w]*)\s*;?', s)
            if am2 and not s.startswith('if') and not s.startswith('for'):
                var, rhs = am2.group(1), am2.group(2)
                try:
                    result[var] = Interval.const(int(rhs))
                except ValueError:
                    if rhs in result:
                        result[var] = result[rhs]

        return result

    def _evaluate_multi_dim(self, ai: AllocInfo, wi: WriteInfo,
                             state: Dict[str, Interval],
                             lines: List[str],
                             dim_stats: Dict[str, int]) -> Verdict:
        # D1 已在调用前短路, 这里做 D2-D5

        # 获取分配大小区间
        if ai.size_const > 0:
            size_iv = Interval.const(ai.size_const)
        elif ai.size_var and ai.size_var in state:
            size_iv = state[ai.size_var]
        elif ai.var in state:
            size_iv = state[ai.var]
        else:
            size_iv = Interval.top()

        # D3: 循环区间 — 阈值加宽后的上界 ≤ 分配大小 → 安全
        if not size_iv.is_top() and size_iv.hi is not None:
            widened = _threshold_widen(size_iv)
            if widened.hi is not None:
                usable = _usable_size(widened.hi)
                if wi.size > 0 and wi.offset + wi.size <= usable:
                    dim_stats['D3_safe'] += 1
                    return Verdict.SAFE
                # 同变量写入
                if wi.size < 0 and wi.size_var == ai.size_var:
                    if widened.hi <= usable:
                        dim_stats['D3_safe'] += 1
                        return Verdict.SAFE

        # D2: 路径约束交集后的区间判定
        if not size_iv.is_top():
            boundary = _effective_boundary(size_iv.hi) if size_iv.hi else 0
            if wi.size > 0:
                total_write = wi.offset + wi.size
                if total_write <= boundary:
                    dim_stats['D2_safe'] += 1
                    return Verdict.SAFE
                if size_iv.hi is not None and total_write > size_iv.hi:
                    # 约束收紧后仍超出 → 确认溢出
                    return Verdict.OVERFLOW
            # 同变量大小: malloc(n)+memcpy(,,n), n ≤ usable_size(n) → 安全
            if wi.size < 0 and wi.size_var == ai.size_var:
                if size_iv.hi is not None:
                    usable = _usable_size(size_iv.hi)
                    if size_iv.hi <= usable:
                        dim_stats['D2_safe'] += 1
                        return Verdict.SAFE
            # 常量分配 + 变量写入: malloc(C)+memcpy(,,v)
            if wi.size < 0 and wi.size_var and wi.size_var != ai.size_var:
                wiv = state.get(wi.size_var, Interval.top())
                if not wiv.is_top() and wiv.hi is not None:
                    usable = _usable_size(size_iv.hi) if size_iv.hi else 0
                    if wiv.hi <= usable:
                        dim_stats['D2_safe'] += 1
                        return Verdict.SAFE
                    if wiv.lo is not None and wiv.lo > usable:
                        return Verdict.OVERFLOW

        # D4: 过程间 — 简化为函数摘要常量绑定检查
        if ai.size_var and ai.size_var in state:
            iv = state[ai.size_var]
            if iv.is_const() and iv.const_val() is not None:
                cv = iv.const_val()
                if cv > 0:
                    boundary = _effective_boundary(cv)
                    if wi.size > 0 and wi.offset + wi.size <= boundary:
                        dim_stats['D4_safe'] += 1
                        return Verdict.SAFE

        # D5: 无法证明安全 → 保守保留
        if size_iv.is_top():
            return Verdict.UNCERTAIN
        if size_iv.hi is not None and wi.size > 0:
            if wi.offset + wi.size > size_iv.hi:
                return Verdict.OVERFLOW
        return Verdict.UNCERTAIN


__all__ = [
    'PSDCPEngine', 'PSDCPResult', 'PathConstraint', 'CmpOp',
    'LoopInfo', 'FuncSummary',
    '_usable_size', '_effective_boundary',
]
