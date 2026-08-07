# 循环累积拷贝上界——用迭代上界×单次拷贝量证明循环内拷贝安全
# 误报根源: 循环内的memcpy(dst+off, src, per)被直接视为溢出候选,
#   但循环被cmp守卫约束N次迭代, 累积写入量=N×per可能仍≤分配量
#   现有管线对循环仅做likelihood×1.5的加权, 无实际累积量计算
#
# 方法: (1)找sink所在循环(双向可达闭合) (2)提取循环头迭代守卫上界N
#   (3)单次拷贝量=值流解析 (4)累积=per_hi×N; 累积≤usable→可证安全
# 安全性: 累积采用过近似(迭代上界×单次上界), 只用于"证明安全"的过滤,
#   不用于判定溢出——过近似只会少过滤, 不会误杀真漏洞
#
# 与循环摘要的区别: 不做完整循环摘要, 仅提取守卫上界乘单次量;
#   与interval widening的区别: 不用迭代收敛, 直接闭合计算
# TODO: _iteration_bound仅识别递增计数器+立即数上界; 递减计数器与数据依赖上界返回None, 属保守空缺

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass

from .param_size_equality import ParamSizeEquality
from .path_size_resolver import PathSizeResolver

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)

_ASCEND_JCC = {'jl', 'jle', 'jb', 'jbe', 'jne', 'jnz'}  # 计数器递增→回循环体
_WIN_SIZE_REG = {'memcpy':'r8','memmove':'r8','strncpy':'r8','snprintf':'rdx',
                 'read':'r8','recv':'r8','fread':'rdx'}
_LINUX_SIZE_REG = {'memcpy':'rdx','memmove':'rdx','strncpy':'rdx','snprintf':'rsi',
                   'read':'rdx','recv':'rdx','fread':'rsi'}


@dataclass
class LoopCumulativeResult:
    in_loop: bool
    iter_bound: Optional[int] = None    # 迭代次数上界
    per_iter_hi: Optional[int] = None   # 单次拷贝量上界
    cumulative_hi: Optional[int] = None # 累积拷贝量上界
    provably_safe: bool = False
    evidence: str = ""


class LoopCumulativeBound:
    """循环累积拷贝上界计算器"""

    def __init__(self):
        self._param_eq = ParamSizeEquality(max_trace_depth=8)

    def compute(self, instructions: List[str],
                bb_boundaries: List[Tuple[int, int]],
                cfg_edges: List[Tuple[int, int]],
                copy_idx: int, copy_func: str,
                alloc_usable: int) -> LoopCumulativeResult:
        """计算循环内拷贝的累积上界并判定是否可证安全。
        alloc_usable<=0或单次量/迭代上界未知→不判定安全
        """
        sink_bb = self._bb_of(copy_idx, bb_boundaries)
        if sink_bb is None or alloc_usable <= 0:
            return LoopCumulativeResult(in_loop=False)

        loop_bbs = self._loop_members(sink_bb, bb_boundaries, cfg_edges)
        if not loop_bbs:
            return LoopCumulativeResult(in_loop=False)

        header = self._loop_header(loop_bbs, bb_boundaries, cfg_edges)
        iter_bound = (self._iteration_bound(header, instructions, bb_boundaries,
                                            loop_bbs)
                      if header is not None else None)

        per_hi = self._per_iteration_size(instructions, copy_idx, copy_func)
        if iter_bound is None or per_hi is None:
            return LoopCumulativeResult(in_loop=True, iter_bound=iter_bound,
                                        per_iter_hi=per_hi)

        cumulative = iter_bound * per_hi
        safe = cumulative <= alloc_usable
        ev = (f"loop@{sink_bb}: iter≤{iter_bound}×per={per_hi}="
              f"cum={cumulative} ≤ usable={alloc_usable}" if safe else
              f"loop@{sink_bb}: cum={cumulative} > usable={alloc_usable}")
        return LoopCumulativeResult(in_loop=True, iter_bound=iter_bound,
                                    per_iter_hi=per_hi,
                                    cumulative_hi=cumulative,
                                    provably_safe=safe, evidence=ev)

    @staticmethod
    def _bb_of(instr_idx, bb_boundaries) -> Optional[int]:
        for bb_id, (start, end) in enumerate(bb_boundaries):
            if start <= instr_idx < end:
                return bb_id
        return None

    @staticmethod
    def _loop_members(sink_bb, bb_boundaries, cfg_edges) -> Set[int]:
        """循环成员=与sink互相可达的基本块(双向闭包)"""
        n = len(bb_boundaries)
        if sink_bb >= n:
            return set()
        adj = defaultdict(list)
        for s, d in cfg_edges:
            if s < n and d < n:
                adj[s].append(d)

        def reach_set(t: int) -> Set[int]:
            seen = {t}
            q = deque([t])
            while q:
                u = q.popleft()
                for v in adj[u]:
                    if v not in seen:
                        seen.add(v)
                        q.append(v)
            return seen

        from_sink = reach_set(sink_bb)
        # to_sink: 反向可达sink的节点集合
        pred = defaultdict(list)
        for s, d in cfg_edges:
            if s < n and d < n:
                pred[d].append(s)
        seen = {sink_bb}
        q = deque([sink_bb])
        while q:
            u = q.popleft()
            for v in pred[u]:
                if v not in seen:
                    seen.add(v)
                    q.append(v)
        return from_sink & seen

    @staticmethod
    def _loop_header(loop_bbs, bb_boundaries, cfg_edges) -> Optional[int]:
        """循环头=有来自循环外前驱的成员BB; 多个则取离入口最近"""
        n = len(bb_boundaries)
        candidates = []
        for h in loop_bbs:
            for s, d in cfg_edges:
                if d == h and s < n and s not in loop_bbs:
                    candidates.append(h)
                    break
        if not candidates:
            return None
        dist = {0: 0}
        q = deque([0])
        adj = defaultdict(list)
        for s, d in cfg_edges:
            if s < n and d < n:
                adj[s].append(d)
        while q:
            u = q.popleft()
            for v in adj[u]:
                if v not in dist:
                    dist[v] = dist[u] + 1
                    q.append(v)
        return min(candidates, key=lambda h: dist.get(h, 999))

    def _iteration_bound(self, header, instructions, bb_boundaries,
                         loop_bbs) -> Optional[int]:
        """从循环头守卫提取迭代上界——cmp counter,N; 递增型jcc回循环体"""
        if header >= len(bb_boundaries):
            return None
        start, end = bb_boundaries[header]
        for i in range(start, end):
            il = instructions[i].strip().lower()
            if not il or il.startswith((';', '.')):
                continue
            if 'cmp' not in il:
                continue
            ops = self._cmp_pair(il)
            if ops is None:
                continue
            jcc = self._next_jcc(instructions, i)
            if jcc not in _ASCEND_JCC:
                continue
            bound = None
            counter = None
            for side, val in ops:
                if val is not None:
                    bound = val
                elif counter is None and self._is_counter(
                        side, instructions, loop_bbs, bb_boundaries):
                    counter = self._canon(side)
            if bound is not None and counter is not None and 0 < bound <= 0x10000:
                return bound
        return None

    @staticmethod
    def _is_counter(operand, instructions, loop_bbs, bb_boundaries) -> bool:
        """判定cmp操作数是否循环内被递增的槽/寄存器"""
        token = LoopCumulativeBound._canon(operand)
        if not token:
            return False
        for bb in loop_bbs:
            if bb >= len(bb_boundaries):
                continue
            s, e = bb_boundaries[bb]
            for j in range(s, e):
                il = instructions[j].strip().lower()
                if not il or il.startswith((';', '.')):
                    continue
                if re.search(rf'\binc\b.*{re.escape(token)}', il):
                    return True
                if re.search(rf'\badd\b.*{re.escape(token)}', il):
                    return True
        return False

    @staticmethod
    def _canon(operand: str) -> str:
        """操作数规范形: [base+off]统一, %前缀剥离"""
        op = operand.strip().lower()
        m = re.search(r'\[(rbp|rsp)([+\-]?0x[0-9a-f]+|\d+)\]', op)
        if m:
            return f"[{m.group(1)}{m.group(2)}]"
        m = re.search(r'([+\-]?(?:0x[0-9a-f]+|\d+))\(%(rbp|rsp)\)', op)
        if m:
            return f"[{m.group(2)}{m.group(1)}]"
        return op.lstrip('%')

    def _per_iteration_size(self, instructions, copy_idx,
                            copy_func) -> Optional[int]:
        """单次拷贝量上界——值流解析为常量"""
        abi = self._param_eq._detect_abi(instructions, copy_idx)
        reg = (_WIN_SIZE_REG if abi == 'win' else _LINUX_SIZE_REG).get(
            copy_func, 'rdx' if abi == 'linux' else 'r8')
        origin = self._param_eq._trace_reg(instructions, copy_idx, reg)
        if origin.kind == 'imm':
            return PathSizeResolver._to_int(origin.sig)
        return None

    def loop_advances_dst(self, instructions, bb_boundaries, cfg_edges,
                          copy_idx, copy_func) -> bool:
        """判定循环内拷贝目标是否随迭代前进(offset式写)。
        前进→每次写入不同位置→累积量=实际写入总量;
        不前进(同址覆盖)→累积上界过近似, 不能用于判定溢出
        """
        sink_bb = self._bb_of(copy_idx, bb_boundaries)
        if sink_bb is None:
            return False
        loop_bbs = self._loop_members(sink_bb, bb_boundaries, cfg_edges)
        abi = self._param_eq._detect_abi(instructions, copy_idx)
        dst_reg = ('rcx' if abi == 'win' else 'rdi') if copy_func in (
            'memcpy', 'memmove', 'strncpy', 'strcpy', 'gets',
            'read', 'recv', 'fread', 'snprintf') else 'rdi'
        for bb in loop_bbs:
            if bb >= len(bb_boundaries):
                continue
            s, e = bb_boundaries[bb]
            for j in range(s, e):
                il = instructions[j].strip().lower()
                if not il or il.startswith((';', '.')):
                    continue
                # Intel: lea dst,[...] / add dst,imm | AT&T: lea ...,dst / add imm,dst
                if re.search(rf'\blea\s+{dst_reg}\b', il):
                    return True
                if re.search(rf'\blea\s+.*{re.escape(dst_reg)}\s*$', il):
                    return True
                if re.search(rf'\badd\s+{dst_reg}\b', il):
                    return True
                if re.search(rf'\badd\s+.*{re.escape(dst_reg)}\s*$', il):
                    return True
        return False

    @staticmethod
    def _cmp_pair(il: str) -> Optional[List[Tuple[str, Optional[int]]]]:
        """解析cmp操作数→[(op, imm_or_none), ...]"""
        m = re.match(r'cmp\s+(.+)$', il)
        if not m:
            return None
        parts = m.group(1).split(',')
        if len(parts) != 2:
            return None
        out = []
        for p in parts:
            p = p.strip().lower()
            imm = re.search(r'(?:0x[0-9a-f]+|\d+)$', p)
            val = None
            if imm and ('$' in p or '0x' in p or imm.group(0).isdigit()):
                val = PathSizeResolver._to_int(imm.group(0))
            out.append((p, val))
        return out

    @staticmethod
    def _next_jcc(instructions: List[str], ci: int) -> Optional[str]:
        """cmp后3条指令内找jcc"""
        for j in range(ci + 1, min(ci + 4, len(instructions))):
            il = instructions[j].strip().lower()
            if not il or il.startswith(';'):
                continue
            m = re.search(r'\b(j[a-z]{1,3})\b', il)
            if m:
                return m.group(1)
            if 'ret' in il or 'call' in il:
                return None
        return None

