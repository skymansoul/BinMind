# 路径敏感逐路径大小解析——用支配性守卫约束解析未知拷贝大小
# 误报根源: copy_size解析为TOP(未知)→"约束未知→保守保留"→FP
# 典型: malloc(N); if(len>N) return; memcpy(buf,in,len)
#   ——len上界=支配性cmp+jcc守卫给出的N, 实际不可能溢出
#
# 方法: 守卫约束在sink的支配基本块上→对所有到达sink的路径生效
#   (1)溯源copy_size→栈槽/参数键 (2)计算sink基本块的支配集
#   (3)对每个支配BB提取cmp键vs N的分支方向→size≤N即上界
#   (4)取所有支配守卫上界的最小值→全局拷贝上界
# 安全性: 只取支配BB上的守卫→约束对所有路径成立; 无守卫则返回None
#
# 与guard_constraint_tracker的区别: 该模块只查call前线性窗口的
#   cmp+jcc→exit; 本模块沿支配路径收集, 覆盖跨基本块的守卫

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass

from .param_size_equality import ParamSizeEquality

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)

_NON_REG = {'qword','dword','word','byte','ptr','xmmword'}
_PARAM_REGS = ('rdi','rsi','rdx','rcx','r8','r9')
# 条件跳转→大小上界的约束方向(按"通向sink的分支边"分类)
# TAKEN边(跳到目标)约束为≤N: jle/jbe/je/jz
_TAKEN_UPPER = {'jle','jbe','je','jz'}
# NOT-TAKEN边(fall-through)约束为≤N: jg/ja/jne/jnz
_NOTTAKEN_UPPER = {'jg','ja','jne','jnz'}


@dataclass
class PathSizeResult:
    upper_bound: Optional[int]      # 全局拷贝上界; None=无法证明
    guard_count: int = 0
    dominators: int = 0
    evidence: List[str] = None

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []


class PathSizeResolver:
    """路径敏感大小解析器——支配性守卫约束求解拷贝上界"""

    def __init__(self, max_paths: int = 64):
        self._max_paths = max_paths
        self._param_eq = ParamSizeEquality(max_trace_depth=10)

    def resolve_copy_upper_bound(self, instructions: List[str],
                                 copy_idx: int, copy_func: str,
                                 bb_boundaries: List[Tuple[int, int]],
                                 cfg_edges: List[Tuple[int, int]],
                                 abi: str = 'auto') -> PathSizeResult:
        """解析copy_size的全局上界——所有支配路径守卫的紧上界"""
        sink_bb = self._bb_of(instructions, copy_idx, bb_boundaries)
        if sink_bb is None:
            return PathSizeResult(None)

        key = self._size_guard_key(instructions, copy_idx, copy_func)
        if key is None:
            return PathSizeResult(None)

        dom = self._dominates(bb_boundaries, cfg_edges)
        dom_of_sink = dom.get(sink_bb, set())

        bounds = []
        evidence = []
        for bb in dom_of_sink:
            ub = self._bb_guard_upper(instructions, bb_boundaries, bb,
                                      sink_bb, cfg_edges, key)
            if ub is not None:
                bounds.append(ub)
                evidence.append(f"dom@{bb}→copy≤{ub}")
        if not bounds:
            return PathSizeResult(None, guard_count=0,
                                  dominators=len(dom_of_sink))

        return PathSizeResult(min(bounds), guard_count=len(bounds),
                              dominators=len(dom_of_sink), evidence=evidence)

    def _size_guard_key(self, instructions, copy_idx, copy_func):
        """溯源copy_size→守卫比对键: 栈槽签名或参数寄存器集合"""
        abi = self._param_eq._detect_abi(instructions, copy_idx)
        reg = (_WIN_SIZE_REG if abi == 'win' else _LINUX_SIZE_REG).get(
            copy_func, 'rdx' if abi == 'linux' else 'r8')
        origin = self._param_eq._trace_reg(instructions, copy_idx, reg)
        if origin.kind == 'slot':
            return ('slot', origin.sig)
        if origin.kind == 'param':
            return ('param', origin.sig)
        return None

    def _bb_guard_upper(self, instructions, bb_boundaries, bb,
                        sink_bb, cfg_edges, key) -> Optional[int]:
        """提取基本块末尾条件分支产生的size上界(若存在)。
        方向性: 根据"通向sink的分支边"判定约束——taken边用jle/jbe,
        fall-through边用jg/ja; 选错边会导致误杀真漏洞
        """
        if bb >= len(bb_boundaries):
            return None
        start, end = bb_boundaries[bb]
        # 反向找cmp/test, 其后为jcc
        for i in range(end - 1, start - 1, -1):
            il = instructions[i].strip().lower()
            if not il or il.startswith((';', '.')):
                continue
            if 'cmp' not in il and 'test' not in il:
                continue
            jcc = self._next_jcc(instructions, i)
            if jcc is None:
                continue
            operands = self._cmp_operands(il)
            if operands is None:
                continue
            sink_via_taken, sink_via_fall = self._sink_branch_side(
                bb, sink_bb, cfg_edges, bb_boundaries)
            if sink_via_taken == sink_via_fall:
                continue  # 分支边不唯一/无信息——保守跳过
            bound = self._guard_bound(operands, jcc, key, sink_via_taken)
            if bound is not None:
                return bound
        return None

    @staticmethod
    def _sink_branch_side(bb: int, sink_bb: int, cfg_edges,
                          bb_boundaries) -> Tuple[bool, bool]:
        """判定通向sink的分支边: (经跳转taken, 经fall-through)。
        基于CFG后继可达性——跳转边=非顺序后继, fall-through=顺序后继
        """
        succs = {v for (s, v) in cfg_edges if s == bb and v != bb}
        fall_bb = PathSizeResolver._fallthrough_bb(bb, bb_boundaries)
        via_taken = any(PathSizeResolver._reachable(v, sink_bb, cfg_edges)
                        for v in succs if v != fall_bb)
        via_fall = fall_bb is not None and PathSizeResolver._reachable(
            fall_bb, sink_bb, cfg_edges)
        return via_taken, via_fall

    @staticmethod
    def _fallthrough_bb(bb: int, bb_boundaries) -> Optional[int]:
        """fall-through后继=起始索引等于bb结束索引的BB"""
        if bb >= len(bb_boundaries):
            return None
        end = bb_boundaries[bb][1]
        for v, (start, _) in enumerate(bb_boundaries):
            if v != bb and start == end:
                return v
        return None

    @staticmethod
    def _guard_bound(operands, jcc: str, key, sink_via_taken: bool) -> Optional[int]:
        """判定守卫是否约束size键并返回上界(仅≤N方向)。
        cmp的两个操作数中: 一个匹配size键(被比较变量), 另一个是常量界
        """
        key_kind, key_val = key
        var_matched = False
        bound = None
        for side, val in operands:
            if PathSizeResolver._matches_key(side, key_kind, key_val):
                var_matched = True
            if val is not None:
                bound = val
        if not var_matched or bound is None:
            return None
        if sink_via_taken and jcc in _TAKEN_UPPER:
            return bound
        if not sink_via_taken and jcc in _NOTTAKEN_UPPER:
            return bound
        return None

    @staticmethod
    def _reachable(from_bb: int, to_bb: int, cfg_edges) -> bool:
        """CFG中from_bb是否可达to_bb"""
        adj = defaultdict(list)
        for src, dst in cfg_edges:
            adj[src].append(dst)
        if from_bb == to_bb:
            return True
        seen = {from_bb}
        q = deque([from_bb])
        while q:
            u = q.popleft()
            for v in adj[u]:
                if v == to_bb:
                    return True
                if v not in seen:
                    seen.add(v)
                    q.append(v)
        return False

    @staticmethod
    def _matches_key(operand: str, key_kind: str, key_val: str) -> bool:
        """cmp操作数与size键匹配: 栈槽签名或参数寄存器族"""
        op = operand.strip().lower().replace(' ', '')
        if key_kind == 'slot':
            # 归一化: 'rbp+0x18' 与 'rbp0x18' 统一
            m = re.search(r'\[(rbp|rsp)([+\-]?0x[0-9a-f]+|\d+)\]', op)
            if m:
                norm = f"{m.group(1)}{m.group(2)}"
                return norm == key_val.replace('rbp0x', 'rbp+0x').replace(
                    'rsp0x', 'rsp+0x') or norm == key_val
            m = re.search(r'(rbp|rsp)([+\-]?0x[0-9a-f]+|\d+)', op)
            if m:
                norm = f"{m.group(1)}{m.group(2)}"
                return norm == key_val.replace('rbp0x', 'rbp+0x').replace(
                    'rsp0x', 'rsp+0x') or norm == key_val
            return op == key_val
        # param键: 参数寄存器及其32位变体
        idx = key_val
        reg32 = {'0':'edi','1':'esi','2':'edx','3':'ecx','4':'r8d','5':'r9d'}
        reg64 = {'0':'rdi','1':'rsi','2':'rdx','3':'rcx','4':'r8','5':'r9'}
        return op.lstrip('%') in (reg32.get(idx), reg64.get(idx))

    @staticmethod
    def _cmp_operands(il: str) -> Optional[List[Tuple[str, Optional[int]]]]:
        """解析cmp/test操作数→[(op1, imm_or_none), (op2, imm_or_none)]
        支持 AT&T: cmp $imm, %reg / cmp $imm, off(%rbp)
        支持 Intel: cmp reg, imm / cmp DWORD PTR [rbp+off], imm
        """
        m = re.match(r'cmp\s+(.+)$', il)
        if not m:
            m = re.match(r'test\s+(.+)$', il)
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
    def _to_int(s: str) -> int:
        return int(s, 16) if '0x' in s.lower() else int(s)

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

    def _bb_of(self, instructions, instr_idx, bb_boundaries):
        for bb_id, (start, end) in enumerate(bb_boundaries):
            if start <= instr_idx < end:
                return bb_id
        return None

    @staticmethod
    def _dominates(bb_boundaries, cfg_edges) -> Dict[int, Set[int]]:
        """计算每个基本块的支配者集合——删点可达性 O(V·(V+E))"""
        # TODO: 大函数(>500基本块)改用迭代数据流/Lengauer-Tarjan, 当前O(V^2)在极端CFG上偏慢
        n = len(bb_boundaries)
        adj = defaultdict(list)
        pred = defaultdict(list)
        for src, dst in cfg_edges:
            if src < n and dst < n:
                adj[src].append(dst)
                pred[dst].append(src)

        def reachable_from(entry: int, banned: int) -> Set[int]:
            seen = {entry}
            q = deque([entry])
            while q:
                u = q.popleft()
                for v in adj[u]:
                    if v == banned or v in seen:
                        continue
                    seen.add(v)
                    q.append(v)
            return seen

        dom = {}
        for t in range(n):
            full = reachable_from(0, -1)
            if t not in full:
                dom[t] = set()
                continue
            dom[t] = {0}
            for d in full:
                if d == t or d == 0:
                    continue
                if t in reachable_from(0, d):
                    dom[t].add(d)
            dom[t].add(t)
        return dom


# 按ABI的size寄存器——与param_size_equality保持一致
_WIN_SIZE_REG = {'memcpy':'r8','memmove':'r8','strncpy':'r8','snprintf':'rdx',
                 'read':'r8','recv':'r8','fread':'rdx'}
_LINUX_SIZE_REG = {'memcpy':'rdx','memmove':'rdx','strncpy':'rdx','snprintf':'rsi',
                   'read':'rdx','recv':'rdx','fread':'rsi'}

