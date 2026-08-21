# 路径可行性分析器: 判定从入口到sink的CFG路径是否实际可达
# 在现有简单BFS可达性基础上增加路径条件的轻量符号追踪
#
# 核心创新: 不构建完整的符号执行引擎(太重)，而是从CFG中提取
#   与堆操作相关的条件分支，做局部约束检查
#
# 应用场景:
# 阶段3过滤: 排除死代码/不可达路径中的误报
#   - 与constraint_simplifier配合: 对POSSIBLE_OVERFLOW做路径条件
#     棱镜分析, 在特定路径条件下溢出是否成立
#
# 与 heap_overflow_filter.py 中 _is_reachable_block 的BFS方式区别:
#   BFS仅检查块是否从入口可达，不关心路径条件
#   本模块检查路径条件中与堆大小相关的约束(如if(len>256))，
#   将条件信息融入溢出判定

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class FeasibilityVerdict(Enum):
    REACHABLE = 'reachable'              # 确定可达
    CONDITIONALLY_REACHABLE = 'cond'     # 条件可达
    UNREACHABLE = 'unreachable'          # 确定不可达
    UNKNOWN = 'unknown'                  # 无法判定


@dataclass
class PathCondition:
    """从入口到目标基本块的路径条件"""
    bb_path: List[int]                    # 经过的基本块ID序列
    comparisons: List['ComparisonCond']   # 路径上的比较条件
    cond_count: int = 0

    def is_trivially_satisfiable(self) -> bool:
        """快速检查: 路径条件是否存在明显矛盾(如 x>256 且 x<32)"""
        # 收集所有对同一变量的约束
        lower_bounds: Dict[str, int] = {}
        upper_bounds: Dict[str, int] = {}

        for cond in self.comparisons:
            if cond.target_var is None:
                continue
            if cond.op in ('>', '>=', '≥'):
                lower_bounds[cond.target_var] = max(
                    lower_bounds.get(cond.target_var, 0), cond.value)
            elif cond.op in ('<', '<=', '≤'):
                upper_bounds[cond.target_var] = min(
                    upper_bounds.get(cond.target_var, 0xFFFFFFFF), cond.value)

        for var in set(lower_bounds) & set(upper_bounds):
            if lower_bounds[var] > upper_bounds[var]:
                return False  # 矛盾
        return True


@dataclass
class ComparisonCond:
    """路径上的一条比较条件"""
    op: str              # >, <, >=, <=, ==, !=
    target_var: Optional[str] = None  # 比较的变量(若能解析)
    value: int = 0       # 比较的常量
    raw_instr: str = ""  # 原始汇编指令


class PathFeasibilityAnalyzer:
    """路径可行性分析器。

    构建CFG并从入口到sink提取路径条件，
    检查是否存在矛盾约束或不可达路径。

    分析粒度:
      - 仅分析包含堆大小相关比较的条件分支(if(size>N), if(len<M))
      - 忽略非堆相关的控制流(如循环计数器、flag检查)
      - 这是精度和性能的折衷: 完全符号执行需要数分钟/函数，
        而我们控制在毫秒级
    """

    # 与大小/长度相关的变量名模式
    _SIZE_VAR_PATTERN = re.compile(
        r'(size|len|count|nbyte|n|sz|length|nmemb|num)', re.I)
    # 条件分支模式
    _COND_PATTERN = re.compile(
        r'(cmp|test)\s+(\w+),\s*(0x[0-9a-f]+|\d+)', re.I)
    _JUMP_PATTERN = re.compile(
        r'\b(j[a-z]+)\b', re.I)
    # 条件跳转与比较操作符的映射
    _JCC_TO_OP = {
        'ja': ('>', False), 'jnbe': ('>', False),
        'jae': ('>=', False), 'jnb': ('>=', False), 'jnc': ('>=', False),
        'jb': ('<', False), 'jnae': ('<', False), 'jc': ('<', False),
        'jbe': ('<=', False), 'jna': ('<=', False),
        'je': ('==', True), 'jz': ('==', True),
        'jne': ('!=', True), 'jnz': ('!=', True),
        'jg': ('>', True), 'jnle': ('>', True),
        'jge': ('>=', True), 'jnl': ('>=', True),
        'jl': ('<', True), 'jnge': ('<', True),
        'jle': ('<=', True), 'jng': ('<=', True),
    }

    def __init__(self):
        self._size_threshold = 256  # 被认为是"大"分配/拷贝的阈值

    def analyze_path(self,
                      sink_instr_idx: int,
                      instructions: List[str],
                      bb_boundaries: List[Tuple[int, int]],
                      cfg_edges: List[Tuple[int, int]],
                      entry_bb: int = 0
                      ) -> Tuple[FeasibilityVerdict, Optional[PathCondition]]:
        """分析从入口到sink的路径可行性。"""
        # 找到sink所在的基本块
        sink_bb = -1
        for bb_id, (start, end) in enumerate(bb_boundaries):
            if start <= sink_instr_idx < end:
                sink_bb = bb_id
                break

        if sink_bb < 0:
            return (FeasibilityVerdict.REACHABLE, None)

        # BFS找最短路径
        path = self._find_shortest_path(entry_bb, sink_bb, cfg_edges)
        if path is None:
            return (FeasibilityVerdict.UNREACHABLE, None)

        # 沿路径收集比较条件
        comparisons = self._collect_path_conditions(
            path, instructions, bb_boundaries)

        path_cond = PathCondition(
            bb_path=path, comparisons=comparisons,
            cond_count=len(comparisons))

        if not comparisons:
            return (FeasibilityVerdict.REACHABLE, path_cond)

        if not path_cond.is_trivially_satisfiable():
            return (FeasibilityVerdict.UNREACHABLE, path_cond)

        # 有约束但无矛盾 → 条件可达
        return (FeasibilityVerdict.CONDITIONALLY_REACHABLE, path_cond)

    def get_size_bounds_on_path(self,
                                 sink_instr_idx: int,
                                 instructions: List[str],
                                 bb_boundaries: List[Tuple[int, int]],
                                 cfg_edges: List[Tuple[int, int]]
                                 ) -> Tuple[Optional[int], Optional[int]]:
        """提取路径上对size/len变量的上下界。

        用途: 若路径条件要求 len ≤ 64, 但 alloc_size=32,
              则拷贝的len被限制为≤64 → 可能溢出仍需报告
        """
        _, path_cond = self.analyze_path(
            sink_instr_idx, instructions, bb_boundaries, cfg_edges)

        if path_cond is None:
            return (None, None)

        lo, hi = None, None
        for cond in path_cond.comparisons:
            if cond.op in ('>', '>=', '≥') and cond.target_var:
                lo = max(lo or 0, cond.value)
            elif cond.op in ('<', '<=', '≤') and cond.target_var:
                hi = min(hi or 0xFFFFFFFF, cond.value)

        return (lo, hi)

    def _find_shortest_path(self,
                             from_bb: int,
                             to_bb: int,
                             cfg_edges: List[Tuple[int, int]]
                             ) -> Optional[List[int]]:
        """BFS最短路径"""
        adj = defaultdict(list)
        for src, dst in cfg_edges:
            adj[src].append(dst)

        q = deque([(from_bb, [from_bb])])
        visited = {from_bb}

        while q:
            current, path = q.popleft()
            if current == to_bb:
                return path
            for neighbor in adj.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    q.append((neighbor, path + [neighbor]))
        return None

    def _collect_path_conditions(self,
                                   bb_path: List[int],
                                   instructions: List[str],
                                   bb_boundaries: List[Tuple[int, int]]
                                   ) -> List[ComparisonCond]:
        """沿基本块路径收集条件跳转前的比较"""
        conditions = []
        if not bb_path or len(bb_path) < 2:
            return conditions

        for i, bb_id in enumerate(bb_path[:-1]):
            next_bb = bb_path[i + 1]
            if bb_id >= len(bb_boundaries):
                continue
            start, end = bb_boundaries[bb_id]

            # 检查基本块末尾的条件跳转
            for j in range(end - 1, start - 1, -1):
                if j < 0 or j >= len(instructions):
                    continue
                instr = instructions[j].strip().lower()
                if not instr:
                    continue

                # 找条件跳转前的cmp
                if 'cmp' in instr:
                    m = self._COND_PATTERN.match(instr)
                    if m:
                        var = m.group(2)
                        val = (
                            int(m.group(3), 16)
                            if '0x' in m.group(3).lower()
                            else int(m.group(3))
                        )
                        # 仅收集与大小相关的比较
                        if self._SIZE_VAR_PATTERN.search(var) or val > self._size_threshold:
                            conditions.append(ComparisonCond(
                                op='?', target_var=var, value=val, raw_instr=instr))
                break

        return conditions

    def is_loop_controlled_overflow(self,
                                     sink_instr_idx: int,
                                     instructions: List[str],
                                     bb_boundaries: List[Tuple[int, int]],
                                     cfg_edges: List[Tuple[int, int]]
                                     ) -> bool:
        """判断溢出是否发生在循环控制的上下文中。

        循环中逐次递增的拷贝更容易导致非预期的溢出, 这是真漏洞的强信号。
        """
        sink_bb = -1
        for bb_id, (start, end) in enumerate(bb_boundaries):
            if start <= sink_instr_idx < end:
                sink_bb = bb_id
                break

        if sink_bb < 0:
            return False

        # 检查是否存在回到sink_bb或其前驱的回边
        adj = defaultdict(list)
        for src, dst in cfg_edges:
            adj[src].append(dst)

        # 简单的循环检测: 是否存在从sink_bb可达的节点能回到sink_bb
        visited = set()
        stack = [sink_bb]
        while stack:
            u = stack.pop()
            if u in visited:
                continue
            visited.add(u)
            for v in adj.get(u, []):
                if v == sink_bb:  # 回边
                    return True
                stack.append(v)

        return False
