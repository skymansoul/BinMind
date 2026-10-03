# 循环结构恢复——从CFG的SCC分析中重建高级循环(while/for/do-while)
#
# 核心问题: 二进制分析中得到的CFG是扁平的——所有基本块只有
# 跳转关系，没有"这是循环体"的标注。将CFG的强连通分量(SCC)
# 识别为循环是常规做法，但区分while/for/do-while需要更细粒度的
# 模式分析——这直接影响反编译输出的可读性和漏洞分析的效率。
#
# 技术方案:
#   1. SCC检测: Tarjan算法找出所有强连通分量(循环候选)
#   2. 循环类型分类: 基于循环入口块的结构特征判断——
#      do-while: 入口即循环体(无条件先执行一次)
#      while: 条件检查在循环体之前
#      for: 入口块有初始化+条件+增量模式
#   3. 嵌套分析: SCC嵌套关系→循环嵌套树
#   4. 循环变量推断: 在循环体内寻找被迭代修改的寄存器→
#      推断循环变量和步长

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

from .src.recovery.scc_detector import TarjanSCC

logger = logging.getLogger(__name__)


class LoopKind(Enum):
    WHILE = 'while'
    FOR = 'for'
    DO_WHILE = 'do_while'
    UNKNOWN = 'unknown'


@dataclass
class LoopStructure:
    """重建的循环结构"""
    loop_id: int
    kind: LoopKind
    header_block: int           # 循环头(条件检查块)
    body_blocks: List[int]      # 循环体
    latch_block: int            # 回边源块
    exit_block: int             # 循环出口块
    init_blocks: List[int]      # for循环的初始化块
    increment_blocks: List[int] # for循环的增量块
    nesting_depth: int          # 嵌套深度
    loop_var_reg: str           # 推断的循环变量寄存器
    estimated_trip_count: int   # 估计迭代次数


class LoopStructureRecovery:
    """循环结构恢复——SCC+模式分类。

    分类逻辑:
      do-while: 回边源→循环头，且循环头无来自外部的条件分支
      while: 循环头有外部入边+条件分支→exit或body
      for: while模式 + 头部/前驱中有初始化+增量模式
    """

    def __init__(self, max_trip_estimate: int = 1000):
        self._max_trip = max_trip_estimate
        self._inc_pattern = re.compile(
            r'\b(inc|dec|add|sub)\s+(\w+),\s*(0x[0-9a-f]+|\d+)', re.I)
        self._cmp_pattern = re.compile(
            r'\b(cmp|test)\s+(\w+),\s*(0x[0-9a-f]+|\d+)', re.I)

    def recover(self,
                basic_blocks: List[Tuple[int, List[str]]],
                cfg_edges: List[Tuple[int, int]]
                ) -> List[LoopStructure]:
        """从CFG恢复循环结构。"""
        adj = defaultdict(list)
        for src, dst in cfg_edges:
            adj[src].append(dst)

        # SCC检测
        tarjan = TarjanSCC(dict(adj))
        sccs = tarjan.find_sccs()
        if not sccs:
            return []

        # 循环类型分类
        block_instrs = {bid: instrs for bid, instrs in basic_blocks}
        loops = []
        for loop_id, scc in enumerate(sccs):
            if len(scc) < 2:
                continue

            # 找循环头: SCC中入边来自SCC外部的节点
            header = self._find_header(scc, adj)

            # 找回边: 目标=header且源在SCC内的边
            latch = self._find_latch(scc, header, adj)

            # 找出口: header的后继中不在SCC内的节点
            exit_block = self._find_exit(header, scc, adj)

            # 分类
            loop_kind = self._classify_loop(
                header, scc, latch, exit_block, adj, block_instrs)

            # 推断循环变量
            loop_var, trip_count = self._infer_loop_variable(
                header, block_instrs.get(header, []))

            # 嵌套深度: 检查SCC是否被其他SCC包含
            depth = self._compute_nesting_depth(scc, sccs)

            # for循环的初始化和增量块
            init_blocks, inc_blocks = [], []
            if loop_kind == LoopKind.FOR:
                init_blocks = self._find_init_blocks(header, scc, adj, block_instrs)
                inc_blocks = self._find_inc_blocks(latch, block_instrs)

            loops.append(LoopStructure(
                loop_id=loop_id, kind=loop_kind,
                header_block=header, body_blocks=list(scc),
                latch_block=latch, exit_block=exit_block,
                init_blocks=init_blocks, increment_blocks=inc_blocks,
                nesting_depth=depth, loop_var_reg=loop_var,
                estimated_trip_count=trip_count))

        return loops

    def _find_header(self, scc: List[int],
                     adj: Dict[int, List[int]]) -> int:
        """找循环头——SCC中有外部入边的节点"""
        scc_set = set(scc)
        for node in scc:
            # 检查是否有来自SCC外的入边
            has_external = False
            for pred in self._get_predecessors(node, adj):
                if pred not in scc_set:
                    has_external = True
                    break
            if has_external:
                return node
        return scc[0]  # 回退: 第一个节点

    def _find_latch(self, scc: List[int], header: int,
                    adj: Dict[int, List[int]]) -> int:
        """找回边源——SCC中指向header的节点"""
        scc_set = set(scc)
        for node in scc:
            if node == header:
                continue
            if header in adj.get(node, []):
                return node
        return scc[-1] if len(scc) > 1 else scc[0]

    def _find_exit(self, header: int, scc: List[int],
                   adj: Dict[int, List[int]]) -> int:
        """找循环出口——header的后继中不在SCC内的节点"""
        scc_set = set(scc)
        for succ in adj.get(header, []):
            if succ not in scc_set:
                return succ
        return -1

    def _get_predecessors(self, node: int,
                          adj: Dict[int, List[int]]) -> List[int]:
        preds = []
        for src, dsts in adj.items():
            if node in dsts:
                preds.append(src)
        return preds

    def _classify_loop(self, header: int, scc: List[int],
                       latch: int, exit_block: int,
                       adj: Dict[int, List[int]],
                       block_instrs: Dict[int, List[str]]
                       ) -> LoopKind:
        """基于结构特征分类循环类型。

        判定规则:
          - header的后继中既有body又有exit→while
          - header无条件跳转到body→do-while
          - header中存在inc/cmp组合且latch无条件回到header→for
        """
        header_succs = adj.get(header, [])
        scc_set = set(scc)

        body_succ = [s for s in header_succs if s in scc_set]
        exit_succ = [s for s in header_succs if s not in scc_set]

        header_instrs = block_instrs.get(header, [])
        header_text = ' '.join(header_instrs).lower()

        # for特征: 有inc/add+cmp/test组合
        has_increment = bool(self._inc_pattern.search(header_text))
        has_compare = bool(self._cmp_pattern.search(header_text))
        if has_increment and has_compare:
            return LoopKind.FOR

        # do-while: header无条件跳转到body
        if not exit_succ and body_succ:
            # 检查header的最后一条指令是否为无条件跳转
            if header_instrs and not any(
                w in header_instrs[-1].lower()
                for w in ('je', 'jne', 'jg', 'jl', 'jge', 'jle', 'ja', 'jb')):
                return LoopKind.DO_WHILE

        # while: header有条件分支
        if exit_succ and body_succ:
            return LoopKind.WHILE

        return LoopKind.UNKNOWN

    def _infer_loop_variable(self, header: int,
                              instrs: List[str]) -> Tuple[str, int]:
        """推断循环变量——在循环头中搜索被比较+修改的寄存器"""
        text = ' '.join(instrs).lower()
        # 找被cmp/test引用的寄存器
        cmp_matches = self._cmp_pattern.findall(text)
        inc_matches = self._inc_pattern.findall(text)

        inc_regs = {m[1] for m in inc_matches}
        trip = self._max_trip

        for _, reg, bound_str in cmp_matches:
            if reg in inc_regs:
                bound = int(bound_str, 16) if '0x' in bound_str else (
                    int(bound_str) if bound_str.isdigit() else self._max_trip)
                trip = min(self._max_trip, bound)
                return reg, trip

        if inc_regs:
            return list(inc_regs)[0], self._max_trip
        return 'unknown', self._max_trip

    def _compute_nesting_depth(self, scc: List[int],
                                all_sccs: List[List[int]]) -> int:
        depth = 0
        scc_set = set(scc)
        for other in all_sccs:
            if other == scc:
                continue
            if scc_set.issubset(set(other)):
                depth += 1
        return depth

    def _find_init_blocks(self, header: int, scc: List[int],
                           adj: Dict[int, List[int]],
                           block_instrs: Dict[int, List[str]]
                           ) -> List[int]:
        """找for循环的初始化块——header的前驱但不在SCC内"""
        scc_set = set(scc)
        init_blocks = []
        for pred in self._get_predecessors(header, adj):
            if pred not in scc_set:
                init_blocks.append(pred)
        return init_blocks[:2]

    def _find_inc_blocks(self, latch: int,
                          block_instrs: Dict[int, List[str]]
                          ) -> List[int]:
        """找for循环的增量块——通常是latch本身"""
        instrs = block_instrs.get(latch, [])
        if any(self._inc_pattern.search(i) for i in instrs):
            return [latch]
        return []
