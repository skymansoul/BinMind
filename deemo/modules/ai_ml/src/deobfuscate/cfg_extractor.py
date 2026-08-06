# CFG/DFG重建与一致性度量
# 用于 iterative_deobfuscator.py 的迭代精化回路
#
# 关键设计: 使用轻量级静态分析（正则+基本块分割），不依赖完整编译器
# 精度足够用于一致性检查，不需要编译通过

import math
import re
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict, deque, Counter
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class CFGNode:
    """CFG基本块"""
    id: int
    start_addr: int
    end_addr: int
    instructions: List[str] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    is_conditional: bool = False
    defined_vars: Set[str] = field(default_factory=set)
    used_vars: Set[str] = field(default_factory=set)


@dataclass
class DFGEdge:
    """数据流边: A.defined_vars ∩ B.used_vars 非空且B可达于A"""
    def_site: int
    use_site: int
    var_name: str
    crosses_loop: bool = False


class CFGDFGExtractor:
    """从代码文本重建CFG和DFG。

    分支检测: if/else/for/while/do/switch/goto/break/continue/return
    赋值检测: var = ... 形式的正则匹配
    变量使用: 标识符模式匹配（排除关键字）
    """

    def __init__(self):
        self._branch_pattern = re.compile(
            r'\b(if|else|for|while|do|switch|goto|break|continue|return)\b')
        self._assign_pattern = re.compile(r'(\w[\w\d_]*)\s*=\s*')
        self._var_use_pattern = re.compile(r'\b([a-zA-Z_]\w{0,31})\b')
        self._keywords = frozenset({
            'if', 'else', 'for', 'while', 'do', 'return', 'int', 'char',
            'void', 'long', 'short', 'sizeof', 'const', 'static', 'unsigned',
            'signed', 'float', 'double', 'struct', 'enum', 'union', 'typedef',
            'extern', 'volatile', 'register', 'auto', 'break', 'continue',
            'goto', 'switch', 'case', 'default',
        })

    def extract_cfg(self, code: str) -> List[CFGNode]:
        lines = code.split('\n')
        nodes = []
        current_instrs = []
        block_id = 0

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('//') or stripped.startswith('#'):
                if current_instrs:
                    nodes.append(CFGNode(
                        id=block_id, start_addr=block_id * 100,
                        end_addr=block_id * 100 + len(current_instrs),
                        instructions=current_instrs[:]))
                    block_id += 1
                    current_instrs = []
                continue
            current_instrs.append(stripped)
            if self._branch_pattern.search(stripped) and not stripped.endswith('{'):
                if current_instrs:
                    nodes.append(CFGNode(
                        id=block_id, start_addr=block_id * 100,
                        end_addr=block_id * 100 + len(current_instrs),
                        instructions=current_instrs[:]))
                    block_id += 1
                    current_instrs = []

        if current_instrs:
            nodes.append(CFGNode(id=block_id, start_addr=block_id * 100,
                end_addr=block_id * 100 + len(current_instrs),
                instructions=current_instrs[:]))

        # successors
        for i, node in enumerate(nodes):
            if node.instructions:
                last = node.instructions[-1]
                if self._branch_pattern.search(last):
                    node.is_conditional = True
                if i + 1 < len(nodes):
                    node.successors.append(i + 1)

        # def-use
        for node in nodes:
            for instr in node.instructions:
                m = self._assign_pattern.search(instr)
                if m:
                    node.defined_vars.add(m.group(1))
                for mu in self._var_use_pattern.finditer(instr):
                    var = mu.group(1)
                    if var not in self._keywords:
                        node.used_vars.add(var)

        return nodes

    def extract_df_edges(self, cfg_nodes: List[CFGNode]) -> List[DFGEdge]:
        edges = []
        for i, node_a in enumerate(cfg_nodes):
            for var in node_a.defined_vars:
                reachable = self._reachable_blocks(cfg_nodes, i)
                for j in reachable:
                    if j != i and var in cfg_nodes[j].used_vars:
                        crosses = self._edge_crosses_loop(cfg_nodes, i, j)
                        edges.append(DFGEdge(
                            def_site=i, use_site=j, var_name=var,
                            crosses_loop=crosses))
        return edges

    def _reachable_blocks(self, cfg_nodes: List[CFGNode], start: int) -> Set[int]:
        visited = {start}
        q = deque([start])
        while q:
            u = q.popleft()
            if u < len(cfg_nodes):
                for v in cfg_nodes[u].successors:
                    if v not in visited and v < len(cfg_nodes):
                        visited.add(v)
                        q.append(v)
        return visited

    def _edge_crosses_loop(self, cfg_nodes: List[CFGNode],
                           a: int, b: int) -> bool:
        if b < a:
            return True
        for i in range(a, min(b + 1, len(cfg_nodes))):
            for succ in cfg_nodes[i].successors:
                if succ < a:
                    return True
        return False


class CFGDFGConsistency:
    """度量去混淆代码与原始混淆代码间的CFG/DFG结构一致性。

    不要求完全一致（否则去混淆无意义），而是度量结构骨架的保持程度。
    """

    def __init__(self, extractor: Optional[CFGDFGExtractor] = None):
        self._extractor = extractor or CFGDFGExtractor()

    def compute_consistency(self,
                            obfuscated_code: str,
                            deobfuscated_code: str) -> Dict[str, float]:
        cfg_orig = self._extractor.extract_cfg(obfuscated_code)
        cfg_deob = self._extractor.extract_cfg(deobfuscated_code)
        cfg_sim = self._cfg_similarity(cfg_orig, cfg_deob)

        df_orig = self._extractor.extract_df_edges(cfg_orig)
        df_deob = self._extractor.extract_df_edges(cfg_deob)
        dfg_sim = self._dfg_similarity(df_orig, df_deob)

        inconsistent = self._find_inconsistent(cfg_orig, cfg_deob)
        overall = 0.5 * cfg_sim + 0.5 * dfg_sim
        penalty = len(inconsistent) / max(1, len(cfg_deob)) * 0.2
        overall = max(0.0, overall - penalty)

        return {
            'cfg_similarity': cfg_sim, 'dfg_similarity': dfg_sim,
            'overall': overall, 'inconsistent_regions': inconsistent,
        }

    def _cfg_similarity(self, cfg_a, cfg_b) -> float:
        n_a, n_b = len(cfg_a), len(cfg_b)
        if n_a == 0 or n_b == 0:
            return 0.0
        block_ratio = min(n_a, n_b) / max(n_a, n_b)
        br_a = sum(1 for n in cfg_a if n.is_conditional) / max(1, n_a)
        br_b = sum(1 for n in cfg_b if n.is_conditional) / max(1, n_b)
        branch_sim = 1.0 - min(1.0, abs(br_a - br_b))
        out_a = sum(len(n.successors) for n in cfg_a) / max(1, n_a)
        out_b = sum(len(n.successors) for n in cfg_b) / max(1, n_b)
        max_out = max(out_a, out_b, 1.0)
        out_sim = 1.0 - min(1.0, abs(out_a - out_b) / max_out)
        return (block_ratio + branch_sim + out_sim) / 3.0

    def _dfg_similarity(self, df_a, df_b) -> float:
        n_a, n_b = len(df_a), len(df_b)
        if n_a == 0 and n_b == 0:
            return 1.0
        if n_a == 0 or n_b == 0:
            return 0.0
        deg_a = Counter(e.var_name for e in df_a)
        deg_b = Counter(e.var_name for e in df_b)
        all_vars = set(deg_a.keys()) | set(deg_b.keys())
        sim_sum = 0.0
        for var in all_vars:
            ca = deg_a.get(var, 0) / max(1, n_a)
            cb = deg_b.get(var, 0) / max(1, n_b)
            sim_sum += 1.0 - min(1.0, abs(ca - cb) * 2)
        return sim_sum / max(1, len(all_vars))

    def _find_inconsistent(self, cfg_orig, cfg_deob) -> List[int]:
        inconsistent = []
        for i, node in enumerate(cfg_deob):
            if not node.successors and i < len(cfg_deob) - 1:
                if not any('return' in inst for inst in node.instructions):
                    inconsistent.append(i)
        return inconsistent
