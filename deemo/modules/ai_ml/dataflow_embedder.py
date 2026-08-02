# 2026-07-29 10:20
# dataflow_embedder.py
# 数据流嵌入器 — 将静态数据流信息编码为嵌入向量辅助漏洞检测
# 依据: DFEPT [Zotero: "Data Flow Embedding for Enhancing Pre-Trained Model Based Vulnerability Detection"]
#       Path-sensitive code embedding via contrastive learning [Zotero]
# 核心: 构造use-def链和到达定值图 → 通过轻量消息传递编码数据流语义

from __future__ import annotations
import re
import math
import hashlib
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ---- helpers ----
def _df_dot(a, b): return sum(x*y for x,y in zip(a,b))
def _df_l2(v):
    n = math.sqrt(sum(x*x for x in v))
    return v if n<1e-12 else [x/n for x in v]
def _df_zeros(n): return [0.0]*n


@dataclass
class DefUseNode:
    """定义-使用节点: 代表程序中一个变量的一次定义或使用"""
    var_name: str
    node_type: str  # 'def' 或 'use'
    instruction_idx: int
    basic_block_id: int
    source_line: str = ""


class DataFlowGraph:
    """到达定值数据流图"""

    def __init__(self):
        self.nodes: List[DefUseNode] = []
        self.edges: List[Tuple[int, int, str]] = []  # (src_idx, dst_idx, edge_type)
        self.var_to_nodes: Dict[str, List[int]] = defaultdict(list)

    def add_def(self, var: str, instr_idx: int, bb_id: int, line=""):
        idx = len(self.nodes)
        self.nodes.append(DefUseNode(var, 'def', instr_idx, bb_id, line))
        self.var_to_nodes[var].append(idx)

    def add_use(self, var: str, instr_idx: int, bb_id: int, line=""):
        idx = len(self.nodes)
        self.nodes.append(DefUseNode(var, 'use', instr_idx, bb_id, line))

        # 连接到最近的同变量def (到达定值)
        if var in self.var_to_nodes:
            for def_idx in reversed(self.var_to_nodes[var]):
                if self.nodes[def_idx].node_type == 'def':
                    self.edges.append((def_idx, idx, 'reaching_def'))
                    break

    def to_feature_matrix(self, embed_dim: int = 32) -> List[List[float]]:
        """将数据流图转换为节点特征矩阵"""
        feats = []
        for n in self.nodes:
            f = [0.0] * embed_dim
            # 节点类型编码
            f[0] = 1.0 if n.node_type == 'def' else 0.0
            # 位置编码 (简单归一化)
            f[1] = n.instruction_idx / 100.0
            f[2] = n.basic_block_id / 50.0
            # 变量名哈希特征
            h = hashlib.md5(n.var_name.encode()).digest()
            for j in range(min(4, embed_dim - 3)):
                f[3 + j] = h[j] / 255.0
            feats.append(f)
        return feats


class DataFlowEmbedder:
    """数据流嵌入器 — DFEPT风格

    将函数的数据流信息编码为固定维度嵌入。
    使用简化消息传递: def节点向可达的use节点传递语义信号。
    """

    def __init__(self, embed_dim: int = 64):
        self.dim = embed_dim
        self._rng_hash = lambda s: int(hashlib.md5(s.encode()).hexdigest()[:8], 16)

    def extract_def_use(self, pseudocode: str) -> DataFlowGraph:
        """从伪代码中提取def-use关系

        使用正则识别赋值语句(定义)和变量引用(使用)
        """
        dfg = DataFlowGraph()
        lines = pseudocode.split('\n')
        bb_id = 0

        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('//') or stripped.startswith('#'):
                continue

            # 追踪基本块边界
            if re.match(r'^\s*(?:label|loc)_\w+:', stripped):
                bb_id += 1

            # 检测赋值: var = expr
            assign_match = re.match(r'^\s*(?:(\w+)\s*=)\s*(.+?)(?:;|$)', stripped)
            if assign_match:
                lhs = assign_match.group(1)
                rhs = assign_match.group(2)
                dfg.add_def(lhs, idx, bb_id, stripped)

                # 识别rhs中的变量使用
                rhs_vars = re.findall(r'\b([a-zA-Z_]\w*)\b', rhs)
                reserved = {'if','else','while','for','return','sizeof','goto','switch','case','break','continue',
                           'int','char','void','long','short','float','double','unsigned','signed','struct','enum',
                           'const','static','extern','volatile','register','typedef','union','bool','true','false'}
                for var in rhs_vars:
                    if var not in reserved and var != lhs:
                        dfg.add_use(var, idx, bb_id, stripped)
                continue

            # 函数调用中的参数使用
            call_match = re.match(r'^\s*(\w+)\s*\((.+?)\)', stripped)
            if call_match:
                args = call_match.group(2)
                arg_vars = re.findall(r'\b([a-zA-Z_]\w*)\b', args)
                reserved = {'if','else','while','for','return','sizeof','goto','switch','case','break','continue',
                           'int','char','void','long','short','float','double','unsigned','signed','struct','enum',
                           'const','static','extern','volatile','register','typedef','union','bool','true','false'}
                for var in arg_vars:
                    if var not in reserved:
                        dfg.add_use(var, idx, bb_id, stripped)

        return dfg

    def embed(self, pseudocode: str) -> List[float]:
        """从伪代码生成数据流嵌入"""
        dfg = self.extract_def_use(pseudocode)
        if not dfg.nodes:
            return _df_zeros(self.dim)

        node_feats = dfg.to_feature_matrix(self.dim)

        # 简化消息传递: def→use
        embeddings = [f[:] for f in node_feats]
        for src, dst, etype in dfg.edges:
            if etype == 'reaching_def' and src < len(embeddings) and dst < len(embeddings):
                # def节点的信号传递到use节点
                for j in range(self.dim):
                    embeddings[dst][j] += 0.3 * embeddings[src][j]

        # 全局池化
        N = len(embeddings)
        pooled = _df_zeros(self.dim)
        for emb in embeddings:
            for j in range(self.dim):
                pooled[j] += emb[j]
        for j in range(self.dim):
            pooled[j] /= max(N, 1)

        return _df_l2(pooled)

    def embed_batch(self, pseudocode_list: List[str]) -> List[List[float]]:
        return [self.embed(pc) for pc in pseudocode_list]


def create_dataflow_embedder(dim: int = 64) -> DataFlowEmbedder:
    return DataFlowEmbedder(embed_dim=dim)
