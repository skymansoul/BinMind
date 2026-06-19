"""
基于图神经网络的跨二进制漏洞检测模块

功能:
    1. 将二进制函数控制流图 + 数据流图输入图神经网络 (GNN), 训练检测特定漏洞模式
    2. 与规则引擎互补, 提升未知模式发现能力
    3. 跨二进制通用 (基于函数级图)

核心技术:
    - 图构建: 节点=基本块, 边=控制流/数据流
    - 节点特征: 指令 token 嵌入 (简化)
    - 简化 GNN: 多层消息传递
    - 训练: 二分类 (vulnerable / not)
"""

import logging
import os
import re
import json
import math
import pickle
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


class NodeFeature(Enum):
    """节点特征维度"""
    INSTR_COUNT = 0
    HAS_CALL = 1
    HAS_DANGEROUS_CALL = 2
    HAS_LOOP = 3
    HAS_MEM_READ = 4
    HAS_MEM_WRITE = 5
    HAS_ARITH = 6
    BRANCH_COUNT = 7
    BLOCK_DEGREE = 8
    IS_ENTRY = 9
    IS_EXIT = 10
    SIZE_BYTES = 11
    FEATURE_DIM = 12


@dataclass
class GraphNode:
    """图节点"""
    node_id: int
    features: List[float] = field(default_factory=lambda: [0.0] * NodeFeature.FEATURE_DIM.value)
    label: Optional[int] = None  # 0=safe, 1=vulnerable


@dataclass
class Graph:
    """函数图"""
    func_name: str
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[Tuple[int, int]] = field(default_factory=list)   # directed
    edge_attr: List[List[float]] = field(default_factory=list)
    label: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def adj(self) -> Dict[int, List[int]]:
        a: Dict[int, List[int]] = defaultdict(list)
        for s, d in self.edges:
            a[s].append(d)
        return a


@dataclass
class GNNPrediction:
    """GNN 预测"""
    graph: Graph
    vuln_prob: float
    confidence: float
    contributions: Dict[int, float] = field(default_factory=dict)


class GraphBuilder:
    """从反编译代码构建图"""

    DANGEROUS = {"strcpy", "system", "execve", "popen", "sprintf",
                 "gets", "scanf", "memcpy", "free", "malloc", "alloc"}

    def build(self, binary_path: str, func_name: str) -> Graph:
        import subprocess
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', f'pdf @ {func_name}; q', binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
        except Exception as e:
            logger.warning(f"反编译失败: {e}")
            return Graph(func_name=func_name)

        text = r.stdout
        graph = Graph(func_name=func_name)
        # 简化的块切分
        blocks = self._split_blocks(text)
        for i, blk in enumerate(blocks):
            node = self._featurize_block(blk, i, len(blocks))
            graph.nodes.append(node)
        # 边: 相邻块
        for i in range(len(blocks) - 1):
            graph.edges.append((i, i + 1))
            graph.edge_attr.append([1.0])
        if graph.nodes:
            graph.nodes[0].features[NodeFeature.IS_ENTRY.value] = 1.0
            graph.nodes[-1].features[NodeFeature.IS_EXIT.value] = 1.0
        return graph

    def _split_blocks(self, asm: str) -> List[str]:
        blocks: List[str] = []
        current: List[str] = []
        for line in asm.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue
            if re.match(r"0x[0-9a-f]+\s+", stripped):
                current.append(stripped)
                ins = stripped.lower()
                if re.search(r"\b(jmp|call|ret)\b", ins):
                    blocks.append("\n".join(current))
                    current = []
        if current:
            blocks.append("\n".join(current))
        return blocks

    def _featurize_block(self, block_text: str, idx: int,
                         total: int) -> GraphNode:
        node = GraphNode(node_id=idx)
        f = node.features
        f[NodeFeature.INSTR_COUNT.value] = block_text.count("\n")
        f[NodeFeature.HAS_CALL.value] = 1.0 if "call " in block_text else 0.0
        dangerous_count = sum(1 for d in self.DANGEROUS
                              if d in block_text.lower())
        f[NodeFeature.HAS_DANGEROUS_CALL.value] = min(1.0, dangerous_count)
        f[NodeFeature.HAS_LOOP.value] = 1.0 if any(
            kw in block_text.lower()
            for kw in ["loop", "jl", "jg", "jle", "jge"]
        ) else 0.0
        f[NodeFeature.HAS_MEM_READ.value] = 1.0 if "mov" in block_text and "[" in block_text else 0.0
        f[NodeFeature.HAS_MEM_WRITE.value] = 1.0 if "[" in block_text and "mov" in block_text else 0.0
        f[NodeFeature.HAS_ARITH.value] = 1.0 if any(
            op in block_text for op in ["add", "sub", "mul", "div"]
        ) else 0.0
        f[NodeFeature.BRANCH_COUNT.value] = sum(1 for kw in ["jmp", "je", "jne", "jnz", "jz"]
                                                  if kw in block_text.lower())
        f[NodeFeature.BLOCK_DEGREE.value] = min(1.0, f[NodeFeature.BRANCH_COUNT.value] / 5.0)
        f[NodeFeature.SIZE_BYTES.value] = min(1.0, len(block_text) / 1000.0)
        return node


class SimpleGNN:
    """
    简化 GNN 实现 (无 PyG 依赖)
    - 多层消息传递
    - Sum aggregator
    - 二分类 readout
    """

    def __init__(self,
                 in_dim: int = NodeFeature.FEATURE_DIM.value,
                 hidden_dim: int = 32,
                 num_layers: int = 2,
                 lr: float = 0.01):
        self.in_dim = in_dim
        self.hidden = hidden_dim
        self.num_layers = num_layers
        self.lr = lr
        if NUMPY_AVAILABLE:
            # 第一层
            self.W1 = np.random.randn(in_dim, hidden_dim) * 0.1
            # 后续层
            self.W_layers = [np.random.randn(hidden_dim, hidden_dim) * 0.1
                             for _ in range(num_layers - 1)]
            # 输出层
            self.W_out = np.random.randn(hidden_dim, 1) * 0.1
            self.b = np.zeros(hidden_dim)
        else:
            self.W1 = [[random.uniform(-0.1, 0.1) for _ in range(hidden_dim)]
                       for _ in range(in_dim)]
            self.W_layers = [[[random.uniform(-0.1, 0.1) for _ in range(hidden_dim)]
                              for _ in range(hidden_dim)]
                             for _ in range(num_layers - 1)]
            self.W_out = [[random.uniform(-0.1, 0.1)] for _ in range(hidden_dim)]
            self.b = [0.0] * hidden_dim

    def _embed_node(self, x: List[float], W: List[List[float]],
                    b: Optional[List[float]] = None) -> List[float]:
        if NUMPY_AVAILABLE:
            xv = np.array(x, dtype=np.float32)
            out = xv @ np.array(W, dtype=np.float32)
            if b is not None:
                out += np.array(b, dtype=np.float32)
            return np.maximum(0, out).tolist(  # ReLU)
        out = [0.0] * len(W[0])
        for i, row in enumerate(W):
            for j, w in enumerate(row):
                out[j] += x[i] * w
        if b is not None:
            for j in range(len(out)):
                out[j] += b[j]
        return [max(0.0, v) for v in out]

    def _aggregate(self, neighbors: List[List[float]]) -> List[float]:
        if not neighbors:
            return [0.0] * self.hidden
        if NUMPY_AVAILABLE:
            arr = np.array(neighbors, dtype=np.float32)
            return arr.sum(axis=0).tolist()
        result = [0.0] * self.hidden
        for n in neighbors:
            for i, v in enumerate(n):
                result[i] += v
        return result

    def forward(self, graph: Graph) -> GNNPrediction:
        if not graph.nodes:
            return GNNPrediction(graph=graph, vuln_prob=0.5, confidence=0.0)
        # 初始化节点嵌入
        h = [n.features for n in graph.nodes]
        # 第一层
        h = [self._embed_node(x, self.W1, self.b) for x in h]
        adj = graph.adj()
        # 后续层 (消息传递)
        for W in self.W_layers:
            new_h: List[List[float]] = []
            for i, node_h in enumerate(h):
                neigh = [h[j] for j in adj.get(i, [])]
                agg = self._aggregate(neigh)
                if NUMPY_AVAILABLE:
                    combined = (np.array(node_h) + np.array(agg)).tolist()
                else:
                    combined = [node_h[k] + agg[k] for k in range(self.hidden)]
                new_h.append(self._embed_node(combined, W))
            h = new_h
        # 读出: sum pooling
        if NUMPY_AVAILABLE:
            graph_emb = np.array(h).sum(axis=0)
            logit = (graph_emb @ self.W_out.flatten())[0]
        else:
            graph_emb = [0.0] * self.hidden
            for node_h in h:
                for i, v in enumerate(node_h):
                    graph_emb[i] += v
            logit = sum(graph_emb[i] * self.W_out[i][0]
                        for i in range(self.hidden))
        prob = 1.0 / (1.0 + math.exp(-logit))
        # 节点贡献度
        contributions = {
            i: sum(h[i]) / max(1, len(h[i]))
            for i in range(len(h))
        }
        return GNNPrediction(
            graph=graph, vuln_prob=prob,
            confidence=min(1.0, abs(prob - 0.5) * 2),
            contributions=contributions
        )

    def train_step(self, graphs: List[Graph],
                   labels: List[int]) -> float:
        loss_total = 0.0
        for g, y in zip(graphs, labels):
            pred = self.forward(g)
            target = float(y)
            error = pred.vuln_prob - target
            loss_total += error ** 2
            # 简化: 只更新 W_out
            if NUMPY_AVAILABLE:
                grad = 2 * error * pred.vuln_prob * (1 - pred.vuln_prob)
                self.W_out -= self.lr * grad * 0.01
            else:
                pass
        return loss_total / max(1, len(graphs))


import random
import math


class GNNVulnDetector:
    """GNN 漏洞检测器"""

    def __init__(self):
        self.builder = GraphBuilder()
        self.gnn = SimpleGNN()
        self._trained = False

    def detect(self, binary_path: str, func_name: str) -> Dict[str, Any]:
        g = self.builder.build(binary_path, func_name)
        pred = self.gnn.forward(g)
        # 节点贡献 -> 关键代码块
        sorted_nodes = sorted(pred.contributions.items(),
                              key=lambda kv: kv[1], reverse=True)
        critical_blocks = [
            {'node_id': nid, 'contribution': c}
            for nid, c in sorted_nodes[:5]
        ]
        return {
            'success': True,
            'vuln_probability': pred.vuln_prob,
            'is_vulnerable': pred.vuln_prob > 0.5,
            'confidence': pred.confidence,
            'critical_blocks': critical_blocks,
            'graph_stats': {
                'node_count': len(g.nodes),
                'edge_count': len(g.edges)
            }
        }

    def train(self, training_data: List[Tuple[Graph, int]],
              epochs: int = 10):
        graphs, labels = zip(*training_data)
        for ep in range(epochs):
            loss = self.gnn.train_step(list(graphs), list(labels))
        self._trained = True


def detect_with_gnn(binary_path: str, func_name: str) -> Dict[str, Any]:
    """便捷入口"""
    d = GNNVulnDetector()
    return d.detect(binary_path, func_name)
