# ISA无关VEX IR编码器: 二进制代码 → VEX IR语句 → 图拓扑嵌入
# 用于 cross_isa_alignment.py 的跨ISA零样本语义对齐

import math
import logging
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

logger = logging.getLogger(__name__)


class VexOpCategory(Enum):
    """VEX IR操作分类-ISA无关语义标签。

    VEX IR的opcode集合是封闭且ISA无关的。
    这使跨ISA统一操作语义空间成为可能。
    """
    ARITH = 'arith'
    LOGIC = 'logic'
    COMPARE = 'compare'
    MEM_LOAD = 'mem_load'
    MEM_STORE = 'mem_store'
    BRANCH = 'branch'
    CALL = 'call'
    CONST = 'const'
    CAST = 'cast'
    UNKNOWN = 'unknown'


_VEX_OP_MAP: Dict[str, VexOpCategory] = {
    'Iop_Add': VexOpCategory.ARITH, 'Iop_Sub': VexOpCategory.ARITH,
    'Iop_Mul': VexOpCategory.ARITH, 'Iop_Div': VexOpCategory.ARITH,
    'Iop_And': VexOpCategory.LOGIC, 'Iop_Or': VexOpCategory.LOGIC,
    'Iop_Xor': VexOpCategory.LOGIC, 'Iop_Shl': VexOpCategory.LOGIC,
    'Iop_Shr': VexOpCategory.LOGIC, 'Iop_Not': VexOpCategory.LOGIC,
    'Iop_CmpEQ': VexOpCategory.COMPARE, 'Iop_CmpNE': VexOpCategory.COMPARE,
    'Iop_CmpLT': VexOpCategory.COMPARE, 'Iop_CmpLE': VexOpCategory.COMPARE,
    'Iop_Load': VexOpCategory.MEM_LOAD, 'Iop_LoadG': VexOpCategory.MEM_LOAD,
    'Iop_Store': VexOpCategory.MEM_STORE, 'Iop_StoreG': VexOpCategory.MEM_STORE,
    'Iop_Call': VexOpCategory.CALL,
    'Iop_Const': VexOpCategory.CONST,
    'Iop_Cast': VexOpCategory.CAST, 'Iop_Reinterp': VexOpCategory.CAST,
}


@dataclass
class VexIRStatement:
    """VEX IR语句的ISA无关抽象"""
    op_name: str
    op_category: VexOpCategory
    args: List[str] = field(default_factory=list)
    result: str = ""
    address: int = 0
    stmt_idx: int = 0

    def category_vector(self) -> List[float]:
        cats = list(VexOpCategory)
        return [1.0 if self.op_category == c else 0.0 for c in cats]


class ISAPivotEncoder:
    """ISA无关枢轴编码器: 二进制代码 → VEX IR → 图嵌入。

    所有ISA差异在VEX IR层被归一化。后续图构建和嵌入
    完全在VEX IR语义空间中进行。
    """

    FEATURE_DIM = 10
    TOPO_DIM = 11

    def __init__(self, embedding_dim: int = 128):
        self.embed_dim = embedding_dim
        rng = np.random.RandomState(42)
        total_dim = self.FEATURE_DIM + self.TOPO_DIM
        self._projection = rng.randn(embedding_dim, total_dim) / math.sqrt(total_dim)

    def encode(self,
               vex_stmts: List[VexIRStatement],
               cfg_adjacency: Optional[List[List[int]]] = None) -> np.ndarray:
        if not vex_stmts:
            return np.zeros(self.embed_dim, dtype=np.float64)

        cat_counts = defaultdict(int)
        for stmt in vex_stmts:
            cat_counts[stmt.op_category] += 1
        cat_vec = np.array(
            [cat_counts.get(c, 0) / max(1, len(vex_stmts))
             for c in VexOpCategory], dtype=np.float64)

        bigram_counts = defaultdict(int)
        for i in range(len(vex_stmts) - 1):
            bigram = (vex_stmts[i].op_category, vex_stmts[i+1].op_category)
            bigram_counts[bigram] += 1
        top_bigrams = sorted(bigram_counts.items(), key=lambda x: -x[1])[:10]
        bigram_vec = np.zeros(10, dtype=np.float64)
        for idx, (_, count) in enumerate(top_bigrams):
            bigram_vec[idx] = count / max(1, len(vex_stmts) - 1)

        if cfg_adjacency and len(cfg_adjacency) > 1:
            topo_vec = self._extract_cfg_topology(cfg_adjacency)
        else:
            topo_vec = np.zeros(self.TOPO_DIM, dtype=np.float64)
            topo_vec[0] = len(vex_stmts) / 200.0

        combined = np.concatenate([cat_vec, bigram_vec, topo_vec])
        if len(combined) > self.FEATURE_DIM + self.TOPO_DIM:
            combined = combined[:self.FEATURE_DIM + self.TOPO_DIM]
        elif len(combined) < self.FEATURE_DIM + self.TOPO_DIM:
            combined = np.pad(combined,
                            (0, self.FEATURE_DIM + self.TOPO_DIM - len(combined)))

        embedding = self._projection @ combined
        norm = np.linalg.norm(embedding)
        if norm > 1e-12:
            embedding /= norm
        return embedding

    def _extract_cfg_topology(self, adjacency: List[List[int]]) -> np.ndarray:
        n = len(adjacency)
        if n == 0:
            return np.zeros(self.TOPO_DIM, dtype=np.float64)
        degrees = [sum(row) for row in adjacency]
        n_edges = sum(degrees)
        avg_deg = n_edges / max(1, n)
        deg_var = float(np.var(degrees)) if n > 1 else 0.0
        deg_counts = defaultdict(int)
        for d in degrees:
            deg_counts[d] += 1
        total = sum(deg_counts.values())
        deg_entropy = -sum((c/total) * math.log(c/total + 1e-12)
                          for c in deg_counts.values())
        dists = []
        for src in np.random.choice(n, size=min(10, n), replace=False):
            dist = [n * 2] * n
            dist[src] = 0
            q = deque([src])
            while q:
                u = q.popleft()
                for v in range(n):
                    if adjacency[u][v] and dist[v] > dist[u] + 1:
                        dist[v] = dist[u] + 1
                        q.append(v)
            finite = [d for d in dist if d < n * 2]
            if finite:
                dists.append(float(np.mean(finite)))
        avg_path = float(np.mean(dists)) if dists else 0.0
        visited = [False] * n
        components = 0
        for i in range(n):
            if visited[i]:
                continue
            components += 1
            q = deque([i])
            visited[i] = True
            while q:
                u = q.popleft()
                for v in range(n):
                    if not visited[v] and (adjacency[u][v] or adjacency[v][u]):
                        visited[v] = True
                        q.append(v)
        leaf_count = sum(1 for d in degrees if d <= 1)
        return np.array([
            math.log(1 + n), math.log(1 + n_edges), avg_deg / 10.0,
            math.log(1 + deg_var), math.log(1 + components),
            min(1.0, avg_path / 20.0), deg_entropy,
            leaf_count / max(1, n), max(degrees) / 50.0 if degrees else 0.0,
            min(1.0, avg_path / 10.0), deg_var / 100.0,
        ], dtype=np.float64)
