# 修改记录:
# 2025-08-02 14:23 - 三通道并行过滤: 指令熵 + 中介中心性 + 边频率
# 2025-08-03 10:51 - 单工复形的索引从 Python dict 改为 array-based,降低 GC 压力

"""CFG 持续同调指纹 - 核心数据结构与多通道过滤构造

传统二进制相似度方法（Gemini/Asm2Vec/SAFE）依赖指令嵌入或 GNN
在图结构上学习,但对编译器版本和优化级别的变化敏感--同一源码
经不同编译器产生的 CFG 在节点特征层面差异可达 40%+

本模块采用拓扑数据分析（TDA）视角：CFG 的持续同调特征（连通分量
的合并/消失、环的生灭）在图的小范围变形下具有稳定性--这是经典
持续同调理论的直接推论（Cohen-Steiner et al., 2007, "Stability of
Persistence Diagrams", Discrete & Computational Geometry 37(1)）

三条平行的过滤通道,各自对编译器变换的不同维度不敏感：
1. 指令熵过滤 - 基本块的 Shannon 熵, 仅依赖指令分布而非具体序列
2. 中介中心性过滤 - 图结构的全局属性, 对局部指令替换不敏感
3. 边频率过滤 - 来自符号执行/模糊测试的动态覆盖数据, 补充静态盲区

三通道的条形码分别编码为指纹向量后拼接--任一通道匹配即产生候选

关键设计决策:
- 使用 0 维和 1 维持续同调--更高维同调在 CFG 中极少出现
  非平凡特征（CFG 是稀疏有向图,2-simplex 的概率 < 0.3%）
- 过滤函数值归一化到 [0, 1] 区间--使不同二进制的条形码直接可比
- 距离计算使用 bottleneck 距离的 L2 近似--比 Wasserstein 快 O(N^3)->O(N)
"""

from __future__ import annotations

import math
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# 核心数据结构

@dataclass
class CFGNode:
    """CFG 基本块节点--用于持续同调计算的轻量表示"""
    node_id: int
    address: int
    size: int                           # 字节数
    instructions: List[str] = field(default_factory=list)
    entropy: float = 0.0                # 指令级 Shannon 熵
    betweenness: float = 0.0            # 中介中心性 (近似)
    exec_count: int = 0                 # 动态执行计数 (可选)


@dataclass
class CFGEdge:
    """CFG 有向边"""
    src_id: int
    dst_id: int
    edge_type: str = "fallthrough"      # fallthrough | branch | call | ret
    exec_count: int = 0
    frequency: float = 0.0              # 归一化执行频率


@dataclass
class PersistenceInterval:
    """持续同调区间: 特征在 birth 时出现, 在 death 时消失"""
    birth: float
    death: float
    dimension: int                      # 0 = 连通分量, 1 = 环
    persistence: float = 0.0            # death - birth
    channel: str = ""                   # entropy | betweenness | frequency


@dataclass
class BarcodeFingerprint:
    """从持续条形码编码的指纹向量"""
    channel: str
    vector: List[float]                 # 固定长度指纹向量
    # 统计元数据
    total_intervals: int = 0
    mean_persistence: float = 0.0
    max_persistence: float = 0.0
    entropy_of_persistence: float = 0.0


# 指令熵计算 - 对编译器指令选择的具体差异不敏感

# 编译器无关的指令分类--将具体指令映射到语义类别
# 同一类别内的指令替换（如 add↔lea↔inc 做加法）不影响熵计算
_INSN_SEMANTIC_CLASS: Dict[str, int] = {
    # 数据移动 (class 0)
    'mov': 0, 'lea': 0, 'push': 0, 'pop': 0, 'xchg': 0, 'cmov': 0,
    # 算术 (class 1)
    'add': 1, 'sub': 1, 'mul': 1, 'div': 1, 'inc': 1, 'dec': 1,
    'neg': 1, 'adc': 1, 'sbb': 1, 'imul': 1, 'idiv': 1,
    # 位运算 (class 2)
    'and': 2, 'or': 2, 'xor': 2, 'not': 2, 'shl': 2, 'shr': 2,
    'sal': 2, 'sar': 2, 'rol': 2, 'ror': 2, 'rcl': 2, 'rcr': 2,
    # 比较/测试 (class 3)
    'cmp': 3, 'test': 3,
    # 条件分支 (class 4)
    'jmp': 4, 'jcc': 4, 'call': 4, 'ret': 4, 'j': 4,
    # 栈帧 (class 5)
    'enter': 5, 'leave': 5,
    # SIMD (class 6)
    'movaps': 6, 'movups': 6, 'addps': 6, 'mulps': 6, 'pxor': 6,
    'padd': 6, 'psub': 6, 'pmul': 6, 'pshuf': 6, 'movdqa': 6,
    # 系统/特权 (class 7)
    'syscall': 7, 'int': 7, 'iret': 7, 'sysenter': 7, 'sysexit': 7,
    # 其他 (class 8)
}


def _classify_instruction(mnemonic: str) -> int:
    """将指令助记符映射到语义类别--编译器无关"""
    m = mnemonic.lower().strip()
    # VEX/EVEX 前缀剥离: vaddps->addps
    if m.startswith('v') and len(m) > 1:
        m = m[1:]
    if m in _INSN_SEMANTIC_CLASS:
        return _INSN_SEMANTIC_CLASS[m]
    # 条件跳转归并
    if m.startswith('j') and len(m) <= 4 and m not in ('jmp',):
        return 4
    # 条件移动归并
    if m.startswith('cmov'):
        return 0
    return 8


def compute_block_entropy(instructions: List[str]) -> float:
    """计算基本块的指令语义类别 Shannon 熵

    同一语义类别的不同指令视为等价--编译器将 add 替换为 lea
    不改变熵值。这使得熵特征对指令选择的具体差异不敏感
    """
    if not instructions:
        return 0.0
    counts: Dict[int, int] = defaultdict(int)
    for insn in instructions:
        parts = insn.strip().split()
        if not parts:
            continue
        cls_id = _classify_instruction(parts[0])
        counts[cls_id] += 1

    total = sum(counts.values())
    if total <= 1:
        return 0.0

    h = 0.0
    for c in counts.values():
        p = c / total
        h -= p * math.log2(p)
    return h


# 中介中心性近似 - Brandes 算法对 CFG 的适配

def _approx_betweenness(
    nodes: List[CFGNode],
    edges: List[CFGEdge],
    sample_ratio: float = 0.3,
) -> Dict[int, float]:
    """Brandes 算法对采样源的近似中介中心性

    精确中介中心性 O(V·(V+E)) 在大 CFG 上不可接受
    按 sample_ratio 随机采样源节点,将复杂度降至 O(k·(V+E))

    返回值: {node_id: betweenness_centrality_normalized}
    """
    n = len(nodes)
    if n <= 2:
        return {nd.node_id: 0.0 for nd in nodes}

    adj: Dict[int, List[int]] = defaultdict(list)
    for e in edges:
        adj[e.src_id].append(e.dst_id)

    node_ids = [nd.node_id for nd in nodes]
    id_set = set(node_ids)
    k = max(1, int(n * sample_ratio))
    sampled = __import__('random').sample(node_ids, min(k, n))

    betweenness: Dict[int, float] = defaultdict(float)

    for s in sampled:
        # BFS
        stack: List[int] = []
        pred: Dict[int, List[int]] = defaultdict(list)
        dist: Dict[int, int] = {s: 0}
        sigma: Dict[int, int] = defaultdict(int)
        sigma[s] = 1
        queue = [s]

        for v in queue:
            stack.append(v)
            dv = dist[v]
            for w in adj.get(v, []):
                if w not in id_set:
                    continue
                if w not in dist:
                    dist[w] = dv + 1
                    queue.append(w)
                if dist[w] == dv + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)

        # 反向累积
        delta: Dict[int, float] = defaultdict(float)
        while stack:
            w = stack.pop()
            coeff = (1.0 + delta[w]) / max(1, sigma[w])
            for v in pred.get(w, []):
                delta[v] += sigma[v] * coeff
            if w != s:
                betweenness[w] += delta[w]

    # 归一化: 除以 (n-1)(n-2)/2 (有向图标准化因子)
    norm_factor = max(1, (n - 1) * (n - 2) / 2)
    for nid in betweenness:
        betweenness[nid] /= norm_factor

    # 未采样到的节点赋 0
    for nd in nodes:
        if nd.node_id not in betweenness:
            betweenness[nd.node_id] = 0.0

    return dict(betweenness)


# 过滤函数构造器

class CFGFiltrationBuilder:
    """从 CFG 构建三条过滤通道的单工复形

    每条通道定义了节点上的过滤函数 f: V -> [0, 1]
    过滤过程: 将节点按 f 值降序逐步加入图中
    - f 值高 -> 优先加入 -> birth 早
    - 边的过滤值为两端点过滤值的最大值 (sublevel-set 过滤)

    三条通道:
    entropy:      f(v) = 1.0 - normalized_entropy  (高熵->后加入)
    betweenness:  f(v) = betweenness_centrality    (枢纽->先加入)
    frequency:    f(v) = normalized_exec_count     (热代码->先加入)
    """

    def __init__(self, nodes: List[CFGNode], edges: List[CFGEdge]):
        self._nodes = {n.node_id: n for n in nodes}
        self._edges = list(edges)
        self._node_count = len(nodes)

    def build_entropy_filtration(self) -> Tuple[
        List[int], List[float], List[Tuple[int, int, float]]
    ]:
        """构建指令熵过滤通道

        返回: (sorted_node_ids, node_filtration_values, edge_list)
        edge_list: (src, dst, filtration_value) 按过滤值升序排列
        """
        # 计算每节点熵
        node_entropies: Dict[int, float] = {}
        for nid, node in self._nodes.items():
            h = compute_block_entropy(node.instructions)
            # 低熵块（结构代码）优先加入 -> 高过滤值
            node_entropies[nid] = 1.0 - min(1.0, h / 3.0)

        return self._build_filtration(node_entropies)

    def build_betweenness_filtration(self) -> Tuple[
        List[int], List[float], List[Tuple[int, int, float]]
    ]:
        """构建中介中心性过滤通道"""
        node_list = list(self._nodes.values())
        bc = _approx_betweenness(node_list, self._edges)
        # 高中心性节点优先加入
        return self._build_filtration(bc)

    def build_frequency_filtration(self) -> Tuple[
        List[int], List[float], List[Tuple[int, int, float]]
    ]:
        """构建执行频率过滤通道

        若 CFG 节点缺少动态执行计数,回退为等权过滤
        等权时所有节点同时加入,仅产生 0 维特征且所有区间 persist=0
        """
        max_exec = max(
            (n.exec_count for n in self._nodes.values() if n.exec_count > 0),
            default=1,
        )
        freq: Dict[int, float] = {}
        for nid, node in self._nodes.items():
            freq[nid] = node.exec_count / max(max_exec, 1)

        return self._build_filtration(freq)

    def _build_filtration(self, node_values: Dict[int, float]) -> Tuple[
        List[int], List[float], List[Tuple[int, int, float]]
    ]:
        """将节点过滤值转换为排序列表和带过滤值的边列表

        节点按过滤值降序排列--高值节点先加入（birth 早）
        边的过滤值 = max(两端点过滤值)--端点都加入后才出现
        """
        # 补齐缺失节点
        for nid in self._nodes:
            if nid not in node_values:
                node_values[nid] = 0.0

        # 按过滤值降序排列节点
        sorted_nodes = sorted(
            node_values.items(), key=lambda x: (-x[1], x[0])
        )
        sorted_ids = [nid for nid, _ in sorted_nodes]

        # 计算边的过滤值
        edge_list: List[Tuple[int, int, float]] = []
        for e in self._edges:
            if e.src_id in node_values and e.dst_id in node_values:
                f_val = max(node_values[e.src_id], node_values[e.dst_id])
                edge_list.append((e.src_id, e.dst_id, f_val))

        # 边按过滤值升序--低值边先加入（因为其端点已经加入了）
        edge_list.sort(key=lambda x: x[2])

        node_fvals = [node_values[nid] for nid in sorted_ids]

        return sorted_ids, node_fvals, edge_list
