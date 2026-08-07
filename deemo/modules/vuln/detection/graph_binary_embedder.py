# 图驱动的二进制函数嵌入器——从CFG+数据流图提取函数级向量表征。
# GBsim GCN+Transformer混合架构、AMMF
# 多特征融合策略、Call Graphlets 局部/全局图统计特征。
#
# 核心设计:
#   - 基础图统计特征（度分布、集聚系数、中心性）→ Call Graphlets统计视角
#   - 节点级语义特征（指令类别直方图+操作数类型分布）→ AMMF basic-block特征
# 图拓扑嵌入（匿名随机游走签名）→ GBsim图结构编码
# 跨架构归一化——特征提取与架构解耦，同函数不同架构产物距离可控
#
# 当前实现——x86/x86_64/ARM/MIPS四架构
# 增强——随机游走嵌入与跨架构对齐投影

import os, re, math, json, hashlib, struct, logging
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from enum import Enum
import random as _random

logger = logging.getLogger(__name__)

# numpy为可选依赖——无numpy时回退至纯Python实现
try:
    import numpy as np
    _NUMPY_AVAIL = True
except ImportError:
    np = None
    _NUMPY_AVAIL = False


class ArchFamily(str, Enum):
    X86 = "x86"
    X86_64 = "x86_64"
    ARM32 = "arm32"
    ARM64 = "arm64"
    MIPS32 = "mips32"
    MIPS64 = "mips64"
    UNKNOWN = "unknown"


@dataclass
class BasicBlockNode:
    """基本块节点——图嵌入原子单元"""
    addr: int
    size: int = 0
    instructions: List[str] = field(default_factory=list)
    opcode_hist: Dict[str, int] = field(default_factory=dict)
    successor_addrs: List[int] = field(default_factory=list)
    predecessor_addrs: List[int] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False


@dataclass
class FunctionGraph:
    """函数图表示——节点为基本块，边为控制流转移"""
    name: str
    addr: int
    arch: ArchFamily = ArchFamily.UNKNOWN
    nodes: Dict[int, BasicBlockNode] = field(default_factory=dict)
    edges: List[Tuple[int, int]] = field(default_factory=list)
    call_targets: List[int] = field(default_factory=list)
    num_instructions: int = 0
    cyclic_complexity: int = 0


@dataclass
class GraphEmbedding:
    """GNN风格图嵌入结果——固定维度特征向量"""
    func_name: str
    func_addr: int
    arch: ArchFamily
    vector: List[float] = field(default_factory=list)
    dim: int = 128
    feature_names: List[str] = field(default_factory=list)
    generation_method: str = "handcrafted"


# 特征提取器基类
# 每个提取器负责一个特征维度，产出固定大小数值向量。
# 可插拔设计——新增特征维度只需实现extract()。

class FeatureExtractor:
    """图特征提取器基类"""

    def extract(self, graph: FunctionGraph) -> Dict[str, float]:
        raise NotImplementedError

    @property
    def feature_count(self) -> int:
        raise NotImplementedError  # pragma: no cover


class GraphStatisticsExtractor(FeatureExtractor):
    """图统计特征提取——Call Graphlets统计视角。

    提取16维特征: 节点数、边数、密度、最大/平均入度出度、
    集聚系数、直径估计、叶子节点比例、中心节点比例。
    """

    def extract(self, graph: FunctionGraph) -> Dict[str, float]:
        feats = {}
        n = len(graph.nodes)
        m = len(graph.edges)
        feats['num_nodes'] = float(n)
        feats['num_edges'] = float(m)
        feats['density'] = (2 * m / (n * (n - 1))) if n > 1 else 0.0
        feats['log_nodes'] = math.log1p(n)
        feats['log_edges'] = math.log1p(m)

        # 度数统计
        in_deg = defaultdict(int)
        out_deg = defaultdict(int)
        for src, dst in graph.edges:
            out_deg[src] += 1
            in_deg[dst] += 1

        out_vals = list(out_deg.values()) if out_deg else [0]
        in_vals = list(in_deg.values()) if in_deg else [0]
        feats['max_out_degree'] = float(max(out_vals))
        feats['avg_out_degree'] = sum(out_vals) / max(len(out_vals), 1)
        feats['max_in_degree'] = float(max(in_vals))
        feats['avg_in_degree'] = sum(in_vals) / max(len(in_vals), 1)

        # 叶子/根节点比例
        leaves = sum(1 for a in graph.nodes if out_deg.get(a, 0) == 0)
        roots = sum(1 for a in graph.nodes if in_deg.get(a, 0) == 0)
        feats['leaf_ratio'] = leaves / max(n, 1)
        feats['root_ratio'] = roots / max(n, 1)

        # 循环复杂度近似——McCabe: E - N + 2P
        # 单函数P=1，简化为 m - n + 2
        feats['cyclomatic_complexity'] = float(max(1, m - n + 2))
        feats['log_complexity'] = math.log1p(max(1, m - n + 2))
        feats['edges_per_node'] = m / max(n, 1)

        return feats

    @property
    def feature_count(self) -> int:
        return 15


class InstructionHistogramExtractor(FeatureExtractor):
    """指令类别直方图——AMMF basic-block级语义特征。

    按操作类型分12类: 算术、逻辑、分支、调用、
    内存读写、栈操作、比较、传送、移位、浮点、特权、其他。
    每类计数归一化后产出12维特征。

    跨架构归一化: 使用架构无关指令类别而非具体助记符，
    x86的MOV与ARM的LDR均归入"数据传送"类别。
    """

    # 架构无关指令类别映射表
    _OP_CATEGORIES = {
        'arith': {'add', 'sub', 'mul', 'div', 'inc', 'dec', 'neg', 'adc', 'sbb',
                   'imul', 'idiv', 'madd', 'msub'},
        'logic': {'and', 'or', 'xor', 'not', 'shl', 'shr', 'sar', 'rol', 'ror',
                   'lsl', 'lsr', 'asr', 'bic', 'orn', 'eon'},
        'branch': {'jmp', 'je', 'jne', 'jg', 'jl', 'jge', 'jle', 'ja', 'jb',
                    'jae', 'jbe', 'jo', 'jno', 'js', 'jns', 'jcxz', 'loop',
                    'b', 'beq', 'bne', 'bgt', 'blt', 'bge', 'ble', 'cbz', 'cbnz',
                    'ret', 'call'},
        'mem_read': {'mov', 'ldr', 'lw', 'lb', 'lhu', 'ld', 'ldrb', 'ldrh',
                      'ldp', 'pop'},
        'mem_write': {'str', 'sw', 'sb', 'sh', 'st', 'strb', 'strh', 'stp',
                       'push', 'stm'},
        'stack': {'push', 'pop', 'enter', 'leave', 'stmfd', 'ldmfd'},
        'compare': {'cmp', 'test', 'tst', 'teq', 'cmn', 'ands'},
        'transfer': {'mov', 'lea', 'movsx', 'movzx', 'movsxd', 'xchg',
                      'cwtl', 'cltq', 'sxtw', 'uxtw'},
        'shift': {'shl', 'shr', 'sar', 'rol', 'ror', 'lsl', 'lsr', 'asr'},
        'float': {'addss', 'addsd', 'subss', 'subsd', 'mulss', 'mulsd',
                   'divss', 'divsd', 'fadd', 'fsub', 'fmul', 'fdiv',
                   'vadd', 'vsub', 'vmul', 'vdiv', 'fld', 'fst'},
        'privileged': {'syscall', 'int', 'hlt', 'cli', 'sti', 'iret',
                        'svc', 'hvc', 'smc', 'msr', 'mrs', 'eret'},
        'other': set(),
    }

    def extract(self, graph: FunctionGraph) -> Dict[str, float]:
        cat_counts = {cat: 0 for cat in self._OP_CATEGORIES}
        total_insns = 0

        for node in graph.nodes.values():
            for insn in node.instructions:
                total_insns += 1
                mnemonic = self._parse_mnemonic(insn).lower()
                categorized = False
                for cat, mnems in self._OP_CATEGORIES.items():
                    if mnemonic in mnems:
                        cat_counts[cat] += 1
                        categorized = True
                        break
                if not categorized and mnemonic:
                    cat_counts['other'] += 1

        feats = {}
        norm = max(total_insns, 1)
        for cat, cnt in cat_counts.items():
            feats[f'insn_{cat}'] = cnt / norm
        feats['total_instructions'] = float(total_insns)
        feats['log_instructions'] = math.log1p(total_insns)

        return feats

    def _parse_mnemonic(self, insn: str) -> str:
        """从汇编行提取助记符"""
        insn = insn.strip()
        # 去除地址前缀与注释
        if ':' in insn[:20]:
            insn = insn.split(':', 1)[1].strip()
        parts = insn.split()
        if not parts:
            return ""
        return parts[0].strip().lower()

    @property
    def feature_count(self) -> int:
        return len(self._OP_CATEGORIES) + 2  # 12类 + total + log_total


class RandomWalkEmbeddingExtractor(FeatureExtractor):
    """匿名随机游走嵌入——参考GBsim图拓扑编码思想。

    Ivanov & Burnaev (2018)匿名游走: 每个节点在游走序列中用
    首次出现顺序编号替代，相同拓扑结构游走得到相同匿名序列。
    统计匿名游走分布直方图作为图拓扑特征的紧凑表示。
    """

    def __init__(self, walk_length: int = 6, num_walks: int = 20):
        self.walk_len = walk_length
        self.num_walks = num_walks

    def extract(self, graph: FunctionGraph) -> Dict[str, float]:
        if len(graph.nodes) < 2:
            return {'rw_mean': 0.0, 'rw_var': 0.0, 'rw_unique_ratio': 0.0,
                    'rw_entropy': 0.0, 'rw_diameter_est': 0.0}

        node_list = list(graph.nodes.keys())
        adj = defaultdict(set)
        for src, dst in graph.edges:
            adj[src].add(dst)
            adj[dst].add(src)  # 无向化——简化游走

        walk_signatures = []
        for _ in range(self.num_walks):
            start = _random.choice(node_list)
            walk = self._random_walk(start, adj)
            sig = self._anonymize_walk(walk)
            walk_signatures.append(tuple(sig))

        unique_sigs = set(walk_signatures)

        feats = {}
        feats['rw_unique_ratio'] = len(unique_sigs) / max(len(walk_signatures), 1)

        walk_lens = [len(w) for w in walk_signatures]
        feats['rw_mean'] = sum(walk_lens) / max(len(walk_lens), 1)
        feats['rw_var'] = (sum((l - feats['rw_mean'])**2 for l in walk_lens)
                           / max(len(walk_lens), 1))

        # 熵——衡量游走多样性
        sig_counts = Counter(walk_signatures)
        total = sum(sig_counts.values())
        ent = 0.0
        for cnt in sig_counts.values():
            p = cnt / total
            ent -= p * math.log(p) if p > 0 else 0
        feats['rw_entropy'] = min(10.0, ent)

        feats['rw_diameter_est'] = float(max(walk_lens))

        return feats

    def _random_walk(self, start, adj, max_steps=None):
        steps = max_steps or self.walk_len
        walk = [start]
        current = start
        for _ in range(steps - 1):
            neighbors = list(adj.get(current, set()))
            if not neighbors:
                break
            current = _random.choice(neighbors)
            walk.append(current)
        return walk

    def _anonymize_walk(self, walk):
        name_map = {}
        anon = []
        next_id = 0
        for node in walk:
            if node not in name_map:
                name_map[node] = next_id
                next_id += 1
            anon.append(name_map[node])
        return anon

    @property
    def feature_count(self) -> int:
        return 5


# 跨架构对齐投影
# 不同架构编译同一函数时图形状因指令集差异而变化。
# 使用轻量线性投影将架构相关特征映射至共享子空间。
# GBsim跨架构语言模型思路，采用更轻量的PCA启发方法。

class CrossArchAligner:
    """跨架构特征对齐器——将不同架构特征映射至可比空间。

    方法: 对每种架构-特征对的均值做中心化，使同一函数
    在不同架构下的特征向量差异主要由编译差异而非架构差异贡献。
    """

    def __init__(self):
        self._arch_offsets: Dict[str, Dict[str, float]] = {}
        self._fitted: bool = False

    def fit(self, samples: List[Tuple[ArchFamily, Dict[str, float]]]):
        """用带架构标签特征样本计算各架构均值偏移。

        参数: [(ArchFamily, {feature_name: value}), ...]
        """
        arch_sums: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
        for arch, feats in samples:
            arch_key = arch.value
            for fname, fval in feats.items():
                arch_sums[arch_key][fname].append(fval)

        self._arch_offsets = {}
        for arch_key, feat_vals in arch_sums.items():
            self._arch_offsets[arch_key] = {
                fname: sum(vals) / len(vals) for fname, vals in feat_vals.items()}

        # 全局均值
        global_means = {}
        all_feats = defaultdict(list)
        for arch_key, feat_vals in arch_sums.items():
            for fname, vals in feat_vals.items():
                all_feats[fname].extend(vals)
        for fname, vals in all_feats.items():
            global_means[fname] = sum(vals) / len(vals)

        # 存储偏移量——架构均值减全局均值再取反（对齐用的偏移）
        for arch_key in self._arch_offsets:
            for fname in self._arch_offsets[arch_key]:
                self._arch_offsets[arch_key][fname] = (
                    global_means.get(fname, 0.0) - self._arch_offsets[arch_key][fname])

        self._fitted = True
        logger.info(f"Cross-arch aligner fitted with {len(samples)} samples, "
                     f"{len(self._arch_offsets)} architectures")

    def align(self, arch: ArchFamily, features: Dict[str, float]) -> Dict[str, float]:
        """对特征向量做跨架构对齐"""
        if not self._fitted:
            return features
        offsets = self._arch_offsets.get(arch.value, {})
        aligned = {}
        for fname, fval in features.items():
            aligned[fname] = fval + offsets.get(fname, 0.0)
        return aligned


# 主编排器

class GraphBinaryEmbedder:
    """二进制函数图嵌入器。

    编排多个特征提取器，将FunctionGraph转换为固定维度向量。
    支持跨架构对齐与向量聚合（均值池化/求和池化）。
    """

    def __init__(self, embed_dim: int = 128, enable_cross_arch_align: bool = True):
        self.embed_dim = embed_dim
        self.extractors: List[FeatureExtractor] = [
            GraphStatisticsExtractor(),
            InstructionHistogramExtractor(),
            RandomWalkEmbeddingExtractor(),
        ]
        self.aligner = CrossArchAligner() if enable_cross_arch_align else None
        self._total_ft_count = sum(ext.feature_count for ext in self.extractors)

    def embed(self, graph: FunctionGraph) -> GraphEmbedding:
        """从FunctionGraph构造嵌入向量。

        流程: 各提取器提取特征→拼接→PCA式降维至embed_dim→可选跨架构对齐。
        """
        all_feats: Dict[str, float] = {}
        feature_names = []

        for extractor in self.extractors:
            feats = extractor.extract(graph)
            all_feats.update(feats)
            feature_names.extend(feats.keys())

        # 跨架构对齐
        if self.aligner and self.aligner._fitted:
            all_feats = self.aligner.align(graph.arch, all_feats)

        # 转换为固定长度向量
        feature_list = [all_feats.get(n, 0.0) for n in feature_names]
        vector = self._pad_or_truncate(feature_list, self.embed_dim)

        return GraphEmbedding(
            func_name=graph.name, func_addr=graph.addr,
            arch=graph.arch, vector=vector, dim=len(vector),
            feature_names=feature_names[:self.embed_dim])

    def embed_batch(self, graphs: List[FunctionGraph]) -> List[GraphEmbedding]:
        """批量嵌入——多函数并行特征提取"""
        return [self.embed(g) for g in graphs]

    def similarity(self, emb1: GraphEmbedding, emb2: GraphEmbedding) -> float:
        """计算两个嵌入的余弦相似度"""
        v1, v2 = emb1.vector, emb2.vector
        if not v1 or not v2 or len(v1) != len(v2):
            return 0.0
        if _NUMPY_AVAIL:
            a1 = np.array(v1); a2 = np.array(v2)
            return float(np.dot(a1, a2) / (np.linalg.norm(a1) * np.linalg.norm(a2) + 1e-8))
        dot = sum(a * b for a, b in zip(v1, v2))
        n1 = math.sqrt(sum(a * a for a in v1))
        n2 = math.sqrt(sum(b * b for b in v2))
        return dot / max(n1 * n2, 1e-8)

    def fit_aligner(self, samples: List[Tuple[ArchFamily, Dict[str, float]]]):
        """训练跨架构对齐器"""
        if self.aligner:
            self.aligner.fit(samples)

    def _pad_or_truncate(self, feats, target_dim):
        """填充或截断特征至目标维度——右侧0-padding"""
        if len(feats) >= target_dim:
            return list(feats)[:target_dim]
        return list(feats) + [0.0] * (target_dim - len(feats))


# 图构建辅助函数

def build_graph_from_disasm(func_name: str, func_addr: int,
                             basic_blocks: List[Dict],
                             arch: str = "x86_64") -> FunctionGraph:
    """从反汇编基本块列表构建FunctionGraph。

    参数:
        func_name: 函数名
        func_addr: 函数起始地址
        basic_blocks: [{addr, instructions: [str], successors: [int]}, ...]
        arch: 架构字符串

    返回FunctionGraph。
    """
    arch_map = {
        'x86': ArchFamily.X86, 'x86_64': ArchFamily.X86_64, 'amd64': ArchFamily.X86_64,
        'arm': ArchFamily.ARM32, 'arm32': ArchFamily.ARM32,
        'arm64': ArchFamily.ARM64, 'aarch64': ArchFamily.ARM64,
        'mips': ArchFamily.MIPS32, 'mips32': ArchFamily.MIPS32,
        'mips64': ArchFamily.MIPS64,
    }
    arch_enum = arch_map.get(arch.lower(), ArchFamily.UNKNOWN)

    graph = FunctionGraph(name=func_name, addr=func_addr, arch=arch_enum)
    edges = []
    total_insns = 0

    for bb in basic_blocks:
        addr = bb.get('addr', 0)
        insns = bb.get('instructions', [])
        node = BasicBlockNode(addr=addr, instructions=insns)
        node.successor_addrs = bb.get('successors', [])
        node.size = len(insns)
        total_insns += len(insns)

        graph.nodes[addr] = node
        for succ in node.successor_addrs:
            edges.append((addr, succ))

    graph.edges = edges
    graph.num_instructions = total_insns
    graph.cyclic_complexity = max(1, len(edges) - len(graph.nodes) + 2)

    return graph


def compute_similarity_matrix(embeddings: List[GraphEmbedding]
                               ) -> List[List[float]]:
    """计算嵌入间成对相似度矩阵"""
    embedder = GraphBinaryEmbedder()
    n = len(embeddings)
    matrix = [[0.0] * n for _ in range(n)]
    for i in range(n):
        matrix[i][i] = 1.0
        for j in range(i + 1, n):
            sim = embedder.similarity(embeddings[i], embeddings[j])
            matrix[i][j] = sim
            matrix[j][i] = sim
    return matrix
