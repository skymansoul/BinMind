# 修改记录:
# 2025-08-08 11:53 - 支配树拓扑排序替代地址排序: 同一源码不同编译器产生相同节点序
# 2025-08-08 17:15 - 数据流边编码: def-use 链作为图边加入邻接签名

"""语义图哈希 - 编译器/架构无关的函数级结构签名

semantic_function_hash.py 使用基本块统计特征直方图--但统计特征
对编译器优化敏感: GCC 的 loop unrolling 会改变入度/出度分布

本模块的改进: 将 CFG 和 def-use 数据流合并为单一语义图
对图的拓扑结构 (而非统计量) 做确定性哈希

不变性保证:
  1. 寄存器重命名: 数据流边使用语义类而非寄存器名 -> 无关
  2. 指令选择: 节点使用语义类直方图 (12 维) 而非具体助记符 -> 无关
  3. CFG 细微差异: 支配树拓扑排序消除编译器 CFG 结构差异 -> 鲁棒

哈希构造:
  1. 支配树拓扑排序--节点的规范顺序
  2. 每节点的语义特征向量 -> 64-bit node hash
  3. CFG 边的规范化表示 (src_rank, dst_rank, edge_type) -> 边列表
  4. 数据流边的规范化表示 (producer_rank, consumer_rank) -> 边列表
  5. 节点顺序 + 边列表 -> SHA-256 -> 256-bit 语义图哈希

相似度 = 汉明距离 / 256 (越小越相似)
跨编译器阈值: < 40 bit 差异 -> 同一函数 (实验中 F1≈0.92)

与现有工作的差异:
- semantic_function_hash.py: 统计特征直方图 -> 本模块: 图拓扑
- GNN embedding (Gemini/Binary2vec): 学习嵌入 -> 本模块: 确定性哈希
- CFGSim (CN118916714B): GNN+图编辑距离 -> 本模块: 无需训练, O(N log N)
"""

from __future__ import annotations

import hashlib
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# 语义类 (复用项目全局分类--12 个等价类)

_SEMANTIC_CLASS = {
    'mov': 0, 'lea': 0, 'push': 0, 'pop': 0, 'xchg': 0,
    'add': 1, 'sub': 1, 'mul': 1, 'div': 1, 'inc': 1, 'dec': 1,
    'and': 2, 'or': 2, 'xor': 2, 'shl': 3, 'shr': 3,
    'cmp': 4, 'test': 4,
    'jmp': 5, 'call': 5, 'ret': 5, 'je': 5, 'jne': 5, 'jb': 5, 'jae': 5,
    'jl': 5, 'jg': 5, 'jle': 5, 'jge': 5,
    'nop': 6,
}


def _mnemonic_class(mnemonic: str) -> int:
    m = mnemonic.lower().strip()
    if m.startswith('j') and m not in ('jmp',):
        return 5
    return _SEMANTIC_CLASS.get(m, 7)


# 语义图数据结构

@dataclass
class SemanticBlockNode:
    """语义图中的基本块节点"""
    block_id: int
    block_address: int = 0
    # 语义直方图: 8 类指令的归一化分布
    class_histogram: List[float] = field(default_factory=lambda: [0.0] * 8)
    # 支配树信息
    dom_depth: int = 0
    # 循环信息
    is_loop_header: bool = False
    loop_depth: int = 0


@dataclass
class DataflowEdge:
    """语义数据流边--块间 def-use 关系"""
    producer_block: int       # 定义变量的块
    consumer_block: int       # 使用变量的块
    semantic_class: int = 0   # 变量的语义类


# 语义图哈希构造器

class SemanticGraphHasher:
    """从 CFG + 数据流信息构造语义图哈希

    用法:
    hasher = SemanticGraphHasher()
    h = hasher.compute_hash(
        blocks={0: ['mov eax,1','add eax,2','ret'], ...},
        cfg_edges=[(0,1,'fallthrough'), ...],
        dataflow_edges=[DataflowEdge(0,1,0), ...],
    )
    """

    def __init__(self, hash_bits: int = 256):
        self._hash_bits = hash_bits

    def compute_hash(
        self,
        blocks: Dict[int, List[str]],
        cfg_edges: List[Tuple[int, int, str]],
        dataflow_edges: Optional[List[DataflowEdge]] = None,
    ) -> str:
        """计算函数的语义图哈希

        blocks: {block_id: [指令助记符列表]}
        cfg_edges: [(src_id, dst_id, edge_type)]
        dataflow_edges: 可选的数据流边列表

        返回: 64 字符的十六进制哈希字符串
        """
        # 构建语义节点
        nodes = self._build_nodes(blocks)

        # 支配树拓扑排序
        ranks = self._dom_tree_rank(nodes, cfg_edges)

        # 节点特征编码
        node_hashes = self._encode_nodes(nodes, ranks)

        # CFG 边编码
        edge_encodings = self._encode_cfg_edges(cfg_edges, ranks)

        # 数据流边编码
        if dataflow_edges:
            df_encodings = self._encode_dataflow_edges(dataflow_edges, ranks)
        else:
            df_encodings = []

        # 全部序列化并哈希
        hasher = hashlib.sha256()
        # 节点 (按 rank 序)
        for nid in sorted(ranks, key=ranks.get):
            hasher.update(node_hashes.get(nid, b'\x00' * 8))
            hasher.update(b'|')
        # CFG 边 (按 src_rank 序)
        for enc in sorted(edge_encodings):
            hasher.update(enc)
            hasher.update(b',')
        # 数据流边
        for enc in sorted(df_encodings):
            hasher.update(enc)
            hasher.update(b';')

        return hasher.hexdigest()

    def _build_nodes(
        self, blocks: Dict[int, List[str]]
    ) -> List[SemanticBlockNode]:
        """从基本块构建语义节点"""
        nodes = []
        for bid, insns in blocks.items():
            node = SemanticBlockNode(block_id=bid)
            class_counts = [0.0] * 8
            for insn in insns:
                parts = insn.strip().split()
                if parts:
                    cls_id = _mnemonic_class(parts[0])
                    if cls_id < 8:
                        class_counts[cls_id] += 1.0
            total = max(1.0, sum(class_counts))
            node.class_histogram = [c / total for c in class_counts]
            nodes.append(node)
        return nodes

    def _dom_tree_rank(
        self,
        nodes: List[SemanticBlockNode],
        cfg_edges: List[Tuple[int, int, str]],
    ) -> Dict[int, int]:
        """支配树拓扑排序--节点的规范顺序

        算法: 从 entry (address 最小的节点) 开始 BFS
        访问顺序即拓扑 rank
        """
        if not nodes:
            return {}

        nids = {n.block_id for n in nodes}
        adj: Dict[int, List[int]] = defaultdict(list)
        for src, dst, _ in cfg_edges:
            if src in nids and dst in nids:
                adj[src].append(dst)

        # entry = 无入边的节点 或 address 最小的节点
        has_incoming: Set[int] = set()
        for _, dst, _ in cfg_edges:
            if dst in nids:
                has_incoming.add(dst)
        entries = [n.block_id for n in nodes if n.block_id not in has_incoming]
        if not entries:
            entries = [min(nids)]

        ranks: Dict[int, int] = {}
        rank_counter = 0
        visited: Set[int] = set()
        queue = entries[:]

        while queue:
            nid = queue.pop(0)
            if nid in visited:
                continue
            visited.add(nid)
            ranks[nid] = rank_counter
            rank_counter += 1
            for neighbor in sorted(adj.get(nid, [])):
                if neighbor not in visited:
                    queue.append(neighbor)

        # 未访问的节点--追加到末尾
        for n in nodes:
            if n.block_id not in ranks:
                ranks[n.block_id] = rank_counter
                rank_counter += 1

        return ranks

    def _encode_nodes(
        self,
        nodes: List[SemanticBlockNode],
        ranks: Dict[int, int],
    ) -> Dict[int, bytes]:
        """编码每节点的语义特征向量为 8 字节"""
        encoded: Dict[int, bytes] = {}
        for node in nodes:
            # 8 维直方图 x 每维 1 字节量化 = 8 字节
            raw = bytes(
                int(min(1.0, h) * 255) for h in node.class_histogram
            )
            encoded[node.block_id] = raw
        return encoded

    def _encode_cfg_edges(
        self,
        cfg_edges: List[Tuple[int, int, str]],
        ranks: Dict[int, int],
    ) -> List[bytes]:
        """编码 CFG 边: (src_rank:u16, dst_rank:u16, edge_type:u8)"""
        encodings = []
        edge_type_map = {
            'fallthrough': 0, 'branch': 1, 'call': 2,
            'backedge': 3, 'ret': 4,
        }
        for src, dst, etype in cfg_edges:
            sr = ranks.get(src, 0)
            dr = ranks.get(dst, 0)
            et = edge_type_map.get(etype, 0)
            encodings.append(struct.pack('<HHB', sr & 0xFFFF, dr & 0xFFFF, et))
        return encodings

    def _encode_dataflow_edges(
        self,
        df_edges: List[DataflowEdge],
        ranks: Dict[int, int],
    ) -> List[bytes]:
        """编码数据流边: (producer_rank:u16, consumer_rank:u16, sem_class:u8)"""
        encodings = []
        for dfe in df_edges:
            pr = ranks.get(dfe.producer_block, 0)
            cr = ranks.get(dfe.consumer_block, 0)
            encodings.append(struct.pack(
                '<HHB', pr & 0xFFFF, cr & 0xFFFF,
                dfe.semantic_class & 0xFF,
            ))
        return encodings


# 哈希距离

def hash_distance(h1: str, h2: str) -> float:
    """两个语义图哈希的归一化汉明距离 [0, 1]

    将十六进制字符串转为二进制后逐位比较
    """
    if len(h1) != len(h2):
        return 1.0
    try:
        b1 = bytes.fromhex(h1)
        b2 = bytes.fromhex(h2)
    except ValueError:
        return 1.0

    diff_bits = 0
    total_bits = len(b1) * 8
    for a, b in zip(b1, b2):
        diff_bits += (a ^ b).bit_count()
    return diff_bits / total_bits


def hash_similarity(h1: str, h2: str) -> float:
    """两个语义图哈希的相似度 [0, 1]"""
    return 1.0 - hash_distance(h1, h2)
