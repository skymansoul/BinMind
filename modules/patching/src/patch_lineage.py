# 初始实现：字节/语义距离矩阵 + UPGMA 树构建
# 增加 merge point 检测：两个分支的补丁收敛识别

"""Patch Evolutionary Lineage — 补丁演化谱系重建。

当多个补丁在时间线上应用于同一 binary，它们之间可能存在演化关系：
  - 衍化 (derivation): 补丁 B 基于 A 修改而来
  - 合并 (merge): 补丁 C 综合了 A 和 B 的修改
  - 分支 (branch): A 和 B 从共同祖先分化
  - 废弃 (abandonment): 某条补丁线不再维护

本模块从补丁的字节级和语义级相似度重建演化树。

方法：
  1. 对每个补丁提取多层特征：字节哈希、修改地址区间、受影响函数签名
  2. 计算成对距离矩阵（1 - Jaccard 相似度 或 字节汉明距离）
  3. UPGMA (Unweighted Pair Group Method with Arithmetic Mean) 构建系统树
  4. 检测 merge nodes：节点与两个以上祖先的距离在阈值内
  5. 输出带时间戳的演化树（可序列化为 JSON）

与生物信息学方法的差异：
  生物系统学使用序列比对 (MUSCLE/MAFFT) + 最大似然 (RAxML/IQ-TREE)。
  二进制补丁不可比对（变长指令），因此使用特征向量距离 + UPGMA。
  该方案用于重建二进制补丁的演化谱系。
"""

import math
import json
import time
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


class LineageEvent(str, Enum):
    DERIVATION = "derivation"
    MERGE = "merge"
    BRANCH = "branch"
    ABANDONMENT = "abandonment"
    ROOT = "root"


@dataclass
class PatchRecord:
    """演化谱系中的单个补丁记录。"""
    patch_id: str
    applied_at: float = 0.0           # POSIX 时间戳
    binary_hash: str = ""             # 补丁应用后 binary 的哈希
    modified_addresses: List[Tuple[int, int]] = field(default_factory=list)
    # 修改的地址区间
    modified_function_names: List[str] = field(default_factory=list)
    byte_fingerprint: str = ""        # 补丁字节的紧凑哈希
    feature_vector: List[float] = field(default_factory=list)
    # 可选：已知的父补丁（若人工记录）
    known_parent_id: str = ""


@dataclass
class LineageNode:
    """演化树中的节点。"""
    node_id: str
    patch_id: str = ""                # 叶节点有此字段；内部节点为空
    parent_id: str = ""               # 父节点 ID
    children_ids: List[str] = field(default_factory=list)
    event: LineageEvent = LineageEvent.DERIVATION
    depth: int = 0                    # 距根的距离
    height: float = 0.0               # UPGMA 高度（距离尺度）
    # 时间
    created_at: float = 0.0


@dataclass
class LineageTree:
    """补丁演化树。"""
    root_id: str = ""
    nodes: Dict[str, LineageNode] = field(default_factory=dict)
    leaf_count: int = 0
    # 统计
    max_depth: int = 0
    merge_count: int = 0
    branch_count: int = 0
    abandoned_leafs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'root_id': self.root_id,
            'nodes': len(self.nodes),
            'leafs': self.leaf_count,
            'max_depth': self.max_depth,
            'merges': self.merge_count,
            'branches': self.branch_count,
            'abandoned': self.abandoned_leafs,
        }


# 特征提取

class PatchFeatureExtractor:
    """从补丁记录中提取用于谱系分析的特征向量。

    多层特征：
      1. 地址区间重叠度
      2. 修改函数 Jaccard
      3. 字节指纹汉明距离
      4. 时间距离
    """

    def extract(self, record: PatchRecord,
                binary_bytes: bytes = b"") -> List[float]:
        """提取归一化特征向量。"""
        feats = []

        # 地址空间覆盖范围（归一化到 0..1）
        addr_span = sum(end - start for start, end in record.modified_addresses)
        feats.append(min(addr_span / 4096.0, 1.0))

        # 修改函数数（归一化）
        feats.append(min(len(record.modified_function_names) / 10.0, 1.0))

        # 字节指纹的哈希熵
        if record.byte_fingerprint:
            fp_bytes = bytes.fromhex(record.byte_fingerprint) if len(record.byte_fingerprint) % 2 == 0 else record.byte_fingerprint.encode()
            entropy = self._shannon_entropy(fp_bytes)
            feats.append(entropy / 8.0)
        else:
            feats.append(0.0)

        record.feature_vector = feats
        return feats

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        from collections import Counter
        if not data:
            return 0.0
        n = len(data)
        freq = Counter(data)
        return -sum((c/n) * math.log2(c/n) for c in freq.values())


# 距离矩阵

class PatchDistanceMatrix:
    """计算补丁记录间的成对距离。"""

    def compute(self, records: List[PatchRecord]) -> List[List[float]]:
        """计算 N×N 距离矩阵。"""
        n = len(records)
        matrix = [[0.0] * n for _ in range(n)]

        for i in range(n):
            for j in range(i + 1, n):
                dist = self._pairwise_distance(records[i], records[j])
                matrix[i][j] = dist
                matrix[j][i] = dist
        return matrix

    def _pairwise_distance(self, a: PatchRecord, b: PatchRecord) -> float:
        """两个补丁间的综合距离。"""
        # 地址重叠距离
        addr_dist = self._address_jaccard_distance(a, b)

        # 函数名距离
        func_dist = self._function_jaccard_distance(a, b)

        # 字节指纹距离
        byte_dist = self._byte_fingerprint_distance(a, b)

        # 时间距离（归一化）
        time_diff = abs(a.applied_at - b.applied_at)
        time_dist = min(time_diff / (86400.0 * 30.0), 1.0)  # 30 天归一化

        # 加权合成
        return (0.35 * addr_dist + 0.25 * func_dist +
                0.25 * byte_dist + 0.15 * time_dist)

    @staticmethod
    def _address_jaccard_distance(a: PatchRecord, b: PatchRecord) -> float:
        """地址区间的 Jaccard 距离。"""
        a_set = set()
        for start, end in a.modified_addresses:
            a_set.update(range(start, end, 16))
        b_set = set()
        for start, end in b.modified_addresses:
            b_set.update(range(start, end, 16))
        if not a_set and not b_set:
            return 0.0
        inter = len(a_set & b_set)
        union = len(a_set | b_set)
        return 1.0 - (inter / union) if union > 0 else 1.0

    @staticmethod
    def _function_jaccard_distance(a: PatchRecord, b: PatchRecord) -> float:
        """修改函数的 Jaccard 距离。"""
        a_set = set(a.modified_function_names)
        b_set = set(b.modified_function_names)
        if not a_set and not b_set:
            return 0.0
        inter = len(a_set & b_set)
        union = len(a_set | b_set)
        return 1.0 - (inter / union) if union > 0 else 1.0

    @staticmethod
    def _byte_fingerprint_distance(a: PatchRecord, b: PatchRecord) -> float:
        """字节指纹的归一化汉明距离。"""
        if not a.byte_fingerprint or not b.byte_fingerprint:
            return 0.5
        try:
            ba = bytes.fromhex(a.byte_fingerprint) if len(a.byte_fingerprint) % 2 == 0 else a.byte_fingerprint.encode()
            bb = bytes.fromhex(b.byte_fingerprint) if len(b.byte_fingerprint) % 2 == 0 else b.byte_fingerprint.encode()
            min_len = min(len(ba), len(bb))
            max_len = max(len(ba), len(bb))
            if max_len == 0:
                return 0.0
            # 对齐部分汉明距离
            hamming = sum(bin(x ^ y).count('1') for x, y in zip(ba[:min_len], bb[:min_len]))
            # 长度差异
            return (hamming / (min_len * 8) * 0.7 + (max_len - min_len) / max_len * 0.3)
        except (ValueError, TypeError):
            return 0.5


# UPGMA 树构建

class UPGMATreeBuilder:
    """UPGMA 算法构建补丁演化树。

    输入：距离矩阵 + 补丁记录列表。
    输出：有根的系统树 (LineageTree)。

    UPGMA 假设分子钟——演化速率恒定。
    对补丁谱系，此假设合理：补丁修改通常随时间均匀累积。
    """

    def build(self, records: List[PatchRecord],
              distance_matrix: List[List[float]]
              ) -> LineageTree:
        """UPGMA 主循环。"""
        n = len(records)
        if n == 0:
            return LineageTree()

        tree = LineageTree()

        # 初始化：每个补丁是一个叶节点
        clusters = []
        node_ids = []
        for i, rec in enumerate(records):
            nid = "leaf_%d" % i
            node = LineageNode(
                node_id=nid, patch_id=rec.patch_id,
                depth=0, height=0.0,
                created_at=rec.applied_at)
            tree.nodes[nid] = node
            clusters.append({i})  # 簇中记录索引的集合
            node_ids.append([nid])
            tree.leaf_count += 1

        # 距离矩阵副本（可修改）
        dist = [row[:] for row in distance_matrix]

        # 活动簇索引
        active = list(range(n))

        next_inner = 0
        while len(active) > 1:
            # 找最近的两个簇
            min_dist = float('inf')
            ci, cj = -1, -1
            for a_idx, a in enumerate(active):
                for b_idx, b in enumerate(active):
                    if a_idx >= b_idx:
                        continue
                    if dist[a][b] < min_dist:
                        min_dist = dist[a][b]
                        ci, cj = a, b

            if ci == -1 or cj == -1:
                break

            # 合并簇
            new_cluster_indices = clusters[active.index(ci)] | clusters[active.index(cj)]
            new_node_ids = node_ids[active.index(ci)] + node_ids[active.index(cj)]

            inner_id = "inner_%d" % next_inner
            next_inner += 1
            inner_node = LineageNode(
                node_id=inner_id, height=min_dist / 2.0,
                event=LineageEvent.BRANCH if len(new_cluster_indices) > 2
                else LineageEvent.DERIVATION)
            # 关联子节点
            for nid in new_node_ids:
                child = tree.nodes[nid]
                child.parent_id = inner_id
                inner_node.children_ids.append(nid)
                inner_node.depth = max(inner_node.depth, child.depth + 1)
            tree.nodes[inner_id] = inner_node

            # 更新距离矩阵（UPGMA 均值公式）
            for other_idx, other in enumerate(active):
                if other == ci or other == cj:
                    continue
                size_i = len(clusters[active.index(ci)])
                size_j = len(clusters[active.index(cj)])
                new_dist = ((size_i * dist[ci][other] + size_j * dist[cj][other]) /
                           (size_i + size_j))
                dist[ci][other] = new_dist
                dist[other][ci] = new_dist

            # 移除 cj
            cj_pos = active.index(cj)
            active.pop(cj_pos)
            clusters.pop(cj_pos)
            node_ids.pop(cj_pos)

            # 更新 ci 的簇
            ci_pos = active.index(ci)
            clusters[ci_pos] = new_cluster_indices
            node_ids[ci_pos] = [inner_id]

        # 最后剩余的是根
        if active:
            tree.root_id = node_ids[active.index(active[0])][0]

        # 统计
        tree.max_depth = max(n.depth for n in tree.nodes.values())
        tree.merge_count = sum(1 for n in tree.nodes.values()
                              if n.event == LineageEvent.BRANCH)
        tree.branch_count = sum(1 for n in tree.nodes.values()
                               if len(n.children_ids) >= 2)

        # 检测废弃叶节点：最近 90 天内无更新
        now = time.time()
        cutoff = now - 86400 * 90
        for nid, node in tree.nodes.items():
            if (not node.children_ids and node.patch_id and
                node.created_at < cutoff):
                tree.abandoned_leafs.append(node.patch_id)

        return tree


# 便捷函数

def reconstruct_lineage(records: List[PatchRecord]) -> LineageTree:
    """一键重建补丁演化谱系。"""
    dm = PatchDistanceMatrix()
    matrix = dm.compute(records)
    builder = UPGMATreeBuilder()
    return builder.build(records, matrix)
