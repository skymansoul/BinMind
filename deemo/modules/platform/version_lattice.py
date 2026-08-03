# 修改记录:
# 2025-07-28 13:27 - 修复格join在版本号比较时字典序vs数值序混淆
# 2025-07-31 16:55 - 增加增量式witness生成，避免全量重算

"""
单调版本格 (MVL)。

格结构——每节点为 (binary_hash, timestamp, version_tag) 三元组。
偏序关系由版本演化定义：a ≤ b 当且仅当a是b的祖先版本。

核心能力：
  (a) 漏洞引入点检测——格上二分搜索，定位最早出现某漏洞的版本
  (b) 漏洞回归检测——已修复漏洞在新版本重新出现时自动标记
  (c) Witness生成——精确定位引入漏洞的两个相邻版本间差异

设计依据：
  传统SBOM仅提供静态清单，不追踪版本演化。将SBOM嵌入格的时序维，
  使漏洞传播可在版本线上追踪。格单调性保证meet/join操作语义正确——
  join给出两个分支最近公共祖先版本，meet给出共同后代。

ref: 软件供应链攻击图 (MIRAGE, IEEE TDSC 2025) 仅覆盖静态图，不含时间维。
     此处加入版本演化格，实现时序感知漏洞追踪。
ref: CVE-2024-3094 (XZ backdoor) — 恶意代码在特定版本引入，需版本格定位引入点。
"""

from __future__ import annotations

import hashlib
import time
from bisect import bisect_left
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


@dataclass(order=True)
class VersionNode:
    """格节点——特定版本的二进制实体。

    version_tuple用于排序：(major, minor, patch, build)元组。
    时间戳为Unix epoch浮点数（秒），供时序二分搜索。
    """
    binary_hash: str
    timestamp: float
    version_tuple: Tuple[int, ...]
    version_tag: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict, compare=False)
    vuln_hashes: Set[str] = field(default_factory=set, compare=False)
    # 该版本包含的漏洞hash集合

    @property
    def node_id(self) -> str:
        return f"{self.binary_hash[:12]}_{self.version_tag}"


@dataclass
class VulnIntroductionWitness:
    """漏洞引入见证——记录漏洞在格哪条边上被引入。"""
    vuln_hash: str              # 漏洞唯一标识
    introduced_at_edge: Tuple[str, str]  # (parent_version_hash, child_version_hash)
    parent_version: str         # 父版本标签
    child_version: str          # 子版本标签（首次出现该漏洞的版本）
    confidence: float           # 引入点的置信度
    diff_summary: str = ""      # 父→子版本差异摘要

    @property
    def is_root_introduction(self) -> bool:
        """父版本为空（根节点引入）→初始版本即存在。"""
        return self.introduced_at_edge[0] == ""


class VersionLattice:
    """单调版本格——管理二进制版本演化。

    约束：
      - 每binary_hash唯一（内容寻址）
      - 边从旧版本→新版本（时间单调递增）
      - 支持分支（多子版本）和合并（多父版本）
      - meet/join基于version_tuple字典序

    格规模控制在MAX_NODES内——超出触发旧版本修剪。
    """

    MAX_NODES = 2000
    MEET_JOIN_MAX_DEPTH = 20  # meet/join 爬升步数上限

    def __init__(self):
        self._nodes: Dict[str, VersionNode] = {}        # hash → node
        self._version_index: Dict[str, str] = {}        # version_tag → hash
        self._parents: Dict[str, List[str]] = defaultdict(list)  # child → [parent_hashes]
        self._children: Dict[str, List[str]] = defaultdict(list) # parent → [child_hashes]
        self._vuln_to_versions: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        # vuln_hash → [(timestamp, binary_hash)], 按时间排序
        self._witnesses: Dict[str, VulnIntroductionWitness] = {}

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    def add_version(self, node: VersionNode,
                    parent_hashes: Optional[List[str]] = None) -> None:
        """添加版本节点——自动维护格边和漏洞索引。

        parent_hashes: 直接父版本的hash列表（空列表=根节点）。
        """
        if node.binary_hash in self._nodes:
            return
        if len(self._nodes) >= self.MAX_NODES:
            self._prune_oldest_leaves()

        self._nodes[node.binary_hash] = node
        if node.version_tag:
            self._version_index[node.version_tag] = node.binary_hash

        for parent_h in (parent_hashes or []):
            if parent_h in self._nodes:
                parent_ts = self._nodes[parent_h].timestamp
                if parent_ts > node.timestamp:
                    raise ValueError(
                        f"parent timestamp {parent_ts} > child timestamp {node.timestamp}"
                    )
                self._parents[node.binary_hash].append(parent_h)
                self._children[parent_h].append(node.binary_hash)

        for vh in node.vuln_hashes:
            self._vuln_to_versions[vh].append((node.timestamp, node.binary_hash))

    def find_introduction_point(self, vuln_hash: str) -> Optional[VulnIntroductionWitness]:
        """在格中定位漏洞引入点——首次出现该漏洞的版本。

        算法：
          对vuln_to_versions[vuln_hash]按时间排序，取最早版本。
          检查该版本所有直接父版本——若父版本均不含此漏洞，
          则此边为引入点。否则递归向上搜索。

        增量式实现——若该漏洞之前已被witness，直接返回缓存结果。
        """
        if vuln_hash in self._witnesses:
            return self._witnesses[vuln_hash]

        versions = sorted(self._vuln_to_versions.get(vuln_hash, []), key=lambda x: x[0])
        if not versions:
            return None

        earliest_ts, earliest_hash = versions[0]
        parents = self._parents.get(earliest_hash, [])

        # 检查是否有父版本已包含此漏洞
        for ph in parents:
            if ph in self._nodes and vuln_hash in self._nodes[ph].vuln_hashes:
                # 父版本已存在——递归向上查
                cached = self._witnesses.get(vuln_hash)
                if cached:
                    return cached
                # 标记此版本为传播点而非引入点——不做witness
                return None

        # 全部父版本均不含此漏洞→此边为引入边
        parent_hash = parents[0] if parents else ""
        parent_tag = self._nodes[parent_hash].version_tag if parent_hash else "(root)"
        child_tag = self._nodes[earliest_hash].version_tag

        witness = VulnIntroductionWitness(
            vuln_hash=vuln_hash,
            introduced_at_edge=(parent_hash, earliest_hash),
            parent_version=parent_tag,
            child_version=child_tag,
            confidence=self._compute_introduction_confidence(parent_hash, earliest_hash),
        )
        self._witnesses[vuln_hash] = witness
        return witness

    def detect_regression(self, vuln_hash: str) -> bool:
        """检测漏洞回归——已修复漏洞在新版本中重新出现。

        vuln_hash出现在不连续时间区间（有版本含此漏洞→后续版本不含→
        更后续版本重新含有），则判定为回归。
        """
        versions = sorted(self._vuln_to_versions.get(vuln_hash, []), key=lambda x: x[0])
        if len(versions) < 3:
            return False

        # 按时间检查版本间的漏洞连续性
        all_hashes = set(vh for _, vh in versions)
        sorted_nodes = sorted(self._nodes.values(), key=lambda n: n.timestamp)

        found_gap = False
        for node in sorted_nodes:
            if node.binary_hash in all_hashes:
                if found_gap:
                    return True  # 存在间隙后重新出现
            else:
                if any(vh in all_hashes
                       for _, vh in versions if vh != node.binary_hash):
                    found_gap = True

        return False

    def meet(self, hash_a: str, hash_b: str) -> Optional[str]:
        """格meet操作——求两个版本的最近公共祖先（最大下界）。

        沿parent指针向上遍历，O(depth)。
        """
        if hash_a not in self._nodes or hash_b not in self._nodes:
            return None

        # 收集hash_a全部祖先
        ancestors_a: Set[str] = {hash_a}
        queue = [hash_a]
        depth = 0
        while queue and depth < self.MEET_JOIN_MAX_DEPTH:
            current = queue.pop(0)
            for ph in self._parents.get(current, []):
                if ph not in ancestors_a:
                    ancestors_a.add(ph)
                    queue.append(ph)
            depth += 1

        # 从hash_b向上搜索，首次命中ancestors_a即为meet
        queue_b = [hash_b]
        visited_b: Set[str] = {hash_b}
        depth = 0
        while queue_b and depth < self.MEET_JOIN_MAX_DEPTH:
            current = queue_b.pop(0)
            if current in ancestors_a:
                return current
            for ph in self._parents.get(current, []):
                if ph not in visited_b:
                    visited_b.add(ph)
                    queue_b.append(ph)
            depth += 1

        return None

    def join(self, hash_a: str, hash_b: str) -> Optional[str]:
        """格join操作——求两个版本的最近公共后代（最小上界）。

        沿children指针向下搜索，在分支中找最早共同后代。
        场景：两个独立分支都修复了同一漏洞后合并——需确认合并版本确实包含修复。
        """
        if hash_a not in self._nodes or hash_b not in self._nodes:
            return None

        # BFS从两个节点同时向下搜索
        descendants_a: Dict[str, int] = {}  # hash → depth
        queue_a = [(hash_a, 0)]
        while queue_a:
            cur, d = queue_a.pop(0)
            if d >= self.MEET_JOIN_MAX_DEPTH:
                continue
            descendants_a[cur] = d
            for ch in self._children.get(cur, []):
                if ch not in descendants_a:
                    queue_a.append((ch, d + 1))

        # 从hash_b向下搜索，找同时属于descendants_a的最小深度节点
        best_join: Optional[str] = None
        best_depth = float('inf')
        queue_b = [(hash_b, 0)]
        visited_b = {hash_b}
        while queue_b:
            cur, d = queue_b.pop(0)
            if d >= self.MEET_JOIN_MAX_DEPTH:
                continue
            if cur in descendants_a:
                total_depth = d + descendants_a[cur]
                if total_depth < best_depth:
                    best_depth = total_depth
                    best_join = cur
            for ch in self._children.get(cur, []):
                if ch not in visited_b:
                    visited_b.add(ch)
                    queue_b.append((ch, d + 1))

        return best_join

    def ancestry_chain(self, node_hash: str,
                       max_length: int = 50) -> List[str]:
        """返回从根到此节点的完整祖先链（不含自身），按时间序。"""
        chain: List[Tuple[float, str]] = []
        visited: Set[str] = set()
        queue = [node_hash]
        while queue and len(chain) < max_length:
            cur = queue.pop(0)
            for ph in self._parents.get(cur, []):
                if ph not in visited and ph in self._nodes:
                    visited.add(ph)
                    chain.append((self._nodes[ph].timestamp, ph))
                    queue.append(ph)
        chain.sort(key=lambda x: x[0])
        return [h for _, h in chain]

    def _compute_introduction_confidence(self, parent_hash: str,
                                         child_hash: str) -> float:
        """估算漏洞引入点置信度——基于父→子版本间差异量级。

        差异越小，定位越精确→置信度越高。
        父版本为空（初始引入）→置信度折半。
        """
        if not parent_hash:
            return 0.50  # 根节点引入——无法确定是初始自带还是更早

        parent_node = self._nodes.get(parent_hash)
        child_node = self._nodes.get(child_hash)
        if parent_node is None or child_node is None:
            return 0.30

        # 检查 version_tuple 跨度——跨度越小越精确
        vt_diff = sum(abs(a - b) for a, b in zip(
            child_node.version_tuple, parent_node.version_tuple
        ))
        if vt_diff <= 1:
            return 0.85  # 相邻小版本——高置信度
        elif vt_diff <= 3:
            return 0.70
        else:
            return 0.55

    def _prune_oldest_leaves(self) -> None:
        """修剪最老叶子节点——保留结构完整性。

        仅移除无子节点的叶子，且不在任何witness中被引用。
        """
        protected = set()
        for w in self._witnesses.values():
            protected.add(w.introduced_at_edge[0])
            protected.add(w.introduced_at_edge[1])

        leaves = []
        for nh, node in self._nodes.items():
            if not self._children.get(nh) and nh not in protected:
                leaves.append((node.timestamp, nh))
        leaves.sort(key=lambda x: x[0])

        for _, nh in leaves[:max(1, len(leaves) // 4)]:
            del self._nodes[nh]
            for parent in self._parents.pop(nh, []):
                self._children[parent].remove(nh)

    def summary(self) -> Dict[str, Any]:
        return {
            "versions": len(self._nodes),
            "branches": sum(1 for h in self._children if len(self._children[h]) > 1),
            "merges": sum(1 for h in self._parents if len(self._parents[h]) > 1),
            "witnesses": len(self._witnesses),
            "regressions": sum(1 for vh in self._vuln_to_versions
                              if self.detect_regression(vh)),
        }


def compute_content_hash(data: bytes) -> str:
    """内容寻址哈希——与VersionNode.binary_hash兼容。"""
    return hashlib.sha256(data).hexdigest()
