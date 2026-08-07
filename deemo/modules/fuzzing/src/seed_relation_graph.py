"""种子间覆盖关系图 (Inter-Seed Relationship Graph, ISRG) — 基于覆盖模式的种子关系建模.

修改记录:
2025-07-25 16:42 - 新增覆盖流中心性 (coverage flow centrality) 指标
2025-07-27 09:15 - 关系图增量更新逻辑，避免每次重建全图
2025-07-30 11:08 - 集成稀疏覆盖指纹，阈值自适应调节

  SEAFuzz                -- 基于稀有度加权的结构相似性, 种子调度
  HF-DGF    -- 值流图(VFG)用于依赖关系建模
  AFLRun "Toward Unbiased Multiple-Target Fuzzing" — 路径多样性度量用于多目标公平性
  AMOS2 -- 状态依赖 vs 状态无关种子度量分类

核心假设:
  种子A的覆盖集合⊆种子B的覆盖集合 → B在覆盖意义上"包含"A。
  若A和B的覆盖交集很小 → 两者探索了不同的程序区域，都应保留。
  传统的贪心裁剪 (cull_queue) 仅按"覆盖面最大的种子优先"做贪心覆盖，
  丢失了覆盖模式的结构信息。ISRG 补全这个缺口。

与现有模块的关系:
  - Scheduler: 调用 ISRG 的 diversity_score 作为种子选择的偏置项
  - CorpusManager: 调用 ISRG 在 prune 前额外保留关系图中的桥接种子
  - CoverageTracker: 提供原始位图数据用于相似度计算
"""

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

# Jaccard 相似度阈值: 高于此值认为两个种子存在覆盖包含关系
# 根据 SEAFuzz 的经验设定为 0.6; 在二进制目标上该阈值偏保守,
# 可通过 calibrate_threshold() 自适应校准。
_DEFAULT_INCLUSION_THRESHOLD = 0.6
_MIN_FINGERPRINT_SIZE = 4

@dataclass
class SeedNode:
    """ISRG 中一个种子节点。"""
    seed_id: str
    coverage_fingerprint: FrozenSet[int] = field(default_factory=frozenset)
    # 入边/出边: 邻接种子ID集合
    in_neighbors: Set[str] = field(default_factory=set)
    out_neighbors: Set[str] = field(default_factory=set)
    # 覆盖流中心性: 途经该节点的覆盖传递路径数 (归一化后)
    flow_centrality: float = 0.0
    # 多样性贡献: 该种子相对其邻域贡献了多少新边
    diversity_contribution: float = 0.0
    # 最后更新时间戳
    last_updated: float = field(default_factory=time.time)

class SeedRelationGraph:
    """种子间覆盖关系有向图。

    节点 = 种子, 边 A→B 表示 B 的覆盖 ≽ A 的覆盖 (覆盖超集关系)。
    无全覆盖关系的种子间不存在边, 但可通过路径连通性分析间接关系。

    典型用法:
      srg = SeedRelationGraph()
      srg.upsert_seed(seed_id, coverage_set)
      srg.upsert_seed(other_id, other_coverage)
      diversity = srg.diversity_score(seed_id)  # 用于调度偏置
      bridges = srg.find_bridge_seeds()           # 裁剪前需保留的桥接种子
    """

    def __init__(self, inclusion_threshold: float = _DEFAULT_INCLUSION_THRESHOLD):
        self.threshold = inclusion_threshold
        self._nodes: Dict[str, SeedNode] = {}
        # 覆盖指纹 → 种子ID 反向索引, 用于快速查询相似种子
        self._fingerprint_index: Dict[FrozenSet[int], List[str]] = defaultdict(list)
        self._dirty: bool = False  # 标记图是否需要重新计算中心性
        self._edge_count: int = 0

    # //// 添加/更新种子节点 ////
    def upsert_seed(self, seed_id: str, coverage: Set[int]) -> None:
        """插入新种子或更新已有种子的覆盖集。

        覆盖集变化时需要重建与该种子相关的所有边。
        若覆盖集不变, 跳过更新以节省计算。
        """
        fp = self._to_fingerprint(coverage)
        existing = self._nodes.get(seed_id)
        if existing is not None and existing.coverage_fingerprint == fp:
            existing.last_updated = time.time()
            return

        # 移除旧索引条目
        if existing is not None:
            old_fp = existing.coverage_fingerprint
            self._fingerprint_index[old_fp] = [
                sid for sid in self._fingerprint_index[old_fp] if sid != seed_id
            ]
            # 删除旧的出入边
            for nb_id in existing.in_neighbors:
                nb = self._nodes.get(nb_id)
                if nb:
                    nb.out_neighbors.discard(seed_id)
                    self._edge_count -= 1
            for nb_id in existing.out_neighbors:
                nb = self._nodes.get(nb_id)
                if nb:
                    nb.in_neighbors.discard(seed_id)
                    self._edge_count -= 1

        node = SeedNode(
            seed_id=seed_id,
            coverage_fingerprint=fp,
            last_updated=time.time(),
        )
        self._nodes[seed_id] = node
        self._fingerprint_index[fp].append(seed_id)

        # 重建与所有其他节点的边
        for other_id, other in self._nodes.items():
            if other_id == seed_id:
                continue
            rel = self._classify_relation(fp, other.coverage_fingerprint)
            if rel == "superset":
                node.out_neighbors.add(other_id)
                other.in_neighbors.add(seed_id)
                self._edge_count += 1
            elif rel == "subset":
                node.in_neighbors.add(other_id)
                other.out_neighbors.add(seed_id)
                self._edge_count += 1
            # "disjoint" 或 "partial" 不建边

        self._dirty = True

    def remove_seed(self, seed_id: str) -> bool:
        """从图中移除种子, 清理所有关联边。"""
        node = self._nodes.pop(seed_id, None)
        if node is None:
            return False

        fp = node.coverage_fingerprint
        self._fingerprint_index[fp] = [
            sid for sid in self._fingerprint_index[fp] if sid != seed_id
        ]

        for nb_id in node.in_neighbors:
            nb = self._nodes.get(nb_id)
            if nb:
                nb.out_neighbors.discard(seed_id)
                self._edge_count -= 1
        for nb_id in node.out_neighbors:
            nb = self._nodes.get(nb_id)
            if nb:
                nb.in_neighbors.discard(seed_id)
                self._edge_count -= 1

        self._dirty = True
        return True

    # //// 关系分类 ////
    def _classify_relation(self, fp_a: FrozenSet[int],
                           fp_b: FrozenSet[int]) -> str:
        """基于 Jaccard 相似度和集合包含关系分类两个种子的关系。

        返回: "superset" (A⊇B), "subset" (A⊆B), "disjoint" (不相交), "partial" (部分重叠)
        """
        if not fp_a or not fp_b:
            return "disjoint"

        intersection = len(fp_a & fp_b)
        if intersection == 0:
            return "disjoint"

        union = len(fp_a | fp_b)
        jaccard = intersection / union

        if jaccard < self.threshold:
            return "partial"

        # 高 Jaccard 时, 进一步区分包含方向
        if len(fp_a) >= len(fp_b):
            coverage_ratio = intersection / max(1, len(fp_b))
            if coverage_ratio >= self.threshold:
                return "superset"
        if len(fp_b) >= len(fp_a):
            coverage_ratio = intersection / max(1, len(fp_a))
            if coverage_ratio >= self.threshold:
                return "subset"

        return "partial"

    # //// 覆盖指纹生成 ////
    def _to_fingerprint(self, coverage: Set[int]) -> FrozenSet[int]:
        """生成轻量覆盖指纹。

        对于大型覆盖集 (>500 边), 使用 min-hash 风格的采样以降低内存开销。
        采样策略: 取模哈希到固定大小的桶, 每个桶保留最小值。
        这保留了 Jaccard 相似度的无偏估计性质。
        """
        if len(coverage) <= 500:
            return frozenset(coverage)

        # MinHash 风格降维: 512 个桶
        n_buckets = 512
        buckets: List[int] = [0x7FFFFFFF] * n_buckets
        for edge in coverage:
            bucket = edge % n_buckets
            if edge < buckets[bucket]:
                buckets[bucket] = edge
        # 过滤空桶
        return frozenset(b for b in buckets if b != 0x7FFFFFFF)

    # //// 多样性评分 ////
    def diversity_score(self, seed_id: str) -> float:
        """计算种子对其局部邻域的结构多样性贡献。

        高多样性贡献 = 该种子的覆盖与所有邻居的覆盖交集都小。
        这识别出那些探索了独特程序区域的种子, 应在调度中获得优先级。

        返回 [0, 1], 1 表示完全独立于邻域。
        """
        node = self._nodes.get(seed_id)
        if node is None:
            return 0.5  # 未知种子: 中性先验

        fp = node.coverage_fingerprint
        if not fp:
            return 0.0

        neighbors = node.in_neighbors | node.out_neighbors
        if not neighbors:
            return 1.0  # 孤立节点: 完全独特

        # 与每个邻居计算 Jaccard 距离, 取平均
        total_dist = 0.0
        count = 0
        for nb_id in neighbors:
            nb = self._nodes.get(nb_id)
            if nb is None or not nb.coverage_fingerprint:
                continue
            intersection = len(fp & nb.coverage_fingerprint)
            union = len(fp | nb.coverage_fingerprint)
            jaccard = intersection / union if union > 0 else 0.0
            total_dist += (1.0 - jaccard)
            count += 1

        if count == 0:
            return 0.5
        node.diversity_contribution = total_dist / count
        return node.diversity_contribution

    # //// 覆盖流中心性 ////
    def compute_flow_centrality(self) -> None:
        """计算每个节点的覆盖流中心性 (Coverage Flow Centrality)。

        定义: 节点 v 的 flow_centrality = 从 v 可达的节点数 / 总节点数。
        直觉: 若种子 v 的覆盖包含了许多其他种子的覆盖 (v 是其超集),
              则 v 在覆盖传递中处于枢纽位置, 应获得更高的能量分配。
              但反之, 若 v 仅是一个庞大覆盖集的子集, 其枢纽性较低。

        复杂度: O(V·(V+E)), 使用 BFS 从每个节点出发。
        对于大规模语料库 (>5000 种子), 后续可切换为近似算法。
        """
        if not self._dirty:
            return

        total = max(1, len(self._nodes))
        for nid, node in self._nodes.items():
            # BFS 沿出边方向遍历
            visited: Set[str] = set()
            queue = [nid]
            while queue:
                cur = queue.pop()
                if cur in visited:
                    continue
                visited.add(cur)
                cur_node = self._nodes.get(cur)
                if cur_node:
                    for out_nb in cur_node.out_neighbors:
                        if out_nb not in visited:
                            queue.append(out_nb)
            node.flow_centrality = (len(visited) - 1) / max(1, total - 1)

        self._dirty = False

    # //// 桥接种子检测 ////
    def find_bridge_seeds(self, min_flow: float = 0.1) -> List[str]:
        """检测覆盖流中的桥接种子 — 裁剪时不应被移除的种子。

        桥接种子的特征:
          - 高 flow_centrality (连接多个覆盖区域)
          - 高 diversity_contribution (覆盖独特)
          - 低入度 (不轻易被其他种子替代)

        这些种子在贪心裁剪中容易被牺牲 (因为其覆盖可能被更大的种子包含),
        但它们在覆盖空间中处于承上启下的位置, 移除后会导致探索路径断裂。
        """
        self.compute_flow_centrality()
        bridges = []
        for nid, node in self._nodes.items():
            in_deg = len(node.in_neighbors)
            out_deg = len(node.out_neighbors)
            # 桥接条件: 有出边 (影响下游) + 低入度 (不易被替代) + 有流动或多样性
            if out_deg > 0 and in_deg <= 2:
                if node.flow_centrality >= min_flow or node.diversity_contribution >= 0.5:
                    bridges.append(nid)
        return bridges

    # //// 图统计 ////
    def stats(self) -> dict:
        n = len(self._nodes)
        e = self._edge_count
        densities = [
            nd.diversity_contribution for nd in self._nodes.values()
        ]
        flows = [
            nd.flow_centrality for nd in self._nodes.values()
        ]
        return {
            "node_count": n,
            "edge_count": e,
            "graph_density": e / max(1, n * (n - 1)) if n > 1 else 0.0,
            "isolated_nodes": sum(
                1 for nd in self._nodes.values()
                if not nd.in_neighbors and not nd.out_neighbors
            ),
            "avg_diversity": sum(densities) / max(1, n),
            "avg_flow_centrality": sum(flows) / max(1, n),
            "bridge_seed_count": len(self.find_bridge_seeds()),
        }

    # //// 自适应阈值校准 ////
    def calibrate_threshold(self) -> float:
        """基于当前图中覆盖集大小分布自适应调整 inclusion_threshold。

        覆盖集越小, Jaccard 越不稳定 (小样本偏差大), 应降低阈值。
        覆盖集越大, 包含关系应更严格, 否则误判率高。
        """
        if len(self._nodes) < 10:
            return self.threshold

        sizes = [len(nd.coverage_fingerprint) for nd in self._nodes.values()]
        avg_size = sum(sizes) / len(sizes)
        # avg_size < 50 → 阈值 0.5; avg_size > 500 → 阈值 0.7
        calibrated = 0.5 + 0.2 * min(1.0, avg_size / 500.0)
        self.threshold = calibrated
        return calibrated

    def rebuild(self) -> None:
        """全部重建关系图 — 用于阈值校准后的完整刷新。"""
        all_seeds = [(nid, set(nd.coverage_fingerprint))
                     for nid, nd in self._nodes.items()]
        self._nodes.clear()
        self._fingerprint_index.clear()
        self._edge_count = 0
        for sid, cov in all_seeds:
            self.upsert_seed(sid, cov)

    def clear(self) -> None:
        self._nodes.clear()
        self._fingerprint_index.clear()
        self._edge_count = 0
        self._dirty = False
