"""覆盖感知种子拼接 (Coverage-Aware Seed Splicing, CASS) — 基于覆盖转移边界的智能拼接.

  AFL 的 splice 阶段 (random crossover at midpoint)
    — 纯随机拼接, 不考虑覆盖语义, 约 5% 概率产生有意义的子代
  SEAFuzz  的结构稀有度建模
    — 表明种子内部不同区域对覆盖的贡献是不均匀的
  Entropic
    — 信息论视角: 最大化每次变异的信息增益
  ZTaint-Havoc  的字节重要性热图
    — 证明可以通过反馈推断每个字节位置对覆盖的因果影响

核心假设:
  种子数据的不同区域驱动不同的覆盖边。若两个种子 A 和 B 的覆盖
  集合互补 (交集小), 则在覆盖转移边界处拼接它们的数据, 产生的
  后代有更高概率继承两者的互补覆盖, 从而探索新的路径组合。

  这与 ISRG 协同: ISRG 标识"哪些种子覆盖互补", CASS 决定
  "在互补种子的哪个位置拼接最有效"。

与传统 splice 的区别:
  AFL splice:    随机中点分割 + 交换 → O(1) 决策, 低成功率
  结构感知 splice: 按数据格式字段边界拼接 → 需预先知道格式
  CASS splice:    在覆盖转移边界拼接 → 无需格式知识, 基于反馈
"""

import hashlib
import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

@dataclass
class CoverageRegion:
    """种子数据的一个区域, 关联到特定的覆盖边子集。"""
    start: int                     # 区域内起始偏移 (含)
    end: int                       # 区域内结束偏移 (不含)
    edge_ids: Set[int] = field(default_factory=set)
    # 该区域对覆盖的贡献置信度 [0,1], 基于多次变异反馈累积
    confidence: float = 0.3

@dataclass
class SpliceCandidate:
    """一个拼接候选方案。"""
    seed_a: str                    # 父种子A的ID
    seed_b: str                    # 父种子B的ID
    splice_offset: int             # 在A中的切点
    complementarity: float         # A和B的覆盖互补度 (1 - Jaccard)
    transition_score: float        # 该切点处的覆盖转移强度
    total_score: float = 0.0       # complementarity * transition_score

class CoverageAwareSplicer:
    """覆盖感知种子拼接引擎。

    工作流程:
      1. 接收变异反馈: 将每次变异 (offset, old_byte, new_byte, coverage_delta)
         注册到对应字节位置
      2. 构建覆盖转移图: 识别种子数据中"覆盖变化剧烈"的位置
         → 这些位置可能是语义边界 (如文件头→数据体的分界)
      3. 当需要 splice 时: 在 ISRG 中找到互补种子对,
         在覆盖转移边界处执行拼接, 而非随机中点

    复杂度: 每个种子的覆盖区域图 O(D) 空间, D = 种子长度,
           每次 splice O(K·R) 其中 K = 候选对数, R = 转移边界数
    """

    def __init__(self, window_size: int = 8,
                 transition_threshold: float = 0.3):
        """
        window_size: 计算覆盖转移时的滑动窗口大小 (字节)
        transition_threshold: 多大覆盖变化率视为转移边界 [0, 1]
        """
        self.window_size = window_size
        self.transition_threshold = transition_threshold

        # seed_id → {offset → CoverageRegion}
        self._seed_regions: Dict[str, Dict[int, CoverageRegion]] = defaultdict(dict)
        # seed_id → [(boundary_offset, transition_strength), ...]
        self._boundary_cache: Dict[str, List[Tuple[int, float]]] = {}

        # 全局字节→覆盖的共现统计 (用于冷启动)
        self._global_byte_coverage: Dict[int, Dict[int, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self._total_mutations: int = 0

    # //// 反馈收集 ////
    def register_mutation(self, seed_id: str, offset: int,
                          coverage_before: Set[int],
                          coverage_after: Set[int]) -> None:
        """记录一次字节级变异对覆盖的影响。

        若某字节位置的变异反复引起覆盖变化, 则该位置处于覆盖敏感区。
        若相邻字节的覆盖敏感模式突变, 则此处为覆盖转移边界。
        """
        self._total_mutations += 1
        gained = coverage_after - coverage_before
        lost = coverage_before - coverage_after

        if not gained and not lost:
            return

        # 更新该位置的覆盖区域信息
        region = self._get_or_create_region(seed_id, offset)
        region.edge_ids.update(gained)
        region.edge_ids.update(lost)

        # 置信度递增 (指数移动平均)
        region.confidence = min(1.0, region.confidence + 0.1)

        # 更新全局共现统计
        for eid in gained | lost:
            self._global_byte_coverage[offset % 256][eid] += 1

        # 使边界缓存失效
        self._boundary_cache.pop(seed_id, None)

        # 冷数据淘汰: 每1000次变异清理低置信度区域
        if self._total_mutations % 1000 == 0:
            self._prune_low_confidence()

    # //// 转移边界检测 ////
    def detect_boundaries(self, seed_id: str, data_len: int) -> List[Tuple[int, float]]:
        """检测种子数据中的覆盖转移边界。

        算法:
          对每个窗口 [i, i+window_size), 计算窗口内覆盖边集合的
          平均 Jaccard 距离 (窗口间比较)。距离最大处即为转移边界。

        返回 [(offset, transition_strength), ...] 按强度降序。
        """
        if seed_id in self._boundary_cache:
            return self._boundary_cache[seed_id]

        regions = self._seed_regions.get(seed_id, {})
        if len(regions) < 3:
            # 数据不足, 退化为均匀分布的伪边界
            n_boundaries = max(2, data_len // 64)
            step = max(1, data_len // (n_boundaries + 1))
            pseudo = [(i * step, 0.1) for i in range(1, n_boundaries + 1)]
            return pseudo

        boundaries = []
        w = self.window_size

        for center in range(w, max(w + 1, data_len - w), w // 2):
            left_start = max(0, center - w)
            left_end = center
            right_start = center
            right_end = min(data_len, center + w)

            left_edges = self._region_edges_in_range(left_start, left_end, regions)
            right_edges = self._region_edges_in_range(right_start, right_end, regions)

            if not left_edges or not right_edges:
                continue

            # 窗口间 Jaccard 距离 = 1 - |L ∩ R| / |L ∪ R|
            intersection = len(left_edges & right_edges)
            union = len(left_edges | right_edges)
            jaccard = intersection / union if union > 0 else 0.0
            distance = 1.0 - jaccard

            if distance >= self.transition_threshold:
                boundaries.append((center, distance))

        boundaries.sort(key=lambda x: x[1], reverse=True)
        self._boundary_cache[seed_id] = boundaries
        return boundaries

    def _region_edges_in_range(self, start: int, end: int,
                                regions: Dict[int, CoverageRegion]) -> Set[int]:
        """聚合指定字节范围内的所有覆盖边。"""
        edges: Set[int] = set()
        for offset, region in regions.items():
            if start <= offset < end:
                edges.update(region.edge_ids)
        return edges

    # //// 互补种子对预筛选 (委托给 ISRG) ////
    def find_complementary_pairs(self, seed_ids: List[str],
                                 coverage_sets: Dict[str, Set[int]],
                                 max_pairs: int = 10) -> List[Tuple[str, str, float]]:
        """查找覆盖互补度最高的种子对。

        互补度 = 1 - Jaccard(A, B), 即覆盖集合的差异性。
        互补度越高, 两个种子探索了越不同的程序区域 → splice 潜力越大。
        """
        pairs = []
        n = len(seed_ids)
        for i in range(n):
            for j in range(i + 1, n):
                cov_a = coverage_sets.get(seed_ids[i], set())
                cov_b = coverage_sets.get(seed_ids[j], set())
                if not cov_a or not cov_b:
                    continue
                inter = len(cov_a & cov_b)
                union = len(cov_a | cov_b)
                jac = inter / union if union > 0 else 0.0
                complementarity = 1.0 - jac
                if complementarity > 0.3:  # 至少有一定互补性
                    pairs.append((seed_ids[i], seed_ids[j], complementarity))

        pairs.sort(key=lambda x: x[2], reverse=True)
        return pairs[:max_pairs]

    # //// 主入口: 执行覆盖感知拼接 ////
    def splice(self, data_a: bytes, seed_a: str,
               data_b: bytes, seed_b: str,
               coverage_a: Optional[Set[int]] = None,
               coverage_b: Optional[Set[int]] = None) -> Tuple[bytes, int, float]:
        """执行一次覆盖感知拼接。

        1. 在种子A中检测覆盖转移边界
        2. 选择转移强度最高的边界作为切点
        3. A[0:cut] + B[cut:] → 后代

        返回 (spliced_data, cut_offset, transition_score)。

        若数据不足以确定边界, 退化为 AFL 风格的中点随机拼接。
        """
        if not data_a or not data_b:
            return (data_a + data_b, 0, 0.0)

        boundaries_a = self.detect_boundaries(seed_a, len(data_a))
        boundaries_b = self.detect_boundaries(seed_b, len(data_b))

        # 选择转移强度最高的边界
        if boundaries_a and boundaries_a[0][1] >= self.transition_threshold:
            cut = boundaries_a[0][0]
            score = boundaries_a[0][1]
        elif boundaries_b and boundaries_b[0][1] >= self.transition_threshold:
            cut = boundaries_b[0][0]
            score = boundaries_b[0][1]
        else:
            # 回退: 随机中点 ± jitter
            mid = len(data_a) // 2
            jitter = random.randint(-len(data_a) // 8, len(data_a) // 8)
            cut = max(1, min(len(data_a) - 1, mid + jitter))
            score = 0.05

        # 确保 cut 在合法范围内
        cut = max(1, min(len(data_a) - 1, cut))
        # 若 B 太短, 截断切点
        if cut >= len(data_b):
            cut = len(data_b) - 1 if len(data_b) > 1 else 1

        spliced = data_a[:cut] + data_b[cut:]
        return (spliced, cut, score)

    # //// 批量拼接: 从候选对生成一批后代 ////
    def generate_offspring(self, seeds: Dict[str, bytes],
                           coverage_sets: Dict[str, Set[int]],
                           n_offspring: int = 5) -> List[Tuple[bytes, str, str, float]]:
        """从种子池生成一批覆盖感知的拼接后代。

        返回 [(offspring_data, parent_a_id, parent_b_id, quality_score), ...]。
        quality_score = complementarity * transition_score, 用于排序。
        """
        seed_ids = list(seeds.keys())
        if len(seed_ids) < 2:
            return []

        pairs = self.find_complementary_pairs(seed_ids, coverage_sets, max_pairs=20)
        if not pairs:
            return []

        offspring = []
        for sid_a, sid_b, complementarity in pairs:
            data_a = seeds.get(sid_a)
            data_b = seeds.get(sid_b)
            if not data_a or not data_b:
                continue

            result, cut, trans_score = self.splice(
                data_a, sid_a, data_b, sid_b,
                coverage_sets.get(sid_a), coverage_sets.get(sid_b),
            )
            quality = complementarity * trans_score
            offspring.append((result, sid_a, sid_b, quality))

        offspring.sort(key=lambda x: x[3], reverse=True)
        return offspring[:n_offspring]

    # //// 内部辅助 ////
    def _get_or_create_region(self, seed_id: str, offset: int) -> CoverageRegion:
        regions = self._seed_regions[seed_id]
        if offset not in regions:
            regions[offset] = CoverageRegion(
                start=max(0, offset - 2), end=offset + 3
            )
        return regions[offset]

    def _prune_low_confidence(self) -> None:
        """清理置信度过低的覆盖区域以控制内存。"""
        for seed_id in list(self._seed_regions.keys()):
            regions = self._seed_regions[seed_id]
            low_conf = [
                off for off, r in regions.items() if r.confidence < 0.1
            ]
            for off in low_conf:
                del regions[off]
            if not regions:
                del self._seed_regions[seed_id]

    # //// 统计 ////
    def stats(self) -> dict:
        total_regions = sum(
            len(regions) for regions in self._seed_regions.values()
        )
        total_boundaries = sum(
            len(b) for b in self._boundary_cache.values()
        )
        return {
            "tracked_seeds": len(self._seed_regions),
            "total_regions": total_regions,
            "total_boundaries_detected": total_boundaries,
            "total_mutations_recorded": self._total_mutations,
        }

    def clear(self) -> None:
        self._seed_regions.clear()
        self._boundary_cache.clear()
        self._global_byte_coverage.clear()
        self._total_mutations = 0
