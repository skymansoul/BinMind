#
# 覆盖密度感知的模糊测试变异策略 — 在 AFL 风格覆盖率反馈之上叠加空间密度分析。
#
# 传统覆盖率引导的 fuzzer 将所有新覆盖边等权对待——第 1 次和第 100 次
# 命中同一条新边的价值相同。这忽略了"覆盖密度"——某些代码区域被反复
# 探索但从未产生新状态（"饱和区"），而相邻区域可能完全未被触及。
#
# 本模块在 bitmap 之上维护一个低开销的密度估计器：
#   (a) 将覆盖 bitmap 划分为固定大小的 bucket（默认 64 条边/bucket）
#   (b) 每个 bucket 维护指数衰减命中计数——最近命中的权重更高
#   (c) 密度 = bucket 内的加权命中数 / bucket 大小
#   (d) 低密度 bucket 的相邻区域被标记为"值得优先变异"——种子覆盖这些
#       区域的字节被给予更高的变异概率
#
# 与 AFL 的 effector map 的区别：
#   AFL effector map 标记"翻转某字节是否改变覆盖"——是二值的。
#   本模块输出每个字节位置的连续变异概率——密度越低，概率越高。

import math
import struct
from typing import Dict, List, Tuple, Set, Optional


class CoverageDensityMap:
    """覆盖密度感知的字节级变异优先级映射。

    Bucket 大小 64 条边——取 2 的幂以用移位代替除法。
    指数衰减半衰期默认 500 次执行——之后的覆盖事件权重降为 0.5。
    """

    BUCKET_SHIFT = 6  # 64 edges per bucket
    BUCKET_SIZE = 1 << BUCKET_SHIFT

    def __init__(self, bitmap_size: int = 65536, halflife_execs: int = 500):
        self._bitmap_size = bitmap_size
        self._num_buckets = (bitmap_size + self.BUCKET_SIZE - 1) // self.BUCKET_SIZE
        self._bucket_hits = [0.0] * self._num_buckets
        self._total_execs = 0
        # 衰减因子: exp(-λ × 1)，λ = ln(2) / halflife
        self._decay_per_exec = math.exp(-math.log(2) / halflife_execs)

    def update(self, bitmap: bytes):
        """用一次模糊测试执行的覆盖 bitmap 更新密度图。

        对 bitmap 中每个非零字节，递增对应 bucket 的加权命中计数。
        所有 bucket 统一做一次指数衰减——这比每 bucket 独立衰减更高效。
        """
        self._total_execs += 1

        # 统一衰减
        for i in range(self._num_buckets):
            self._bucket_hits[i] *= self._decay_per_exec

        # 更新命中
        for i, byte_val in enumerate(bitmap):
            if byte_val == 0:
                continue
            bucket = i >> self.BUCKET_SHIFT
            if bucket < self._num_buckets:
                # 命中权重 = log2(1 + byte_val)——边被命中的次数越多，
                # 代表该区域越"热"。用对数压缩避免少数极热 bucket 完全
                # 主导密度分布（hit count 在 AFL 中可达 255）
                weight = math.log2(1 + byte_val)
                self._bucket_hits[bucket] += weight

    def get_density(self, edge_index: int) -> float:
        """返回指定边所在 bucket 的当前密度估计 [0, 1]。

        密度 = bucket_hits / (bucket_size × log2(256)) 归一化。
        """
        bucket = edge_index >> self.BUCKET_SHIFT
        if bucket >= self._num_buckets:
            return 1.0
        # 归一化: 最大可能值 = bucket_size × log2(256) = 64 × 8 = 512
        max_possible = self.BUCKET_SIZE * 8.0
        return min(1.0, self._bucket_hits[bucket] / max_possible)

    def get_byte_mutation_probability(self, seed: bytes,
                                       edge_map: Dict[int, List[int]]
                                       ) -> List[float]:
        """计算种子每个字节的变异概率。

        edge_map: {byte_offset: [edge_indices]}——种子各字节覆盖的边列表。
        返回: 长度 = len(seed) 的概率列表。概率 ∈ [0.05, 0.5]。
        下限 0.05 保证即使最热的区域也有微小概率被变异（避免完全停滞）。
        上限 0.5 防止单个字节被过度变异（变异器需探索多字节组合）。
        """
        probs = [0.1] * len(seed)  # 未映射字节的默认概率

        for byte_offset, edges in edge_map.items():
            if byte_offset >= len(seed):
                continue
            if not edges:
                continue

            # 取该字节覆盖的所有边的密度平均值
            avg_density = sum(self.get_density(e) for e in edges) / len(edges)
            # 密度越低 → 变异概率越高
            prob = 0.5 - 0.45 * avg_density
            probs[byte_offset] = max(0.05, min(0.5, prob))

        return probs

    def cold_regions(self, top_n: int = 5) -> List[Tuple[int, int, float]]:
        """返回密度最低的 top_n 个 bucket 区间。

        返回 [(start_edge, end_edge, density), ...] 按密度升序。
        """
        regions = []
        for i in range(self._num_buckets):
            density = min(1.0, self._bucket_hits[i] / (self.BUCKET_SIZE * 8.0))
            regions.append((i << self.BUCKET_SHIFT,
                           (i + 1) << self.BUCKET_SHIFT,
                           round(density, 4)))
        regions.sort(key=lambda x: x[2])
        return regions[:top_n]
