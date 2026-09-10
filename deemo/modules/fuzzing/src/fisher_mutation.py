"""Fisher 信息制导变异选择器 — 信息散度度量 + 覆盖分布差异排序.

参考: Amari & Nagaoka 信息几何 (理论背景)
      本模块用标量对角信息散度做变异优先级排序,
      是信息几何概念在离散 fuzzing 空间的简化适配。"""

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# Fisher 估计参数
_CHUNK_SIZE = 8           # 块级 Fisher 的字节窗口
_MIN_OBSERVATIONS = 5     # Fisher 估计的最少观测数
_JEFFREYS_ALPHA = 0.5     # Jeffreys 先验的伪计数
_DECAY_FACTOR = 0.995     # 旧观测的指数衰减因子


@dataclass
class FisherByteProfile:
    """单个字节位置的 Fisher 信息剖面."""
    offset: int
    # 覆盖增益分布的充分统计量
    obs_count: int = 0
    sum_gain: float = 0.0            # Σ coverage_delta
    sum_sq_gain: float = 0.0         # Σ coverage_delta²
    # 离散化: 覆盖增益分桶 (0, 1, 2-4, 5+)
    bucket_0: int = 0                # 无增益
    bucket_1: int = 0                # 1条新边
    bucket_2_4: int = 0              # 2-4条
    bucket_5plus: int = 0            # ≥5条
    # 推断度量
    fisher_value: float = 0.0        # 对角 Fisher 信息
    jeffreys_fisher: float = 0.0     # Jeffreys 先验修正值
    last_updated: float = 0.0


class FisherMutationSelector:
    """基于 Fisher 信息度量的变异优先级排序器.

    对每个字节位置维护结果分布的充分统计量, 计算对角 Fisher 信息,
    按信息量降序推荐变异位置。自然梯度视角: 优先变异那些
    "结果分布对该位置变化最敏感" 的字节 — 即梯度在信息几何上最陡的方向。

    使用方式:
      fms = FisherMutationSelector()
      for each execution:
          fms.observe(byte_offset, coverage_delta)
      # 获取高信息量变异位置
      priorities = fms.top_informative_positions(seed_data, top_k=10)
    """

    def __init__(self, chunk_size: int = _CHUNK_SIZE):
        self.chunk_size = chunk_size
        self._byte_profiles: Dict[int, FisherByteProfile] = {}
        self._chunk_profiles: Dict[int, FisherByteProfile] = {}  # chunk_start → profile
        self._global_baseline: Dict[int, float] = {0: 0.5, 1: 0.3, 2: 0.15, 3: 0.05}
        self._total_obs: int = 0
        self._last_decay: float = time.time()

    # //// 观测收集 ////
    def observe(self, byte_offset: int, coverage_delta: int,
                exec_time_ms: float = 0.0) -> None:
        """记录一次字节变异的结果.

        对每个观测同时更新字节级和块级 profile。
        """
        self._total_obs += 1
        self._maybe_decay()

        # 字节级
        bp = self._get_byte_profile(byte_offset)
        self._update_profile(bp, coverage_delta)

        # 块级 (8-byte chunks)
        chunk_start = (byte_offset // self.chunk_size) * self.chunk_size
        cp = self._get_chunk_profile(chunk_start)
        self._update_profile(cp, coverage_delta)

        # 每 50 次观测重算 Fisher 值
        if self._total_obs % 50 == 0:
            self._recompute_all_fisher()

    def _update_profile(self, bp: FisherByteProfile, coverage_delta: int) -> None:
        bp.obs_count += 1
        bp.sum_gain += coverage_delta
        bp.sum_sq_gain += coverage_delta * coverage_delta
        if coverage_delta == 0:
            bp.bucket_0 += 1
        elif coverage_delta == 1:
            bp.bucket_1 += 1
        elif coverage_delta <= 4:
            bp.bucket_2_4 += 1
        else:
            bp.bucket_5plus += 1
        bp.last_updated = time.time()

    # //// Fisher 信息计算 ////
    def _recompute_all_fisher(self) -> None:
        """对所有 byte profile 重算 Fisher 值.

        Fisher 信息的离散近似:
          F_i = Σ_k (Δp_k)² / p_k
        其中 p_k 是全局基线桶概率, Δp_k 是该位置的经验概率偏差。

        直觉: 若某位置的覆盖增益分布显著偏离全局基线,
        则该位置的 Fisher 信息高 → 变更此位置产生"意外"结果 → 值得探索。
        """
        for bp in self._byte_profiles.values():
            if bp.obs_count < _MIN_OBSERVATIONS:
                bp.fisher_value = 0.0
                bp.jeffreys_fisher = 0.0
                continue

            total = bp.obs_count
            # 经验分布
            emp = [
                bp.bucket_0 / total,
                bp.bucket_1 / total,
                bp.bucket_2_4 / total,
                bp.bucket_5plus / total,
            ]
            # 全局基线分布
            base = [
                self._global_baseline.get(0, 0.5),
                self._global_baseline.get(1, 0.3),
                self._global_baseline.get(2, 0.15),
                self._global_baseline.get(3, 0.05),
            ]

            # Fisher: Σ (emp_k - base_k)² / base_k
            fisher = 0.0
            for e, b in zip(emp, base):
                if b > 1e-8:
                    fisher += (e - b) ** 2 / b
            bp.fisher_value = fisher

            # Jeffreys 修正: 在观测数据中加入 Beta(0.5,0.5) 伪计数
            jeff_total = total + _JEFFREYS_ALPHA * 4
            jeff_emp = [
                (bp.bucket_0 + _JEFFREYS_ALPHA) / jeff_total,
                (bp.bucket_1 + _JEFFREYS_ALPHA) / jeff_total,
                (bp.bucket_2_4 + _JEFFREYS_ALPHA) / jeff_total,
                (bp.bucket_5plus + _JEFFREYS_ALPHA) / jeff_total,
            ]
            jeffreys = 0.0
            for e, b in zip(jeff_emp, base):
                if b > 1e-8:
                    jeffreys += (e - b) ** 2 / b
            bp.jeffreys_fisher = jeffreys

        # 更新全局基线为加权平均
        total_all = sum(bp.obs_count for bp in self._byte_profiles.values())
        if total_all > 0:
            self._global_baseline[0] = sum(
                bp.bucket_0 for bp in self._byte_profiles.values()) / total_all
            self._global_baseline[1] = sum(
                bp.bucket_1 for bp in self._byte_profiles.values()) / total_all
            self._global_baseline[2] = sum(
                bp.bucket_2_4 for bp in self._byte_profiles.values()) / total_all
            self._global_baseline[3] = sum(
                bp.bucket_5plus for bp in self._byte_profiles.values()) / total_all

    # //// 变异推荐 ////
    def top_informative_positions(self, data_len: int, top_k: int = 10,
                                   use_chunks: bool = False) -> List[Tuple[int, float, str]]:
        """按 Fisher 信息降序返回值得变异的位置.

        use_chunks=True → 返回块级 (chunk_start) 推荐, 用于字段级变异
        use_chunks=False → 返回字节级推荐

        返回 [(offset, fisher_value, granularity), ...]
        granularity ∈ {"byte", "chunk"}
        """
        profiles = self._chunk_profiles if use_chunks else self._byte_profiles
        granularity = "chunk" if use_chunks else "byte"

        candidates = []
        max_offset = data_len if not use_chunks else (data_len // self.chunk_size) * self.chunk_size
        for offset, bp in profiles.items():
            if offset >= max_offset:
                continue
            # 使用 Jeffreys 修正值 (对小样本更鲁棒)
            fv = bp.jeffreys_fisher if bp.obs_count < 20 else bp.fisher_value
            if fv < 0.01:  # 过滤 Fisher 极低的均匀分布位置
                continue
            candidates.append((offset, fv))

        candidates.sort(key=lambda x: x[1], reverse=True)
        return [(off, fv, granularity) for off, fv in candidates[:top_k]]

    def natural_gradient_mutation(self, seed_data: bytes,
                                   top_k: int = 8) -> List[Tuple[int, int, str]]:
        """自然梯度制导变异: 在高 Fisher 位置施加与信息量成比例的变异.

        返回 [(offset, suggested_byte_val, rationale), ...].
        rationale: "fisher_byte" | "fisher_chunk" | "exploratory"

        变异策略:
          - 高 Fisher (>0.5): 微扰动 (±1, bitflip) — 位置敏感, 小变更即可改变结果分布
          - 中 Fisher (0.2-0.5): 边界值注入 (0x00/0xFF/0x7F) — 探索值范围边界
          - 低 Fisher: 随机值 — 位置稳定, 大幅变更才可能产生效果
        """
        import random
        suggestions = []
        data_len = len(seed_data)
        if data_len == 0:
            return []

        # 字节级推荐
        byte_candidates = self.top_informative_positions(data_len, top_k=top_k, use_chunks=False)

        for offset, fv, _ in byte_candidates:
            if offset >= data_len:
                continue
            orig = seed_data[offset]
            if fv > 0.5:
                # 微扰动
                if random.random() < 0.5:
                    new_val = orig ^ (1 << random.randint(0, 7))
                else:
                    delta = random.choice([-1, 1])
                    new_val = (orig + delta) & 0xFF
                rationale = "fisher_byte_perturb"
            elif fv > 0.2:
                new_val = random.choice([0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF])
                rationale = "fisher_byte_boundary"
            else:
                new_val = random.randint(0, 255)
                rationale = "fisher_byte_explore"
            suggestions.append((offset, new_val, rationale))

        # 补充块级推荐: 高 Fisher 块内的字节做协同变异
        chunk_candidates = self.top_informative_positions(
            data_len, top_k=max(2, top_k // 3), use_chunks=True)
        for chunk_start, fv, _ in chunk_candidates:
            if fv < 0.3 or chunk_start >= data_len:
                continue
            # 在块内随机选一个偏移做变异
            for _ in range(2):
                off = chunk_start + random.randint(0, min(self.chunk_size - 1,
                                                          data_len - chunk_start - 1))
                if off < data_len:
                    suggestions.append(
                        (off, seed_data[off] ^ (1 << random.randint(0, 7)),
                         "fisher_chunk"))
        return suggestions[:top_k]

    # //// 内部辅助 ////
    def _get_byte_profile(self, offset: int) -> FisherByteProfile:
        if offset not in self._byte_profiles:
            self._byte_profiles[offset] = FisherByteProfile(offset=offset)
        return self._byte_profiles[offset]

    def _get_chunk_profile(self, chunk_start: int) -> FisherByteProfile:
        if chunk_start not in self._chunk_profiles:
            self._chunk_profiles[chunk_start] = FisherByteProfile(offset=chunk_start)
        return self._chunk_profiles[chunk_start]

    def _maybe_decay(self) -> None:
        """每 500 次观测对旧数据做指数衰减, 保持对分布偏移的响应性."""
        if self._total_obs % 500 == 0:
            for bp in self._byte_profiles.values():
                bp.obs_count = max(1, int(bp.obs_count * _DECAY_FACTOR))
                bp.bucket_0 = max(1, int(bp.bucket_0 * _DECAY_FACTOR))
                bp.bucket_1 = max(0, int(bp.bucket_1 * _DECAY_FACTOR))
                bp.bucket_2_4 = max(0, int(bp.bucket_2_4 * _DECAY_FACTOR))
                bp.bucket_5plus = max(0, int(bp.bucket_5plus * _DECAY_FACTOR))

    # //// 统计 ////
    def stats(self) -> dict:
        n_bytes = len(self._byte_profiles)
        n_chunks = len(self._chunk_profiles)
        fvals = [bp.jeffreys_fisher for bp in self._byte_profiles.values()
                 if bp.obs_count >= _MIN_OBSERVATIONS]
        return {
            "tracked_bytes": n_bytes,
            "tracked_chunks": n_chunks,
            "total_observations": self._total_obs,
            "mean_fisher": sum(fvals) / max(1, len(fvals)),
            "max_fisher": max(fvals) if fvals else 0.0,
            "high_info_bytes": sum(1 for f in fvals if f > 0.5),
            "global_baseline": self._global_baseline,
        }

    def clear(self) -> None:
        self._byte_profiles.clear()
        self._chunk_profiles.clear()
        self._global_baseline = {0: 0.5, 1: 0.3, 2: 0.15, 3: 0.05}
        self._total_obs = 0
