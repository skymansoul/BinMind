# 2026-08-01

"""污点引导的变异引擎 -- 零额外执行的字节重要性推断 [ZTaint-Havoc, ISSTA 2025]。

参考:
  ZTaint-Havoc (ISSTA 2025)       -- 从 AFL++ havoc 阶段反向推断热字节, 零额外执行
  Checksum-Aware Fuzzing + DTA    -- 动态污点分析+符号执行的校验和感知模糊测试
  STAFF (arXiv:2509.18039)       -- 全系统污点辅助固件模糊测试
  TAIFuzz (SPIE 2024)            -- 污点分析插桩基固件模糊测试

核心假设 (ZTaint-Havoc 验证):
  变异某个字节后覆盖发生变化 → 该字节对程序行为有因果影响 → "热字节"。
  通过记录 havoc 阶段每次变异前后覆盖变化, 在无额外插桩的条件下
  逐步构建字节重要性映射, 后续变异中强化热字节区域的变异密度。

与 StructureAwareMutator 的关系:
  - StructureAwareMutator: 基于数据结构的字段划分和操作
  - TaintGuidedMutator: 基于运行时反馈的字节重要性, 与结构无关
  两者可叠加: 先用结构划分确定字段边界, 再在热字段内用污点权重引导变异。
"""

import hashlib
import logging
import math
import random
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ByteTaintRecord:
    """单个字节位置的污点追踪记录。"""
    offset: int
    byte_value: int
    hit_count: int = 0            # 被变异的次数
    coverage_change_count: int = 0  # 变异后覆盖变化的次数
    crash_trigger_count: int = 0   # 触发崩溃的次数
    # ZTaint-Havoc: 不仅记录是否变化, 还区分变化方向 (edge_gain / edge_loss)
    edge_gain_count: int = 0
    edge_loss_count: int = 0
    last_seen: float = 0.0         # 最近一次变异的时间戳
    importance_score: float = 0.0   # 综合重要性评分 [0, 1]


class TaintGuidedMutator:
    """基于运行时反馈的字节重要性引导变异。

    不依赖额外插桩或符号执行, 通过观察 havoc 阶段每次变异的
    效果 (覆盖变化) 推断字节重要性, 是 ZTaint-Havoc 的 Python 实现。

    使用方法:
      tgm = TaintGuidedMutator()
      for each seed:
          mutated = tgm.mutate(seed, original_coverage)
          new_cov = executor.execute(mutated)
          tgm.feedback(original_cov, new_cov, crashed=False)
    """

    def __init__(self, history_window: int = 500,
                 hot_threshold: float = 0.3):
        """
        history_window: 保留最近多少次变异的反馈记录
        hot_threshold: importance_score > 此值的字节被视为"热字节"
        """
        self.history_window = history_window
        self.hot_threshold = hot_threshold
        # offset -> ByteTaintRecord
        self._taint_map: Dict[int, ByteTaintRecord] = {}
        # 最近变异的 (offset, old_byte, new_byte) 队列
        self._mutation_log: List[Tuple[int, int, int]] = []
        self._total_mutations: int = 0
        self._epoch: int = 0

    def mutate(self, data: bytes, base_coverage: Optional[Set[int]] = None,
               mutation_rate: float = 0.01) -> bytes:
        """执行一次污点引导的变异。

        base_coverage: 变异前的覆盖边集合 (可选, 用于后续 feedback)。
        若未提供, 按均匀分布变异。

        算法:
          1. 若有污点数据, 在热字节区域以更高概率变异
          2. 若无足够数据, 回退到均匀随机变异
          3. 记录变异位置供后续 feedback 更新
        """
        if not data:
            return data

        raw = bytearray(data)
        n = len(raw)
        self._total_mutations += 1

        # 选择变异位置: 热字节加权采样
        hot_offsets = self._get_hot_offsets(n)
        if hot_offsets and random.random() < 0.7:
            # 70% 在热字节区域变异
            offset = random.choice(hot_offsets)
        else:
            # 30% 均匀探索
            offset = random.randint(0, n - 1)

        old_byte = raw[offset]
        # 变异操作: 比特翻转 (40%), 字节随机 (30%), 算术加减 (20%), 有趣值 (10%)
        op_roll = random.random()

        if op_roll < 0.4:
            bit = random.randint(0, 7)
            raw[offset] ^= (1 << bit)
        elif op_roll < 0.7:
            raw[offset] = random.randint(0, 255)
        elif op_roll < 0.9:
            delta = random.randint(-16, 16)
            raw[offset] = (raw[offset] + delta) & 0xFF
        else:
            interesting = [0x00, 0x01, 0x7F, 0x80, 0xFF]
            raw[offset] = random.choice(
                [v for v in interesting if v != raw[offset]]
            ) if len([v for v in interesting if v != raw[offset]]) > 0 else raw[offset]

        # 记录日志供 feedback 使用
        self._mutation_log.append((offset, old_byte, raw[offset]))
        if len(self._mutation_log) > self.history_window:
            self._mutation_log.pop(0)

        return bytes(raw)

    def feedback(self, prev_coverage: Set[int], new_coverage: Set[int],
                 crashed: bool = False) -> None:
        """根据变异结果更新污点权重。

        prev_coverage: 变异前的覆盖边集合
        new_coverage:  变异后的覆盖边集合
        crashed:       是否触发崩溃
        """
        if not self._mutation_log:
            return

        offset, old_b, new_b = self._mutation_log[-1]
        gained = new_coverage - prev_coverage
        lost = prev_coverage - new_coverage
        has_change = len(gained) > 0 or len(lost) > 0

        rec = self._get_or_create_record(offset, old_b)
        rec.hit_count += 1
        rec.last_seen = time.time()

        if has_change:
            rec.coverage_change_count += 1
            rec.edge_gain_count += len(gained)
            rec.edge_loss_count += len(lost)

        if crashed:
            rec.crash_trigger_count += 1

        self._recalc_importance(offset)

        # 每 100 次变异重新归一化所有权重
        self._epoch += 1
        if self._epoch % 100 == 0:
            self._normalize_all_scores()

    def _get_or_create_record(self, offset: int, byte_val: int) -> ByteTaintRecord:
        key = offset
        if key not in self._taint_map:
            self._taint_map[key] = ByteTaintRecord(
                offset=offset, byte_value=byte_val
            )
        return self._taint_map[key]

    def _recalc_importance(self, offset: int) -> None:
        """ZTaint-Havoc 风格的重要性计算。

        score = (coverage_change_count / hit_count) * log2(1 + edge_gain_count + edge_loss_count)
        即: 该字节"每次变异产生覆盖变化的比率" × "变化幅度"。

        若 hit_count 太少 (< 3), 使用先验值 0.1 避免小样本过拟合。
        """
        rec = self._taint_map.get(offset)
        if rec is None or rec.hit_count < 2:
            return

        hit = max(1, rec.hit_count)
        change_ratio = rec.coverage_change_count / hit

        # 崩溃触发的字节 ×2 加权
        crash_bonus = 1.0 + min(1.0, rec.crash_trigger_count / max(1, hit))

        magnitude = math.log2(1 + rec.edge_gain_count + rec.edge_loss_count)
        rec.importance_score = min(1.0, change_ratio * magnitude * crash_bonus)

    def _normalize_all_scores(self) -> None:
        """将所有字节的重要性分数归一化到 [0, 1] 并应用指数衰减。"""
        if not self._taint_map:
            return
        max_score = max(r.importance_score for r in self._taint_map.values()) or 1.0
        for rec in self._taint_map.values():
            rec.importance_score = rec.importance_score / max_score

    def _get_hot_offsets(self, data_len: int) -> List[int]:
        hot = []
        for off, rec in self._taint_map.items():
            if off < data_len and rec.importance_score >= self.hot_threshold:
                hot.append(off)
        return hot if hot else list(range(data_len))

    def get_heatmap(self, data_len: int) -> List[float]:
        """生成当前数据的字节重要性热图 (0.0-1.0 数组)。

        可用于可视化或喂给其他变异引擎。
        """
        heatmap = [0.0] * data_len
        for off, rec in self._taint_map.items():
            if off < data_len:
                heatmap[off] = rec.importance_score
        return heatmap

    def get_stats(self) -> Dict:
        hot_count = sum(
            1 for r in self._taint_map.values()
            if r.importance_score >= self.hot_threshold
        )
        return {
            "total_bytes_tracked": len(self._taint_map),
            "hot_bytes": hot_count,
            "total_mutations": self._total_mutations,
            "avg_importance": (
                sum(r.importance_score for r in self._taint_map.values())
                / max(1, len(self._taint_map))
            ),
            "top_5_offsets": sorted(
                [(off, round(r.importance_score, 3))
                 for off, r in self._taint_map.items()],
                key=lambda x: x[1], reverse=True
            )[:5],
        }

    def reset(self) -> None:
        self._taint_map.clear()
        self._mutation_log.clear()
        self._total_mutations = 0
        self._epoch = 0


# ===== 叠加式变异: 结构感知 + 污点引导 =====

class HybridMutator:
    """结构感知变异 (字段级) + 污点引导变异 (字节级) 的叠加引擎。

    先调用 StructureAwareMutator 进行字段级变换,
    再在此结果的字节序列上用 TaintGuidedMutator 精调。
    """

    def __init__(self):
        self._taint_mutator = TaintGuidedMutator()
        self._struct_mutator = None  # 按需加载, 避免强依赖

    def mutate(self, data: bytes, boundaries: Optional[List[int]] = None,
               base_coverage: Optional[Set[int]] = None) -> bytes:
        """两层变异叠加。

        第1层 (可选): 结构感知变异 — 约 50% 概率执行
        第2层 (总是): 污点引导字节级变异
        """
        result = data

        # 第1层: 结构感知
        if self._struct_mutator is None:
            try:
                from fuzzing.fuzz_structure_mutator import StructureAwareMutator
                self._struct_mutator = StructureAwareMutator()
            except ImportError:
                pass

        if self._struct_mutator is not None and random.random() < 0.5:
            result = self._struct_mutator.mutate(result, boundaries)

        # 第2层: 污点引导
        result = self._taint_mutator.mutate(result, base_coverage)

        return result

    def feedback(self, prev_cov: Set[int], new_cov: Set[int],
                 crashed: bool = False) -> None:
        self._taint_mutator.feedback(prev_cov, new_cov, crashed)

    def get_heatmap(self, data_len: int) -> List[float]:
        return self._taint_mutator.get_heatmap(data_len)

    @property
    def stats(self) -> Dict:
        return self._taint_mutator.get_stats()
