"""污点反馈驱动的字节级变异引擎 -- 不依赖额外插桩的热字节推断。

通过记录 havoc 变异前后的覆盖边变化, 反向推导各字节位置对覆盖率的影响力,
构建热字节映射以指导后续变异集中在高价值位置。

参考: ZTaint-Havoc  反馈反向推断热字节, STAFF  全系统污点固件,
TAIFuzz 污点插桩固件测试。

与 StructureAwareMutator 协同: 结构层先划字段边界, 字节层再用污点权重精调。
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
    """单个偏移位置的污点追踪累积数据。

    追踪维度: 命中次数、覆盖变化次数、崩溃触发次数、新增/丢失边计数。
    重要性分数由覆盖率变化率和变化幅度综合计算。
    """
    offset: int
    byte_value: int
    hit_count: int = 0            # 该偏移被选为变异目标的次数
    coverage_change_count: int = 0  # 变异后覆盖边集合发生变化的次数
    crash_trigger_count: int = 0   # 变异触发崩溃的次数
    # ZTaint-Havoc 区分: 新增边 vs 丢失边, 用于判断影响方向
    edge_gain_count: int = 0
    edge_loss_count: int = 0
    last_seen: float = 0.0         # 最近一次变异的时间戳 (epoch)
    importance_score: float = 0.0   # 归一化重要性, 区间 [0, 1]

class TaintGuidedMutator:
    """运行时覆盖反馈驱动的字节重要性评估与变异引导。

    无插桩开销: 仅依赖 fuzzer 已有的覆盖边集合差异。
    核心算法源自 ZTaint-Havoc  的 Python 等价实现。
    """

    def __init__(self, history_window: int = 500,
                 hot_threshold: float = 0.3):
        """
        history_window: 变异日志的滑动窗口长度, 越旧越早丢弃
        hot_threshold: 重要性分数高于此阈值的字节视为热字节, 优先变异
        """
        self.history_window = history_window
        self.hot_threshold = hot_threshold
        # 偏移 → 污点记录映射
        self._taint_map: Dict[int, ByteTaintRecord] = {}
        # 滑动窗口: (offset, old_byte, new_byte)
        self._mutation_log: List[Tuple[int, int, int]] = []
        self._total_mutations: int = 0
        self._epoch: int = 0

    def mutate(self, data: bytes, base_coverage: Optional[Set[int]] = None,
               mutation_rate: float = 0.01) -> bytes:
        """执行一次污点加权的字节变异。

        base_coverage 可选, 用于后续 feedback 比较; 未提供时退化为均匀随机。

        策略:
          有足够污点数据 → 70% 概率在热字节区域变异, 30% 均匀探索
          无数据 → 均匀随机选择位置
          变异算子按比例分配: 比特翻转 0.4, 随机字节 0.3, 算术微调 0.2, 边界值 0.1
        """
        if not data:
            return data

        raw = bytearray(data)
        n = len(raw)
        self._total_mutations += 1

        # 热字节集合加权采样确定变异位置
        hot_offsets = self._get_hot_offsets(n)
        if hot_offsets and random.random() < 0.7:
            # 热字节区域集中变异
            offset = random.choice(hot_offsets)
        else:
            # 均匀探索未知区域
            offset = random.randint(0, n - 1)

        old_byte = raw[offset]
        # 算子按概率分布: flip=0.4, random=0.3, arith=0.2, interesting=0.1
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

        # 滑动窗口记录, 供 feedback 阶段回溯
        self._mutation_log.append((offset, old_byte, raw[offset]))
        if len(self._mutation_log) > self.history_window:
            self._mutation_log.pop(0)

        return bytes(raw)

    def feedback(self, prev_coverage: Set[int], new_coverage: Set[int],
                 crashed: bool = False) -> None:
        """依据最近一次变异的覆盖差异更新对应字节的污点权重。

        prev_coverage: 变异前覆盖边集合
        new_coverage:  变异后覆盖边集合
        crashed:       目标是否因本次变异崩溃
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

        # 每 100 轮变异后全局归一化, 防止分数漂移
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
        """按 ZTaint-Havoc 公式重新计算某偏移的重要性。

        score = (覆盖变化次数 / 命中次数) * log2(1 + edge_gain + edge_loss)
        意为: 该位置每次变异引发覆盖变化的概率 × 变化幅度。

        命中不足 3 次时分数设为 0.1, 防止小样本过拟合。
        若该偏移曾触发崩溃, 得分额外 × crash_bonus (上限 ×2)。
        """
        rec = self._taint_map.get(offset)
        if rec is None or rec.hit_count < 2:
            return

        hit = max(1, rec.hit_count)
        change_ratio = rec.coverage_change_count / hit

        # 崩溃触发位置加权, 最高 2 倍
        crash_bonus = 1.0 + min(1.0, rec.crash_trigger_count / max(1, hit))

        magnitude = math.log2(1 + rec.edge_gain_count + rec.edge_loss_count)
        rec.importance_score = min(1.0, change_ratio * magnitude * crash_bonus)

    def _normalize_all_scores(self) -> None:
        """将全部字节的重要性分数同步缩放到 [0, 1] 区间。"""
        if not self._taint_map:
            return
        max_score = max(r.importance_score for r in self._taint_map.values()) or 1.0
        for rec in self._taint_map.values():
            rec.importance_score = rec.importance_score / max_score

    def _get_hot_offsets(self, data_len: int) -> List[int]:
        """筛选当前数据长度内的热字节偏移列表。

        若没有任何字节满足 hot_threshold, 返回全量偏移以避免空集。
        """
        hot = []
        for off, rec in self._taint_map.items():
            if off < data_len and rec.importance_score >= self.hot_threshold:
                hot.append(off)
        return hot if hot else list(range(data_len))

    def get_heatmap(self, data_len: int) -> List[float]:
        """输出长度为 data_len 的字节重要性数组, 值域 [0.0, 1.0]。

        可用于可视化或传递给其他变异引擎做加权参考。
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

# 结构感知 + 污点引导双层叠加变异

class HybridMutator:
    """双层变异引擎: 结构感知 (字段级) 叠加污点引导 (字节级)。

    第 1 层: StructureAwareMutator 做字段边界变换 (约 50% 概率执行)
    第 2 层: TaintGuidedMutator 在结果上做字节精调 (总是执行)
    两层独立, 结构层不可用时自动跳过。
    """

    def __init__(self):
        self._taint_mutator = TaintGuidedMutator()
        self._struct_mutator = None  # 延迟导入, 解耦强依赖

    def mutate(self, data: bytes, boundaries: Optional[List[int]] = None,
               base_coverage: Optional[Set[int]] = None) -> bytes:
        """依次执行结构层和污点层变异。

        第 1 层 (结构感知): 约半数概率触发, 未导入时跳过
        第 2 层 (污点引导): 始终执行, 以覆盖反馈精调字节
        """
        result = data

        # 结构感知层: 延迟导入, 避免循环依赖
        if self._struct_mutator is None:
            try:
                from fuzzing.fuzz_structure_mutator import StructureAwareMutator
                self._struct_mutator = StructureAwareMutator()
            except ImportError:
                pass

        if self._struct_mutator is not None and random.random() < 0.5:
            result = self._struct_mutator.mutate(result, boundaries)

        # 污点引导字节级精调
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
