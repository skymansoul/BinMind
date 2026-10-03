"""
反事实变异类型定义 — SCM rung-3 因果推断在模糊测试中的数据结构。

Pearl 因果阶梯:
  rung-1 (association):    P(Y|X)        —  突变X后观察到效果Y的概率
  rung-2 (intervention):   P(Y|do(X))    —  强制设置字节为X后的效果
  rung-3 (counterfactual): P(Y_{X'}|X,Y) —  已知X→Y, 若做的是X'会怎样?

ref: Pearl "Causality" 2nd ed. §7 — do-calculus 与反事实的形式化定义
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import FrozenSet, List, Tuple, Optional

_MAX_HISTORY = 500
_MIN_SAMPLES_FOR_CAUSAL = 30
_CF_CONFIDENCE_THRESHOLD = 0.6
_BOOTSTRAP_SAMPLES = 100


@dataclass
class MutationObservation:
    """单次变异的观测记录。counterfactual_mutator 消费此类型。"""
    byte_offset: int
    original_value: int = 0
    mutated_value: int = 0
    mutation_type: str = ""
    coverage_delta: int = 0
    new_edge_ids: FrozenSet[int] = field(default_factory=frozenset)
    execution_time_ms: float = 10.0
    is_crash: bool = False
    timestamp: float = field(default_factory=time.time)
    # 兼容旧字段
    old_value: int = 0
    new_value: int = 0
    new_edges: int = 0
    new_crashes: int = 0
    exec_time_ms: float = 0.0

    def __post_init__(self):
        if self.old_value == 0 and self.original_value != 0:
            self.old_value = self.original_value
        if self.new_value == 0 and self.mutated_value != 0:
            self.new_value = self.mutated_value
        if self.new_edges == 0 and self.coverage_delta != 0:
            self.new_edges = self.coverage_delta
        if self.exec_time_ms == 0.0:
            self.exec_time_ms = self.execution_time_ms

    def effect_score(self) -> float:
        crash_bonus = 10.0 if self.is_crash else 0.0
        if self.execution_time_ms <= 0:
            return float(self.coverage_delta) + crash_bonus
        return float(self.coverage_delta) + crash_bonus - self.execution_time_ms / 10000.0


@dataclass
class CounterfactualEstimate:
    """一次反事实推断的结果。"""
    byte_offset: int
    actual_value: int = 0
    cf_value: int = 0
    expected_delta: float = 0.0
    confidence: float = 0.0
    causal_effect_sign: int = 0
    # 兼容旧字段
    hypothetical_value: int = 0
    estimated_edges: float = 0.0
    evidence: list[int] = field(default_factory=list)
    method: str = 'linear'

    def __post_init__(self):
        if self.hypothetical_value == 0 and self.cf_value != 0:
            self.hypothetical_value = self.cf_value
        if self.estimated_edges == 0.0 and self.expected_delta != 0.0:
            self.estimated_edges = self.expected_delta

    def is_reliable(self, min_confidence: float = 0.6) -> bool:
        return self.confidence >= min_confidence and len(self.evidence) >= 2


@dataclass
class CausalByteModel:
    """单字节位置的局部因果模型 — 指数加权线性回归。
    线性在小邻域内足够捕捉梯度方向。指数衰减使旧观测逐渐遗忘。"""
    offset: int
    slope: float = 0.0
    intercept: float = 0.0
    decay: float = 0.95
    n_obs: int = 0
    sum_x: float = 0.0
    sum_y: float = 0.0
    sum_xy: float = 0.0
    sum_x2: float = 0.0
    total_weight: float = 0.0
    last_effect: float = 0.0

    def update(self, byte_value: int, effect: float) -> None:
        w = self.decay ** self.n_obs if self.n_obs > 0 else 1.0
        self.n_obs += 1
        x = float(byte_value)
        self.sum_x += w * x
        self.sum_y += w * effect
        self.sum_xy += w * x * effect
        self.sum_x2 += w * x * x
        self.total_weight += w
        self.last_effect = effect
        denom = self.total_weight * self.sum_x2 - self.sum_x ** 2
        if abs(denom) > 1e-12:
            self.slope = (self.total_weight * self.sum_xy - self.sum_x * self.sum_y) / denom
            self.intercept = (self.sum_y - self.slope * self.sum_x) / self.total_weight
        elif self.total_weight > 0:
            self.intercept = self.sum_y / self.total_weight

    def predict(self, byte_value: int) -> float:
        return self.slope * float(byte_value) + self.intercept

    def gradient_sign(self) -> int:
        if abs(self.slope) < 1e-6:
            return 0
        return 1 if self.slope > 0 else -1

    def best_value(self, current: int, lo: int = 0, hi: int = 255) -> Tuple[int, float]:
        best_val, best_pred = lo, float('-inf')
        for v in (lo, hi, (lo + hi) // 2):
            if v == current:
                continue
            p = self.predict(v)
            if p > best_pred:
                best_pred, best_val = p, v
        if self.slope > 0 and hi != current:
            p = self.predict(hi)
            if p > best_pred:
                best_pred, best_val = p, hi
        elif self.slope < 0 and lo != current:
            p = self.predict(lo)
            if p > best_pred:
                best_pred, best_val = p, lo
        return best_val, round(best_pred, 3)

    def quality(self) -> float:
        if self.total_weight < 3:
            return 0.0
        mean_y = self.sum_y / max(self.total_weight, 1e-12)
        pred = self.predict(int(self.sum_x / max(self.total_weight, 1e-12)))
        res = (self.last_effect - pred) ** 2
        tot = (self.last_effect - mean_y) ** 2
        if tot < 1e-12:
            return 0.5
        return max(0.0, min(1.0, 1.0 - res / tot))


def generate_cf_values(original: int, actual: int) -> List[int]:
    """生成有意义的反事实变异候选值 — 边界值/极端值/翻转值。
    不枚举全部 256 — 仅选对 fuzzing 最有信息量的 12 个。"""
    pool = {0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF}
    pool.add(original ^ 0xFF)
    pool.add(original ^ 0x01)
    pool.add(original ^ 0x80)
    pool.update(((original + d) & 0xFF) for d in (-35, -1, 1, 35))
    pool.discard(actual)
    return list(pool)[:12]


def std_dev(values: List[float]) -> float:
    """样本标准差 — bootstrap 置信区间估计的辅助函数。"""
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(max(0.0, var))


__all__ = [
    'MutationObservation', 'CounterfactualEstimate',
    'CausalByteModel',
    'generate_cf_values', 'std_dev',
    '_MAX_HISTORY', '_MIN_SAMPLES_FOR_CAUSAL',
    '_CF_CONFIDENCE_THRESHOLD', '_BOOTSTRAP_SAMPLES',
]
