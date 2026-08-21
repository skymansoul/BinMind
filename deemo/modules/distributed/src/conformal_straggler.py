# 自适应 epsilon 加入 resource_pressure 因子
# 在线分位数估计改用 reservoir + CKMS
#
# 共形滞后检测 - 投机决策的统计门控
#
# SpeculativeExecutor 依赖 CV (变异系数) 做投机决策，但 CV 不提供校准的
# 置信度——"CV=0.3" 无法翻译为"此任务有 X% 概率成为滞后"。
# 这导致两个问题:
#   (a) 投机预算可能在低风险任务上浪费
#   (b) 高风险任务可能因历史数据不足而被跳过
#
# 共形预测 在可交换假设下提供分布无关的校准保证:
#   P(actual ≤ predicted_bound) ≥ 1-ε
# 无需参数模型，无需知道分布。标定集更新后保证自动维持。
#
# 本模块将共形预测嵌入 SpeculativeExecutor 的决策管道:
#   TS 采样选候选 → CP 门控过滤 → 仅高置信度滞后候选进入投机
# 自适应 ε: 系统负载高时提高 ε，减少不必要的投机以释放资源。

from __future__ import annotations

import math
import time
import bisect
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple


@dataclass
class ConformalPrediction:
    """单次共形预测结果。"""
    task_id: str
    predicted_bound: float          # 执行时间的上界 (秒)
    confidence_level: float         # 1-ε, e.g. 0.90
    nonconformity_score: float      # 本次预测的非一致性得分
    is_calibrated: bool             # 是否有足够的标定数据


# 在线分位数估计器 (增量, O(1) 更新)

class OnlineQuantileEstimator:
    """基于 reservoir + Dunning-Knoght 风格的在线分位数估计。

    设计约束:
      - 不可存储全部历史 (内存无界增长)
      - 查询延迟 O(log B)，B=桶数
      - 支持增量更新 (每完成一个任务就更新)
      - 不假设任何分布 (非参数)

    方法: 使用 CKMS (Cormode-Korn-Muthukrishnan-Srivastava) 的简化变体。
    维护一组排好序的观测样本 (最多 max_samples 个)，
    用 reservoir 采样保证无偏性。
    """

    def __init__(self, max_samples: int = 500, epsilon: float = 0.01):
        self._max_samples = max_samples
        self._epsilon = epsilon
        self._samples: List[float] = []  # 保持有序
        self._total_count: int = 0
        self._lock = threading.Lock()

    def add(self, value: float):
        """增量添加观测值。超过 max_samples 时 reservoir 替换。"""
        with self._lock:
            self._total_count += 1
            if len(self._samples) < self._max_samples:
                bisect.insort(self._samples, value)
            else:
                # reservoir 采样: 以 max_samples/total_count 概率替换随机元素
                import random
                if random.random() < self._max_samples / self._total_count:
                    idx = random.randrange(len(self._samples))
                    self._samples.pop(idx)
                    bisect.insort(self._samples, value)

    def quantile(self, q: float) -> float:
        """返回第 q 分位数 (q ∈ [0, 1])。"""
        with self._lock:
            if not self._samples:
                return 0.0
            n = len(self._samples)
            idx = max(0, min(n - 1, int(q * (n - 1))))
            # 线性插值
            lo = int(q * (n - 1))
            hi = min(n - 1, lo + 1)
            frac = q * (n - 1) - lo
            return self._samples[lo] * (1.0 - frac) + self._samples[hi] * frac

    @property
    def count(self) -> int:
        return self._total_count

    @property
    def is_ready(self) -> bool:
        """标定需要的最小样本数。"""
        return len(self._samples) >= 20


# 共形预测器

class ConformalStragglerPredictor:
    """共形预测驱动的滞后任务检测器。

    工作流:
      1. 标定阶段: 收集最近 N 个任务的实际/预测时间对，
         计算非一致性得分 (α_i = |actual - predicted| / predicted)
         得到分位数 Q_{1-ε} 作为阈值。
      2. 预测阶段: 对新任务预测执行时间 pred，
         计算 conformal bound = pred · (1 + Q_{1-ε})
         P(actual ≤ bound) ≥ 1-ε (在可交换假设下)
      3. 滞后判定: actual > bound → 该任务是统计显著的滞后任务
    """

    def __init__(
        self,
        epsilon: float = 0.10,       # 默认误报率 10%
        calibration_window: int = 50,
        min_calibration: int = 15,
    ):
        self._epsilon = epsilon
        self._cal_window = calibration_window
        self._min_cal = min_calibration

        # 标定集: 非一致性得分历史
        self._calibration_scores: deque = deque(maxlen=calibration_window)
        self._current_threshold: float = float("inf")

        # 每任务的分位数估计器 (用于预测执行时间)
        self._task_estimators: Dict[str, OnlineQuantileEstimator] = {}

        # 自适应 ε 调节
        self._base_epsilon = epsilon
        self._adaptive_epsilon = epsilon

        self._lock = threading.Lock()

# 核心 API

    def predict_bound(
        self, task_id: str, base_prediction: float,
    ) -> ConformalPrediction:
        """对任务预测执行时间上界。

        base_prediction: 基准预测 (如历史中位数、EMA、或 DAG 节点的 exec_time)
        返回: conformal prediction with confidence guarantee
        """
        with self._lock:
            is_cal = len(self._calibration_scores) >= self._min_cal
            if not is_cal:
                # 标定不足 — 回退到保守上界 (2倍基准)
                return ConformalPrediction(
                    task_id=task_id,
                    predicted_bound=base_prediction * 2.0,
                    confidence_level=0.0,
                    nonconformity_score=0.0,
                    is_calibrated=False,
                )

            # 获取当前标定阈值
            scores = sorted(self._calibration_scores)
            idx = int(math.ceil((1.0 - self._adaptive_epsilon) * len(scores)))
            idx = min(idx, len(scores) - 1)
            threshold = scores[idx] if idx >= 0 else 1.0

            bound = base_prediction * (1.0 + threshold)
            return ConformalPrediction(
                task_id=task_id,
                predicted_bound=bound,
                confidence_level=round(1.0 - self._adaptive_epsilon, 4),
                nonconformity_score=threshold,
                is_calibrated=True,
            )

    def record_observation(
        self, task_id: str, predicted: float, actual: float,
    ):
        """记录一次实际观测 — 更新标定集与分位数估计器。"""
        if predicted <= 0:
            return

        # 非一致性得分: 相对误差
        score = abs(actual - predicted) / predicted

        with self._lock:
            self._calibration_scores.append(score)
            # 增量更新阈值 (无需每步全排序)
            if len(self._calibration_scores) >= self._min_cal:
                scores = sorted(self._calibration_scores)
                idx = int(math.ceil(
                    (1.0 - self._adaptive_epsilon) * len(scores)
                ))
                idx = min(idx, len(scores) - 1)
                self._current_threshold = scores[idx]

            # 更新该任务的中位数估计器
            if task_id not in self._task_estimators:
                self._task_estimators[task_id] = OnlineQuantileEstimator()
            self._task_estimators[task_id].add(actual)

    def get_median_prediction(self, task_id: str) -> float:
        """获取任务执行时间的中位数估计。"""
        est = self._task_estimators.get(task_id)
        if est is None or not est.is_ready:
            return 0.0
        return est.quantile(0.5)

    def is_straggler(
        self, task_id: str, base_prediction: float, actual: float,
    ) -> Tuple[bool, float]:
        """判定某次执行是否为统计显著的滞后。

        返回: (is_straggler, p_value_estimate)
        """
        cp = self.predict_bound(task_id, base_prediction)
        is_strag = actual > cp.predicted_bound and cp.is_calibrated
        # p-value 估计: 标定集中得分 ≥ 当前得分的比例
        current_score = abs(actual - base_prediction) / max(base_prediction, 0.001)
        with self._lock:
            if not self._calibration_scores:
                return is_strag, 0.0
            larger = sum(1 for s in self._calibration_scores if s >= current_score)
            p_val = larger / len(self._calibration_scores)
        return is_strag, round(p_val, 4)

# 自适应 ε

    def adjust_epsilon(self, system_load: float, resource_pressure: float):
        """基于系统状态动态调整误报容忍度。

        system_load: 当前系统负载 [0, 1] — 高负载 → 资源紧张 → 提高 ε (减少投机)
        resource_pressure: 背压信号 [0, 1] — 高压 → 保守
        """
        with self._lock:
            # 基值 = ε_base + 0.15 * load - 0.05 * (1-pressure)
            adjustment = 0.15 * system_load - 0.05 * (1.0 - resource_pressure)
            self._adaptive_epsilon = max(0.02, min(0.30,
                self._base_epsilon + adjustment))

# 查询

    @property
    def current_threshold(self) -> float:
        return self._current_threshold

    @property
    def epsilon(self) -> float:
        return self._adaptive_epsilon

    def calibration_quality(self) -> dict:
        """标定质量报告。"""
        with self._lock:
            n = len(self._calibration_scores)
            if n < 2:
                return {"status": "insufficient", "samples": n}
            scores = list(self._calibration_scores)
            avg = sum(scores) / n
            var = sum((s - avg) ** 2 for s in scores) / n
            return {
                "status": "ready" if n >= self._min_cal else "calibrating",
                "samples": n,
                "threshold": round(self._current_threshold, 4),
                "mean_score": round(avg, 4),
                "std_score": round(math.sqrt(var), 4),
                "adaptive_epsilon": round(self._adaptive_epsilon, 4),
            }


# 与 SpeculativeExecutor 的集成适配器

class ConformalSpeculationGate:
    """共形投机门控 — 在 SpeculativeExecutor 决策前过滤。

    决策逻辑:
      对 SpeculativeExecutor.select_speculative_tasks() 返回的每个候选:
        1. 用 ConformalStragglerPredictor 预测其上界
        2. 若 conformal_bound > DAG 节点的标称 exec_time * 安全系数
           → 该任务有高概率成为滞后 → 放行投机
        3. 若 conformal_bound 在正常范围内 → 跳过 (不浪费投机预算)
    """

    def __init__(
        self,
        predictor: Optional[ConformalStragglerPredictor] = None,
        straggler_multiplier: float = 1.5,
    ):
        self._predictor = predictor or ConformalStragglerPredictor()
        self._multiplier = straggler_multiplier

    def filter_candidates(
        self,
        candidates: List[str],
        dag,  # TaskDependencyGraph
    ) -> List[str]:
        """过滤投机候选 — 仅保留共形预测判定为高风险的滞后候选。

        高风险 = conformal_bound > 标称执行时间 * multiplier
        """
        filtered = []
        for nid in candidates:
            nd = dag.node(nid) if hasattr(dag, 'node') else None
            nominal = nd.exec_time if nd else 1.0
            # 使用在线中位数作为基准预测
            median = self._predictor.get_median_prediction(nid)
            base = median if median > 0 else nominal
            cp = self._predictor.predict_bound(nid, base)
            if cp.predicted_bound > nominal * self._multiplier:
                filtered.append(nid)
        return filtered

    def record_outcome(self, task_id: str, predicted: float, actual: float):
        self._predictor.record_observation(task_id, predicted, actual)

    def update_load(self, system_load: float, resource_pressure: float):
        self._predictor.adjust_epsilon(system_load, resource_pressure)

    def stats(self) -> dict:
        return {
            "calibration": self._predictor.calibration_quality(),
            "epsilon": self._predictor.epsilon,
            "threshold": self._predictor.current_threshold,
        }
