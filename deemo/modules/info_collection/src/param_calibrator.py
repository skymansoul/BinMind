"""
在线参数自校准 (OPC)。

审计发现: 5 个模块中约 200 个手工参数标注为"基于经验估计",
无标定来源、无可复现调参流程。专利审查会要求提供参数推导过程
和敏感度分析。本模块提供数据驱动的在线校准机制, 解决此问题。

方法: 对 Gain Matrix 和 Entropy Profile 的每个参数维护 EMA + EMA 方差,
每次采集完成后用观测结果更新。校准值可在会话间持久化 (JSON)。

与 OODC (在线结果驱动校准) 的差异: OODC 校准的是采集器选择策略
(Thompson 采样的 Beta 后验), 本质是 Bandit 的 reward 建模;
本模块校准的是调度器和深度控制器的静态参数表, 本质是系统配置
的超参数优化。两者互补: OODC 决定 "选哪个", OPC 决定 "配置是否准确"。
"""

from __future__ import annotations

import json
import math
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .intent_route import IntentCategory


@dataclass
class RunningEstimate:
    """EMA 运行估计: 均值 + 方差。"""
    mean: float = 0.5
    var: float = 0.01
    n_updates: int = 0
    initial_value: float = 0.5  # 保留初始值用于回退

    def update(self, observed: float, alpha: float = 0.10) -> None:
        delta = observed - self.mean
        self.mean += alpha * delta
        self.var = (1 - alpha) * (self.var + alpha * delta * delta)
        self.n_updates += 1

    @property
    def std(self) -> float:
        return math.sqrt(max(0, self.var))

    @property
    def converged(self) -> bool:
        """方差低于阈值 → 估计已收敛到稳态。"""
        return self.var < 0.005 and self.n_updates >= 20


@dataclass
class CalibrationState:
    """参数校准的完整状态。"""
    # (action_id, intent_value) → gain 的 EMA 估计
    gain_estimates: Dict[Tuple[str, str], RunningEstimate] = field(default_factory=dict)
    # (intent_value) → (base_entropy, decay_rate) 的 EMA 估计
    entropy_base: Dict[str, RunningEstimate] = field(default_factory=dict)
    entropy_decay: Dict[str, RunningEstimate] = field(default_factory=dict)
    # 元数据
    total_observations: int = 0
    last_persist_time: float = 0.0


class ParameterCalibrator:
    """
    在线参数校准器。

    不替代静态参数表, 而是在其基础上做增量修正:
    calibrated = (1 - λ) * static + λ * ema_estimate
    其中 λ = min(0.8, n_updates / 30) —— 观测越多, EMA 权重越大,
    但静态先验始终保留至少 20% 的权重 (防止过拟合到短期噪声)。
    """

    def __init__(self, state: Optional[CalibrationState] = None):
        self._state = state or CalibrationState()

    # Gain Matrix 校准

    def observe_gain(
        self, action_id: str, intent: IntentCategory,
        observed_utility: float,  # 0-1, 采集结果的有用程度
    ) -> None:
        """观测一次采集结果, 更新对应 (action, intent) 的 gain 估计。"""
        key = (action_id, intent.value)
        if key not in self._state.gain_estimates:
            self._state.gain_estimates[key] = RunningEstimate(initial_value=0.5)
        self._state.gain_estimates[key].update(observed_utility)
        self._state.total_observations += 1

    def get_calibrated_gain(
        self, action_id: str, intent: IntentCategory, static_gain: float = 0.5,
    ) -> float:
        """获取校准后的 gain 值 = 静态先验 + EMA 修正。"""
        key = (action_id, intent.value)
        est = self._state.gain_estimates.get(key)
        if est is None or est.n_updates < 5:
            return static_gain
        lam = min(0.8, est.n_updates / 30.0)
        return round((1 - lam) * static_gain + lam * est.mean, 4)

    def get_gain_confidence(self, action_id: str, intent: IntentCategory) -> float:
        """获取 gain 估计的置信度 (1 - 归一化标准差)。"""
        key = (action_id, intent.value)
        est = self._state.gain_estimates.get(key)
        if est is None:
            return 0.0
        return round(1.0 - min(0.95, est.std), 4)

    # Entropy Profile 校准

    def observe_entropy(
        self, intent: IntentCategory,
        observed_uniqueness: float,   # 唯一条目 / 总条目, [0, 1]
        observed_items: int,          # 总条目数
        depth_level: int,             # 0=shallow, 1=standard, 2=deep
    ) -> None:
        """
        从一次采集结果中观测信息增量, 更新该类别的熵参数。

        observed_uniqueness: 高 → 采集仍在发现新信息 → 基准熵应提高
        observed_items: 条目多但唯一性低 → 衰减率应提高 (更快饱和)
        depth_level: 深度越大发现新信息的难度越大 → 衰减率修正
        """
        iv = intent.value
        if iv not in self._state.entropy_base:
            self._state.entropy_base[iv] = RunningEstimate(initial_value=3.5)
            self._state.entropy_decay[iv] = RunningEstimate(initial_value=0.50)

        # 基准熵更新: 唯一性高 → 熵向上修正
        self._state.entropy_base[iv].update(observed_uniqueness * 5.0 + 1.0)

        # 衰减率更新: 深度越大唯一性越低 → 衰减率向下修正 (慢衰减)
        depth_factor = 1.0 / (1.0 + 0.3 * depth_level)
        self._state.entropy_decay[iv].update(
            (1.0 - observed_uniqueness) * depth_factor + 0.1,
        )

        self._state.total_observations += 1

    def get_calibrated_entropy_base(
        self, intent: IntentCategory, static_base: float = 3.2,
    ) -> float:
        est = self._state.entropy_base.get(intent.value)
        if est is None or est.n_updates < 5:
            return static_base
        lam = min(0.7, est.n_updates / 25.0)
        return round((1 - lam) * static_base + lam * est.mean, 4)

    def get_calibrated_decay_rate(
        self, intent: IntentCategory, static_decay: float = 0.50,
    ) -> float:
        est = self._state.entropy_decay.get(intent.value)
        if est is None or est.n_updates < 5:
            return static_decay
        lam = min(0.7, est.n_updates / 25.0)
        return round((1 - lam) * static_decay + lam * est.mean, 4)

    # 持久化

    def save(self, filepath: str) -> None:
        """将校准状态导出为 JSON。"""
        data: Dict[str, Any] = {
            "total_observations": self._state.total_observations,
            "gain_estimates": {},
            "entropy_base": {},
            "entropy_decay": {},
        }
        for (aid, iv), est in self._state.gain_estimates.items():
            data["gain_estimates"][f"{aid}|{iv}"] = {
                "mean": est.mean, "var": est.var,
                "n_updates": est.n_updates, "initial": est.initial_value,
            }
        for iv, est in self._state.entropy_base.items():
            data["entropy_base"][iv] = {
                "mean": est.mean, "var": est.var,
                "n_updates": est.n_updates, "initial": est.initial_value,
            }
        for iv, est in self._state.entropy_decay.items():
            data["entropy_decay"][iv] = {
                "mean": est.mean, "var": est.var,
                "n_updates": est.n_updates, "initial": est.initial_value,
            }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        self._state.last_persist_time = time.time()

    def load(self, filepath: str) -> bool:
        """从 JSON 恢复校准状态。"""
        if not os.path.exists(filepath):
            return False
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        self._state.total_observations = data.get("total_observations", 0)
        for key_str, val in data.get("gain_estimates", {}).items():
            aid, iv = key_str.split("|", 1)
            self._state.gain_estimates[(aid, iv)] = RunningEstimate(
                mean=val["mean"], var=val["var"],
                n_updates=val["n_updates"], initial_value=val["initial"],
            )
        for iv, val in data.get("entropy_base", {}).items():
            self._state.entropy_base[iv] = RunningEstimate(
                mean=val["mean"], var=val["var"],
                n_updates=val["n_updates"], initial_value=val["initial"],
            )
        for iv, val in data.get("entropy_decay", {}).items():
            self._state.entropy_decay[iv] = RunningEstimate(
                mean=val["mean"], var=val["var"],
                n_updates=val["n_updates"], initial_value=val["initial"],
            )
        self._state.last_persist_time = time.time()
        return True

    # 查询

    def convergence_report(self) -> Dict[str, Any]:
        """返回当前校准的收敛状态报告。"""
        gain_total = len(self._state.gain_estimates)
        gain_converged = sum(1 for e in self._state.gain_estimates.values() if e.converged)
        entropy_total = len(self._state.entropy_base)
        entropy_converged = sum(1 for e in self._state.entropy_base.values() if e.converged)
        return {
            "total_observations": self._state.total_observations,
            "gain_estimates": gain_total,
            "gain_converged": gain_converged,
            "entropy_estimates": entropy_total,
            "entropy_converged": entropy_converged,
            "overall_ready": (
                self._state.total_observations >= 100
                and gain_converged >= max(1, gain_total // 2)
            ),
        }

    @property
    def observation_count(self) -> int:
        return self._state.total_observations

    def reset(self) -> None:
        self._state = CalibrationState()


__all__ = [
    "RunningEstimate",
    "CalibrationState",
    "ParameterCalibrator",
]
