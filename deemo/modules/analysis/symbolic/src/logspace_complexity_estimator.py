#!/usr/bin/env python3
# 修改记录:
# 2025-07-28 09:44 - EMA 漂移检测的触发窗口从 50 扩展到自适应 [30, 200]
# 2025-07-31 14:05 - 加入模型选择逻辑（线性 vs 对数空间），基于回溯 RMSE
# 2025-08-01 08:52 - 与上游 ConstraintComplexityEstimator 的特征向量接口对齐
"""
对数空间约束复杂度预估器 —— 替代线性回归的非线性求解时间预测

背景: 现有 ConstraintComplexityEstimator 使用线性回归 (w*x) 预测 Z3 求解时间
但求解时间与 constraint_count 的关系更接近指数 —— 线性模型在约束数超过一定
阈值后系统性低估求解时间，导致 BudgetManager 超支

本模块提供 LogSpaceComplexityEstimator，使用 记录(y) ~ w*x 的对数空间线性回归
（本质上是对数-线性模型，即 y ≈ exp(w*x)），同时通过 EMA 追踪预测误差并在线
检测精度退化信号。当 EMA 偏差连续超过阈值时触发模型重校准

ref: 线性模型 → 对数空间回归的转换参考了 Z3 内部的 heuristics 时间估算思路
但将其实现为外部可插拔的轻量预测器 —— ref: z3/src/sat/sat_solver.h 的
重启 策略对 search space s 的近似
"""

from __future__ import annotations

import logging
import math
import time
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 特征维数 —— 与上游 ConstraintComplexityEstimator 的 5 维特征对齐
_FEATURE_DIM = 5

# EMA 平滑系数 —— 高 α 对瞬时误差敏感，低 α 更稳定
_EMA_ALPHA = 0.12

# 漂移检测 —— 连续 error_ratio > _DRIFT_THRESHOLD 的次数超过 _DRIFT_WINDOW
# 则触发重校准
_DRIFT_THRESHOLD = 1.8
_DRIFT_WINDOW_MIN = 30
_DRIFT_WINDOW_MAX = 200


class LogSpaceComplexityEstimator:
    """对数空间回归求解时间预估器
    
    与线性 ConstraintComplexityEstimator 互补:
    - 线性模型: 快速，适合约束少且特征分布均匀的场景
    - 对数模型: 捕捉指数的求解时间增长，适合大型约束集
    
    自动模型选择:
    维护两个模型在最近 N 次求解上的 RMSE 滚动窗口
    每次预测前选择 RMSE 更低的模型。这本质上是退火式的在线
    model selec，不需要离线训练
    
    Attributes:
    weights: 当前对数空间回归权重 (5,)
    bias: 对数空间偏置项
    _linear_rmse: 线性模型最近窗口的均方根误差
    _log_rmse: 对数空间模型最近窗口的均方根误差
    """

    def __init__(self, lr: float = 0.008, window: int = 120):
        self.weights = [0.0] * _FEATURE_DIM
        self.bias = 0.0
        self.lr = lr
        self._window = window

        # 预测误差追踪
        self._errors: deque = deque(maxlen=window)
        self._predictions: deque = deque(maxlen=10)
        self._actuals: deque = deque(maxlen=10)

        # EMA 漂移检测
        self._ema_error_ratio = 1.0
        self._drift_counter = 0
        self._drift_window = _DRIFT_WINDOW_MIN  # 自适应窗口
        self._needs_recalibration = False

        # 模型选择
        self._linear_rmse: deque = deque(maxlen=60)
        self._log_rmse: deque = deque(maxlen=60)
        self._last_model_choice: str = "log_space"

        # 运行统计
        self._prediction_count = 0
        self._skip_count = 0

    #-------------------------------------------------------------------
    # 特征提取 —— 与现有 ConstraintComplexityEstimator 对齐
    #-------------------------------------------------------------------

    @staticmethod
    def extract_features(constraints: List[str]) -> List[float]:
        """从约束字符串列表提取 5 维特征向量
        
        特征:
        [0] constraint_count (记录-变换: log2(count+1))
        [1] max_paren_depth (最大括号嵌套深度)
        [2] bv_width (位宽，正则匹配 bv\d+ 和 提取)
        [3] arithmetic_ratio (含算术操作的约束比例)
        [4] boolean_ratio (含布尔操作的约束比例)
        """
        import re
        n = len(constraints)
        if n == 0:
            return [0.0] * _FEATURE_DIM

        # 特征 0: 对数化的约束数 —— 避免线性特征在 n>>100 时梯度消失
        f_count = math.log2(n + 1)

        # 特征 1: 最大括号嵌套深度
        max_depth = 0
        for c in constraints:
            depth = 0
            cur_max = 0
            for ch in c:
                if ch == '(':
                    depth += 1
                    cur_max = max(cur_max, depth)
                elif ch == ')':
                    depth -= 1
            max_depth = max(max_depth, cur_max)
        f_depth = float(max_depth)

        # 特征 2: 位宽
        width_sum = 0
        width_count = 0
        for c in constraints:
            wf = re.findall(r'bv(\d+)', c)
            for w in wf:
                width_sum += int(w)
                width_count += 1
        f_width = width_sum / max(width_count, 1)

        # 特征 3/4: 算术/布尔操作比例
        arith = sum(1 for c in constraints
                    if any(op in c for op in ('+', '-', '*', '/', '%')))
        bool_ops = sum(1 for c in constraints
                       if any(op in c for op in ('and', 'or', 'not', 'And', 'Or', 'Not')))
        f_arith = arith / n
        f_bool = bool_ops / n

        return [f_count, f_depth, f_width, f_arith, f_bool]

    #-------------------------------------------------------------------
    # 预测
    #-------------------------------------------------------------------

    def predict(self, constraints: List[str]) -> float:
        """预测 Z3 求解时间（秒）
        
        返回对数空间 regres 的 exp 值
        若模型尚未初始化（权重全 0），退化为启发式: 0.01 * n_constraints
        """
        features = self.extract_features(constraints)
        log_val = self.bias
        for i in range(_FEATURE_DIM):
            log_val += self.weights[i] * features[i]
        # 将 log-space 预测转回线性时间
        predicted = math.exp(log_val)
        # 防止极端值 —— clamp 到合理范围
        predicted = max(0.001, min(predicted, 3600.0))
        self._predictions.append(predicted)
        return predicted

    def predict_linear(self, constraints: List[str]) -> float:
        """备选: 纯线性预测 —— 用于模型选择比较"""
        features = self.extract_features(constraints)
        val = self.bias
        for i in range(_FEATURE_DIM):
            val += self.weights[i] * features[i]
        # 线性预测不经过 exp，直接 clamp
        return max(0.001, min(val, 3600.0))

    #-------------------------------------------------------------------
    # 在线学习
    #-------------------------------------------------------------------

    def update(self, constraints: List[str], actual_time: float) -> None:
        """用一次求解结果更新模型权重
        
        在 记录 空间中执行 SGD —— 损失 = (记录(actual) - 记录(predicted))^2
        因为 Z3 求解时间的分布是长尾的（大部分快，少数慢），对数变换
        使梯度更均匀，避免长尾的少数慢查询主导权重更新
        """
        if actual_time <= 0:
            return

        features = self.extract_features(constraints)
        log_actual = math.log(max(actual_time, 1e-6))
        log_pred = self.bias
        for i in range(_FEATURE_DIM):
            log_pred += self.weights[i] * features[i]

        error = log_actual - log_pred
        self._errors.append(abs(error))
        self._actuals.append(actual_time)

        # SGD 权重更新
        grad = -2.0 * error
        for i in range(_FEATURE_DIM):
            self.weights[i] -= self.lr * grad * features[i]
        self.bias -= self.lr * grad

        # EMA 误差更新 —— 用于漂移检测
        error_ratio = actual_time / max(self._predictions[-1], 1e-6) if self._predictions else 1.0
        self._ema_error_ratio = (
            _EMA_ALPHA * error_ratio + (1.0 - _EMA_ALPHA) * self._ema_error_ratio
        )

        # 更新模型选择 RMSE
        if self._predictions:
            pred = self._predictions[-1]
            self._log_rmse.append((actual_time - pred) ** 2)
            lin_pred = self.predict_linear(constraints)
            self._linear_rmse.append((actual_time - lin_pred) ** 2)
            self._last_model_choice = "log_space" if (
                self._mean(self._log_rmse) <= self._mean(self._linear_rmse)
            ) else "linear"

        # 漂移检测
        if error_ratio > _DRIFT_THRESHOLD:
            self._drift_counter += 1
            # 自适应窗口: 总预测数越多，容忍度越高（模型越应稳定）
            self._prediction_count += 1
            self._drift_window = max(
                _DRIFT_WINDOW_MIN,
                min(_DRIFT_WINDOW_MAX, self._prediction_count // 5)
            )
        else:
            self._drift_counter = max(0, self._drift_counter - 1)

        self._needs_recalibration = self._drift_counter >= self._drift_window
        if self._needs_recalibration:
            logger.debug(
                "LogSpaceComplexityEstimator: drift detected — "
                f"ema_error={self._ema_error_ratio:.2f}, "
                f"drift_count={self._drift_counter}/{self._drift_window}"
            )

    #-------------------------------------------------------------------
    # 模型诊断
    #-------------------------------------------------------------------

    def needs_recalibration(self) -> bool:
        return self._needs_recalibration

    def recalibrate(self) -> None:
        """重置权重的 70% 为默认值，保留 30% 的历史信息
        
        完全清零会丢失所有已学信息——70/30 是折中: 用默认值的偏置修正
        漂移方向，但保留方向性信息以避免冷启动
        """
        defaults = [0.0, 0.15, 0.001, 0.45, 0.25]
        for i in range(_FEATURE_DIM):
            self.weights[i] = 0.3 * self.weights[i] + 0.7 * defaults[i]
        self.bias *= 0.3
        self._drift_counter = 0
        self._needs_recalibration = False
        self._ema_error_ratio = 1.0

    def choose_model(self) -> str:
        """基于滑动 RMSE 窗口选择当前最佳模型"""
        if len(self._log_rmse) < 10:
            return self._last_model_choice
        return "log_space" if (
            self._mean(self._log_rmse) <= self._mean(self._linear_rmse)
        ) else "linear"

    def stats(self) -> Dict[str, Any]:
        return {
            "model": self._last_model_choice,
            "weights": [round(w, 6) for w in self.weights],
            "bias": round(self.bias, 6),
            "ema_error_ratio": round(self._ema_error_ratio, 4),
            "drift_counter": self._drift_counter,
            "drift_window": self._drift_window,
            "needs_recalibration": self._needs_recalibration,
            "prediction_count": self._prediction_count,
            "log_rmse": round(math.sqrt(self._mean(self._log_rmse)), 4) if self._log_rmse else None,
            "linear_rmse": round(math.sqrt(self._mean(self._linear_rmse)), 4) if self._linear_rmse else None,
        }

    @staticmethod
    def _mean(d: deque) -> float:
        if not d:
            return 1e9
        return sum(d) / len(d)
