"""
创建: 2024-10-11
修改:
  2025-08-03 - GP/Cholesky 委托给 gp_regression.py，评分委托给 hyper_quality.py，持久化统一
贝叶斯优化的生成管线超参自调优 — 跨会话学习最优参数组合。

问题：系统有 4 个关键可调参数（temperature, max_tokens, worker_count,
diversification_threshold），目前均通过 CONFIG 静态设定。不同模块、不同
会话的最优参数可能不同，静态设定无法适应场景变化。

现有超参优化（Optuna, Hyperopt, BayesianOptimization）聚焦 ML 模型训练，
不适用于 LLM 代码生成管线的参数整定——后者的评估函数涉及多维度质量指标
（语法正确率、架构合规率、语义收敛率、审查通过率），且每次评估需要
完整的并行生成会话，成本远高于单次模型推理。

方案：高斯过程回归 + 期望改进（Expected Improvement）采集函数。
  1. 每次会话结束后，记录 (参数向量, 综合质量分数) 作为观测点
  2. 使用 GP 回归建模参数→质量的非线性映射（RBF 核 + 白噪声）
  3. 下次会话前，用 EI 采集函数搜索参数空间，推荐最优下一组参数
  4. 探索-利用权衡由 EI 自动处理——高不确定性区域和高预测值区域
     都会被探索

参数空间定义：
  - temperature: [0.1, 0.9]（连续）
  - max_tokens: [4000, 24000]（整数，log 尺度）
  - worker_count: [2, 8]（整数）
  - diversification_threshold: [0.25, 0.65]（连续）

质量分数计算：加权组合
  score = 0.30 * syntax_pass_rate
        + 0.25 * (1 - drift_violation_rate)
        + 0.20 * (1 - convergence_rate)
        + 0.15 * (1 - quality_anomaly_rate)
        + 0.10 * review_pass_rate

与现有工作的差异：
  - Optuna/Hyperopt: ML 训练超参，评估成本低，可大规模采样
  - 本模块: LLM 管线超参，评估成本高（每次评估=完整会话），使用
    GP+EI 以最少采样次数找到最优区域
  - 跨会话持久化观测点，形成持续优化的"学习回路"
"""

from __future__ import annotations

import json
import math
import os
import time
from dataclasses import dataclass, field

# GP回归 + 线性代数委托给 engine/gp_regression.py
from parallel_deep_dev.engine.gp_regression import (
    gp_predict, expected_improvement,
)


# 参数空间定义
PARAM_BOUNDS: dict[str, tuple[float, float]] = {
    "temperature": (0.1, 0.9),
    "max_tokens": (4000.0, 24000.0),
    "worker_count": (2.0, 8.0),
    "diversification_threshold": (0.25, 0.65),
}

PARAM_INTEGER: set[str] = {"max_tokens", "worker_count"}
PARAM_LOG_SCALE: set[str] = {"max_tokens"}

from parallel_deep_dev.config import _data_dir
_OBSERVATIONS_PATH = os.path.join(_data_dir(), "hyper_observations.json")


@dataclass
class Observation:
    """单次会话的观测点。"""
    params: dict[str, float]
    score: float             # 0.0-1.0 综合质量分数
    session_id: str
    timestamp: float
    detail: dict = field(default_factory=dict)


@dataclass
class Suggestion:
    """GP+EI 推荐的下一组参数。"""
    params: dict[str, float]
    expected_improvement: float
    predicted_score: float
    uncertainty: float


class HyperOptimizer:
    """贝叶斯优化的超参自调优器。

    使用高斯过程回归（RBF核）建模参数→质量映射，
    期望改进采集函数推荐下一组参数。

    不支持外部依赖——纯 numpy-free 实现，适合嵌入到项目中。
    """

    def __init__(self):
        self._observations: list[Observation] = []
        self._load_observations()

    # 观测记录

    def record(
        self,
        params: dict[str, float],
        score: float,
        session_id: str | None = None,
        detail: dict | None = None,
    ) -> None:
        """记录一次会话的参数和结果。"""
        obs = Observation(
            params=dict(params),
            score=max(0.0, min(1.0, score)),
            session_id=session_id or f"session_{int(time.time())}",
            timestamp=time.time(),
            detail=detail or {},
        )
        self._observations.append(obs)
        self._save_observations()

    # 参数推荐

    def suggest(self, n_random_restarts: int = 20) -> Suggestion | None:
        """使用 GP+EI 推荐下一组最优参数。

        若观测点不足 3 个，返回参数空间中心的随机扰动。
        若已有足够观测，使用 GP 回归 + EI 最大化搜索。"""
        if len(self._observations) < 3:
            return self._random_suggestion()

        # 提取训练数据
        X = [self._params_to_vector(o.params) for o in self._observations]
        y = [o.score for o in self._observations]

        # GP 超参
        length_scale = 0.3
        noise = 0.01

        # 多起点随机搜索 EI 最大值
        best_ei = -1.0
        best_params: dict[str, float] | None = None
        best_pred = 0.0
        best_uncertainty = 0.0

        for _ in range(n_random_restarts):
            candidate_vec = self._random_vector()
            pred_mean, pred_var = gp_predict(
                candidate_vec, X, y, length_scale, noise,
            )
            pred_std = math.sqrt(max(pred_var, 1e-12))
            y_best = max(y)

            # Expected Improvement
            ei = expected_improvement(pred_mean, pred_std, y_best)

            if ei > best_ei:
                best_ei = ei
                best_params = self._vector_to_params(candidate_vec)
                best_pred = pred_mean
                best_uncertainty = pred_std

        if best_params is None:
            return self._random_suggestion()

        return Suggestion(
            params=best_params,
            expected_improvement=round(best_ei, 4),
            predicted_score=round(best_pred, 3),
            uncertainty=round(best_uncertainty, 3),
        )

    def best_so_far(self) -> Observation | None:
        """返回到目前为止得分最高的观测。"""
        if not self._observations:
            return None
        return max(self._observations, key=lambda o: o.score)

    # 统计

    def stats(self) -> dict:
        if not self._observations:
            return {"observations": 0, "best_score": None}
        scores = [o.score for o in self._observations]
        avg = sum(scores) / len(scores)
        return {
            "observations": len(self._observations),
            "best_score": round(max(scores), 3),
            "avg_score": round(avg, 3),
            "improvement_trend": (
                "improving" if len(scores) >= 3
                and scores[-1] > scores[0] + 0.05
                else "stable" if len(scores) >= 3
                else "insufficient_data"
            ),
        }

    # 持久化

    def _save_observations(self) -> None:
        try:
            payload = {
                "observations": [
                    {
                        "params": o.params, "score": o.score,
                        "session_id": o.session_id,
                        "timestamp": o.timestamp, "detail": o.detail,
                    }
                    for o in self._observations
                ],
            }
            with open(_OBSERVATIONS_PATH, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def _load_observations(self) -> None:
        if not os.path.isfile(_OBSERVATIONS_PATH):
            return
        try:
            with open(_OBSERVATIONS_PATH, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError):
            return
        for d in payload.get("observations", []):
            self._observations.append(Observation(
                params=d["params"], score=d["score"],
                session_id=d.get("session_id", ""),
                timestamp=d.get("timestamp", 0.0),
                detail=d.get("detail", {}),
            ))

    # 内部

    def _params_to_vector(self, params: dict[str, float]) -> list[float]:
        vec: list[float] = []
        for name, (lo, hi) in PARAM_BOUNDS.items():
            val = params.get(name, (lo + hi) / 2)
            if name in PARAM_LOG_SCALE:
                val = (math.log(val) - math.log(lo)) / (math.log(hi) - math.log(lo))
            else:
                val = (val - lo) / (hi - lo)
            vec.append(max(0.0, min(1.0, val)))
        return vec

    def _vector_to_params(self, vec: list[float]) -> dict[str, float]:
        params: dict[str, float] = {}
        for i, (name, (lo, hi)) in enumerate(PARAM_BOUNDS.items()):
            val = vec[i] if i < len(vec) else 0.5
            if name in PARAM_LOG_SCALE:
                val = math.exp(val * (math.log(hi) - math.log(lo)) + math.log(lo))
            else:
                val = lo + val * (hi - lo)
            if name in PARAM_INTEGER:
                val = round(val)
            params[name] = max(lo, min(hi, val))
        return params

    def _random_vector(self) -> list[float]:
        import random
        return [random.random() for _ in PARAM_BOUNDS]

    def _random_suggestion(self) -> Suggestion:
        import random
        params: dict[str, float] = {}
        for name, (lo, hi) in PARAM_BOUNDS.items():
            if name in PARAM_INTEGER:
                params[name] = float(random.randint(int(lo), int(hi)))
            else:
                params[name] = lo + random.random() * (hi - lo)
        return Suggestion(
            params=params, expected_improvement=0.0,
            predicted_score=0.5, uncertainty=1.0,
        )


# GP回归/线性代数/正态分布委托给 engine/gp_regression.py

# 便捷集成入口

# 质量评分 + 会话记录委托给 engine/hyper_quality.py
