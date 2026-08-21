# coding: utf-8
# 增加 max_evaluations 上限 (默认100), Cholesky 数值稳定性
"""
贝叶斯优化钩子参数调优 - GP 代理模型 + EI 采集, 面向管道执行的参数搜索.

与 scikit-optimize/Optuna 的差异: 目标函数是管道执行质量 (非 ML 精度),
参数空间是钩子语义参数 (分析深度/阈值/算法变体). 纯 Python 无外部依赖.
O(n^3) Cholesky 分解限制评估点数 <= max_evaluations (默认 100).
"""

import math
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class ParamDef:
    """单个可调参数的定义."""
    name: str
    kind: str = 'continuous'  # 'continuous' | 'integer' | 'categorical'
    low: float = 0.0
    high: float = 1.0
    choices: List[Any] = field(default_factory=list)  # categorical 的可选值


@dataclass
class Trial:
    """一次评估试验的记录."""
    params: Dict[str, Any]      # 参数名 → 值
    quality: float              # 产出质量 [0, 1]
    wall_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)


class GaussianProcess:
    """简化高斯过程回归 - RBF kernel + 噪声 + Cholesky 分解.

    参考: Rasmussen & Williams, Algorithm 2.1.
    """

    def __init__(self, length_scale: float = 1.0, signal_var: float = 1.0,
                 noise_var: float = 1e-4):
        self._ls = length_scale
        self._sf = signal_var
        self._sn = noise_var
        self._X: List[List[float]] = []   # 训练输入
        self._y: List[float] = []          # 训练目标
        self._L = None                      # Cholesky 分解
        self._alpha = None                  # K⁻¹y

    def fit(self, X: List[List[float]], y: List[float]):
        self._X = [list(x) for x in X]
        self._y = list(y)
        n = len(X)
        K = [[self._kernel(X[i], X[j]) for j in range(n)] for i in range(n)]
        for i in range(n):
            K[i][i] += self._sn
        # Cholesky: K = L Lᵀ
        self._L = self._cholesky(K)
        # α = K⁻¹y (通过两次三角求解)
        self._alpha = self._solve_tri(self._L, self._y)

    def predict(self, x: List[float]) -> Tuple[float, float]:
        """返回 (mean, variance) 的后验预测."""
        if not self._X or self._L is None:
            return 0.5, 1.0
        k_star = [self._kernel(x, xi) for xi in self._X]
        # v = L⁻¹k*
        v = self._forward_sub(self._L, k_star)
        # mean = k*ᵀ α
        mean = sum(k_star[i] * self._alpha[i] for i in range(len(k_star)))
        # var = k(x,x) - vᵀv
        var = self._kernel(x, x) - sum(vi * vi for vi in v)
        return mean, max(1e-9, var)

    def _kernel(self, a: List[float], b: List[float]) -> float:
        sq_dist = sum((ai - bi) ** 2 for ai, bi in zip(a, b))
        return self._sf * math.exp(-0.5 * sq_dist / (self._ls ** 2))

    @staticmethod
    def _cholesky(A: List[List[float]]) -> List[List[float]]:
        n = len(A)
        L = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(i + 1):
                s = sum(L[i][k] * L[j][k] for k in range(j))
                if i == j:
                    L[i][j] = math.sqrt(max(1e-12, A[i][i] - s))
                else:
                    L[i][j] = (A[i][j] - s) / L[j][j]
        return L

    @staticmethod
    def _forward_sub(L: List[List[float]], b: List[float]) -> List[float]:
        n = len(L)
        y = [0.0] * n
        for i in range(n):
            y[i] = (b[i] - sum(L[i][j] * y[j] for j in range(i))) / L[i][i]
        return y

    @staticmethod
    def _solve_tri(L: List[List[float]], b: List[float]) -> List[float]:
        n = len(L)
        y = GaussianProcess._forward_sub(L, b)
        x = [0.0] * n
        for i in range(n - 1, -1, -1):
            x[i] = (y[i] - sum(L[j][i] * x[j] for j in range(i + 1, n))) / L[i][i]
        return x


def expected_improvement(mu: float, sigma: float, best_y: float, xi: float = 0.01) -> float:
    """期望改进 (Expected Improvement) 采集函数.

    EI(x) = (mu - best_y - xi) * Φ(Z) + sigma * φ(Z), 其中 Z = (mu - best_y - xi) / sigma.
    """
    if sigma < 1e-9:
        return 0.0
    d = mu - best_y - xi
    Z = d / sigma
    # 标准正态 CDF 近似 (Abramowitz & Stegun 26.2.17)
    phi = math.exp(-0.5 * Z * Z) / math.sqrt(2 * math.pi)
    # Φ(Z) via erf
    Phi = 0.5 * (1.0 + math.erf(Z / math.sqrt(2.0)))
    return d * Phi + sigma * phi


class BayesOptimizer:
    """贝叶斯优化器 - 为钩子参数空间找到最大化产出质量的参数组合.

    用法:
      space = [ParamDef('depth', 'integer', 1, 10),
               ParamDef('threshold', 'continuous', 0.0, 1.0)]
      opt = BayesOptimizer(space, objective_fn)
      best_params, best_score = opt.optimize(n_iterations=20)
    """

    def __init__(self, param_space: List[ParamDef],
                 objective: Callable[[Dict[str, Any]], float],
                 n_initial: int = 5, length_scale: float = 0.5,
                 max_evaluations: int = 100):
        self._space = param_space
        self._obj = objective
        self._n_init = n_initial
        self._max_evals = max_evaluations
        self._gp = GaussianProcess(length_scale=length_scale, noise_var=1e-4)
        self._trials: List[Trial] = []
        self._best_trial: Optional[Trial] = None
        self._bounds = [(0.0, 1.0)] * len(param_space)

    def optimize(self, n_iterations: int = 20,
                 callback: Optional[Callable] = None) -> Tuple[Dict[str, Any], float]:
        """执行贝叶斯优化. n_iterations 受 max_evaluations 上限约束."""
        n_iterations = min(n_iterations, self._max_evals)
        init_points = self._initial_points()
        for x_norm in init_points[:n_iterations]:
            params = self._denormalize(x_norm)
            self._record(x_norm, params, self._obj(params))

        for _ in range(max(0, n_iterations - len(init_points))):
            # GP 在评估点 ≤1 时无意义, 直接随机采样
            if len(self._trials) <= 1:
                x_next = [random.uniform(0, 1) for _ in self._bounds]
            else:
                self._gp.fit([t.params_norm for t in self._trials],
                            [t.quality for t in self._trials])
                best_y = max(t.quality for t in self._trials)
                x_next = self._acquire(best_y)

            params = self._denormalize(x_next)
            self._record(x_next, params, self._obj(params))
            if callback:
                callback(self._best_trial)

        if self._best_trial is None and self._trials:
            self._best_trial = max(self._trials, key=lambda t: t.quality)
        return (self._best_trial.params, self._best_trial.quality) if self._best_trial else ({}, 0.0)

    def _acquire(self, best_y: float, n_restarts: int = 20) -> List[float]:
        """通过最大化 EI 选择下一个评估点 (random restarts + local refinement)."""
        best_x = None
        best_ei = -1.0

        for _ in range(n_restarts):
            x = [random.uniform(0, 1) for _ in self._bounds]
            # 简单局部搜索: 扰动 10 步, 取 EI 最大者
            for _ in range(10):
                mu, var = self._gp.predict(x)
                ei = expected_improvement(mu, math.sqrt(var), best_y)
                if ei > best_ei:
                    best_ei = ei
                    best_x = list(x)
                # 扰动一个随机维度
                dim = random.randrange(len(x))
                x[dim] += random.uniform(-0.1, 0.1)
                x[dim] = max(0.0, min(1.0, x[dim]))

        return best_x if best_x else [random.uniform(0, 1) for _ in self._bounds]

    def _initial_points(self) -> List[List[float]]:
        points = []
        # 随机采样
        for _ in range(self._n_init - 2):
            points.append([random.uniform(0, 1) for _ in self._bounds])
        # 边界点: 全低 + 全高
        if len(self._bounds) > 0:
            points.append([0.0] * len(self._bounds))
            points.append([1.0] * len(self._bounds))
        return points

    def _record(self, x_norm: List[float], params: Dict[str, Any], quality: float):
        t = Trial(params=params, quality=quality)
        t.params_norm = x_norm  # 附加归一化值
        self._trials.append(t)
        if self._best_trial is None or quality > self._best_trial.quality:
            self._best_trial = t

    def _denormalize(self, x: List[float]) -> Dict[str, Any]:
        result = {}
        for i, pd in enumerate(self._space):
            v = x[i] if i < len(x) else 0.5
            if pd.kind == 'categorical' and pd.choices:
                idx = int(v * (len(pd.choices) - 1) + 0.5)
                idx = max(0, min(len(pd.choices) - 1, idx))
                result[pd.name] = pd.choices[idx]
            elif pd.kind == 'integer':
                result[pd.name] = int(pd.low + v * (pd.high - pd.low) + 0.5)
            else:
                result[pd.name] = pd.low + v * (pd.high - pd.low)
        return result

    def _normalize(self, params: Dict[str, Any]) -> List[float]:
        x = []
        for pd in self._space:
            val = params.get(pd.name, pd.low)
            if pd.kind == 'categorical' and pd.choices:
                try:
                    idx = pd.choices.index(val)
                    x.append(idx / max(1, len(pd.choices) - 1))
                except ValueError:
                    x.append(0.5)
            else:
                v = (float(val) - pd.low) / max(1e-9, pd.high - pd.low)
                x.append(max(0.0, min(1.0, v)))
        return x

    @property
    def trials(self) -> List[Trial]:
        return list(self._trials)

    @property
    def best(self) -> Optional[Trial]:
        return self._best_trial

    def convergence(self) -> List[float]:
        """返回每次评估后的最佳质量序列 (用于绘制收敛曲线)."""
        best_so_far = []
        cur_best = -float('inf')
        for t in self._trials:
            if t.quality > cur_best:
                cur_best = t.quality
            best_so_far.append(cur_best)
        return best_so_far
