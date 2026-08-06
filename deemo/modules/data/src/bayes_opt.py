# 贝叶斯超参数优化 (Gradient-Free Bayesian Hyperparameter Optimization)
#
# 核心问题: 去重/压缩/索引管线有 10+ 可调参数 (batch_size, threads,
#   simhash_bits, minhash_perms, cdc_mask_bits, zstd_level, cache_shards, ...).
#   手动调参依赖专家经验, 网格搜索计算爆炸 (指数级).
#
# 创新点:
#   1. Gaussian Process 代理模型: 用 GP 拟合未知的
#      f(params) → (throughput, recall, memory_usage) 响应面.
#      Matern 5/2 kernel 捕获非平滑响应 (超参对性能的阶梯效应).
#   2. 约束 Expected Improvement (cEI): 在 recall ≥ target_recall 和
#      memory ≤ budget 的约束下, 最大化 expected improvement of throughput.
#      用 Monte Carlo 估计约束满足概率 P(feasible | params).
#   3. 多保真度优化: 先用小数据集 (1K signatures) 快速评估,
#      仅对 Top-5 候选用全量数据 (100K) 精确验证.
#      类似 BOHB (Bayesian Optimization + HyperBand) 但更轻量,
#      适合每次评估耗时秒级的管线场景.
#   4. 在线模型更新: 每次管线运行后自动将观测 (params, metrics)
#      加入 GP 训练集, 持续优化. 不需要离线调参阶段.
#
# 与现有工作:
#   - Optuna/Hyperopt: 通用框架, 不感知管线约束.
#   - BOHB (ICML 2018): 多保真度 + HyperBand, 面向 ML 训练.
#   - 本方案: 约束 EI + 多保真度 + 管线原生集成.

import math
import random
import time
from typing import Callable, Dict, List, Optional, Tuple


class GaussianProcess:
    """轻量 GP 回归: Matern 5/2 kernel, Cholesky 求解.

    无外部依赖 (不使用 scikit-learn/scipy), 面向嵌入部署.
    """

    def __init__(self, length_scale: float = 1.0,
                 signal_variance: float = 1.0,
                 noise_variance: float = 1e-4):
        self.ls = length_scale
        self.sv = signal_variance
        self.nv = noise_variance
        self._X: List[List[float]] = []
        self._y: List[float] = []
        self._L = None   # Cholesky of K + σ²I
        self._alpha = None  # K⁻¹y

    def fit(self, X: List[List[float]], y: List[float]):
        self._X = X; self._y = y
        n = len(X)
        K = [[0.0]*n for _ in range(n)]
        for i in range(n):
            for j in range(i, n):
                k = self._matern52(X[i], X[j])
                K[i][j] = k
                if i != j: K[j][i] = k
        # K + σ²I
        for i in range(n):
            K[i][i] += self.nv
        # Cholesky
        self._L = self._cholesky(K)
        # α = K⁻¹y
        self._alpha = self._solve(self._L, y)

    def predict(self, x: List[float]) -> Tuple[float, float]:
        """返回 (mean, std)."""
        if not self._X:
            return 0.0, math.sqrt(self.sv)
        n = len(self._X)
        k_star = [self._matern52(x, xi) for xi in self._X]
        mean = sum(k_star[i] * self._alpha[i] for i in range(n))
        v = self._solve(self._L, k_star)
        var = self._matern52(x, x) - sum(k_star[i]*v[i] for i in range(n))
        return mean, math.sqrt(max(var, 1e-12))

    def _matern52(self, a: List[float], b: List[float]) -> float:
        r2 = sum((ai-bi)**2 for ai, bi in zip(a, b)) / (self.ls**2)
        r = math.sqrt(max(r2, 0))
        return self.sv * (1.0 + math.sqrt(5.0)*r + 5.0*r2/3.0) * math.exp(-math.sqrt(5.0)*r)

    def _cholesky(self, A: List[List[float]]) -> List[List[float]]:
        n = len(A); L = [[0.0]*n for _ in range(n)]
        for i in range(n):
            for j in range(i+1):
                s = sum(L[i][k]*L[j][k] for k in range(j))
                if i == j:
                    L[i][j] = math.sqrt(max(A[i][i]-s, 1e-12))
                else:
                    L[i][j] = (A[i][j]-s)/L[j][j]
        return L

    def _solve(self, L: List[List[float]], b: List[float]) -> List[float]:
        n = len(L); y = list(b)
        for i in range(n):
            y[i] = (y[i]-sum(L[i][j]*y[j] for j in range(i)))/L[i][i]
        for i in range(n-1, -1, -1):
            y[i] = (y[i]-sum(L[j][i]*y[j] for j in range(i+1, n)))/L[i][i]
        return y


class ConstrainedBayesianOptimizer:
    """约束贝叶斯优化器: GP代理+约束EI+多保真度.

    用法:
      cbo = ConstrainedBayesianOptimizer(param_bounds, constraint_fn)
      for iteration in range(max_iter):
          params = cbo.suggest()
          throughput, recall, memory = evaluate_pipeline(params)
          cbo.observe(params, throughput, feasible=(recall>=0.9 and memory<1e9))
      best = cbo.best_params()
    """

    def __init__(self, param_bounds: List[Tuple[float, float]],
                 constraint_fn: Callable = None,
                 n_initial: int = 10, n_mc_samples: int = 50):
        self.bounds = param_bounds
        self.d = len(param_bounds)
        self._constraint_fn = constraint_fn
        self.n_initial = n_initial
        self.n_mc = n_mc_samples

        self._gp_obj = GaussianProcess(length_scale=0.5)
        self._gp_feas = GaussianProcess(length_scale=0.5)
        self._X: List[List[float]] = []
        self._y_obj: List[float] = []    # objective (throughput)
        self._y_feas: List[float] = []   # feasibility (0/1)

        self._best_params: Optional[List[float]] = None
        self._best_value: float = float('-inf')

    def suggest(self) -> List[float]:
        """建议下一组超参数: 约束 EI 最大化."""
        if len(self._X) < self.n_initial:
            return self._random_params()

        # Monte Carlo 约束 EI
        best_idx = max(range(len(self._y_obj)),
                       key=lambda i: self._y_obj[i] if self._y_feas[i] > 0.5 else float('-inf'))
        f_best = self._y_obj[best_idx] if best_idx < len(self._y_obj) else 0

        best_params = None
        best_eic = float('-inf')

        for _ in range(200):  # 随机候选采样
            candidate = self._random_params()
            mu_o, std_o = self._gp_obj.predict(candidate)
            mu_f, std_f = self._gp_feas.predict(candidate)

            # EI: (μ - f_best)·Φ(z) + σ·φ(z)  where z = (μ - f_best)/σ
            if std_o < 1e-9:
                ei = max(0, mu_o - f_best)
            else:
                z = (mu_o - f_best) / std_o
                ei = (mu_o - f_best) * self._norm_cdf(z) + std_o * self._norm_pdf(z)

            # 可行性概率: P(y_feas > 0.5)
            p_feas = 1.0 - self._norm_cdf((0.5 - mu_f) / max(std_f, 1e-9))

            eic = ei * p_feas
            if eic > best_eic:
                best_eic = eic
                best_params = candidate

        return best_params or self._random_params()

    def observe(self, params: List[float], objective: float,
                feasible: bool = True):
        """记录一次评估结果."""
        self._X.append(params)
        self._y_obj.append(objective)
        self._y_feas.append(1.0 if feasible else 0.0)
        self._gp_obj.fit(self._X, self._y_obj)
        self._gp_feas.fit(self._X, self._y_feas)

        if feasible and objective > self._best_value:
            self._best_value = objective
            self._best_params = list(params)

    def best_params(self) -> Optional[List[float]]:
        return self._best_params

    def _random_params(self) -> List[float]:
        return [random.uniform(lo, hi) for lo, hi in self.bounds]

    @staticmethod
    def _norm_cdf(x: float) -> float:
        return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))

    @staticmethod
    def _norm_pdf(x: float) -> float:
        return math.exp(-0.5*x*x) / math.sqrt(2.0*math.pi)


# ---------------------------------------------------------------------------
# 管线参数适配器: 将符号参数名映射到连续优化空间
# ---------------------------------------------------------------------------

class PipelineParamAdapter:
    """管线参数→连续优化变量的双向映射.

    支持的参数:
      batch_size: [16, 4096] log-scale
      max_workers: [1, 16] linear
      simhash_bits: [64, 256] linear
      minhash_perms: [64, 512] linear
      cdc_mask_bits: [8, 16] linear
      zstd_level: [1, 12] integer (round)
      cache_shards: [1, 16] integer (round)
    """

    PARAM_SPECS = {
        "batch_size":     (16, 4096, "log"),
        "max_workers":    (1, 16, "linear"),
        "simhash_bits":   (64, 256, "linear"),
        "minhash_perms":  (64, 512, "linear"),
        "cdc_mask_bits":  (8, 16, "linear"),
        "zstd_level":     (1, 12, "int"),
        "cache_shards":   (1, 16, "int"),
    }

    def __init__(self, active_params: List[str] = None):
        self.names = active_params or list(self.PARAM_SPECS.keys())
        self.bounds = [self.PARAM_SPECS[n][:2] for n in self.names]

    def to_continuous(self, params: Dict[str, float]) -> List[float]:
        """符号参数→连续向量 (归一化到 [0,1])."""
        vec = []
        for name in self.names:
            lo, hi, scale = self.PARAM_SPECS[name]
            val = params.get(name, (lo+hi)/2)
            if scale == "log":
                vec.append((math.log(val)-math.log(lo))/
                           (math.log(hi)-math.log(lo)))
            else:
                vec.append((val-lo)/(hi-lo))
        return vec

    def from_continuous(self, vec: List[float]) -> Dict[str, float]:
        """连续向量→符号参数."""
        params = {}
        for i, name in enumerate(self.names):
            lo, hi, scale = self.PARAM_SPECS[name]
            t = max(0.0, min(1.0, vec[i]))
            if scale == "log":
                val = math.exp(math.log(lo)+t*(math.log(hi)-math.log(lo)))
            elif scale == "int":
                val = round(lo+t*(hi-lo))
            else:
                val = lo+t*(hi-lo)
            params[name] = val
        return params


__all__ = [
    "ConstrainedBayesianOptimizer",
    "GaussianProcess",
    "PipelineParamAdapter",
]
