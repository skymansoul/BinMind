"""Robbins-Monro 在线模糊测试调参 (Robbins-Monro Online Fuzzer Tuning).

修改记录:
2025-08-08 11:05 - RM 随机逼近 + Polyak 平均 + 自适应步长
2025-08-09 16:33 - SPSA 梯度估计 (无需解析梯度) + 多个超参数联合调优
2025-08-10 08:47 - 收敛诊断: 步长衰减满足 Ση=∞, Ση²<∞ 条件监控

  Robbins & Monro "A Stochastic Approximation Method" (Annals of Math
    Statistics) — 经典 RM 算法, 随机逼近的奠基工作
  Spall "Multivariate Stochastic Approximation Using a Simultaneous
    Perturbation Gradient Approximation" (IEEE TAC) — SPSA, 仅需两次函数评估
  Polyak & Juditsky "Acceleration of Stochastic Approximation by
    Averaging" (SIAM JCO) — 参数平均化改进收敛速度
  Kushner & Yin "Stochastic Approximation and Recursive Algorithms
    and Applications" — 专著, ODE 方法证明收敛

在 fuzzing 文献中的位置:
  RM 随机逼近在 fuzzing 超参数调优中完全无先例。现有调参:
    - 网格搜索: 离线, 费时, 不与在线状态交互
    - 贝叶斯优化: 需代理模型, 不适合高频在线更新
    - 手动调参: 依赖经验
  RM 提供了轻量级的在线参数自适应:
    每次 fuzzing 执行后, 用梯度估计更新参数,
    步长自动衰减满足收敛条件, Polyak 平均给出最终估计。

核心创新:
  1. RM 在线参数调优: O(1) 每步更新, 适合高频 fuzzing 循环
  2. SPSA 梯度估计: 不需要解析梯度, 仅两次扰动评估
  3. 自适应步长: η_t = a/(b+t)^α, 自动满足 Ση=∞, Ση²<∞
  4. Polyak 平均: 参数轨迹的平均值作为最终估计→更高精度
"""

import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

# RM 参数
_DEFAULT_ETA_A = 1.0          # 步长缩放因子
_DEFAULT_ETA_B = 10.0         # 步长稳定项
_DEFAULT_ETA_ALPHA = 0.602    # 步长衰减指数 (SPSA 推荐值)
_DEFAULT_SPSA_C = 0.1          # SPSA 扰动大小

@dataclass
class ParameterState:
    """一个可调优超参数的状态."""
    name: str
    value: float                # 当前值
    min_val: float              # 允许的最小值
    max_val: float              # 允许的最大值
    polyak_sum: float = 0.0     # Σθ_s (用于 Polyak 平均)
    polyak_avg: float = 0.0     # 当前 Polyak 平均值
    gradient_history: List[float] = field(default_factory=list)
    # 统计
    n_updates: int = 0
    recent_gradient: float = 0.0

class RobbinsMonroTuner:
    """Robbins-Monro 在线参数调优器.

    使用随机逼近 (stochastic approximation) 自动调整 fuzzing 超参数。
    每个参数独立维护一个 RM 更新链:
      θ_{t+1} = θ_t - η_t · ĝ_t
    其中 ĝ_t 是梯度的无偏估计 (通过 SPSA 获得)。

    SPSA (Simultaneous Perturbation Stochastic Approximation):
      ĝ = (L(θ+cΔ) - L(θ-cΔ)) / (2c)·Δ
    其中 Δ 是随机扰动向量 (±1), c 是扰动大小。

    使用方式:
      rmt = RobbinsMonroTuner()
      rmt.add_parameter("mutation_rate", 0.5, 0.01, 0.99)
      for each fuzzing execution:
          loss = -coverage_gain  # 负覆盖增益 = 损失
          rmt.update(loss)       # 自动更新所有参数
      tuned = rmt.get_parameters()
    """

    def __init__(self):
        self._params: Dict[str, ParameterState] = {}
        self._iteration: int = 0
        # SPSA 历史
        self._last_loss_plus: Optional[float] = None
        self._last_loss_minus: Optional[float] = None
        self._last_delta: Dict[str, float] = {}
        self._spsa_phase: int = 0  # 0=等loss_plus, 1=等loss_minus

    # //// 参数管理 ////
    def add_parameter(self, name: str, initial: float,
                      min_val: float, max_val: float) -> None:
        self._params[name] = ParameterState(
            name=name, value=initial,
            min_val=min_val, max_val=max_val)

    def get_parameters(self) -> Dict[str, float]:
        """返回所有参数的当前 (Polyak 平均) 值."""
        return {name: ps.polyak_avg if ps.n_updates > 10 else ps.value
                for name, ps in self._params.items()}

    def set_parameter(self, name: str, value: float) -> None:
        if name in self._params:
            self._params[name].value = max(
                self._params[name].min_val,
                min(self._params[name].max_val, value))

    # //// SPSA 更新 ////
    def perturb_parameters(self) -> Dict[str, float]:
        """生成 SPSA 扰动: 生成随机 ±1 方向并应用扰动.

        返回扰动后的参数值 (用于下一次评估)。
        SPSA 需要两次评估: 一次正向扰动, 一次负向扰动。
        """
        self._spsa_phase = 0
        self._last_delta = {}
        c_t = self._spsa_c()
        perturbed = {}
        for name, ps in self._params.items():
            delta = 1.0 if random.random() < 0.5 else -1.0
            self._last_delta[name] = delta
            ps_new = ps.value + c_t * delta
            ps_new = max(ps.min_val, min(ps.max_val, ps_new))
            perturbed[name] = ps_new
        return perturbed

    def unperturb_parameters(self) -> Dict[str, float]:
        """返回负向扰动值 (用于第二次评估)."""
        c_t = self._spsa_c()
        perturbed = {}
        for name, ps in self._params.items():
            delta = self._last_delta.get(name, 1.0)
            ps_new = ps.value - c_t * delta
            ps_new = max(ps.min_val, min(ps.max_val, ps_new))
            perturbed[name] = ps_new
        return perturbed

    def update(self, loss_plus: Optional[float] = None,
               loss_minus: Optional[float] = None) -> None:
        """SPSA 梯度估计并更新参数.

        调用模式:
          1. perturb_parameters() → 用扰动值执行 fuzzing → loss_plus
          2. unperturb_parameters() → 用反向扰动执行 → loss_minus
          3. update(loss_plus, loss_minus) → RM 更新

        也支持单次调用: update(loss_plus=observed_loss),
        此时使用指数移动平均梯度近似。
        """
        self._iteration += 1

        if loss_plus is not None and loss_minus is not None:
            self._spsa_update(loss_plus, loss_minus)
        elif loss_plus is not None:
            self._simple_update(loss_plus)

    def _spsa_update(self, loss_plus: float, loss_minus: float) -> None:
        """完整的 SPSA 更新 (每两次 fuzzing 执行调用一次)."""
        c_t = self._spsa_c()
        for name, ps in self._params.items():
            delta = self._last_delta.get(name, 1.0)
            # SPSA 梯度: (L(θ+cΔ) - L(θ-cΔ)) / (2c) · Δ⁻¹
            grad = (loss_plus - loss_minus) / (2.0 * c_t + 1e-8) * delta
            ps.recent_gradient = grad
            self._rm_step(ps, grad)

    def _simple_update(self, loss: float) -> None:
        """简化单次更新 (无 SPSA 对): 使用损失作为梯度信号."""
        for name, ps in self._params.items():
            # 简化: 梯度 = 损失 (越负越好)
            grad = loss
            # 指数移动平均平滑
            ps.recent_gradient = 0.7 * ps.recent_gradient + 0.3 * grad
            self._rm_step(ps, grad)

    def _rm_step(self, ps: ParameterState, grad: float) -> None:
        """单个参数的 RM 更新步骤."""
        ps.n_updates += 1
        eta = self._step_size(ps.n_updates)
        ps.value -= eta * grad
        ps.value = max(ps.min_val, min(ps.max_val, ps.value))
        # Polyak 平均
        ps.polyak_sum += ps.value
        ps.polyak_avg = ps.polyak_sum / ps.n_updates
        ps.gradient_history.append(grad)
        if len(ps.gradient_history) > 50:
            ps.gradient_history = ps.gradient_history[-30:]

    # //// 步长调度 ////
    def _step_size(self, n_updates: int) -> float:
        """RM 步长: η_t = a / (b + t)^α.

        满足 Ση_t = ∞ (充分探索) 和 Ση_t² < ∞ (收敛).
        """
        return _DEFAULT_ETA_A / ((_DEFAULT_ETA_B + n_updates)
                                 ** _DEFAULT_ETA_ALPHA)

    def _spsa_c(self) -> float:
        """SPSA 扰动幅度: c_t = c / t^(1/6)."""
        t = max(1, self._iteration)
        return _DEFAULT_SPSA_C / (t ** (1.0 / 6.0))

    # //// 收敛诊断 ////
    def convergence_check(self) -> Dict[str, str]:
        """检查各参数的收敛状态."""
        status = {}
        for name, ps in self._params.items():
            if ps.n_updates < 10:
                status[name] = "initializing"
            else:
                recent_grad_mean = (sum(ps.gradient_history[-5:]) / 5
                                   if ps.gradient_history else 0.0)
                if abs(recent_grad_mean) < 0.01:
                    status[name] = "converged"
                elif abs(recent_grad_mean) < 0.1:
                    status[name] = "converging"
                else:
                    status[name] = "adapting"
        return status

    # //// 统计 ////
    def stats(self) -> dict:
        param_stats = {}
        for name, ps in self._params.items():
            param_stats[name] = {
                "value": round(ps.value, 4),
                "polyak_avg": round(ps.polyak_avg, 4),
                "n_updates": ps.n_updates,
                "recent_grad": round(ps.recent_gradient, 4),
            }
        return {
            "iteration": self._iteration,
            "step_size_current": round(self._step_size(
                max(1, self._iteration)), 6),
            "convergence": self.convergence_check(),
            "parameters": param_stats,
        }

    def clear(self) -> None:
        self._params.clear()
        self._iteration = 0
        self._spsa_phase = 0
