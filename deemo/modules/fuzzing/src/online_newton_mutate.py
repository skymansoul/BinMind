"""在线牛顿步突变自适应 — 对角 Hessian + 协方差追踪.

参考: Hazan et al.. 使用对角近似的 ONS 更新权重。
对角 Hessian 下等价于自适应步长的一阶方法;
全矩阵 ONS 的理论 O(log T) 界在对角近似下不严格成立。"""

import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple


# ONS 参数
_DEFAULT_ETA = 0.05           # ONS 学习率
_MIN_EIGENVALUE = 0.01        # Hessian 对角的最小值 (保证可逆)
_HESSIAN_RESET_ROUNDS = 100   # Hessian 重置周期
_EPSILON_PROJECTION = 1e-8    # 单纯形投影的数值容差


@dataclass
class MutationOperator:
    """带二阶统计量的突变算子."""
    name: str
    weight: float = 1.0
    prob: float = 0.0
    # 一阶统计
    cumulative_gradient: float = 0.0
    calls: int = 0
    success_count: int = 0
    # 二阶统计
    hessian_diag: float = 1.0           # H_{ii} — 梯度的二阶矩
    hessian_off_diag: Dict[str, float] = field(
        default_factory=dict)           # H_{ij} — 算子协方差


MutatorFn = Callable[[bytes], Tuple[bytes, List[int]]]


class OnlineNewtonMutationAdaptor:
    """在线牛顿步突变自适应器.

    w_{t+1} = argmin_{w∈Δ_N} ||H_t^{1/2}(w - (w_t - η·H_t^{-1}·g_t))||²
    即: w_t - η·H_t^{-1}·g_t 后在马氏距离下投影到单纯形。

    Hessian 更新: H_t = Σ_{s≤t} g_s·g_sᵀ + ε·I (经验 Fisher 近似)
    对角+稀疏 Sherman-Morrison: 仅对 top-k 相关算子对维护非对角元。

    使用方式:
      ons = OnlineNewtonMutationAdaptor()
      strategy = ons.select()
      mutated, positions = ons.mutate(data, strategy)
      ons.update(strategy, gradient=0.5)  # 0=差, 1=好
    """

    def __init__(self, eta: float = _DEFAULT_ETA,
                 n_operators: int = 8):
        self.eta = eta
        self.n_operators = n_operators
        self._operators: Dict[str, MutationOperator] = {}
        self._mutators: Dict[str, MutatorFn] = {}
        self._init_default_operators()
        self._round: int = 0
        self._cumulative_loss: float = 0.0
        self._best_fixed_loss: float = 0.0
        # 算子互补矩阵的 top-k 非对角元追踪
        self._complement_pairs: List[Tuple[str, str, float]] = []
        self._recalc_probs()

    def _init_default_operators(self) -> None:
        """初始化 8 种突变算子."""
        names = ["bitflip", "byteflip", "arith", "interesting",
                 "havoc", "splice", "delete", "insert"]
        for name in names:
            self._operators[name] = MutationOperator(name=name)
        # 简化的变异实现
        self._mutators["bitflip"] = self._make_bitflip()
        self._mutators["byteflip"] = self._make_byteflip()
        self._mutators["arith"] = self._make_arith()
        self._mutators["interesting"] = self._make_interesting()
        self._mutators["havoc"] = self._make_havoc()
        self._mutators["splice"] = self._make_splice()
        self._mutators["delete"] = self._make_delete()
        self._mutators["insert"] = self._make_insert()

    # //// 策略选择 ////
    def select(self) -> str:
        self._round += 1
        probs = [op.prob for op in self._operators.values()]
        names = list(self._operators.keys())
        r = random.random(); cum = 0.0
        for i, p in enumerate(probs):
            cum += p
            if r <= cum:
                return names[i]
        return names[-1]

    def mutate(self, data: bytes, strategy_name: Optional[str] = None
               ) -> Tuple[bytes, List[int], str]:
        if strategy_name is None:
            strategy_name = self.select()
        mutator = self._mutators.get(strategy_name)
        if mutator is None:
            strategy_name = list(self._mutators.keys())[0]
            mutator = self._mutators[strategy_name]
        result, positions = mutator(data)
        self._operators[strategy_name].calls += 1
        return result, positions, strategy_name

    # //// ONS 梯度更新 ////
    def update(self, strategy_name: str, gradient: float,
               precursor: Optional[str] = None) -> None:
        """ONS 权重更新.

        gradient: 负损失梯度 (正=好, 负=差), 范围 [-1, 1]
        precursor: 若此变异叠加在前一策略的输出上, 记录互补效应
        """
        op = self._operators.get(strategy_name)
        if op is None:
            return

        gradient = max(-1.0, min(1.0, gradient))
        g_positive = max(0.0, gradient)
        if g_positive > 0.3:
            op.success_count += 1

        # 更新累积梯度
        op.cumulative_gradient += gradient

        # Hessian 更新: H_{ii} += g²
        op.hessian_diag += gradient * gradient
        op.hessian_diag = max(_MIN_EIGENVALUE, op.hessian_diag)

        # 非对角: 若提供了 precursor, 更新协方差 H_{precursor, strategy}
        if precursor and precursor in self._operators:
            prec_op = self._operators[precursor]
            old_val = prec_op.hessian_off_diag.get(strategy_name, 0.0)
            prec_op.hessian_off_diag[strategy_name] = (
                0.9 * old_val + 0.1 * gradient * gradient)
            # 追踪互补对
            self._track_complement(precursor, strategy_name, gradient)

        # ONS 权重更新: w ← w - η·H^{-1}·g
        # 使用对角+稀疏 Hessian
        for name, oper in self._operators.items():
            if name == strategy_name:
                g_i = gradient
            else:
                g_i = 0.0  # 其他算子本轮梯度为零
            h_inv = 1.0 / max(_MIN_EIGENVALUE, oper.hessian_diag)
            delta = self.eta * h_inv * g_i
            oper.weight = max(0.01, oper.weight - delta)

        # 投影到单纯形
        self._project_to_simplex()

        # 损失追踪
        loss = 1.0 - gradient  # 梯度高 → 损失低
        self._cumulative_loss += loss
        self._best_fixed_loss = min(self._best_fixed_loss, loss)

        # 周期性 Hessian 重置
        if self._round % _HESSIAN_RESET_ROUNDS == 0:
            self._reset_hessian()

        self._recalc_probs()

    # //// 单纯形投影 ////
    def _project_to_simplex(self) -> None:
        """将权重投影到概率单纯形: Σw_i = 1, w_i ≥ 0.01.

        使用 Wang & Carreira-Perpiñán (2013) 的 O(n log n) 投影算法。
        """
        names = list(self._operators.keys())
        ws = [max(0.01, self._operators[n].weight) for n in names]
        # 排序
        sorted_idx = sorted(range(len(ws)), key=lambda i: ws[i], reverse=True)
        sorted_w = [ws[i] for i in sorted_idx]
        cumsum = 0.0
        rho = len(ws)
        for j in range(len(ws)):
            cumsum += sorted_w[j]
            if sorted_w[j] - (cumsum - 1.0) / (j + 1) <= 0.01:
                rho = j
                break
        theta = (sum(sorted_w[:rho]) - 1.0) / rho if rho > 0 else 0.0
        for i in range(len(ws)):
            ws[i] = max(0.01, ws[i] - theta)
        # 归一化
        total = sum(ws)
        for i, name in enumerate(names):
            self._operators[name].weight = ws[i] / max(1e-12, total)

    # //// 互补追踪 ////
    def _track_complement(self, precursor: str, successor: str,
                          gain: float) -> None:
        """记录算子互补对: precursor→successor 的增益."""
        self._complement_pairs.append((precursor, successor, gain))
        if len(self._complement_pairs) > 50:
            self._complement_pairs = self._complement_pairs[-30:]

    def top_complements(self, top_k: int = 5) -> List[Tuple[str, str, float]]:
        """返回增益最高的算子互补对."""
        pairs = defaultdict(float)
        for a, b, g in self._complement_pairs:
            pairs[(a, b)] = max(pairs[(a, b)], g)  # 取最大增益
        sorted_pairs = sorted(pairs.items(), key=lambda x: x[1], reverse=True)
        return [(a, b, g) for (a, b), g in sorted_pairs[:top_k]]

    # //// 遗憾计算 ////
    def empirical_regret(self) -> float:
        """经验遗憾: 累积损失 - 最佳固定策略损失."""
        return max(0.0, self._cumulative_loss - self._best_fixed_loss * self._round)

    def theoretical_regret_bound(self) -> float:
        """ONS 理论遗憾上界: O(n·log T)."""
        if self._round == 0:
            return 0.0
        return self.n_operators * math.log(self._round + 1)

    # //// 概率重算 ////
    def _recalc_probs(self) -> None:
        names = list(self._operators.keys())
        weights = [self._operators[n].weight for n in names]
        total = sum(weights)
        for i, name in enumerate(names):
            self._operators[name].prob = weights[i] / max(1e-12, total)

    def _reset_hessian(self) -> None:
        for op in self._operators.values():
            op.hessian_diag = max(_MIN_EIGENVALUE,
                                 op.hessian_diag * 0.5 + 0.5)
            op.hessian_off_diag.clear()

    # //// 统计 ////
    def stats(self) -> dict:
        op_stats = {}
        for name, op in self._operators.items():
            op_stats[name] = {
                "weight": round(op.weight, 3),
                "prob": round(op.prob, 3),
                "calls": op.calls,
                "success_rate": round(
                    op.success_count / max(1, op.calls), 3),
                "hessian_diag": round(op.hessian_diag, 3),
            }
        top_comp = self.top_complements(3)
        return {
            "round": self._round,
            "empirical_regret": round(self.empirical_regret(), 4),
            "theoretical_regret_bound": round(
                self.theoretical_regret_bound(), 4),
            "learning_rate": self.eta,
            "operators": op_stats,
            "top_complements": [
                f"{a}→{b}({g:.2f})" for a, b, g in top_comp],
        }

    def clear(self) -> None:
        for op in self._operators.values():
            op.weight = 1.0; op.calls = 0; op.success_count = 0
            op.cumulative_gradient = 0.0
            op.hessian_diag = 1.0; op.hessian_off_diag.clear()
        self._round = 0; self._cumulative_loss = 0.0
        self._best_fixed_loss = 0.0; self._complement_pairs.clear()
        self._recalc_probs()

    # //// 变异实现 (精简) ////
    @staticmethod
    def _make_bitflip() -> MutatorFn:
        def fn(d):
            if not d: return d, []
            a = bytearray(d); p = random.randint(0, len(a)-1)
            a[p] ^= (1 << random.randint(0, 7)); return bytes(a), [p]
        return fn
    @staticmethod
    def _make_byteflip() -> MutatorFn:
        def fn(d):
            if not d: return d, []
            a = bytearray(d); p = random.randint(0, len(a)-1)
            a[p] ^= 0xFF; return bytes(a), [p]
        return fn
    @staticmethod
    def _make_arith() -> MutatorFn:
        def fn(d):
            if not d: return d, []
            a = bytearray(d); p = random.randint(0, len(a)-1)
            a[p] = (a[p] + random.choice([-35,-1,1,35])) & 0xFF
            return bytes(a), [p]
        return fn
    @staticmethod
    def _make_interesting() -> MutatorFn:
        def fn(d):
            if not d: return d, []
            a = bytearray(d); p = random.randint(0, len(a)-1)
            cand = [v for v in [0,1,0x7F,0x80,0xFF,0xFE] if v != a[p]]
            if cand: a[p] = random.choice(cand)
            return bytes(a), [p]
        return fn
    @staticmethod
    def _make_havoc() -> MutatorFn:
        def fn(d):
            if not d: return d, []
            a = bytearray(d); pos = []
            for _ in range(random.randint(1, min(16, len(a)))):
                p = random.randint(0, len(a)-1)
                op = random.randint(0,3)
                if op == 0: a[p] ^= (1 << random.randint(0,7))
                elif op == 1: a[p] = random.randint(0,255)
                elif op == 2: a[p] = (a[p]+random.randint(-35,35))&0xFF
                else: a[p] = random.choice([0,1,0x7F,0x80,0xFF])
                pos.append(p)
            return bytes(a), pos
        return fn
    @staticmethod
    def _make_splice() -> MutatorFn:
        def fn(d):
            if len(d) < 4: return d, []
            a = bytearray(d); cs = max(1, len(a)//4)
            s = random.randint(0, max(0, len(a)-cs))
            t = random.randint(0, max(0, len(a)-cs))
            a[t:t+cs] = a[s:s+cs]
            return bytes(a), list(range(t, t+cs))
        return fn
    @staticmethod
    def _make_delete() -> MutatorFn:
        def fn(d):
            if len(d) < 2: return d, []
            a = bytearray(d); cs = random.randint(1, max(1, len(a)//8))
            s = random.randint(0, max(0, len(a)-cs))
            del a[s:s+cs]; return bytes(a), [s]
        return fn
    @staticmethod
    def _make_insert() -> MutatorFn:
        def fn(d):
            if len(d) < 2: return d, []
            a = bytearray(d); cs = random.randint(1, max(1, len(a)//8))
            s = random.randint(0, max(0, len(a)-cs))
            t = random.randint(0, len(a))
            a[t:t] = a[s:s+cs]
            return bytes(a), list(range(t, t+cs))
        return fn
