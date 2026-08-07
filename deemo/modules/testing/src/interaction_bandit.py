# 交互感知的上下文老虎机变异调度器 — 建模变异操作符的 pairwise 交互效应
#
# 核心问题:
#   adaptive_mutator.py 用 EWMA 独立追踪每个操作符的覆盖奖励,
#   thompson_test_selector.py 用独立 Beta 后验做策略选择。
#   两者均假设操作符/策略之间独立——但变异操作符之间存在强交互:
# bitflip_1 之后接 arith_8 的效果 ≠ 两者独立效果之和
# havoc 之后接 dict_insert 可能因格式破坏而抵消前者收益
# 某些操作符组合 (如 splice + bitflip) 有超加性收益
#
#   忽略交互效应导致:
#     a) 重复选择相互抵消的操作符组合, 浪费 fuzzing 预算
#     b) 未能发现高收益的操作符序列模式
#     c) 对"操作符A之后选B"的联合收益估计偏差
#
# 本模块的方法 — LinUCB + 交互特征:
#   1. 每个操作符维护一个线性模型: E[reward | context] = θ^T · x
#   2. context x 包含三部分:
#      a) 操作符自身特征: 历史EWMA、选择次数、最近k次奖励
#      b) 交互特征: 前一操作符 × 当前操作符 的联合EWMA (pairwise interaction)
#      c) 输入特征: 输入大小对数、字节熵、类型标签
#   3. 使用 LinUCB (hybrid/shared-features variant) 做探索-利用平衡:
#      select = argmax(θ_a^T · x_a + α · √(x_a^T · A_a^{-1} · x_a))
#      注: 所有arm共享相同特征结构(自身EWMA/经验权重/输入特征/交互特征),
#      但各自维护独立的A矩阵和θ向量——介于disjoint和hybrid之间
#   4. 交互矩阵 I[i][j] = 操作符i之后选j的 EWMA 奖励
#
# 为什么用 LinUCB 而非 Thompson 采样:
#   - Thompson 采样假设 Beta-Bernoulli 共轭, 但覆盖奖励是连续的
# LinUCB 天然支持连续奖励和上下文特征
# 交互特征可直接加入上下文向量, 无需修改算法结构
#
# 文献:
#   Li et al. 2010, "A Contextual-Bandit Approach to Personalized News Article
#     Recommendation", WWW 2010 — LinUCB 原始论文
#   "Balancing Exploration and Exploitation: Fuzzing Based on
#     Adaptive Scheduling" — DDPG+MAB做fuzz调度;
#     本项目取MAB思想但以LinUCB替代DDPG (线性模型, 训练开销低)
#   "Efficient Directed Fuzz Testing Based on Exp3"
#     — 对抗bandit做定向fuzzing; 本项目以LinUCB替代Exp3 (连续奖励)

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class OperatorArm:
    """单个操作符的 LinUCB 状态"""
    name: str
    # 线性模型参数
    A: List[List[float]] = field(default_factory=list)  # d×d 协方差矩阵
    A_inv: List[List[float]] = field(default_factory=list)  # A^{-1}
    b: List[float] = field(default_factory=list)        # d维累积奖励向量
    theta: List[float] = field(default_factory=list)     # d维权向量
    # 统计
    trials: int = 0
    ewma_reward: float = 0.5
    total_reward: float = 0.0
    last_seen_at: float = 0.0
    # 交互追踪: prev_op_name → (trials, ewma_reward)
    pairwise_after: Dict[str, Tuple[int, float]] = field(default_factory=dict)


@dataclass
class InteractionMatrix:
    """O×O 交互矩阵——操作符i之后选j的联合效果追踪"""
    ops: List[str] = field(default_factory=list)
    # (prev_op, curr_op) → (trials, ewma_reward)
    _cells: Dict[Tuple[str, str], Tuple[int, float]] = field(
        default_factory=dict)

    def record(self, prev_op: str, curr_op: str, reward: float,
                alpha: float = 0.3) -> None:
        key = (prev_op, curr_op)
        trials, ewma = self._cells.get(key, (0, 0.5))
        new_trials = trials + 1
        new_ewma = alpha * reward + (1.0 - alpha) * ewma
        self._cells[key] = (new_trials, new_ewma)

    def get_interaction(self, prev_op: str, curr_op: str) -> float:
        """返回交互奖励的 EWMA, 无记录时返回 0.5 (中性)"""
        _, ewma = self._cells.get((prev_op, curr_op), (0, 0.5))
        return ewma

    def to_feature_vector(self, prev_op: str, curr_ops: List[str]) -> List[float]:
        """为给定前驱操作符和所有候选操作符生成交互特征向量"""
        return [self.get_interaction(prev_op, op) for op in curr_ops]


class InteractionBanditScheduler:
    """交互感知的上下文老虎机变异调度器。

    典型用法:
        scheduler = InteractionBanditScheduler(
            operator_names=['bitflip_1_1', 'arith_8', 'havoc_random', ...],
            context_dim=5,
        )
        # 每轮选择:
        selected = scheduler.select(input_size=256, input_entropy=4.5)
        # 应用变异, 获得覆盖奖励:
        reward = execute_and_measure_coverage(mutated_input)
        scheduler.update(selected, reward)

    与 adaptive_mutator.py 的接合:
        adaptive_mutator 的 OperatorStats.ewma_reward 可作为本模块的
        baseline_context 输入, 形成两层调度: EWMA 粗选 → LinUCB 精选。
    """

    def __init__(self,
                 operator_names: List[str],
                 context_dim: int = 5,
                 alpha: float = 0.3,
                 ridge_lambda: float = 1.0):
        """
        context_dim: 上下文向量维度 (自身特征3 + 交互特征1 + 输入特征1)
        alpha: LinUCB 探索参数, 越大越倾向探索
        ridge_lambda: L2 正则化系数 (A = λI + Σ x·x^T)
        """
        self._ops = operator_names
        self._d = context_dim
        self._alpha = alpha
        self._lambda = ridge_lambda

        self._arms: Dict[str, OperatorArm] = {}
        self._interactions = InteractionMatrix(ops=operator_names)
        self._last_selected: str = ""

        for op in operator_names:
            arm = OperatorArm(name=op)
            arm.A = [[ridge_lambda if i == j else 0.0
                       for j in range(context_dim)]
                      for i in range(context_dim)]
            arm.A_inv = [[1.0 / ridge_lambda if i == j else 0.0
                           for j in range(context_dim)]
                          for i in range(context_dim)]
            arm.b = [0.0] * context_dim
            arm.theta = [0.0] * context_dim
            self._arms[op] = arm

    def select(self, input_size: int = 0,
               input_entropy: float = 0.0,
               input_type: str = "",
               prev_ewma_rewards: Optional[Dict[str, float]] = None,
               ) -> str:
        """选择最优操作符——LinUCB 决策。

        input_size, input_entropy, input_type: 当前待变异输入的特征。
        prev_ewma_rewards: 可选的外部 EWMA 值 (来自 adaptive_mutator)。
        """
        best_op = self._ops[0]
        best_ucb = -float('inf')

        for op_name in self._ops:
            arm = self._arms[op_name]
            ctx = self._build_context(
                op_name, input_size, input_entropy,
                input_type, prev_ewma_rewards)

            # 计算 UCB: θ^T·x + α·√(x^T·A^{-1}·x)
            # 先算 x^T·A^{-1} → 中间向量, 再点乘 x
            xTAinv = [0.0] * self._d
            for i in range(self._d):
                s = 0.0
                for j in range(self._d):
                    s += ctx[j] * arm.A_inv[j][i]
                xTAinv[i] = s

            variance = sum(xTAinv[i] * ctx[i] for i in range(self._d))
            if variance < 0:
                variance = 0.0

            predicted = sum(arm.theta[i] * ctx[i] for i in range(self._d))
            ucb = predicted + self._alpha * math.sqrt(max(0.0, variance) + 1e-6)

            if ucb > best_ucb:
                best_ucb = ucb
                best_op = op_name

        # 保存前次选择用于交互记录
        prev = self._last_selected
        self._last_selected = best_op
        self._prev_selected = prev
        return best_op

    def update(self, operator_name: str, reward: float) -> None:
        """用观察到的奖励更新所选操作符的线性模型。

        reward: [0, 1] 归一化覆盖奖励 (如 new_edges/total_edges)。
        """
        arm = self._arms.get(operator_name)
        if arm is None:
            return

        ctx = self._build_context(
            operator_name, 0, 0.0, "",
            None)

        # 更新 A^{-1} 和 b (增量 Sherman-Morrison, 或用简单重建)
        # 对低维度 (d≤10), 直接重建 A 并求逆更稳定
        arm.trials += 1
        arm.total_reward += reward
        arm.ewma_reward = 0.3 * reward + 0.7 * arm.ewma_reward
        arm.last_seen_at = time.monotonic()

        # 在线更新 A += x·x^T, b += reward·x
        for i in range(self._d):
            for j in range(self._d):
                arm.A[i][j] += ctx[i] * ctx[j]
            arm.b[i] += reward * ctx[i]

        # 重新求逆 (小矩阵, O(d^3) 可忽略)
        arm.A_inv = self._invert_matrix(arm.A)

        # 更新 theta = A^{-1}·b
        for i in range(self._d):
            s = 0.0
            for j in range(self._d):
                s += arm.A_inv[i][j] * arm.b[j]
            arm.theta[i] = s

        # 更新交互矩阵——使用前次选择, 非当前选择
        prev = self._prev_selected if hasattr(self, '_prev_selected') else ""
        if prev and prev != operator_name:
            self._interactions.record(prev, operator_name, reward)

        # 更新 arm 内部 pairwise 追踪
        if prev and prev != operator_name:
            prev_trials, prev_ewma = arm.pairwise_after.get(
                prev, (0, 0.5))
            arm.pairwise_after[prev] = (
                prev_trials + 1,
                0.3 * reward + 0.7 * prev_ewma,
            )

    def _build_context(self, op_name: str,
                        input_size: int, input_entropy: float,
                        input_type: str,
                        prev_ewma_rewards: Optional[Dict[str, float]],
                        ) -> List[float]:
        """构建操作符的上下文特征向量

        特征设计:
          [0]: 操作符自身的 EWMA 奖励 (归一化到 [0,1])
          [1]: 操作符的 ln(1 + trials) / ln(1 + max_trials) (经验权重)
          [2]: 输入特征: min(1.0, log2(input_size + 1) / 16)
          [3]: 交互特征: 前一操作符→当前操作符的联合 EWMA
          [4]: 输入熵特征: input_entropy / 8.0 (归一化)
        """
        arm = self._arms.get(op_name)
        if arm is None:
            return [0.0] * self._d

        max_trials = max((a.trials for a in self._arms.values()), default=1)

        ctx = [0.0] * self._d
        # f0: 自身 EWMA
        ctx[0] = arm.ewma_reward
        # f1: 经验权重 (对数归一化)
        ctx[1] = math.log1p(arm.trials) / max(1.0, math.log1p(max_trials))
        # f2: 输入大小特征
        ctx[2] = min(1.0, math.log2(max(1, input_size + 1)) / 16.0)
        # f3: 交互特征——使用前次选择
        prev = self._prev_selected if hasattr(self, '_prev_selected') else ""
        if prev:
            ctx[3] = self._interactions.get_interaction(prev, op_name)
        else:
            ctx[3] = 0.5
        # f4: 输入熵
        ctx[4] = min(1.0, max(0.0, input_entropy / 8.0))

        return ctx

    @staticmethod
    def _invert_matrix(A: List[List[float]]) -> List[List[float]]:
        """小矩阵求逆 (d×d, d≤10)——高斯消元 + 部分主元"""
        n = len(A)
        # 构建增广矩阵 [A | I]
        aug = [row[:] + [1.0 if i == j else 0.0 for j in range(n)]
                for i, row in enumerate(A)]

        for col in range(n):
            # 部分主元: 找该列绝对值最大的行
            pivot = col
            max_val = abs(aug[col][col])
            for row in range(col + 1, n):
                if abs(aug[row][col]) > max_val:
                    max_val = abs(aug[row][col])
                    pivot = row
            if max_val < 1e-12:
                # 零主元: 矩阵奇异, 跳过此列——不对应行做归一化
                # 在d≤10+λ正则化下几乎不可能触发, 但保留防御
                continue
            if pivot != col:
                aug[col], aug[pivot] = aug[pivot], aug[col]

            pivot_val = aug[col][col]
            for j in range(2 * n):
                aug[col][j] /= pivot_val

            for row in range(n):
                if row == col:
                    continue
                factor = aug[row][col]
                for j in range(2 * n):
                    aug[row][j] -= factor * aug[col][j]

        # 提取右半部分
        return [[aug[i][n + j] for j in range(n)] for i in range(n)]

    # 诊断

    def interaction_report(self) -> Dict[Tuple[str, str], float]:
        """返回所有操作符对的交互 EWMA, 用于诊断和可视化"""
        return {
            key: ewma for key, (_, ewma) in self._interactions._cells.items()
        }

    def best_chain(self, length: int = 3) -> List[str]:
        """贪心搜索最优操作符序列——用于指导多步变异策略"""
        if not self._ops:
            return []
        chain = [self._ops[0]]
        for _ in range(length - 1):
            candidates = [
                (op, self._interactions.get_interaction(chain[-1], op))
                for op in self._ops if op != chain[-1]
            ]
            if not candidates:
                break
            best = max(candidates, key=lambda x: x[1])
            chain.append(best[0])
        return chain

    def stats(self) -> Dict[str, Any]:
        return {
            "operators": len(self._ops),
            "total_selections": sum(a.trials for a in self._arms.values()),
            "interactions_tracked": len(self._interactions._cells),
            "arms": {
                name: {
                    "trials": arm.trials,
                    "ewma": round(arm.ewma_reward, 4),
                    "theta_norm": round(
                        math.sqrt(sum(t * t for t in arm.theta)), 4),
                }
                for name, arm in self._arms.items()
            },
        }

    def reset(self) -> None:
        for arm in self._arms.values():
            arm.trials = 0
            arm.ewma_reward = 0.5
            arm.total_reward = 0.0
            arm.b = [0.0] * self._d
            arm.theta = [0.0] * self._d
            for i in range(self._d):
                for j in range(self._d):
                    arm.A[i][j] = self._lambda if i == j else 0.0
                    arm.A_inv[i][j] = 1.0 / self._lambda if i == j else 0.0
        self._interactions._cells.clear()
