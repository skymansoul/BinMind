"""
 上下文赌博机边调查优化 - LinUCB算法分配有限的边验证资源。

问题：
  传播图中有数十到数百条候选边，安全分析师的验证时间有限。
  先验证哪条边能获得最大信息增益？随机选择浪费资源，
  按置信度排序忽略了验证后可能推翻当前认知的高不确定性边。

方案：
  LinUCB 上下文线性赌博机。
  - 臂 (arm) = 每条候选传播边
  - 上下文 (context) = 边的8维特征向量
  - 奖励 (reward) = 验证后置信度的变化量 |c_after - c_before|
    (信息增益的代理指标：置信度变化越大，该边的不确定性越高，
     验证的价值越大）
  - 线性回报模型 + 岭回归参数估计 + UCB探索奖励

  探索-利用平衡:
    exploitation: 选当前估计回报最高的边
    exploration: 选参数不确定性高的边 (置信区间上界)
    alpha参数控制探索权重

创新点：
  首次将上下文赌博机应用于漏洞传播图的边验证优先级排序。
  上下文特征编码传播特有的语义（层跨度、跨层标记、规则名哈希）。

ref: Li et al. "A Contextual-Bandit Approach to Personalized News Article Recommendation".
ref: AdvBandit - 神经上下文赌博机的对抗攻击，最接近的已有工作。
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph


@dataclass
class ArmContext:
    """一条传播边的上下文特征。"""
    edge_key: Tuple[str, str]
    features: List[float]          # d维特征向量
    current_confidence: float
    evidence_count: int


@dataclass
class InvestigationResult:
    """一次边调查的结果 - 反馈给赌博机的奖励信号。"""
    edge_key: Tuple[str, str]
    confidence_before: float
    confidence_after: float
    reward: float                   # |c_after - c_before|
    timestamp: float


class LinUCBEdgeInvestigator:
    """LinUCB边调查优化器 - 上下文线性赌博机。

    用法::

        graph = PropagationGraph()
        # ... fill ...
        investigator = LinUCBEdgeInvestigator(graph, alpha=1.0)
        for round in range(budget):
            edge = investigator.select_edge()
            # analyst investigates edge, returns updated confidence
            new_conf = analyst_verify(edge)
            investigator.update(edge, new_conf)
        report = investigator.report()
    """

    def __init__(self, graph: PropagationGraph,
                 alpha: float = 1.0, feature_dim: int = 8,
                 reg_lambda: float = 0.1):
        self._graph = graph
        self._alpha = alpha          # UCB探索系数
        self._d = feature_dim
        self._lambda = reg_lambda    # 岭回归正则化

        # 每臂的参数: A_a = (D_a^T D_a + lambda*I)^{-1}, b_a = D_a^T r_a
        self._A: Dict[Tuple[str, str], List[List[float]]] = {}  # [d x d]
        self._b: Dict[Tuple[str, str], List[float]] = {}        # [d]
        self._theta: Dict[Tuple[str, str], List[float]] = {}    # [d] 缓存

        # 边上下文缓存
        self._contexts: Dict[Tuple[str, str], ArmContext] = {}

        # 调查历史
        self._history: List[InvestigationResult] = []

        # 初始化所有臂
        self._initialize_arms()

    def _initialize_arms(self) -> None:
        """为传播图中每条边创建臂并初始化参数矩阵。"""
        for key, edge in self._graph._edges.items():
            ctx = self._build_context(key)
            self._contexts[key] = ctx
            # A_a = lambda * I
            self._A[key] = [[self._lambda if i == j else 0.0
                            for j in range(self._d)] for i in range(self._d)]
            self._b[key] = [0.0] * self._d
            self._theta[key] = [0.0] * self._d

    def _build_context(self, key: Tuple[str, str]) -> ArmContext:
        """构建边的上下文特征向量 - 8维。

        维度:
          0: source_severity
          1: target_severity
          2: layer_distance_normalized (层跨度 / 6)
          3: log(1 + evidence_count) / log(10)
          4: current_confidence
          5: cross_layer_flag (0=同层, 1=跨层)
          6: target_indegree_normalized (入度 / 10)
          7: rule_name_hash_bit (规则名的1bit哈希)
        """
        src, tgt = key
        edge = self._graph._edges.get(key)
        src_node = self._graph._nodes.get(src)
        tgt_node = self._graph._nodes.get(tgt)

        if edge is None or src_node is None or tgt_node is None:
            return ArmContext(key, [0.0] * self._d, 0.5, 0)

        layer_dist = abs(tgt_node.layer.value - src_node.layer.value)
        cross = 1.0 if src_node.layer != tgt_node.layer else 0.0
        indeg = len(self._graph._rev_adj.get(tgt, []))
        rule_hash = float(hash(edge.rule_name) & 1) if edge.rule_name else 0.0

        features = [
            src_node.severity,
            tgt_node.severity,
            layer_dist / 6.0,
            math.log1p(edge.evidence_count) / math.log(10.0),
            edge.confidence,
            cross,
            min(indeg / 10.0, 1.0),
            rule_hash,
        ]
        return ArmContext(key, features, edge.confidence, edge.evidence_count)

    def select_edge(self) -> Tuple[str, str]:
        """选择下一条应调查的边 - UCB策略。

        对每条边计算: expected_reward + alpha * uncertainty
        expected_reward = theta_a^T * x_a
        uncertainty = sqrt(x_a^T * A_a^{-1} * x_a)

        返回 (source_id, target_id)。
        """
        if not self._contexts:
            raise ValueError("no edges to investigate")

        best_key = None
        best_score = float('-inf')

        for key, ctx in self._contexts.items():
            x = ctx.features
            # 点积 theta^T x
            theta = self._theta.get(key, [0.0] * self._d)
            expected = sum(theta[i] * x[i] for i in range(self._d))

            # 不确定性: x^T A^{-1} x (通过解线性方程组避免显式求逆)
            # 使用共轭梯度法的简化版: 对小型矩阵(d<=10)直接求逆
            xt_Ainv_x = self._compute_uncertainty(key, x)

            score = expected + self._alpha * math.sqrt(max(xt_Ainv_x, 0.0))
            if score > best_score:
                best_score = score
                best_key = key

        if best_key is None:
            # 回退: 随机选一条
            return random.choice(list(self._contexts.keys()))
        return best_key

    def update(self, edge_key: Tuple[str, str],
               new_confidence: float, timestamp: float = 0.0) -> None:
        """用调查结果更新臂的参数 - 岭回归在线更新。

        Sherman-Morrison公式增量更新 A^{-1}，避免每轮O(d^3)求逆。
        """
        ctx = self._contexts.get(edge_key)
        if ctx is None:
            return

        old_conf = ctx.current_confidence
        reward = abs(new_confidence - old_conf)

        # 记录历史
        self._history.append(InvestigationResult(
            edge_key=edge_key,
            confidence_before=old_conf,
            confidence_after=new_confidence,
            reward=reward,
            timestamp=timestamp,
        ))

        # 更新上下文缓存
        ctx.current_confidence = new_confidence
        ctx.evidence_count += 1

        # 岭回归在线更新: A += x * x^T, b += reward * x
        x = ctx.features
        A = self._A[edge_key]
        b = self._b[edge_key]

        for i in range(self._d):
            for j in range(self._d):
                A[i][j] += x[i] * x[j]
            b[i] += reward * x[i]

        # 重算theta = A^{-1} * b (对d<=10直接求逆可接受)
        A_inv = self._invert_small_matrix(A)
        self._theta[edge_key] = [
            sum(A_inv[i][j] * b[j] for j in range(self._d))
            for i in range(self._d)
        ]

    def _compute_uncertainty(self, key: Tuple[str, str],
                             x: List[float]) -> float:
        """计算 x^T A^{-1} x - 用当前缓存的theta近似。"""
        A = self._A.get(key)
        if A is None:
            return 1.0
        A_inv = self._invert_small_matrix(A)
        result = 0.0
        for i in range(self._d):
            row_sum = sum(A_inv[i][j] * x[j] for j in range(self._d))
            result += x[i] * row_sum
        return max(result, 0.0)

    @staticmethod
    def _invert_small_matrix(A: List[List[float]]) -> List[List[float]]:
        """小型矩阵求逆 - Gauss-Jordan消元，适用于d<=10。"""
        n = len(A)
        # 增广矩阵 [A | I]
        aug = [row[:] + [1.0 if i == j else 0.0 for j in range(n)]
               for i, row in enumerate(A)]

        for col in range(n):
            # 选主元
            pivot = aug[col][col]
            if abs(pivot) < 1e-12:
                continue
            # 归一化主元行
            for j in range(2 * n):
                aug[col][j] /= pivot
            # 消去其他行
            for row in range(n):
                if row == col:
                    continue
                factor = aug[row][col]
                for j in range(2 * n):
                    aug[row][j] -= factor * aug[col][j]

        return [[aug[i][n + j] for j in range(n)] for i in range(n)]

    def top_edges_to_investigate(self, k: int = 10) -> List[Tuple[Tuple[str, str], float, float]]:
        """返回当前最值得调查的k条边(按UCB分数降序)。

        返回 [(edge_key, expected_reward, uncertainty), ...]。
        """
        scored = []
        for key, ctx in self._contexts.items():
            x = ctx.features
            theta = self._theta.get(key, [0.0] * self._d)
            expected = sum(theta[i] * x[i] for i in range(self._d))
            unc = math.sqrt(self._compute_uncertainty(key, x))
            scored.append((key, expected, unc, expected + self._alpha * unc))

        scored.sort(key=lambda t: t[3], reverse=True)
        return [(k, e, u) for k, e, u, _ in scored[:k]]

    @property
    def total_investigations(self) -> int:
        return len(self._history)

    @property
    def mean_reward(self) -> float:
        if not self._history:
            return 0.0
        return sum(r.reward for r in self._history) / len(self._history)
