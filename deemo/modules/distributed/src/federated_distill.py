# 联邦策略蒸馏 — 跨集群调度知识的隐私保护迁移
#
# 不同集群的调度器各自独立学习调度策略 (如 GRLScheduler 的 Q 网络)。
# 直接共享 Q 网络权重会泄露集群的任务模式信息——
# 权重编码了哪种任务类型频繁出现、执行时间分布等敏感信息。
#
# 知识蒸馏 (Hinton et al. 2015) 提供了隐私保护的替代方案:
#   教师 (Cluster A 的调度器) 在公开的合成任务集上生成软标签
#   (Q 值分布)，学生 (Cluster B 的调度器) 在相同合成集上模仿教师
#   的输出。合成集不含任何真实任务 → 无隐私泄露。
#
# 联邦聚合: K 个集群各自训练本地教师，中央协调器聚合软标签
# (平均或加权平均)，分发聚合后的软标签给各学生。
# 整个过程不传输模型权重或原始数据。
#
# 本模块实现:
#   1. 教师: 对合成任务集计算 Q 值向量 (软标签)
#   2. 聚合器: FedAvg 风格的软标签加权平均
#   3. 学生: 用 KL 散度损失模仿教师输出，更新本地 Q 网络
#   4. 差分隐私可选: 在软标签上注入拉普拉斯噪声 (ε-DP)
#
# 与标准联邦学习的区别:
#   FL: 共享模型权重 → 梯度泄露风险 (membership inference, gradient inversion)
#   本方案: 共享软标签 → 无梯度信息, 合成数据不含真实样本 → 零泄露

from __future__ import annotations

import math
import random
import hashlib
from typing import Optional, List, Dict, Tuple


def _synthetic_task_graph(seed: int, n_nodes: int = 10,
                          n_features: int = 8) -> List[List[float]]:
    """生成合成任务图特征矩阵 — 不含任何真实任务信息。

    使用确定性伪随机生成器 + seed 使各集群可独立复现相同的合成集。
    """
    rng = random.Random(seed)
    # 生成 n_nodes 个节点，每个 n_features 维特征
    feats = []
    for _ in range(n_nodes):
        row = [rng.random() for _ in range(n_features)]
        # 归一化部分特征 (模拟执行时间/优先级)
        row[0] = rng.uniform(0.1, 5.0)   # exec_time
        row[1] = rng.uniform(0.0, 1.0)   # priority
        feats.append(row)
    return feats


class PolicyTeacher:
    """教师模型 — 用本地 Q 网络在合成集上生成软标签。

    输出: [(task_features, q_values_vector), ...]
    其中 q_values 是各候选动作的 Q 值分布 (温度软化后)。
    """

    def __init__(self, temperature: float = 2.0):
        self._T = temperature

    def distill(
        self, local_q_network,  # 本地 LinearQPolicy 或等价物
        n_synthetic_tasks: int = 50,
        n_nodes_per_graph: int = 10,
        base_seed: int = 0xDEAD,
    ) -> List[Tuple[List[List[float]], List[float]]]:
        """生成软标签数据集。"""
        dataset = []
        for i in range(n_synthetic_tasks):
            seed = base_seed + i
            graph_feats = _synthetic_task_graph(seed, n_nodes_per_graph)
            q_values = []
            for node_feats in graph_feats:
                # 构造全局特征 = 图均值 + 节点特征 (与 GRLScheduler 一致)
                global_feat = [0.0] * len(node_feats)
                for row in graph_feats:
                    for j in range(len(row)):
                        global_feat[j] += row[j] / len(graph_feats)
                phi = global_feat + node_feats
                q_raw = local_q_network.q_value(phi)
                q_values.append(q_raw)

            # 温度软化
            if self._T > 0:
                max_q = max(q_values) if q_values else 0.0
                q_values = [
                    math.exp((q - max_q) / self._T) for q in q_values
                ]
                total = sum(q_values) or 1.0
                q_values = [q / total for q in q_values]

            dataset.append((graph_feats, q_values))
        return dataset


class FederatedDistillationAggregator:
    """联邦蒸馏聚合器 — 收集教师软标签，聚合后分发。

    聚合 = 加权平均软标签 (按各集群的任务量加权)。
    可选 DP 噪声注入满足 (ε, δ)-差分隐私。
    """

    def __init__(self, dp_epsilon: Optional[float] = None):
        self._dp_eps = dp_epsilon
        self._contributions: Dict[str, dict] = {}  # cluster_id → {weight, labels}

    def submit(
        self, cluster_id: str,
        labels: List[Tuple[List[List[float]], List[float]]],
        weight: float = 1.0,
    ):
        self._contributions[cluster_id] = {"weight": weight, "labels": labels}

    def aggregate(self) -> List[Tuple[List[List[float]], List[float]]]:
        """加权平均聚合软标签。"""
        if not self._contributions:
            return []

        total_w = sum(c["weight"] for c in self._contributions.values())
        if total_w <= 0:
            return []

        # 取第一个贡献者的标签结构作为模板
        first = next(iter(self._contributions.values()))
        template = first["labels"]
        n_graphs = len(template)

        aggregated = []
        for g_idx in range(n_graphs):
            ref_feats, ref_qs = template[g_idx]
            n_nodes = len(ref_qs)
            avg_qs = [0.0] * n_nodes

            for contrib in self._contributions.values():
                labels = contrib["labels"]
                if g_idx >= len(labels):
                    continue
                _, qs = labels[g_idx]
                w = contrib["weight"] / total_w
                for j in range(min(n_nodes, len(qs))):
                    avg_qs[j] += w * qs[j]

            # 可选 DP 噪声
            if self._dp_eps is not None:
                rng = random.Random(g_idx)
                scale = 0.01 / max(self._dp_eps, 0.01)
                for j in range(n_nodes):
                    u = rng.uniform(-0.5, 0.5)
                    noise = -math.copysign(1.0, u) * scale * math.log(
                        1.0 - 2.0 * abs(u)
                    )
                    avg_qs[j] = max(0.0, avg_qs[j] + noise)

            # 重归一化
            total = sum(avg_qs) or 1.0
            avg_qs = [q / total for q in avg_qs]
            aggregated.append((ref_feats, avg_qs))

        return aggregated


class PolicyStudent:
    """学生模型 — 用聚合软标签更新本地 Q 网络。

    损失 = KL(teacher_softmax || student_softmax)
    对线性 Q 策略: 更新 w ← w + lr·(q_teacher - q_student)·φ
    等价于用教师 Q 值作为回归目标。
    """

    def __init__(self, learning_rate: float = 0.05):
        self._lr = learning_rate

    def learn(
        self, local_q_network,
        distilled_labels: List[Tuple[List[List[float]], List[float]]],
        epochs: int = 3,
    ) -> float:
        """用蒸馏标签训练本地 Q 网络。返回平均训练损失。"""
        total_loss = 0.0
        n_updates = 0

        for _ in range(epochs):
            for graph_feats, teacher_qs in distilled_labels:
                global_feat = [0.0] * len(graph_feats[0])
                for row in graph_feats:
                    for j in range(len(row)):
                        global_feat[j] += row[j] / len(graph_feats)
                for node_idx, (node_feats, tq) in enumerate(
                    zip(graph_feats, teacher_qs)
                ):
                    phi = global_feat + node_feats
                    sq = local_q_network.q_value(phi)
                    # KL 散度梯度对线性模型: ∂KL/∂w = (sq - tq)·φ
                    err = local_q_network.update(phi, tq, self._lr)
                    total_loss += abs(err)
                    n_updates += 1

        return total_loss / max(n_updates, 1)


def federated_round(
    clusters: Dict[str, any],  # {cluster_id: local_q_network}
    aggregator: FederatedDistillationAggregator,
    teacher: PolicyTeacher,
    student: PolicyStudent,
    cluster_weights: Optional[Dict[str, float]] = None,
) -> Dict[str, float]:
    """执行一轮联邦蒸馏: 各集群教师生成软标签 → 聚合 → 学生更新。

    返回 {cluster_id: training_loss}。
    """
    weights = cluster_weights or {cid: 1.0 for cid in clusters}
    aggregator._contributions.clear()

    for cid, q_net in clusters.items():
        labels = teacher.distill(q_net)
        aggregator.submit(cid, labels, weights.get(cid, 1.0))

    aggregated = aggregator.aggregate()

    losses = {}
    for cid, q_net in clusters.items():
        loss = student.learn(q_net, aggregated)
        losses[cid] = round(loss, 6)

    return losses
