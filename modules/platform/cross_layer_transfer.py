"""
跨层迁移风险模型 — 领域自适应实现不同平台层间的风险知识迁移。

问题：
  固件层漏洞数据丰富（大量 CVE 和固件分析结果），但硬件/内核层标注稀缺。
  传统方案为每层独立训练风险模型 → 稀缺层模型欠拟合。

方案：
  对抗域适应——学习层不变的特征表示，使固件层训练的模型可迁移至硬件/内核层。
  1. 特征提取器 f：节点 → d维嵌入向量
  2. 风险预测器 r：嵌入向量 → 风险评分
  3. 层判别器 d：嵌入向量 → 平台层分类（对抗目标：让d无法区分来源层）

  训练目标：min L_risk - λ · L_domain_confusion
  → 特征嵌入在保留风险预测能力的同时混淆层判别器

与已有工作区分：
  DAM2P: 跨项目代码漏洞检测的域适应，处理的是AST/CFG特征
                      而非传播图跨层风险迁移。不涉及平台层的硬件/固件差异。
  本模块: 将对抗域适应引入跨平台层风险传播建模。
         层特定的语义差距（固件MMIO vs 内核系统调用 vs 硬件缓存时序）
         通过学习层不变的风险拓扑表征来桥接。

ref: Ganin et al. "Domain-Adversarial Training of Neural Networks" —
     对抗域适应的理论基础。
ref: DAM2P — 跨项目代码漏洞检测的域适应，最接近的已有工作。
"""

from __future__ import annotations

import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph, VulnNode


@dataclass
class NodeFeature:
    """节点特征向量 — 用于跨层迁移的输入表征。

    特征维度选择依据：
    - 图拓扑特征（入度、出度、PageRank近似值、聚类系数）
    - 层内语义特征（层类型、vuln_type的哈希、severity）
    - 跨层特征（跨层边数、层跨度、涉及的层类型数）

    共计 d 维（默认 d=16），维度选择是精度/过拟合权衡。
    """
    node_id: str
    layer: PlatformLayer
    vector: List[float] = field(default_factory=list)


class LayerInvariantEncoder:
    """层不变特征编码器 — 将不同平台层的节点映射到共享嵌入空间。

    使用简化的梯度反转层 (GRL) 实现对抗域适应。
    不依赖 PyTorch/TensorFlow——纯 NumPy 级实现，适配安全分析管线。
    核心是随机梯度下降的对抗训练循环，非深度学习框架的黑盒调用。
    """

    def __init__(self, embed_dim: int = 16, lambda_domain: float = 0.1):
        self._dim = embed_dim
        self._lambda = lambda_domain
        # 特征提取器权重: [d_input, d_embed]
        self._W_enc: List[List[float]] = []
        # 风险预测器权重: [d_embed, 1]
        self._W_risk: List[float] = []
        # 层判别器权重: [d_embed, n_layers]
        self._W_disc: List[List[float]] = []
        self._fitted = False

    def extract_features(self, graph: PropagationGraph) -> List[NodeFeature]:
        """从传播图中提取节点特征向量 — 不依赖学习的静态特征提取。

        提取以下特征（共16维）：
          0: severity (归一化严重度)
          1: log(1 + indegree)
          2: log(1 + outdegree)
          3: cross_layer_edge_ratio
          4: layer_value / 6 (层位置归一化)
          5: mean_neighbor_severity
          6: max_neighbor_severity
          7: clustering_coefficient_approx
          8-15: vuln_type哈希的8个bit
        """
        features: List[NodeFeature] = []
        n = graph.node_count
        if n == 0:
            return features

        for nid, node in graph._nodes.items():
            vec = [0.0] * self._dim

            indeg = len(graph._rev_adj.get(nid, []))
            outdeg = len(graph._adj.get(nid, []))

            cross_in = sum(1 for s in graph._rev_adj.get(nid, [])
                          if s in graph._nodes and graph._nodes[s].layer != node.layer)
            cross_out = sum(1 for t in graph._adj.get(nid, [])
                           if t in graph._nodes and graph._nodes[t].layer != node.layer)
            total_edges = indeg + outdeg
            cross_ratio = (cross_in + cross_out) / max(total_edges, 1)

            neighbor_sevs = []
            for s in graph._rev_adj.get(nid, []):
                if s in graph._nodes:
                    neighbor_sevs.append(graph._nodes[s].severity)
            for t in graph._adj.get(nid, []):
                if t in graph._nodes:
                    neighbor_sevs.append(graph._nodes[t].severity)

            mean_ns = sum(neighbor_sevs) / len(neighbor_sevs) if neighbor_sevs else 0.0
            max_ns = max(neighbor_sevs) if neighbor_sevs else 0.0

            # 聚类系数近似：邻居间的边数 / 邻居对的组合数
            neighbors = set(graph._rev_adj.get(nid, [])) | set(graph._adj.get(nid, []))
            neighbor_edges = 0
            for a in neighbors:
                for b in neighbors:
                    if a < b and (a, b) in graph._edges:
                        neighbor_edges += 1
            npairs = len(neighbors) * (len(neighbors) - 1) / 2.0
            clustering = neighbor_edges / max(npairs, 1.0)

            # vuln_type哈希的bit向量 (填充至dim)
            vt_hash = hash(node.vuln_type) & 0xFF
            n_bits = min(8, max(0, self._dim - 8))

            vec[0] = node.severity
            vec[1] = math.log1p(indeg) / math.log1p(max(n, 1))
            vec[2] = math.log1p(outdeg) / math.log1p(max(n, 1))
            vec[3] = cross_ratio
            vec[4] = node.layer.value / 6.0
            vec[5] = mean_ns
            vec[6] = max_ns
            vec[7] = clustering
            for bit in range(n_bits):
                vec[8 + bit] = float((vt_hash >> bit) & 1)

            features.append(NodeFeature(node_id=nid, layer=node.layer, vector=vec))

        return features

    def _compute_layer_adaptation_weights(self, graph: PropagationGraph
                                          ) -> Dict[int, float]:
        """计算层自适应对抗权重。

        创新：不同平台层需要不同的域混淆强度。
        跨层边密度高的层(KERNEL: 连接4个其他层)比密度低的层
        (SMART_CONTRACT: 仅被MALWARE连接)更难对齐——需要更强的梯度反转。
        权重 = cross_layer_edge_ratio(layer) 归一化至 [0.5, 1.5]。
        """
        layer_stats: Dict[int, Dict[str, float]] = {}
        for node in graph._nodes.values():
            lv = node.layer.value
            if lv not in layer_stats:
                layer_stats[lv] = {'total': 0, 'cross': 0}
        for (src, tgt) in graph._edges:
            s_node = graph._nodes.get(src)
            t_node = graph._nodes.get(tgt)
            if s_node and t_node:
                for nid, lv in [(src, s_node.layer.value), (tgt, t_node.layer.value)]:
                    if lv in layer_stats:
                        layer_stats[lv]['total'] += 1
                if s_node.layer != t_node.layer:
                    slv = s_node.layer.value; tlv = t_node.layer.value
                    if slv in layer_stats:
                        layer_stats[slv]['cross'] = layer_stats[slv]['cross'] + 1
                    if tlv in layer_stats:
                        layer_stats[tlv]['cross'] = layer_stats[tlv]['cross'] + 1

        weights = {}
        max_ratio = 0.0
        for lv, stats in layer_stats.items():
            ratio = stats['cross'] / max(stats['total'], 1)
            weights[lv] = ratio
            max_ratio = max(max_ratio, ratio)
        # 归一化到 [0.5, 1.5]
        for lv in weights:
            if max_ratio > 0:
                weights[lv] = 0.5 + (weights[lv] / max_ratio)
        return weights

    def fit(self, graph: PropagationGraph,
            risk_labels: Optional[Dict[str, float]] = None,
            n_iterations: int = 300,
            lr: float = 0.05) -> Dict[str, Any]:
        """对抗训练——学习层不变的特征嵌入(层自适应梯度反转)。

        若未提供 risk_labels，使用节点的 severity 作为弱监督信号。
        返回训练统计：{final_risk_loss, final_domain_confusion, n_layers_confused}。
        """
        features = self.extract_features(graph)
        if not features:
            return {"error": "no features extracted"}

        n_nodes = len(features)
        n_layers = len(PlatformLayer)

        # 权重初始化
        d = self._dim
        self._W_enc = [[random.gauss(0, 0.1) for _ in range(d)] for _ in range(d)]
        self._W_risk = [random.gauss(0, 0.1) for _ in range(d)]
        self._W_disc = [[random.gauss(0, 0.1) for _ in range(d)] for _ in range(n_layers)]

        labels_risk = risk_labels or {
            f.node_id: graph._nodes[f.node_id].severity for f in features
        }

        # 层自适应梯度反转权重：跨层边密度高的层需要更强的域混淆
        layer_weights = self._compute_layer_adaptation_weights(graph)

        risk_loss_final = 0.0
        domain_loss_final = 0.0

        for iteration in range(n_iterations):
            lr_t = lr / (1.0 + 0.005 * iteration)
            grad_enc = [[0.0] * d for _ in range(d)]
            grad_risk = [0.0] * d
            grad_disc = [[0.0] * d for _ in range(n_layers)]
            total_risk = 0.0
            total_domain = 0.0

            for feat in features:
                x = feat.vector
                # 编码
                emb = [0.0] * d
                for i in range(d):
                    s = sum(self._W_enc[i][j] * x[j] for j in range(d))
                    emb[i] = max(0.0, s)  # ReLU

                # 风险预测
                risk_pred = sum(self._W_risk[i] * emb[i] for i in range(d))
                risk_pred = 1.0 / (1.0 + math.exp(-risk_pred))  # sigmoid
                risk_true = labels_risk.get(feat.node_id, 0.5)
                risk_err = risk_pred - risk_true
                total_risk += risk_err ** 2

                # 风险梯度
                for i in range(d):
                    grad_risk[i] += 2.0 * risk_err * risk_pred * (1.0 - risk_pred) * emb[i]

                # 域判别（层分类）
                layer_logits = [0.0] * n_layers
                for l in range(n_layers):
                    layer_logits[l] = sum(self._W_disc[l][i] * emb[i] for i in range(d))
                # softmax
                max_logit = max(layer_logits)
                exps = [math.exp(ll - max_logit) for ll in layer_logits]
                sum_exps = sum(exps)
                probs = [e / sum_exps for e in exps]
                true_layer = feat.layer.value
                domain_err = probs[true_layer] - 1.0
                total_domain += abs(domain_err)

                # 域判别梯度（对抗方向：梯度反转）
                for l in range(n_layers):
                    target = 1.0 if l == true_layer else 0.0
                    err_l = probs[l] - target
                    for i in range(d):
                        grad_disc[l][i] += err_l * emb[i]

                # 编码器梯度 = 风险梯度 - λ * 域梯度（对抗）
                for i in range(d):
                    for j in range(d):
                        g_risk = grad_risk[i] * self._W_risk[i] * (1.0 if emb[i] > 0 else 0.0) * x[j]
                        g_domain = sum(grad_disc[l][i] for l in range(n_layers)) * (1.0 if emb[i] > 0 else 0.0) * x[j]
                        # 层自适应梯度反转：不同层用不同λ
                        layer_lambda = self._lambda * layer_weights.get(
                            feat.layer.value, 1.0)
                        grad_enc[i][j] += g_risk - layer_lambda * g_domain

            # SGD 更新
            for i in range(d):
                for j in range(d):
                    self._W_enc[i][j] -= lr_t * grad_enc[i][j] / n_nodes
                self._W_risk[i] -= lr_t * grad_risk[i] / n_nodes
            for l in range(n_layers):
                for i in range(d):
                    self._W_disc[l][i] -= lr_t * grad_disc[l][i] / n_nodes

            risk_loss_final = total_risk / n_nodes
            domain_loss_final = total_domain / n_nodes

        self._fitted = True
        return {
            "final_risk_loss": round(risk_loss_final, 6),
            "final_domain_confusion": round(domain_loss_final, 4),
            "embed_dim": d,
            "iterations": n_iterations,
        }

    def embed(self, node_feature: NodeFeature) -> List[float]:
        """将节点特征映射到层不变嵌入空间。需要先调用 fit()。"""
        d = self._dim
        if not self._W_enc:
            return node_feature.vector[:d]

        x = node_feature.vector
        emb = [0.0] * d
        for i in range(d):
            s = sum(self._W_enc[i][j] * x[j] for j in range(min(d, len(x))))
            emb[i] = max(0.0, s)
        return emb

    def transfer_risk(self, source_graph: PropagationGraph,
                      target_graph: PropagationGraph,
                      risk_labels: Optional[Dict[str, float]] = None,
                      ) -> Dict[str, float]:
        """在源图上训练，将风险模型迁移到目标图。

        返回 {target_node_id: predicted_risk}。
        """
        self.fit(source_graph, risk_labels)
        target_features = self.extract_features(target_graph)
        predictions: Dict[str, float] = {}

        for feat in target_features:
            emb = self.embed(feat)
            logit = sum(self._W_risk[i] * emb[i] for i in range(len(emb)))
            pred = 1.0 / (1.0 + math.exp(-logit))
            predictions[feat.node_id] = round(pred, 4)

        return predictions

    @property
    def is_fitted(self) -> bool:
        return self._fitted
