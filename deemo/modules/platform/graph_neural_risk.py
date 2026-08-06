"""
DAG消息传递风险预测 -- 有向无环图感知的图神经网络用于传播风险评分。

问题：
  RiskScorer使用PageRank风格的迭代评分，权重固定(0.4自身+0.6传播)。
  忽略了传播动力学的层间异质性。

方案：
  DAG感知的消息传递神经网络(MPNN)，层特定变换矩阵 + 边置信度加权聚合。
  1. 节点嵌入: 10维手工特征 -> W_embed -> h0 (ReLU)
  2. 消息传递(2轮): 仅沿DAG低层->高层, 边置信度为消息权重
  3. 读出: sigmoid(W_readout * h_final + b)
  4. 全参数训练: 解析梯度经ReLU反向传播至W_msg, W_update, W_embed

ref: Gilmer et al. (ICML 2017) "Neural Message Passing for Quantum Chemistry".
"""

from __future__ import annotations

import math
import random
from typing import Any, Dict, List, Optional, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph


class DAGMessagePassingRisk:
    """DAG感知消息传递风险预测器。"""

    def __init__(self, hidden_dim: int = 16, n_mp_layers: int = 2):
        self._h = hidden_dim
        self._n_layers = n_mp_layers
        self._input_dim = 10
        n_layers_count = len(PlatformLayer)

        self._W_msg: List[List[List[float]]] = []
        self._W_update: List[List[List[float]]] = []
        self._W_readout: List[float] = []
        self._W_embed: List[List[float]] = []
        self._b_readout: float = 0.0
        self._fitted = False

        self._init_weights(n_layers_count)

    def _init_weights(self, n_layers: int) -> None:
        h, d_in = self._h, self._input_dim
        for _ in range(self._n_layers):
            w_msg, w_upd = [], []
            for _ in range(n_layers):
                scale = math.sqrt(2.0 / (h + h))
                w_msg.append([[random.gauss(0, scale) for _ in range(h)] for _ in range(h)])
                w_upd.append([[random.gauss(0, scale) for _ in range(h)] for _ in range(h)])
            self._W_msg.append(w_msg)
            self._W_update.append(w_upd)
        scale_e = math.sqrt(2.0 / (d_in + h))
        self._W_embed = [[random.gauss(0, scale_e) for _ in range(h)] for _ in range(d_in)]
        self._W_readout = [random.gauss(0, 0.1) for _ in range(h)]

    def _node_features(self, graph: PropagationGraph, node_id: str) -> List[float]:
        node = graph._nodes[node_id]
        indeg = len(graph._rev_adj.get(node_id, []))
        outdeg = len(graph._adj.get(node_id, []))
        cross_in = sum(1 for s in graph._rev_adj.get(node_id, [])
                      if s in graph._nodes and graph._nodes[s].layer != node.layer)
        cross_out = sum(1 for t in graph._adj.get(node_id, [])
                       if t in graph._nodes and graph._nodes[t].layer != node.layer)
        total = indeg + outdeg
        cross_ratio = (cross_in + cross_out) / max(total, 1)
        layer_oh = [0.0] * 6
        if 0 <= node.layer.value < 6:
            layer_oh[node.layer.value] = 1.0
        return [node.severity,
                math.log1p(indeg) / math.log1p(max(graph.node_count, 1)),
                math.log1p(outdeg) / math.log1p(max(graph.node_count, 1)),
                cross_ratio] + layer_oh

    def _forward_with_cache(self, graph: PropagationGraph):
        """前向传播并缓存所有中间值供反向传播使用。

        返回 (final_embeddings, cache):
          cache = {
            'nodes': [nid, ...],
            'features': {nid: vec},
            'h0_pre': {nid: [pre-ReLU]},  # 嵌入层预激活
            'h0': {nid: [after-ReLU]},      # 嵌入层输出
            'rounds': [
              {  # round 0
                'pre_act': {nid: [pre-ReLU]},   # W_update@h + msg 的预激活
                'msg_agg': {nid: [aggregated]},
                'msg_count': {nid: int},
                'sources': {nid: [(src_id, conf), ...]},
                'h_out': {nid: [after-ReLU]},
              },
              ...
            ]
          }
        """
        nodes = list(graph._nodes.keys())
        cache = {'nodes': nodes, 'features': {}, 'h0_pre': {}, 'h0': {},
                 'rounds': []}

        # 嵌入层
        for nid in nodes:
            x = self._node_features(graph, nid)
            cache['features'][nid] = x
            pre = [sum(self._W_embed[j][i] * x[j] for j in range(self._input_dim))
                   for i in range(self._h)]
            cache['h0_pre'][nid] = pre
            cache['h0'][nid] = [max(0.0, v) for v in pre]

        h_current = {nid: list(cache['h0'][nid]) for nid in nodes}

        for mp_round in range(self._n_layers):
            round_cache = {'pre_act': {}, 'msg_agg': {}, 'msg_count': {},
                          'sources': {}, 'h_out': {}}
            h_new = {}

            for nid in nodes:
                layer_idx = graph._nodes[nid].layer.value
                W_msg = self._W_msg[mp_round][layer_idx]
                W_upd = self._W_update[mp_round][layer_idx]

                msg_agg = [0.0] * self._h
                msg_count = 0
                sources = []
                for src_id in graph._rev_adj.get(nid, []):
                    edge = graph._edges.get((src_id, nid))
                    if edge is None:
                        continue
                    src_emb = h_current.get(src_id)
                    if src_emb is None:
                        continue
                    sources.append((src_id, edge.confidence))
                    for i in range(self._h):
                        src_t = sum(W_msg[i][j] * src_emb[j] for j in range(self._h))
                        msg_agg[i] += edge.confidence * src_t
                    msg_count += 1

                if msg_count > 0:
                    for i in range(self._h):
                        msg_agg[i] /= msg_count

                round_cache['sources'][nid] = sources
                round_cache['msg_agg'][nid] = list(msg_agg)
                round_cache['msg_count'][nid] = msg_count

                old_t = [sum(W_upd[i][j] * h_current[nid][j] for j in range(self._h))
                        for i in range(self._h)]
                pre_act = [old_t[i] + msg_agg[i] for i in range(self._h)]
                round_cache['pre_act'][nid] = pre_act
                h_new[nid] = [max(0.0, v) for v in pre_act]

            round_cache['h_out'] = h_new
            cache['rounds'].append(round_cache)
            h_current = h_new

        return h_current, cache

    def fit(self, graph: PropagationGraph,
            risk_labels: Optional[Dict[str, float]] = None,
            n_epochs: int = 500, lr: float = 0.01) -> Dict[str, float]:
        """训练所有参数: W_embed, W_msg, W_update, W_readout。

        解析梯度经ReLU反向传播至全部权重矩阵。"""
        nodes = list(graph._nodes.keys())
        if not nodes:
            return {"error": "empty graph"}
        if risk_labels is None:
            risk_labels = {nid: graph._nodes[nid].severity for nid in nodes}

        final_loss = 0.0
        n_nodes = len(nodes)
        n_layers_count = len(PlatformLayer)
        h = self._h

        for epoch in range(n_epochs):
            lr_t = lr / (1.0 + 0.001 * epoch)
            embeddings, cache = self._forward_with_cache(graph)

            # 累积梯度
            grad_readout = [0.0] * h
            grad_b = 0.0
            grad_embed = [[0.0] * h for _ in range(self._input_dim)]
            grad_msg = [[[[0.0] * h for _ in range(h)] for _ in range(n_layers_count)]
                       for _ in range(self._n_layers)]
            grad_update = [[[[0.0] * h for _ in range(h)] for _ in range(n_layers_count)]
                          for _ in range(self._n_layers)]

            total_loss = 0.0
            # 各节点的dL/d(h_final)
            dL_dh: Dict[str, List[float]] = {nid: [0.0] * h for nid in nodes}

            for nid in nodes:
                emb = embeddings[nid]
                logit = sum(self._W_readout[i] * emb[i] for i in range(h)) + self._b_readout
                pred = 1.0 / (1.0 + math.exp(-logit))
                target = risk_labels.get(nid, 0.5)
                err = pred - target
                total_loss += err ** 2

                dsig = err * pred * (1.0 - pred)
                for i in range(h):
                    grad_readout[i] += dsig * emb[i]
                    dL_dh[nid][i] = dsig * self._W_readout[i]
                grad_b += dsig

            # 反向传播通过消息传递层 (从最后一层向前)
            for mp_round in range(self._n_layers - 1, -1, -1):
                rcache = cache['rounds'][mp_round]
                dL_dh_prev: Dict[str, List[float]] = {nid: [0.0] * h for nid in nodes}
                h_in = cache['h0'] if mp_round == 0 else cache['rounds'][mp_round - 1]['h_out']

                for nid in nodes:
                    layer_idx = graph._nodes[nid].layer.value
                    dh = dL_dh[nid]
                    pre_act = rcache['pre_act'][nid]
                    # dL/d(pre_act) = dL/dh * ReLU'(pre_act)
                    dpre = [dh[i] if pre_act[i] > 0 else 0.0 for i in range(h)]

                    # W_update 梯度: dL/d(W_update[i][j]) = dpre[i] * h_in[nid][j]
                    h_old = h_in.get(nid, [0.0] * h)
                    for i in range(h):
                        for j in range(h):
                            grad_update[mp_round][layer_idx][i][j] += dpre[i] * h_old[j]

                    # 累积 dL/d(h_old): W_update^T @ dpre
                    W_upd = self._W_update[mp_round][layer_idx]
                    for j in range(h):
                        s = sum(W_upd[i][j] * dpre[i] for i in range(h))
                        dL_dh_prev[nid][j] += s

                    # W_msg 梯度: 消息聚合的梯度
                    sources = rcache['sources'][nid]
                    msg_count = max(rcache['msg_count'][nid], 1)
                    W_msg = self._W_msg[mp_round][layer_idx]
                    for src_id, conf in sources:
                        src_emb = h_in.get(src_id, [0.0] * h)
                        for i in range(h):
                            for j in range(h):
                                g = dpre[i] * conf * src_emb[j] / msg_count
                                grad_msg[mp_round][layer_idx][i][j] += g
                        # dL/d(src_emb) 经 W_msg^T 回流（对每个 j，累加所有 i 的贡献）
                        for j in range(h):
                            s = sum(conf * W_msg[i2][j] * dpre[i2] / msg_count
                                   for i2 in range(h))
                            dL_dh_prev[src_id][j] += s

                dL_dh = dL_dh_prev

            # 嵌入层梯度
            for nid in nodes:
                x = cache['features'][nid]
                dh0 = dL_dh[nid]
                h0_pre = cache['h0_pre'][nid]
                for i in range(h):
                    if h0_pre[i] <= 0:
                        continue
                    for j in range(self._input_dim):
                        grad_embed[j][i] += dh0[i] * x[j]

            # SGD更新所有参数
            for i in range(h):
                self._W_readout[i] -= lr_t * grad_readout[i] / n_nodes
            self._b_readout -= lr_t * grad_b / n_nodes
            for j in range(self._input_dim):
                for i in range(h):
                    self._W_embed[j][i] -= lr_t * grad_embed[j][i] / n_nodes
            for mp_round in range(self._n_layers):
                for l_idx in range(n_layers_count):
                    for i in range(h):
                        for j in range(h):
                            self._W_msg[mp_round][l_idx][i][j] -= (
                                lr_t * grad_msg[mp_round][l_idx][i][j] / n_nodes)
                            self._W_update[mp_round][l_idx][i][j] -= (
                                lr_t * grad_update[mp_round][l_idx][i][j] / n_nodes)

            final_loss = total_loss / n_nodes

        self._fitted = True
        return {"final_loss": round(final_loss, 6), "epochs": n_epochs}

    def predict(self, graph: PropagationGraph) -> Dict[str, float]:
        embeddings, _ = self._forward_with_cache(graph)
        predictions: Dict[str, float] = {}
        for nid, emb in embeddings.items():
            logit = sum(self._W_readout[i] * emb[i] for i in range(self._h)) + self._b_readout
            predictions[nid] = round(1.0 / (1.0 + math.exp(-logit)), 4)
        return predictions
