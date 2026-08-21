"""
 对比传播路径嵌入 - InfoNCE自监督学习传播路径的语义向量表示。

问题：\"哪些历史漏洞的传播模式与当前CVE最相似？\"传统关键词匹配无法捕捉
传播模式的结构语义。

方案：对比学习训练路径嵌入。正样本=同路径的两个增强视图(边dropout/置信度扰动/
路径截断)，负样本=批次内其他路径。编码器=MLP(12->64->d)->L2归一化。

与已有工作的区分：GraphCL/GRACE做图级/节点级对比学习；CVGAD做异常检测；
VGFL-SA攻击图联邦学习。本模块首次将对比学习应用于漏洞传播路径语义嵌入。

ref: Oord et al., Chen et al..
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph


@dataclass
class PathSample:
    """一条传播路径样本。"""
    node_ids: List[str]
    layer_sequence: List[int]       # 沿途的平台层序列
    confidences: List[float]        # 沿途边置信度序列
    severities: List[float]         # 沿途节点严重度序列
    length: int
    path_id: str = ""


class ContrastivePathEncoder:
    """对比传播路径编码器 - MLP架构, 输出L2归一化嵌入。

    用法::

        graph = PropagationGraph()
        encoder = ContrastivePathEncoder(embed_dim=32)
        encoder.extract_paths(graph, max_paths=200)
        encoder.fit(n_epochs=300, lr=0.01)
        # 相似性搜索
        similar = encoder.find_similar(query_path_id, top_k=5)
    """

    def __init__(self, embed_dim: int = 32, temperature: float = 0.07):
        self._d = embed_dim
        self._tau = temperature
        self._input_dim = 12  # 路径特征维度

        # 编码器权重 MLP: input_dim -> 64 -> embed_dim
        self._W1: List[List[float]] = []
        self._b1: List[float] = []
        self._W2: List[List[float]] = []
        self._b2: List[float] = []

        # 路径存储
        self._paths: List[PathSample] = []
        self._embeddings: Dict[str, List[float]] = {}  # path_id -> embedding
        self._fitted = False

        self._init_weights()

    def _init_weights(self) -> None:
        h = 64
        d_in = self._input_dim
        scale1 = math.sqrt(2.0 / (d_in + h))
        scale2 = math.sqrt(2.0 / (h + self._d))
        self._W1 = [[random.gauss(0, scale1) for _ in range(d_in)] for _ in range(h)]
        self._b1 = [0.0] * h
        self._W2 = [[random.gauss(0, scale2) for _ in range(h)] for _ in range(self._d)]
        self._b2 = [0.0] * self._d

    def extract_paths(self, graph: PropagationGraph,
                      max_paths: int = 200, min_length: int = 2) -> int:
        """从传播图中提取传播路径样本。

        对所有(source, target)对做DFS，收集深度<=5的路径。
        返回收集到的路径数。
        """
        self._paths = []
        nodes = list(graph._nodes.keys())

        # 采样起始节点对以避免O(N^2)爆炸
        sources = nodes[:min(len(nodes), 30)]
        targets = nodes[:min(len(nodes), 30)]

        for src in sources:
            for tgt in targets:
                if src == tgt:
                    continue
                if len(self._paths) >= max_paths:
                    break
                raw_paths = graph.find_propagation_paths(
                    src, tgt, max_paths=1, max_depth=5,
                )
                for rp in raw_paths:
                    if len(rp) < min_length:
                        continue
                    layers = []
                    confs = []
                    sevs = []
                    for i, nid in enumerate(rp):
                        node = graph._nodes.get(nid)
                        if node:
                            layers.append(node.layer.value)
                            sevs.append(node.severity)
                        if i < len(rp) - 1:
                            edge = graph._edges.get((rp[i], rp[i+1]))
                            confs.append(edge.confidence if edge else 0.5)
                    pid = f"{src[:8]}_{tgt[:8]}_{len(self._paths)}"
                    self._paths.append(PathSample(
                        node_ids=rp, layer_sequence=layers,
                        confidences=confs, severities=sevs,
                        length=len(rp), path_id=pid,
                    ))
                if len(self._paths) >= max_paths:
                    break
            if len(self._paths) >= max_paths:
                break

        return len(self._paths)

    def _path_to_features(self, path: PathSample) -> List[float]:
        """将路径编码为12维特征向量。

        维度:
          0-3: 层序列统计 (min, max, mean, std of layer values)
          4-6: 置信度统计 (min, max, mean)
          7-9: 严重度统计 (min, max, mean)
          10: 路径长度(归一化)
          11: 层跨度 (max_layer - min_layer)
        """
        layers = path.layer_sequence
        confs = path.confidences
        sevs = path.severities

        def stats(vals, default=0.0):
            if not vals:
                return default, default, default, default
            m = sum(vals) / len(vals)
            var = sum((v - m)**2 for v in vals) / max(len(vals), 1)
            return min(vals), max(vals), m, math.sqrt(var)

        lmin, lmax, lmean, lstd = stats(layers, 0.0)
        cmin, cmax, cmean, _ = stats(confs, 0.5)
        smin, smax, smean, _ = stats(sevs, 0.5)

        return [
            lmin / 6.0, lmax / 6.0, lmean / 6.0, min(lstd / 2.0, 1.0),
            cmin, cmax, cmean,
            smin, smax, smean,
            min(path.length / 10.0, 1.0),
            (lmax - lmin) / 6.0,
        ]

    def _encode(self, features: List[float]) -> List[float]:
        """MLP编码: input_dim -> 64(ReLU) -> embed_dim -> L2 normalize."""
        h = [0.0] * 64
        for i in range(64):
            s = sum(self._W1[i][j] * features[j] for j in range(self._input_dim))
            h[i] = max(0.0, s + self._b1[i])  # ReLU

        emb = [0.0] * self._d
        for i in range(self._d):
            s = sum(self._W2[i][j] * h[j] for j in range(64))
            emb[i] = s + self._b2[i]

        # L2归一化
        norm = math.sqrt(sum(e**2 for e in emb))
        if norm > 1e-9:
            emb = [e / norm for e in emb]
        return emb

    def _augment(self, path: PathSample) -> PathSample:
        """随机增强: 40%边dropout, 40%置信度扰动, 20%路径截断。"""
        choice = random.random()
        if choice < 0.4 and len(path.confidences) >= 1:
            # 边dropout: 移除随机一条边(合并两端节点)
            drop_idx = random.randint(0, len(path.confidences) - 1)
            new_confs = [c for i, c in enumerate(path.confidences) if i != drop_idx]
            new_layers = list(path.layer_sequence)
            new_sevs = list(path.severities)
            if drop_idx + 1 < len(new_layers):
                new_layers.pop(drop_idx + 1)
                new_sevs.pop(drop_idx + 1)
            return PathSample(
                node_ids=path.node_ids, layer_sequence=new_layers,
                confidences=new_confs, severities=new_sevs,
                length=path.length - 1, path_id=path.path_id,
            )
        elif choice < 0.8 and path.confidences:
            # 置信度扰动
            new_confs = [max(0.0, min(1.0, c + random.gauss(0, 0.1)))
                        for c in path.confidences]
            return PathSample(
                node_ids=path.node_ids, layer_sequence=path.layer_sequence,
                confidences=new_confs, severities=path.severities,
                length=path.length, path_id=path.path_id,
            )
        else:
            # 路径截断
            if path.length <= 2:
                return path
            cut = random.randint(1, path.length - 2)
            return PathSample(
                node_ids=path.node_ids[cut:],
                layer_sequence=path.layer_sequence[cut:],
                confidences=path.confidences[cut:],
                severities=path.severities[cut:],
                length=path.length - cut, path_id=path.path_id,
            )

    def _encode_with_pre_norm(self, features: List[float]
                              ) -> Tuple[List[float], List[float], List[float]]:
        """编码+返回中间值供反向传播。返回 (h, z, e) 其中h=隐藏层, z=预归一化, e=L2归一化。"""
        h = [0.0] * 64
        for i in range(64):
            s = sum(self._W1[i][j] * features[j] for j in range(self._input_dim))
            h[i] = max(0.0, s + self._b1[i])
        z = [0.0] * self._d
        for i in range(self._d):
            z[i] = sum(self._W2[i][j] * h[j] for j in range(64)) + self._b2[i]
        norm = math.sqrt(sum(zi**2 for zi in z))
        if norm > 1e-9:
            e = [zi / norm for zi in z]
        else:
            e = [0.0] * self._d
        return h, z, e

    def fit(self, n_epochs: int = 400, lr: float = 0.01,
            batch_size: int = 32) -> Dict[str, float]:
        """InfoNCE对比损失+全参数反向传播训练编码器。"""
        if len(self._paths) < 2:
            return {"error": "insufficient paths"}

        final_loss = 0.0
        n_paths = len(self._paths)

        for epoch in range(n_epochs):
            lr_t = lr / (1.0 + 0.002 * epoch)
            total_loss = 0.0
            n_batches = 0
            indices = list(range(n_paths))
            random.shuffle(indices)

            for b_start in range(0, n_paths, batch_size):
                batch_idx = indices[b_start:b_start + batch_size]
                if len(batch_idx) < 2:
                    continue
                batch_features = []
                batch_aug_features = []
                for idx in batch_idx:
                    batch_features.append(self._path_to_features(self._paths[idx]))
                    aug = self._augment(self._paths[idx])
                    batch_aug_features.append(self._path_to_features(aug))

                bs = len(batch_idx)
                # Forward + cache intermediates
                cached_orig = [self._encode_with_pre_norm(f) for f in batch_features]
                cached_aug = [self._encode_with_pre_norm(f) for f in batch_aug_features]

                h_orig = [c[0] for c in cached_orig]
                z_orig = [c[1] for c in cached_orig]
                e_orig = [c[2] for c in cached_orig]
                z_aug  = [c[1] for c in cached_aug]
                e_aug  = [c[2] for c in cached_aug]

                # InfoNCE loss
                loss = 0.0
                # dL/de for each embedding (accumulated)
                dL_de_orig = [[0.0] * self._d for _ in range(bs)]
                dL_de_aug  = [[0.0] * self._d for _ in range(bs)]

                for i in range(bs):
                    pos_sim = sum(e_orig[i][k] * e_aug[i][k] for k in range(self._d)) / self._tau
                    neg_sum = 0.0
                    neg_terms = []
                    # 先收集所有负例未经加权
                    for j in range(bs):
                        if j == i:
                            continue
                        s = sum(e_orig[i][k] * e_orig[j][k] for k in range(self._d))
                        neg_terms.append((j, s, False))
                        s2 = sum(e_orig[i][k] * e_aug[j][k] for k in range(self._d))
                        neg_terms.append((j, s2, True))
                    # 硬负例挖掘: 相似度越高的负例权重越大
                    # 权重 = softmax(sims) * (2*bs-2) 使平均权重=1
                    sims = [s for _, s, _ in neg_terms]
                    max_sim = max(sims)
                    exp_sims = [math.exp((s - max_sim) / self._tau) for _, s, _ in neg_terms]
                    sum_exp = sum(exp_sims)
                    if sum_exp < 1e-9:
                        continue
                    n_neg = len(neg_terms)
                    for idx, (j, s, is_aug) in enumerate(neg_terms):
                        weight = (exp_sims[idx] / sum_exp) * n_neg  # 硬负例权重>1, 易负例<1
                        neg_sum += weight * math.exp(s / self._tau)
                    loss += -math.log(math.exp(pos_sim) / neg_sum)

                    # dL/de_orig[i]: 正例贡献 + 负例贡献
                    for k in range(self._d):
                        # 正例梯度: -e_aug[i][k] / tau
                        dL_de_orig[i][k] -= e_aug[i][k] / self._tau
                    for j, sim_val, is_aug in neg_terms:
                        weight = math.exp(sim_val / self._tau) / neg_sum
                        src_emb = e_aug[j] if is_aug else e_orig[j]
                        for k in range(self._d):
                            dL_de_orig[i][k] += weight * src_emb[k] / self._tau

                    # dL/de_aug[i] (仅正例贡献)
                    for k in range(self._d):
                        dL_de_aug[i][k] = -e_orig[i][k] / self._tau
                    # 负例贡献: e_aug[i] 作为其他样本的负例时
                    for j in range(bs):
                        if j == i:
                            continue
                        s_ji = sum(e_orig[j][k] * e_aug[i][k] for k in range(self._d))
                        n_sum_j = 0.0
                        for jj in range(bs):
                            if jj == j: continue
                            n_sum_j += math.exp(sum(e_orig[j][k] * e_orig[jj][k] for k in range(self._d)) / self._tau)
                            n_sum_j += math.exp(sum(e_orig[j][k] * e_aug[jj][k] for k in range(self._d)) / self._tau)
                        if n_sum_j > 1e-9:
                            w = math.exp(s_ji / self._tau) / n_sum_j
                            for k in range(self._d):
                                dL_de_aug[i][k] += w * e_orig[j][k] / self._tau

                loss /= bs
                total_loss += loss
                n_batches += 1

                # Backprop through L2 norm -> z -> W2 -> h -> W1
                grad_W2 = [[0.0] * 64 for _ in range(self._d)]
                grad_b2 = [0.0] * self._d
                grad_W1 = [[0.0] * self._input_dim for _ in range(64)]
                grad_b1 = [0.0] * 64

                for i in range(bs):
                    for src_de, src_z in [(dL_de_orig[i], z_orig[i]), (dL_de_aug[i], z_aug[i])]:
                        # L2 norm gradient: dL/dz = (dL/de - (dL/de·e)*e) / ||z||
                        e_vec = [zk / (math.sqrt(sum(zk2**2 for zk2 in src_z)) + 1e-9) for zk in src_z]
                        dot = sum(src_de[k] * e_vec[k] for k in range(self._d))
                        dL_dz = [(src_de[k] - dot * e_vec[k]) / (math.sqrt(sum(zk2**2 for zk2 in src_z)) + 1e-9)
                                for k in range(self._d)]
                        # W2 gradient: dL/dW2[k][j] = dL/dz[k] * h[j]
                        for k in range(self._d):
                            grad_b2[k] += dL_dz[k]
                            for j in range(64):
                                grad_W2[k][j] += dL_dz[k] * h_orig[i][j]
                        # Backprop to h: dL/dh[j] = sum_k W2[k][j] * dL/dz[k]
                        for j in range(64):
                            dL_dh_j = sum(self._W2[k][j] * dL_dz[k] for k in range(self._d))
                            if h_orig[i][j] > 0:  # ReLU derivative
                                grad_b1[j] += dL_dh_j
                                for m in range(self._input_dim):
                                    grad_W1[j][m] += dL_dh_j * batch_features[i][m]

                n = 2 * bs  # orig + aug views
                for k in range(self._d):
                    self._b2[k] -= lr_t * grad_b2[k] / max(n, 1)
                    for j in range(64):
                        self._W2[k][j] -= lr_t * grad_W2[k][j] / max(n, 1)
                for j in range(64):
                    self._b1[j] -= lr_t * grad_b1[j] / max(n, 1)
                    for m in range(self._input_dim):
                        self._W1[j][m] -= lr_t * grad_W1[j][m] / max(n, 1)

            final_loss = total_loss / max(n_batches, 1)

        self._embeddings = {}
        for path in self._paths:
            self._embeddings[path.path_id] = self._encode(
                self._path_to_features(path))
        self._fitted = True
        return {"final_loss": round(final_loss, 6), "epochs": n_epochs}

    def find_similar(self, query_path_id: str, top_k: int = 5
                     ) -> List[Tuple[str, float]]:
        """余弦相似度搜索 - 找与查询路径最相似的k条路径。

        返回 [(path_id, cosine_similarity), ...]。
        """
        if query_path_id not in self._embeddings:
            return []
        q_emb = self._embeddings[query_path_id]

        scored = []
        for pid, emb in self._embeddings.items():
            if pid == query_path_id:
                continue
            sim = sum(q_emb[i] * emb[i] for i in range(self._d))
            scored.append((pid, sim))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]
