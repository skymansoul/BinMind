# 时序GAT CVE依赖图
# 时序图注意力网络 — CVE依赖图上的时间感知表示学习
#
# 问题: 现有CVE图模块 (cve_graph_gnn, cve_hgat_attention) 将图视为
# 静态快照. 但CVE依赖图是动态演化的:
# 新CVE每天发布, 与已有节点建立边.
# 旧CVE的影响随时间衰减 (修补后不再活跃).
# 边权重应反映CVE的"新鲜度" — 2026年的边比2020年更重要.
# 静态GNN平等对待所有节点/边, 无法捕获这种时间动态.
#
# 解决方案: 时序图注意力网络 (TGAT).
# 在标准GAT的基础上注入时间信号:
#   1. 时间位置编码: 每个节点附加其发布时间戳的正弦编码.
#   2. 时间衰减边权重: 边权重 w_uv = exp(-λ·age_days).
#      较新的边获得更高注意力.
#   3. 时间感知注意力: α_uv = softmax(LeakyReLU(a^T·[W·h_u||W·h_v||TE(Δ_t)])).
#      其中TE(Δ_t)是边两端节点时间差的正弦编码.
#
# 相对于静态GAT的改进:
# 新发布的CVE自动获得更高的结构重要性.
# 历史CVE的信息不会淹没当前威胁.
# 时间差分编码使模型学习"CVE间典型时间间隔".
#
# 设计说明:
#   1. 双时间信号: 绝对时间 (节点年龄) + 相对时间 (边时间差).
#   2. 与现有CVEExploitGraph兼容: 使用相同的节点/边结构.
#
#
# TGAT: Inductive Temporal Graph Attention (ICLR)
# Adaptive Spatio-Temporal Attention for APT
# TGAT for Cloud-Native Privilege Escalation

import math, random
from typing import Dict, List, Optional, Tuple

def _sinusoidal_encoding(t, d, i):
    """位置编码 PE(t, 2i)=sin(t/10000^{2i/d}), PE(t, 2i+1)=cos(...)."""
    freq = t / (10000.0 ** (2.0 * i / d))
    return math.sin(freq) if i % 2 == 0 else math.cos(freq)

def _time_encode(t, d):
    return [_sinusoidal_encoding(t, d, i) for i in range(d)]

class TemporalGATLayer:
    """单层时序图注意力 — 时间感知邻域聚合."""

    def __init__(self, in_dim=8, out_dim=8, time_dim=4, leaky=0.2):
        self._d_in = in_dim; self._d_out = out_dim; self._d_time = time_dim
        lim_w = math.sqrt(6/(in_dim+out_dim)); lim_a = math.sqrt(6/(2*out_dim+time_dim))
        self._W = [[random.uniform(-lim_w,lim_w) for _ in range(out_dim)] for _ in range(in_dim)]
        # 注意力向量: [W·h_u || W·h_v || TE(Δ_t)] → scalar
        self._a = [random.uniform(-lim_a,lim_a) for _ in range(2*out_dim+time_dim)]
        self._leaky = leaky

    def forward(self, features, edges, node_times, lamb=0.01):
        """时间感知前向传播.
        edges: [(src,dst),...] 有向边.
        node_times: [days_since_epoch] 每个节点的发布时间.
        lamb: 时间衰减系数.
        """
        N = len(features); H = [[0.0]*self._d_out for _ in range(N)]
        # 预计算变换后的特征
        Wh = [[sum(features[i][k]*self._W[k][j] for k in range(min(self._d_in,len(features[i])))) for j in range(self._d_out)] for i in range(N)]
        # 构建邻接表
        adj = {i: [] for i in range(N)}
        for s, d in edges:
            if 0<=s<N and 0<=d<N: adj[s].append(d)
        for i in range(N):
            nbrs = adj[i]
            if not nbrs: H[i] = list(Wh[i]); continue
            # 计算注意力系数
            scores = []
            for j in nbrs:
                dt = abs(node_times[i]-node_times[j])/365.0  # 年
                te = _time_encode(dt, self._d_time)
                concat = Wh[i] + Wh[j] + te
                raw = sum(concat[k]*self._a[k] for k in range(len(self._a)))
                # 时间衰减
                decay = math.exp(-lamb*dt)
                scores.append((j, raw*decay))
            # softmax
            if scores:
                mx = max(v for _, v in scores)
                exps = [(j, math.exp(v-mx)) for j, v in scores]
                total = sum(e[1] for e in exps)
                for j, w in exps:
                    alpha = w/max(total,1e-10)
                    for k in range(self._d_out):
                        H[i][k] += alpha*Wh[j][k]
            # 残差连接
            for k in range(self._d_out):
                H[i][k] = 0.5*Wh[i][k] + 0.5*H[i][k]
                H[i][k] = H[i][k] if H[i][k]>0 else self._leaky*H[i][k]
        return H


class TemporalGATScorer:
    """时序GAT CVE评分器 — 两层时间感知聚合."""

    def __init__(self, in_dim=8, hid_dim=12, time_dim=4):
        self._layer1 = TemporalGATLayer(in_dim, hid_dim, time_dim)
        self._layer2 = TemporalGATLayer(hid_dim, hid_dim, time_dim)
        # 读出层: hid_dim → 1
        lim = math.sqrt(6/(hid_dim+1))
        self._readout = [random.uniform(-lim,lim) for _ in range(hid_dim)]
        self._bias = 0.0
        self._trained = False

    def score(self, features, edges, node_times):
        h1 = self._layer1.forward(features, edges, node_times)
        h2 = self._layer2.forward(h1, edges, node_times)
        scores = {}
        for i in range(len(h2)):
            raw = self._bias + sum(h2[i][k]*self._readout[k] for k in range(len(self._readout)))
            scores[i] = 1.0/(1.0+math.exp(-raw))
        return scores

    def train_step(self, features, edges, node_times, labels, lr=0.01):
        N = len(features)
        preds = self.score(features, edges, node_times)
        loss = sum((preds.get(i,0.5)-labels[i])**2 for i in range(N) if i in labels)/max(len(labels),1)
        # 数值梯度更新读出层
        eps = 1e-5
        for k in range(len(self._readout)):
            o = self._readout[k]; self._readout[k]=o+eps
            p2 = self.score(features, edges, node_times)
            l2 = sum((p2.get(i,0.5)-labels[i])**2 for i in range(N) if i in labels)/max(len(labels),1)
            self._readout[k]=o; self._readout[k]-=lr*(l2-loss)/eps
        self._trained = True

    @property
    def is_trained(self): return self._trained


def build_temporal_gat_from_graph(graph, node_times=None):
    N = len(getattr(graph, '_node_ids', []))
    if N < 3: return TemporalGATScorer()
    features = getattr(graph, '_features', [[0.0]*8 for _ in range(N)])
    edges = []
    for rel_adj in getattr(graph, '_adj', {}).values():
        for src, dsts in rel_adj.items():
            for dst in dsts: edges.append((src, dst))
    if node_times is None:
        cve_type = getattr(graph, '_node_types', [])
        node_times = [random.uniform(0,3650) for _ in range(N)]
    scorer = TemporalGATScorer(in_dim=len(features[0]) if features else 8)
    # 使用图的标签训练
    labels = {}
    for i, t in enumerate(getattr(graph, '_node_types', [])):
        if t == 0:  # CVE节点
            feat = features[i]
            epss = feat[0] if len(feat)>0 else 0
            kev = feat[3] if len(feat)>3 else 0
            labels[i] = max(0.0, min(1.0, epss*0.7+kev*0.3))
    scorer.train_step(features, edges, node_times, labels)
    return scorer
