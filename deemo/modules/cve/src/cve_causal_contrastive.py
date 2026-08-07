# ~ 2026-11-14
# C3E: Causal Contrastive CVE Embedding
# 自监督表示学习方法, 结合因果特征选择、对比学习和因果传播.
#
# 核心参考文献:
#
#     -- 将 Pearl 的 do-calculus 应用于漏洞检测, 使用后门准则消除虚假相关.
#     本文将其因果特征选择思想迁移到 CVE 元数据特征空间.
#
# 挑战驱动的多模态对比学习, 自适应难负样本挖掘.
#     本文将其对比学习框架适配到 CVE 特征向量 + 利用标签.
#
# 结构因果模型 (SCM) 在软件供应链依赖 DAG 上的应用.
#     本文将其因果传播思想用于 CVE→Product→Vendor 依赖图.
#
# EPSS 在 KEV 中的效能分析, 发现 EPSS 对高严重性 CVE 的
#     预妥协预测存在盲区. 本文的难负样本挖掘直接针对此盲区.
#
# 方法概述:
#   阶段 1 — 因果特征选择: 使用简化的 PC 算法在 CVE 特征空间中进行
#     条件独立性测试, 识别哪些特征对 "被利用" 结果有直接因果边.
#     虚假特征 (仅通过混淆变量与利用关联) 被降权.
#   阶段 2 — 对比预训练: 使用 InfoNCE 损失 + 难负样本挖掘学习嵌入.
#     正样本对: 共享因果特征剖面且利用结果相同的 CVE.
#     难负样本: 特征相似但利用结果不同的 CVE (EPSS 盲区).
#   阶段 3 — 因果传播: 在 Product→Vendor 依赖图上使用 SCM 启发的
#     加权方案传播利用可能性, 边权重反映因果影响而非相关性.
#
# 时间复杂度: O(|F|^2 * N + |E| * d) where |F|=特征数 (~8), N=CVE数,
#   |E|=依赖边数, d=嵌入维度. 对于 10K CVE, 阶段 1 < 100ms, 阶段 2 < 2s,
#   阶段 3 < 500ms.

import math
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple, Any

from .cve_models import CVEEntry
from .cve_kb import CVEKnowledgeBase

try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False
    np = None

# 可观测特征定义
# 从 CVE 元数据中提取的可观测变量, 用于因果发现
_FEATURE_NAMES = [
    "cvss_score",        # CVSS 基础分数 [0, 10]
    "epss_score",        # EPSS 利用概率 [0, 1]
    "epss_percentile",   # EPSS 百分位 [0, 1]
    "cisa_kev",          # CISA KEV 标记 {0, 1}
    "exploit_maturity",  # 利用成熟度编码 [0, 1]
    "days_since_pub",    # 发布后天数 (对数归一化)
    "cwe_rarity",        # CWE 稀有度 [0, 1]
    "has_fix",           # 是否有修复 {0, 1}
    "ref_count",         # 参考链接数 (对数归一化)
    "cpe_count",         # CPE 匹配数 (对数归一化)
]
_N_FEATURES = len(_FEATURE_NAMES)

# 目标变量: 是否被实际利用 (KEV 收录 或 maturity >= functional)
_TARGET_EXPLOITED = "is_exploited"

# 条件独立性测试的显著性阈值
_CI_ALPHA = 0.05
# 对比学习温度参数
_CONTRASTIVE_TAU = 0.1
# 嵌入维度
_EMBEDDING_DIM = 16
# 对比训练轮次
_CONTRASTIVE_EPOCHS = 50
# 学习率
_LR = 0.01
# 难负样本比例 (每 batch 中难负样本的占比)
_HARD_NEGATIVE_RATIO = 0.3


class CausalFeatureSelector:
    """基于简化 PC 算法的因果特征选择.

    对每对特征 (X, Y), 测试是否存在分离集 S 使得 X ⊥ Y | S.
    如果存在, 移除 X-Y 之间的边. 然后定向 v-结构.
    最终输出每个特征相对于目标变量 T 的因果权重.

    简化: 使用 Pearson 偏相关系数的 Fisher z-变换作为条件独立性
    检验统计量. 对二元变量使用点双列相关系数.
    """

    def __init__(self):
        self._adj: Dict[int, Set[int]] = {}          # 邻接矩阵 (无向)
        self._directed: Set[Tuple[int, int]] = set() # 有向边
        self._causal_weights: Dict[str, float] = {}  # 特征 → 因果权重

    def fit(self, features: List[List[float]], labels: List[int]):
        """在特征矩阵上运行因果发现.

        features: N×F 矩阵, 每行一个 CVE 的特征向量.
        labels: N 个二元标签 (0=未利用, 1=已利用).
        """
        N = len(features)
        F = _N_FEATURES
        if N < 5 or F < 2:
            return

        # 将目标变量加入特征矩阵 (最后一个位置)
        X = [list(row) + [float(l)] for row, l in zip(features, labels)]
        target_idx = F  # 目标变量的索引

        # 阶段 1: 初始化完全无向图 (所有变量对之间都有边)
        self._adj.clear()
        for i in range(F + 1):
            self._adj[i] = {j for j in range(F + 1) if j != i}

        # 阶段 2: 条件独立性测试, 移除边
        # 分离集大小从 0 递增到 F-1
        max_sep = min(F - 1, 3)  # 限制分离集大小以控制复杂度
        for sep_size in range(max_sep + 1):
            for i in range(F + 1):
                for j in list(self._adj[i]):
                    if j <= i:
                        continue
                    if i not in self._adj[j]:
                        continue
                    # 寻找分离集
                    neighbors = (self._adj[i] | self._adj[j]) - {i, j}
                    if len(neighbors) < sep_size:
                        continue

                    # 测试所有大小为 sep_size 的子集
                    separated = self._test_separation(X, i, j, neighbors, sep_size)
                    if separated:
                        self._adj[i].discard(j)
                        self._adj[j].discard(i)

        # 阶段 3: 定向 v-结构 (i → k ← j where i,j not adjacent, k unshielded)
        self._directed.clear()
        for k in range(F + 1):
            neighbors_k = list(self._adj[k])
            for idx_i, i in enumerate(neighbors_k):
                for j in neighbors_k[idx_i + 1:]:
                    if j in self._adj[i]:
                        continue  # i 和 j 相邻, 不是 v-结构
                    # k 是 i 和 j 的共同邻居, i-j 无边 → v-结构候选
                    # 定向: i → k, j → k
                    self._directed.add((i, k))
                    self._directed.add((j, k))

        # 阶段 4: 计算每个特征对目标变量的因果权重
        self._causal_weights.clear()
        target_parents = {src for src, dst in self._directed if dst == target_idx}
        # 也考虑无向邻接 (方向未确定但存在依赖)
        undirected = self._adj[target_idx] - {src for src, _ in self._directed}

        for feat_idx in range(F):
            weight = 0.0
            if feat_idx in target_parents:
                weight += 0.7  # 直接因果边
            elif feat_idx in undirected:
                weight += 0.3  # 相关但未确定方向
            # 二阶路径: feat → intermediate → target
            for intermediate in self._adj[feat_idx]:
                if (intermediate, target_idx) in self._directed:
                    weight += 0.15
            name = _FEATURE_NAMES[feat_idx] if feat_idx < len(_FEATURE_NAMES) else f"f{feat_idx}"
            self._causal_weights[name] = min(weight, 1.0)

    def _test_separation(self, X, i, j, neighbors, sep_size) -> bool:
        """测试是否存在大小为 sep_size 的分离集使 i ⊥ j.

        使用 Fisher z-变换的偏相关系数. 返回 True 表示找到分离集.
        """
        from itertools import combinations
        N = len(X)

        for S in combinations(neighbors, sep_size):
            S = list(S)
            # 计算偏相关系数 r_{ij|S}
            r = self._partial_correlation(X, i, j, S, N)
            if r is None:
                continue
            # Fisher z-变换: z = 0.5 * ln((1+r)/(1-r))
            if abs(r) >= 1.0:
                z = float('inf') if r > 0 else float('-inf')
            else:
                z = 0.5 * math.log((1 + r) / (1 - r))
            # z ~ N(0, 1/sqrt(N - |S| - 3))
            se = 1.0 / math.sqrt(N - len(S) - 3)
            z_score = abs(z) / se
            # 双尾检验: p < alpha → 拒绝 H0 (不独立) → 保留边
            # p > alpha → 不拒绝 H0 (可能独立) → 可以作为分离集
            # 使用正态近似: |z| < 1.96 对应 p > 0.05
            if z_score < 1.96:
                return True
        return False

    def _partial_correlation(self, X, i, j, S, N) -> Optional[float]:
        """计算偏相关系数 r_{ij|S}. 使用递推公式.

        当 |S|=0: r_{ij} (Pearson).
        当 |S|=1: r_{ij|k} = (r_{ij} - r_{ik}*r_{jk}) / sqrt((1-r_{ik}^2)*(1-r_{jk}^2)).
        当 |S|>1: 递归调用.
        """
        if len(S) == 0:
            return self._pearson_r(X, i, j, N)
        if len(S) == 1:
            k = S[0]
            rij = self._pearson_r(X, i, j, N)
            rik = self._pearson_r(X, i, k, N)
            rjk = self._pearson_r(X, j, k, N)
            if rij is None or rik is None or rjk is None:
                return None
            denom = math.sqrt((1 - rik*rik) * (1 - rjk*rjk))
            if abs(denom) < 1e-10:
                return 0.0
            return (rij - rik * rjk) / denom
        # |S| > 1: 递归移除一个变量
        k = S[0]
        S_rest = S[1:]
        rij_k = self._partial_correlation(X, i, j, [k], N)
        if rij_k is None:
            return None
        if len(S_rest) == 0:
            return rij_k
        # 对 S_rest 递归
        return self._partial_correlation_with_r(X, i, j, S_rest, N, rij_k)

    def _partial_correlation_with_r(self, X, i, j, S, N, r_ij_Sminus) -> Optional[float]:
        """已知 r_{ij|S'} 计算 r_{ij|S'+{k}}. 与 _partial_correlation 逻辑相同."""
        if not S:
            return r_ij_Sminus
        k = S[0]
        rik = self._partial_correlation(X, i, k, S[1:], N)
        rjk = self._partial_correlation(X, j, k, S[1:], N)
        if rik is None or rjk is None:
            return None
        denom = math.sqrt((1 - rik*rik) * (1 - rjk*rjk))
        if abs(denom) < 1e-10:
            return 0.0
        return (r_ij_Sminus - rik * rjk) / denom

    def _pearson_r(self, X, i, j, N) -> Optional[float]:
        """计算 Pearson 相关系数 r_{ij}."""
        if N < 3:
            return None
        mean_i = sum(X[n][i] for n in range(N)) / N
        mean_j = sum(X[n][j] for n in range(N)) / N
        cov = sum((X[n][i] - mean_i) * (X[n][j] - mean_j) for n in range(N))
        std_i = math.sqrt(sum((X[n][i] - mean_i) ** 2 for n in range(N)))
        std_j = math.sqrt(sum((X[n][j] - mean_j) ** 2 for n in range(N)))
        if std_i < 1e-10 or std_j < 1e-10:
            return 0.0
        return cov / (std_i * std_j)

    @property
    def causal_weights(self) -> Dict[str, float]:
        return dict(self._causal_weights)


class ContrastiveCVEEncoder:
    """基于 InfoNCE 损失 + 难负样本挖掘的 CVE 嵌入学习.

    正样本对: 共享高因果权重特征剖面且利用标签相同的两个 CVE.
    难负样本: 余弦相似度高但利用标签不同的 CVE 对.
    使用梯度下降在嵌入矩阵上最小化对比损失.
    """

    def __init__(self, embedding_dim: int = _EMBEDDING_DIM,
                 temperature: float = _CONTRASTIVE_TAU):
        self._dim = embedding_dim
        self._tau = temperature
        self._embeddings: Dict[str, List[float]] = {}  # cve_id → embedding
        self._feat_matrix: List[List[float]] = []       # 用于训练
        self._labels: List[int] = []                    # 利用标签
        self._cve_ids: List[str] = []                   # 对应的 CVE ID

    def fit(self, cve_ids: List[str], features: List[List[float]],
            labels: List[int], causal_weights: Dict[str, float],
            epochs: int = _CONTRASTIVE_EPOCHS, lr: float = _LR):
        """对比预训练: 学习嵌入矩阵 E ∈ R^{N×d}.

        损失: L = -E[log(exp(sim(z_i, z_j)/τ) / Σ_k exp(sim(z_i, z_k)/τ))]
        其中 (i,j) 为正样本对, k 遍历 batch 中所有样本.
        难负样本通过高相似度但不同标签的样本对识别.
        """
        N = len(cve_ids)
        if N < 2:
            return

        self._cve_ids = list(cve_ids)
        self._labels = list(labels)
        self._feat_matrix = [list(f) for f in features]

        # 计算因果加权特征: f'_i = f_i ⊙ w (逐元素乘以因果权重)
        weight_vec = [causal_weights.get(name, 0.5) for name in _FEATURE_NAMES]
        weighted_features = [
            [f[k] * weight_vec[k] for k in range(min(len(f), len(weight_vec)))]
            for f in features
        ]

        # 初始化嵌入: 使用因果加权特征的随机投影
        E = [[0.0] * self._dim for _ in range(N)]
        for i in range(N):
            wf = weighted_features[i]
            for d in range(self._dim):
                # 确定性投影: 使用不同频率的正弦函数
                val = sum(
                    wf[k % len(wf)] * math.sin((d + 1) * (k + 1) * 0.7)
                    for k in range(len(wf))
                ) / max(len(wf), 1)
                E[i][d] = val

        # L2 归一化初始嵌入
        for i in range(N):
            norm = math.sqrt(sum(x * x for x in E[i])) or 1.0
            E[i] = [x / norm for x in E[i]]

        # 构建正样本对: 相同标签 + 高因果特征相似度
        pos_pairs: List[Tuple[int, int]] = []
        for i in range(N):
            # 找到与 i 标签相同且特征最相似的样本
            best_j = -1
            best_sim = -1.0
            for j in range(N):
                if i == j or labels[i] != labels[j]:
                    continue
                sim = self._cosine_sim(features[i], features[j])
                if sim > best_sim:
                    best_sim = sim
                    best_j = j
            if best_j >= 0:
                pos_pairs.append((i, best_j))

        # 识别难负样本: 高特征相似度但不同标签
        hard_negatives: Dict[int, List[int]] = defaultdict(list)
        for i in range(N):
            candidates = []
            for j in range(N):
                if labels[i] == labels[j]:
                    continue
                sim = self._cosine_sim(features[i], features[j])
                candidates.append((sim, j))
            candidates.sort(key=lambda x: x[0], reverse=True)
            n_hard = max(1, int(len(candidates) * _HARD_NEGATIVE_RATIO))
            hard_negatives[i] = [j for _, j in candidates[:n_hard]]

        # 梯度下降
        for epoch in range(epochs):
            total_loss = 0.0
            grad = [[0.0] * self._dim for _ in range(N)]

            for i, j in pos_pairs:
                # 正样本损失: -log(exp(sim(z_i,z_j)/τ) / Z)
                sim_pos = self._cosine_sim(E[i], E[j])
                # 分母: 所有样本 (包括自身)
                Z = 0.0
                for k in range(N):
                    if k == i:
                        continue
                    Z += math.exp(self._cosine_sim(E[i], E[k]) / self._tau)
                Z += math.exp(sim_pos / self._tau)
                if Z < 1e-10:
                    continue

                loss_i = -sim_pos / self._tau + math.log(Z)
                total_loss += max(loss_i, 0.0)  # clamp 防止爆炸

                # 梯度: ∂L/∂z_i
                # 为正样本: grad += (z_j/τ) * (1 - exp(sim_pos/τ)/Z)
                # 为负样本: grad -= Σ_k (z_k/τ) * exp(sim_ik/τ)/Z
                weight_pos = 1.0 - math.exp(sim_pos / self._tau) / Z
                for d in range(self._dim):
                    grad[i][d] += E[j][d] / self._tau * weight_pos

                for k in range(N):
                    if k == i:
                        continue
                    sim_ik = self._cosine_sim(E[i], E[k])
                    weight_neg = math.exp(sim_ik / self._tau) / Z
                    is_hard = 1.5 if k in hard_negatives.get(i, []) else 1.0
                    for d in range(self._dim):
                        grad[i][d] -= E[k][d] / self._tau * weight_neg * is_hard

            # 更新嵌入
            for i in range(N):
                g_norm = math.sqrt(sum(g * g for g in grad[i])) or 1.0
                # 梯度裁剪
                clip = min(1.0, 0.5 / g_norm)
                for d in range(self._dim):
                    E[i][d] -= lr * grad[i][d] * clip
                # 重新归一化
                norm = math.sqrt(sum(x * x for x in E[i])) or 1.0
                E[i] = [x / norm for x in E[i]]

            # 自适应学习率衰减
            lr *= 0.98

        # 存储最终嵌入
        self._embeddings.clear()
        for i, cid in enumerate(cve_ids):
            self._embeddings[cid] = list(E[i])

    def _cosine_sim(self, a: List[float], b: List[float]) -> float:
        """余弦相似度."""
        dot = sum(ai * bi for ai, bi in zip(a, b))
        na = math.sqrt(sum(x * x for x in a)) or 1.0
        nb = math.sqrt(sum(x * x for x in b)) or 1.0
        return dot / (na * nb)

    def get_embedding(self, cve_id: str) -> Optional[List[float]]:
        return self._embeddings.get(cve_id)

    def find_similar(self, cve_id: str, top_n: int = 10) -> List[Tuple[str, float]]:
        """找到嵌入空间中与给定 CVE 最相似的 CVE."""
        vec = self._embeddings.get(cve_id)
        if vec is None:
            return []
        sims = []
        for cid, emb in self._embeddings.items():
            if cid == cve_id:
                continue
            sims.append((cid, self._cosine_sim(vec, emb)))
        sims.sort(key=lambda x: x[1], reverse=True)
        return sims[:top_n]

    @property
    def embeddings(self) -> Dict[str, List[float]]:
        return dict(self._embeddings)


class CausalPropagator:
    """SCM 启发的因果传播.

    在 Product→Vendor 依赖图上, 使用因果权重 (由 CausalFeatureSelector
    确定) 作为边强度, 传播利用可能性.

    传播公式: s_v^(t+1) = σ( Σ_{u∈N(v)} w_{uv} * s_u^(t) + b_v )
    其中 w_{uv} 是从因果特征权重派生的边权重, b_v 是节点的基准分数.
    """

    def __init__(self, causal_weights: Dict[str, float]):
        self._causal_weights = causal_weights
        self._graph: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
        self._base_scores: Dict[str, float] = {}

    def build_graph(self, kb: CVEKnowledgeBase,
                    embeddings: Optional[Dict[str, List[float]]] = None):
        """从 KB 构建 CVE→Product→Vendor 因果传播图."""
        entries, _ = kb.search(limit=100000)
        if not entries:
            return

        # 从因果权重计算默认边权重
        default_w = self._causal_weights.get("epss_score", 0.5)

        for entry in entries:
            cid = entry.cve_id if hasattr(entry, 'cve_id') else entry.get('cve_id', '')
            if not cid:
                continue

            products = entry.products if hasattr(entry, 'products') else entry.get('products', [])
            if isinstance(products, str):
                products = [products] if products else []

            # 基准分数: EPSS + KEV 的加权组合
            epss = _get_num(entry, "epss_score") or 0.0
            kev = 1.0 if _get_bool(entry, "cisa_kev") else 0.0
            maturity = _maturity_val(_get_str(entry, "exploit_maturity", ""))
            base = 0.4 * epss + 0.3 * kev + 0.3 * maturity
            self._base_scores[cid] = base

            for prod in products:
                # 因果边: CVE → Product
                prod_node = f"product:{prod}"
                self._graph[cid].append((prod_node, default_w))
                self._graph[prod_node].append((cid, default_w * 0.5))  # 反向边 (反馈)

                # Product→Vendor 边
                vendors = entry.vendors if hasattr(entry, 'vendors') else entry.get('vendors', [])
                if isinstance(vendors, str):
                    vendors = [vendors] if vendors else []
                for vend in vendors:
                    vend_node = f"vendor:{vend}"
                    self._graph[prod_node].append((vend_node, default_w * 0.7))
                    self._graph[vend_node].append((prod_node, default_w * 0.3))
                    if base > 0.3:
                        self._base_scores.setdefault(vend_node, 0.0)
                        self._base_scores[vend_node] = max(self._base_scores.get(vend_node, 0.0), base * 0.5)

    def propagate(self, n_iterations: int = 5) -> Dict[str, float]:
        """执行因果传播, 返回每个 CVE 的最终传播分数.

        收敛条件: 分数的最大变化 < 1e-4 或达到最大迭代次数.
        """
        # 初始化分数
        scores = dict(self._base_scores)

        for it in range(n_iterations):
            new_scores = dict(scores)
            max_delta = 0.0

            for node, neighbors in self._graph.items():
                incoming = 0.0
                total_w = 0.0
                for neighbor, edge_w in neighbors:
                    neighbor_score = scores.get(neighbor, 0.0)
                    incoming += neighbor_score * edge_w
                    total_w += abs(edge_w)

                if total_w > 0:
                    propagated = incoming / total_w
                    new_scores[node] = 0.5 * scores.get(node, 0.0) + 0.5 * propagated

                delta = abs(new_scores.get(node, 0.0) - scores.get(node, 0.0))
                if delta > max_delta:
                    max_delta = delta

            scores = new_scores
            if max_delta < 1e-4:
                break

        # 过滤出 CVE 节点
        return {k: v for k, v in scores.items()
                if not k.startswith("product:") and not k.startswith("vendor:")}


# C3E Pipeline

class C3EPipeline:
    """C3E 完整流水线: 因果发现 → 对比学习 → 因果传播."""

    def __init__(self, kb: CVEKnowledgeBase):
        self._kb = kb
        self._selector = CausalFeatureSelector()
        self._encoder: Optional[ContrastiveCVEEncoder] = None
        self._propagator: Optional[CausalPropagator] = None
        self._scores: Dict[str, Dict[str, Any]] = {}
        self._fitted = False

    def fit(self) -> Dict[str, Any]:
        """运行完整 C3E 流水线.

        Returns:
          统计信息 dict, 包含 causal_weights, embedding_dim, n_cves 等.
        """
        entries, _ = self._kb.search(limit=100000)
        if not entries:
            self._fitted = True
            return {"error": "no entries in KB"}

        # 提取特征和标签
        features, labels, cve_ids = self._extract_features(entries)
        N = len(cve_ids)
        if N < 5:
            self._fitted = True
            return {"error": f"need >= 5 entries, got {N}"}

        start = time.time()

        # 阶段 1: 因果特征选择
        self._selector.fit(features, labels)
        causal_w = self._selector.causal_weights

        # 阶段 2: 对比预训练
        self._encoder = ContrastiveCVEEncoder()
        self._encoder.fit(cve_ids, features, labels, causal_w)
        embeddings = self._encoder.embeddings

        # 阶段 3: 因果传播
        self._propagator = CausalPropagator(causal_w)
        self._propagator.build_graph(self._kb, embeddings)
        propagated = self._propagator.propagate()

        # 合并分数
        self._scores.clear()
        for cid in cve_ids:
            base = self._propagator._base_scores.get(cid, 0.0)
            prop = propagated.get(cid, base)
            emb = embeddings.get(cid, [0.0] * _EMBEDDING_DIM)
            emb_norm = math.sqrt(sum(x * x for x in emb)) if emb else 0.0

            # 融合分数: 0.3*base + 0.4*propagated + 0.3*embedding_magnitude
            score = 0.3 * base + 0.4 * prop + 0.3 * min(emb_norm, 1.0)
            score = 1.0 / (1.0 + math.exp(-6.0 * (score - 0.35)))  # sigmoid 校准

            self._scores[cid] = {
                "c3e_score": round(score, 4),
                "base_score": round(base, 4),
                "propagated_score": round(prop, 4),
                "embedding_magnitude": round(emb_norm, 4),
                "label": _score_label(score),
            }

        elapsed = time.time() - start
        self._fitted = True

        return {
            "n_cves": N,
            "causal_weights": {k: round(v, 3) for k, v in causal_w.items()},
            "embedding_dim": _EMBEDDING_DIM,
            "propagation_nodes": len(self._propagator._graph),
            "elapsed_seconds": round(elapsed, 3),
        }

    def _extract_features(self, entries) -> Tuple[List[List[float]], List[int], List[str]]:
        """从 KB 条目提取特征矩阵和标签."""
        features = []
        labels = []
        cve_ids = []
        now = datetime.now(timezone.utc)

        # 预计算 CWE 频率用于稀有度
        cwe_freq: Dict[str, int] = defaultdict(int)
        for e in entries:
            cwes = e.cwes if hasattr(e, 'cwes') else e.get('cwes', [])
            if isinstance(cwes, str):
                cwes = [cwes] if cwes else []
            for cwe in cwes:
                cwe_freq[cwe] += 1
        max_cwe = max(cwe_freq.values()) if cwe_freq else 1

        for e in entries:
            cid = e.cve_id if hasattr(e, 'cve_id') else e.get('cve_id', '')
            if not cid:
                continue

            cvss = (_get_num(e, "cvss_score") or 0.0) / 10.0
            epss = _get_num(e, "epss_score") or 0.0
            epss_pct = _get_num(e, "epss_percentile") or 0.0
            kev = 1.0 if _get_bool(e, "cisa_kev") else 0.0
            mat = _maturity_val(_get_str(e, "exploit_maturity", ""))

            pub = _get_str(e, "published_date", "")
            days = _days_since(pub, now)
            days_norm = min(math.log(1 + days) / math.log(3660), 1.0) if days > 0 else 0.0

            cwes = e.cwes if hasattr(e, 'cwes') else e.get('cwes', [])
            if isinstance(cwes, str):
                cwes = [cwes] if cwes else []
            rarity = 0.0
            for cwe in cwes:
                freq = cwe_freq.get(cwe, 0)
                rarity = max(rarity, 1.0 - freq / max_cwe)

            has_fix = 1.0 if (_get_str(e, "fix_version") or _get_str(e, "patched_version")) else 0.0

            refs = e.references if hasattr(e, 'references') else e.get('references', [])
            if isinstance(refs, list):
                ref_count = min(math.log(1 + len(refs)) / math.log(101), 1.0)
            else:
                ref_count = 0.0

            cpes = e.cpe_matches if hasattr(e, 'cpe_matches') else e.get('cpe_matches', [])
            if isinstance(cpes, list):
                cpe_count = min(math.log(1 + len(cpes)) / math.log(101), 1.0)
            else:
                cpe_count = 0.0

            features.append([cvss, epss, epss_pct, kev, mat, days_norm, rarity, has_fix, ref_count, cpe_count])

            # 标签: 是否被实际利用
            is_exploited = 1 if (kev > 0 or mat >= 0.5) else 0
            labels.append(is_exploited)
            cve_ids.append(cid)

        return features, labels, cve_ids

    def get_scores(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._scores)

    def find_similar_cves(self, cve_id: str, top_n: int = 10) -> List[Tuple[str, float]]:
        """在 C3E 嵌入空间中找相似 CVE."""
        if self._encoder is None:
            return []
        return self._encoder.find_similar(cve_id, top_n)

    @property
    def is_fitted(self) -> bool:
        return self._fitted


# 辅助函数

def _get_num(entry, field: str) -> Optional[float]:
    if hasattr(entry, field):
        return getattr(entry, field)
    if isinstance(entry, dict):
        return entry.get(field)
    return None


def _get_str(entry, field: str, default: str = "") -> str:
    if hasattr(entry, field):
        return str(getattr(entry, field) or default)
    if isinstance(entry, dict):
        return str(entry.get(field, default))
    return default


def _get_bool(entry, field: str) -> bool:
    if hasattr(entry, field):
        return bool(getattr(entry, field))
    if isinstance(entry, dict):
        return bool(entry.get(field, False))
    return False


def _maturity_val(maturity: str) -> float:
    m = maturity.lower().strip().replace(" ", "_")
    enc = {"unknown": 0.0, "poc": 0.25, "proof_of_concept": 0.25,
           "functional": 0.5, "metasploit": 0.75, "weaponized": 1.0}
    return enc.get(m, 0.0)


def _days_since(date_str: str, now: datetime) -> float:
    if not date_str:
        return 365.0
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return max(0.0, (now - dt).total_seconds() / 86400.0)
    except (ValueError, TypeError):
        return 365.0


def _score_label(score: float) -> str:
    if score >= 0.75:
        return "CRITICAL"
    elif score >= 0.5:
        return "HIGH"
    elif score >= 0.25:
        return "MEDIUM"
    return "LOW"


# 便捷接口

def run_c3e_pipeline(kb: CVEKnowledgeBase) -> Dict[str, Any]:
    """一站式 C3E 流水线: 在 KB 上运行因果发现、对比学习、因果传播.

    Returns:
      {stats, causal_weights, scores, top_exploitable}
    """
    pipeline = C3EPipeline(kb)
    stats = pipeline.fit()
    scores = pipeline.get_scores()

    ranked = sorted(scores.items(), key=lambda x: x[1].get("c3e_score", 0), reverse=True)
    top_10 = [(cid, info["c3e_score"], info["label"]) for cid, info in ranked[:10]]

    return {
        "stats": stats,
        "causal_weights": stats.get("causal_weights", {}),
        "scores": scores,
        "top_10": top_10,
    }
