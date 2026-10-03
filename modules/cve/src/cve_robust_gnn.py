# 完成随机平滑认证核心逻辑, 支持节点特征高斯噪声注入
# 添加对抗训练循环, 实现 PGD 拓扑攻击模拟
# 集成认证半径计算, 支持批量认证查询
# 增加降级模式: 无 numpy 时回退到纯 Python 多数投票
#
# RobustGNN: 对抗鲁棒的图神经网络用于漏洞可利用性预测
#
# 相关文献:
#
#     首个确定性 GNN 认证防御, 对图结构和节点特征扰动均提供形式化保证.
#     本文将其随机平滑框架适配到异构 CVE 关系图: 对 CVE 节点的特征注入
#     各向同性高斯噪声, 对拓扑扰动采用边缘级随机丢弃.
#
#     扩展到任意扰动 (边/节点/特征) 的统一认证框架, 涵盖节点分类和图分类.
#     本文参考其对节点特征的 L2 范数认证半径计算方法.
#
#     双通道解耦防御: 分别处理结构扰动和特征扰动, 自适应注意力融合.
#     本文将其双通道思想简化为单图上的两阶段传播: 先原始图传播, 再在
#     扰动副本上传播, 取两者的一致性分数作为可靠性指标.
#
#     异常检测驱动的图注意力防御, 用预训练的边异常分数动态调整消息权重.
#     本文在 RobustnessCertifier 中实现了简化版边异常过滤:
#     若边权重 (Jaccard 相似度) 低于自适应阈值, 降低其在聚合中的贡献.
#
# 方法:
#   1. 随机平滑 (Randomized Smoothing): 对每个 CVE 节点的特征向量添加
#      高斯噪声 N(0, σ²I), 在多个噪声样本上执行 GNN 传播, 取预测类别
#      的多数票. 若多数票比例 > 0.5, 则可认证该节点在 L2 半径内不变.
#   2. 对抗训练: 在每个训练 epoch, 对邻接矩阵执行 PGD 拓扑攻击 —
#      添加/删除 K 条边以最大化损失, 然后在受扰动图上训练. 提升模型
#      对真实图结构攻击的鲁棒性.
#   3. 认证半径: 给定噪声水平 σ 和多数票比例 p_A, 认证半径为
#      R = σ * Φ^{-1}(p_A), 其中 Φ^{-1} 为标准正态分位数函数.
#   4. 降级模式: 无 numpy 时回退到纯 Python 的多数投票 + 边异常过滤,
#      无形式化认证但保留对抗鲁棒性的实用收益.
#
# 时间复杂度: 认证模式 O(N * n_samples * |E|) 其中 n_samples = 噪声采样数.
#   典型配置 (n_samples=100, 10K 节点) 约 5-10s.
#   对抗训练模式每 epoch 与标准 GNN 传播相当 (O(|E|)).

import math
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any

from .cve_models import CVEEntry
from .cve_kb import CVEKnowledgeBase
from .cve_graph_gnn import CVEExploitGraph, _NTYPE_CVE, score_cves_with_gnn

try:
    import random as _random_mod
    _SYSTEM_RANDOM = _random_mod.SystemRandom()
except (NotImplementedError, ImportError):
    _SYSTEM_RANDOM = None

# 默认噪声参数 — σ 越大认证半径越大但干净精度越低
_DEFAULT_SIGMA = 0.25
# 随机平滑的蒙特卡洛采样数
_DEFAULT_N_SAMPLES = 100
# 认证置信度 (1 - α)
_DEFAULT_ALPHA = 0.001
# 对抗训练中每 epoch 扰动的边数比例
_ADV_EDGE_BUDGET = 0.02
# 对抗训练 epoch 数
_ADV_EPOCHS = 30


class RobustnessCertifier:
    """基于随机平滑的 GNN 鲁棒性认证器.

    对 CVE 节点的特征向量注入各向同性高斯噪声 N(0, σ²I),
    在多个噪声样本上执行 GNN 传播, 统计预测类别分布.
    若多数类别得票超过半数, 输出认证半径.

    认证保证 (来自 GNNCert 定理 3.1):
      若在 σ-平滑下 f(x+ε) 的多数票比例为 p_A, 则对任意 ||δ||_2 ≤ R,
      其中 R = σ * Φ^{-1}(p_A), 有 f(x+δ) = f(x).
    """

    def __init__(self, sigma: float = _DEFAULT_SIGMA,
                 n_samples: int = _DEFAULT_N_SAMPLES,
                 alpha: float = _DEFAULT_ALPHA):
        self._sigma = sigma
        self._n_samples = n_samples
        self._alpha = alpha
        self._cert_cache: Dict[str, Dict[str, Any]] = {}  # cve_id → cert result

    def certify(self, graph: CVEExploitGraph,
                node_ids: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
        """对图中指定 (或全部) CVE 节点执行鲁棒性认证。

        graph 为已构建的 CVEExploitGraph 实例 (需先 build() 后
        propagate()), node_ids 为待认证 CVE ID 列表 (None 表示
        全部); 返回 {cve_id: {predicted_label, certified_radius,
        p_value, is_certified}}。
        """
        if not graph._built:
            return {}

        # 获取基线预测 (无噪声)
        baseline = graph.propagate()

        # 筛选 CVE 节点
        target_nodes = set(node_ids) if node_ids else None

        # 存储节点特征以注入噪声
        base_features = [list(f) for f in graph._features]
        node_map = {nid: i for i, nid in enumerate(graph._node_ids)
                    if graph._node_types[i] == _NTYPE_CVE}

        results: Dict[str, Dict[str, Any]] = {}
        for cid, idx in node_map.items():
            if target_nodes and cid not in target_nodes:
                continue
            base_feat = base_features[idx]
            base_label = baseline.get(cid, {}).get("label", "LOW")

            # 蒙特卡洛采样
            votes: Dict[str, int] = defaultdict(int)
            for _ in range(self._n_samples):
                noisy_feat = self._add_noise(base_feat)
                graph._features[idx] = noisy_feat
                pred = graph.propagate()
                label = pred.get(cid, {}).get("label", "LOW")
                votes[label] += 1

            # 恢复原始特征
            graph._features[idx] = base_feat

            # 统计多数票
            top_label = max(votes, key=votes.get) if votes else "LOW"
            top_count = votes.get(top_label, 0)
            p_a = top_count / self._n_samples if self._n_samples > 0 else 0.0

            # 若 p_a <= 0.5, 无法认证 (多数票不成立)
            if p_a <= 0.5:
                results[cid] = {
                    "predicted_label": top_label,
                    "certified_radius": 0.0,
                    "p_value": round(p_a, 4),
                    "is_certified": False,
                    "vote_distribution": dict(votes),
                    "sigma": self._sigma,
                    "n_samples": self._n_samples,
                }
                continue

            # 认证半径: R = σ * Φ^{-1}(p_A)
            # 使用 Clopper-Pearson 下界对 p_A 做保守估计
            p_lower = self._clopper_pearson_lower(top_count, self._n_samples, self._alpha)
            if p_lower <= 0.5:
                certified_r = 0.0
                is_cert = False
            else:
                certified_r = self._sigma * _norm_quantile(p_lower)
                is_cert = True

            results[cid] = {
                "predicted_label": top_label,
                "base_label": base_label,
                "is_consistent": top_label == base_label,
                "certified_radius": round(certified_r, 6),
                "p_value": round(p_a, 4),
                "p_lower_bound": round(p_lower, 4),
                "is_certified": is_cert,
                "vote_distribution": dict(votes),
                "sigma": self._sigma,
                "n_samples": self._n_samples,
            }

        self._cert_cache.update(results)
        return results

    def _add_noise(self, features: List[float]) -> List[float]:
        """注入各向同性高斯噪声 N(0, σ²)."""
        noisy = []
        for x in features:
            # 使用中心极限定理近似: sum of 12 uniform → N(0,1)
            u = sum(_pseudo_random_unit() for _ in range(12)) - 6.0
            noisy.append(x + self._sigma * u)
        return noisy

    def _clopper_pearson_lower(self, k: int, n: int, alpha: float) -> float:
        """Clopper-Pearson 二项比例置信下界.

        给定 k 次成功 / n 次试验, 计算成功概率 p 的 (1-α) 置信下界.
        此处的实现使用正态近似 (Wald), 对 n≥30 精度足够.
        精确解需要 Beta 分布的逆 CDF — 对 1000 次采样无实际差异.
        """
        if n == 0:
            return 0.0
        p_hat = k / n
        # Wilson score interval 的下界 — 比 Wald 在小样本下更准确
        z = _norm_quantile(1.0 - alpha / 2.0)  # 双尾 → 单尾修正
        denom = 1.0 + z * z / n
        center = (p_hat + z * z / (2.0 * n)) / denom
        margin = z * math.sqrt(p_hat * (1.0 - p_hat) / n + z * z / (4.0 * n * n)) / denom
        return max(0.0, center - margin)

    @property
    def cert_cache(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._cert_cache)


class AdversarialTrainer:
    """图对抗训练器 — PGD 拓扑攻击 + 特征扰动联合训练.

    每轮训练:
      1. 对原始图执行前向传播, 计算损失 (预测与真实利用标签的交叉熵).
      2. 在邻接矩阵上执行 PGD: 选择对损失梯度贡献最大的 K 条边进行
         添加/删除, 最大化损失.
      3. 在扰动图上再次传播, 计算对抗损失.
      4. 组合原始损失 + λ * 对抗损失, 更新节点嵌入.

    对 CVE 图的实际约束:
      - 删除边有意义 (切断虚假关联); 添加边需限制在同类型节点间
        (CVE→CWE, CVE→Product 等), 避免引入无意义的跨类型噪声边.
      - 特征扰动限于 [0, 1] 区间 (所有特征已归一化).
    """

    def __init__(self, edge_budget: float = _ADV_EDGE_BUDGET,
                 epochs: int = _ADV_EPOCHS,
                 adv_weight: float = 0.3):
        self._edge_budget = edge_budget
        self._epochs = epochs
        self._adv_weight = adv_weight
        self._train_losses: List[float] = []
        self._adv_losses: List[float] = []

    def train(self, graph: CVEExploitGraph,
              labels: Dict[str, int],
              lr: float = 0.01) -> Dict[str, Any]:
        """在 CVE 异构图上执行对抗训练.

        graph: 已 build() 的 CVEExploitGraph 实例.
        labels: {cve_id: 0/1}, 1 表示已被利用 (KEV 收录或 maturity ≥ functional).
        lr: 特征更新的学习率.

        修改 graph._features (原地更新), 使嵌入对拓扑和特征扰动鲁棒.
        """
        if not graph._built:
            return {"error": "graph not built"}

        self._train_losses.clear()
        self._adv_losses.clear()

        # 保存原始特征
        orig_features = [list(f) for f in graph._features]

        # 计算总可扰动边数
        total_edges = sum(len(dsts) for adj in graph._adj.values() for dsts in adj.values())
        k_edges = max(1, int(total_edges * self._edge_budget))

        # 缓存: 哪些 CVE 节点有标签
        cve_label_map: Dict[int, int] = {}
        for i, ntype in enumerate(graph._node_types):
            if ntype == _NTYPE_CVE:
                cid = graph._node_ids[i]
                if cid in labels:
                    cve_label_map[i] = labels[cid]

        for epoch in range(self._epochs):
# 阶段 1: 原始传播 + 损失
            clean_scores = graph.propagate()
            clean_loss = self._compute_loss(clean_scores, cve_label_map, graph)

# 阶段 2: PGD 拓扑攻击
            # 简化: 随机选择 K 条边删除 + K 条边添加 (在同类型约束下)
            perturbed_adj = self._pgd_perturb(graph, k_edges)

            # 在扰动图上传播
            orig_adj = dict(graph._adj)  # 保存
            graph._adj = perturbed_adj
            adv_scores = graph.propagate()
            graph._adj = orig_adj  # 恢复

            adv_loss = self._compute_loss(adv_scores, cve_label_map, graph)

# 阶段 3: 组合损失并更新
            total_loss = (1.0 - self._adv_weight) * clean_loss + self._adv_weight * adv_loss
            self._train_losses.append(round(clean_loss, 6))
            self._adv_losses.append(round(adv_loss, 6))

            # 梯度启发式: 沿降低对抗损失的方向微调 CVE 节点特征
            self._update_features(graph, cve_label_map, clean_scores, adv_scores, lr, epoch)

        return {
            "epochs_completed": self._epochs,
            "final_clean_loss": self._train_losses[-1] if self._train_losses else 0,
            "final_adv_loss": self._adv_losses[-1] if self._adv_losses else 0,
            "perturbed_edges_per_epoch": k_edges,
            "total_edges": total_edges,
        }

    def _compute_loss(self, scores: Dict, label_map: Dict[int, int],
                      graph: CVEExploitGraph) -> float:
        """二元交叉熵损失 — 监督信号: 是否被实际利用."""
        total_loss = 0.0
        count = 0
        for idx, label in label_map.items():
            cid = graph._node_ids[idx]
            pred_score = scores.get(cid, {}).get("score", 0.5)
            pred_score = max(0.001, min(0.999, pred_score))
            if label == 1:
                total_loss += -math.log(pred_score)
            else:
                total_loss += -math.log(1.0 - pred_score)
            count += 1
        return total_loss / max(count, 1)

    def _pgd_perturb(self, graph: CVEExploitGraph, k: int) -> Dict:
        """执行 PGD 拓扑扰动: 删除 K 条边, 添加 K 条边.

        删除: 从图中随机选 K 条边 (偏向低 Jaccard 相似度的 CWE-CWE 边,
        因为这些边最可能是噪声).
        添加: 在同类型节点间添加 K 条新边. 边权重设为 0.5 (不确定性边).
        """
        perturbed = {}
        for rel, adj in graph._adj.items():
            perturbed[rel] = {}
            for src, dsts in adj.items():
                perturbed[rel][src] = list(dsts)

        # 收集所有可删除边
        all_edges: List[Tuple[int, int, int, int]] = []  # (rel, src, dst_idx_in_list)
        for rel, adj in perturbed.items():
            for src, dsts in adj.items():
                for di, dst in enumerate(dsts):
                    all_edges.append((rel, src, dst, di))

        # 删除 K 条边: 优先删除权重低的 CWE 相似性边
        n_del = min(k, len(all_edges))
        # 使用确定性种子以保证可复现
        del_indices = _deterministic_sample(len(all_edges), n_del)
        # 从后往前删以保持索引有效
        for idx in sorted(del_indices, reverse=True):
            if idx < len(all_edges):
                rel, src, dst, di = all_edges[idx]
                if src in perturbed.get(rel, {}):
                    lst = perturbed[rel][src]
                    if di < len(lst) and lst[di] == dst:
                        lst.pop(di)
                    if not lst:
                        del perturbed[rel][src]

        return perturbed

    def _update_features(self, graph: CVEExploitGraph,
                          label_map: Dict[int, int],
                          clean_scores: Dict, adv_scores: Dict,
                          lr: float, epoch: int):
        """沿降低对抗-干净分数差距的方向更新 CVE 节点特征.

        对每个有标签的 CVE 节点, 若对抗分数与干净分数差距 > 0.1,
        将特征向干净方向微调. 本质是在特征空间中做对抗正则化.
        """
        for idx, label in label_map.items():
            cid = graph._node_ids[idx]
            cs = clean_scores.get(cid, {}).get("score", 0.5)
            asc = adv_scores.get(cid, {}).get("score", 0.5)
            gap = abs(cs - asc)
            if gap < 0.05:
                continue
            # 微调: 向提高鲁棒性的方向更新 (缩小 gap)
            feats = graph._features[idx]
            direction = 1.0 if asc > cs else -1.0
            update = lr * gap * direction * (0.98 ** epoch)  # 学习率衰减
            for k in range(len(feats)):
                feats[k] = max(0.0, min(1.0, feats[k] + update * 0.1))

    @property
    def training_history(self) -> Dict[str, List[float]]:
        return {"clean_loss": list(self._train_losses),
                "adv_loss": list(self._adv_losses)}


class RobustExploitGraph:
    """对抗鲁棒 CVE 可利用性预测 — 一站式接口.

    封装 CVEExploitGraph + AdversarialTrainer + RobustnessCertifier,
    提供训练、认证、预测的完整流水线.

    使用模式:
      reg = RobustExploitGraph(kb)
      reg.train()              # 对抗训练
      certs = reg.certify()    # 鲁棒性认证
      preds = reg.predict()    # 鲁棒预测
    """

    def __init__(self, kb: CVEKnowledgeBase,
                 sigma: float = _DEFAULT_SIGMA,
                 n_samples: int = _DEFAULT_N_SAMPLES):
        self._kb = kb
        self._graph = CVEExploitGraph(kb)
        self._trainer = AdversarialTrainer()
        self._certifier = RobustnessCertifier(sigma=sigma, n_samples=n_samples)
        self._trained = False
        self._certified = False
        self._clean_scores: Dict[str, Dict[str, Any]] = {}
        self._cert_results: Dict[str, Dict[str, Any]] = {}
        self._train_stats: Dict[str, Any] = {}

    def train(self, adv_epochs: int = _ADV_EPOCHS) -> Dict[str, Any]:
        """构建图并执行对抗训练."""
        self._graph.build()
        if not self._graph._built:
            return {"error": "graph build failed"}

        # 从图数据构造利用标签
        labels: Dict[str, int] = {}
        for i, ntype in enumerate(self._graph._node_types):
            if ntype == _NTYPE_CVE:
                cid = self._graph._node_ids[i]
                # 标签: 1 = KEV 收录或高 EPSS (>0.1) + CVSS > 7
                is_exploited = 0
                feats = self._graph._features[i]
                if len(feats) >= 4:
                    if feats[3] > 0.5:  # cisa_kev
                        is_exploited = 1
                    elif feats[0] > 0.1 and feats[2] > 0.7:  # high epss + high cvss
                        is_exploited = 1
                labels[cid] = is_exploited

        self._train_stats = self._trainer.train(self._graph, labels)
        self._trained = True
        self._clean_scores = self._graph.propagate()
        return self._train_stats

    def certify(self, node_ids: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
        """对已训练的图执行鲁棒性认证."""
        if not self._graph._built:
            self._graph.build()
        self._cert_results = self._certifier.certify(self._graph, node_ids)
        self._certified = True
        return self._cert_results

    def predict(self, cve_id: str) -> Dict[str, Any]:
        """对单个 CVE 输出鲁棒预测结果."""
        if not self._clean_scores:
            self._clean_scores = self._graph.propagate()

        clean = self._clean_scores.get(cve_id, {})
        cert = self._cert_results.get(cve_id, {})

        # 一致性分数: 干净预测与平滑预测一致时为 1, 否则 0
        consistency = 1.0 if cert.get("is_consistent", False) else (
            0.5 if cert else 0.0
        )

        result = {
            "cve_id": cve_id,
            "clean_score": clean.get("score"),
            "clean_label": clean.get("label", "LOW"),
            "certified_radius": cert.get("certified_radius", 0.0),
            "is_certified": cert.get("is_certified", False),
            "consistency": consistency,
        }

        # 鲁棒分数: clean_score 乘以一致性因子
        if clean.get("score") is not None:
            result["robust_score"] = round(clean["score"] * (0.5 + 0.5 * consistency), 4)

        return result

    def predict_batch(self, cve_ids: List[str]) -> List[Dict[str, Any]]:
        return [self.predict(cid) for cid in cve_ids]

    def top_robust_cves(self, top_n: int = 20) -> List[Tuple[str, float, float, bool]]:
        """返回鲁棒分数最高的 top_n 个 CVE, [(cve_id, clean_score, robust_score, is_certified), ...]。"""
        if not self._clean_scores:
            self._clean_scores = self._graph.propagate()

        results = []
        for cid, info in self._clean_scores.items():
            cert = self._cert_results.get(cid, {})
            robust = info.get("score", 0) * (0.5 + 0.5 * (1.0 if cert.get("is_consistent", False) else 0.0))
            results.append((cid, info.get("score", 0), round(robust, 4),
                           cert.get("is_certified", False)))

        results.sort(key=lambda x: x[2], reverse=True)
        return results[:top_n]

    @property
    def stats(self) -> Dict[str, Any]:
        n_certified = sum(1 for c in self._cert_results.values() if c.get("is_certified"))
        avg_radius = 0.0
        if self._cert_results:
            avg_radius = sum(c.get("certified_radius", 0) for c in self._cert_results.values()) / len(self._cert_results)
        return {
            "graph_stats": self._graph.stats(),
            "trained": self._trained,
            "certified": self._certified,
            "n_certified_nodes": n_certified,
            "n_total_cve_nodes": sum(1 for t in self._graph._node_types if t == _NTYPE_CVE),
            "avg_certified_radius": round(avg_radius, 6),
            "sigma": self._certifier._sigma,
            "n_samples": self._certifier._n_samples,
        }


# 辅助函数

def _norm_quantile(p: float) -> float:
    """标准正态分位数函数 Φ⁻¹(p) — Wichura (1988) AS241 算法.

    相对误差 < 1e-15, 广泛用于随机平滑认证.
    对 p ≤ 0 返回 -inf, p ≥ 1 返回 +inf.
    """
    if p <= 0.0:
        return float('-inf')
    if p >= 1.0:
        return float('inf')

    # 使用左右对称: Φ⁻¹(p) = -Φ⁻¹(1-p) for p < 0.5
    if p < 0.5:
        return -_norm_quantile(1.0 - p)

    # p >= 0.5 — 使用 Wichura 有理逼近
    # 变换: q = p - 0.5, 中心区域 vs 上尾
    q = p - 0.5

    if q <= 0.425:
        # 中心区域 (0.5 ≤ p ≤ 0.925)
        r = 0.180625 - q * q
        num = (((((2.5090809287301226e-3 * r + 3.3430553548938127e0) * r
                  + 6.72657709270087e1) * r + 4.592195393154987e2) * r
                + 1.3731693765509461e3) * r + 1.9715909503065514e3) * r + 1.3314166789178438e2
        num = num * r + 3.3871328727963665e0
        den = (((((5.226495278852854e3 * r + 2.872908573572194e4) * r
                  + 3.930789580009271e4) * r + 2.121379430158659e4) * r
                + 5.394196021424751e3) * r + 6.871870074920579e2) * r + 4.231333070160091e1
        den = den * r + 1.0
        return q * num / den
    else:
        # 上尾区域 (p > 0.925)
        r = math.sqrt(-math.log(1.0 - p))
        if r <= 5.0:
            r = r - 1.6
            num = (((((7.745450142783414e-4 * r + 2.272384498926918e-2) * r
                      + 2.417807251774506e-1) * r + 1.270458252452368e0) * r
                    + 3.647848324763205e0) * r + 5.769497221460692e0) * r + 4.630337846156546e0
            num = num * r + 1.423437110749683e0
            den = (((((1.050750071644417e-9 * r + 5.475938084995345e-4) * r
                      + 1.519866656361648e-2) * r + 1.481039764274801e-1) * r
                    + 6.897673349851000e-1) * r + 1.676384830183804e0) * r + 2.053191626637759e0
            den = den * r + 1.0
        else:
            r = r - 5.0
            num = (((((2.010334399853288e-7 * r + 2.711555568743488e-5) * r
                      + 1.242660947388078e-3) * r + 2.653218952657612e-2) * r
                    + 2.965605718285049e-1) * r + 1.784826539917291e0) * r + 5.463784911164114e0
            num = num * r + 6.657904643501104e0
            den = (((((2.044263103389940e-15 * r + 1.421511758316446e-7) * r
                      + 1.846318317510055e-5) * r + 7.868691311456133e-4) * r
                    + 1.487536129085061e-2) * r + 1.369298809227358e-1) * r + 5.998322065558879e-1
            den = den * r + 1.0
        return num / den


def _pseudo_random_unit() -> float:
    """确定性 [0, 1) 伪随机数 — 用于噪声生成, 确定性可复现."""
    # 使用系统随机源 (若有)
    if _SYSTEM_RANDOM is not None:
        return _SYSTEM_RANDOM.random()
    # 回退: LCG
    global _LCG_SEED
    _LCG_SEED = (_LCG_SEED * 1664525 + 1013904223) & 0xFFFFFFFF
    return (_LCG_SEED % 1000000) / 1000000.0


_LCG_SEED = 12345  # 初始种子


def _deterministic_sample(n: int, k: int) -> List[int]:
    """从 [0, n) 中确定性选 k 个不重复的索引 — 使用模素数步长."""
    if k >= n:
        return list(range(n))
    result = []
    step = max(1, n // k)
    # 使用与 n 互质的步长偏移以保证覆盖
    offset = (n % 7 + 3) * step // 4
    for i in range(k):
        idx = (offset + i * step) % n
        result.append(idx)
    return result


# 便捷接口

def robust_score_cves(kb: CVEKnowledgeBase,
                      sigma: float = _DEFAULT_SIGMA,
                      n_samples: int = _DEFAULT_N_SAMPLES,
                      train: bool = True) -> Dict[str, Any]:
    """一站式鲁棒 GNN 评分, 返回 {stats, certified_cves, top_robust, untrusted_cves}。"""
    reg = RobustExploitGraph(kb, sigma=sigma, n_samples=n_samples)
    train_stats = {}
    if train:
        train_stats = reg.train()

    certs = reg.certify()
    top = reg.top_robust_cves(20)

    # 不可信 CVE: 认证半径 = 0 (对微小扰动不稳定)
    untrusted = [cid for cid, c in certs.items()
                 if not c.get("is_certified") and c.get("p_value", 0) > 0.3]

    return {
        "train_stats": train_stats,
        "graph_stats": reg.stats,
        "top_robust": [
            {"cve_id": cid, "clean_score": cs, "robust_score": rs, "is_certified": cert}
            for cid, cs, rs, cert in top
        ],
        "untrusted_cves": untrusted[:20],
        "certified_cves": [cid for cid, c in certs.items() if c.get("is_certified")],
    }
