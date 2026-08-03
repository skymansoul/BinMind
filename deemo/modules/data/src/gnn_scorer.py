# 图结构二进制相似度评分 — 基于函数调用图的图核匹配
# 文献依据:
#   Collyer et al., "Know Your Neighborhood..." (arXiv:2406.02606, 2024)
#   HermesSim [He et al., USENIX Security 2024]: SOG + GNN + multi-head softmax, x64 跨架构召回比 Trex 高 184%
#   GBsim [Du & Wei, Entropy 2025]: GCN + BERT, MRR=0.901, Recall@1=0.831
#   补充参考:
#     Bin2vec — 二进制函数嵌入 baseline 方案
#     VulANalyzeR — GCN+attention 结构, 多任务联合训练
#     BEDetector — 双通道编码策略
#     VulHawk — 熵引导跨架构搜索 (与 WL kernel 互补)
#     Unsupervised Binary Code Translation — 无监督跨架构翻译

import math
from typing import Dict, List, Tuple, Set, Optional, Any
from collections import Counter, defaultdict

# ---------------------------------------------------------------------------
# CallGraphBuilder — 从分析结果构造调用图
# ---------------------------------------------------------------------------

class CallGraph:
    """有向调用图。

    节点: 函数地址 (int/str)
    边: caller → callee
    无向版本供 WL kernel 做子树模式提取。
    """

    def __init__(self):
        self._adj: Dict[str, Set[str]] = defaultdict(set)
        self._rev_adj: Dict[str, Set[str]] = defaultdict(set)
        self._nodes: Set[str] = set()

    def add_edge(self, caller: str, callee: str):
        self._adj[caller].add(callee)
        self._rev_adj[callee].add(caller)
        self._nodes.add(caller)
        self._nodes.add(callee)

    @property
    def nodes(self) -> Set[str]:
        return self._nodes

    @property
    def edge_count(self) -> int:
        return sum(len(v) for v in self._adj.values())

    def neighbors(self, node: str) -> Set[str]:
        return self._adj.get(node, set()) | self._rev_adj.get(node, set())

    def degree(self, node: str) -> int:
        return len(self.neighbors(node))

    @classmethod
    def from_findings(cls, findings: List[dict]) -> "CallGraph":
        """从分析结果列表构造调用图。

        接受的 findings 格式:
          {"type": "call_edge", "caller": "0x401000", "callee": "0x402000"}
          {"type": "function_call", "from": "main", "to": "printf"}
          {"call_graph": [{"src": "...", "dst": "..."}, ...]}
        """
        cg = cls()
        for f in findings:
            ftype = f.get("type", "")
            if ftype in ("call_edge", "function_call"):
                src = f.get("caller") or f.get("from") or f.get("src")
                dst = f.get("callee") or f.get("to") or f.get("dst")
                if src and dst:
                    cg.add_edge(str(src), str(dst))
            elif ftype == "call_graph" or "call_graph" in f:
                edges = f.get("call_graph", [])
                for e in edges:
                    s = e.get("src") or e.get("caller") or e.get("from")
                    d = e.get("dst") or e.get("callee") or e.get("to")
                    if s and d:
                        cg.add_edge(str(s), str(d))
        return cg

    def stats(self) -> dict:
        degrees = [self.degree(n) for n in self._nodes]
        return {
            "nodes": len(self._nodes),
            "edges": self.edge_count,
            "max_degree": max(degrees) if degrees else 0,
            "avg_degree": round(sum(degrees) / max(len(degrees), 1), 2),
            "isolated_nodes": sum(1 for d in degrees if d == 0),
        }


# ---------------------------------------------------------------------------
# GraphletCounter — 3-node / 4-node 子图模式计数
# 参考 Collyer et al. (2024) 的 call graphlets 方案。
# 3-node graphlet: 3 个连通节点有 2 种非同构模式
#   - triangle (3 条边: A-B, B-C, C-A)
#   - path (2 条边: A-B-C)
# 4-node graphlet: 6 种非同构连通模式
# ---------------------------------------------------------------------------

def count_graphlets(cg: CallGraph, node: str, size: int = 3) -> Counter:
    """单节点 graphlet 分布统计。

    size=3: 统计该节点参与的所有 3-node graphlet → Counter({pattern: count})
    pattern key = 规范化度序列串 (如 "1-1-2" = path, "2-2-2" = triangle)。
    graphlet 谱作为节点的特征向量供图核使用。
    """
    nb = cg.neighbors(node)
    nb_list = list(nb)
    patterns = Counter()

    if size == 3:
        for i in range(len(nb_list)):
            for j in range(i + 1, len(nb_list)):
                a, b = nb_list[i], nb_list[j]
                # 三个节点: node, a, b
                edges = 0
                if a in cg.neighbors(node):
                    edges += 1
                if b in cg.neighbors(node):
                    edges += 1
                if a in cg.neighbors(b) or b in cg.neighbors(a):
                    edges += 1
                degs = tuple(sorted([
                    cg.degree(node), cg.degree(a), cg.degree(b)
                ]))
                patterns[f"3-{degs}"] += 1

    return patterns


def graphlet_spectrum(cg: CallGraph, sample_size: int = 100) -> List[float]:
    """整图 graphlet 频谱 —— 所有节点 graphlet 计数经归一化后压入定长向量。

    采样: 节点数 > sample_size 时随机取 sample_size 个节点做近似。
    输出: 定长 float 向量，供图间相似度比对。
    """
    import random
    nodes = list(cg.nodes)
    if len(nodes) > sample_size:
        rng = random.Random(42)
        nodes = rng.sample(nodes, sample_size)

    pattern_counter = Counter()
    total_graphlets = 0
    for node in nodes:
        gc = count_graphlets(cg, node, size=3)
        for pat, cnt in gc.items():
            pattern_counter[pat] += cnt
            total_graphlets += cnt

    # 归一化为频率向量
    if total_graphlets == 0:
        return [0.0] * 16   # 无可用数据时的回退维度

    patterns_sorted = sorted(pattern_counter.keys())
    vec = [pattern_counter[p] / total_graphlets for p in patterns_sorted]
    # 对齐至固定维度
    while len(vec) < 16:
        vec.append(0.0)
    return vec[:16]


# ---------------------------------------------------------------------------
# Weisfeiler-Lehman Subtree Kernel — 经典图核方法
# Shervashidze et al., "Weisfeiler-Lehman Graph Kernels", JMLR 2011.
# 通过迭代标签压缩捕获子树模式，对调用图局部结构敏感，
# 计算复杂度 O(h·m) (h 轮迭代, m 边数)。
# ---------------------------------------------------------------------------

def wl_subtree_features(cg: CallGraph, iterations: int = 3) -> Dict[str, Counter]:
    """WL 子树核特征提取 —— 每轮迭代返回压缩标签的计数分布。

    流程:
      1. 初始化: 各节点标签 = degree 字符串
      2. 每轮: 收集邻域标签 → 排序拼接 → 哈希压缩 → 新标签
      3. 记录每轮标签分布 (Counter)
    返回值 {iter_0: Counter, iter_1: Counter, ...},
    两图相似度 = sum_i dot(feats_a[i], feats_b[i]) / (norm_a * norm_b)
    """
    labels: Dict[str, str] = {}
    for node in cg.nodes:
        labels[node] = str(cg.degree(node))

    features: Dict[str, Counter] = {}
    for h in range(iterations):
        features[f"iter_{h}"] = Counter(labels.values())

        # 标签压缩: 收集邻域标签 → 哈希
        new_labels: Dict[str, str] = {}
        for node in cg.nodes:
            nb_labels = sorted([
                labels[nb] for nb in cg.neighbors(node)
            ])
            signature = labels[node] + "|" + ",".join(nb_labels)
            import hashlib
            new_label = hashlib.md5(signature.encode()).hexdigest()[:8]
            new_labels[node] = new_label
        labels = new_labels

    return features


# ---------------------------------------------------------------------------
# GraphScorer — 多信号融合评分
# ---------------------------------------------------------------------------

class GraphScorer:
    """基于图结构的二进制签名相似度评分。

    融合三种信号:
      1. Graphlet spectrum 余弦相似度 (权重 0.4)
      2. WL subtree kernel 特征相似度 (权重 0.4)
      3. 元数据相似度 (size + tag + stage) (权重 0.2)
    缺失图结构时退化为纯元数据评分。
    """

    def __init__(self, w_graphlet: float = 0.4, w_wl: float = 0.4,
                 w_meta: float = 0.2):
        self.wg = w_graphlet
        self.ww = w_wl
        self.wm = w_meta
        self._cache: Dict[int, tuple] = {}

    def build_features(self, sig_id: int, findings: List[dict]) -> tuple:
        """为签名构建缓存特征三元组 (graphlet_vec, wl_features, has_graph)。"""
        cg = CallGraph.from_findings(findings)
        has_graph = len(cg.nodes) > 0
        if has_graph:
            g_vec = graphlet_spectrum(cg)
            wl_f = wl_subtree_features(cg, iterations=3)
        else:
            g_vec = []
            wl_f = {}
        self._cache[sig_id] = (g_vec, wl_f, has_graph)
        return self._cache[sig_id]

    def score(self, sig_a: int, sig_b: int,
              findings_a: List[dict] = None,
              findings_b: List[dict] = None,
              meta_a: dict = None, meta_b: dict = None) -> float:
        """返回 [0, 1] 区间的相似度分值。"""
        if findings_a is not None:
            self.build_features(sig_a, findings_a)
        if findings_b is not None:
            self.build_features(sig_b, findings_b)

        f_a = self._cache.get(sig_a)
        f_b = self._cache.get(sig_b)
        if f_a is None or f_b is None:
            return 0.0   # 缓存未命中

        gv_a, wl_a, has_a = f_a
        gv_b, wl_b, has_b = f_b

        scores = []

        # Graphlet 相似度
        if has_a and has_b and gv_a and gv_b:
            scores.append((self.wg, _cosine(gv_a, gv_b)))
        elif not has_a and not has_b:
            scores.append((self.wg, 1.0))  # 双方均无图 → 结构维度视为不可区分
        else:
            scores.append((self.wg, 0.2))  # 单方有图 → 低相似

        # WL 相似度
        if has_a and has_b and wl_a and wl_b:
            scores.append((self.ww, _wl_similarity(wl_a, wl_b)))
        elif not has_a and not has_b:
            scores.append((self.ww, 1.0))
        else:
            scores.append((self.ww, 0.2))

        # 元数据相似度
        meta_sim = 0.5
        if meta_a and meta_b:
            meta_sim = _metadata_similarity(meta_a, meta_b)
        scores.append((self.wm, meta_sim))

        total = sum(w * s for w, s in scores)
        return round(total, 4)

    def top_k(self, query_sig: int, candidate_ids: List[int],
              db, k: int = 10) -> List[Tuple[int, float]]:
        """从候选集中返回与 query_sig 最相似的 k 个签名。"""
        q_findings_raw = db.get_analyses(query_sig)
        q_findings = _flatten_findings(q_findings_raw)
        q_meta = db.get_signature_by_id(query_sig) or {}
        self.build_features(query_sig, q_findings)

        scored = []
        for cid in candidate_ids:
            if cid == query_sig:
                continue
            c_findings_raw = db.get_analyses(cid)
            c_findings = _flatten_findings(c_findings_raw)
            c_meta = db.get_signature_by_id(cid) or {}
            s = self.score(query_sig, cid,
                           findings_b=c_findings,
                           meta_a=q_meta, meta_b=c_meta)
            scored.append((cid, s))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:k]

    def clear_cache(self):
        self._cache.clear()


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def _flatten_findings(analysis_rows: List[dict]) -> List[dict]:
    """将多行 analysis_results 展平为单层 findings 列表。"""
    all_findings = []
    for row in analysis_rows:
        findings = row.get("findings", [])
        if isinstance(findings, str):
            import json
            try:
                findings = json.loads(findings)
            except Exception:
                findings = []
        if isinstance(findings, list):
            all_findings.extend(findings)
    return all_findings


def _cosine(a: List[float], b: List[float]) -> float:
    ln = min(len(a), len(b))
    if ln == 0:
        return 0.0
    dot = sum(a[i] * b[i] for i in range(ln))
    norm_a = math.sqrt(sum(x * x for x in a[:ln]))
    norm_b = math.sqrt(sum(x * x for x in b[:ln]))
    denom = norm_a * norm_b
    return dot / denom if denom > 0 else 0.0


def _wl_similarity(feats_a: Dict[str, Counter],
                   feats_b: Dict[str, Counter]) -> float:
    """两个 WL 特征集的余弦相似度 —— 各迭代层标签频率拼接后计算。"""
    keys = sorted(set(feats_a.keys()) | set(feats_b.keys()))
    if not keys:
        return 0.0
    sims = []
    for k in keys:
        ca = feats_a.get(k, Counter())
        cb = feats_b.get(k, Counter())
        all_labels = set(ca.keys()) | set(cb.keys())
        va = [ca.get(l, 0) for l in all_labels]
        vb = [cb.get(l, 0) for l in all_labels]
        s = _cosine(va, vb)
        sims.append(s)
    return sum(sims) / len(sims)


def _metadata_similarity(meta_a: dict, meta_b: dict) -> float:
    """签名元数据启发式相似度 —— 基于 file_size + stage + tags。"""
    score = 0.0
    w = 0.0

    # file_size 相似度 (对数空间)
    sa = meta_a.get("file_size", 0)
    sb = meta_b.get("file_size", 0)
    if sa > 0 and sb > 0:
        ratio = min(sa, sb) / max(sa, sb)
        score += ratio * 0.5
        w += 0.5

    # stage 一致
    if meta_a.get("stage") == meta_b.get("stage"):
        score += 0.3
        w += 0.3

    # tags 重叠 (Jaccard)
    ta = set(meta_a.get("tags", []) if isinstance(meta_a.get("tags"), list) else [])
    tb = set(meta_b.get("tags", []) if isinstance(meta_b.get("tags"), list) else [])
    if ta and tb:
        jac = len(ta & tb) / max(len(ta | tb), 1)
        score += jac * 0.2
        w += 0.2

    return score / w if w > 0 else 0.5
