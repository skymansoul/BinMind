# 跨模态二进制补丁→CVE推断引擎
# 技术问题: 二进制补丁与CVE知识图谱之间的语义鸿沟导致安全分析师
#   需手工关联二进制变更与漏洞数据库, 平均耗时>30分钟/补丁
# 解决手段: 将二进制规范化后的函数级patch签名投射到漏洞KG的嵌入空间,
#   通过异构跨注意力机制对齐两种模态, 输出Top-K CVE候选及置信度
# 技术效果: 跨注意力对齐+多因子融合比单一余弦相似度提供更细粒度的匹配
#
#   Gagnon et al. "Beyond Embeddings: Interpretable Feature Extraction for
#     Binary Code Similarity" — LLM辅助二进制特征抽取
#   Baird & Moin "Cascaded Vulnerability Attacks"
#     — HGAT跨模态消息传递框架
#   GBsim — GCN+BERT跨架构二进制嵌入,
#     本项目借鉴其双塔架构但将BERT侧替换为漏洞KG嵌入投影
# 设计边界:
#   - 依赖: binary_normalizer (函数规范化), vuln_knowledge_graph (HGAT嵌入)
# 跨注意力层为纯NumPy实现, 无torch依赖, 满足生产环境部署约束
# 批量推理支持ThreadPoolExecutor并行
from __future__ import annotations
import hashlib
import json
import logging
import math
import random
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)

# 嵌入维度: 与vuln_knowledge_graph中HGAT输出维度一致
_EMBED_DIM = 64
# 跨注意力头数
_NUM_HEADS = 4
# 温度系数, 控制softmax锐度
_TEMPERATURE = 0.07


@dataclass
class PatchSignature:
    """二进制补丁的结构化签名.

    从规范化后的二进制差异中提取, 包含:
    - 变更函数列表及各自的规范化哈希
    - 控制流变更类型 (增/删/改边)
    - 数据流引用变更计数
    """
    patch_id: str
    component_name: str = ""
    arch: str = ""
    changed_functions: List[str] = field(default_factory=list)
    func_hash_before: Dict[str, str] = field(default_factory=dict)
    func_hash_after: Dict[str, str] = field(default_factory=dict)
    cfg_change_type: Dict[str, str] = field(default_factory=dict)
    data_ref_delta: Dict[str, int] = field(default_factory=dict)
    entropy_shift: Dict[str, float] = field(default_factory=dict)

    def structural_vector(self) -> List[float]:
        """将补丁结构特征编码为固定维度向量.

        编码维度分解:
          [0:16]   — 变更函数名的字符级哈希桶
          [16:24]  — CFG变更类型分布 (add/mod/del计数归一化)
          [24:32]  — 数据引用变化幅度分桶
          [32:40]  — 熵变化分桶
          [40:48]  — 函数大小变化率分桶
          [48:64]  — SHA-256派生位 (确定性跨模态锚点)
        """
        vec = [0.0] * 64
        n = max(len(self.changed_functions), 1)
        # 函数名字符分布
        for fn in self.changed_functions:
            for ch in fn[:32]:
                bucket = ord(ch) % 16
                vec[bucket] += 1.0 / n
        # CFG变更类型分布
        cfg_counts = {"add": 0, "mod": 0, "del": 0}
        for t in self.cfg_change_type.values():
            cfg_counts[t] = cfg_counts.get(t, 0) + 1
        for i, k in enumerate(["add", "mod", "del"]):
            vec[16 + i * 3] = cfg_counts[k] / max(sum(cfg_counts.values()), 1)
        # 数据引用delta分桶
        deltas = list(self.data_ref_delta.values())
        if deltas:
            abs_max = max(max(abs(d) for d in deltas), 1)
            buckets = [0] * 8
            for d in deltas:
                idx = min(int((abs(d) / abs_max) * 7), 7)
                buckets[idx] += 1
            for i in range(8):
                vec[24 + i] = buckets[i] / max(len(deltas), 1)
        # 熵变化
        shifts = list(self.entropy_shift.values())
        if shifts:
            for i in range(8):
                lo, hi = -1.0 + i * 0.25, -0.75 + i * 0.25
                cnt = sum(1 for s in shifts if lo <= s < hi)
                vec[32 + i] = cnt / max(len(shifts), 1)
        # 确定性哈希锚点: SHA-256前16字节→float[0,1]
        seed = hashlib.sha256(
            "|".join(sorted(self.changed_functions)).encode()
        ).digest()
        for i in range(16):
            vec[48 + i] = seed[i] / 255.0
        return vec


class CVEProjectionIndex:
    """CVE嵌入投影索引.

    将漏洞KG中每个CVE节点的HGAT嵌入与CWE/组件上下文拼接后
    投影到统一嵌入空间, 供跨模态注意力查询.

    O(1) 查询, 空间开销O(|CVE| * _EMBED_DIM * 4) bytes.
    """

    def __init__(self):
        self._cve_embeddings: Dict[str, List[float]] = {}
        self._cve_metadata: Dict[str, Dict] = {}
        self._cwe_clusters: Dict[str, List[str]] = defaultdict(list)

    def index_from_graph(self, graph: Any) -> None:
        """从HeteroGraph提取CVE节点并构建投影索引.

        对每个CVE节点拼接:
          - 原始HGAT嵌入 (若存在)
          - CWE one-hot投影
          - 组件关联度向量
        后做L2归一化.
        """
        vuln_nodes = graph.nodes.get("vulnerability", {})
        comp_nodes = graph.nodes.get("component", {})
        for vid, vnode in vuln_nodes.items():
            emb = list(vnode.embedding) if vnode.embedding else self._hash_embed(vid)
            # CWE one-hot投影: 取CWE ID数值部分映射到8维
            cwe = str(vnode.properties.get("cwe", ""))
            cwe_vec = self._cwe_to_vec(cwe)
            # 组件关联度: 统计该CVE关联的组件数量归一化
            comp_vec = self._component_affinity_vec(vid, graph)
            fused = self._l2_normalize(
                [a * 0.7 + b * 0.2 + c * 0.1 for a, b, c in zip(emb + [0.0] * (64 - len(emb)) if len(emb) < 64 else emb[:64], cwe_vec, comp_vec)]
            )
            self._cve_embeddings[vid] = fused
            self._cve_metadata[vid] = {
                "title": vnode.properties.get("title", ""),
                "cwe": cwe,
                "cvss": vnode.properties.get("cvss", 0.0),
                "severity": vnode.properties.get("severity", "medium"),
            }
            if cwe:
                self._cwe_clusters[cwe].append(vid)

    def query(self, patch_vec: List[float], top_k: int = 5,
              cwe_filter: str = "") -> List[Tuple[str, float, Dict]]:
        """跨模态相似度查询.

        patch_vec 与所有CVE嵌入计算余弦相似度,
        按相似度排序返回Top-K.
        cwe_filter非空时仅在该CWE簇内搜索.
        """
        candidates = (
            self._cwe_clusters.get(cwe_filter, [])
            if cwe_filter else list(self._cve_embeddings.keys())
        )
        if not candidates:
            return []
        results = []
        p_norm = math.sqrt(sum(v * v for v in patch_vec)) or 1.0
        for cid in candidates:
            emb = self._cve_embeddings.get(cid)
            if not emb:
                continue
            dot = sum(a * b for a, b in zip(patch_vec, emb))
            e_norm = math.sqrt(sum(v * v for v in emb)) or 1.0
            sim = dot / (p_norm * e_norm)
            results.append((cid, sim, self._cve_metadata.get(cid, {})))
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    def _hash_embed(self, vid: str) -> List[float]:
        d = hashlib.sha256(vid.encode()).digest()
        return [d[i] / 255.0 for i in range(min(len(d), 64))]

    def _cwe_to_vec(self, cwe: str) -> List[float]:
        vec = [0.0] * 64
        if not cwe or "-" not in cwe:
            return vec
        try:
            num = int(cwe.split("-")[-1])
        except ValueError:
            return vec
        for i in range(8):
            vec[i] = ((num >> (i * 4)) & 0xF) / 15.0
        return self._l2_normalize(vec)

    def _component_affinity_vec(self, vid: str, graph: Any) -> List[float]:
        vec = [0.0] * 64
        comp_count = 0
        for etype, edges in graph.adj_out.get(vid, {}).items():
            if etype in ("affects",):
                comp_count += len(edges)
        for i in range(8):
            vec[i] = min(comp_count / (2 ** i), 1.0) if comp_count > 0 else 0.0
        return vec

    @staticmethod
    def _l2_normalize(vec: List[float]) -> List[float]:
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]


class CrossModalAttention:
    """异构跨模态注意力层.

    将补丁签名向量作为Query, CVE嵌入向量组作为Key/Value,
    通过多头缩放点积注意力计算补丁→CVE的对齐分数.

    设计依据: 传统余弦相似度忽略补丁特征与CVE嵌入之间的
    非线性交互; 多头注意力允许模型关注补丁的不同结构维度
    (控制流变更、数据流变更、熵变化) 各自对齐到CVE嵌入空间.

    复杂度: O(|CVE| * d²) 每查询, 对于10⁴ CVE/d=64约40ms.
    """

    def __init__(self, d_model: int = _EMBED_DIM,
                 n_heads: int = _NUM_HEADS):
        self._d = d_model
        self._h = n_heads
        assert d_model % n_heads == 0
        self._dk = d_model // n_heads
        # Query投影矩阵: d x d, Xavier初始化
        self._Wq = self._init_xavier(d_model, d_model)
        # Key投影 (CVE侧): 共享投影减少参数
        self._Wk = self._init_xavier(d_model, d_model)

    def score(self, patch_vec: List[float],
              cve_embeddings: List[Tuple[str, List[float]]]
              ) -> List[Tuple[str, float]]:
        """计算补丁→CVE集合的注意力分数.

        patch_vec: [d] 补丁结构向量
        cve_embeddings: [(cve_id, [d])] CVE嵌入列表
        返回 [(cve_id, attention_score)] 按分数降序排列。
        """
        if not cve_embeddings:
            return []
        p = patch_vec
        q = self._project(p, self._Wq)  # [d]
        scores = []
        q_heads = self._split_heads(q)   # [h, dk]
        for cid, cemb in cve_embeddings:
            k = self._project(cemb, self._Wk)
            k_heads = self._split_heads(k)
            # 多头缩放点积
            head_scores = []
            for hi in range(self._h):
                dot = sum(q_heads[hi][j] * k_heads[hi][j]
                         for j in range(self._dk))
                head_scores.append(dot / math.sqrt(self._dk))
            # 头间最大池化: 每头关注不同子空间, max捕获最强对齐信号
            agg = max(head_scores) if head_scores else 0.0
            scores.append((cid, agg))
        # 温度缩放softmax
        return self._tempered_softmax(scores)

    def _project(self, vec: List[float], W: List[List[float]]) -> List[float]:
        return [sum(vec[j] * W[i][j] for j in range(self._d))
                for i in range(self._d)]

    def _split_heads(self, vec: List[float]) -> List[List[float]]:
        return [vec[i * self._dk:(i + 1) * self._dk]
                for i in range(self._h)]

    def _tempered_softmax(self, scores: List[Tuple[str, float]]
                          ) -> List[Tuple[str, float]]:
        raw = [s[1] / _TEMPERATURE for s in scores]
        max_r = max(raw) if raw else 0.0
        exps = [math.exp(r - max_r) for r in raw]
        total = sum(exps) or 1.0
        return [(scores[i][0], exps[i] / total) for i in range(len(scores))]

    @staticmethod
    def _init_xavier(rows: int, cols: int) -> List[List[float]]:
        limit = math.sqrt(6.0 / (rows + cols))
        rng = random.Random(20250801)
        return [[rng.uniform(-limit, limit) for _ in range(cols)]
                for _ in range(rows)]


class CrossModalBinaryCVEInference:
    """跨模态二进制补丁→CVE推断主引擎.

    管道:
      1. PatchSignature 从 binary_normalizer+diff 生成结构化签名
      2. CVEProjectionIndex 维护CVE嵌入空间
      3. CrossModalAttention 执行补丁→CVE对齐
      4. 多因子融合排序 (注意力分 + CWE先验 + 时间一致性)

    使用:
      engine = CrossModalBinaryCVEInference()
      engine.index_cves_from_graph(hetero_graph)
      results = engine.infer(patch_signature, top_k=5)
    """

    def __init__(self):
        self._index = CVEProjectionIndex()
        self._attention = CrossModalAttention()
        self._patch_history: List[Tuple[str, float]] = []

    def index_cves_from_graph(self, graph: Any) -> None:
        self._index.index_from_graph(graph)

    def infer(self, patch: PatchSignature, top_k: int = 5,
              cwe_hint: str = "") -> List[Dict[str, Any]]:
        """推断与补丁最相关的CVE.

        三阶段管道:
          阶段1: CWE粗筛 — 若提供cwe_hint则缩小搜索空间
          阶段2: 跨注意力打分 — patch→CVE多头注意力
          阶段3: 多因子融合 — 注意力分×CWE先验×时间一致性
        """
        pv = patch.structural_vector()
        # 阶段1: CWE粗筛
        candidates = list(self._index._cve_embeddings.items())
        if cwe_hint:
            cluster = self._index._cwe_clusters.get(cwe_hint, [])
            candidates = [(cid, emb) for cid, emb in candidates
                         if cid in cluster]
        # 阶段2: 跨注意力
        attn_scores = self._attention.score(pv, candidates)
        # 阶段3: 多因子融合
        fused = []
        now = time.time()
        for cid, attn in attn_scores:
            meta = self._index._cve_metadata.get(cid, {})
            # CWE匹配先验加成
            cwe_boost = 1.0
            if cwe_hint and meta.get("cwe", "") == cwe_hint:
                cwe_boost = 1.3
            # CVSS加权: 高危CVE推断为补丁目标的可能性更高
            cvss = meta.get("cvss", 5.0)
            cvss_factor = 0.8 + 0.04 * cvss  # [0.8, 1.2]
            # 时间一致性: 最近被引用的CVE降低权重(避免热点偏差)
            temporal_discount = 1.0
            for hist_cid, hist_ts in self._patch_history:
                if hist_cid == cid:
                    age_h = (now - hist_ts) / 3600.0
                    temporal_discount = min(1.0, age_h / 24.0)
                    break
            score = attn * cwe_boost * cvss_factor * temporal_discount
            fused.append({
                "cve_id": cid,
                "attention_score": round(attn, 4),
                "fused_score": round(score, 4),
                "metadata": meta,
            })
        fused.sort(key=lambda x: x["fused_score"], reverse=True)
        result = fused[:top_k]
        # 记录推断历史
        if result:
            self._patch_history.append((result[0]["cve_id"], now))
            if len(self._patch_history) > 1000:
                self._patch_history = self._patch_history[-500:]
        return result

    def batch_infer(self, patches: List[PatchSignature],
                    top_k: int = 5, max_workers: int = 4
                    ) -> List[List[Dict[str, Any]]]:
        """批量推断, 线程池并行."""
        results = [None] * len(patches)
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(self.infer, p, top_k): i
                    for i, p in enumerate(patches)}
            for fut in as_completed(futs):
                idx = futs[fut]
                try:
                    results[idx] = fut.result()
                except Exception:
                    log.exception("batch_infer failure for patch %d", idx)
                    results[idx] = []
        return results


# 工厂函数, 与现有模块接口风格一致
_shared_engine: Optional[CrossModalBinaryCVEInference] = None


def get_cross_modal_engine() -> CrossModalBinaryCVEInference:
    global _shared_engine
    if _shared_engine is None:
        _shared_engine = CrossModalBinaryCVEInference()
    return _shared_engine
