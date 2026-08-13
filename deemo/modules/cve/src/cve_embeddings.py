# ~ 2025-01-13
# 基于嵌入的语义 CVE 搜索 — 建立在 cve_search 的 BM25 引擎之上，
# 增加 TF-IDF 向量化 + 余弦相似度，可查找"相似"CVE 而非仅关键字匹配。
#
# 基本路径使用 TF-IDF（无需已有依赖之外的外部依赖）。
# TF-IDF 向量存储为稀疏 {term_idx: weight} dict — 对于 100K 文档
# ~10K 词汇量，每个文档约 ~100 个非零条目。稀疏向量上的余弦相似度
# 足够快，无需向量数据库即可暴力 top-k。
#
# 可选: sentence-transformers。若已安装，使用 all-MiniLM-L6-v2
# 构建密集嵌入（首次使用约 80MB 下载）。质量优于 TF-IDF 但需 pip install。
# API 两种方式一致。
#
# _tokenize 复用 cve_search.py 的分词器 — 与 BM25 的一致性
# 比嵌入的独立分词器更重要。

import math
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Set, Union, Any

from .cve_models import CVEEntry
from .cve_kb import CVEKnowledgeBase

# 尝试导入 numpy — 可选，用于更快的点积
try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False
    np = None  # type: ignore

# 尝试 sentence-transformers — 完全可选，大型依赖
try:
    from sentence_transformers import SentenceTransformer
    _HAS_SBERT = True
except ImportError:
    _HAS_SBERT = False
    SentenceTransformer = None  # type: ignore

# 复用 BM25 搜索引擎的分词器
# 保持两者词项词汇一致
try:
    from .cve_search import _tokenize, _expand_tokens, _STOPWORDS, _SYNONYMS
except ImportError:
    # 回退: cve_search 不可用时的最小分词器
    import re
    _STOPWORDS = {"a", "an", "the", "and", "or", "in", "on", "at", "to", "for",
                  "of", "with", "by", "is", "are", "was", "were", "be", "been"}
    _SYNONYMS: Dict[str, str] = {}
    def _tokenize(text: str) -> List[str]:
        return [t for t in re.split(r'[^a-z0-9]+', text.lower()) if len(t) >= 2 and t not in _STOPWORDS]
    def _expand_tokens(tokens: List[str]) -> List[str]:
        result = list(tokens)
        for t in tokens:
            if t in _SYNONYMS:
                result.extend(_tokenize(_SYNONYMS[t]))
        return result


# SBERT 模型名称 — 小、快、质量尚可
_SBERT_MODEL = "all-MiniLM-L6-v2"


class CVEEmbeddingIndex:
    """基于 CVE 描述的语义搜索索引。
    默认使用 TF-IDF，sentence-transformers 可用时则使用之。
    TF-IDF 路径下向量为稀疏 {term_idx: tfidf_weight} dict，
    SBERT 路径下为密集 numpy 数组。"""

    def __init__(self, kb: CVEKnowledgeBase):
        self._kb = kb
        # 词汇: term → index
        self._vocab: Dict[str, int] = {}
        # 每个词项的逆文档频率
        self._idf: List[float] = []
        # 文档向量: [{term_idx: weight}]
        self._doc_vecs: List[Dict[int, float]] = []
        # doc_idx → CVEEntry
        self._docs: Dict[int, CVEEntry] = {}
        # 密集向量（仅 SBERT 路径）
        self._dense_vecs: Optional[Any] = None  # numpy array if SBERT
        self._sbert_model: Optional[Any] = None
        self._built = False

# 构建

    def build(self):
        """从所有 KB 条目构建嵌入索引。
        计算 TF-IDF 向量。若 sentence-transformers 可用，同时构建密集嵌入。"""
        self._vocab.clear()
        self._idf.clear()
        self._doc_vecs.clear()
        self._docs.clear()
        self._dense_vecs = None

        entries, total = self._kb.search(limit=100000)
        N = len(entries)
        if N == 0:
            self._built = True
            return

# 第一遍: 构建词汇 + 文档频率
        doc_term_counts: List[Dict[str, int]] = []  # 每文档原始词计数
        df: Dict[str, int] = defaultdict(int)        # 词 → 文档数

        for idx, entry in enumerate(entries):
            tokens = _expand_tokens(_tokenize(entry.description or ""))
            # 同时加入 cve_id 词项（有助于 "similar to CVE-xxx" 查询）
            tokens.extend(_tokenize(entry.cve_id))

            term_counts: Dict[str, int] = defaultdict(int)
            for t in tokens:
                term_counts[t] += 1
            doc_term_counts.append(dict(term_counts))

            for term in term_counts:
                df[term] += 1

            self._docs[idx] = entry

# 构建词汇（过滤稀有词: df >= 2）
        vocab_terms = [t for t, d in df.items() if d >= 2]
        self._vocab = {t: i for i, t in enumerate(vocab_terms)}

# 计算 idf
        vocab_size = len(self._vocab)
        self._idf = [0.0] * vocab_size
        for term, idx in self._vocab.items():
            self._idf[idx] = math.log((N + 1) / (1 + df.get(term, 0)))

# 第二遍: 构建 TF-IDF 向量
        for idx, tc in enumerate(doc_term_counts):
            vec: Dict[int, float] = {}
            doc_len = sum(tc.values()) or 1
            for term, count in tc.items():
                term_idx = self._vocab.get(term)
                if term_idx is None:
                    continue
                # 次线性 tf 缩放: 1 + log(tf)
                tf = 1.0 + math.log(count)
                # 按文档长度归一化
                tf_norm = tf / (1.0 + math.log(doc_len))
                vec[term_idx] = tf_norm * self._idf[term_idx]

            # L2 归一化
            norm = math.sqrt(sum(w * w for w in vec.values())) or 1.0
            for k in vec:
                vec[k] /= norm

            self._doc_vecs.append(vec)

# SBERT 路径（可选）
        if _HAS_SBERT and SentenceTransformer is not None:
            try:
                self._sbert_model = SentenceTransformer(_SBERT_MODEL)
                descriptions = [e.description or "" for e in entries]
                self._dense_vecs = self._sbert_model.encode(
                    descriptions, show_progress_bar=False
                )
            except Exception:
                # 模型下载失败或 OOM — 回退到 TF-IDF
                self._sbert_model = None
                self._dense_vecs = None

        self._built = True

# 搜索

    def search(self, query: str, top_n: int = 10, min_score: float = 0.05) -> List[Tuple[CVEEntry, float]]:
        """语义搜索 — 查找与查询文本相似的 CVE。
        若可用则使用密集 SBERT 嵌入，否则使用 TF-IDF 余弦相似度。
        返回 [(CVEEntry, similarity_score)] 列表。"""
        if not self._built:
            self.build()

        if not self._doc_vecs and self._dense_vecs is None:
            return []

        if self._dense_vecs is not None and self._sbert_model is not None:
            return self._search_dense(query, top_n, min_score)
        return self._search_sparse(query, top_n, min_score)

    def find_similar(self, cve_id: str, top_n: int = 10) -> List[Tuple[CVEEntry, float]]:
        """查找与给定 CVE ID 相似的 CVE。
        以该 CVE 的描述作为查询。"""
        entry = self._kb.get(cve_id)
        if not entry:
            return []
        if not self._built:
            self.build()
        desc = entry.description or ""
        if not desc:
            return []
        return self.search(desc, top_n=top_n)

# 内部: 稀疏 TF-IDF 搜索

    def _search_sparse(self, query: str, top_n: int, min_score: float) -> List[Tuple[CVEEntry, float]]:
        """TF-IDF 余弦相似度搜索。"""
        # 构建查询向量
        tokens = _expand_tokens(_tokenize(query))
        if not tokens:
            return []

        qvec: Dict[int, float] = {}
        q_counts: Dict[str, int] = defaultdict(int)
        for t in tokens:
            q_counts[t] += 1

        for term, count in q_counts.items():
            term_idx = self._vocab.get(term)
            if term_idx is None:
                continue
            tf = 1.0 + math.log(count)
            qvec[term_idx] = tf * self._idf[term_idx]

        # L2 归一化查询
        qnorm = math.sqrt(sum(w * w for w in qvec.values())) or 1.0
        for k in qvec:
            qvec[k] /= qnorm

        # 为所有文档打分
        scores: List[Tuple[int, float]] = []
        for doc_idx, dvec in enumerate(self._doc_vecs):
            score = self._cosine_sparse(qvec, dvec)
            if score >= min_score:
                scores.append((doc_idx, score))

        scores.sort(key=lambda x: x[1], reverse=True)
        return [(self._docs[doc_idx], score) for doc_idx, score in scores[:top_n]]

    def _cosine_sparse(self, v1: Dict[int, float], v2: Dict[int, float]) -> float:
        """两个稀疏向量间的余弦相似度。返回 0.0–1.0。"""
        # 遍历较小的向量
        if len(v1) > len(v2):
            v1, v2 = v2, v1
        dot = sum(v1[k] * v2.get(k, 0.0) for k in v1)
        # 两向量均已 L2 归一化，故 dot = cosine
        return max(0.0, dot)

# 内部: 密集 SBERT 搜索

    def _search_dense(self, query: str, top_n: int, min_score: float) -> List[Tuple[CVEEntry, float]]:
        """密集嵌入余弦相似度搜索。"""
        if self._sbert_model is None or self._dense_vecs is None:
            return self._search_sparse(query, top_n, min_score)

        qvec = self._sbert_model.encode([query], show_progress_bar=False)[0]

        if _HAS_NUMPY and isinstance(self._dense_vecs, getattr(np, 'ndarray', ())):
            # numpy 路径: 向量化余弦
            qnorm = np.linalg.norm(qvec)
            if qnorm == 0:
                return []
            qvec = qvec / qnorm
            dnorm = np.linalg.norm(self._dense_vecs, axis=1)
            dnorm[dnorm == 0] = 1.0
            similarities = np.dot(self._dense_vecs, qvec) / dnorm
            top_indices = np.argsort(similarities)[::-1][:top_n]
            results = []
            for idx in top_indices:
                score = float(similarities[idx])
                if score >= min_score:
                    results.append((self._docs[int(idx)], score))
            return results
        else:
            # 纯 Python 路径
            qnorm = math.sqrt(sum(x * x for x in qvec)) or 1.0
            qvec = [x / qnorm for x in qvec]
            scores = []
            for doc_idx, dvec in enumerate(self._dense_vecs):
                dnorm = math.sqrt(sum(x * x for x in dvec)) or 1.0
                dvec_norm = [x / dnorm for x in dvec]
                dot = sum(a * b for a, b in zip(qvec, dvec_norm))
                if dot >= min_score:
                    scores.append((doc_idx, dot))
            scores.sort(key=lambda x: x[1], reverse=True)
            return [(self._docs[doc_idx], score) for doc_idx, score in scores[:top_n]]

# 混合: 合并 BM25 + 嵌入分数

    def search_hybrid(self, query: str, top_n: int = 10, bm25_weight: float = 0.4) -> List[Tuple[CVEEntry, float]]:
        """合并 BM25 和嵌入搜索分数。
        bm25_weight: BM25 与嵌入的权重（0 = 仅嵌入）。"""
        from .cve_search import CVESearchEngine

        if not self._built:
            self.build()

        # 运行两种搜索
        bm25_engine = CVESearchEngine(self._kb)
        bm25_engine.build()
        bm25_results = bm25_engine.search(query, top_n=top_n * 3)
        emb_results = self.search(query, top_n=top_n * 3)

        # 将分数归一化到 0-1
        bm25_by_cve: Dict[str, float] = {}
        bm25_max = max((s for _, s in bm25_results), default=1.0)
        for entry, score in bm25_results:
            bm25_by_cve[entry.cve_id] = score / bm25_max if bm25_max > 0 else 0.0

        emb_by_cve: Dict[str, float] = {}
        emb_max = max((s for _, s in emb_results), default=1.0)
        for entry, score in emb_results:
            emb_by_cve[entry.cve_id] = score / emb_max if emb_max > 0 else 0.0

        # 合并分数
        combined: Dict[str, Tuple[CVEEntry, float]] = {}
        for entry, _ in emb_results:
            cid = entry.cve_id
            bm25_s = bm25_by_cve.get(cid, 0.0)
            emb_s = emb_by_cve.get(cid, 0.0)
            combined[cid] = (entry, bm25_weight * bm25_s + (1 - bm25_weight) * emb_s)

        # 添加嵌入遗漏的 BM25 专有结果
        for entry, _ in bm25_results:
            cid = entry.cve_id
            if cid not in combined:
                combined[cid] = (entry, bm25_weight * bm25_by_cve.get(cid, 0.0))

        sorted_results = sorted(combined.values(), key=lambda x: x[1], reverse=True)
        return sorted_results[:top_n]

    @property
    def vocab_size(self) -> int:
        return len(self._vocab)

    @property
    def doc_count(self) -> int:
        return len(self._docs)


# 便捷: 一次性相似 CVE 搜索

def find_similar_cves(kb: CVEKnowledgeBase, cve_id: str, top_n: int = 10) -> List[Tuple[CVEEntry, float]]:
    """一次性: 构建索引并查找与给定 CVE ID 相似的 CVE。"""
    index = CVEEmbeddingIndex(kb)
    index.build()
    return index.find_similar(cve_id, top_n=top_n)


def search_semantic(kb: CVEKnowledgeBase, query: str, top_n: int = 10) -> List[Tuple[CVEEntry, float]]:
    """一次性: 构建索引并对给定查询进行语义搜索。"""
    index = CVEEmbeddingIndex(kb)
    index.build()
    return index.search(query, top_n=top_n)
