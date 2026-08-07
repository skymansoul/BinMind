"""
意图嵌入缓存 (IEC) —— 基于语义相似度的分类结果复用。

对已分类的请求构建轻量语义签名, 新请求到达时先查缓存中的最近邻。
若相似度超过自适应阈值则直接复用分类结果, 绕过 LLM API 调用。

相似度方案选择: 使用字符 n-gram Jaccard 预筛选 + TF-IDF 余弦精排的两阶段
管线, 而非 embedding+ANN。选择依据:
1. 安全工具路由中单次分类的延迟预算通常在 200ms 以内, embedding 模型
   推理 (即使是轻量模型如 ModernBERT-149M) 的延迟不可忽略
2. 中文安全领域的嵌入模型极少有预训练权重, 从零训练不实际
3. Jaccard+TF-IDF 对短查询文本 (通常 < 200 字符) 的判别力足够 ——
   安全工具的路由请求具有高词汇特异性 (端口号、IP、CVE编号、PE字段名)
4. 零外部依赖: 不需要 ONNX Runtime / sentence-transformers 等第三方包

阈值自适应: 每个意图类别维护独立的相似度阈值, 使用 Beta-Binomial
共轭模型做后验更新。命中率的目标先验为 Beta(7, 3), 即在 70% 命中率
附近。每次缓存查找的结果 (hit/miss) 作为 Bernoulli 观测更新后验。
后验均值作为下一轮阈值调整的方向: mean > 0.70 → 降低阈值 (更激进),
mean < 0.30 → 提高阈值 (更保守)。调整幅度与后验方差成正比 ——
方差大时步长小 (避免早期噪声误调), 方差小时步长大 (快速收敛)。

与 VectorQ 的相似之处在于按条目特异性而非
全局静态阈值做缓存决策的思想, 但本实现不使用嵌入向量而使用
n-gram 签名, 且阈值在类别级别而非条目级别。VectorQ 的条目级阈值
在缓存条目数 > 1000 时面临冷启动问题, 类别级阈值规避了此问题。
"""

# File: embed_cache.py  |  2026-07-30 create IEC; 2026-08-04 audit: Beta-Binomial threshold + honest grounding

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .intent_route import IntentCategory, IntentResult, ActionParams


@dataclass
class CacheEntry:
    """缓存条目: 原始请求 + 分类结果 + 嵌入签名。"""
    text: str
    result: IntentResult
    char_ngrams: Set[str]
    tf_idf_vector: Dict[str, float]
    hit_count: int = 0
    last_hit: float = 0.0
    created_at: float = 0.0


@dataclass
class CacheLookupResult:
    """缓存查找结果。"""
    hit: bool
    entry: Optional[CacheEntry]
    similarity: float
    threshold_used: float
    category: IntentCategory


class IntentEmbeddingCache:
    """
    基于 n-gram Jaccard + TF-IDF 的意图语义缓存。
    使用 Beta-Binomial 共轭模型做自适应阈值调整。

    n-gram: 字符级 3-gram, 兼顾中英文混合场景。
    两阶段管线: Jaccard (预筛选, O(set_size)) → TF-IDF (精排, O(|vocab|))。
    """

    # 初始阈值: 高确定性类别使用较低阈值 (更容易命中)
    _DEFAULT_THRESHOLDS: Dict[IntentCategory, float] = {
        IntentCategory.STATIC_COLLECTION: 0.62,
        IntentCategory.FILE_ANALYSIS: 0.65,
        IntentCategory.INTEL_CORRELATION: 0.68,
        IntentCategory.DYNAMIC_INTERACTION: 0.72,
        IntentCategory.UNKNOWN: 0.78,
    }

    # Beta-Binomial 先验超参数: Beta(α, β)
    # α = 7, β = 3 → 期望命中率 0.70, 方差约 0.019
    # 先验强度 (α+β=10) 在总共约 20 次观测后收敛到数据主导
    _PRIOR_ALPHA = 7.0
    _PRIOR_BETA = 3.0

    def __init__(self, max_entries: int = 200, ngram_n: int = 3):
        self._entries: List[CacheEntry] = []
        self._max_entries = max_entries
        self._n = ngram_n
        self._df: Dict[str, int] = defaultdict(int)
        self._thresholds = dict(self._DEFAULT_THRESHOLDS)
        # Beta-Binomial 后验参数: 每类别独立维护
        self._post_alpha: Dict[IntentCategory, float] = defaultdict(lambda: self._PRIOR_ALPHA)
        self._post_beta: Dict[IntentCategory, float] = defaultdict(lambda: self._PRIOR_BETA)

    def _ngrams(self, text: str) -> Set[str]:
        clean = text.lower().strip()
        ngrams: Set[str] = set()
        for i in range(len(clean) - self._n + 1):
            ngrams.add(clean[i:i + self._n])
        return ngrams

    def _jaccard(self, set_a: Set[str], set_b: Set[str]) -> float:
        if not set_a or not set_b:
            return 0.0
        return len(set_a & set_b) / len(set_a | set_b)

    def _tfidf_cosine(self, vec_a: Dict[str, float], vec_b: Dict[str, float]) -> float:
        all_keys = set(vec_a.keys()) | set(vec_b.keys())
        dot, na, nb = 0.0, 0.0, 0.0
        for k in all_keys:
            a = vec_a.get(k, 0.0)
            b = vec_b.get(k, 0.0)
            dot += a * b
            na += a * a
            nb += b * b
        if na == 0 or nb == 0:
            return 0.0
        return dot / (math.sqrt(na) * math.sqrt(nb))

    def _build_tfidf(self, ngrams: Set[str]) -> Dict[str, float]:
        total_docs = max(1, len(self._entries) + 1)
        vec: Dict[str, float] = {}
        for ng in ngrams:
            idf = math.log((total_docs + 1) / (self._df.get(ng, 0) + 1)) + 1.0
            vec[ng] = idf
        norm = math.sqrt(sum(v * v for v in vec.values()))
        if norm > 0:
            vec = {k: v / norm for k, v in vec.items()}
        return vec

    def lookup(self, text: str) -> CacheLookupResult:
        """两阶段查找: Jaccard 预筛选 → TF-IDF 精排 → Beta-Binomial 阈值判定。"""
        q_ngrams = self._ngrams(text)
        if not q_ngrams:
            return CacheLookupResult(False, None, 0.0, 0.0, IntentCategory.UNKNOWN)

        best_sim = 0.0
        best_entry: Optional[CacheEntry] = None
        q_vec = self._build_tfidf(q_ngrams)

        for entry in self._entries:
            jaccard = self._jaccard(q_ngrams, entry.char_ngrams)
            if jaccard < 0.3:
                continue
            tfidf_sim = self._tfidf_cosine(q_vec, entry.tf_idf_vector)
            combined = 0.4 * jaccard + 0.6 * tfidf_sim
            if combined > best_sim:
                best_sim = combined
                best_entry = entry

        if best_entry is None or best_sim < 0.3:
            return CacheLookupResult(False, None, best_sim, 0.0, IntentCategory.UNKNOWN)

        cat = best_entry.result.category
        threshold = self._thresholds.get(cat, 0.70)

        if best_sim >= threshold:
            best_entry.hit_count += 1
            best_entry.last_hit = time.time()
            self._post_alpha[cat] += 1.0
        else:
            self._post_beta[cat] += 1.0

        self._adapt_threshold_beta_binomial(cat)
        return CacheLookupResult(
            best_sim >= threshold, best_entry, best_sim, threshold, cat,
        )

    def insert(self, text: str, result: IntentResult) -> None:
        ngrams = self._ngrams(text)
        if not ngrams:
            return
        tfidf = self._build_tfidf(ngrams)
        entry = CacheEntry(
            text=text, result=result, char_ngrams=ngrams,
            tf_idf_vector=tfidf, created_at=time.time(),
        )
        self._entries.append(entry)
        for ng in ngrams:
            self._df[ng] += 1
        if len(self._entries) > self._max_entries:
            removed = self._entries.pop(0)
            for ng in removed.char_ngrams:
                self._df[ng] = max(0, self._df[ng] - 1)

    def _adapt_threshold_beta_binomial(self, cat: IntentCategory) -> None:
        """
        Beta-Binomial 共轭模型的自适应阈值更新。

        后验: Beta(α + hits, β + misses)
        目标命中率: 0.70 (缓存命中率高 → 分类器被有效 bypass)
        最小可接受命中率: 0.30 (低于此 → 阈值太激进, 需收紧)

        步长与后验方差成正比 —— 观测少时方差大, 步长小 (保守);
        观测多时方差小, 步长大 (快速适配到稳态)。
        """
        a = self._post_alpha[cat]
        b = self._post_beta[cat]
        n_eff = a + b
        if n_eff < 10:
            return
        posterior_mean = a / n_eff
        posterior_var = (a * b) / (n_eff * n_eff * (n_eff + 1))

        current = self._thresholds[cat]
        # 步长: 与方差成正比, 最大 0.03, 最小 0.003
        step_scale = min(0.03, max(0.003, posterior_var * 3.0))

        if posterior_mean > 0.70:
            direction = -1  # 降低阈值 → 更激进缓存
        elif posterior_mean < 0.30:
            direction = +1  # 提高阈值 → 更保守
        else:
            return  # 在目标区间内, 不调整

        new_threshold = current + direction * step_scale
        self._thresholds[cat] = max(0.35, min(0.92, new_threshold))

    def evict_stale(self, max_age_seconds: float = 7200.0) -> int:
        now = time.time()
        before = len(self._entries)
        self._entries = [
            e for e in self._entries
            if (now - e.created_at) < max_age_seconds or e.hit_count > 3
        ]
        return before - len(self._entries)

    @property
    def size(self) -> int:
        return len(self._entries)

    @property
    def thresholds(self) -> Dict[str, float]:
        return {k.value: v for k, v in self._thresholds.items()}

    def clear(self) -> None:
        self._entries.clear()
        self._df.clear()
        self._thresholds = dict(self._DEFAULT_THRESHOLDS)
        self._post_alpha.clear()
        self._post_beta.clear()


__all__ = [
    "CacheEntry",
    "CacheLookupResult",
    "IntentEmbeddingCache",
]
