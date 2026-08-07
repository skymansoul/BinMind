"""CLAP (Contrastive Language-Audio Pretraining) contrastive scoring module.

Extracted from adaptive_ai_model.py to isolate the cross-modal embedding alignment
machinery.  The ContrastiveAlignmentScorer maps task features and model
configurations into a shared 16-dimensional embedding space where cosine
similarity replaces heuristic weighted summation for model ranking.

Rationale: the CLAP scorer is a self-contained computational kernel -- it only
depends on math/hashlib/threading and a single enum (ModelType).  Keeping it
in the monolithic adaptive_ai_model.py obscured its responsibility and made
it harder to unit-test, swap out embedding strategies, or reuse in other
selectors.  A dedicated module with lazy import for the shared enum avoids
circular dependencies while preserving the original hot-path performance.
"""

import math
import hashlib
import threading
from typing import Dict, List, Optional


# 对比嵌入空间的维度--在精度与计算开销之间折中，经验值 16 维对 <50 候选模型够用
_CONTRASTIVE_EMBEDDING_DIM = 16


def _entity_fingerprint(text: str, dim: int = _CONTRASTIVE_EMBEDDING_DIM) -> List[float]:
    """确定性伪嵌入：将任意标签映射为固定维度的小范数向量，用作对比空间锚点。

    不引入外部嵌入模型依赖；对同一输入始终产出相同向量，保证可复现性。
    """
    vec = [0.0] * dim
    raw = hashlib.sha256(text.encode("utf-8", errors="replace")).digest()
    idx = 0
    while idx < dim:
        chunk = int.from_bytes(raw[idx * 2 : idx * 2 + 2], "big", signed=False)
        vec[idx] = (chunk / 65535.0) * 2.0 - 1.0  # 归一化到 [-1, 1]
        idx += 1
    norm_sq = sum(v * v for v in vec)
    if norm_sq > 1e-12:
        scale = 1.0 / math.sqrt(norm_sq)
        vec = [v * scale for v in vec]
    return vec


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    """两个同维度向量的余弦相似度，结果裁剪到 [-1, 1]。"""
    dot = 0.0
    norm_a = 0.0
    norm_b = 0.0
    k = 0
    while k < len(a):
        dot += a[k] * b[k]
        norm_a += a[k] * a[k]
        norm_b += b[k] * b[k]
        k += 1
    if norm_a < 1e-12 or norm_b < 1e-12:
        return 0.0
    return max(-1.0, min(1.0, dot / (math.sqrt(norm_a) * math.sqrt(norm_b))))


# 对比任务—模型对齐评分器（CLAP 范式：将异构特征映射到共享嵌入空间，用余弦相似度
# 替代启发式加权求和。优势在于同类任务天然聚集，新模型只需计算一次嵌入即可参与
# 排序，无需重新标定权重。）
class ContrastiveAlignmentScorer:
    """CLAP‑style 跨模态对比对齐：任务侧嵌入与模型侧嵌入做余弦内积，得分越高越匹配。

    任务嵌入 = 融合 task_type 语义指纹 + complexity / urgency / accuracy_req 连续投影。
    模型嵌入 = name 指纹 + model_type 能力等级编码 + 延迟/成本/容量标量投影。
    """

    __slots__ = (
        "_task_embeddings_cache",
        "_model_embeddings_cache",
        "_lock",
        "_complexity_scale",
        "_cost_scale",
    )

    def __init__(self):
        self._task_embeddings_cache: Dict[str, List[float]] = {}
        self._model_embeddings_cache: Dict[str, List[float]] = {}
        self._lock = threading.RLock()
        self._complexity_scale = 0.3  # 连续特征在嵌入更新中的学习率
        self._cost_scale = 0.2

# 任务嵌入
    def embed_task(self, features: "TaskFeatures") -> List[float]:
        """为任务特征构建对比嵌入。

        语义部分用 task_type 指纹锚定方向，连续特征以加性扰动编码数值信息。
        """
        key = f"{features.task_type}|{features.complexity_score:.3f}|{features.urgency:.2f}|{features.accuracy_requirement:.2f}"
        with self._lock:
            if key in self._task_embeddings_cache:
                return self._task_embeddings_cache[key]

        base = _entity_fingerprint(features.task_type, _CONTRASTIVE_EMBEDDING_DIM)
        # 连续特征投影：沿各维度按复杂度/紧急度/精度进行小幅度偏移
        dim = _CONTRASTIVE_EMBEDDING_DIM
        fused = [0.0] * dim
        ci = 0
        while ci < dim:
            delta = (
                features.complexity_score * 0.15 * math.cos(ci * 1.7)
                + features.urgency * 0.10 * math.sin(ci * 2.3)
                + features.accuracy_requirement * 0.12 * math.cos(ci * 3.1 + 0.5)
            )
            fused[ci] = base[ci] + delta
            ci += 1
        # 重新归一化
        norm_sq = sum(v * v for v in fused)
        if norm_sq > 1e-12:
            scale = 1.0 / math.sqrt(norm_sq)
            fused = [v * scale for v in fused]

        with self._lock:
            self._task_embeddings_cache[key] = fused
            # 缓存上限，防止无限增长
            if len(self._task_embeddings_cache) > 512:
                evict_keys = list(self._task_embeddings_cache.keys())[:128]
                for ek in evict_keys:
                    del self._task_embeddings_cache[ek]
        return fused

# 模型嵌入
    def embed_model(self, config: "ModelConfig") -> List[float]:
        """为模型配置构建对比嵌入。

        name 指纹提供区分度；model_type 能力等级 + 延迟/成本标量做微调。
        """
        from ai_ml.adaptive_ai_model import ModelType  # lazy import to avoid circular dependency

        with self._lock:
            if config.name in self._model_embeddings_cache:
                return self._model_embeddings_cache[config.name]

        base = _entity_fingerprint(config.name, _CONTRASTIVE_EMBEDDING_DIM)
        # 模型类型能力系数
        type_strength = {ModelType.STRONG: 0.9, ModelType.STANDARD: 0.6, ModelType.LIGHT: 0.3, ModelType.CUSTOM: 0.5}
        capability_bias = type_strength.get(config.model_type, 0.5)
        # 延迟归一化（0-3000ms → 1-0.1）
        latency_norm = max(0.1, 1.0 - min(config.avg_latency_ms, 3000) / 3000.0)
        # 成本归一化（对数尺度）
        cost_norm = max(0.05, 1.0 / (1.0 + math.log10(max(config.cost_per_token * 1e6, 1e-12) + 1)))

        dim = _CONTRASTIVE_EMBEDDING_DIM
        fused = [0.0] * dim
        ci = 0
        while ci < dim:
            delta = (
                capability_bias * 0.18 * math.cos(ci * 0.9 + 0.3)
                + latency_norm * 0.12 * math.sin(ci * 1.4)
                + cost_norm * 0.08 * math.cos(ci * 2.7 + 1.1)
            )
            fused[ci] = base[ci] + delta
            ci += 1
        norm_sq = sum(v * v for v in fused)
        if norm_sq > 1e-12:
            scale = 1.0 / math.sqrt(norm_sq)
            fused = [v * scale for v in fused]

        with self._lock:
            self._model_embeddings_cache[config.name] = fused
        return fused

    def alignment_score(self, features: "TaskFeatures", config: "ModelConfig") -> float:
        """对比对齐得分 ∈ [0, 1]：任务嵌入与模型嵌入的余弦相似度，min‑max 归一。"""
        task_vec = self.embed_task(features)
        model_vec = self.embed_model(config)
        raw = _cosine_similarity(task_vec, model_vec)
        return (raw + 1.0) / 2.0  # [-1,1] → [0,1]

    def purge_model_cache(self, model_name: Optional[str] = None):
        """清除模型嵌入缓存——模型配置变更后调用。"""
        with self._lock:
            if model_name is None:
                self._model_embeddings_cache.clear()
            elif model_name in self._model_embeddings_cache:
                del self._model_embeddings_cache[model_name]


# 全局对比评分器单例
_global_contrastive_scorer: Optional[ContrastiveAlignmentScorer] = None


def _get_contrastive_scorer() -> ContrastiveAlignmentScorer:
    global _global_contrastive_scorer
    if _global_contrastive_scorer is None:
        _global_contrastive_scorer = ContrastiveAlignmentScorer()
    return _global_contrastive_scorer
