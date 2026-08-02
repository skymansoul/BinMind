# 2026-07-22 15:30
# fewshot_active_sampler.py
# 少样本主动学习采样器 — 联合不确定性/多样性/难度感知的采样策略
# 依据: Smart Cuts [Lan et al. arXiv 2506.20444, 2025] 的数据集图剪枝主动学习
#       "Enhance Active Learning for Vulnerability Detection by Pruning Hard-to-Learn Data"
# 核心: Dataset Map概念 — 通过置信度vs正确性vs可变性三维度识别hard-to-learn样本并剪枝

from __future__ import annotations
import math
import random
import logging
import hashlib
from typing import Dict, List, Optional, Set, Tuple, Callable, Any
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class SampleMetadata:
    """样本元数据 — Smart Cuts风格的Dataset Map坐标"""
    index: int
    label: int
    confidence: float          # 模型预测置信度 (多次预测均值)
    correctness: float         # 正确预测频率 (0=always wrong, 1=always correct)
    variability: float         # 预测标签方差 (高=边界样本, 低=一致)
    difficulty_score: float    # 综合难度: 高值=难以学习
    is_hard_to_learn: bool     # Smart Cuts剪枝标记
    embedding: Optional[List[float]] = None


@dataclass
class QueryResult:
    indices: List[int]
    strategy: str
    scores: List[float]
    metadata: Dict[str, Any] = field(default_factory=dict)


class SamplingStrategy(Enum):
    UNCERTAINTY = 'uncertainty'          # 最高预测不确定性
    DIVERSITY = 'diversity'               # 最大嵌入空间多样性
    MARGIN = 'margin'                    # 最小间隔 (top1 - top2)
    ENTROPY = 'entropy'                  # 最大预测熵
    COMMITTEE = 'committee'              # 委员会分歧
    SMART_CUTS = 'smart_cuts'            # Smart Cuts: 剪枝hard-to-learn
    COMBINED = 'combined'                # 加权组合
    RANDOM = 'random'                    # 随机基准


# ---------------------------------------------------------------------------
# Few-Shot主动学习采样器
# ---------------------------------------------------------------------------

class FewShotActiveSampler:
    """少样本主动学习采样器

    适用于标注稀缺的二进制度分析场景:
      - 初始标注集可能只有几十个样本
      - 需要高效选择最有信息量的样本进行标注
      - 利用Smart Cuts剪枝策略避免标注噪声/不可学样本

    算法流程 (Smart Cuts):
      1. 维护每个样本的 (confidence, correctness, variability) 三元组
      2. 计算 difficulty_score = mean(confidence) * (1 - correctness) + variability
      3. 识别 hard_to_learn: difficulty_score > 阈值 且 variability > 阈值
      4. 剪枝后从剩余候选池中执行不确定性+多样性组合采样
    """

    def __init__(self, n_initial: int = 20,
                 query_batch_size: int = 10,
                 hard_to_learn_threshold: float = 0.65,
                 smart_cuts_prune_ratio: float = 0.15,
                 diversity_lambda: float = 0.3):
        self.n_initial = n_initial
        self.bs = query_batch_size
        self.hard_threshold = hard_to_learn_threshold
        self.prune_ratio = smart_cuts_prune_ratio
        self.div_lambda = diversity_lambda

        self._pool: Dict[int, SampleMetadata] = {}
        self._labeled: Set[int] = set()
        self._pruned: Set[int] = set()
        self._prediction_history: Dict[int, List[int]] = defaultdict(list)
        self._confidence_history: Dict[int, List[float]] = defaultdict(list)
        self._round = 0

    def initialize_pool(self, n_samples: int,
                        labels: Optional[Dict[int, int]] = None,
                        embeddings: Optional[Dict[int, List[float]]] = None):
        """初始化未标注池"""
        self._pool.clear()
        self._labeled.clear()
        self._pruned.clear()
        self._prediction_history.clear()
        self._confidence_history.clear()
        self._round = 0

        for i in range(n_samples):
            label = labels.get(i, -1) if labels else -1
            emb = embeddings.get(i) if embeddings else None
            self._pool[i] = SampleMetadata(
                index=i, label=label,
                confidence=0.5, correctness=0.5, variability=0.5,
                difficulty_score=0.5, is_hard_to_learn=False,
                embedding=emb,
            )

        # 初始随机标注
        if self.n_initial > 0 and n_samples > 0:
            initial_indices = random.sample(
                range(n_samples),
                min(self.n_initial, n_samples))
            for idx in initial_indices:
                self._labeled.add(idx)

    def update_predictions(self, predictions: Dict[int, Tuple[int, float]]):
        """用当前轮次的模型预测更新样本历史

        Args:
            predictions: {sample_index: (predicted_label, confidence)}
        """
        for idx, (pred_label, conf) in predictions.items():
            if idx in self._pool:
                self._prediction_history[idx].append(pred_label)
                self._confidence_history[idx].append(conf)

        self._round += 1

        # 重新计算Dataset Map坐标
        for idx, meta in self._pool.items():
            if idx in self._labeled or idx in self._pruned:
                continue
            preds = self._prediction_history.get(idx, [])
            confs = self._confidence_history.get(idx, [])

            if len(preds) == 0:
                continue

            # Correctness: 预测一致性 (假设大部分预测是对的)
            # 使用mode作为pseudo-label
            if preds:
                mode_pred = Counter(preds).most_common(1)[0][0]
                meta.correctness = sum(1 for p in preds if p == mode_pred) / len(preds)
            meta.confidence = sum(confs) / len(confs) if confs else 0.5

            # Variability: 预测标签的方差
            if len(preds) >= 2:
                unique_ratio = len(set(preds)) / len(preds)
                meta.variability = unique_ratio
            else:
                meta.variability = 0.0

            # Smart Cuts difficulty score
            meta.difficulty_score = (
                meta.confidence * (1.0 - meta.correctness) + meta.variability
            ) / 2.0

            # 标记hard_to_learn
            meta.is_hard_to_learn = (
                meta.difficulty_score > self.hard_threshold and
                meta.variability > 0.5
            )

        # 应用Smart Cuts剪枝
        self._apply_smart_cuts()

    def _apply_smart_cuts(self):
        """剪枝hard-to-learn样本 (Smart Cuts核心)"""
        candidates = []
        for idx, meta in self._pool.items():
            if idx in self._labeled or idx in self._pruned:
                continue
            if meta.is_hard_to_learn:
                candidates.append((idx, meta.difficulty_score))

        if not candidates:
            return

        candidates.sort(key=lambda x: x[1], reverse=True)
        n_prune = max(1, int(len(candidates) * self.prune_ratio))

        for idx, _ in candidates[:n_prune]:
            self._pruned.add(idx)

        logger.debug(
            f"Smart Cuts round {self._round}: pruned {n_prune}/{len(candidates)} hard samples, "
            f"{len(self._pruned)} total pruned, {len(self._pool) - len(self._labeled) - len(self._pruned)} active")

    def query(self, strategy: SamplingStrategy = SamplingStrategy.COMBINED,
              n: Optional[int] = None) -> QueryResult:
        """选择下一批要标注的样本"""
        if n is None:
            n = self.bs

        active_indices = [
            idx for idx in self._pool
            if idx not in self._labeled and idx not in self._pruned
        ]

        if len(active_indices) == 0:
            return QueryResult(indices=[], strategy=strategy.value, scores=[])

        n = min(n, len(active_indices))

        if strategy == SamplingStrategy.RANDOM:
            selected = random.sample(active_indices, n)
            return QueryResult(indices=selected, strategy='random', scores=[0.0] * n)

        elif strategy == SamplingStrategy.UNCERTAINTY:
            return self._query_uncertainty(active_indices, n)

        elif strategy == SamplingStrategy.MARGIN:
            return self._query_margin(active_indices, n)

        elif strategy == SamplingStrategy.ENTROPY:
            return self._query_entropy(active_indices, n)

        elif strategy == SamplingStrategy.DIVERSITY:
            return self._query_diversity(active_indices, n)

        elif strategy == SamplingStrategy.SMART_CUTS:
            return self._query_smart_cuts(active_indices, n)

        elif strategy == SamplingStrategy.COMBINED:
            return self._query_combined(active_indices, n)

        else:
            return self._query_combined(active_indices, n)

    def _calc_uncertainty_score(self, idx: int) -> float:
        """1 - confidence (最不确定的优先)"""
        confs = self._confidence_history.get(idx, [])
        if not confs:
            return 1.0
        avg_conf = sum(confs) / len(confs)
        return 1.0 - avg_conf

    def _calc_margin_score(self, idx: int) -> float:
        """margin: top1_conf - top2_conf (近似)"""
        # 由于只存储单标签预测和置信度, 使用变异性作为margin的代理
        variability = self._pool[idx].variability
        confidence = self._confidence_history.get(idx, [0.5])
        avg_conf = sum(confidence) / len(confidence)
        # 低margin ≈ 高分 (需要更不确定的)
        return (1.0 - avg_conf) * (0.5 + variability)

    def _calc_entropy(self, idx: int) -> float:
        """预测熵 (基于历史标签分布)"""
        preds = self._prediction_history.get(idx, [])
        if len(preds) < 2:
            return 0.0

        counter = Counter(preds)
        total = len(preds)
        entropy = 0.0
        for count in counter.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _query_uncertainty(self, candidates: List[int], n: int) -> QueryResult:
        scores = [(idx, self._calc_uncertainty_score(idx)) for idx in candidates]
        scores.sort(key=lambda x: x[1], reverse=True)
        selected = [s[0] for s in scores[:n]]
        return QueryResult(
            indices=selected, strategy='uncertainty',
            scores=[s[1] for s in scores[:n]],
        )

    def _query_margin(self, candidates: List[int], n: int) -> QueryResult:
        scores = [(idx, self._calc_margin_score(idx)) for idx in candidates]
        scores.sort(key=lambda x: x[1], reverse=True)
        selected = [s[0] for s in scores[:n]]
        return QueryResult(
            indices=selected, strategy='margin',
            scores=[s[1] for s in scores[:n]],
        )

    def _query_entropy(self, candidates: List[int], n: int) -> QueryResult:
        scores = [(idx, self._calc_entropy(idx)) for idx in candidates]
        scores.sort(key=lambda x: x[1], reverse=True)
        selected = [s[0] for s in scores[:n]]
        return QueryResult(
            indices=selected, strategy='entropy',
            scores=[s[1] for s in scores[:n]],
        )

    def _query_diversity(self, candidates: List[int], n: int) -> QueryResult:
        """K-Means++风格的多样性采样"""
        if not candidates:
            return QueryResult(indices=[], strategy='diversity', scores=[])

        # 使用嵌入或随机初始化
        embeddings = {}
        for idx in candidates:
            emb = self._pool[idx].embedding
            if emb is not None:
                embeddings[idx] = emb

        if len(embeddings) < 2:
            return self._query_uncertainty(candidates, n)

        # Farthest-first traversal
        selected = [random.choice(list(embeddings.keys()))]
        remaining = set(embeddings.keys()) - set(selected)

        while len(selected) < n and remaining:
            best = None
            best_dist = -1.0
            for cand in remaining:
                min_dist = min(
                    sum((embeddings[cand][d] - embeddings[s][d]) ** 2
                        for d in range(len(embeddings[cand])))
                    for s in selected
                )
                if min_dist > best_dist:
                    best_dist = min_dist
                    best = cand

            if best is None:
                break
            selected.append(best)
            remaining.discard(best)

        scores = [1.0] * len(selected)
        return QueryResult(indices=selected, strategy='diversity', scores=scores)

    def _query_smart_cuts(self, candidates: List[int], n: int) -> QueryResult:
        """Smart Cuts: 优先选择easy-to-learn + 中等不确定性的样本

        策略: 避免hard-to-learn, 从剩余中选择最不确定的
        """
        # 分离easy/hard
        easy, hard = [], []
        for idx in candidates:
            if self._pool[idx].is_hard_to_learn:
                hard.append(idx)
            else:
                easy.append(idx)

        # 从easy中选择 (若数量不足再从hard补充)
        primary = easy if len(easy) >= n else easy + hard[:n - len(easy)]

        scores = [(idx, self._calc_uncertainty_score(idx)) for idx in primary]
        scores.sort(key=lambda x: x[1], reverse=True)

        selected = [s[0] for s in scores[:n]]
        return QueryResult(
            indices=selected, strategy='smart_cuts',
            scores=[s[1] for s in scores[:n]],
            metadata={'n_easy': len(easy), 'n_hard': len(hard)},
        )

    def _query_combined(self, candidates: List[int], n: int) -> QueryResult:
        """加权组合: (1-λ)*uncertainty + λ*diversity"""
        uncertainty_scores = {idx: self._calc_uncertainty_score(idx)
                              for idx in candidates}

        # 归一化不确定性分数
        if uncertainty_scores:
            max_u = max(uncertainty_scores.values())
            min_u = min(uncertainty_scores.values())
            rng = max(max_u - min_u, 1e-8)
            for idx in uncertainty_scores:
                uncertainty_scores[idx] = (uncertainty_scores[idx] - min_u) / rng

        # 贪心选择: 每轮选择 (1-λ)*uncertainty + λ*diversity 最高的
        selected = []
        remaining = set(candidates)

        while len(selected) < n and remaining:
            best_idx = None
            best_score = -1.0

            for idx in remaining:
                u_score = uncertainty_scores.get(idx, 0.5)

                # 多样性: 到已选样本的最小余弦距离
                d_score = 0.0
                if selected and self._pool[idx].embedding is not None:
                    min_dist = float('inf')
                    for s in selected:
                        if self._pool[s].embedding is not None:
                            dot = sum(a * b for a, b in zip(
                                self._pool[idx].embedding,
                                self._pool[s].embedding))
                            dist = 1.0 - max(-1.0, min(1.0, dot))
                            min_dist = min(min_dist, dist)
                    if min_dist != float('inf'):
                        d_score = min_dist

                combined = (1.0 - self.div_lambda) * u_score + self.div_lambda * d_score
                if combined > best_score:
                    best_score = combined
                    best_idx = idx

            if best_idx is not None:
                selected.append(best_idx)
                remaining.discard(best_idx)
            else:
                break

        return QueryResult(
            indices=selected, strategy='combined',
            scores=[uncertainty_scores.get(i, 0.0) for i in selected],
            metadata={'lambda': self.div_lambda},
        )

    def add_labels(self, labels: Dict[int, int]):
        """接收标注结果并更新已知集"""
        for idx in labels:
            self._labeled.add(idx)
            if idx in self._pool:
                self._pool[idx].label = labels[idx]

    def get_dataset_map(self) -> Dict[str, List[float]]:
        """获取Smart Cuts Dataset Map坐标"""
        result = {'confidence': [], 'correctness': [], 'variability': [],
                  'difficulty': [], 'index': []}
        for idx, meta in self._pool.items():
            if idx in self._pruned:
                continue
            result['index'].append(idx)
            result['confidence'].append(meta.confidence)
            result['correctness'].append(meta.correctness)
            result['variability'].append(meta.variability)
            result['difficulty'].append(meta.difficulty_score)
        return result

    def get_stats(self) -> Dict[str, Any]:
        active = len(self._pool) - len(self._labeled) - len(self._pruned)
        return {
            'total': len(self._pool),
            'labeled': len(self._labeled),
            'pruned': len(self._pruned),
            'active': max(0, active),
            'round': self._round,
            'hard_to_learn_count': sum(1 for m in self._pool.values() if m.is_hard_to_learn),
            'avg_difficulty': sum(m.difficulty_score for m in self._pool.values()) / max(len(self._pool), 1),
        }


def create_fewshot_sampler(n_initial: int = 20, batch_size: int = 10) -> FewShotActiveSampler:
    return FewShotActiveSampler(n_initial=n_initial, query_batch_size=batch_size)


def smart_cuts_query(sampler: FewShotActiveSampler, n: int = 10) -> QueryResult:
    return sampler.query(strategy=SamplingStrategy.SMART_CUTS, n=n)
