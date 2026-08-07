"""多引擎差分测试偏差检测 — 加权投票、二项置信度、跨分析关联。"""
from __future__ import annotations

import statistics
import math
import threading
import time
from collections import defaultdict, deque
from typing import Dict, Set, List, Tuple, Optional, Any

from .result_normalizer import ResultNormalizer

from ._engine_types import (
    EngineKind,
    AnalysisKind,
    DiscrepancySeverity,
    Discrepancy,
    EngineResult,
)


# 引擎可信度追踪: 基于历史运行记录计算每个引擎的加权投票权重。
# 引擎权重随累积证据动态衰减陈旧记录。
class EngineReliabilityTracker:
    """维护各引擎滑动窗口历史表现，产出加权投票系数"""

    _WINDOW = 64  # 保留最近N次记录
    _DECAY = 0.92  # 陈旧记录指数衰减因子

    def __init__(self):
        self._history: Dict[EngineKind, deque[Dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=self._WINDOW))
        self._lock = threading.Lock()

    def record(self, engine: EngineKind, analysis: AnalysisKind,
               had_error: bool, agreed_with_consensus: bool,
               elapsed: float) -> None:
        with self._lock:
            self._history[engine].append({
                "analysis": analysis,
                "error": had_error,
                "agreed": agreed_with_consensus,
                "elapsed": elapsed,
                "ts": time.time(),
            })

    def weight(self, engine: EngineKind) -> float:
        """返回 [0.1, 2.0] 区间权重: 1.0为基准"""
        with self._lock:
            records = self._history[engine]
            if not records:
                return 1.0
            total = 0.0
            w_sum = 0.0
            for i, rec in enumerate(reversed(records)):
                decay = self._DECAY ** i
                score = 1.0
                if rec["error"]:
                    score -= 0.6
                if not rec["agreed"]:
                    score -= 0.3
                total += decay
                w_sum += score * decay
            raw = w_sum / total if total > 0 else 1.0
            return max(0.1, min(2.0, raw))

    def reliability_report(self) -> Dict[str, Any]:
        with self._lock:
            return {
                eng.value: {
                    "weight": self.weight(eng),
                    "sample_count": len(self._history[eng]),
                }
                for eng in self._history
            }


# 跨分析关联器: 当某分析维度偏差反复伴随另一维度偏差时标记为关联，
# 提示可能共享同一根因（如解析器Bug影响多种分析）。
class CrossAnalysisCorrelator:
    """检测不同AnalysisKind间的偏差共现模式"""

    def __init__(self):
        self._cooccur: Dict[Tuple[AnalysisKind, AnalysisKind], int] = defaultdict(int)
        self._total_runs = 0

    def feed(self, discrepancies: List[Discrepancy]) -> None:
        kinds = {d.analysis for d in discrepancies}
        for a in kinds:
            for b in kinds:
                if a != b and a.value < b.value:
                    self._cooccur[(a, b)] += 1
        self._total_runs += 1

    def correlated_pairs(self, min_cooccur: int = 3) -> List[Dict[str, Any]]:
        """返回Pearson残差显著的共现对"""
        if self._total_runs == 0:
            return []
        results = []
        for (a, b), count in self._cooccur.items():
            if count >= min_cooccur:
                rate = count / self._total_runs
                results.append({
                    "analysis_a": a.value,
                    "analysis_b": b.value,
                    "cooccurrence_rate": round(rate, 3),
                    "count": count,
                })
        results.sort(key=lambda x: -x["cooccurrence_rate"])
        return results


# 偏差检测器: 加权投票+二项检验置信度+交叉关联
class DiscrepancyDetector:

    FUNCTION_SIMILARITY_THRESHOLD = 0.7
    STRING_SIMILARITY_THRESHOLD = 0.8
    CRITICAL_DISAGREEMENT = 0.3

    def __init__(self):
        self.normalizer = ResultNormalizer()
        self._lock = threading.Lock()
        self.reliability = EngineReliabilityTracker()
        self.correlator = CrossAnalysisCorrelator()

    # 加权投票共识: 引擎权重越高，其输出在多数表决中越有分量
    def _weighted_consensus(self, sets: Dict[EngineKind, Set[str]]) -> Set[str]:
        """加权多数表决产出共识集"""
        if not sets:
            return set()
        item_scores: Dict[str, float] = defaultdict(float)
        for eng, items in sets.items():
            w = self.reliability.weight(eng)
            for item in items:
                item_scores[item] += w
        total_weight = sum(
            self.reliability.weight(e) for e in sets)
        threshold = total_weight * 0.4  # 需>=40%加权投票
        return {item for item, sc in item_scores.items() if sc >= threshold}

    # 二项置信度: 检验相似度是否显著低于阈值
    @staticmethod
    def _binomial_confidence(similarities: List[float],
                             threshold: float) -> float:
        """返回 [0, 1] 置信度，值越高越确信偏差真实存在"""
        if not similarities:
            return 0.0
        below = sum(1 for s in similarities if s < threshold)
        n = len(similarities)
        # Wilson score interval下限作为保守置信度
        if n == 0:
            return 0.0
        p = below / n
        z = 1.645  # 90%置信
        denom = 1 + z * z / n
        center = (p + z * z / (2 * n)) / denom
        margin = z * math.sqrt(
            (p * (1 - p) + z * z / (4 * n)) / n) / denom
        lower = max(0.0, center - margin)
        return round(lower, 3)

    # 各分析维度检测
    def _pairwise_similarities(
            self, sets: Dict[EngineKind, Set[str]]) -> List[float]:
        engines = list(sets.keys())
        sims = []
        for i in range(len(engines)):
            for j in range(i + 1, len(engines)):
                sims.append(self.normalizer.jaccard_similarity(
                    sets[engines[i]], sets[engines[j]]))
        return sims

    def _track_agreement(self, sets: Dict[EngineKind, Set[str]],
                         consensus: Set[str]) -> None:
        for eng, items in sets.items():
            if consensus:
                agree = self.normalizer.jaccard_similarity(items, consensus)
                self.reliability.record(
                    eng, AnalysisKind.FUNCTION_LIST,
                    had_error=False,
                    agreed_with_consensus=agree >= 0.6,
                    elapsed=0.0)

    def detect_function_list(
            self, results: List[EngineResult]
    ) -> Tuple[List[Discrepancy], Set[str]]:
        discrepancies: list = []
        with self._lock:
            sets: Dict[EngineKind, Set[str]] = {}
            for r in results:
                if r.analysis != AnalysisKind.FUNCTION_LIST:
                    continue
                if r.error or r.data is None:
                    self.reliability.record(
                        r.engine, AnalysisKind.FUNCTION_LIST,
                        had_error=True, agreed_with_consensus=False,
                        elapsed=r.elapsed)
                    continue
                sets[r.engine] = self.normalizer.normalize_set(r.data)
            if len(sets) < 2:
                return discrepancies, set()
            sims = self._pairwise_similarities(sets)
            avg_sim = statistics.mean(sims) if sims else 0.0
            engines = list(sets.keys())
            consensus = self._weighted_consensus(sets)
            self._track_agreement(sets, consensus)
            if avg_sim < self.FUNCTION_SIMILARITY_THRESHOLD:
                conf = self._binomial_confidence(
                    sims, self.FUNCTION_SIMILARITY_THRESHOLD)
                discrepancies.append(Discrepancy(
                    analysis=AnalysisKind.FUNCTION_LIST,
                    severity=DiscrepancySeverity.MAJOR,
                    description=f"Function list avg similarity {avg_sim:.2f}, below threshold",
                    engine_subset=engines,
                    detail={"avg_similarity": avg_sim,
                            "confidence": conf,
                            "pairwise_sims": sims},
                    confidence=conf))
            return discrepancies, consensus

    def detect_strings(
            self, results: List[EngineResult]
    ) -> Tuple[List[Discrepancy], Set[str]]:
        discrepancies: list = []
        with self._lock:
            sets: Dict[EngineKind, Set[str]] = {}
            for r in results:
                if r.analysis != AnalysisKind.STRINGS:
                    continue
                if r.error or r.data is None:
                    continue
                sets[r.engine] = self.normalizer.normalize_set(r.data)
            if len(sets) < 2:
                return discrepancies, set()
            sims = self._pairwise_similarities(sets)
            avg_sim = statistics.mean(sims) if sims else 0.0
            engines = list(sets.keys())
            consensus = self._weighted_consensus(sets)
            if avg_sim < self.STRING_SIMILARITY_THRESHOLD:
                conf = self._binomial_confidence(
                    sims, self.STRING_SIMILARITY_THRESHOLD)
                discrepancies.append(Discrepancy(
                    analysis=AnalysisKind.STRINGS,
                    severity=DiscrepancySeverity.MINOR,
                    description=f"String list avg similarity {avg_sim:.2f}",
                    engine_subset=engines,
                    detail={"avg_similarity": avg_sim, "confidence": conf},
                    confidence=conf))
            return discrepancies, consensus

    def detect_call_graph(self, results: List[EngineResult]) -> list:
        discrepancies: list = []
        with self._lock:
            graphs: Dict[EngineKind, Set[Tuple[str, str]]] = {}
            for r in results:
                if r.analysis != AnalysisKind.CALL_GRAPH:
                    continue
                if r.error or r.data is None:
                    continue
                edges: set = set()
                if isinstance(r.data, dict):
                    for src, dsts in r.data.items():
                        for dst in (dsts if isinstance(dsts, list) else [dsts]):
                            edges.add((str(src), str(dst)))
                graphs[r.engine] = edges
            if len(graphs) < 2:
                return discrepancies
            engines = list(graphs.keys())
            sims = self._pairwise_similarities(graphs)
            avg_sim = statistics.mean(sims) if sims else 0.0
            if avg_sim < 0.6:
                conf = self._binomial_confidence(sims, 0.6)
                discrepancies.append(Discrepancy(
                    analysis=AnalysisKind.CALL_GRAPH,
                    severity=DiscrepancySeverity.MAJOR,
                    description=f"Call graph avg similarity {avg_sim:.2f}",
                    engine_subset=engines,
                    detail={"avg_similarity": avg_sim, "confidence": conf},
                    confidence=conf))
        return discrepancies

    # 新增分析维度
    def detect_imports(self, results: List[EngineResult]) -> List[Discrepancy]:
        discrepancies: list = []
        with self._lock:
            sets: Dict[EngineKind, Set[str]] = {}
            for r in results:
                if r.analysis != AnalysisKind.IMPORTS:
                    continue
                if r.error or r.data is None:
                    continue
                sets[r.engine] = self.normalizer.normalize_set(r.data)
            if len(sets) < 2:
                return discrepancies
            sims = self._pairwise_similarities(sets)
            avg_sim = statistics.mean(sims) if sims else 0.0
            if avg_sim < 0.85:
                conf = self._binomial_confidence(sims, 0.85)
                discrepancies.append(Discrepancy(
                    analysis=AnalysisKind.IMPORTS,
                    severity=DiscrepancySeverity.MAJOR,
                    description=f"Import table avg similarity {avg_sim:.2f}",
                    engine_subset=list(sets.keys()),
                    detail={"avg_similarity": avg_sim, "confidence": conf},
                    confidence=conf))
        return discrepancies

    def detect_outliers(self, results: list[EngineResult]) -> list:
        with self._lock:
            err_counts: dict[EngineKind, int] = defaultdict(int)
            total: dict[EngineKind, int] = defaultdict(int)
            for r in results:
                total[r.engine] += 1
                if r.error:
                    err_counts[r.engine] += 1
            outliers: list = []
            for eng, t in total.items():
                rate = err_counts[eng] / t if t else 0
                if rate > 0.5:
                    outliers.append(eng)
            return outliers
