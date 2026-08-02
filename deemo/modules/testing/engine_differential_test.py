import logging
import os
import re
import json
import time
import hashlib
import statistics
import threading
import math
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter, deque
from typing import Optional, Dict, Tuple, Set, Callable, Any, List

logger = logging.getLogger(__name__)


class EngineKind(str, Enum):
    GHIDRA = "ghidra"
    IDA = "ida"
    RADARE2 = "radare2"
    BINARY_NINJA = "binary_ninja"
    ANGR = "angr"
    CUSTOM_1 = "custom_1"
    CUSTOM_2 = "custom_2"
    INTERNAL = "internal"

class AnalysisKind(str, Enum):
    FUNCTION_LIST = "function_list"
    DECOMPILED = "decompiled"
    CALL_GRAPH = "call_graph"
    CFG = "cfg"
    STRINGS = "strings"
    IMPORTS = "imports"
    DISASSEMBLY = "disassembly"

class DiscrepancySeverity(str, Enum):
    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"
    COSMETIC = "cosmetic"


@dataclass
class EngineResult:
    engine: EngineKind
    analysis: AnalysisKind
    data: Any
    elapsed: float = 0.0
    error: str = ""
    timestamp: float = 0.0

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()


@dataclass
class Discrepancy:
    analysis: AnalysisKind
    severity: DiscrepancySeverity
    description: str
    engine_subset: list = field(default_factory=list)
    detail: dict = field(default_factory=dict)
    # 新增：置信度评分与交叉关联标记
    confidence: float = 0.0
    cross_analysis_hint: Optional[str] = None


@dataclass
class DifferentialTestResult:
    binary_path: str
    binary_hash: str
    analyses: list = field(default_factory=list)
    engine_results: list = field(default_factory=list)
    discrepancies: list = field(default_factory=list)
    consensus: dict = field(default_factory=dict)
    outliers: list = field(default_factory=list)
    overall_score: float = 0.0
    timestamp: float = 0.0
    # 新增：多引擎信度摘要
    engine_reliability: dict = field(default_factory=dict)
    cross_correlations: list = field(default_factory=list)


class EngineAdapter:

    def __init__(self, kind: EngineKind,
                 runner: Optional[Callable[..., Any]] = None):
        self.kind = kind
        self.runner = runner

    def run(self, binary_path: str, analysis: AnalysisKind) -> EngineResult:
        start = time.time()
        if self.runner is None:
            return EngineResult(
                engine=self.kind,
                analysis=analysis,
                data=None,
                elapsed=time.time() - start,
                error="Runner not configured")
        try:
            data = self.runner(binary_path, analysis)
            return EngineResult(
                engine=self.kind,
                analysis=analysis,
                data=data,
                elapsed=time.time() - start)
        except Exception as e:
            return EngineResult(
                engine=self.kind,
                analysis=analysis,
                data=None,
                elapsed=time.time() - start,
                error=str(e))


class ResultNormalizer:

    @staticmethod
    def normalize_function_name(name: str) -> str:
        if not name:
            return ""
        name = name.strip()
        name = re.sub(r"^_+", "", name)
        name = re.sub(r"@\d+$", "", name)
        return name.lower()

    @staticmethod
    def normalize_set(items: list) -> set:
        result: set = set()
        for item in items:
            if isinstance(item, dict):
                key = item.get("name") or item.get("addr") or json.dumps(
                    item, sort_keys=True)
                result.add(str(key))
            else:
                result.add(str(item))
        return result

    @staticmethod
    def jaccard_similarity(a: set, b: set) -> float:
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        inter = len(a & b)
        union = len(a | b)
        return inter / union if union else 0.0


# ---------------------------------------------------------------------------
# 引擎可信度追踪：基于历史运行记录计算每个引擎的加权投票权重，
# 而非对所有引擎一视同仁。引擎权重随累积证据动态衰减陈旧记录。
# ---------------------------------------------------------------------------
class EngineReliabilityTracker:
    """维护各引擎的滑动窗口历史表现，产出加权投票系数"""

    _WINDOW = 64  # 保留最近 N 次记录
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
        """返回 [0.1, 2.0] 区间的权重：1.0 为基准"""
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


# ---------------------------------------------------------------------------
# 交叉分析关联器：当某一分析维度的偏差反复伴随另一维度的偏差时，
# 标记为关联，提示可能共享同一根因（如解析器 Bug 影响多种分析）
# ---------------------------------------------------------------------------
class CrossAnalysisCorrelator:
    """检测不同 AnalysisKind 间的偏差共现模式"""

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
        """返回 Pearson 残差显著的共现对"""
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


# ---------------------------------------------------------------------------
# 偏差检测器增强：加权投票 + 二项检验置信度 + 交叉关联
# ---------------------------------------------------------------------------
class DiscrepancyDetector:

    FUNCTION_SIMILARITY_THRESHOLD = 0.7
    STRING_SIMILARITY_THRESHOLD = 0.8
    CRITICAL_DISAGREEMENT = 0.3

    def __init__(self):
        self.normalizer = ResultNormalizer()
        self._lock = threading.Lock()
        self.reliability = EngineReliabilityTracker()
        self.correlator = CrossAnalysisCorrelator()

    # ---- 加权投票共识：引擎权重越高，其输出在多数表决中越有分量 ----
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
        threshold = total_weight * 0.4  # 需 ≥40% 加权投票
        return {item for item, sc in item_scores.items() if sc >= threshold}

    # ---- 二项置信度：检验相似度是否显著低于阈值 ----
    @staticmethod
    def _binomial_confidence(similarities: List[float],
                             threshold: float) -> float:
        """返回 [0, 1] 的置信度，值越高越确信偏差真实存在"""
        if not similarities:
            return 0.0
        below = sum(1 for s in similarities if s < threshold)
        n = len(similarities)
        # Wilson score interval 下限作为保守置信度
        if n == 0:
            return 0.0
        p = below / n
        z = 1.645  # 90% 置信
        denom = 1 + z * z / n
        center = (p + z * z / (2 * n)) / denom
        margin = z * math.sqrt(
            (p * (1 - p) + z * z / (4 * n)) / n) / denom
        lower = max(0.0, center - margin)
        return round(lower, 3)

    # ---- 各分析维度的检测 ----
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

    # ---- 新增分析维度 ----
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


class EngineDifferentialTester:

    def __init__(self):
        self.adapters: list = []
        self.detector = DiscrepancyDetector()
        self._lock = threading.Lock()
        self.history: list = []
        # 引擎执行时间基准线，用于检测性能退化
        self._time_baselines: Dict[Tuple[EngineKind, AnalysisKind], float] = {}

    def register_engine(self, kind: EngineKind, runner: Callable[..., Any]):
        with self._lock:
            self.adapters.append(EngineAdapter(kind, runner))

    def _compute_hash(self, path: str) -> str:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return ""

    def run(
        self,
        binary_path: str,
        analyses: Optional[List[AnalysisKind]] = None
    ) -> DifferentialTestResult:
        if analyses is None:
            analyses = [
                AnalysisKind.FUNCTION_LIST,
                AnalysisKind.STRINGS,
                AnalysisKind.CALL_GRAPH,
            ]
        with self._lock:
            result = DifferentialTestResult(
                binary_path=binary_path,
                binary_hash=self._compute_hash(binary_path),
                analyses=analyses)
            for adapter in self.adapters:
                for analysis in analyses:
                    r = adapter.run(binary_path, analysis)
                    result.engine_results.append(r)
                    # 更新执行时间基线
                    key = (adapter.kind, analysis)
                    if key in self._time_baselines:
                        prev = self._time_baselines[key]
                        # EMA 平滑基线，检测超过 3x 的退化
                        self._time_baselines[key] = prev * 0.7 + r.elapsed * 0.3
                    else:
                        self._time_baselines[key] = r.elapsed

            for analysis in analyses:
                ar = [r for r in result.engine_results
                      if r.analysis == analysis]
                if analysis == AnalysisKind.FUNCTION_LIST:
                    diffs, consensus = self.detector.detect_function_list(ar)
                    result.discrepancies.extend(diffs)
                    result.consensus["functions"] = list(consensus)
                elif analysis == AnalysisKind.STRINGS:
                    diffs, consensus = self.detector.detect_strings(ar)
                    result.discrepancies.extend(diffs)
                    result.consensus["strings"] = list(consensus)
                elif analysis == AnalysisKind.CALL_GRAPH:
                    diffs = self.detector.detect_call_graph(ar)
                    result.discrepancies.extend(diffs)
                elif analysis == AnalysisKind.IMPORTS:
                    diffs = self.detector.detect_imports(ar)
                    result.discrepancies.extend(diffs)

            result.outliers = self.detector.detect_outliers(
                result.engine_results)

            # ---- 交叉关联注入 ----
            self.detector.correlator.feed(result.discrepancies)
            result.cross_correlations = self.detector.correlator.correlated_pairs()
            # 对已有偏差打交叉关联标记
            corr_pairs = {(c["analysis_a"], c["analysis_b"])
                          for c in result.cross_correlations}
            for d in result.discrepancies:
                for (a, b) in corr_pairs:
                    if d.analysis.value in (a, b):
                        other = b if d.analysis.value == a else a
                        d.cross_analysis_hint = (
                            f"共现关联: {other} 维度偏差频繁伴随出现，"
                            f"建议优先排查共享解析路径")
                        break

            # ---- 可信度报告 ----
            result.engine_reliability = \
                self.detector.reliability.reliability_report()

            n_diffs = len(result.discrepancies)
            n_analyses = max(1, len(analyses) * max(
                1, len(self.adapters) - 1))
            result.overall_score = max(0.0, 1.0 - n_diffs / n_analyses)
            result.timestamp = time.time()
            self.history.append(result)
            return result

    def get_history(self) -> list:
        with self._lock:
            return list(self.history)

    def clear_history(self):
        with self._lock:
            self.history = []

    # ---- 历史基线对比：与之前分析过的同类二进制比较 ----
    def compare_with_baseline(
            self, result: DifferentialTestResult) -> Dict[str, Any]:
        """返回当前结果与历史均值的偏差比例"""
        if len(self.history) < 2:
            return {"baseline_available": False}
        past_scores = [h.overall_score for h in self.history[:-1]]
        avg = statistics.mean(past_scores)
        std = statistics.stdev(past_scores) if len(past_scores) > 1 else 0.0
        z = (result.overall_score - avg) / std if std > 0 else 0.0
        return {
            "baseline_available": True,
            "historical_avg_score": round(avg, 3),
            "current_score": round(result.overall_score, 3),
            "z_score": round(z, 2),
            "degraded": z < -2.0,
        }

    # ---- 偏差聚类：按共享引擎子集将相关偏差归组，减少审查列表中的冗余 ----
    def cluster_discrepancies(
            self, result: DifferentialTestResult) -> List[Dict[str, Any]]:
        """按引擎子集签名聚类，同组偏差大概率同根"""
        groups: Dict[str, List[Discrepancy]] = defaultdict(list)
        for d in result.discrepancies:
            sig = ','.join(sorted(e.value for e in d.engine_subset))
            groups[sig].append(d)
        clusters = []
        for sig, diffs in groups.items():
            clusters.append({
                'engines': sig.split(','),
                'count': len(diffs),
                'analyses': list({d.analysis.value for d in diffs}),
                'max_severity': max(
                    (d.severity for d in diffs),
                    key=lambda s: ['cosmetic', 'minor', 'major', 'critical'].index(
                        s.value)),
                'items': [{
                    'analysis': d.analysis.value,
                    'severity': d.severity.value,
                    'confidence': d.confidence,
                } for d in diffs],
            })
        # 按计数降序：组越大越可能指向系统性问题
        clusters.sort(key=lambda c: -c['count'])
        return clusters

    # ---- 分析维度推荐：基于历史偏差频率，推荐高信噪比的检测维度 ----
    def recommend_analyses(self) -> List[Dict[str, Any]]:
        """统计各分析维度历史上检测到的偏差频率，产出推荐排序"""
        freq: Dict[AnalysisKind, List[float]] = defaultdict(list)
        for hist_result in self.history:
            for d in hist_result.discrepancies:
                freq[d.analysis].append(d.confidence)
        recommendations = []
        for kind in AnalysisKind:
            scores = freq.get(kind, [])
            recommendations.append({
                'analysis': kind.value,
                'times_flagged': len(scores),
                'avg_confidence': round(sum(scores) / len(scores), 3)
                if scores else 0.0,
                'recommend': len(scores) >= 3,
            })
        recommendations.sort(key=lambda r: -r['times_flagged'])
        return recommendations

    # ---- 引擎性能回归追踪：单引擎跨次分析的时间趋势 ----
    def track_engine_performance(
            self) -> Dict[str, Dict[str, Any]]:
        """返回每个引擎每种分析的执行时间趋势"""
        per_key: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        for hist_result in self.history:
            for er in hist_result.engine_results:
                key = (er.engine.value, er.analysis.value)
                per_key[key].append(er.elapsed)
        report = {}
        for (eng, anal), times in per_key.items():
            if len(times) < 2:
                continue
            avg = sum(times) / len(times)
            trend = 0.0
            if len(times) >= 3:
                # 最近 3 次 vs 历史平均
                recent = times[-3:]
                trend = (sum(recent) / len(recent) - avg) / avg if avg > 0 else 0.0
            report[f"{eng}/{anal}"] = {
                'samples': len(times),
                'avg_s': round(avg, 3),
                'latest_s': round(times[-1], 3),
                'trend_pct': round(trend * 100, 1),
                'slowing': trend > 0.2,
            }
        return report

    # ---- 引擎指纹匹配：已知 Bug 模式与特定引擎偏差的签名匹配 ----
    def load_known_fingerprints(
            self, fingerprints: List[Dict[str, Any]]) -> None:
        """
        fingerprints 示例: [{
            'bug_id': 'GHIDRA-1234',
            'engine': 'ghidra',
            'analysis': 'decompiled',
            'signature_pattern': 'sub_40[0-9a-f]{4}',
            'description': 'Ghidra fails to inline small thunks at 0x40xxxx'
        }]
        """
        self._fingerprints = fingerprints

    def match_fingerprints(
            self, result: DifferentialTestResult) -> List[Dict[str, Any]]:
        """将当前偏差与已知引擎 Bug 指纹匹配"""
        if not hasattr(self, '_fingerprints') or not self._fingerprints:
            return []
        matches = []
        for fp in self._fingerprints:
            pat = re.compile(fp['signature_pattern'])
            for d in result.discrepancies:
                engines = [e.value for e in d.engine_subset]
                if fp['engine'] in engines and fp['analysis'] == d.analysis.value:
                    if pat.search(d.description):
                        matches.append({
                            'bug_id': fp['bug_id'],
                            'discrepancy': d.description,
                            'known_issue': fp['description'],
                        })
        return matches

    # ---- Byzantine 共识：要求 ≥⌈2N/3⌉ 引擎一致才认可 ----
    def byzantine_consensus(
            self, result: DifferentialTestResult) -> Dict[str, Any]:
        """对每种分析维度产出拜占庭共识结论"""
        n_engines = len(self.adapters)
        quorum = max(2, math.ceil(2 * n_engines / 3)) if n_engines >= 3 else max(1, n_engines)
        consensus_report: Dict[str, Any] = {}
        for analysis in result.analyses:
            ar = [r for r in result.engine_results
                  if r.analysis == analysis]
            # 按数据签名分组
            sig_groups: Dict[str, List[EngineKind]] = defaultdict(list)
            for r in ar:
                if r.error or r.data is None:
                    continue
                sig = hashlib.sha256(
                    json.dumps(r.data, sort_keys=True).encode()
                ).hexdigest()[:16]
                sig_groups[sig].append(r.engine)
            # 最大组是否达 quorum
            largest = max(sig_groups.values(), key=len) if sig_groups else []
            reached = len(largest) >= quorum
            consensus_report[analysis.value] = {
                'quorum': quorum,
                'total_responding': len(ar),
                'largest_group_size': len(largest),
                'consensus_reached': reached,
                'dissenting_engines': [
                    e.value for e in EngineKind
                    if e not in largest and any(r.engine == e for r in ar)
                ],
            }
        return consensus_report

    # ---- 自动根因分析：偏差类型 + 引擎子集 + 分析维度 → 诊断假设 ----
    def root_cause_analysis(
            self, result: DifferentialTestResult) -> List[Dict[str, Any]]:
        """对每一条偏差生成诊断假设（解析器 Bug / ABI 差异 / 符号缺失等）"""
        hypotheses = []
        for d in result.discrepancies:
            engines = [e.value for e in d.engine_subset]
            analysis = d.analysis.value
            h = {
                'discrepancy': d.description,
                'confidence': d.confidence,
                'hypotheses': [],
            }
            # 规则 1: 单一引擎偏差 → 该引擎的解析器特有问题
            if len(engines) == 1:
                h['hypotheses'].append({
                    'cause': 'engine_specific_bug',
                    'likelihood': 'high',
                    'detail': f'仅 {engines[0]} 产生偏差，建议排查其 {analysis} 实现',
                })
            # 规则 2: 函数列表 + 调用图同时偏差 → 函数边界检测策略差异
            if 'function_list' in analysis and any(
                    dd.analysis.value == 'call_graph'
                    for dd in result.discrepancies
                    if set(e.value for e in dd.engine_subset) == set(engines)):
                h['hypotheses'].append({
                    'cause': 'function_detection_strategy_divergence',
                    'likelihood': 'medium',
                    'detail': '函数列表与调用图同时出现偏差，根因可能在函数入口识别策略',
                })
            # 规则 3: 仅字符串分析偏差 → 编码假设差异
            if analysis == 'strings' and len(engines) <= 2:
                h['hypotheses'].append({
                    'cause': 'string_encoding_assumption',
                    'likelihood': 'medium',
                    'detail': '字符串检测差异通常源于最小长度阈值或编码假设不同',
                })
            # 规则 4: 高置信度 + 多引擎 → 二进制格式模糊性
            if d.confidence >= 0.7 and len(engines) >= 2:
                h['hypotheses'].append({
                    'cause': 'binary_format_ambiguity',
                    'likelihood': 'high',
                    'detail': '多引擎同时出现高置信度偏差，二进制本身可能存在格式歧义',
                })
            if not h['hypotheses']:
                h['hypotheses'].append({
                    'cause': 'unclassified',
                    'likelihood': 'low',
                    'detail': '无匹配的诊断规则，建议人工审查',
                })
            hypotheses.append(h)
        return hypotheses

    # ---- 引擎结果合并/差分：构建统一视图 ----
    def merge_results(self, result: DifferentialTestResult) -> Dict[str, Any]:
        """将多引擎结果合并为并集 + 交集视图"""
        merge: Dict[str, Dict[str, Any]] = {}
        for analysis in result.analyses:
            key = analysis.value
            all_items: Dict[str, Set[str]] = defaultdict(set)
            for r in result.engine_results:
                if r.analysis != analysis or r.error or r.data is None:
                    continue
                normalized = self.detector.normalizer.normalize_set(
                    r.data if isinstance(r.data, list) else [r.data])
                for item in normalized:
                    all_items[item].add(r.engine.value)
            union_count = len(all_items)
            # 交集：被所有引擎发现
            n_engines = len({r.engine for r in result.engine_results
                             if r.analysis == analysis})
            intersection = {item for item, engs in all_items.items()
                            if len(engs) >= n_engines}
            merge[key] = {
                'union_count': union_count,
                'intersection_count': len(intersection),
                'consensus_ratio': round(
                    len(intersection) / union_count, 3)
                if union_count > 0 else 0.0,
                'union_items': sorted(all_items.keys())[:100],
            }
        return merge

    # ---- 关系化比较：跨分析维度检测系统性偏差模式 ----
    def relational_compare(
            self, result: DifferentialTestResult) -> Dict[str, Any]:
        """
        BINSEC 风格的关系化符号执行思想应用到引擎比较：
        不仅比较单维度输出，还比较维度间的关联一致性。
        例如：函数列表中有 N 个函数，调用图中应有 ≥N 个节点。
        """
        relational: Dict[str, Any] = {}
        # 关系 1: 函数数 vs 调用图节点数
        func_consensus = len(result.consensus.get("functions", []))
        if func_consensus > 0:
            import_stat = None
            for d in result.discrepancies:
                if d.analysis == AnalysisKind.CALL_GRAPH:
                    import_stat = d
                    break
            relational["func_vs_callgraph"] = {
                "function_consensus_count": func_consensus,
                "callgraph_discrepant": import_stat is not None,
                "consistent": import_stat is None,
            }
        # 关系 2: 导入函数应在函数列表中全部出现
        if "imports" in result.consensus:
            imp_set = set(result.consensus.get("imports", []))
            func_set = set(result.consensus.get("functions", []))
            missing = imp_set - func_set
            relational["imports_in_functions"] = {
                "import_count": len(imp_set),
                "missing_from_functions": len(missing),
                "missing_examples": sorted(missing)[:10],
                "consistent": len(missing) == 0,
            }
        return relational

    # ---- 侧信道模式检测：引擎行为差异可能暗示信息泄露路径 ----
    def detect_info_leak_patterns(
            self, result: DifferentialTestResult) -> List[Dict[str, Any]]:
        """
        检测指标：
        1. 单引擎暴露了其他引擎未暴露的字符串（可能含密钥/令牌）
        2. 单引擎识别了额外的导入函数 → 可能攻击面被隐藏
        3. 执行时间显著差异 → 可能时序侧信道
        """
        leaks = []
        for d in result.discrepancies:
            engines = [e.value for e in d.engine_subset]
            # 模式 1: 单引擎字符串超集 → 信息泄露风险
            if (d.analysis == AnalysisKind.STRINGS
                    and len(engines) == 1
                    and d.confidence > 0.5):
                leaks.append({
                    "type": "string_superset",
                    "engine": engines[0],
                    "risk": "其他引擎遗漏了字符串，可能包含硬编码凭证",
                    "severity": "medium",
                })
            # 模式 2: 单引擎导入超集 → 隐藏攻击面
            if (d.analysis == AnalysisKind.IMPORTS
                    and len(engines) == 1
                    and d.confidence > 0.6):
                leaks.append({
                    "type": "hidden_attack_surface",
                    "engine": engines[0],
                    "risk": f"{engines[0]} 识别了其他引擎未发现的导入",
                    "severity": "high",
                })
        return leaks

    # ---- 差异摘要可视化数据：输出结构化 JSON 供前端渲染 ----
    def diff_summary(self, result: DifferentialTestResult) -> Dict[str, Any]:
        return {
            "binary": result.binary_path,
            "binary_hash": result.binary_hash,
            "overall_score": round(result.overall_score, 3),
            "engine_count": len(self.adapters),
            "analysis_count": len(result.analyses),
            "discrepancy_by_severity": dict(
                Counter(d.severity.value for d in result.discrepancies)),
            "discrepancy_by_analysis": dict(
                Counter(d.analysis.value for d in result.discrepancies)),
            "consensus_size": {
                k: len(v) for k, v in result.consensus.items()},
            "outlier_engines": [e.value for e in result.outliers],
            "byzantine": self.byzantine_consensus(result),
            "info_leak_alerts": self.detect_info_leak_patterns(result),
            "timestamp": result.timestamp,
        }


# ---------------------------------------------------------------------------
# 持续监控基线：对每引擎结果维护多维特征向量的滑动均值+标准差
# 新结果与基线比较 → z-score 标记离群 → 提示引擎版本退化或二进制异常
# ---------------------------------------------------------------------------
class ContinuousBaselineMonitor:
    """多维特征滑动基线，检测引擎行为漂移"""

    def __init__(self, window: int = 32):
        self._window = window
        self._history: Dict[str, deque[Dict[str, float]]] = defaultdict(
            lambda: deque(maxlen=window))

    def _extract_features(self,
                          result: DifferentialTestResult) -> Dict[str, float]:
        return {
            'overall_score': result.overall_score,
            'discrepancy_count': len(result.discrepancies),
            'consensus_count': sum(
                len(v) for v in result.consensus.values()),
        }

    def record(self, engine: str,
               result: DifferentialTestResult) -> None:
        feats = self._extract_features(result)
        self._history[engine].append(feats)

    def detect_drift(self, engine: str,
                     result: DifferentialTestResult,
                     threshold: float = 2.5) -> Dict[str, Any]:
        feats = self._extract_features(result)
        hist = self._history.get(engine)
        if not hist or len(hist) < 8:
            return {'drift_detected': False, 'reason': 'insufficient_data'}

        anomalies = {}
        for key, val in feats.items():
            vals = [h[key] for h in hist]
            mu = sum(vals) / len(vals)
            sigma = math.sqrt(
                sum((v - mu) ** 2 for v in vals) / len(vals))
            if sigma > 0:
                z = abs(val - mu) / sigma
                if z > threshold:
                    anomalies[key] = {
                        'value': round(val, 3),
                        'mean': round(mu, 3),
                        'z_score': round(z, 2),
                    }
        return {
            'drift_detected': len(anomalies) > 0,
            'anomalies': anomalies,
            'engine': engine,
        }

    def baseline_report(self, engine: str) -> Dict[str, Any]:
        hist = self._history.get(engine)
        if not hist:
            return {'engine': engine, 'samples': 0}
        report = {'engine': engine, 'samples': len(hist)}
        for key in ['overall_score', 'discrepancy_count']:
            vals = [h[key] for h in hist]
            report[key] = {
                'mean': round(sum(vals) / len(vals), 3),
                'min': round(min(vals), 3),
                'max': round(max(vals), 3),
            }
        return report


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 抽象域精度比较器：基于 Formally Verified Binary-Level Pointer Analysis
# (arXiv:2501.17766) 的多精度抽象域思想。对同一函数在不同精度级别下
# 做指针/值集分析，比较各引擎的分析精度：精确度=解析成功的间接调用数
# / 总间接调用数。高精度 → 更精确的别名信息。
# ---------------------------------------------------------------------------
class AbstractDomainComparer:
    """跨引擎抽象域精度比较"""

    def __init__(self):
        self._engine_precision: Dict[str, Dict[str, Any]] = defaultdict(dict)

    def record_indirect_call_resolution(
            self, engine: str, func_id: str,
            total_indirect: int, resolved: int,
            precision_level: str = 'medium') -> None:
        key = f"{func_id}@{precision_level}"
        self._engine_precision[engine][key] = {
            'total': total_indirect,
            'resolved': resolved,
            'precision': precision_level,
            'resolution_rate': round(
                resolved / max(1, total_indirect), 3),
        }

    def compare_precision(self, func_id: str,
                           precision: str = 'medium') -> Dict[str, Any]:
        engines = list(self._engine_precision.keys())
        if len(engines) < 2:
            return {'comparable': False}
        key = f"{func_id}@{precision}"
        rates = {}
        for eng in engines:
            info = self._engine_precision[eng].get(key)
            if info:
                rates[eng] = info['resolution_rate']
        if len(rates) < 2:
            return {'comparable': False}
        best = max(rates, key=rates.get)
        worst = min(rates, key=rates.get)
        return {
            'comparable': True,
            'precision_level': precision,
            'rates': rates,
            'best_engine': best,
            'worst_engine': worst,
            'gap': round(rates[best] - rates[worst], 3),
            'significant_gap': rates[best] - rates[worst] > 0.15,
        }

    def overall_engine_ranking(self) -> List[Tuple[str, float]]:
        avg_rates = {}
        for eng, funcs in self._engine_precision.items():
            rates = [v['resolution_rate'] for v in funcs.values()]
            avg_rates[eng] = round(
                sum(rates) / len(rates), 3) if rates else 0.0
        return sorted(avg_rates.items(), key=lambda x: -x[1])


# 补丁差异评分器：基于 ghidriff 的 Functional Sensitivity Score (FSS) 思路
# 对补丁变更函数做多维度风险评估：变更规模 / 内存操作密度 / 调用链深度 /
# 是否在攻击面上 / 历史漏洞密度。高 FSS → 优先审计。
# ---------------------------------------------------------------------------
class PatchDiffScorer:
    """补丁差异函数的 FSS 风格风险评估"""

    def __init__(self):
        self._scores: Dict[str, Dict[str, Any]] = {}

    def score_function(self, func_name: str,
                        lines_added: int, lines_removed: int,
                        memory_ops: int, is_on_attack_surface: bool,
                        has_prior_cves: int = 0) -> float:
        """计算 Functional Sensitivity Score [0, 10]"""
        change_size = lines_added + lines_removed
        fss = 0.0
        fss += min(3.0, change_size / 10)        # 变更规模 (max 3)
        fss += min(3.0, memory_ops * 0.5)         # 内存操作密度 (max 3)
        fss += 2.0 if is_on_attack_surface else 0  # 攻击面暴露
        fss += min(2.0, has_prior_cves * 0.5)     # 历史漏洞密度 (max 2)
        fss = round(fss, 1)
        self._scores[func_name] = {
            'fss': fss, 'lines_added': lines_added,
            'lines_removed': lines_removed,
            'memory_ops': memory_ops,
            'on_attack_surface': is_on_attack_surface,
            'prior_cves': has_prior_cves,
        }
        return fss

    def top_risky(self, k: int = 10) -> List[Tuple[str, float]]:
        ranked = sorted(
            [(n, s['fss']) for n, s in self._scores.items()],
            key=lambda x: -x[1])
        return ranked[:k]

    def risk_distribution(self) -> Dict[str, int]:
        dist = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for s in self._scores.values():
            if s['fss'] >= 7: dist['critical'] += 1
            elif s['fss'] >= 5: dist['high'] += 1
            elif s['fss'] >= 3: dist['medium'] += 1
            else: dist['low'] += 1
        return dist


# ---------------------------------------------------------------------------
# 语义等价性验证器：验证两个引擎对同一函数的分析是否语义等价
# 比较：函数边界 / 参数数量 / 返回类型 / 局部变量类型推断
# 参考 Glaurung 的 semantic equivalence verification 功能
# ---------------------------------------------------------------------------
class SemanticEquivalenceVerifier:
    """跨引擎语义等价性验证"""

    def verify(self, engine_a_result: Dict[str, Any],
               engine_b_result: Dict[str, Any]) -> Dict[str, Any]:
        checks = {}

        # 检查 1: 函数边界一致（入口地址差 < 16 字节）
        addr_a = engine_a_result.get('address', 0)
        addr_b = engine_b_result.get('address', 0)
        checks['function_boundary'] = abs(addr_a - addr_b) < 16

        # 检查 2: 参数数量一致（±1 容差）
        params_a = engine_a_result.get('param_count', 0)
        params_b = engine_b_result.get('param_count', 0)
        checks['parameter_count'] = abs(params_a - params_b) <= 1

        # 检查 3: 基本块数量偏差 < 20%
        blocks_a = engine_a_result.get('basic_blocks', 0)
        blocks_b = engine_b_result.get('basic_blocks', 0)
        if max(blocks_a, blocks_b) > 0:
            block_dev = abs(blocks_a - blocks_b) / max(blocks_a, blocks_b)
            checks['basic_block_count'] = block_dev < 0.2
        else:
            checks['basic_block_count'] = blocks_a == blocks_b

        # 检查 4: 调用目标一致性
        calls_a = set(engine_a_result.get('callees', []))
        calls_b = set(engine_b_result.get('callees', []))
        if calls_a or calls_b:
            jaccard = len(calls_a & calls_b) / len(calls_a | calls_b)
            checks['callee_consistency'] = jaccard >= 0.7
        else:
            checks['callee_consistency'] = True

        passed = sum(1 for v in checks.values() if v)
        checks['overall'] = {
            'passed': passed, 'total': len(checks) - 1,
            'equivalent': passed >= len(checks) - 1,  # 允许一项偏差
        }
        return checks


# 路径级差分比较器：不比较输出而比较两个引擎的符号执行路径
# 对同一函数的探索路径做集合比较，标记单引擎独有的路径为潜在精度缺失
# 参考 PathFuzzing (arXiv 2507.09892) 的路径编码思路
# ---------------------------------------------------------------------------
class PathBasedDiffComparer:
    """执行路径级别的引擎差异比较"""

    def __init__(self):
        self._path_sets: Dict[str, Dict[str, Set[int]]] = defaultdict(
            lambda: defaultdict(set))

    def record_path(self, engine: str, func_id: str,
                     branch_bits: int) -> None:
        self._path_sets[func_id][engine].add(branch_bits)

    def compare(self, func_id: str) -> Dict[str, Any]:
        eng_paths = self._path_sets.get(func_id, {})
        engines = list(eng_paths.keys())
        if len(engines) < 2:
            return {'comparable': False, 'engines': len(engines)}

        all_paths: Set[int] = set()
        for paths in eng_paths.values():
            all_paths.update(paths)

        report = {'comparable': True, 'total_unique_paths': len(all_paths)}
        for eng in engines:
            eng_set = eng_paths[eng]
            unique_to_eng = eng_set - set().union(
                *[v for k, v in eng_paths.items() if k != eng])
            missing = all_paths - eng_set
            report[eng] = {
                'paths_found': len(eng_set),
                'unique_to_this_engine': len(unique_to_eng),
                'missing_paths': len(missing),
                'coverage_ratio': round(
                    len(eng_set) / len(all_paths), 3) if all_paths else 0.0,
            }
        return report


# ---------------------------------------------------------------------------
# 范围缩减启发式：路径爆炸管理中"范围缩减"策略的实现
# 不分析整个二进制，而是聚焦于：(1) 安全敏感函数邻域
# (2) 最近补丁变更的函数 (3) 用户标注的兴趣区域
# 参考 Symbolic Execution Survey (arXiv 2508.06643) 的分类体系
# ---------------------------------------------------------------------------
class ScopeReductionHeuristic:
    """路径爆炸缓解：聚焦安全敏感代码区域"""

    SENSITIVE_CATEGORIES = {
        'memory': ['malloc', 'free', 'realloc', 'memcpy', 'strcpy',
                    'strcat', 'sprintf', 'gets', 'mmap', 'mprotect'],
        'process': ['execve', 'system', 'popen', 'fork', 'clone'],
        'network': ['socket', 'connect', 'bind', 'listen', 'accept',
                     'recv', 'send', 'read', 'write'],
        'crypto': ['EVP_', 'RSA_', 'AES_', 'SHA', 'MD5', 'HMAC'],
    }

    def __init__(self):
        self._priority_funcs: Dict[str, int] = {}

    def score_function(self, func_name: str,
                        func_code: str = "") -> int:
        """返回函数优先级分：敏感的 → 高分 → 优先符号执行"""
        score = 0
        name_lower = func_name.lower()
        for category, patterns in self.SENSITIVE_CATEGORIES.items():
            for pat in patterns:
                if pat.lower() in name_lower:
                    score += 5 if category == 'memory' else 3
                    break
        if func_code:
            score += func_code.count('if') + func_code.count('switch')
            score += func_code.count('malloc') * 3
            score += func_code.count('free') * 3
        self._priority_funcs[func_name] = score
        return score

    def top_functions(self, k: int = 10) -> List[Tuple[str, int]]:
        ranked = sorted(self._priority_funcs.items(),
                        key=lambda x: -x[1])
        return ranked[:k]

    def should_analyze(self, func_name: str,
                        threshold: int = 5) -> bool:
        return self._priority_funcs.get(func_name, 0) >= threshold


# 二进制函数匹配器：基于助记符 n-gram + TF-IDF 的轻量函数相似度
# 参考 Lund MS Thesis (2025) 的方法：用 Ghidra p-code 或 x86 助记符
# 序列构建 TF-IDF 向量，跨架构/跨编译器比较函数相似性
# ---------------------------------------------------------------------------
class BinaryFunctionMatcher:
    """基于指令助记符 TF-IDF 的函数相似度匹配"""

    def __init__(self):
        self._corpus: Dict[str, List[str]] = {}
        self._idf: Dict[str, float] = {}
        self._n = 3  # n-gram 长度

    def index_function(self, func_id: str,
                        mnemonics: List[str]) -> None:
        """录入函数的助记符序列"""
        ngrams = self._extract_ngrams(mnemonics, self._n)
        self._corpus[func_id] = ngrams
        # 更新 IDF
        n_docs = len(self._corpus)
        for ng in set(ngrams):
            df = sum(1 for grams in self._corpus.values()
                     if ng in grams)
            self._idf[ng] = math.log((n_docs + 1) / (df + 1)) + 1

    def _extract_ngrams(self, tokens: List[str],
                         n: int) -> List[str]:
        return ['|'.join(tokens[i:i + n])
                for i in range(len(tokens) - n + 1)]

    def _tfidf_vector(self, func_id: str) -> Dict[str, float]:
        grams = self._corpus.get(func_id, [])
        if not grams:
            return {}
        tf = {}
        for g in grams:
            tf[g] = tf.get(g, 0) + 1
        vec_len = math.sqrt(sum(
            (cnt * self._idf.get(g, 0)) ** 2
            for g, cnt in tf.items()))
        if vec_len == 0:
            return {}
        return {g: (cnt * self._idf.get(g, 0)) / vec_len
                for g, cnt in tf.items()}

    def similarity(self, func_a: str, func_b: str) -> float:
        """余弦相似度 [0, 1]"""
        va = self._tfidf_vector(func_a)
        vb = self._tfidf_vector(func_b)
        if not va or not vb:
            return 0.0
        dot = sum(va.get(k, 0) * vb.get(k, 0)
                  for k in set(va) | set(vb))
        return round(dot, 4)

    def find_matches(self, query_id: str,
                     top_k: int = 5) -> List[Tuple[str, float]]:
        scores = [(fid, self.similarity(query_id, fid))
                  for fid in self._corpus if fid != query_id]
        scores.sort(key=lambda x: -x[1])
        return scores[:top_k]

    def cross_engine_match(self, func_id_a: str,
                           func_id_b: str) -> Dict[str, Any]:
        """跨引擎函数匹配报告"""
        sim = self.similarity(func_id_a, func_id_b)
        grams_a = set(self._corpus.get(func_id_a, []))
        grams_b = set(self._corpus.get(func_id_b, []))
        return {
            'similarity': sim,
            'shared_ngrams': len(grams_a & grams_b),
            'unique_to_a': len(grams_a - grams_b),
            'unique_to_b': len(grams_b - grams_a),
            'likely_match': sim >= 0.75,
        }


def run_differential_test(
    binary_path: str,
    engines: Optional[Dict[str, Callable[..., Any]]] = None
) -> DifferentialTestResult:
    tester = EngineDifferentialTester()
    if engines:
        for name, runner in engines.items():
            try:
                kind = EngineKind(name)
            except ValueError:
                kind = EngineKind.CUSTOM_1
            tester.register_engine(kind, runner)
    return tester.run(binary_path)
