"""
基于微分测试的二进制分析引擎正确性验证模块

功能:
    1. 定期使用相同二进制、不同反编译引擎或模拟器分析, 对比结果, 检测分析引擎自身的 bug
    2. 提升工具链可靠性
    3. 输出引擎间的差异报告

核心技术:
    - 引擎抽象: 统一调用不同分析后端
    - 结果规范化: 函数签名/控制流/调用图规范化
    - 差异计算: Jaccard / 编辑距离 / 集合差
    - 异常检测: 异常值(显著偏离共识的引擎)
"""

import logging
import os
import json
import time
import hashlib
import statistics
import threading
from typing import Dict, Any, List, Optional, Tuple, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


class EngineKind(Enum):
    """引擎种类"""
    GHIDRA = "ghidra"
    IDA = "ida"
    RADARE2 = "radare2"
    BINARY_NINJA = "binary_ninja"
    ANGR = "angr"
    CUSTOM_1 = "custom_1"
    CUSTOM_2 = "custom_2"
    INTERNAL = "internal"


class AnalysisKind(Enum):
    """分析种类"""
    FUNCTION_LIST = "function_list"
    DECOMPILED = "decompiled"
    CALL_GRAPH = "call_graph"
    CFG = "cfg"
    STRINGS = "strings"
    IMPORTS = "imports"
    DISASSEMBLY = "disassembly"


class DiscrepancySeverity(Enum):
    """差异严重程度"""
    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"
    COSMETIC = "cosmetic"


@dataclass
class EngineResult:
    """引擎结果"""
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
    """差异条目"""
    analysis: AnalysisKind
    severity: DiscrepancySeverity
    description: str
    engine_subset: List[EngineKind] = field(default_factory=list)
    detail: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DifferentialTestResult:
    """微分测试结果"""
    binary_path: str
    binary_hash: str
    analyses: List[AnalysisKind] = field(default_factory=list)
    engine_results: List[EngineResult] = field(default_factory=list)
    discrepancies: List[Discrepancy] = field(default_factory=list)
    consensus: Dict[str, Any] = field(default_factory=dict)
    outliers: List[EngineKind] = field(default_factory=list)
    overall_score: float = 0.0
    timestamp: float = 0.0


class EngineAdapter:
    """引擎适配器"""

    def __init__(self, kind: EngineKind, runner: Optional[Callable[..., Any]] = None):
        self.kind = kind
        self.runner = runner

    def run(self, binary_path: str, analysis: AnalysisKind) -> EngineResult:
        """运行分析"""
        start = time.time()
        if self.runner is None:
            return EngineResult(
                engine=self.kind,
                analysis=analysis,
                data=None,
                elapsed=time.time() - start,
                error="未配置 runner")
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
    """结果规范化器"""

    @staticmethod
    def normalize_function_name(name: str) -> str:
        """规范化函数名"""
        if not name:
            return ""
        # 移除 demangle 差异: 去除前导下划线/类型后缀
        name = name.strip()
        name = re.sub(r"^_+", "", name)
        name = re.sub(r"@\d+$", "", name)
        return name.lower()

    @staticmethod
    def normalize_set(items: List[Any]) -> Set[str]:
        """规范化为字符串集合"""
        result: Set[str] = set()
        for item in items:
            if isinstance(item, dict):
                # 提取关键字段
                key = item.get("name") or item.get("addr") or json.dumps(item, sort_keys=True)
                result.add(str(key))
            else:
                result.add(str(item))
        return result

    @staticmethod
    def jaccard_similarity(a: Set[Any], b: Set[Any]) -> float:
        """Jaccard 相似度"""
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        inter = len(a & b)
        union = len(a | b)
        return inter / union if union else 0.0


class DiscrepancyDetector:
    """差异检测器"""

    FUNCTION_SIMILARITY_THRESHOLD = 0.7
    STRING_SIMILARITY_THRESHOLD = 0.8
    CRITICAL_DISAGREEMENT = 0.3

    def __init__(self):
        self.norm = ResultNormalizer()
        self._lock = threading.Lock()

    def detect_function_list(self, results: List[EngineResult]) -> Tuple[List[Discrepancy], Set[str]]:
        """检测函数列表差异"""
        discrepancies: List[Discrepancy] = []
        with self._lock:
            sets: Dict[EngineKind, Set[str]] = {}
            for r in results:
                if r.analysis != AnalysisKind.FUNCTION_LIST:
                    continue
                if r.error or r.data is None:
                    continue
                sets[r.engine] = self.norm.normalize_set(r.data)
            if len(sets) < 2:
                return discrepancies, set()
            # 计算所有配对的相似度
            sims: List[float] = []
            engines = list(sets.keys())
            for i in range(len(engines)):
                for j in range(i + 1, len(engines)):
                    sim = self.norm.jaccard_similarity(sets[engines[i]], sets[engines[j]])
                    sims.append(sim)
            avg_sim = statistics.mean(sims) if sims else 0.0
            if avg_sim < self.FUNCTION_SIMILARITY_THRESHOLD:
                discrepancies.append(Discrepancy(
                    analysis=AnalysisKind.FUNCTION_LIST,
                    severity=DiscrepancySeverity.MAJOR,
                    description=f"函数列表平均相似度 {avg_sim:.2f}, 低于阈值",
                    engine_subset=engines,
                    detail={"avg_similarity": avg_sim}))
            # 共识: 大多数都有的函数
            counts: Counter = Counter()
            for s in sets.values():
                counts.update(s)
            consensus = {k for k, v in counts.items() if v >= max(1, len(sets) // 2)}
            return discrepancies, consensus

    def detect_strings(self, results: List[EngineResult]) -> Tuple[List[Discrepancy], Set[str]]:
        """检测字符串差异"""
        discrepancies: List[Discrepancy] = []
        with self._lock:
            sets: Dict[EngineKind, Set[str]] = {}
            for r in results:
                if r.analysis != AnalysisKind.STRINGS:
                    continue
                if r.error or r.data is None:
                    continue
                sets[r.engine] = self.norm.normalize_set(r.data)
            if len(sets) < 2:
                return discrepancies, set()
            sims: List[float] = []
            engines = list(sets.keys())
            for i in range(len(engines)):
                for j in range(i + 1, len(engines)):
                    sim = self.norm.jaccard_similarity(sets[engines[i]], sets[engines[j]])
                    sims.append(sim)
            avg_sim = statistics.mean(sims) if sims else 0.0
            if avg_sim < self.STRING_SIMILARITY_THRESHOLD:
                discrepancies.append(Discrepancy(
                    analysis=AnalysisKind.STRINGS,
                    severity=DiscrepancySeverity.MINOR,
                    description=f"字符串列表平均相似度 {avg_sim:.2f}",
                    engine_subset=engines,
                    detail={"avg_similarity": avg_sim}))
            counts: Counter = Counter()
            for s in sets.values():
                counts.update(s)
            consensus = {k for k, v in counts.items() if v >= max(1, len(sets) // 2)}
            return discrepancies, consensus

    def detect_call_graph(self, results: List[EngineResult]) -> List[Discrepancy]:
        """检测调用图差异"""
        discrepancies: List[Discrepancy] = []
        with self._lock:
            graphs: Dict[EngineKind, Set[Tuple[str, str]]] = {}
            for r in results:
                if r.analysis != AnalysisKind.CALL_GRAPH:
                    continue
                if r.error or r.data is None:
                    continue
                edges: Set[Tuple[str, str]] = set()
                if isinstance(r.data, dict):
                    for src, dsts in r.data.items():
                        for dst in (dsts if isinstance(dsts, list) else [dsts]):
                            edges.add((str(src), str(dst)))
                graphs[r.engine] = edges
            if len(graphs) < 2:
                return discrepancies
            engines = list(graphs.keys())
            sims: List[float] = []
            for i in range(len(engines)):
                for j in range(i + 1, len(engines)):
                    sim = self.norm.jaccard_similarity(graphs[engines[i]], graphs[engines[j]])
                    sims.append(sim)
            avg_sim = statistics.mean(sims) if sims else 0.0
            if avg_sim < 0.6:
                discrepancies.append(Discrepancy(
                    analysis=AnalysisKind.CALL_GRAPH,
                    severity=DiscrepancySeverity.MAJOR,
                    description=f"调用图平均相似度 {avg_sim:.2f}",
                    engine_subset=engines,
                    detail={"avg_similarity": avg_sim}))
        return discrepancies

    def detect_outliers(self, results: List[EngineResult]) -> List[EngineKind]:
        """检测离群引擎"""
        # 简化: 按错误率
        with self._lock:
            err_counts: Dict[EngineKind, int] = defaultdict(int)
            total: Dict[EngineKind, int] = defaultdict(int)
            for r in results:
                total[r.engine] += 1
                if r.error:
                    err_counts[r.engine] += 1
            outliers: List[EngineKind] = []
            for eng, t in total.items():
                rate = err_counts[eng] / t if t else 0
                if rate > 0.5:
                    outliers.append(eng)
            return outliers


class EngineDifferentialTester:
    """引擎微分测试器 (主入口)"""

    def __init__(self):
        self.adapters: List[EngineAdapter] = []
        self.detector = DiscrepancyDetector()
        self._lock = threading.Lock()
        self._history: List[DifferentialTestResult] = []

    def register_engine(self, kind: EngineKind, runner: Callable[..., Any]):
        """注册引擎"""
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
        """运行微分测试"""
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
            # 运行所有引擎的指定分析
            for adapter in self.adapters:
                for analysis in analyses:
                    r = adapter.run(binary_path, analysis)
                    result.engine_results.append(r)
            # 检测差异
            for analysis in analyses:
                ar = [r for r in result.engine_results if r.analysis == analysis]
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
            # 离群检测
            result.outliers = self.detector.detect_outliers(result.engine_results)
            # 总体评分
            n_diffs = len(result.discrepancies)
            n_analyses = max(1, len(analyses) * max(1, len(self.adapters) - 1))
            result.overall_score = max(0.0, 1.0 - n_diffs / n_analyses)
            result.timestamp = time.time()
            self._history.append(result)
            return result

    def get_history(self) -> List[DifferentialTestResult]:
        with self._lock:
            return list(self._history)

    def clear_history(self):
        with self._lock:
            self._history = []


# 便捷入口
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
