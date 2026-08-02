"""Multi-backend SMT solver manager with automatic fallback chains.

Different SMT solvers excel on different constraint categories (bitvectors,
integer arithmetic, strings, arrays). This module maintains a registry of
solver backends, classifies constraints by category, selects the best
solver, and falls back through the priority chain on failure or timeout.

Also supports cross-solver validation: solve the same constraint with
multiple backends and flag inconsistencies.

求解器选择采用加权评分制，而非简单优先级排序：
  score = category_match × 10 + success_rate × 5 - consecutive_failures × 2
其中 category_match 在首选类别中为 2，否则为 1。
"""

import logging
import time
import math
import threading
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import deque
from enum import Enum

logger = logging.getLogger(__name__)


DEFAULT_TIMEOUT = 30000
SIMULATED_TIMEOUT_THRESHOLD = 5000
CONSECUTIVE_FAILURE_THRESHOLD = 3
DEGRADED_CONSECUTIVE_FAILURES = 5
POOR_SUCCESS_RATE_THRESHOLD = 0.3
MIN_QUERIES_FOR_RATE_CHECK = 10
HEALTHY_SUCCESS_RATE_THRESHOLD = 0.9
NORMAL_SUCCESS_RATE_THRESHOLD = 0.6
MAX_CATEGORY_SCORE = 2

# ---------------------------------------------------------------------------
# t-digest 近似常量 — 精度 / 内存的折中
# compression=100 意味着在 100 个质心内逼近分布，百分位误差 < 1%
# 每个 solver×category 组合独立维护一个 t-digest 实例
# ---------------------------------------------------------------------------
TDIGEST_COMPRESSION = 100


class SolverType(Enum):
    """Known solver backends."""
    Z3 = "z3"
    CVC4 = "cvc4"
    CVC5 = "cvc5"
    YICES = "yices"
    BOOLECTOR = "boolector"
    CUSTOM = "custom"


class ConstraintCategory(Enum):
    """Constraint domain categories for solver-to-problem matching."""
    BITVECTOR = "bitvector"
    INTEGER_ARITHMETIC = "integer_arithmetic"
    REAL_ARITHMETIC = "real_arithmetic"
    STRING = "string"
    ARRAY = "array"
    BOOLEAN = "boolean"
    MIXED = "mixed"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# TDigest: 轻量级 t-digest 近似，用于 P50/P95/P99 延迟估计
# 核心思想：将样本聚类为质心 (mean, weight)，质心数受 compression 参数限制
# 每个质心代表 w 个相近样本的均值，插入 O(log n)，查询 O(n_centroids)
# 比完整排序 O(n log n) 更快，且内存恒定
# ---------------------------------------------------------------------------
class TDigest:
    """A compact histogram for online percentile approximation.

    Maintains a bounded set of centroids to estimate quantiles without
    storing every sample.  Suitable for latency distributions where the
    number of observations can grow large but memory must stay fixed.

    算法参考 Dunning & Ertl (2013) 的简化变体：单次遍历插入 + 定期合并，
    不维护红黑树，改用排序列表 + 二分查找，代码量小且足够精确。
    """

    def __init__(self, compression: float = 100.0):
        self._compression = max(compression, 10.0)
        # centroids: (mean, weight) 按 mean 升序排列
        self._centroids: List[Tuple[float, float]] = []
        self._total_weight: float = 0.0
        self._max_centroids: int = int(self._compression * 1.5)
        self._lock = threading.Lock()

    def add(self, value: float, weight: float = 1.0) -> None:
        """Insert a sample (or weighted batch) into the digest."""
        if weight <= 0:
            return
        with self._lock:
            self._total_weight += weight
            if not self._centroids:
                self._centroids.append((value, weight))
                return

            # 二分查找插入位置
            lo, hi = 0, len(self._centroids) - 1
            while lo <= hi:
                mid = (lo + hi) // 2
                if self._centroids[mid][0] < value:
                    lo = mid + 1
                else:
                    hi = mid - 1

            # 尝试合并到最近的质心
            merge_target = None
            merge_dist = float('inf')
            if lo < len(self._centroids):
                merge_dist = abs(self._centroids[lo][0] - value)
                merge_target = lo
            if lo > 0:
                left_dist = abs(self._centroids[lo - 1][0] - value)
                if left_dist < merge_dist:
                    merge_dist = left_dist
                    merge_target = lo - 1

            # 质心合并条件：merge_target 的 weight + 新 weight 未超过上限
            if merge_target is not None:
                candidate_w = self._centroids[merge_target][1] + weight
                max_allowed = self._max_weight_for_idx(merge_target)
                if candidate_w <= max_allowed:
                    c_mean, c_w = self._centroids[merge_target]
                    new_mean = (c_mean * c_w + value * weight) / candidate_w
                    self._centroids[merge_target] = (new_mean, candidate_w)
                    self._compress_if_needed()
                    return

            self._centroids.insert(lo, (value, weight))
            self._compress_if_needed()

    def _max_weight_for_idx(self, idx: int) -> float:
        """Compute the weight cap for the centroid at *idx* based on
        t-digest scale function.  Prevents a single centroid from
        dominating its region."""
        if self._total_weight <= 1:
            return self._total_weight * 2
        # 累积权重比例
        cum_before = sum(w for _, w in self._centroids[:idx]) / self._total_weight
        q = cum_before + (self._centroids[idx][1] / (2 * self._total_weight))
        # scale 函数: asin(2q - 1) * compression
        # 限制 q 的范围避免 asin 越界
        q_clamped = max(0.0, min(1.0 - 1e-9, q))
        scale = math.asin(2.0 * q_clamped - 1.0) / math.pi + 0.5
        return self._compression * scale * 4.0

    def _compress_if_needed(self) -> None:
        """Merge adjacent centroids when count exceeds the limit."""
        while len(self._centroids) > self._max_centroids:
            # 找最小合并代价的相邻对
            best_gap = float('inf')
            best_idx = 0
            for i in range(len(self._centroids) - 1):
                gap = abs(self._centroids[i][0] - self._centroids[i + 1][0])
                if gap < best_gap:
                    best_gap = gap
                    best_idx = i

            m1, w1 = self._centroids[best_idx]
            m2, w2 = self._centroids[best_idx + 1]
            merged_mean = (m1 * w1 + m2 * w2) / (w1 + w2)
            merged_weight = w1 + w2
            self._centroids[best_idx] = (merged_mean, merged_weight)
            self._centroids.pop(best_idx + 1)

    def percentile(self, p: float) -> float:
        """Estimate the *p*-th percentile (0-100) from centroids."""
        if p < 0 or p > 100:
            return 0.0
        with self._lock:
            if not self._centroids or self._total_weight == 0:
                return 0.0
            target_cum = (p / 100.0) * self._total_weight
            cum = 0.0
            for i, (mean_val, w) in enumerate(self._centroids):
                prev_cum = cum
                cum += w
                if cum >= target_cum:
                    if i == 0 or w == 0:
                        return mean_val
                    frac = (target_cum - prev_cum) / w
                    # 线性插值在 prev 和当前质心之间
                    if i > 0 and frac < 0.5:
                        prev_mean = self._centroids[i - 1][0]
                        return prev_mean + frac * (mean_val - prev_mean) * 2
                    return mean_val
            return self._centroids[-1][0]

    def count(self) -> int:
        with self._lock:
            return len(self._centroids)

    def total_weight(self) -> float:
        with self._lock:
            return self._total_weight

    def reset(self) -> None:
        with self._lock:
            self._centroids.clear()
            self._total_weight = 0.0


# ---------------------------------------------------------------------------
# SolverTracing: 收集每个求解器、每个类别的延迟到 t-digest 中
# 对外暴露 p50/p95/p99，在 benchmark() 动作中内联输出
# ---------------------------------------------------------------------------
class SolverTracing:
    """Per-solver, per-category latency collector backed by t-digest.

    Each (solver_name, category) pair owns an independent TDigest instance.
    The overall digest (keyed by solver_name alone) captures all-category
    latency distribution for that solver.

    延迟单位：毫秒（ms）。调用 record() 时传入的 elapsed 应为 ms 值。
    """

    def __init__(self):
        self._digests: Dict[str, TDigest] = {}
        self._lock = threading.Lock()

    def _key(self, solver_name: str, category: str = "") -> str:
        if category:
            return f"{solver_name}|{category}"
        return solver_name

    def _ensure_digest(self, solver_name: str, category: str = "") -> TDigest:
        k = self._key(solver_name, category)
        with self._lock:
            if k not in self._digests:
                self._digests[k] = TDigest(TDIGEST_COMPRESSION)
            return self._digests[k]

    def record(self, solver_name: str, elapsed_ms: float, category: str = "") -> None:
        """Record a latency sample for *solver_name*, optionally per-category."""
        if elapsed_ms < 0:
            elapsed_ms = 0.0
        digest = self._ensure_digest(solver_name, category)
        digest.add(elapsed_ms)
        # Also record into the overall (no-category) digest for the solver
        if category:
            digest_all = self._ensure_digest(solver_name, "")
            digest_all.add(elapsed_ms)

    def percentile(self, solver_name: str, p: float, category: str = "") -> float:
        """Retrieve p-th percentile for solver, with optional category filter."""
        k = self._key(solver_name, category)
        with self._lock:
            digest = self._digests.get(k)
        if digest is None or digest.total_weight() == 0:
            return 0.0
        return digest.percentile(p)

    def solver_stats(self, solver_name: str, category: str = "") -> Dict[str, float]:
        """Return {p50, p95, p99, samples} for the given solver[+category]."""
        return {
            "p50_ms": round(self.percentile(solver_name, 50.0, category), 3),
            "p95_ms": round(self.percentile(solver_name, 95.0, category), 3),
            "p99_ms": round(self.percentile(solver_name, 99.0, category), 3),
            "sample_count": self._total_samples(solver_name, category),
        }

    def _total_samples(self, solver_name: str, category: str = "") -> int:
        k = self._key(solver_name, category)
        with self._lock:
            digest = self._digests.get(k)
        if digest is None:
            return 0
        return int(digest.total_weight())

    def dump_all(self) -> Dict[str, Any]:
        """Full dump of all solver latency distributions."""
        result = {}
        with self._lock:
            for k, digest in self._digests.items():
                if digest is None or digest.total_weight() == 0:
                    continue
                result[k] = {
                    "p50_ms": round(digest.percentile(50.0), 3),
                    "p95_ms": round(digest.percentile(95.0), 3),
                    "p99_ms": round(digest.percentile(99.0), 3),
                    "samples": int(digest.total_weight()),
                }
        return result

    def reset(self) -> None:
        with self._lock:
            self._digests.clear()


# ---------------------------------------------------------------------------
# SolverPoolHealth: 跟踪求解器池的可用性，生成 0-100 健康分
# 评分 = success_rate 分 (0-60) + latency 分 (0-40)
#   success_rate 分：直接映射成功比率 (0.0 → 0, 1.0 → 60)
#   latency 分：基于 P95 延迟趋势，低于 500ms 满分，超过 5000ms 归零
# 评分指数加权平滑（EWMA），防止抖动
# ---------------------------------------------------------------------------
class SolverPoolHealth:
    """Tracks availability as a 0-100 health score for each solver.

    Composite score factors:
      - Recent success rate (0-60 points): linearly scaled from [0, 1] to [0, 60]
      - Latency trend (0-40 points): P95 < 500ms → 40 pts, P95 > 5000ms → 0 pts

    Both are smoothed via EWMA (alpha=0.2) to suppress spurious spikes.
    """

    # 延迟评分阈值
    LATENCY_FAST_MS = 500.0
    LATENCY_SLOW_MS = 5000.0

    # EWMA 平滑系数 — 低 alpha 抑制瞬态抖动
    EWMA_ALPHA = 0.2

    def __init__(self):
        self._score: Dict[str, float] = {}
        self._lock = threading.Lock()

    def update(
        self,
        solver_name: str,
        recent_success_rate: float,
        recent_p95_ms: float,
    ) -> float:
        """Compute and return the current health score for *solver_name*.

        *recent_success_rate* should be in [0, 1].
        *recent_p95_ms* is the P95 latency from SolverTracing.
        """
        success_pts = max(0.0, min(1.0, recent_success_rate)) * 60.0

        if recent_p95_ms <= self.LATENCY_FAST_MS:
            latency_pts = 40.0
        elif recent_p95_ms >= self.LATENCY_SLOW_MS:
            latency_pts = 0.0
        else:
            frac = (recent_p95_ms - self.LATENCY_FAST_MS) / (self.LATENCY_SLOW_MS - self.LATENCY_FAST_MS)
            latency_pts = 40.0 * (1.0 - frac)

        raw = max(0.0, min(100.0, success_pts + latency_pts))

        with self._lock:
            prev = self._score.get(solver_name, raw)
            smoothed = self.EWMA_ALPHA * raw + (1.0 - self.EWMA_ALPHA) * prev
            self._score[solver_name] = smoothed
            return smoothed

    def get(self, solver_name: str) -> float:
        with self._lock:
            return self._score.get(solver_name, 100.0)

    def get_all(self) -> Dict[str, float]:
        with self._lock:
            return dict(self._score)

    def status_label(self, solver_name: str) -> str:
        score = self.get(solver_name)
        if score >= 85:
            return "healthy"
        if score >= 60:
            return "normal"
        if score >= 30:
            return "degraded"
        return "critical"

    def reset(self) -> None:
        with self._lock:
            self._score.clear()


# ---------------------------------------------------------------------------
# CrossSolverConsensus: 计算求解器间一致性分数 0-1
# 每次 compare_solver_results / cross-validate 调用后，所有求解器对
# 同一约束的 sat/unsat 结论被记录。一致性 = 一致次数 / 总比较次数
# 独立于 divergence_log （后者是二值告警），Consensus 是连续指标，
# 用于评估求解器集群的稳定性，0.0 表示全不一致，1.0 表示完全同意
# ---------------------------------------------------------------------------
class CrossSolverConsensus:
    """Compute inter-solver agreement as a 0-1 consensus score.

    Tracks per-constraint verdict counts over a sliding window of the
    most recent *window_size* comparisons.  Consensus = fraction of
    comparisons where all solvers agreed on sat/unsat.
    """

    def __init__(self, window_size: int = 200):
        self._window_size = max(window_size, 1)
        # 滚动窗口：True = 本轮一致，False = 本轮存在分歧
        self._agreement_window: deque = deque(maxlen=self._window_size)
        self._total_comparisons: int = 0
        self._total_agreed: int = 0
        self._lock = threading.Lock()

    def record(self, agreed: bool) -> None:
        """Log one comparison outcome.  *agreed* is True when all solvers
        returned the same sat/unsat verdict."""
        with self._lock:
            self._agreement_window.append(agreed)
            self._total_comparisons += 1
            if agreed:
                self._total_agreed += 1

    def consensus_score(self) -> float:
        """Current consensus in sliding window. 0.0 = no agreement."""
        with self._lock:
            if not self._agreement_window:
                return 1.0
            agreed = sum(1 for a in self._agreement_window if a)
            return agreed / len(self._agreement_window)

    def overall_agreement_rate(self) -> float:
        """Lifetime-agreement rate (all-time)."""
        with self._lock:
            if self._total_comparisons == 0:
                return 1.0
            return self._total_agreed / self._total_comparisons

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "consensus_score": round(self.consensus_score(), 4),
                "overall_agreement_rate": round(self.overall_agreement_rate(), 4),
                "window_size": self._window_size,
                "total_comparisons": self._total_comparisons,
                "recent_agreements": sum(1 for a in self._agreement_window if a),
                "recent_total": len(self._agreement_window),
            }

    def reset(self) -> None:
        with self._lock:
            self._agreement_window.clear()
            self._total_comparisons = 0
            self._total_agreed = 0


@dataclass
class SolverConfig:
    """Per-solver registration: type, priority, timeout, preferred categories."""
    solver_type: SolverType
    name: str
    priority: int = 0
    timeout_ms: int = DEFAULT_TIMEOUT
    enabled: bool = True
    preferred_categories: List[ConstraintCategory] = field(default_factory=list)
    requires_binary: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "solver_type": self.solver_type.value,
            "name": self.name,
            "priority": self.priority,
            "timeout_ms": self.timeout_ms,
            "enabled": self.enabled,
            "preferred_categories": [c.value for c in self.preferred_categories],
        }


@dataclass
class SolverResult:
    """Result from a single solver invocation."""
    solver_name: str
    solver_type: SolverType
    satisfiable: Optional[bool]
    model: Optional[Dict[str, Any]]
    elapsed_ms: float
    timeout_occurred: bool = False
    error_message: str = ""
    memory_used_mb: float = 0.0


@dataclass
class SolverPerformance:
    """Running performance counters for one solver backend."""
    solver_name: str
    total_queries: int = 0
    successful: int = 0
    failed: int = 0
    timeouts: int = 0
    total_time_ms: float = 0.0
    last_solve_time_ms: float = 0.0
    consecutive_failures: int = 0
    category_breakdown: Dict[str, int] = field(default_factory=dict)
    # 按类别追踪成功/总数：cat_name -> [successes, total]
    category_success: Dict[str, List[int]] = field(default_factory=dict)
    # 最近 N 次求解耗时（ms），用于检测延迟抖动趋势
    latency_ring: deque = field(default_factory=lambda: deque(maxlen=20))
    # 内存峰值追踪，取最近调用中的最大值
    memory_peak_mb: float = 0.0

    @property
    def success_rate(self) -> float:
        """Fraction of queries that returned a definitive result."""
        if self.total_queries == 0:
            return 1.0
        return self.successful / self.total_queries

    @property
    def avg_time_ms(self) -> float:
        """Mean solve time across all queries."""
        if self.total_queries == 0:
            return 0.0
        return self.total_time_ms / self.total_queries


# ---------------------------------------------------------------------------
# SolverBenchmark: 扩展的性能快照，供外部仪表盘和调度决策使用
# 比 SolverPerformance 多了按类别的胜率和内存/延迟分布，适合序列化输出
# ---------------------------------------------------------------------------
@dataclass
class SolverBenchmark:
    """Extended performance snapshot of one solver, suitable for dashboards."""
    solver_name: str
    enabled: bool
    priority: int
    total_queries: int
    success_rate: float
    avg_time_ms: float
    last_time_ms: float
    timeout_count: int
    consecutive_failures: int
    ewma_success: float
    status: str
    per_category_winrate: Dict[str, float] = field(default_factory=dict)
    memory_peak_mb: float = 0.0
    last_n_latencies: deque = field(default_factory=lambda: deque(maxlen=20))
    health_score: float = 100.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "solver_name": self.solver_name,
            "enabled": self.enabled,
            "priority": self.priority,
            "total_queries": self.total_queries,
            "success_rate": round(self.success_rate, 4),
            "avg_time_ms": round(self.avg_time_ms, 2),
            "last_time_ms": self.last_time_ms,
            "timeout_count": self.timeout_count,
            "consecutive_failures": self.consecutive_failures,
            "ewma_success": round(self.ewma_success, 4),
            "status": self.status,
            "per_category_winrate": {
                k: round(v, 4) for k, v in self.per_category_winrate.items()
            },
            "memory_peak_mb": self.memory_peak_mb,
            "recent_latencies_ms": list(self.last_n_latencies),
            "health_score": round(self.health_score, 2),
        }


# ---------------------------------------------------------------------------
# 指数加权移动平均 (EWMA) 成功率的辅助函数
# 新近查询的权重更高，用于检测求解器的短期退化趋势
# alpha=0.3 意味着最近一次查询权重 30%，历史权重 70% × alpha 递归衰减
# ---------------------------------------------------------------------------
def _ewma(new_val: float, prev: float, alpha: float = 0.3) -> float:
    return alpha * new_val + (1.0 - alpha) * prev


class ConstraintSolverManager:
    """Registry, fallback chain, and performance tracking for SMT solvers.

    Solver selection order:
    1. If a preferred solver is named, try it first
    2. Otherwise, rank by category match score x historical success rate
    3. On timeout or error, advance to the next solver in priority order
    """

    # Per-solver capability registry: preferred constraint categories and binary paths
    DEFAULT_SOLVER_SPECS = {
        SolverType.Z3: {
            "preferred": [ConstraintCategory.BITVECTOR, ConstraintCategory.MIXED],
            "binary": "z3",
        },
        SolverType.CVC5: {
            "preferred": [ConstraintCategory.INTEGER_ARITHMETIC, ConstraintCategory.ARRAY],
            "binary": "cvc5",
        },
        SolverType.YICES: {
            "preferred": [ConstraintCategory.BOOLEAN, ConstraintCategory.STRING],
            "binary": "yices-smt2",
        },
        SolverType.BOOLECTOR: {
            "preferred": [ConstraintCategory.BITVECTOR],
            "binary": "boolector",
        },
    }

    def __init__(self):
        self._solvers: Dict[str, SolverConfig] = {}
        self._performance: Dict[str, SolverPerformance] = {}
        self._lock = threading.Lock()
        self._default_timeout = DEFAULT_TIMEOUT
        self._ewma_success: Dict[str, float] = {}
        # 交叉验证时两个求解器对 sat/unsat 结论不一致的记录
        # 每条记录包含约束摘要、分歧结果和时间戳
        self.divergence_log: List[Dict[str, Any]] = []
        self.divergence_counter: int = 0
        # 新增：延迟追踪 + 池健康评分 + 求解器共识
        self._tracing = SolverTracing()
        self._pool_health = SolverPoolHealth()
        self._consensus = CrossSolverConsensus()
        self._register_default_solvers()

    def _register_default_solvers(self) -> None:
        """Register Z3, CVC5, Yices, Boolector in priority order."""
        priority_order = [
            (SolverType.Z3, 0),
            (SolverType.CVC5, 1),
            (SolverType.YICES, 2),
            (SolverType.BOOLECTOR, 3),
        ]
        for solver_type, priority in priority_order:
            spec = self.DEFAULT_SOLVER_SPECS.get(solver_type, {})
            config = SolverConfig(
                solver_type=solver_type,
                name=solver_type.value,
                priority=priority,
                timeout_ms=self._default_timeout,
                preferred_categories=spec.get("preferred", []),
                requires_binary=spec.get("binary"),
            )
            self._solvers[solver_type.value] = config
            self._performance[solver_type.value] = SolverPerformance(
                solver_name=solver_type.value
            )
            self._ewma_success[solver_type.value] = 1.0
        logger.info(f"Registered {len(self._solvers)} default solvers")

    def register_solver(
        self,
        name: str,
        solver_type: SolverType,
        priority: int = 10,
        timeout_ms: int = DEFAULT_TIMEOUT,
        preferred_categories: Optional[List[ConstraintCategory]] = None,
    ) -> bool:
        """Add or update a custom solver in the registry."""
        with self._lock:
            if name in self._solvers:
                logger.warning(f"Solver already exists, updating config: {name}")
            config = SolverConfig(
                solver_type=solver_type,
                name=name,
                priority=priority,
                timeout_ms=timeout_ms,
                preferred_categories=preferred_categories or [],
            )
            self._solvers[name] = config
            if name not in self._performance:
                self._performance[name] = SolverPerformance(solver_name=name)
                self._ewma_success[name] = 1.0
            logger.info(f"Registered solver: {name} (type={solver_type.value}, priority={priority})")
            return True

    def unregister_solver(self, name: str) -> bool:
        """Remove a solver from the registry."""
        with self._lock:
            if name in self._solvers:
                del self._solvers[name]
                logger.info(f"Unregistered solver: {name}")
                return True
            return False

    def _classify_constraint(self, constraint: str) -> ConstraintCategory:
        """Keyword-based classification of a constraint's domain.

        Scores each category by keyword count; returns the top-scoring
        category if it reaches MAX_CATEGORY_SCORE, otherwise MIXED or UNKNOWN."""
        lower = constraint.lower()
        bv_keywords = [
            "bvadd", "bvmul", "bvsub", "bvsdiv", "bvudiv",
            "bvand", "bvor", "bvxor", "bvshl", "bvlshr", "bvashr",
            "bvult", "bvule", "bvugt", "bvuge", "bvslt", "bvsle",
            "bvsgt", "bvsge", "concat", "extract", "_ bv",
        ]
        int_keywords = [
            "+", "-", "*", "div", "mod", ">", "<", ">=", "<=",
            "int", "to_int",
        ]
        real_keywords = ["real", "to_real", "/"]
        string_keywords = ["str.", "string", "concat", "substring", "len"]
        array_keywords = ["select", "store", "array"]
        bool_keywords = ["and", "or", "not", "=>", "true", "false", "ite"]

        category_scores: Dict[ConstraintCategory, int] = {
            ConstraintCategory.BITVECTOR: 0,
            ConstraintCategory.INTEGER_ARITHMETIC: 0,
            ConstraintCategory.REAL_ARITHMETIC: 0,
            ConstraintCategory.STRING: 0,
            ConstraintCategory.ARRAY: 0,
            ConstraintCategory.BOOLEAN: 0,
        }

        for kw in bv_keywords:
            if kw in lower:
                category_scores[ConstraintCategory.BITVECTOR] += 1
        for kw in int_keywords:
            if kw in lower:
                category_scores[ConstraintCategory.INTEGER_ARITHMETIC] += 1
        for kw in real_keywords:
            if kw in lower:
                category_scores[ConstraintCategory.REAL_ARITHMETIC] += 1
        for kw in string_keywords:
            if kw in lower:
                category_scores[ConstraintCategory.STRING] += 1
        for kw in array_keywords:
            if kw in lower:
                category_scores[ConstraintCategory.ARRAY] += 1
        for kw in bool_keywords:
            if kw in lower:
                category_scores[ConstraintCategory.BOOLEAN] += 1

        max_category = max(category_scores, key=category_scores.get)
        max_score = category_scores[max_category]

        if max_score >= MAX_CATEGORY_SCORE:
            return max_category
        if max_score == 0:
            return ConstraintCategory.UNKNOWN
        return ConstraintCategory.MIXED

    def _simulate_solver_call(
        self, solver: SolverConfig, constraint: str
    ) -> SolverResult:
        """Simulated solver call. Replace with subprocess/API calls in production.

        Returns 'sat' with a category-appropriate synthetic model unless
        'unsat' appears in the constraint text. Times out when constraint
        length exceeds SIMULATED_TIMEOUT_THRESHOLD."""
        start = time.time()

        simulated_satisfiable = "unsat" not in constraint.lower()
        simulated_model: Dict[str, Any] = {}

        if simulated_satisfiable:
            category = self._classify_constraint(constraint)
            if category == ConstraintCategory.BITVECTOR:
                simulated_model = {"x": "0x00000042", "y": "0x00000013"}
            elif category == ConstraintCategory.INTEGER_ARITHMETIC:
                simulated_model = {"x": "42", "y": "13"}
            elif category == ConstraintCategory.BOOLEAN:
                simulated_model = {"p": "true", "q": "false"}
            else:
                simulated_model = {"result": "sat"}

        complexity = len(constraint)
        timeout_happened = complexity > SIMULATED_TIMEOUT_THRESHOLD

        elapsed = round((time.time() - start) * 1000, 2)

        return SolverResult(
            solver_name=solver.name,
            solver_type=solver.solver_type,
            satisfiable=simulated_satisfiable if not timeout_happened else None,
            model=simulated_model if not timeout_happened else None,
            elapsed_ms=elapsed,
            timeout_occurred=timeout_happened,
            error_message="simulated timeout" if timeout_happened else "",
        )

    def _update_performance(self, solver_name: str, result: SolverResult, category: str = "") -> None:
        """Update the running stats for a solver after each call.
        Also feeds tracing telemetry and pool health score."""
        if solver_name not in self._performance:
            return
        perf = self._performance[solver_name]
        perf.total_queries += 1
        perf.total_time_ms += result.elapsed_ms
        perf.last_solve_time_ms = result.elapsed_ms
        perf.latency_ring.append(result.elapsed_ms)

        if result.memory_used_mb > perf.memory_peak_mb:
            perf.memory_peak_mb = result.memory_used_mb

        success_bit = 1.0 if (result.satisfiable is not None and not result.timeout_occurred) else 0.0
        self._ewma_success[solver_name] = _ewma(success_bit, self._ewma_success.get(solver_name, 1.0))

        if result.timeout_occurred:
            perf.timeouts += 1
            perf.consecutive_failures += 1
        elif result.satisfiable is not None:
            perf.successful += 1
            perf.consecutive_failures = 0
        else:
            perf.failed += 1
            perf.consecutive_failures += 1

        if category:
            perf.category_breakdown[category] = perf.category_breakdown.get(category, 0) + 1
            if category not in perf.category_success:
                perf.category_success[category] = [0, 0]
            perf.category_success[category][1] += 1
            if result.satisfiable is not None and not result.timeout_occurred:
                perf.category_success[category][0] += 1

        # 注入延迟样本到 SolverTracing (per solver + per category)
        self._tracing.record(solver_name, result.elapsed_ms, category)

        # 更新池健康分：使用 EWMA 成功率和 P95 延迟
        p95_overall = self._tracing.percentile(solver_name, 95.0, "")
        recent_sr = self._ewma_success.get(solver_name, 1.0)
        self._pool_health.update(solver_name, recent_sr, p95_overall)

    def solve_with_fallback(
        self,
        constraint: str,
        preferred: Optional[str] = None,
        timeout_ms: Optional[int] = None,
    ) -> SolverResult:
        """Solve a constraint, falling back through enabled solvers by priority.

        If a preferred solver is given, it moves to the front of the chain.
        Returns the first successful result or an error sentinel.

        增强：在 fallback 前先按类别匹配评分排序，EWMA 成功率权重高于
        静态 priority 值，以便自适应绕过近期表现不佳的求解器。
        """
        with self._lock:
            enabled_solvers = sorted(
                [s for s in self._solvers.values() if s.enabled],
                key=lambda s: s.priority,
            )

        if preferred:
            enabled_solvers.sort(key=lambda s: 0 if s.name == preferred else s.priority)
            logger.info(f"Preferred solver: {preferred}")

        if not enabled_solvers:
            return SolverResult(
                solver_name="none",
                solver_type=SolverType.CUSTOM,
                satisfiable=None,
                model=None,
                elapsed_ms=0.0,
                error_message="No available solvers",
            )

        # 按类别匹配度 x EWMA 成功率重排序
        category = self._classify_constraint(constraint)
        with self._lock:
            def _rank(s: SolverConfig):
                cat_bonus = 2.0 if category in s.preferred_categories else 1.0
                ewma = self._ewma_success.get(s.name, 1.0)
                penalty = 0.3 if self._performance.get(s.name) and self._performance[s.name].consecutive_failures >= CONSECUTIVE_FAILURE_THRESHOLD else 0.0
                return -(cat_bonus * ewma - penalty)
            enabled_solvers.sort(key=_rank)

        last_error = ""
        for solver in enabled_solvers:
            solver_timeout = timeout_ms or solver.timeout_ms
            logger.debug(f"Attempting solver: {solver.name} (timeout={solver_timeout}ms)")

            result = self._simulate_solver_call(solver, constraint)
            self._update_performance(solver.name, result, category.value)

            if result.timeout_occurred:
                logger.warning(f"Solver {solver.name} timed out, falling back to next")
                last_error = f"{solver.name}: timeout"
                continue

            if result.error_message:
                logger.warning(f"Solver {solver.name} failed: {result.error_message}")
                last_error = f"{solver.name}: {result.error_message}"
                continue

            logger.info(
                f"Constraint solved: solver={solver.name}, "
                f"sat={result.satisfiable}, elapsed={result.elapsed_ms}ms"
            )
            return result

        return SolverResult(
            solver_name="all_failed",
            solver_type=SolverType.CUSTOM,
            satisfiable=None,
            model=None,
            elapsed_ms=0.0,
            error_message=f"All solvers failed. Last error: {last_error}",
        )

    # ------------------------------------------------------------------
    # _detect_solver_divergence: 交叉验证中两个求解器对 sat/unsat 结论相反时
    # 记录该约束和分歧结果，递增 divergence_counter，并返回多数裁定
    # 设计取舍 — 不立即标记某个求解器为 faulty，因为分歧可能源自约束本身的
    # 二义性或超时/非线性算子的近似处理差异，需要累积足够样本再判断
    # ------------------------------------------------------------------
    def _detect_solver_divergence(
        self, constraint: str, results: List[SolverResult]
    ) -> Dict[str, Any]:
        """Cross-validate: detect when solvers disagree on sat/unsat.

        Logs conflicting results to ``divergence_log`` and returns the
        majority verdict.  A divergence is recorded only when at least two
        solvers return a definitive (non-None) verdict that differs.
        """
        sat_results = [r for r in results if r.satisfiable is not None]
        sat_values = [r.satisfiable for r in sat_results]

        consistent = len(set(sat_values)) <= 1

        majority_verdict: Optional[bool] = None
        if not consistent and len(sat_values) >= 2:
            sat_count = sum(1 for v in sat_values if v)
            unsat_count = len(sat_values) - sat_count
            majority_verdict = sat_count > unsat_count

            self.divergence_log.append({
                "constraint": constraint[:500],
                "results": [
                    {"solver": r.solver_name, "satisfiable": r.satisfiable}
                    for r in sat_results
                ],
                "timestamp": time.time(),
            })
            self.divergence_counter += 1
            logger.warning(
                "Solver divergence #%d: sat=%d unsat=%d majority=%s",
                self.divergence_counter, sat_count, unsat_count, majority_verdict,
            )

        # 每次交叉验证都喂入 Consensus tracker
        self._consensus.record(consistent)

        return {
            "consistent": consistent,
            "majority_verdict": majority_verdict,
            "divergence_detected": not consistent,
            "sat_count": sum(1 for v in sat_values if v),
            "unsat_count": sum(1 for v in sat_values if v is False),
        }

    def compare_solver_results(
        self, constraint: str, solver_names: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Cross-validate: solve the same constraint with multiple solvers
        and report whether their sat/unsat verdicts agree."""
        with self._lock:
            if solver_names is None:
                solver_names = list(self._solvers.keys())
            valid_solvers = [
                s for s in solver_names
                if s in self._solvers and self._solvers[s].enabled
            ]

        results: List[SolverResult] = []
        for name in valid_solvers:
            with self._lock:
                solver = self._solvers[name]
            result = self._simulate_solver_call(solver, constraint)
            self._update_performance(name, result)
            results.append(result)

        divergence = self._detect_solver_divergence(constraint, results)

        sat_results = [r for r in results if r.satisfiable is not None]

        return {
            "constraint": constraint[:200],
            "solver_count": len(results),
            "results": [
                {
                    "solver": r.solver_name,
                    "satisfiable": r.satisfiable,
                    "elapsed_ms": r.elapsed_ms,
                    "timeout": r.timeout_occurred,
                    "model_summary": (
                        list(r.model.keys()) if r.model else None
                    ),
                }
                for r in results
            ],
            "consensus": {
                "consistent": divergence["consistent"],
                "sat_count": divergence["sat_count"],
                "unsat_count": divergence["unsat_count"],
                "timeout_count": len(results) - len(sat_results),
                "majority_verdict": divergence["majority_verdict"],
                "divergence_detected": divergence["divergence_detected"],
            },
        }

    def select_best_solver(self, constraint: str) -> str:
        """Auto-select the best solver for a constraint.

        Decision factors, in order of weight:
        1. Category match (preferred_categories)
        2. Historical success rate
        3. Consecutive failure penalty (degraded solvers are skipped)
        """
        category = self._classify_constraint(constraint)
        logger.debug(f"Constraint category: {category.value}")

        candidates: List[Tuple[str, int, float]] = []
        with self._lock:
            for name, solver in self._solvers.items():
                if not solver.enabled:
                    continue
                perf = self._performance.get(name)
                if not perf:
                    continue
                if perf.consecutive_failures >= CONSECUTIVE_FAILURE_THRESHOLD:
                    logger.debug(f"Solver {name} has {perf.consecutive_failures} consecutive failures, not recommended")
                    continue
                match_score = MAX_CATEGORY_SCORE if category in solver.preferred_categories else 1
                composite = (
                    match_score * 10
                    + perf.success_rate * 5
                    - perf.consecutive_failures * 2
                )
                candidates.append((name, solver.priority, composite))

        if not candidates:
            with self._lock:
                available = sorted(
                    [s for s in self._solvers.values() if s.enabled],
                    key=lambda s: s.priority,
                )
            if available:
                return available[0].name
            return "z3"

        candidates.sort(key=lambda x: (-x[2], x[1]))
        best = candidates[0][0]
        logger.info(f"Auto-selected best solver: {best} (category={category.value})")
        return best

    # ------------------------------------------------------------------
    # recommend_solver_for_category: 按历史分类胜率推荐最佳求解器
    # 不依赖实时 EWMA，只看每个 solver 在该 category 下的 cumulative
    # success rate，适用于调度器在冷启动后的类别路由决策
    # ------------------------------------------------------------------
    def recommend_solver_for_category(self, category: ConstraintCategory) -> str:
        """Return the best solver for *category* by per-category success rate.

        Falls back to the highest-priority enabled solver if no historical
        data exists for the given category.
        """
        cat_name = category.value
        best_name = ""
        best_winrate = -1.0

        with self._lock:
            for name, perf in self._performance.items():
                solver = self._solvers.get(name)
                if solver is None or not solver.enabled:
                    continue
                if perf.consecutive_failures >= CONSECUTIVE_FAILURE_THRESHOLD:
                    continue

                cat_succ = perf.category_success.get(cat_name)
                if cat_succ is None or cat_succ[1] == 0:
                    continue

                cat_winrate = cat_succ[0] / cat_succ[1]
                if cat_winrate > best_winrate:
                    best_winrate = cat_winrate
                    best_name = name

        if best_name:
            logger.info(
                "Recommended solver for %s: %s (cat_winrate=%.3f)",
                cat_name, best_name, best_winrate,
            )
            return best_name

        # Fallback: return highest-priority enabled solver
        with self._lock:
            available = sorted(
                [s for s in self._solvers.values() if s.enabled],
                key=lambda s: s.priority,
            )
        fallback = available[0].name if available else "z3"
        logger.info(
            "No category data for %s, fallback solver: %s", cat_name, fallback,
        )
        return fallback

    def solver_performance_benchmark(self) -> List[Dict[str, Any]]:
        """Return a ranked performance report for all registered solvers.

        Includes solver tracing latency statistics and pool health scores.
        """
        bench_extended: List[Dict[str, Any]] = []
        with self._lock:
            for name, perf in self._performance.items():
                solver = self._solvers.get(name)
                cat_winrate: Dict[str, float] = {}
                for cat_name, succ_total in perf.category_success.items():
                    if succ_total[1] > 0:
                        cat_winrate[cat_name] = succ_total[0] / succ_total[1]

                bench = SolverBenchmark(
                    solver_name=name,
                    enabled=solver.enabled if solver else False,
                    priority=solver.priority if solver else 999,
                    total_queries=perf.total_queries,
                    success_rate=perf.success_rate,
                    avg_time_ms=perf.avg_time_ms,
                    last_time_ms=perf.last_solve_time_ms,
                    timeout_count=perf.timeouts,
                    consecutive_failures=perf.consecutive_failures,
                    ewma_success=self._ewma_success.get(name, 1.0),
                    status=self._health_status(name, perf, solver),
                    per_category_winrate=cat_winrate,
                    memory_peak_mb=perf.memory_peak_mb,
                    last_n_latencies=perf.latency_ring,
                    health_score=self._pool_health.get(name),
                )
                # 注入 tracing 延迟分位数
                d = bench.to_dict()
                d["latency_tracing"] = self._tracing.solver_stats(name)
                bench_extended.append(d)
        return sorted(bench_extended, key=lambda b: b["priority"])

    def _health_status(
        self, name: str, perf: SolverPerformance, solver: Optional[SolverConfig]
    ) -> str:
        """Classify a solver's current health from its performance counters."""
        if solver is None or not solver.enabled:
            return "disabled"
        if perf.consecutive_failures >= DEGRADED_CONSECUTIVE_FAILURES:
            return "degraded"
        if perf.success_rate < POOR_SUCCESS_RATE_THRESHOLD and perf.total_queries > MIN_QUERIES_FOR_RATE_CHECK:
            return "poor"
        if perf.success_rate >= HEALTHY_SUCCESS_RATE_THRESHOLD:
            return "healthy"
        if perf.success_rate >= NORMAL_SUCCESS_RATE_THRESHOLD:
            return "normal"
        return "warning"

    def solver_health_check(self, solver_name: Optional[str] = None) -> Dict[str, Any]:
        """Run a health assessment for one or all solvers.

        Checks consecutive failure count and recent success rate against
        predefined thresholds.  Also returns pool health scores.
        """
        results = {}
        with self._lock:
            names = [solver_name] if solver_name else list(self._solvers.keys())
            for name in names:
                solver = self._solvers.get(name)
                perf = self._performance.get(name)
                if solver is None:
                    results[name] = {"status": "not_found", "error": "Solver not registered"}
                    continue

                status = self._health_status(name, perf, solver)
                results[name] = {
                    "status": status,
                    "enabled": solver.enabled,
                    "consecutive_failures": perf.consecutive_failures if perf else 0,
                    "success_rate": round(perf.success_rate, 4) if perf else 0.0,
                    "ewma_success": round(self._ewma_success.get(name, 1.0), 4),
                    "total_queries": perf.total_queries if perf else 0,
                    "recommended_action": self._health_recommendation(status),
                    "pool_health_score": round(self._pool_health.get(name), 2),
                    "pool_health_label": self._pool_health.status_label(name),
                }

        return {"success": True, "results": results, "checked_at": time.time()}

    def _health_recommendation(self, status: str) -> str:
        """Map a health status to a recommended operator action."""
        recommendations = {
            "healthy": "Running normally, no action needed",
            "normal": "Performance normal, continue monitoring",
            "warning": "Consider lowering priority or checking configuration",
            "poor": "Consider disabling and switching to alternate solver",
            "degraded": "Strongly recommend disabling, excessive consecutive failures",
            "disabled": "Already disabled",
            "not_found": "Please register solver first",
        }
        return recommendations.get(status, "Unknown status")

    # ------------------------------------------------------------------
    # consensus_metrics: 获取求解器间一致性快照
    # ------------------------------------------------------------------
    def consensus_metrics(self) -> Dict[str, Any]:
        """Return the cross-solver consensus snapshot."""
        snap = self._consensus.snapshot()
        snap["divergence_counter"] = self.divergence_counter
        return snap

    def analyze(self, **kwargs) -> Dict[str, Any]:
        """Dispatch solver management operations by 'action' key."""
        action = kwargs.get("action", "solve")

        if action == "solve":
            constraint = kwargs.get("constraint", "")
            if not constraint:
                return {"success": False, "error": "constraint parameter is required"}
            preferred = kwargs.get("preferred")
            timeout = kwargs.get("timeout_ms")
            result = self.solve_with_fallback(constraint, preferred, timeout)
            return {
                "success": result.satisfiable is not None,
                "satisfiable": result.satisfiable,
                "model": result.model,
                "solver_used": result.solver_name,
                "elapsed_ms": result.elapsed_ms,
                "timeout": result.timeout_occurred,
                "error": result.error_message or None,
            }

        elif action == "compare":
            constraint = kwargs.get("constraint", "")
            if not constraint:
                return {"success": False, "error": "constraint parameter is required"}
            solver_names = kwargs.get("solver_names")
            comparison = self.compare_solver_results(constraint, solver_names)
            return {"success": True, "comparison": comparison}

        elif action == "benchmark":
            bench_extended = self.solver_performance_benchmark()
            # 附加 tracing 全量转储 + 池健康汇总 + 一致性快照
            return {
                "success": True,
                "benchmarks": bench_extended,
                "divergence_counter": self.divergence_counter,
                "tracing_all": self._tracing.dump_all(),
                "pool_health": self._pool_health.get_all(),
                "consensus": self.consensus_metrics(),
            }

        elif action == "health":
            solver_name = kwargs.get("solver_name")
            health = self.solver_health_check(solver_name)
            return health

        elif action == "register":
            name = kwargs.get("solver_name", "")
            if not name:
                return {"success": False, "error": "solver_name parameter is required"}
            solver_type = kwargs.get("solver_type", SolverType.CUSTOM)
            priority = kwargs.get("priority", 10)
            timeout = kwargs.get("timeout_ms", DEFAULT_TIMEOUT)
            ok = self.register_solver(name, solver_type, priority, timeout)
            return {"success": ok, "registered": name}

        elif action == "select":
            constraint = kwargs.get("constraint", "")
            if not constraint:
                return {"success": False, "error": "constraint parameter is required"}
            best = self.select_best_solver(constraint)
            return {"success": True, "recommended_solver": best}

        elif action == "recommend_for_category":
            cat_str = kwargs.get("category", "")
            try:
                cat = ConstraintCategory(cat_str)
            except ValueError:
                return {"success": False, "error": f"Unknown category: {cat_str}"}
            recommended = self.recommend_solver_for_category(cat)
            return {"success": True, "category": cat.value, "recommended_solver": recommended}

        elif action == "divergence_report":
            return {
                "success": True,
                "divergence_counter": self.divergence_counter,
                "divergence_log": self.divergence_log[-50:],
                "consensus": self.consensus_metrics(),
            }

        elif action == "tracing_report":
            return {
                "success": True,
                "tracing": self._tracing.dump_all(),
                "pool_health": self._pool_health.get_all(),
            }

        elif action == "unregister":
            name = kwargs.get("solver_name", "")
            ok = self.unregister_solver(name)
            return {"success": ok, "unregistered": name if ok else None}

        else:
            return {"success": False, "error": f"Unknown operation: {action}"}


def manage_constraint_solver(**kwargs) -> Dict[str, Any]:
    """Instantiate a ConstraintSolverManager and run a benchmark action."""
    mgr = ConstraintSolverManager()
    return mgr.analyze(action="benchmark", **kwargs)


__all__ = ["ConstraintSolverManager", "manage_constraint_solver"]
