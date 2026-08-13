"""Multi-backend SMT solver manager with automatic fallback chains.

Different SMT solvers excel on different constraint categories (bitvectors,
integer arithmetic, strings, arrays). This module maintains a registry of
solver backends, classifies constraints by category, selects the best
solver, and falls back through the priority chain on failure or timeout.

Also supports cross-solver validation: solve the same constraint with
multiple backends and flag inconsistencies.
"""

import logging
import time
import threading
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

log = logging.getLogger(__name__)


DEFAULT_TIMEOUT = 30000
SIMULATED_TIMEOUT_THRESHOLD = 5000
CONSECUTIVE_FAILURE_THRESHOLD = 3
DEGRADED_CONSECUTIVE_FAILURES = 5
POOR_SUCCESS_RATE_THRESHOLD = 0.3
MIN_QUERIES_FOR_RATE_CHECK = 10
HEALTHY_SUCCESS_RATE_THRESHOLD = 0.9
NORMAL_SUCCESS_RATE_THRESHOLD = 0.6
MAX_CATEGORY_SCORE = 2


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


class ConstraintSolverManager:
    """Registry, fallback chain, and performance tracking for SMT solvers.

    Solver selection order:
    1. If a preferred solver is named, try it first
    2. Otherwise, rank by category match score × historical success rate
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

    def _update_performance(self, solver_name: str, result: SolverResult) -> None:
        """Update the running stats for a solver after each call."""
        if solver_name not in self._performance:
            return
        perf = self._performance[solver_name]
        perf.total_queries += 1
        perf.total_time_ms += result.elapsed_ms
        perf.last_solve_time_ms = result.elapsed_ms
        if result.timeout_occurred:
            perf.timeouts += 1
            perf.consecutive_failures += 1
        elif result.satisfiable is not None:
            perf.successful += 1
            perf.consecutive_failures = 0
        else:
            perf.failed += 1
            perf.consecutive_failures += 1

    def solve_with_fallback(
        self,
        constraint: str,
        preferred: Optional[str] = None,
        timeout_ms: Optional[int] = None,
    ) -> SolverResult:
        """Solve a constraint, falling back through enabled solvers by priority.

        If a preferred solver is given, it moves to the front of the chain.
        Returns the first successful result or an error sentinel."""
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

        last_error = ""
        for solver in enabled_solvers:
            solver_timeout = timeout_ms or solver.timeout_ms
            logger.debug(f"Attempting solver: {solver.name} (timeout={solver_timeout}ms)")

            result = self._simulate_solver_call(solver, constraint)
            self._update_performance(solver.name, result)

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

        sat_results = [r for r in results if r.satisfiable is not None]
        sat_values = [r.satisfiable for r in sat_results]

        consistent = True
        if len(set(sat_values)) > 1:
            consistent = False

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
                "consistent": consistent,
                "sat_count": sum(1 for v in sat_values if v),
                "unsat_count": sum(1 for v in sat_values if v is False),
                "timeout_count": len(results) - len(sat_results),
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

    def solver_performance_benchmark(self) -> List[Dict[str, Any]]:
        """Return a ranked performance report for all registered solvers."""
        benchmarks = []
        with self._lock:
            for name, perf in self._performance.items():
                solver = self._solvers.get(name)
                benchmarks.append({
                    "solver_name": name,
                    "enabled": solver.enabled if solver else False,
                    "priority": solver.priority if solver else 999,
                    "total_queries": perf.total_queries,
                    "success_rate": round(perf.success_rate, 4),
                    "avg_time_ms": round(perf.avg_time_ms, 2),
                    "last_time_ms": perf.last_solve_time_ms,
                    "timeout_count": perf.timeouts,
                    "consecutive_failures": perf.consecutive_failures,
                    "status": self._health_status(name, perf, solver),
                })
        return sorted(benchmarks, key=lambda b: b["priority"])

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
        predefined thresholds."""
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
                    "total_queries": perf.total_queries if perf else 0,
                    "recommended_action": self._health_recommendation(status),
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

    def analyze(self, **kwargs) -> Dict[str, Any]:
        """Dispatch solver management operations by 'action' key."""
        action = kwargs.get("action", "solve")

        try:
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
                benchmarks = self.solver_performance_benchmark()
                return {"success": True, "benchmarks": benchmarks}

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

            elif action == "unregister":
                name = kwargs.get("solver_name", "")
                ok = self.unregister_solver(name)
                return {"success": ok, "unregistered": name if ok else None}

            else:
                return {"success": False, "error": f"Unknown operation: {action}"}

        except Exception as e:
            logger.error(f"Solver management operation failed: {e}", exc_info=True)
            return {"success": False, "error": str(e)}


def manage_constraint_solver(**kwargs) -> Dict[str, Any]:
    """Instantiate a ConstraintSolverManager and run a benchmark action."""
    mgr = ConstraintSolverManager()
    return mgr.analyze(action="benchmark", **kwargs)


__all__ = ["ConstraintSolverManager", "manage_constraint_solver"]
