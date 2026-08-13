"""Symbolic execution optimizer: caching, pruning, simplification, parallelism.

Four orthogonal optimizations that compound:
  1. ConstraintSolverCache — two-tier (memory + disk) solver-result cache
  2. PathPruner — drop paths by loop bound, similarity, coverage stagnation
  3. ConstraintSimplifier — deduplicate, simplify arithmetic, remove contradictions
  4. ParallelSolver — thread-pool solver with cache integration and timeouts

SymExecOptimizer exposes them through one consolidated interface.
"""

import os
import re
import logging
import hashlib
import pickle
import tempfile
import threading
import time
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, Future, TimeoutError
from functools import lru_cache

logger = logging.getLogger(__name__)

ANGR_AVAILABLE = False
try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
    logger.info("angr loaded")
except ImportError:
    logger.warning("angr not installed. Install: pip install angr")

Z3_AVAILABLE = False
try:
    import z3
    Z3_AVAILABLE = True
    logger.info("Z3 solver loaded")
except ImportError:
    logger.warning("Z3 not installed. Install: pip install z3-solver")


class PruningStrategy:
    """Available path-pruning strategies. ALL enables every method."""
    NONE = 'none'
    UNSAT_EARLY = 'unsat_early'
    LOOP_BOUND = 'loop_bound'
    SIMILAR_STATE = 'similar_state'
    COVERAGE_GUIDED = 'coverage_guided'
    HEURISTIC = 'heuristic'
    ALL = 'all'


class CachePolicy:
    """Storage tier for the solver cache."""
    NONE = 'none'
    MEMORY = 'memory'
    DISK = 'disk'
    HYBRID = 'hybrid'


DEFAULT_CONFIG = {
    'cache_enabled': True,
    'cache_policy': CachePolicy.HYBRID,
    'cache_max_size': 10000,
    'cache_ttl': 3600,
    'pruning_strategy': PruningStrategy.ALL,
    'loop_bound': 5,
    'max_paths': 1000,
    'solver_timeout': 30,
    'parallel_solvers': 4,
    'simplify_constraints': True,
}


@dataclass
class ConstraintCacheEntry:
    """A cached solver result: constraint hash, satisfiability, solution, stats."""
    constraint_hash: str = ''
    result: Any = None
    is_satisfiable: bool = False
    solution: Optional[Dict[str, Any]] = None
    timestamp: float = 0.0
    hit_count: int = 0
    solve_time: float = 0.0
    metadata: Dict = field(default_factory=dict)


@dataclass
class PathInfo:
    """Metadata for one symbolic execution path, used by the pruner."""
    path_id: str = ''
    address: int = 0
    constraints: List = field(default_factory=list)
    constraint_hash: str = ''
    is_active: bool = True
    is_pruned: bool = False
    prune_reason: str = ''
    depth: int = 0
    visited_addresses: Set[int] = field(default_factory=set)
    loop_counts: Dict = field(default_factory=dict)
    similarity_score: float = 0.0
    metadata: Dict = field(default_factory=dict)


@dataclass
class OptimizationStats:
    """Aggregate counters for all optimization passes."""
    total_paths_explored: int = 0
    paths_pruned: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    solver_calls: int = 0
    solver_time_saved: float = 0.0
    total_solve_time: float = 0.0
    pruning_by_strategy: Dict = field(default_factory=dict)


class ConstraintSolverCache:
    """Two-tier cache: in-memory dict + per-hash pickle files on disk.
    Entries expire after ttl seconds. Eviction policy is least-hit-count."""

    def __init__(self,
        cache_policy: str = CachePolicy.HYBRID,
        max_size: int = 10000,
        ttl: int = 3600,
        cache_dir: Optional[str] = None
    ):
        self.cache_policy = cache_policy
        self.max_size = max_size
        self.ttl = ttl
        self.cache_dir = cache_dir or tempfile.mkdtemp(prefix='solver_cache_')
        self.memory_cache: Dict[str, ConstraintCacheEntry] = {}
        self.stats: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
        if cache_policy in [CachePolicy.DISK, CachePolicy.HYBRID]:
            os.makedirs(self.cache_dir, exist_ok=True)
        logger.info(f"[SolverCache] Cache initialized, policy: {cache_policy}, max: {max_size}")

    def hash_constraints(self, constraints: List[Any]) -> str:
        """Deterministic 16-char hex hash from sorted constraint strings."""
        try:
            constraint_strs = []
            for c in constraints:
                if hasattr(c, '__str__'):
                    constraint_strs.append(str(c))
                elif isinstance(c, (int, float, str, bytes)):
                    constraint_strs.append(str(c))
                else:
                    constraint_strs.append(repr(c))
            combined = '\n'.join(sorted(constraint_strs))
            return hashlib.sha256(combined.encode()).hexdigest()[:16]
        except Exception as e:
            logger.warning(f"[SolverCache] Hash calculation failed: {e}")
            return hashlib.sha256(str(constraints).encode()).hexdigest()[:16]

    def get(self, constraint_hash: str) -> Optional[ConstraintCacheEntry]:
        """Look up in memory, fall back to disk. Expired entries are evicted."""
        with self._lock:
            if constraint_hash in self.memory_cache:
                entry = self.memory_cache[constraint_hash]
                if time.time() - entry.timestamp > self.ttl:
                    self._evict(constraint_hash)
                    self.stats['cache_misses'] += 1
                    return None
                entry.hit_count += 1
                self.stats['cache_hits'] += 1
                return entry
            if self.cache_policy in [CachePolicy.DISK, CachePolicy.HYBRID]:
                entry = self._load_from_disk(constraint_hash)
                if entry:
                    if time.time() - entry.timestamp > self.ttl:
                        self._delete_from_disk(constraint_hash)
                        self.stats['cache_misses'] += 1
                        return None
                    self.memory_cache[constraint_hash] = entry
                    entry.hit_count += 1
                    self.stats['cache_hits'] += 1
                    return entry
            self.stats['cache_misses'] += 1
            return None

    def put(self,
        constraint_hash: str,
        result: Any,
        is_satisfiable: bool,
        solution: Optional[Dict[str, Any]] = None,
        solve_time: float = 0.0
    ) -> None:
        """Store a result. Evicts LRU if at capacity. Persists to disk if configured."""
        entry = ConstraintCacheEntry(
            constraint_hash=constraint_hash,
            result=result,
            is_satisfiable=is_satisfiable,
            solution=solution,
            timestamp=time.time(),
            solve_time=solve_time)
        with self._lock:
            if len(self.memory_cache) >= self.max_size:
                self._evict_lru()
            self.memory_cache[constraint_hash] = entry
            if self.cache_policy in [CachePolicy.DISK, CachePolicy.HYBRID]:
                self._save_to_disk(constraint_hash, entry)
            self.stats['cache_puts'] += 1

    def _evict_lru(self) -> None:
        """Remove the entry with the lowest hit count."""
        if not self.memory_cache:
            return
        min_hash = min(
            self.memory_cache.keys(),
            key=lambda h: self.memory_cache[h].hit_count)
        self._evict(min_hash)

    def _evict(self, constraint_hash: str) -> None:
        """Remove an entry from memory and disk."""
        if constraint_hash in self.memory_cache:
            del self.memory_cache[constraint_hash]
        if self.cache_policy in [CachePolicy.DISK, CachePolicy.HYBRID]:
            self._delete_from_disk(constraint_hash)

    def _save_to_disk(self, constraint_hash: str, entry: ConstraintCacheEntry) -> None:
        """Pickle an entry to a cache file."""
        try:
            path = os.path.join(self.cache_dir, f'{constraint_hash}.cache')
            with open(path, 'wb') as f:
                pickle.dump(entry, f)
        except Exception as e:
            logger.warning(f"[SolverCache] Disk save failed: {e}")

    def _load_from_disk(self, constraint_hash: str) -> Optional[ConstraintCacheEntry]:
        """Unpickle a cache entry from disk. Returns None if absent or corrupt."""
        try:
            path = os.path.join(self.cache_dir, f'{constraint_hash}.cache')
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    return pickle.load(f)
        except Exception as e:
            logger.warning(f"[SolverCache] Disk load failed: {e}")
        return None

    def _delete_from_disk(self, constraint_hash: str) -> None:
        """Remove a disk cache file."""
        try:
            path = os.path.join(self.cache_dir, f'{constraint_hash}.cache')
            if os.path.exists(path):
                os.remove(path)
        except Exception as e:
            logger.warning(f"[SolverCache] Disk delete failed: {e}")

    def clear(self) -> None:
        """Drop all memory and disk entries."""
        with self._lock:
            self.memory_cache.clear()
            if self.cache_policy in [CachePolicy.DISK, CachePolicy.HYBRID]:
                for f in os.listdir(self.cache_dir):
                    if f.endswith('.cache'):
                        os.remove(os.path.join(self.cache_dir, f))

    def get_stats(self) -> Dict[str, Any]:
        """Return cache performance counters."""
        return {
            'memory_cache_size': len(self.memory_cache),
            'hits': self.stats['cache_hits'],
            'misses': self.stats['cache_misses'],
            'puts': self.stats['cache_puts'],
            'hit_rate': self.stats['cache_hits'] / (self.stats['cache_hits'] + self.stats['cache_misses'] + 1)
        }


class PathPruner:
    """Multi-strategy path pruning to contain state explosion.

    Strategies:
      LOOP_BOUND     — prune paths that revisit an address ≥ loop_bound times
      SIMILAR_STATE  — prune when the same state hash appears ≥ 3 times
      COVERAGE_GUIDED — prune when a path deeper than 10 adds no new coverage
      MAX_PATHS      — hard cap on active path count
    """

    def __init__(self,
        strategy: str = PruningStrategy.ALL,
        loop_bound: int = 5,
        max_paths: int = 1000,
        similarity_threshold: float = 0.9
    ):
        self.strategy = strategy
        self.loop_bound = loop_bound
        self.max_paths = max_paths
        self.similarity_threshold = similarity_threshold
        self.active_paths: Dict[str, PathInfo] = {}
        self.visited_states: Dict[str, int] = defaultdict(int)
        self.coverage: Set[int] = set()
        self.stats: OptimizationStats = OptimizationStats()
        logger.info(f"[PathPruner] Pruner initialized, strategy: {strategy}")

    def should_prune(self, path: PathInfo) -> Tuple[bool, str]:
        """Evaluate all enabled strategies. Returns (prune_flag, reason_string)."""
        if self.strategy == PruningStrategy.NONE:
            return False, ''
        if len(self.active_paths) >= self.max_paths:
            return True, 'max_paths_limit'
        if self.strategy in [PruningStrategy.LOOP_BOUND, PruningStrategy.ALL]:
            for addr, count in path.loop_counts.items():
                if count >= self.loop_bound:
                    self.stats.pruning_by_strategy['loop_bound'] = \
                        self.stats.pruning_by_strategy.get('loop_bound', 0) + 1
                    return True, f'loop_bound exceeded at {hex(addr)}'
        if self.strategy in [PruningStrategy.SIMILAR_STATE, PruningStrategy.ALL]:
            state_hash = self._hash_path_state(path)
            if self.visited_states[state_hash] >= 3:
                self.stats.pruning_by_strategy['similar_state'] = \
                    self.stats.pruning_by_strategy.get('similar_state', 0) + 1
                return True, 'similar_state'
        if self.strategy in [PruningStrategy.COVERAGE_GUIDED, PruningStrategy.ALL]:
            new_coverage = len(path.visited_addresses - self.coverage)
            if new_coverage == 0 and path.depth > 10:
                self.stats.pruning_by_strategy['coverage_guided'] = \
                    self.stats.pruning_by_strategy.get('coverage_guided', 0) + 1
                return True, 'no_new_coverage'
        return False, ''

    def register_path(self, path: PathInfo) -> None:
        """Add a path to the active set and update coverage."""
        self.active_paths[path.path_id] = path
        self.coverage.update(path.visited_addresses)
        state_hash = self._hash_path_state(path)
        self.visited_states[state_hash] += 1

    def prune_path(self, path_id: str, reason: str) -> None:
        """Mark a path pruned and remove it from the active set."""
        if path_id in self.active_paths:
            path = self.active_paths[path_id]
            path.is_active = False
            path.is_pruned = True
            path.prune_reason = reason
            self.stats.paths_pruned += 1
            del self.active_paths[path_id]
            logger.debug(f"[PathPruner] Pruned path {path_id}: {reason}")

    def _hash_path_state(self, path: PathInfo) -> str:
        """Hash the last 10 visited addresses for state-deduplication."""
        recent = list(path.visited_addresses)[-10:]
        return hashlib.md5(str(sorted(recent)).encode()).hexdigest()[:8]

    def get_stats(self) -> OptimizationStats:
        """Return pruning statistics with total paths computed."""
        self.stats.total_paths_explored = len(self.active_paths) + self.stats.paths_pruned
        return self.stats


class ConstraintSimplifier:
    """Pre-processing pass: deduplicate, simplify arithmetic identities,
    and remove Z3-detectable contradictions before submitting to the solver."""

    def __init__(self):
        self.simplify_stats: Dict[str, int] = defaultdict(int)

    def simplify(self, constraints: List[Any]) -> List[Any]:
        """Apply the full simplification pipeline."""
        if not constraints:
            return constraints
        simplified = []
        unique = self._remove_duplicates(constraints)
        self.simplify_stats['duplicates_removed'] += len(constraints) - len(unique)
        for c in unique:
            simplified_c = self._simplify_arithmetic(c)
            if simplified_c:
                simplified.append(simplified_c)
        if Z3_AVAILABLE:
            simplified = self._remove_contradictions(simplified)
        self.simplify_stats['total_simplified'] += 1
        return simplified

    def _remove_duplicates(self, constraints: List[Any]) -> List[Any]:
        """Drop constraints with identical string representations."""
        seen = set()
        unique = []
        for c in constraints:
            c_str = str(c)
            if c_str not in seen:
                seen.add(c_str)
                unique.append(c)
        return unique

    def _simplify_arithmetic(self, constraint: Any) -> Optional[Any]:
        """Apply trivial arithmetic identities via string replacement.
        Also runs z3.simplify() if available."""
        c_str = str(constraint)
        replacements = [
            ('+ 0', ''),
            ('- 0', ''),
            ('* 1', ''),
            ('/ 1', ''),
            ('== True', ''),
            ('== False', ' == 0'),
        ]
        for old, new in replacements:
            c_str = c_str.replace(old, new)
        if Z3_AVAILABLE and isinstance(constraint, z3.BoolRef):
            try:
                return z3.simplify(constraint)
            except Exception:
                logger.debug("suppressed", exc_info=True)
        return constraint

    def _remove_contradictions(self, constraints: List[Any]) -> List[Any]:
        """Use Z3 to detect and drop internally contradictory constraints."""
        if not Z3_AVAILABLE:
            return constraints
        try:
            solver = z3.Solver()
            valid = []
            for c in constraints:
                if isinstance(c, z3.BoolRef):
                    solver.push()
                    solver.add(c)
                    if solver.check() == z3.sat:
                        valid.append(c)
                    else:
                        self.simplify_stats['contradictions_removed'] += 1
                    solver.pop()
                else:
                    valid.append(c)
            return valid
        except Exception as e:
            logger.warning(f"[Simplifier] Contradiction detection failed: {e}")
            return constraints


class ParallelSolver:
    """Thread-pool-based parallel constraint solver with integrated caching.

    Submits constraint sets to a ThreadPoolExecutor. Each worker checks
    the cache first, then falls back to Z3 (preferred) or claripy."""

    def __init__(self,
        max_workers: int = 4,
        timeout: float = 30.0,
        cache: Optional[ConstraintSolverCache] = None
    ):
        self.max_workers = max_workers
        self.timeout = timeout
        self.cache = cache or ConstraintSolverCache()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.stats: Dict[str, Any] = defaultdict(float)

    def solve_batch(self,
        constraint_sets: List[List[Any]]
    ) -> List[Optional[Dict[str, Any]]]:
        """Submit multiple constraint sets in parallel; return results in order."""
        futures: Dict[Future, int] = {}
        for i, constraints in enumerate(constraint_sets):
            future = self.executor.submit(
                self._solve_with_cache,
                constraints)
            futures[future] = i
        results = [None] * len(constraint_sets)
        for future in as_completed(futures, timeout=self.timeout * len(constraint_sets)):
            idx = futures[future]
            try:
                result = future.result(timeout=self.timeout)
                results[idx] = result
            except TimeoutError:
                logger.warning(f"[ParallelSolver] Solver timeout: index {idx}")
                results[idx] = {'satisfiable': False, 'error': 'timeout'}
            except Exception as e:
                logger.warning(f"[ParallelSolver] Solve failed: index {idx} - {e}")
                results[idx] = {'satisfiable': False, 'error': str(e)}
        return results

    def _solve_with_cache(self, constraints: List[Any]) -> Optional[Dict[str, Any]]:
        """Check cache, miss → solve with Z3/claripy → cache the result."""
        constraint_hash = self.cache.hash_constraints(constraints)
        cached = self.cache.get(constraint_hash)
        if cached:
            self.stats['time_saved'] += cached.solve_time
            return {
                'satisfiable': cached.is_satisfiable,
                'solution': cached.solution,
                'cached': True
            }
        start_time = time.time()
        if Z3_AVAILABLE:
            result = self._solve_z3(constraints)
        elif ANGR_AVAILABLE:
            result = self._solve_claripy(constraints)
        else:
            result = {'satisfiable': False, 'error': 'no_solver'}
        solve_time = time.time() - start_time
        self.cache.put(
            constraint_hash,
            result,
            result.get('satisfiable', False),
            result.get('solution'),
            solve_time)
        self.stats['total_solve_time'] += solve_time
        return result

    def _solve_z3(self, constraints: List[Any]) -> Dict[str, Any]:
        """Solve a constraint list with Z3. Returns model if SAT."""
        try:
            solver = z3.Solver()
            solver.set('timeout', int(self.timeout * 1000))
            for c in constraints:
                if isinstance(c, z3.BoolRef):
                    solver.add(c)
            result = solver.check()
            if result == z3.sat:
                model = solver.model()
                solution = {}
                for decl in model.decls():
                    solution[str(decl)] = str(model[decl])
                return {'satisfiable': True, 'solution': solution}
            else:
                return {'satisfiable': False}
        except Exception as e:
            return {'satisfiable': False, 'error': str(e)}

    def _solve_claripy(self, constraints: List[Any]) -> Dict[str, Any]:
        """Fallback solver using angr's claripy."""
        try:
            solver = claripy.Solver()
            for c in constraints:
                if hasattr(c, '__and__'):
                    solver.add(c)
            result = solver.satisfiable()
            if result:
                solution = {}
                for var in solver.variables:
                    solution[var] = solver.eval(var, 1)[0]
                return {'satisfiable': True, 'solution': solution}
            else:
                return {'satisfiable': False}
        except Exception as e:
            return {'satisfiable': False, 'error': str(e)}

    def shutdown(self) -> None:
        """Wait for all pending futures and shut down the thread pool."""
        self.executor.shutdown(wait=True)


class SymExecOptimizer:
    """Composite optimizer: wires cache, pruner, simplifier, and parallel
    solver into a single interface for the symbolic execution pipeline."""

    def __init__(self,
        config: Optional[Dict[str, Any]] = None
    ):
        self.config = config or DEFAULT_CONFIG
        self.cache = ConstraintSolverCache(
            cache_policy=self.config.get('cache_policy', CachePolicy.HYBRID),
            max_size=self.config.get('cache_max_size', 10000),
            ttl=self.config.get('cache_ttl', 3600))
        self.pruner = PathPruner(
            strategy=self.config.get('pruning_strategy', PruningStrategy.ALL),
            loop_bound=self.config.get('loop_bound', 5),
            max_paths=self.config.get('max_paths', 1000))
        self.simplifier = ConstraintSimplifier()
        self.parallel_solver = ParallelSolver(
            max_workers=self.config.get('parallel_solvers', 4),
            timeout=self.config.get('solver_timeout', 30),
            cache=self.cache)
        logger.info("[SymExecOptimizer] Symbolic execution optimizer initialized")

    def optimize_solve(self,
        constraints: List[Any]
    ) -> Optional[Dict[str, Any]]:
        """Simplify constraints, then solve with caching."""
        if self.config.get('simplify_constraints', True):
            constraints = self.simplifier.simplify(constraints)
        return self.parallel_solver._solve_with_cache(constraints)

    def should_prune_path(self, path_info: PathInfo) -> Tuple[bool, str]:
        """Delegate to the pruner."""
        return self.pruner.should_prune(path_info)

    def get_optimization_stats(self) -> Dict[str, Any]:
        """Aggregate stats from all sub-components."""
        return {
            'cache': self.cache.get_stats(),
            'pruning': self.pruner.get_stats().__dict__,
            'simplification': dict(self.simplifier.simplify_stats),
            'solver': dict(self.parallel_solver.stats)
        }

    def cleanup(self) -> None:
        """Clear cache and shut down the solver thread pool."""
        self.cache.clear()
        self.parallel_solver.shutdown()


def create_optimizer(config: Optional[Dict[str, Any]] = None) -> SymExecOptimizer:
    """Factory for SymExecOptimizer with optional config override."""
    return SymExecOptimizer(config)


__all__ = [
    'SymExecOptimizer',
    'ConstraintSolverCache',
    'PathPruner',
    'ConstraintSimplifier',
    'ParallelSolver',
    'ConstraintCacheEntry',
    'PathInfo',
    'OptimizationStats',
    'PruningStrategy',
    'CachePolicy',
    'create_optimizer',
    'DEFAULT_CONFIG',
    'ANGR_AVAILABLE',
    'Z3_AVAILABLE'
]
