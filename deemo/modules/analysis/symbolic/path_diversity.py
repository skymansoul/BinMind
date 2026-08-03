"""Path diversity tracking for anti-explosion 符号执行

module a backward-兼容性 shim. real library code
moved ``analysis.symbolic.src.path_diversity_core``

``DynamicPathExplorator`` ``run_path_diversity_exploration``
已废弃 fake/stub implementations 使用 random sleeps synthetic
data. preserved deprecation warnings for backward
兼容性. 使用 real engine classes ``path_diversity_core``
for actual 符号执行
"""

import warnings
import random
import time
from typing import Dict, Any, List, Optional

# Re-export real library code 核心模块 for backward 兼容性
from modules.analysis.symbolic.src.path_diversity_core import (
    # ---- constants / enums ----
    DiversityStrategy,
    PathFeatureType,

    # ---- dataclasses ----
    PathFeature,
    PathNode,
    DiversityMetrics,
    SnapshotDiffResult,

    # ---- core engine ----
    PathSimilarityCalculator,
    PathDiversityTracker,
    DiversityAwarePathSelector,

    # ---- ANN / indexing ----
    ANNIndex,
    _RandomProjectionNode,
    _RandomProjectionTree,

    # ---- budget / monitoring / analytics ----
    DiversityBudget,
    PathHeatmap,
    StreamingDiversityMonitor,
    SnapshotDiff,

    # ---- 工具函数 ----
    _simhash,
    _hamming_distance,
    _feature_to_vector,
)

# 确保 __all__ lists everything for star imports
__all__ = [
    "DiversityStrategy",
    "PathFeatureType",
    "PathFeature",
    "PathNode",
    "DiversityMetrics",
    "SnapshotDiffResult",
    "PathSimilarityCalculator",
    "PathDiversityTracker",
    "DiversityAwarePathSelector",
    "ANNIndex",
    "DiversityBudget",
    "PathHeatmap",
    "StreamingDiversityMonitor",
    "SnapshotDiff",
    "_simhash",
    "_hamming_distance",
    "_feature_to_vector",
    # 已废弃 fake parts — preserved for backward 兼容性
    "DynamicPathExplorator",
    "run_path_diversity_exploration",
]


class DynamicPathExplorator:
    """Top-level exploration 驱动. Accepts path candidates, selects
    via a DiversityAwarePathSelector, simulates exploration
    
    已废弃::
    a fake exploration stub 使用 ``time.sleep`` random
    values instead performing real 符号执行. 使用 core
    engine classes ``path_diversity_core`` instead
    """

    def __init__(self, strategy: str = "hybrid"):
        warnings.warn(
            "DynamicPathExplorator is deprecated: it uses fake random sleeps "
            "and synthetic data instead of real symbolic exploration. "
            "Use PathDiversityTracker and DiversityAwarePathSelector from "
            "path_diversity_core for actual analysis.",
            DeprecationWarning,
            stacklevel=2,
        )
        try:
            self._strategy = DiversityStrategy(strategy.lower())
        except ValueError:
            self._strategy = DiversityStrategy.HYBRID

        self._selector = DiversityAwarePathSelector(self._strategy)
        self._running = False
        self._exploration_count = 0
        self._max_explorations = 1000

    def add_path_candidate(self, path_id: str, address: int, constraints: List[str],
                           depth: int = 0, parent_id: Optional[str] = None):
        """Feed a path selector's candidate 池"""
        self._selector.add_path(path_id, address, constraints, depth, parent_id)

    def explore(self, iterations: int = 50) -> Dict[str, Any]:
        """运行 exploration loop for a fixed number iterations"""
        explored = []
        for _ in range(iterations):
            if self._exploration_count >= self._max_explorations:
                break

            path_id = self._selector.select_next()
            if path_id is None:
                break

            result = self._explore_path(path_id)
            explored.append(result)
            self._exploration_count += 1

        return {
            'success': True,
            'explored_paths': len(explored),
            'total_explorations': self._exploration_count,
            'stats': self._selector.get_stats()
        }

    def _explore_path(self, path_id: str) -> Dict[str, Any]:
        """Explore a path solving constraints deriving new branches
        
        Retrieves path's constraint list diversity tracker
        attempts SAT solving via Z3 (falling back claripy), 构造
        new branches negating individual constraints — standard
        concolic-execution (DART) pattern for branch discovery
        
        solver available or path stored constraints
        falls back a heuristic 估算 derived path's structural
        features (depth) rather random data
        """
        # Retrieve constraints selector's diversity tracker
        constraints: List[str] = []
        path_depth: int = 0
        tracker = getattr(self._selector, '_diversity_tracker', None)
        if tracker is not None:
            with tracker._lock:
                node = tracker._paths.get(path_id)
                if node is not None:
                    constraints = list(node.constraints) if node.constraints else []
                    path_depth = node.depth

        if not constraints:
            return {
                'path_id': path_id,
                'status': 'explored',
                'solved': False,
                'new_constraints': 0,
                'new_branches': min(path_depth, 3),
                'note': 'no_constraints_available',
            }

        # Attempt SAT solving
        start_time = time.time()
        sat, solution = self._solve_path_constraints(constraints)
        solve_time = time.time() - start_time

        new_branches = 0
        new_constraints = 0
        if sat:
            for i, c in enumerate(constraints):
                neg = self._negate_constraint_str(c)
                if neg is not None:
                    new_constraints += 1
                    new_branches += 1
                    if new_branches >= 10:
                        break

        return {
            'path_id': path_id,
            'status': 'explored',
            'solved': sat,
            'satisfiable': sat,
            'solve_time': round(solve_time, 4),
            'new_constraints': new_constraints,
            'new_branches': new_branches,
            'solution': solution,
        }

    @staticmethod
    def _solve_path_constraints(constraints: List[str]) -> tuple:
        """Attempt SAT solving a list constraint strings
        
        返回 (satisfiable: bool, solution: dict or None)
        Tries Z3 first, claripy
        """
        # Try Z3
        try:
            import z3
            solver = z3.Solver()
            solver.set('timeout', 5000)
            var_map: Dict[str, Any] = {}
            import re as _re
            for c in constraints:
                names = _re.findall(r'[a-zA-Z_]\w*', c)
                for n in names:
                    if n not in var_map and not n[0].isupper():
                        var_map[n] = z3.Int(n)
                try:
                    expr = DynamicPathExplorator._str_to_z3(c, var_map, z3)
                    if expr is not None:
                        solver.add(expr)
                except Exception:
                    continue
            if solver.check() == z3.sat:
                model = solver.model()
                sol = {}
                for n, v in var_map.items():
                    try:
                        sol[n] = model[v].as_long()
                    except Exception:
                        sol[n] = str(model[v])
                return True, sol
        except ImportError:
            pass
        except Exception:
            pass

        # Try claripy
        try:
            import claripy
            s = claripy.Solver()
            for c in constraints:
                s.add(claripy.BoolV(c))
            if s.satisfiable():
                sol = {}
                for v in s.variables:
                    try:
                        sol[v] = s.eval(v, 1)[0]
                    except Exception:
                        pass
                return True, sol
        except ImportError:
            pass
        except Exception:
            pass

        return False, None

    @staticmethod
    def _str_to_z3(s: str, var_map: Dict[str, Any], z3_mod: Any) -> Optional[Any]:
        """Translate a constraint string a Z3 BoolRef expression"""
        s = s.strip()
        if ' and ' in s:
            parts = s.split(' and ', 1)
            l = DynamicPathExplorator._str_to_z3(parts[0], var_map, z3_mod)
            r = DynamicPathExplorator._str_to_z3(parts[1], var_map, z3_mod)
            return z3_mod.And(l, r) if l is not None and r is not None else None
        if ' or ' in s:
            parts = s.split(' or ', 1)
            l = DynamicPathExplorator._str_to_z3(parts[0], var_map, z3_mod)
            r = DynamicPathExplorator._str_to_z3(parts[1], var_map, z3_mod)
            return z3_mod.Or(l, r) if l is not None and r is not None else None
        for op, method in [('>=', '__ge__'), ('<=', '__le__'),
                            ('!=', '__ne__'), ('==', '__eq__'),
                            ('>', '__gt__'), ('<', '__lt__')]:
            if op in s:
                left_s, right_s = s.split(op, 1)
                left = DynamicPathExplorator._parse_z3_term(left_s.strip(), var_map, z3_mod)
                right = DynamicPathExplorator._parse_z3_term(right_s.strip(), var_map, z3_mod)
                if left is not None and right is not None:
                    return getattr(left, method)(right)
                return None
        return None

    @staticmethod
    def _parse_z3_term(term: str, var_map: Dict[str, Any], z3_mod: Any) -> Optional[Any]:
        """解析 a term a variable var_map or an integer literal"""
        term = term.strip()
        if term in var_map:
            return var_map[term]
        try:
            return int(term)
        except ValueError:
            return z3_mod.Int(term)

    @staticmethod
    def _negate_constraint_str(constraint: str) -> Optional[str]:
        """Negate a single constraint for branch generation"""
        s = constraint.strip()
        if ' and ' in s or ' or ' in s:
            return f'not ({s})'
        neg_map = {'>': '<=', '<': '>=', '>=': '<', '<=': '>',
                    '==': '!=', '!=': '=='}
        for op, neg_op in neg_map.items():
            if op in s:
                left, right = s.split(op, 1)
                return f'{left.strip()} {neg_op} {right.strip()}'
        return f'not ({s})'

    def get_stats(self) -> Dict[str, Any]:
        return {
            'explorations': self._exploration_count,
            **self._selector.get_stats()
        }


def run_path_diversity_exploration(
    strategy: str = "hybrid",
    iterations: int = 50,
    path_count: int = 20
) -> Dict[str, Any]:
    """One-shot: 构造 a synthetic path population, explore chosen
    diversity strategy, 返回 stats
    
    已废弃::
    function 使用 已废弃 ``DynamicPathExplorator``
    构造 fake random results. For real path diversity analysis
    使用 ``PathDiversityTracker`` ``path_diversity_core`` directly
    """
    warnings.warn(
        "run_path_diversity_exploration is deprecated: it uses "
        "DynamicPathExplorator which returns fake random exploration "
        "results. Use PathDiversityTracker from path_diversity_core "
        "for actual analysis.",
        DeprecationWarning,
        stacklevel=2,
    )
    explorator = DynamicPathExplorator(strategy=strategy)

    for i in range(path_count):
        explorator.add_path_candidate(
            path_id=f"path_{i}",
            address=0x1000 + i * 0x10,
            constraints=[f"x{i} > 0", f"y{i} < 100"],
            depth=i % 5,
            parent_id=f"path_{i-1}" if i > 0 else None
        )

    result = explorator.explore(iterations=iterations)
    result['final_stats'] = explorator.get_stats()
    return result
