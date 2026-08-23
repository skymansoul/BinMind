"""符号执行路径多样性追踪 (防爆炸)。

本模块为向后兼容垫片。实际库代码
已移至 ``analysis.symbolic.src.path_diversity_core``。

``DynamicPathExplorator`` 和 ``run_path_diversity_exploration``
已废弃 — 旧版使用随机休眠和合成数据的伪实现。保留弃用警告
用于向后兼容。实际符号执行请使用 ``path_diversity_core`` 中的引擎类。
"""

import warnings
import random
import time
from typing import Dict, Any, List, Optional

# 向后兼容: 从核心模块重导出实际库代码
from modules.analysis.symbolic.src.path_diversity_core import (
# constants / enums
    DiversityStrategy,
    PathFeatureType,

# dataclasses
    PathFeature,
    PathNode,
    DiversityMetrics,
    SnapshotDiffResult,

# core engine
    PathSimilarityCalculator,
    PathDiversityTracker,
    DiversityAwarePathSelector,

# ANN / indexing
    ANNIndex,
    _RandomProjectionNode,
    _RandomProjectionTree,

# budget / monitoring / analytics
    DiversityBudget,
    PathHeatmap,
    StreamingDiversityMonitor,
    SnapshotDiff,

# 工具函数
    _simhash,
    _hamming_distance,
    _feature_to_vector,
)

# 确保 __all__ 列出全部导出项, 支持 star import
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
    # 已废弃伪实现, 保留向后兼容
    "DynamicPathExplorator",
    "run_path_diversity_exploration",
]


class DynamicPathExplorator:
    """顶层探索驱动器。接收路径候选, 通过 DiversityAwarePathSelector
    筛选, 模拟探索流程

    已废弃: 使用 time.sleep 随机值和合成数据代替真实符号执行。
    请使用 path_diversity_core 中的核心引擎类
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
        """向路径选择器的候选池添加路径"""
        self._selector.add_path(path_id, address, constraints, depth, parent_id)

    def explore(self, iterations: int = 50) -> Dict[str, Any]:
        """运行固定迭代次数的探索循环"""
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
        """探索单条路径, 求解约束并派生新分支

        从选择器的多样性追踪器中取路径约束列表, 尝试通过 Z3
        (回退到 claripy) 做 SAT 求解, 对每条约束取反构造新分支 —
        标准 concolic 执行 (DART) 的分支发现模式

        求解器不可用或路径无约束时回退到启发式估算, 推导路径的
        结构特征 (深度), 而非使用随机数据
        """
        # 从选择器的多样性追踪器中取约束
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

        # 尝试 SAT 求解
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
        """尝试对约束字符串列表做 SAT 求解

        返回 (satisfiable: bool, solution: dict or None)
        先试 Z3, 回退到 claripy
        """
        # 尝试 Z3
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

        # 尝试 claripy
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
        """把约束字符串转换为 Z3 BoolRef 表达式"""
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
        """解析项: 从变量映射或整数字面量"""
        term = term.strip()
        if term in var_map:
            return var_map[term]
        try:
            return int(term)
        except ValueError:
            return z3_mod.Int(term)

    @staticmethod
    def _negate_constraint_str(constraint: str) -> Optional[str]:
        """对单条约束取反, 用于分支生成"""
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
    """一次性接口: 构造合成路径群体, 按指定多样性策略探索, 返回统计

    已废弃: 使用已废弃的 DynamicPathExplorator 构造伪随机结果。
    真实路径多样性分析请直接使用 path_diversity_core 中的
    PathDiversityTracker
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
