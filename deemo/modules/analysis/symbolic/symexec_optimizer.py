"""符号执行 优化器: control-plane 调度器

SymExec优化器 composite 入口 wires together
优化 passes. individual 优化 passes live
src.symexec_opt_passes 包含:
- ConstraintSolver缓存(two-tier memory + disk缓存)
- IncrementalSolver缓存(Z3 push/pop incremental solving)
- PathPruner (loop-bound, similarity, 覆盖率-guided pruning)
- ConstraintSimplifier (dedup, arithmetic, CSE, contradiction removal)
- 并行Solver (thread-池 solver auto-scaling 性能分析)
- ConstraintComplexityEstimator (pre-solve time prediction)
- 优化流水线 (配置urable DAG: Simplify -> CSE -> 缓存-> Solve)
- SolverBudgetManager (global solver time budget token bucket)

module retains SymExec优化器 调度器 re-exports
public names symexec_opt_passes for backward 兼容性
"""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Import 优化 passes extracted sub-module
# ---------------------------------------------------------------------------
from .src.symexec_opt_passes import (
    ANGR_AVAILABLE,
    Z3_AVAILABLE,
    PSUTIL_AVAILABLE,
    CachePolicy,
    ConstraintCacheEntry,
    ConstraintComplexityEstimator,
    ConstraintFeatures,
    ConstraintSimplifier,
    ConstraintSolverCache,
    IncrementalSolverCache,
    OptimizationPass,
    OptimizationPipeline,
    OptimizationStats,
    ParallelSolver,
    PassResult,
    PathInfo,
    PathPruner,
    PruningStrategy,
    SolverBudgetManager,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default 配置 for 优化器
# ---------------------------------------------------------------------------

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
    'auto_scale_workers': True,
    'incremental_solving': False,
    'solver_profile_window': 100,
    'adaptive_pruning': True,
    # 四轮增强 — 复杂度预估器配置
    'enable_complexity_estimator': True,
    'complexity_skip_threshold': 0.9,
    # 四轮增强 — 优化管道配置
    'pipeline_passes': ['simplify', 'cse', 'cache', 'solve'],
    # 四轮增强 — 求解器预算管理
    'solver_budget_per_interval': 60.0,
    'solver_budget_interval': 60.0,
}


# =============================================================================
# SymExec优化器 — top-level control-plane 调度器
# =============================================================================

class SymExecOptimizer:
    """Composite 优化器: wires缓存, pruner, simplifier, 并行
    solver a single interface for 符号执行 流水线
    
    增强 — 可选 IncrementalSolverCache 用于增量求解场景；
    可选 hotspot profiling 用于识别高耗时的约束类别；
    可选 adaptive pruning 根据内存压力动态调整路径上限
    
    四轮增强 — 集成 ConstraintComplexityEstimator、优化流水线、
    SolverBudgetManager，提供求解前预测、管道化执行和全局预算控制
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or DEFAULT_CONFIG
        use_incremental = self.config.get('incremental_solving', False)
        cache_policy = self.config.get('cache_policy', CachePolicy.HYBRID)
        cache_max_size = self.config.get('cache_max_size', 10000)
        cache_ttl = self.config.get('cache_ttl', 3600)
        solver_timeout = self.config.get('solver_timeout', 30)

        if use_incremental:
            self.cache = IncrementalSolverCache(
                cache_policy=cache_policy,
                max_size=cache_max_size,
                ttl=cache_ttl,
                solver_timeout=solver_timeout)
        else:
            self.cache = ConstraintSolverCache(
                cache_policy=cache_policy,
                max_size=cache_max_size,
                ttl=cache_ttl)

        self.pruner = PathPruner(
            strategy=self.config.get('pruning_strategy', PruningStrategy.ALL),
            loop_bound=self.config.get('loop_bound', 5),
            max_paths=self.config.get('max_paths', 1000),
            adaptive_pruning=self.config.get('adaptive_pruning', True))
        self.simplifier = ConstraintSimplifier()

        # 四轮增强 — 预算管理器
        self.budget_manager = SolverBudgetManager(
            per_interval=self.config.get('solver_budget_per_interval', 60.0),
            interval=self.config.get('solver_budget_interval', 60.0),
        )
        if self.config.get('enable_complexity_estimator', True):
            self.budget_manager.start()

        # 四轮增强 — 复杂度预估器
        self.complexity_estimator = ConstraintComplexityEstimator()

        self.parallel_solver = ParallelSolver(
            max_workers=self.config.get('parallel_solvers', 4),
            timeout=solver_timeout,
            cache=self.cache,
            auto_scale=self.config.get('auto_scale_workers', True),
            solver_profile_window=self.config.get('solver_profile_window', 100),
            complexity_estimator=self.complexity_estimator,
            budget_manager=self.budget_manager,
        )

        # 四轮增强 — 优化管道
        self.pipeline = OptimizationPipeline(
            simplifier=self.simplifier,
            solver_cache=self.cache,
            parallel_solver=self.parallel_solver,
            enabled_passes=self.config.get('pipeline_passes',
                                           ['simplify', 'cse', 'cache_lookup', 'solve']),
        )

        logger.info("[SymExecOptimizer] Symbolic execution optimizer initialized")

    def optimize_solve(self, constraints: List[Any]) -> Optional[Dict[str, Any]]:
        """Simplify constraints, solve 缓存"""
        if self.config.get('simplify_constraints', True):
            constraints = self.simplifier.simplify(constraints)
        return self.parallel_solver._solve_with_cache(constraints)

    def optimize_solve_pipeline(self, constraints: List[Any]) -> Tuple[Optional[Dict[str, Any]], List[PassResult]]:
        """执行 full 优化 流水线: Simplify -> CSE -> 缓存-> Solve
        
        四轮增强 — 通过 OptimizationPipeline 执行完整的优化通道
        返回求解结果和各阶段耗时明细
        
        Args:
        constraints: 待求解的约束列表
        
        返回:
        (result_dict, pass_results_list)
        """
        return self.pipeline.execute(constraints)

    def optimize_solve_incremental(self,
        base_constraints: List[Any],
        new_constraints: List[Any]
    ) -> Dict[str, Any]:
        """增量求解：在 base_constraints 上追加 new_constraints
        
        仅在配置 incremental_solving=True 且 缓存为 IncrementalSolver缓存时有效
        否则回退为全量求解 + 缓存查找
        """
        if isinstance(self.cache, IncrementalSolverCache):
            simplified_base = (self.simplifier.simplify(base_constraints)
                               if self.config.get('simplify_constraints', True)
                               else base_constraints)
            simplified_new = (self.simplifier.simplify(new_constraints)
                              if self.config.get('simplify_constraints', True)
                              else new_constraints)
            return self.cache.solve_incremental(simplified_base, simplified_new)
        else:
            # 回退：全量合并求解
            combined = list(base_constraints) + list(new_constraints)
            return self.parallel_solver._solve_with_cache(combined) or {}

    def should_prune_path(self, path_info: PathInfo) -> Tuple[bool, str]:
        """Delegate pruner"""
        return self.pruner.should_prune(path_info)

    def get_optimization_stats(self) -> Dict[str, Any]:
        """Aggregate stats sub-components"""
        stats: Dict[str, Any] = {
            'cache': self.cache.get_stats(),
            'pruning': self.pruner.get_stats().__dict__,
            'simplification': dict(self.simplifier.simplify_stats),
            'solver': dict(self.parallel_solver.stats),
            'memory_status': self.pruner.get_memory_status(),
            # 四轮增强 — 额外统计
            'complexity_estimator': self.complexity_estimator.stats(),
            'pipeline': self.pipeline.stats(),
            'budget': self.budget_manager.stats(),
        }
        return stats

    def profile_hotspots(self) -> Optional[Dict[str, Any]]:
        """手动触发求解器热点分析报告
        
        返回:
        {'hotspots': [(category, avg_time, count, total_time),.], 'total_queries': int}
        如果采样窗口未满则返回 None
        """
        return self.parallel_solver.profile_solver_hotspots()

    def cleanup(self) -> None:
        """Clear缓存, shut down solver 池, 停止 budget manager"""
        self.budget_manager.stop()
        self.cache.clear()
        self.parallel_solver.shutdown()


def create_optimizer(config: Optional[Dict[str, Any]] = None) -> SymExecOptimizer:
    """工厂 for SymExec优化器 optional 配置 override"""
    return SymExecOptimizer(config)


# ---------------------------------------------------------------------------
# Backward-compatible re-exports: name old __all__
# importable symexec_优化器 exactly
# ---------------------------------------------------------------------------

__all__ = [
    # Control plane
    'SymExecOptimizer',
    'create_optimizer',
    'DEFAULT_CONFIG',
    # Re-exported symexec_opt_passes (backward 兼容性)
    'ConstraintSolverCache',
    'IncrementalSolverCache',
    'PathPruner',
    'ConstraintSimplifier',
    'ParallelSolver',
    'ConstraintCacheEntry',
    'PathInfo',
    'OptimizationStats',
    'PruningStrategy',
    'CachePolicy',
    'ConstraintComplexityEstimator',
    'ConstraintFeatures',
    'OptimizationPipeline',
    'OptimizationPass',
    'PassResult',
    'SolverBudgetManager',
    'ANGR_AVAILABLE',
    'Z3_AVAILABLE',
    'PSUTIL_AVAILABLE',
]
