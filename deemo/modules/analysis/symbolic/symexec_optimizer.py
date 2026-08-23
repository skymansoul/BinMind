"""符号执行优化器: 控制面调度器。

SymExecOptimizer 作为组合入口串起各优化 pass, 具体 pass 位于
src.symexec_opt_passes:
- ConstraintSolverCache (内存 + 磁盘两级缓存)
- IncrementalSolverCache (Z3 push/pop 增量求解)
- PathPruner (循环界、相似度、覆盖率引导剪枝)
- ConstraintSimplifier (去重、算术化简、CSE、矛盾移除)
- ParallelSolver (线程池求解器自动扩缩与性能分析)
- ConstraintComplexityEstimator (求解前耗时预测)
- 优化流水线 (可配置 DAG: Simplify -> CSE -> cache -> Solve)
- SolverBudgetManager (全局求解时间预算令牌桶)

本模块保留 SymExecOptimizer 调度器, 并从 symexec_opt_passes
再导出公共名称以保持向后兼容。
"""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

# 从子模块导入优化 pass
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

# 优化器默认配置

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


# SymExecOptimizer — 顶层控制面调度器

class SymExecOptimizer:
    """组合优化器: 把缓存、剪枝器、化简器与并行求解器接成
    符号执行流水线的单一接口。

    增强: 可选 IncrementalSolverCache 用于增量求解场景; 可选
    hotspot profiling 识别高耗时约束类别; 可选 adaptive pruning
    根据内存压力动态调整路径上限。

    四轮增强: 集成 ConstraintComplexityEstimator、优化流水线、
    SolverBudgetManager, 提供求解前预测、管道化执行与全局预算控制。
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
        """化简约束后经缓存求解。"""
        if self.config.get('simplify_constraints', True):
            constraints = self.simplifier.simplify(constraints)
        return self.parallel_solver._solve_with_cache(constraints)

    def optimize_solve_pipeline(self, constraints: List[Any]) -> Tuple[Optional[Dict[str, Any]], List[PassResult]]:
        """执行完整优化流水线: Simplify -> CSE -> cache -> Solve。

        四轮增强: 通过 OptimizationPipeline 执行全部优化通道,
        返回求解结果与各阶段耗时明细。
        """
        return self.pipeline.execute(constraints)

    def optimize_solve_incremental(self,
        base_constraints: List[Any],
        new_constraints: List[Any]
    ) -> Dict[str, Any]:
        """增量求解: 在 base_constraints 上追加 new_constraints。

        仅在配置 incremental_solving=True 且缓存为
        IncrementalSolverCache 时有效, 否则回退为全量求解 + 缓存查找。
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
        """委托给 pruner 判断。"""
        return self.pruner.should_prune(path_info)

    def get_optimization_stats(self) -> Dict[str, Any]:
        """聚合各子组件的统计。"""
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
        """手动触发求解器热点分析报告。

        返回 {'hotspots': [(category, avg_time, count, total_time), ...],
        'total_queries': int}, 采样窗口未满时返回 None。
        """
        return self.parallel_solver.profile_solver_hotspots()

    def cleanup(self) -> None:
        """清空缓存, 关闭求解器线程池, 停止预算管理器。"""
        self.budget_manager.stop()
        self.cache.clear()
        self.parallel_solver.shutdown()


def create_optimizer(config: Optional[Dict[str, Any]] = None) -> SymExecOptimizer:
    """SymExecOptimizer 工厂, 可用配置覆盖默认值。"""
    return SymExecOptimizer(config)


# 向后兼容再导出: 旧模块名下的 __all__ 仍可按原名导入

__all__ = [
    # 控制面
    'SymExecOptimizer',
    'create_optimizer',
    'DEFAULT_CONFIG',
    # Re-exported symexec_opt_passes（向后兼容）
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
