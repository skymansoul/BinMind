#!/usr/bin/env python3
"""
符号执行约束求解缓存与路径剪枝优化模块

功能：
1. 约束求解结果缓存（避免重复求解）
2. 路径剪枝策略（减少探索空间）
3. 求解超时控制
4. 并行求解支持
5. 约束简化与优化
6. 与现有 symbolic_exe 模块集成

依赖：angr（可选）、z3-solver（可选）
"""

import os
import re
import logging
import hashlib
import pickle
import tempfile
import threading
import time
from typing import Dict, Any, List, Optional, Tuple, Set, Union
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, Future, TimeoutError
from functools import lru_cache

logger = logging.getLogger(__name__)

# angr 可用性检查
ANGR_AVAILABLE = False
try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
    logger.info("angr 已加载，符号执行优化功能可用")
except ImportError:
    logger.warning("angr 未安装，符号执行优化受限。安装: pip install angr")

# Z3 可用性检查
Z3_AVAILABLE = False
try:
    import z3
    Z3_AVAILABLE = True
    logger.info("Z3 solver 已加载")
except ImportError:
    logger.warning("Z3 未安装。安装: pip install z3-solver")


# ==================== 常量定义 ====================

class PruningStrategy(Enum):
    """路径剪枝策略"""
    NONE = 'none'
    UNSAT_EARLY = 'unsat_early'  # 早期不可达剪枝
    LOOP_BOUND = 'loop_bound'    # 循环边界剪枝
    SIMILAR_STATE = 'similar_state'  # 相似状态剪枝
    COVERAGE_GUIDED = 'coverage_guided'  # 覆盖率引导剪枝
    HEURISTIC = 'heuristic'      # 启发式剪枝
    ALL = 'all'                  # 所有策略


class CachePolicy(Enum):
    """缓存策略"""
    NONE = 'none'
    MEMORY = 'memory'            # 内存缓存
    DISK = 'disk'                # 磁盘缓存
    HYBRID = 'hybrid'            # 混合缓存


# 默认配置
DEFAULT_CONFIG = {
    'cache_enabled': True,
    'cache_policy': CachePolicy.HYBRID,
    'cache_max_size': 10000,
    'cache_ttl': 3600,           # 1小时
    'pruning_strategy': PruningStrategy.ALL,
    'loop_bound': 5,
    'max_paths': 1000,
    'solver_timeout': 30,
    'parallel_solvers': 4,
    'simplify_constraints': True,
}


@dataclass
class ConstraintCacheEntry:
    """约束缓存条目"""
    constraint_hash: str = ''
    result: Optional[Any] = None
    is_satisfiable: bool = False
    solution: Optional[Dict[str, Any]] = None
    timestamp: float = 0.0
    hit_count: int = 0
    solve_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PathInfo:
    """路径信息"""
    path_id: str = ''
    address: int = 0
    constraints: List[Any] = field(default_factory=list)
    constraint_hash: str = ''
    is_active: bool = True
    is_pruned: bool = False
    prune_reason: str = ''
    depth: int = 0
    visited_addresses: Set[int] = field(default_factory=set)
    loop_counts: Dict[int, int] = field(default_factory=dict)
    similarity_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OptimizationStats:
    """优化统计"""
    total_paths_explored: int = 0
    paths_pruned: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    solver_calls: int = 0
    solver_time_saved: float = 0.0
    total_solve_time: float = 0.0
    pruning_by_strategy: Dict[str, int] = field(default_factory=dict)


class ConstraintSolverCache:
    """
    约束求解缓存
    
    功能：
    - 缓存求解结果避免重复计算
    - 支持内存和磁盘缓存
    - 哈希约束快速查找
    - TTL 过期机制
    
    Attributes:
        cache_policy: 缓存策略
        max_size: 最大缓存大小
        ttl: 缓存过期时间
    """
    
    def __init__(
        self,
        cache_policy: CachePolicy = CachePolicy.HYBRID,
        max_size: int = 10000,
        ttl: int = 3600,
        cache_dir: Optional[str] = None
    ):
        """
        初始化约束求解缓存
        
        Args:
            cache_policy: 缓存策略
            max_size: 最大缓存条目数
            ttl: 缓存过期时间（秒）
            cache_dir: 磁盘缓存目录
        """
        self.cache_policy = cache_policy
        self.max_size = max_size
        self.ttl = ttl
        self.cache_dir = cache_dir or tempfile.mkdtemp(prefix='solver_cache_')
        
        self.memory_cache: Dict[str, ConstraintCacheEntry] = {}
        self.stats: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
        
        # 初始化磁盘缓存
        if cache_policy in [CachePolicy.DISK, CachePolicy.HYBRID]:
            os.makedirs(self.cache_dir, exist_ok=True)
        
        logger.info(f"[SolverCache] 初始化缓存，策略: {cache_policy}, 最大: {max_size}")
    
    def hash_constraints(self, constraints: List[Any]) -> str:
        """
        计算约束的哈希值
        
        Args:
            constraints: 约束列表
            
        Returns:
            哈希字符串
        """
        try:
            # 将约束转换为可哈希的字符串
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
            logger.warning(f"[SolverCache] 哈希计算失败: {e}")
            return hashlib.sha256(str(constraints).encode()).hexdigest()[:16]
    
    def get(self, constraint_hash: str) -> Optional[ConstraintCacheEntry]:
        """
        从缓存获取结果
        
        Args:
            constraint_hash: 约束哈希
            
        Returns:
            缓存条目或 None
        """
        with self._lock:
            # 检查内存缓存
            if constraint_hash in self.memory_cache:
                entry = self.memory_cache[constraint_hash]
                
                # 检查 TTL
                if time.time() - entry.timestamp > self.ttl:
                    self._evict(constraint_hash)
                    self.stats['cache_misses'] += 1
                    return None
                
                entry.hit_count += 1
                self.stats['cache_hits'] += 1
                return entry
            
            # 检查磁盘缓存
            if self.cache_policy in [CachePolicy.DISK, CachePolicy.HYBRID]:
                entry = self._load_from_disk(constraint_hash)
                if entry:
                    # 检查 TTL
                    if time.time() - entry.timestamp > self.ttl:
                        self._delete_from_disk(constraint_hash)
                        self.stats['cache_misses'] += 1
                        return None
                    
                    # 加载到内存缓存
                    self.memory_cache[constraint_hash] = entry
                    entry.hit_count += 1
                    self.stats['cache_hits'] += 1
                    return entry
            
            self.stats['cache_misses'] += 1
            return None
    
    def put(
        self,
        constraint_hash: str,
        result: Any,
        is_satisfiable: bool,
        solution: Optional[Dict[str, Any]] = None,
        solve_time: float = 0.0
    ) -> None:
        """
        将结果存入缓存
        
        Args:
            constraint_hash: 约束哈希
            result: 求解结果
            is_satisfiable: 是否可满足
            solution: 解（可选）
            solve_time: 求解时间
        """
        entry = ConstraintCacheEntry(
            constraint_hash=constraint_hash,
            result=result,
            is_satisfiable=is_satisfiable,
            solution=solution,
            timestamp=time.time(),
            solve_time=solve_time
        )
        
        with self._lock:
            # 检查容量
            if len(self.memory_cache) >= self.max_size:
                self._evict_lru()
            
            # 存入内存缓存
            self.memory_cache[constraint_hash] = entry
            
            # 存入磁盘缓存
            if self.cache_policy in [CachePolicy.DISK, CachePolicy.HYBRID]:
                self._save_to_disk(constraint_hash, entry)
            
            self.stats['cache_puts'] += 1
    
    def _evict_lru(self) -> None:
        """
        淘汰最近最少使用的缓存条目
        """
        if not self.memory_cache:
            return
        
        # 找到 hit_count 最小的条目
        min_hash = min(
            self.memory_cache.keys(),
            key=lambda h: self.memory_cache[h].hit_count
        )
        
        self._evict(min_hash)
    
    def _evict(self, constraint_hash: str) -> None:
        """
        淘汰指定缓存条目
        
        Args:
            constraint_hash: 约束哈希
        """
        if constraint_hash in self.memory_cache:
            del self.memory_cache[constraint_hash]
        
        if self.cache_policy in [CachePolicy.DISK, CachePolicy.HYBRID]:
            self._delete_from_disk(constraint_hash)
    
    def _save_to_disk(self, constraint_hash: str, entry: ConstraintCacheEntry) -> None:
        """
        保存到磁盘
        
        Args:
            constraint_hash: 约束哈希
            entry: 缓存条目
        """
        try:
            path = os.path.join(self.cache_dir, f'{constraint_hash}.cache')
            with open(path, 'wb') as f:
                pickle.dump(entry, f)
        except Exception as e:
            logger.warning(f"[SolverCache] 磁盘保存失败: {e}")
    
    def _load_from_disk(self, constraint_hash: str) -> Optional[ConstraintCacheEntry]:
        """
        从磁盘加载
        
        Args:
            constraint_hash: 约束哈希
            
        Returns:
            缓存条目或 None
        """
        try:
            path = os.path.join(self.cache_dir, f'{constraint_hash}.cache')
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    return pickle.load(f)
        except Exception as e:
            logger.warning(f"[SolverCache] 磁盘加载失败: {e}")
        
        return None
    
    def _delete_from_disk(self, constraint_hash: str) -> None:
        """
        从磁盘删除
        
        Args:
            constraint_hash: 约束哈希
        """
        try:
            path = os.path.join(self.cache_dir, f'{constraint_hash}.cache')
            if os.path.exists(path):
                os.remove(path)
        except Exception as e:
            logger.warning(f"[SolverCache] 磁盘删除失败: {e}")
    
    def clear(self) -> None:
        """
        清空缓存
        """
        with self._lock:
            self.memory_cache.clear()
            
            if self.cache_policy in [CachePolicy.DISK, CachePolicy.HYBRID]:
                for f in os.listdir(self.cache_dir):
                    if f.endswith('.cache'):
                        os.remove(os.path.join(self.cache_dir, f))
    
    def get_stats(self) -> Dict[str, Any]:
        """
        获取缓存统计
        
        Returns:
            统计字典
        """
        return {
            'memory_cache_size': len(self.memory_cache),
            'hits': self.stats['cache_hits'],
            'misses': self.stats['cache_misses'],
            'puts': self.stats['cache_puts'],
            'hit_rate': self.stats['cache_hits'] / (self.stats['cache_hits'] + self.stats['cache_misses'] + 1)
        }


class PathPruner:
    """
    路径剪枝器
    
    功能：
    - 早期不可达剪枝
    - 循环边界剪枝
    - 相似状态剪枝
    - 覆盖率引导剪枝
    
    Attributes:
        strategy: 剪枝策略
        loop_bound: 循环边界
        max_paths: 最大路径数
    """
    
    def __init__(
        self,
        strategy: PruningStrategy = PruningStrategy.ALL,
        loop_bound: int = 5,
        max_paths: int = 1000,
        similarity_threshold: float = 0.9
    ):
        """
        初始化路径剪枝器
        
        Args:
            strategy: 剪枝策略
            loop_bound: 循环迭代上限
            max_paths: 最大探索路径数
            similarity_threshold: 相似状态阈值
        """
        self.strategy = strategy
        self.loop_bound = loop_bound
        self.max_paths = max_paths
        self.similarity_threshold = similarity_threshold
        
        self.active_paths: Dict[str, PathInfo] = {}
        self.visited_states: Dict[str, int] = defaultdict(int)
        self.coverage: Set[int] = set()
        
        self.stats: OptimizationStats = OptimizationStats()
        
        logger.info(f"[PathPruner] 初始化剪枝器，策略: {strategy}")
    
    def should_prune(self, path: PathInfo) -> Tuple[bool, str]:
        """
        判断路径是否应该剪枝
        
        Args:
            path: 路径信息
            
        Returns:
            (是否剪枝, 剪枝原因)
        """
        if self.strategy == PruningStrategy.NONE:
            return False, ''
        
        # 路径数量限制
        if len(self.active_paths) >= self.max_paths:
            return True, 'max_paths_limit'
        
        # 循环边界剪枝
        if self.strategy in [PruningStrategy.LOOP_BOUND, PruningStrategy.ALL]:
            for addr, count in path.loop_counts.items():
                if count >= self.loop_bound:
                    self.stats.pruning_by_strategy['loop_bound'] += 1
                    return True, f'loop_bound exceeded at {hex(addr)}'
        
        # 相似状态剪枝
        if self.strategy in [PruningStrategy.SIMILAR_STATE, PruningStrategy.ALL]:
            state_hash = self._hash_path_state(path)
            if self.visited_states[state_hash] >= 3:
                self.stats.pruning_by_strategy['similar_state'] += 1
                return True, 'similar_state'
        
        # 覆盖率引导剪枝
        if self.strategy in [PruningStrategy.COVERAGE_GUIDED, PruningStrategy.ALL]:
            new_coverage = len(path.visited_addresses - self.coverage)
            if new_coverage == 0 and path.depth > 10:
                self.stats.pruning_by_strategy['coverage_guided'] += 1
                return True, 'no_new_coverage'
        
        return False, ''
    
    def register_path(self, path: PathInfo) -> None:
        """
        注册新路径
        
        Args:
            path: 路径信息
        """
        self.active_paths[path.path_id] = path
        
        # 更新覆盖率
        self.coverage.update(path.visited_addresses)
        
        # 更新状态计数
        state_hash = self._hash_path_state(path)
        self.visited_states[state_hash] += 1
    
    def prune_path(self, path_id: str, reason: str) -> None:
        """
        剪枝指定路径
        
        Args:
            path_id: 路径 ID
            reason: 剪枝原因
        """
        if path_id in self.active_paths:
            path = self.active_paths[path_id]
            path.is_active = False
            path.is_pruned = True
            path.prune_reason = reason
            
            self.stats.paths_pruned += 1
            del self.active_paths[path_id]
            
            logger.debug(f"[PathPruner] 剪枝路径 {path_id}: {reason}")
    
    def _hash_path_state(self, path: PathInfo) -> str:
        """
        计算路径状态的哈希
        
        Args:
            path: 路径信息
            
        Returns:
            状态哈希
        """
        # 使用最近访问的地址序列作为状态特征
        recent = list(path.visited_addresses)[-10:]
        return hashlib.md5(str(sorted(recent)).encode()).hexdigest()[:8]
    
    def get_stats(self) -> OptimizationStats:
        """
        获取优化统计
        
        Returns:
            OptimizationStats
        """
        self.stats.total_paths_explored = len(self.active_paths) + self.stats.paths_pruned
        return self.stats


class ConstraintSimplifier:
    """
    约束简化器
    
    功能：
    - 简化复杂约束
    - 消除冗余约束
    - 提取关键约束
    """
    
    def __init__(self):
        """
        初始化约束简化器
        """
        self.simplify_stats: Dict[str, int] = defaultdict(int)
    
    def simplify(self, constraints: List[Any]) -> List[Any]:
        """
        简化约束列表
        
        Args:
            constraints: 原始约束
            
        Returns:
            简化后的约束
        """
        if not constraints:
            return constraints
        
        simplified = []
        
        # 1. 消除重复约束
        unique = self._remove_duplicates(constraints)
        self.simplify_stats['duplicates_removed'] += len(constraints) - len(unique)
        
        # 2. 简化算术约束
        for c in unique:
            simplified_c = self._simplify_arithmetic(c)
            if simplified_c:
                simplified.append(simplified_c)
        
        # 3. 消除矛盾约束（如果可用）
        if Z3_AVAILABLE:
            simplified = self._remove_contradictions(simplified)
        
        self.simplify_stats['total_simplified'] += 1
        
        return simplified
    
    def _remove_duplicates(self, constraints: List[Any]) -> List[Any]:
        """
        消除重复约束
        
        Args:
            constraints: 约束列表
            
        Returns:
            唯一约束列表
        """
        seen = set()
        unique = []
        
        for c in constraints:
            c_str = str(c)
            if c_str not in seen:
                seen.add(c_str)
                unique.append(c)
        
        return unique
    
    def _simplify_arithmetic(self, constraint: Any) -> Optional[Any]:
        """
        简化算术约束
        
        Args:
            constraint: 约束
            
        Returns:
            简化后的约束
        """
        # 基于字符串的简化
        c_str = str(constraint)
        
        # 简化恒等式
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
        
        # 如果有 Z3，使用 Z3 简化
        if Z3_AVAILABLE and isinstance(constraint, z3.BoolRef):
            try:
                return z3.simplify(constraint)
            except:
                pass
        
        return constraint
    
    def _remove_contradictions(self, constraints: List[Any]) -> List[Any]:
        """
        消除矛盾约束
        
        Args:
            constraints: 约束列表
            
        Returns:
            无矛盾的约束列表
        """
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
            logger.warning(f"[Simplifier] 矛盾检测失败: {e}")
            return constraints


class ParallelSolver:
    """
    并行求解器
    
    功能：
    - 并行执行多个求解任务
    - 超时控制
    - 结果汇总
    """
    
    def __init__(
        self,
        max_workers: int = 4,
        timeout: float = 30.0,
        cache: Optional[ConstraintSolverCache] = None
    ):
        """
        初始化并行求解器
        
        Args:
            max_workers: 最大并行数
            timeout: 单个求解超时
            cache: 约束缓存
        """
        self.max_workers = max_workers
        self.timeout = timeout
        self.cache = cache or ConstraintSolverCache()
        
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.stats: Dict[str, Any] = defaultdict(float)
    
    def solve_batch(
        self,
        constraint_sets: List[List[Any]]
    ) -> List[Optional[Dict[str, Any]]]:
        """
        并行求解多个约束集
        
        Args:
            constraint_sets: 约束集列表
            
        Returns:
            求解结果列表
        """
        futures: Dict[Future, int] = {}
        
        for i, constraints in enumerate(constraint_sets):
            future = self.executor.submit(
                self._solve_with_cache,
                constraints
            )
            futures[future] = i
        
        results = [None] * len(constraint_sets)
        
        for future in as_completed(futures, timeout=self.timeout * len(constraint_sets)):
            idx = futures[future]
            try:
                result = future.result(timeout=self.timeout)
                results[idx] = result
            except TimeoutError:
                logger.warning(f"[ParallelSolver] 求解超时: index {idx}")
                results[idx] = {'satisfiable': False, 'error': 'timeout'}
            except Exception as e:
                logger.warning(f"[ParallelSolver] 求解失败: index {idx} - {e}")
                results[idx] = {'satisfiable': False, 'error': str(e)}
        
        return results
    
    def _solve_with_cache(self, constraints: List[Any]) -> Optional[Dict[str, Any]]:
        """
        使用缓存求解
        
        Args:
            constraints: 约束列表
            
        Returns:
            求解结果
        """
        # 计算哈希
        constraint_hash = self.cache.hash_constraints(constraints)
        
        # 检查缓存
        cached = self.cache.get(constraint_hash)
        if cached:
            self.stats['time_saved'] += cached.solve_time
            return {
                'satisfiable': cached.is_satisfiable,
                'solution': cached.solution,
                'cached': True
            }
        
        # 求解
        start_time = time.time()
        
        if Z3_AVAILABLE:
            result = self._solve_z3(constraints)
        elif ANGR_AVAILABLE:
            result = self._solve_claripy(constraints)
        else:
            result = {'satisfiable': False, 'error': 'no_solver'}
        
        solve_time = time.time() - start_time
        
        # 存入缓存
        self.cache.put(
            constraint_hash,
            result,
            result.get('satisfiable', False),
            result.get('solution'),
            solve_time
        )
        
        self.stats['total_solve_time'] += solve_time
        
        return result
    
    def _solve_z3(self, constraints: List[Any]) -> Dict[str, Any]:
        """
        使用 Z3 求解
        
        Args:
            constraints: 约束列表
            
        Returns:
            求解结果
        """
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
        """
        使用 claripy 求解
        
        Args:
            constraints: 约束列表
            
        Returns:
            求解结果
        """
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
        """
        关闭求解器
        """
        self.executor.shutdown(wait=True)


class SymExecOptimizer:
    """
    符号执行优化器
    
    集成缓存、剪枝、简化功能
    
    Attributes:
        cache: 约束缓存
        pruner: 路径剪枝器
        simplifier: 约束简化器
        parallel_solver: 并行求解器
    """
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        初始化符号执行优化器
        
        Args:
            config: 配置字典
        """
        self.config = config or DEFAULT_CONFIG
        
        # 初始化组件
        self.cache = ConstraintSolverCache(
            cache_policy=self.config.get('cache_policy', CachePolicy.HYBRID),
            max_size=self.config.get('cache_max_size', 10000),
            ttl=self.config.get('cache_ttl', 3600)
        )
        
        self.pruner = PathPruner(
            strategy=self.config.get('pruning_strategy', PruningStrategy.ALL),
            loop_bound=self.config.get('loop_bound', 5),
            max_paths=self.config.get('max_paths', 1000)
        )
        
        self.simplifier = ConstraintSimplifier()
        
        self.parallel_solver = ParallelSolver(
            max_workers=self.config.get('parallel_solvers', 4),
            timeout=self.config.get('solver_timeout', 30),
            cache=self.cache
        )
        
        logger.info("[SymExecOptimizer] 符号执行优化器初始化完成")
    
    def optimize_solve(
        self,
        constraints: List[Any]
    ) -> Optional[Dict[str, Any]]:
        """
        优化求解
        
        Args:
            constraints: 约束列表
            
        Returns:
            求解结果
        """
        # 1. 简化约束
        if self.config.get('simplify_constraints', True):
            constraints = self.simplifier.simplify(constraints)
        
        # 2. 使用缓存求解
        return self.parallel_solver._solve_with_cache(constraints)
    
    def should_prune_path(self, path_info: PathInfo) -> Tuple[bool, str]:
        """
        判断是否剪枝路径
        
        Args:
            path_info: 路径信息
            
        Returns:
            (是否剪枝, 原因)
        """
        return self.pruner.should_prune(path_info)
    
    def get_optimization_stats(self) -> Dict[str, Any]:
        """
        获取优化统计
        
        Returns:
            统计字典
        """
        return {
            'cache': self.cache.get_stats(),
            'pruning': self.pruner.get_stats().__dict__,
            'simplification': dict(self.simplifier.simplify_stats),
            'solver': dict(self.parallel_solver.stats)
        }
    
    def cleanup(self) -> None:
        """
        清理资源
        """
        self.cache.clear()
        self.parallel_solver.shutdown()


def create_optimizer(config: Optional[Dict[str, Any]] = None) -> SymExecOptimizer:
    """
    创建符号执行优化器的便捷函数
    
    Args:
        config: 配置字典
        
    Returns:
        SymExecOptimizer
    """
    return SymExecOptimizer(config)


# ==================== 导出 ====================

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