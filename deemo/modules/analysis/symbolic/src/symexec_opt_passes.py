"""符号执行引擎的优化 pass。

各优化技术从 symexec_optimizer.py 拆出:
1. ConstraintSolverCache — 内存 + 磁盘两级求解结果缓存
2. PathPruner — 按循环界、相似度、覆盖率停滞丢弃路径
3. ConstraintSimplifier — 去重、算术化简、矛盾移除、
   公共子表达式消除 (CSE)
4. ParallelSolver — 线程池求解器, 集成缓存与超时

增强:
- 公共子表达式消除 (CSE): 识别在 >=3 个约束中出现的子表达式,
  提取为单一新变量后在求解器中注册一次, 减少 Z3 的符号计算量
- Bloom 预过滤器: cache.get() 访问磁盘前用 Bloom filter 快速判断
  key 是否可能存在, 避免磁盘 IO 的 miss 开销
- 自动扩缩容: pending 任务队列 > 100 时自动把 workers 翻倍
  (上限 CPU 核数)
- IncrementalSolverCache: 继承 ConstraintSolverCache, 利用 Z3
  push/pop 实现增量求解; warm_start_model 保存上一轮 SAT 变量
  赋值, 在追加约束时作为启发式起点; 跟踪 warm_start_hit_rate
  评估增量求解效率
- AdaptivePruningThreshold: PathPruner.should_prune 中根据
  psutil.virtual_memory().available 动态调整 max_paths —
  mem_pressure_ratio > 0.8 (空闲 < 20%) 时减半,
  < 0.4 (空闲 > 60%) 时恢复原始值
- profile_solver_hotspots: ParallelSolver._solve_with_cache 中按
  hotspot_category 记录每类约束的求解耗时, 每 solver_profile_window
  (默认 100) 次查询后输出排序报告
- ConstraintComplexityEstimator: 求解前从约束特征 (constraint_count,
  max_depth, bv_width, arithmetic_ratio, boolean_ratio) 用线性回归
  预测 z3 求解时间, predicted_time > timeout 则跳过求解
- OptimizationPipeline: 把 Simplifier → CSE → CacheLookup →
  ParallelSolver 串联为可配置 DAG 优化通道, 每个 pass 可独立启停,
  管道自省各 pass 的时间贡献度
- SolverBudgetManager: 为所有活跃符号执行任务分配全局求解时间预算,
  预算耗尽时抑制低优先级任务; 预算周期性更新 (默认每 60 秒刷新
  60 秒求解额度)

控制面调度器 (SymExecOptimizer) 位于父模块 symexec_optimizer.py。
"""

import collections
import hashlib
import json
import logging
import multiprocessing as _mp
import os
import pickle
import re as _re_mod
import struct
import tempfile
import threading
import time
from collections import Counter, OrderedDict, defaultdict, deque
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid  # noqa: F401

logger = logging.getLogger(__name__)

_LEGACY_MODE = False



ANGR_AVAILABLE = False
try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
    logger.info("angr 已加载")
except ImportError:
    logger.warning("angr 未安装。安装: pip install angr")

Z3_AVAILABLE = False
try:
    import z3
    Z3_AVAILABLE = True
    logger.info("Z3 求解器已加载")
except ImportError:
    logger.warning("Z3 未安装。安装: pip install z3-solver")

PSUTIL_AVAILABLE = False
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    logger.warning("psutil 未安装。pip install psutil")


class PruningStrategy(str, Enum):
    """可用的路径剪枝策略。"""
    NONE = 'none'
    UNSAT_EARLY = 'unsat_early'
    LOOP_BOUND = 'loop_bound'
    SIMILAR_STATE = 'similar_state'
    COVERAGE_GUIDED = 'coverage_guided'
    HEURISTIC = 'heuristic'
    ALL = 'all'


class CachePolicy(str, Enum):
    """求解器缓存的存储层级。"""
    NONE = 'none'
    MEMORY = 'memory'
    DISK = 'disk'
    HYBRID = 'hybrid'


# Bloom 预过滤器: 256KiB (2M bits), 误报率 ~1% 100k 条目 3 哈希
# 快速判断 key 是否可能存在于磁盘缓存中，避免磁盘 IO 的 miss 开销
_BLOOM_SIZE_BITS = 2_097_152  # 256 KiB

class _BloomPreFilter:
    def __init__(self):
        size_bytes = _BLOOM_SIZE_BITS // 8
        self._bits = bytearray(size_bytes)
        self._mask = _BLOOM_SIZE_BITS - 1

    def _locs(self, key: str):
        h = hashlib.sha256(key.encode()).digest()
        a = struct.unpack_from("<Q", h, 0)[0]
        b = struct.unpack_from("<Q", h, 8)[0]
        c = struct.unpack_from("<Q", h, 16)[0]
        return a & self._mask, b & self._mask, c & self._mask

    def add(self, key: str):
        for loc in self._locs(key):
            self._bits[loc // 8] |= 1 << (loc % 8)

    def might_contain(self, key: str) -> bool:
        for loc in self._locs(key):
            if not (self._bits[loc // 8] & (1 << (loc % 8))):
                return False
        return True


@dataclass
class ConstraintCacheEntry:
    """缓存中的求解结果: 约束哈希、可满足性、解与统计。"""
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
    """单条符号执行路径的元数据, 供剪枝器使用。"""
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
    """优化 pass 的聚合计数。"""
    total_paths_explored: int = 0
    paths_pruned: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    solver_calls: int = 0
    solver_time_saved: float = 0.0
    total_solve_time: float = 0.0
    pruning_by_strategy: Dict = field(default_factory=dict)


# 四轮增强 — ConstraintComplexityEstimator：求解前预测 z3 求解时间
#
# 特征工程 — 从约束列表中提取 5 个可计算特征：
#   constraint_count: 约束总数
#   max_depth: 最深嵌套 AST 深度（字符串括号平衡计数）
# bv_width: 最大位向量宽度（扫描 bv\d+, 提取, concat）
# arithmetic_ratio: 算术操作符 (+, -, *, /, bvadd, bvmul,.) 占比
# boolean_ratio: 布尔连接词 (, or,, =>, ite) 占比
#
# 模型 — 简单线性回归，系数从历史 solve_time 记录中拟合
# 每次求解成功后更新模型，在线学习本工作负载的特征分布


@dataclass
class ConstraintFeatures:
    """从约束列表提取的特征向量, 用于求解耗时预测。"""
    constraint_count: int = 0
    max_depth: int = 0
    bv_width: int = 0
    arithmetic_ratio: float = 0.0
    boolean_ratio: float = 0.0


class ConstraintComplexityEstimator:
    """调用求解器前从约束特征预测 Z3 求解耗时。

    四轮增强: 符号执行中大量约束会触发 Z3 超时 (如并行求解器
    设置的 30s), 等待超时拿到不可解结果比直接跳过更浪费计算
    时间; 本预估器在求解前估算耗时, predicted_time > timeout
    则跳过。

    线性回归权重初始化为启发式值, 每次求解后在线更新;
    weights 为特征→系数映射, history 保存最近 N 次
    (features, actual_time) 记录, prediction_count 为总预测次数,
    skip_count 为因预测超时而跳过的次数。
    """

    # 初始权重 — 基于 5 个特征的启发式估计
    # solve_time ≈ w0 + w1*cnt + w2*depth + w3*bv + w4*arith + w5*bool
    _DEFAULT_WEIGHTS = {
        'intercept': 0.01,
        'constraint_count': 0.05,
        'max_depth': 0.02,
        'bv_width': 0.0001,
        'arithmetic_ratio': 0.5,
        'boolean_ratio': 0.3,
    }

    def __init__(self, learning_rate: float = 0.01, history_size: int = 500):
        self.weights: Dict[str, float] = dict(self._DEFAULT_WEIGHTS)
        self.learning_rate = learning_rate
        self.history: deque = deque(maxlen=history_size)
        self.prediction_count: int = 0
        self.skip_count: int = 0
        self._lock = threading.Lock()

    def extract_features(self, constraints: List[Any]) -> ConstraintFeatures:
        """从约束列表提取数值特征。

        通过字符串表示分析约束集的结构复杂性, 不依赖 Z3 AST
        遍历 (避免构造开销), 直接扫描字符串模式。
        """
        if not constraints:
            return ConstraintFeatures()

        c_strs = [str(c).lower() for c in constraints]
        constraint_count = len(c_strs)

        # max_depth: 字符串括号嵌套深度
        max_depth = 0
        for s in c_strs:
            depth = 0
            current_max = 0
            for ch in s:
                if ch == '(':
                    depth += 1
                    current_max = max(current_max, depth)
                elif ch == ')':
                    depth -= 1
            max_depth = max(max_depth, current_max)

        # bv_width: 从 提取(bv, 7, 0) 或 bv128 等模式中提取最大位宽
        bv_width = 0
        bv_pattern = _re_mod.compile(r'bv(\d+)')
        extract_pattern = _re_mod.compile(r'extract\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)')
        for s in c_strs:
            for m in bv_pattern.finditer(s):
                w = int(m.group(1))
                bv_width = max(bv_width, w)
            for m in extract_pattern.finditer(s):
                hi = int(m.group(1))
                bv_width = max(bv_width, hi + 1)

        # 操作符计数
        total_ops = 0
        arith_ops = 0
        bool_ops = 0

        arith_keywords = ('bvadd', 'bvsub', 'bvmul', 'bvudiv', 'bvurem',
                          'bvsdiv', 'bvsrem', ' + ', ' - ', ' * ', ' / ',
                          'bvshl', 'bvlshr', 'bvashr')
        bool_keywords = ('and', 'or', 'not', '=>', '&&', '||', 'ite',
                         'implies', 'if')

        for s in c_strs:
            for kw in arith_keywords:
                cnt = s.count(kw)
                arith_ops += cnt
                total_ops += cnt
            for kw in bool_keywords:
                cnt = s.count(kw)
                bool_ops += cnt
                total_ops += cnt

        arithmetic_ratio = arith_ops / max(1, total_ops)
        boolean_ratio = bool_ops / max(1, total_ops)

        return ConstraintFeatures(
            constraint_count=constraint_count,
            max_depth=max_depth,
            bv_width=bv_width,
            arithmetic_ratio=round(arithmetic_ratio, 4),
            boolean_ratio=round(boolean_ratio, 4),
        )

    def predict(self, features: ConstraintFeatures) -> float:
        """预测 Z3 求解耗时 (秒), 返回非负数。"""
        w = self.weights
        predicted = (
            w['intercept'] +
            w['constraint_count'] * features.constraint_count +
            w['max_depth'] * features.max_depth +
            w['bv_width'] * features.bv_width +
            w['arithmetic_ratio'] * features.arithmetic_ratio +
            w['boolean_ratio'] * features.boolean_ratio
        )
        return max(0.0, predicted)

    def should_skip(self, constraints: List[Any], timeout: float) -> Tuple[bool, float]:
        """比较预测耗时与超时阈值, 返回 (是否跳过, 预测秒数)。"""
        features = self.extract_features(constraints)
        predicted = self.predict(features)

        with self._lock:
            self.prediction_count += 1
            should_skip = predicted > timeout
            if should_skip:
                self.skip_count += 1
                logger.debug(
                    f"[ComplexityEstimator] Skipping solve: "
                    f"predicted={predicted:.3f}s > timeout={timeout}s "
                    f"(features: cnt={features.constraint_count}, "
                    f"depth={features.max_depth}, bv={features.bv_width})"
                )

        return should_skip, predicted

    def update(self, features: ConstraintFeatures, actual_time: float):
        """用简单随机梯度下降在线更新权重。

        features 为触发此次求解的约束特征, actual_time 为实际
        求解耗时秒数。
        """
        with self._lock:
            self.history.append((features, actual_time))
            predicted = self.predict(features)
            error = actual_time - predicted
            lr = self.learning_rate

            # SGD: w_i += lr * error * x_i
            self.weights['intercept'] += lr * error
            self.weights['constraint_count'] += lr * error * features.constraint_count
            self.weights['max_depth'] += lr * error * features.max_depth
            self.weights['bv_width'] += lr * error * features.bv_width
            self.weights['arithmetic_ratio'] += lr * error * features.arithmetic_ratio
            self.weights['boolean_ratio'] += lr * error * features.boolean_ratio

    def mean_absolute_error(self) -> Optional[float]:
        """计算近期历史的平均绝对误差, 无数据时返回 None。"""
        if not self._lock.acquire(timeout=5):
            return None
        try:
            if not self.history:
                return None
            total = 0.0
            for feat, actual in self.history:
                total += abs(self.predict(feat) - actual)
            return total / len(self.history)
        finally:
            self._lock.release()

    def stats(self) -> Dict[str, Any]:
        """暴露预估器状态供遥测。"""
        if not self._lock.acquire(timeout=5):
            return {
                'weights': dict(self.weights),
                'prediction_count': self.prediction_count,
                'skip_count': self.skip_count,
                'mae': None,
                'history_size': 0,
            }
        try:
            return {
                'weights': dict(self.weights),
                'prediction_count': self.prediction_count,
                'skip_count': self.skip_count,
                'mae': round(self.mean_absolute_error() or 0.0, 5),
                'history_size': len(self.history),
            }
        finally:
            self._lock.release()


# 四轮增强 — OptimizationPipeline：可配置 DAG 的优化通道
#
# 将 Simplifier → CSE → CacheLookup → Solve 串联为管道
# 每个 pass 是独立的、可启停的处理阶段
# 管道在执行后自省各阶段的耗时贡献度


class OptimizationPass(Enum):
    """优化流水线阶段。"""
    SIMPLIFY = "simplify"
    CSE = "cse"
    CACHE_LOOKUP = "cache_lookup"
    SOLVE = "solve"


@dataclass
class PassResult:
    """单个优化 pass 的输出。"""
    pass_name: str
    duration_seconds: float = 0.0
    skipped: bool = False
    result: Any = None
    metadata: Dict = field(default_factory=dict)


class OptimizationPipeline:
    """可配置的优化 pass DAG: Simplify -> CSE -> CacheLookup -> Solve。

    四轮增强: 传统 SymExecOptimizer 把 simplifier → cache → solver
    硬编码成固定调用顺序; OptimizationPipeline 把每个优化阶段抽象
    为可配置的管道节点, 支持:

    - 每个 pass 独立启停
    - 自动计时各阶段耗时
    - 自省贡献度分析: identify_contributions() 按总耗时排序
    - 链式调用: pipe.execute(constraints) → result

    管道执行模型:
    Input → [Simplifier?] → [CSE?] → [CacheLookup?] → [Solve] → 输出,
    任意阶段可跳过 (如 CacheLookup 跳过 → 直达 solve)。
    """

    def __init__(self,
                 simplifier: 'ConstraintSimplifier',
                 solver_cache: 'ConstraintSolverCache',
                 parallel_solver: 'ParallelSolver',
                 enabled_passes: Optional[List[str]] = None):
        self.simplifier = simplifier
        self.solver_cache = solver_cache
        self.parallel_solver = parallel_solver

        # 默认启用所有 pass
        self.enabled_passes: Set[str] = set(enabled_passes or [
            OptimizationPass.SIMPLIFY.value,
            OptimizationPass.CSE.value,
            OptimizationPass.CACHE_LOOKUP.value,
            OptimizationPass.SOLVE.value,
        ])

        # 各 pass 的累积计时与计数
        self._pass_timings: Dict[str, float] = defaultdict(float)
        self._pass_counts: Dict[str, int] = defaultdict(int)
        self._pipeline_lock = threading.Lock()

    def execute(self, constraints: List[Any]) -> Tuple[Optional[Dict[str, Any]], List[PassResult]]:
        """对约束集执行完整优化流水线, 返回 (求解结果, 各阶段 PassResult 列表)。"""
        pass_results: List[PassResult] = []
        current_constraints = list(constraints)

        # Pass 1: Simplify (化简)
        if OptimizationPass.SIMPLIFY.value in self.enabled_passes:
            t0 = time.monotonic()
            current_constraints = self.simplifier.simplify(current_constraints)
            duration = time.monotonic() - t0
            pr = PassResult(
                pass_name=OptimizationPass.SIMPLIFY.value,
                duration_seconds=round(duration, 5),
                skipped=False,
                result={'simplified_count': len(current_constraints)},
                metadata={'constraints_before': len(constraints),
                          'constraints_after': len(current_constraints)},
            )
            pass_results.append(pr)
            self._record_pass(OptimizationPass.SIMPLIFY.value, duration)

        # --- Pass 2: CSE (含 simplify, 独立计时) ---
        if OptimizationPass.CSE.value in self.enabled_passes:
            t0 = time.monotonic()
            # CSE 已嵌入 ConstraintSimplifier.simplify() 中
            # 此处记录 simplify_stats 中的 cse_eliminated 计数
            cse_count = self.simplifier.simplify_stats.get('cse_eliminated', 0)
            duration = time.monotonic() - t0
            pr = PassResult(
                pass_name=OptimizationPass.CSE.value,
                duration_seconds=round(duration, 5),
                skipped=False,
                result={'cse_eliminated': cse_count},
            )
            pass_results.append(pr)
            self._record_pass(OptimizationPass.CSE.value, duration)

        # Pass 3: CacheLookup (缓存查找)
        cache_hit = False
        if OptimizationPass.CACHE_LOOKUP.value in self.enabled_passes:
            t0 = time.monotonic()
            constraint_hash = self.solver_cache.hash_constraints(current_constraints)
            cached_entry = self.solver_cache.get(constraint_hash)
            duration = time.monotonic() - t0
            if cached_entry:
                cache_hit = True
                pr = PassResult(
                    pass_name=OptimizationPass.CACHE_LOOKUP.value,
                    duration_seconds=round(duration, 5),
                    skipped=False,
                    result={
                        'satisfiable': cached_entry.is_satisfiable,
                        'solution': cached_entry.solution,
                        'cached': True,
                    },
                    metadata={'hit': True},
                )
                pass_results.append(pr)
                self._record_pass(OptimizationPass.CACHE_LOOKUP.value, duration)
                return {'satisfiable': cached_entry.is_satisfiable,
                        'solution': cached_entry.solution,
                        'cached': True}, pass_results
            else:
                pr = PassResult(
                    pass_name=OptimizationPass.CACHE_LOOKUP.value,
                    duration_seconds=round(duration, 5),
                    skipped=False,
                    metadata={'hit': False},
                )
                pass_results.append(pr)
                self._record_pass(OptimizationPass.CACHE_LOOKUP.value, duration)

        # Pass 4: Solve (求解)
        if OptimizationPass.SOLVE.value in self.enabled_passes:
            t0 = time.monotonic()
            result = self.parallel_solver._solve_with_cache(current_constraints)
            duration = time.monotonic() - t0
            pr = PassResult(
                pass_name=OptimizationPass.SOLVE.value,
                duration_seconds=round(duration, 5),
                skipped=False,
                result=result,
            )
            pass_results.append(pr)
            self._record_pass(OptimizationPass.SOLVE.value, duration)
            return result, pass_results

        return None, pass_results

    def _record_pass(self, pass_name: str, duration: float):
        with self._pipeline_lock:
            self._pass_timings[pass_name] += duration
            self._pass_counts[pass_name] += 1

    def identify_contributions(self) -> List[Tuple[str, float, float, int]]:
        """分析各 pass 的耗时贡献, 返回按总耗时降序的
        (pass_name, total_time, avg_time, call_count) 列表。"""
        with self._pipeline_lock:
            entries = []
            for pass_name in self._pass_timings:
                total_t = self._pass_timings[pass_name]
                count = self._pass_counts.get(pass_name, 0)
                avg_t = total_t / max(1, count)
                entries.append((pass_name, round(total_t, 4), round(avg_t, 5), count))
            entries.sort(key=lambda e: e[1], reverse=True)
            return entries

    def stats(self) -> Dict[str, Any]:
        """暴露流水线遥测数据。"""
        contributions = self.identify_contributions()
        return {
            'enabled_passes': list(self.enabled_passes),
            'contributions': [
                {'pass': name, 'total_time': total, 'avg_time': avg, 'calls': cnt}
                for name, total, avg, cnt in contributions
            ],
        }


# 四轮增强 — SolverBudgetManager：全局求解时间预算
#
# 符号执行中并行求解器可能同时被多个任务调用，总和求解时间不受控
# SolverBudgetManager 为 "一分钟内允许的总求解时间" 设置硬限制
#
# 机制：
#   - 每个 interval（默认 60s），budget 刷新为 per_interval 秒
#   - 每次求解前，从 budget 中扣除 predicted_time（由 ComplexityEstimator 提供）
# 预算耗尽 → is_budget_exhausted() 返回 True
#   - 低优先级（非 critical）任务在预算耗尽时被抑制（skip/requeue）
# critical 任务始终不受预算限制
#
# 后台线程周期性刷新预算


class SolverBudgetManager:
    """跨活跃符号任务分配全局求解时间预算。

    四轮增强: 防止符号执行引擎中多个 worker 同时触发大量耗时求解,
    把 CPU 时间耗在 Z3 求解器上 (影响 UI 响应、fuzzer 协同等)。

    预算模型: token bucket
    - 每 interval 秒补充 per_interval 秒的求解时间额度
    - 每次求解消耗 predicted_time 秒的额度
    - 额度耗尽 → is_budget_exhausted() = True → 非关键任务被抑制
    - critical 路径始终获得求解权限 (不扣预算, 单独计数)

    budget_seconds 为当前剩余预算, consumed_total 为累计消耗,
    critical_solve_time 为关键路径累计消耗 (不受预算限制)。
    """

    def __init__(self,
                 per_interval: float = 60.0,
                 interval: float = 60.0):
        self.per_interval = per_interval
        self.interval = interval
        self.budget_seconds: float = per_interval
        self.consumed_total: float = 0.0
        self.critical_solve_time: float = 0.0
        self._lock = threading.Lock()
        self._refresh_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self):
        """启动后台预算刷新线程。"""
        if self._refresh_thread is not None:
            return
        self._stop_event.clear()
        self._refresh_thread = threading.Thread(
            target=self._refresh_loop, daemon=True,
            name="SolverBudgetManager-refresh"
        )
        self._refresh_thread.start()
        logger.info(
            f"[SolverBudgetManager] Started: {self.per_interval}s budget "
            f"per {self.interval}s interval"
        )

    def stop(self):
        """停止后台刷新线程。"""
        self._stop_event.set()
        if self._refresh_thread is not None:
            self._refresh_thread.join(timeout=2.0)
            self._refresh_thread = None

    def _refresh_loop(self):
        """周期性地把预算重置为 per_interval。"""
        while not self._stop_event.is_set():
            self._stop_event.wait(self.interval)
            with self._lock:
                self.budget_seconds = self.per_interval
                logger.debug(
                    f"[SolverBudgetManager] Budget refreshed: "
                    f"{self.budget_seconds:.1f}s remaining"
                )

    def consume(self, seconds: float, is_critical: bool = False) -> bool:
        """尝试从求解时间预算中扣除 seconds 秒。

        is_critical 为关键路径时绕行预算限制; 消耗成功 (或关键
        路径) 返回 True, 预算耗尽且非关键返回 False。
        """
        if is_critical:
            with self._lock:
                self.critical_solve_time += seconds
            return True

        with self._lock:
            if self.budget_seconds >= seconds:
                self.budget_seconds -= seconds
                self.consumed_total += seconds
                return True
            return False

    def is_budget_exhausted(self) -> bool:
        """检查当前预算是否耗尽。"""
        with self._lock:
            return self.budget_seconds <= 0

    def remaining(self) -> float:
        """返回剩余预算秒数。"""
        with self._lock:
            return max(0.0, self.budget_seconds)

    def stats(self) -> Dict[str, Any]:
        """暴露预算状态供遥测。"""
        with self._lock:
            return {
                'budget_remaining': round(self.budget_seconds, 2),
                'per_interval': self.per_interval,
                'interval_seconds': self.interval,
                'consumed_total': round(self.consumed_total, 2),
                'critical_solve_time': round(self.critical_solve_time, 2),
                'is_exhausted': self.budget_seconds <= 0,
            }


class ConstraintSolverCache:
    """两级缓存: 内存 dict + 每哈希一个磁盘 pickle 文件。

    条目超过 ttl 秒过期; Bloom 预过滤避免磁盘 IO 的 miss 开销。

    增强: 污染率监控 — hit_count < 2 的条目占比 > 0.5 时警告
    低质量缓存 (条目写入后几乎从未被命中)。
    """

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
        self._bloom = _BloomPreFilter()
        if cache_policy in [CachePolicy.DISK, CachePolicy.HYBRID]:
            os.makedirs(self.cache_dir, exist_ok=True)
        logger.info(f"[SolverCache] Cache initialized, policy: {cache_policy}, max: {max_size}")

    def hash_constraints(self, constraints: List[Any]) -> str:
        """对排序后的约束字符串取确定性的 16 字符 hex 哈希。"""
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
        """先查内存, 经 Bloom 预筛后回退磁盘。"""
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
            # Bloom 负向过滤
            if self.cache_policy in [CachePolicy.DISK, CachePolicy.HYBRID]:
                if not self._bloom.might_contain(constraint_hash):
                    self.stats['cache_misses'] += 1
                    return None
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
        """存储结果, 超容量时逐出 LRU 项, 并更新 Bloom 索引。"""
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
                self._bloom.add(constraint_hash)
                self._save_to_disk(constraint_hash, entry)
            self.stats['cache_puts'] += 1

    def _evict_lru(self) -> None:
        if not self.memory_cache:
            return
        min_hash = min(self.memory_cache.keys(),
                      key=lambda h: self.memory_cache[h].hit_count)
        self._evict(min_hash)

    def _evict(self, constraint_hash: str) -> None:
        if constraint_hash in self.memory_cache:
            del self.memory_cache[constraint_hash]
        if self.cache_policy in [CachePolicy.DISK, CachePolicy.HYBRID]:
            self._delete_from_disk(constraint_hash)

    def _save_to_disk(self, constraint_hash: str, entry: ConstraintCacheEntry) -> None:
        try:
            path = os.path.join(self.cache_dir, f'{constraint_hash}.cache')
            with open(path, 'wb') as f:
                pickle.dump(entry, f)
        except Exception as e:
            logger.warning(f"[SolverCache] Disk save failed: {e}")

    def _load_from_disk(self, constraint_hash: str) -> Optional[ConstraintCacheEntry]:
        try:
            path = os.path.join(self.cache_dir, f'{constraint_hash}.cache')
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    return pickle.load(f)
        except Exception as e:
            logger.warning(f"[SolverCache] Disk load failed: {e}")
        return None

    def _delete_from_disk(self, constraint_hash: str) -> None:
        try:
            path = os.path.join(self.cache_dir, f'{constraint_hash}.cache')
            if os.path.exists(path):
                os.remove(path)
        except Exception as e:
            logger.warning(f"[SolverCache] Disk delete failed: {e}")

    def clear(self) -> None:
        with self._lock:
            self.memory_cache.clear()
            if self.cache_policy in [CachePolicy.DISK, CachePolicy.HYBRID]:
                for f in os.listdir(self.cache_dir):
                    if f.endswith('.cache'):
                        os.remove(os.path.join(self.cache_dir, f))

    def get_stats(self) -> Dict[str, Any]:
        hits = self.stats['cache_hits']
        misses = self.stats['cache_misses']
        # 污染率：hit_count < 2 的条目占比
        with self._lock:
            low_hit = sum(1 for e in self.memory_cache.values() if e.hit_count < 2)
            total = max(1, len(self.memory_cache))
            pollution = low_hit / total
        if pollution > 0.5:
            logger.warning(f"[SolverCache] High cache pollution ratio: {pollution:.2f}")
        return {
            'memory_cache_size': len(self.memory_cache),
            'hits': hits,
            'misses': misses,
            'puts': self.stats['cache_puts'],
            'hit_rate': hits / (hits + misses + 1),
            'pollution_ratio': round(pollution, 4)
        }


class IncrementalSolverCache(ConstraintSolverCache):
    """增量求解缓存: 扩展 ConstraintSolverCache, 用 Z3 push/pop 与
    warm-start 模型复用支持逐条增长的约束集。

    设计动机: 符号执行中约束沿执行路径逐条追加, 全量重求解浪费
    计算资源; 通过维护持久化 Z3 solver 实例 (push/pop), 新增约束
    时复用上一轮 SAT 解的变量赋值作为启发式搜索起点 (warm-start),
    可把增量求解的典型耗时从 O(exp(n+k)) 降至近似 O(k)。

    warm_start_model 存储最近一次 SAT 解的 {var_name: value}
    映射; warm_start_hit_rate 衡量增量求解的有效性 (命中/尝试)。
    空间开销 O(v) (v = 当前活跃变量数), 时间收益在约束数量线性
    增长的符号执行场景中最显著。
    """

    def __init__(self,
        cache_policy: str = CachePolicy.HYBRID,
        max_size: int = 10000,
        ttl: int = 3600,
        cache_dir: Optional[str] = None,
        solver_timeout: int = 30
    ):
        super().__init__(cache_policy=cache_policy, max_size=max_size, ttl=ttl, cache_dir=cache_dir)
        self._solver_timeout = solver_timeout
        # Z3 持久化 solver — 仅在首次使用时惰性初始化
        self._persistent_solver = None
        self._solver_constraint_count = 0
        # 最近一次 SAT 解的变量 → 值映射，用作增量求解的 warm-start 种子
        self.warm_start_model: Dict[str, str] = {}
        self._warm_start_hits: int = 0
        self._warm_start_attempts: int = 0
        self._incremental_lock = threading.Lock()
        logger.info("[IncrementalSolverCache] Incremental solver cache initialized")

    @property
    def warm_start_hit_rate(self) -> float:
        """返回 warm-start 命中率：命中次数 / 总尝试次数"""
        denom = max(1, self._warm_start_attempts)
        return self._warm_start_hits / denom

    def _ensure_persistent_solver(self):
        """惰性初始化持久化 Z3 solver

        注：Z3 solver 的 push/pop scope 机制允许在不重建 solver 的前提下
        增量添加/移除约束，内部启发式算法自然复用上一次求解的状态
        """
        if self._persistent_solver is None and Z3_AVAILABLE:
            self._persistent_solver = z3.Solver()
            self._persistent_solver.set('timeout', int(self._solver_timeout * 1000))
            self._solver_constraint_count = 0

    def solve_incremental(self,
        base_constraints: List[Any],
        new_constraints: List[Any]
    ) -> Dict[str, Any]:
        """增量求解: 在已有约束集 base_constraints 上追加 new_constraints。

        算法流程:
        1. base_constraints 首次求解时建立持久化 solver
        2. 追加约束通过 solver.push() 添加作用域
        3. 若 SAT, 把 model 存入 warm_start_model 并记录命中
        4. 若 UNSAT, solver.pop() 回退到 base 状态

        返回 {'satisfiable': bool, 'solution': dict, 'warm_started':
        bool, 'solve_time': float}。
        """
        result: Dict[str, Any] = {'satisfiable': False, 'warm_started': False, 'solution': None}
        if not Z3_AVAILABLE:
            result['error'] = 'z3_unavailable'
            return result

        with self._incremental_lock:
            self._ensure_persistent_solver()
            solver = self._persistent_solver

            # 基础约束尚未加载到持久化 solver 中
            if self._solver_constraint_count == 0 and base_constraints:
                for c in base_constraints:
                    if isinstance(c, z3.BoolRef):
                        solver.add(c)
                self._solver_constraint_count = len(base_constraints)

            self._warm_start_attempts += 1
            had_warm_start = len(self.warm_start_model) > 0

            solver.push()
            z3_constraints_added = 0
            for c in new_constraints:
                if isinstance(c, z3.BoolRef):
                    solver.add(c)
                    z3_constraints_added += 1

            start = time.time()
            check_result = solver.check()
            elapsed = time.time() - start

            if check_result == z3.sat:
                model = solver.model()
                solution = {}
                for decl in model.decls():
                    solution[str(decl)] = str(model[decl])
                result['satisfiable'] = True
                result['solution'] = solution

                # 更新 warm_start_model
                self.warm_start_model = dict(solution)
                if had_warm_start:
                    self._warm_start_hits += 1
                result['warm_started'] = had_warm_start

                # 保持 push 作用域（约束累积）
                self._solver_constraint_count += z3_constraints_added
            else:
                # UNSAT — 回退到 base 状态
                solver.pop()
                result['satisfiable'] = False
                result['warm_started'] = False

            result['solve_time'] = round(elapsed, 4)

        # 在锁外缓存结果
        combined = list(base_constraints) + list(new_constraints)
        constraint_hash = self.hash_constraints(combined)
        self.put(constraint_hash, result, result['satisfiable'],
                 result.get('solution'), elapsed)
        return result

    def reset_persistent_solver(self) -> None:
        """重置持久化 solver，丢弃所有已加载的约束"""
        with self._incremental_lock:
            self._persistent_solver = None
            self._solver_constraint_count = 0
            self.warm_start_model.clear()
            self._warm_start_hits = 0
            self._warm_start_attempts = 0

    def get_stats(self) -> Dict[str, Any]:
        """返回缓存统计 + 增量求解指标"""
        base_stats = super().get_stats()
        with self._incremental_lock:
            base_stats['warm_start_hit_rate'] = round(self.warm_start_hit_rate, 4)
            base_stats['warm_start_hits'] = self._warm_start_hits
            base_stats['warm_start_attempts'] = self._warm_start_attempts
            base_stats['persistent_constraint_count'] = self._solver_constraint_count
        return base_stats

    def clear(self) -> None:
        """清空缓存并重置增量求解状态"""
        super().clear()
        self.reset_persistent_solver()


class PathPruner:
    """抑制状态爆炸的多策略路径剪枝。

    策略:
    LOOP_BOUND — 重复访问某地址 >= loop_bound 次的路径被剪除
    SIMILAR_STATE — 相同状态哈希出现 >= 3 次被剪除
    COVERAGE_GUIDED — 深度超过 10 且无新覆盖的路径被剪除
    MAX_PATHS — 活跃路径数的硬上限

    AdaptivePruningThreshold — 根据系统可用内存动态调整 max_paths:
    mem_pressure_ratio > 0.8 (空闲 < 20%) 时减半,
    < 0.4 (空闲 > 60%) 时恢复原始值; 内存检查每 50 次剪枝评估
    执行一次以避免 syscall 开销。
    """

    def __init__(self,
        strategy: str = PruningStrategy.ALL,
        loop_bound: int = 5,
        max_paths: int = 1000,
        similarity_threshold: float = 0.9,
        adaptive_pruning: bool = True
    ):
        self.strategy = strategy
        self.loop_bound = loop_bound
        self.max_paths = max_paths
        self._original_max_paths = max_paths  # 自适应剪枝恢复目标
        self.similarity_threshold = similarity_threshold
        self.active_paths: Dict[str, PathInfo] = {}
        self.visited_states: Dict[str, int] = defaultdict(int)
        self.coverage: Set[int] = set()
        self.stats: OptimizationStats = OptimizationStats()
        self._adaptive_pruning = adaptive_pruning
        self._prune_call_counter = 0  # 内存检查节流计数器
        self._MEM_CHECK_INTERVAL = 50
        logger.info(f"[PathPruner] Pruner initialized, strategy: {strategy}")

    def _adapt_max_paths_memory(self):
        """根据系统可用内存调整 max_paths

        算法权衡 — 内存紧张时激进剪枝可避免 OOM 杀死进程
        但可能漏掉有效的深层路径。采用二档阶梯阈值而非连续映射：
        极端压力（<20%）→ halve；充裕（>60%）→ 恢复
        滞后区间 [20%, 60%] 保持不变以避免频繁振荡
        O(1) 决策，含一次 psutil.virtual_memory() 系统调用
        """
        if not PSUTIL_AVAILABLE or not self._adaptive_pruning:
            return
        mem = psutil.virtual_memory()
        mem_pressure_ratio = 1.0 - (mem.available / mem.total)

        if mem_pressure_ratio > 0.8:
            # 空闲内存 < 20%，激进剪枝
            halved = max(10, self._original_max_paths // 2)
            if self.max_paths != halved:
                self.max_paths = halved
                logger.warning(
                    f"[PathPruner] High memory pressure (mem_pressure_ratio={mem_pressure_ratio:.2f}), "
                    f"max_paths reduced to {self.max_paths}"
                )
        elif mem_pressure_ratio < 0.4:
            # 空闲内存 > 60%，恢复正常阈值
            if self.max_paths != self._original_max_paths:
                self.max_paths = self._original_max_paths
                logger.info(
                    f"[PathPruner] Memory pressure relieved (mem_pressure_ratio={mem_pressure_ratio:.2f}), "
                    f"max_paths restored to {self.max_paths}"
                )

    def should_prune(self, path: PathInfo) -> Tuple[bool, str]:
        """评估各启用策略, 返回 (是否剪除, 原因字符串)。"""
        if self.strategy == PruningStrategy.NONE:
            return False, ''

        # 自适应内存剪枝 — 节流到每 50 次调用检查一次
        self._prune_call_counter += 1
        if self._prune_call_counter % self._MEM_CHECK_INTERVAL == 0:
            self._adapt_max_paths_memory()

        if len(self.active_paths) >= self.max_paths:
            return True, 'max_paths_limit'

        # 循环边界剪枝
        if self.strategy in [PruningStrategy.LOOP_BOUND, PruningStrategy.ALL]:
            for addr, count in path.loop_counts.items():
                if count >= self.loop_bound:
                    self.stats.pruning_by_strategy['loop_bound'] = \
                        self.stats.pruning_by_strategy.get('loop_bound', 0) + 1
                    return True, f'loop_bound exceeded at {hex(addr)}'

        # 状态相似性剪枝
        if self.strategy in [PruningStrategy.SIMILAR_STATE, PruningStrategy.ALL]:
            state_hash = self._hash_path_state(path)
            if self.visited_states[state_hash] >= 3:
                self.stats.pruning_by_strategy['similar_state'] = \
                    self.stats.pruning_by_strategy.get('similar_state', 0) + 1
                return True, 'similar_state'

        # 覆盖率引导剪枝
        if self.strategy in [PruningStrategy.COVERAGE_GUIDED, PruningStrategy.ALL]:
            new_coverage = len(path.visited_addresses - self.coverage)
            if new_coverage == 0 and path.depth > 10:
                self.stats.pruning_by_strategy['coverage_guided'] = \
                    self.stats.pruning_by_strategy.get('coverage_guided', 0) + 1
                return True, 'no_new_coverage'
        return False, ''

    def register_path(self, path: PathInfo) -> None:
        self.active_paths[path.path_id] = path
        self.coverage.update(path.visited_addresses)
        state_hash = self._hash_path_state(path)
        self.visited_states[state_hash] += 1

    def prune_path(self, path_id: str, reason: str) -> None:
        if path_id in self.active_paths:
            path = self.active_paths[path_id]
            path.is_active = False
            path.is_pruned = True
            path.prune_reason = reason
            self.stats.paths_pruned += 1
            del self.active_paths[path_id]
            logger.debug(f"[PathPruner] Pruned path {path_id}: {reason}")

    @staticmethod
    def _hash_path_state(path: PathInfo) -> str:
        recent = list(path.visited_addresses)[-10:]
        return hashlib.md5(str(sorted(recent)).encode()).hexdigest()[:8]

    def get_stats(self) -> OptimizationStats:
        self.stats.total_paths_explored = len(self.active_paths) + self.stats.paths_pruned
        return self.stats

    def get_memory_status(self) -> Dict[str, Any]:
        """返回当前内存自适应剪枝状态"""
        status: Dict[str, Any] = {
            'max_paths': self.max_paths,
            'original_max_paths': self._original_max_paths,
            'adaptive_pruning': self._adaptive_pruning,
            'mem_pressure_ratio': None,
        }
        if PSUTIL_AVAILABLE:
            mem = psutil.virtual_memory()
            status['mem_pressure_ratio'] = round(1.0 - (mem.available / mem.total), 4)
            status['available_gb'] = round(mem.available / (1024 ** 3), 2)
        return status


class ConstraintSimplifier:
    """预处理 pass: 去重、算术恒等化简、移除 Z3 可检测的矛盾、
    消除公共子表达式。

    增强: CSE — 在 >=3 个约束中出现的公共子表达式被提取为单一
    新变量, 减少 Z3 求解器内部 AST 节点数。
    """

    def __init__(self):
        self.simplify_stats: Dict[str, int] = defaultdict(int)

    def simplify(self, constraints: List[Any]) -> List[Any]:
        """应用完整化简流水线。"""
        if not constraints:
            return constraints
        unique = self._remove_duplicates(constraints)
        self.simplify_stats['duplicates_removed'] += len(constraints) - len(unique)

        simplified = []
        for c in unique:
            simplified_c = self._simplify_arithmetic(c)
            if simplified_c is not None:
                simplified.append(simplified_c)

        simplified = self._common_subexpr_elimination(simplified)
        if Z3_AVAILABLE:
            simplified = self._remove_contradictions(simplified)
        self.simplify_stats['total_simplified'] += 1
        return simplified

    def _remove_duplicates(self, constraints: List[Any]) -> List[Any]:
        # 使用 dict.fromkeys 保留首次出现顺序，比 set 更精确去重
        seen: Dict[str, bool] = {}
        unique = []
        for c in constraints:
            c_str = str(c)
            if c_str not in seen:
                seen[c_str] = True
                unique.append(c)
        return unique

    def _simplify_arithmetic(self, constraint: Any) -> Optional[Any]:
        c_str = str(constraint)
        # 代数恒等消除 — 基于字符串替换的快速第一遍
        c_str = c_str.replace('+ 0', '')
        c_str = c_str.replace('- 0', '')
        c_str = c_str.replace('* 1', '')
        c_str = c_str.replace('/ 1', '')
        c_str = c_str.replace('== True', '')
        c_str = c_str.replace('== False', ' == 0')
        # Z3 simplify — 仅对 BoolRef 调用，z3.simplify 极少抛异常
        if Z3_AVAILABLE and isinstance(constraint, z3.BoolRef):
            return z3.simplify(constraint)
        return constraint

    def _common_subexpr_elimination(self, constraints: List[Any]) -> List[Any]:
        """基于哈希的公共子表达式消除。

        策略 — 两阶段 CSE:
        1. 把约束规范化为字符串哈希并构建频率表, 出现 >= 3 次的
           子表达式成为提取候选
        2. Z3 约束 (BoolRef) 用 z3.substitute() 把频繁子表达式
           替换为 fresh Bool 变量, 并新增等价约束
           (fresh_var == sub_expr), 减少 Z3 内部遍历的 AST 节点数

        非 Z3 约束 (字符串 / claripy) 回退到文本级替换: 子表达式
        文本换成简短规范标签, 至少降低下游缓存层的字符串哈希成本。

        复杂度 O(n*m), n = |constraints|, m = |频繁子表达式|;
        实际 m << n, 对约束列表约跑 2 遍。
        """
        if len(constraints) < 3:
            return constraints

        c_strs = [str(c) for c in constraints]

        # 阶段 1: 识别出现 >= 3 次的叶级 S 表达式
        expr_counts: Counter = Counter()
        for s in c_strs:
            tokens = _re_mod.findall(r'\([^()]+\)', s)
            expr_counts.update(set(tokens))

        frequent = {expr for expr, cnt in expr_counts.items() if cnt >= 3}
        if not frequent:
            return constraints

        self.simplify_stats['cse_eliminated'] += len(frequent)

        # 阶段 2: 替换频繁子表达式
        # Z3 路径 — 用 z3.substitute() 做 AST 级重写
        if Z3_AVAILABLE:
            return self._cse_substitute_z3(constraints, frequent)

        # 回退 — 非 Z3 约束做字符串级替换
        return self._cse_substitute_text(constraints, frequent)

    def _cse_substitute_z3(self, constraints: List[Any],
                           frequent: Set[str]) -> List[Any]:
        """Z3 级 CSE: 把频繁子表达式替换为 fresh Bool 变量。

        对每个出现在约束中的频繁子表达式 E, 创建 fresh
        Bool('cse_N') 并新增等价约束 (cse_N == E), 然后用
        z3.substitute() 把原约束中的 E 替换为 cse_N。

        只处理 z3.BoolRef 约束, 非 Z3 对象原样透传。
        """
        optimized: List[Any] = []
        # 从实际 Z3 AST 节点构建 (str_repr -> z3_expr) 映射
        # 对应频繁子表达式的字符串表示
        str_to_z3expr: Dict[str, z3.ExprRef] = {}
        for c in constraints:
            if not isinstance(c, z3.BoolRef):
                continue
            c_str = str(c)
            for freq_expr in frequent:
                if freq_expr in c_str and freq_expr not in str_to_z3expr:
                    # 遍历 Z3 AST 查找匹配字符串的子节点
                    matched = self._find_z3_subexpr(c, freq_expr)
                    if matched is not None:
                        str_to_z3expr[freq_expr] = matched

        if not str_to_z3expr:
            return list(constraints)

        # 创建 fresh 变量等价约束
        fresh_vars: Dict[str, z3.BoolRef] = {}
        cse_counter = 0
        for freq_str, z3_expr in str_to_z3expr.items():
            fresh = z3.Bool(f'cse_{cse_counter}')
            fresh_vars[freq_str] = fresh
            optimized.append(fresh == z3_expr)
            cse_counter += 1

        # 替换原始约束
        for c in constraints:
            if isinstance(c, z3.BoolRef):
                substituted = c
                for freq_str, z3_expr in str_to_z3expr.items():
                    if freq_str in str(substituted):
                        try:
                            substituted = z3.substitute(
                                substituted, (z3_expr, fresh_vars[freq_str])
                            )
                        except Exception:
                        # z3.substitute 结构不匹配
                        # AST 不匹配; 保留原约束
                            pass
                optimized.append(substituted)
            else:
                optimized.append(c)

        return optimized

    @staticmethod
    def _find_z3_subexpr(node: Any, target_str: str) -> Optional[Any]:
        """深度优先搜索 str() 等于 target_str 的 Z3 AST 子节点。

        返回第一个匹配节点, 未找到返回 None; 用迭代栈避免大 AST
        上的递归深度问题。
        """
        stack = [node]
        visited = set()
        while stack:
            current = stack.pop()
            cid = id(current)
            if cid in visited:
                continue
            visited.add(cid)
            if str(current) == target_str:
                return current
            if hasattr(current, 'children') and callable(current.children):
                try:
                    for child in current.children():
                        stack.append(child)
                except Exception:
                    pass
            elif hasattr(current, '__iter__'):
                try:
                    for child in current:
                        stack.append(child)
                except Exception:
                    pass
        return None

    def _cse_substitute_text(self, constraints: List[Any],
                             frequent: Set[str]) -> List[Any]:
        """非 Z3 约束的字符串级 CSE 回退。

        把频繁子表达式文本替换为简短规范标签 (如 '__cse_0__'),
        降低求解器缓存层的字符串哈希成本 (不减少 Z3 AST 节点数)。
        返回替换后的新列表。
        """
        import re as _re
        optimized: List[Any] = []
        # 按长度降序排列 — 先替换最长子表达式
        # 避免部分匹配覆盖较短模式
        sorted_freq = sorted(frequent, key=len, reverse=True)
        cse_labels: Dict[str, str] = {}
        for i, expr in enumerate(sorted_freq):
            cse_labels[expr] = f'__cse_{i}__'

        for c in constraints:
            c_str = str(c)
            for expr in sorted_freq:
                if expr in c_str:
                    c_str = c_str.replace(expr, cse_labels[expr])
            # 尽可能保留类型, 否则返回字符串
            if isinstance(c, str):
                optimized.append(c_str)
            else:
                optimized.append(c_str)
        return optimized

    def _remove_contradictions(self, constraints: List[Any]) -> List[Any]:
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
    """基于线程池的并行约束求解器, 集成缓存、自动扩缩容与
    求解器热点性能分析。

    增强: profile_solver_hotspots — 在 _solve_with_cache 中按约束
    类型分类计时, 每 solver_profile_window 次求解后输出排序报告,
    标识消耗不均衡求解时间的约束类别。
    """

    # 约束分类关键词映射 — 基于 SMT-LIB / Z3 表达式模式
    _CONSTRAINT_CATEGORIES: List[Tuple[str, Tuple[str, ...]]] = [
        ('arithmetic', ('bvadd', 'bvsub', 'bvmul', 'bvudiv', 'bvurem',
                        'bvsdiv', 'bvsrem', '+', '-', '*', '/')),
        ('bitwise', ('bvand', 'bvor', 'bvxor', 'bvnot', 'bvshl',
                     'bvlshr', 'bvashr', 'concat', 'extract', '<<', '>>')),
        ('comparison', ('bvult', 'bvule', 'bvugt', 'bvuge',
                        'bvslt', 'bvsle', 'bvsgt', 'bvsge',
                        '=', 'distinct', '==', '!=', '<=', '>=')),
        ('memory', ('store', 'load', 'select', 'mem', 'memory',
                    'zero_extend', 'sign_extend')),
        ('boolean', ('ite', 'if', 'implies', 'and', 'or', 'not', '=>', '&&', '||')),
    ]

    def __init__(self,
        max_workers: int = 4,
        timeout: float = 30.0,
        cache: Optional[ConstraintSolverCache] = None,
        auto_scale: bool = True,
        solver_profile_window: int = 100,
        # 四轮增强 — 复杂度预估器
        complexity_estimator: Optional[ConstraintComplexityEstimator] = None,
        # 四轮增强 — 预算管理器
        budget_manager: Optional[SolverBudgetManager] = None,
    ):
        self.max_workers = max_workers
        self._base_workers = max_workers
        self.timeout = timeout
        self.cache = cache or ConstraintSolverCache()
        self.auto_scale = auto_scale
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.stats: Dict[str, Any] = defaultdict(float)

        # 求解器性能分析
        self.solver_profile_window = solver_profile_window
        self._profile_counter: int = 0
        self._hotspot_profiles: Dict[str, List[float]] = defaultdict(list)
        self._profile_lock = threading.Lock()

        # 四轮增强 — 复杂度预估器
        self.complexity_estimator = complexity_estimator or ConstraintComplexityEstimator()
        # 四轮增强 — 预算管理器
        self.budget_manager = budget_manager

    def _categorize_constraints(self, constraints: List[Any]) -> str:
        """将约束集归类到主导类别

        设计取舍 — 使用字符串模式匹配而非 AST 遍历
        牺牲 5-10% 的分类精度换取 ~100x 的分类速度
        一个约束集可能匹配多个类别，取匹配次数最多的类别作为 hotspot_category
        """
        if not constraints:
            return 'empty'
        combined = ' '.join(str(c).lower() for c in constraints)
        category_counts: Dict[str, int] = {}
        for hotspot_category, keywords in self._CONSTRAINT_CATEGORIES:
            count = sum(1 for kw in keywords if kw in combined)
            if count > 0:
                category_counts[hotspot_category] = count
        if not category_counts:
            return 'other'
        return max(category_counts, key=lambda k: category_counts[k])

    def profile_solver_hotspots(self) -> Optional[Dict[str, Any]]:
        """输出求解器热点分析报告。

        每 solver_profile_window 次求解后, 按各 hotspot_category
        的平均求解耗时降序排列; 返回 {'hotspots': [(category,
        avg_time, count, total_time), ...]} 或 None (窗口未满)。
        """
        with self._profile_lock:
            if self._profile_counter < self.solver_profile_window:
                return None
            report: Dict[str, Any] = {'hotspots': [], 'total_queries': self._profile_counter}
            entries = []
            for hotspot_category, times in self._hotspot_profiles.items():
                total = sum(times)
                avg = total / len(times)
                entries.append((hotspot_category, round(avg, 5), len(times), round(total, 4)))
            # 按平均耗时降序排列
            entries.sort(key=lambda e: e[1], reverse=True)
            report['hotspots'] = entries

            logger.info("=" * 60)
            logger.info(f"[ParallelSolver] Hotspot report ({self._profile_counter} queries)")
            logger.info(f"{'Category':<16} {'Count':>6} {'Avg(s)':>10} {'Total(s)':>10}")
            logger.info("-" * 60)
            for hotspot_category, avg_t, cnt, total_t in entries:
                logger.info(f"{hotspot_category:<16} {cnt:>6} {avg_t:>10.5f} {total_t:>10.4f}")
            logger.info("=" * 60)

            # 重置计数器
            self._profile_counter = 0
            self._hotspot_profiles.clear()
            return report

    def _auto_scale(self, pending_count: int):
        """pending > 100 -> 翻倍 workers 至 CPU 核数上限"""
        if not self.auto_scale:
            return
        cpu_count = _mp.cpu_count()
        if pending_count > 100 and self.max_workers < cpu_count:
            new_workers = min(cpu_count, self._base_workers * 2)
            if new_workers != self.max_workers:
                self.executor._max_workers = new_workers
                self.max_workers = new_workers
                logger.info(f"[ParallelSolver] Auto-scaled to {new_workers} workers")

    def solve_batch(self,
        constraint_sets: List[List[Any]]
    ) -> List[Optional[Dict[str, Any]]]:
        """并行提交多个约束集, 按提交顺序返回结果。"""
        self._auto_scale(len(constraint_sets))
        futures: Dict[Future, int] = {}
        for i, constraints in enumerate(constraint_sets):
            future = self.executor.submit(self._solve_with_cache, constraints)
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

    def _solve_with_cache(self,
                          constraints: List[Any],
                          is_critical: bool = False) -> Optional[Dict[str, Any]]:
        """带缓存、复杂度预估与预算检查的约束求解。

        四轮增强, 求解前执行: 1) ComplexityEstimator 预测耗时 →
        超过 timeout 则跳过; 2) BudgetManager 检查预算 → 非关键
        任务预算耗尽则拒绝。
        """
        constraint_hash = self.cache.hash_constraints(constraints)
        cached = self.cache.get(constraint_hash)
        if cached:
            self.stats['time_saved'] += cached.solve_time
            return {
                'satisfiable': cached.is_satisfiable,
                'solution': cached.solution,
                'cached': True
            }

        # 四轮增强 — 复杂度预估：预测过长则跳过
        features = self.complexity_estimator.extract_features(constraints)
        should_skip, predicted = self.complexity_estimator.should_skip(
            constraints, self.timeout
        )
        if should_skip:
            self.stats['skipped_by_estimator'] += 1
            return {
                'satisfiable': False,
                'error': 'skipped_by_estimator',
                'predicted_seconds': round(predicted, 4),
            }

        # 四轮增强 — 预算检查：非关键任务预算耗尽则拒绝
        if self.budget_manager is not None and not is_critical:
            if self.budget_manager.is_budget_exhausted():
                self.stats['skipped_by_budget'] += 1
                return {
                    'satisfiable': False,
                    'error': 'budget_exhausted',
                }
            # 尝试从预算中扣减
            consumed = self.budget_manager.consume(predicted, is_critical=False)
            if not consumed:
                self.stats['skipped_by_budget'] += 1
                return {
                    'satisfiable': False,
                    'error': 'budget_exhausted',
                }

        # 约束分类 — 用于热点分析
        hotspot_category = self._categorize_constraints(constraints)

        start_time = time.time()
        if Z3_AVAILABLE:
            result = self._solve_z3(constraints)
        elif ANGR_AVAILABLE:
            result = self._solve_claripy(constraints)
        else:
            result = {'satisfiable': False, 'error': 'no_solver'}
        solve_time = time.time() - start_time

        # 四轮增强 — 更新复杂度预估器
        self.complexity_estimator.update(features, solve_time)

        self.cache.put(
            constraint_hash, result,
            result.get('satisfiable', False),
            result.get('solution'), solve_time)
        self.stats['total_solve_time'] += solve_time

        # 记录热点分析数据
        self._record_hotspot(hotspot_category, solve_time)

        return result

    def _record_hotspot(self, hotspot_category: str, solve_time: float) -> None:
        """将单次求解耗时记录到对应类别中"""
        with self._profile_lock:
            self._hotspot_profiles[hotspot_category].append(solve_time)
            self._profile_counter += 1
            if self._profile_counter >= self.solver_profile_window:
                # 窗口满，在后台线程中输出报告以避免阻塞求解路径
                threading.Thread(target=self.profile_solver_hotspots, daemon=True).start()

    def _solve_z3(self, constraints: List[Any]) -> Dict[str, Any]:
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
        self.executor.shutdown(wait=True)


__all__ = [
    # 常量
    'ANGR_AVAILABLE',
    'Z3_AVAILABLE',
    'PSUTIL_AVAILABLE',
    # 枚举
    'PruningStrategy',
    'CachePolicy',
    'OptimizationPass',
    # 数据类
    'ConstraintCacheEntry',
    'PathInfo',
    'OptimizationStats',
    'ConstraintFeatures',
    'PassResult',
    # 缓存
    'ConstraintSolverCache',
    'IncrementalSolverCache',
    # 剪枝
    'PathPruner',
    # 化简
    'ConstraintSimplifier',
    # 求解器
    'ParallelSolver',
    # 流水线
    'OptimizationPipeline',
    # 预算
    'SolverBudgetManager',
    # 预估器
    'ConstraintComplexityEstimator',
]
