"""覆盖率引导的符号探索, 支持遗传与贪心策略

维护基本块/边覆盖率位图, 用评分机制选择路径候选。
支持五种探索策略:
- GREEDY: 始终选择得分最高的未探索路径
- GENETIC: 通过交叉/变异进化输入种子种群
- RANDOM: 均匀随机选择
- HYBRID: 交替使用遗传 (每5步) 与贪心
- EPSILON_GREEDY: 以概率 epsilon 随机选择, 否则贪心

遗传优化器使用轮盘赌选择、单点交叉、逐字节变异。
适应度 = 覆盖率增益 × 0.7 + 风险分 × 0.3

epsilon-greedy 策略的意义: 纯贪心策略容易陷入局部最优 —
总是选最高分的路径会导致探索集中在程序的子区域。
epsilon 参数以固定概率引入随机探索, 在利用与探索之间取得平衡,
参考 Sutton & Barto

AdaptiveEpsilon 用指数衰减替代硬编码 epsilon, 使探索前期更激进、后期更精耕
CoverageDeltaTracker 用环形缓冲区追踪每步增量, 检测覆盖衰退并自动触发变异增强
StreamingCoverageReporter 将覆盖快照以异步生成器形式产出, 便于实时监控面板消费
DictionaryGenerator 从高适应度遗传种子中提取 magic byte 序列生成 AFL 字典
CrashSignatureBuilder 构建崩溃去重签名用于崩溃分组与分类
"""

import logging
import os
import random
import time
import json
import hashlib
import math
import threading
import pickle
import struct
from typing import Dict, Any, List, Optional, Tuple, Set, AsyncIterator, Iterator, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

_log = logging.getLogger(__name__)


class ExplorationStrategy(Enum):
    """可用的路径选择策略"""
    GREEDY = "greedy"
    GENETIC = "genetic"
    RANDOM = "random"
    HYBRID = "hybrid"
    EPSILON_GREEDY = "epsilon_greedy"


class CoverageMetric(Enum):
    """覆盖率度量的粒度"""
    BLOCK = "block"
    EDGE = "edge"
    PATH = "path"
    FUNCTION = "function"


@dataclass
class CoverageInfo:
    """已覆盖块、边、函数、路径的快照"""
    blocks: Set[int] = field(default_factory=set)
    edges: Set[Tuple[int, int]] = field(default_factory=set)
    functions: Set[str] = field(default_factory=set)
    paths: Set[str] = field(default_factory=set)
    total_blocks: int = 0
    total_edges: int = 0

    def coverage_ratio(self, metric: CoverageMetric) -> float:
        """返回目标空间的覆盖比例"""
        if metric == CoverageMetric.BLOCK:
            return len(self.blocks) / max(1, self.total_blocks)
        elif metric == CoverageMetric.EDGE:
            return len(self.edges) / max(1, self.total_edges)
        elif metric == CoverageMetric.FUNCTION:
            return len(self.functions) / max(1, self.total_edges)
        return 0.0


@dataclass
class PathState:
    """贪心选择的路径候选及其评分元数据"""
    path_id: str
    constraints: List = field(default_factory=list)
    depth: int = 0
    coverage_gain: float = 0.0
    risk_score: float = 0.0
    explored: bool = False
    timestamp: float = 0.0
    metadata: Dict = field(default_factory=dict)

    def score(self) -> float:
        """加权综合分: 覆盖率增益主导, 风险分打破平局"""
        return self.coverage_gain * 0.6 + self.risk_score * 0.4


@dataclass
class GeneticSeed:
    """遗传种群中的一个个体: 输入字节 + 适应度"""
    input_bytes: bytes
    fitness: float = 0.0
    coverage_bits: int = 0
    generation: int = 0
    parent_ids: List = field(default_factory=list)
    byte_entropy: float = 0.0

    def compute_id(self) -> str:
        """用于谱系追踪的短哈希"""
        return hashlib.sha256(self.input_bytes).hexdigest()[:16]


# 字节熵计算：作为种子多样性的代理指标
# 在遗传算法 fitness 中加入熵奖励项，避免种群过早收敛到单一字节模式
# 权重 0.05，仅起轻微引导作用，不主导选择
def _entropy_of_bytes(buf: bytes) -> float:
    if not buf:
        return 0.0
    freq = [0] * 256
    for b in buf:
        freq[b] += 1
    n = len(buf)
    return -sum((c / n) * math.log2(c / n) for c in freq if c > 0)


class CoverageTracker:
    """线程安全的块/边记录器, 维护滑动历史窗口用于计算近期覆盖率速度

    停滞检测计数器 `_stagnant_steps` 用于触发自适应突变率
    """

    def __init__(self):
        self._coverage = CoverageInfo()
        self._history: List[CoverageInfo] = []
        self._lock = threading.RLock()
        self._stagnant_steps: int = 0
        self._last_block_count: int = 0

    def record(self, blocks: Set[int], edges: Optional[Set[Tuple[int, int]]] = None):
        """记录新覆盖的块与边, 返回新增块数"""
        with self._lock:
            prev_blocks = len(self._coverage.blocks)
            prev_edges = len(self._coverage.edges)
            self._coverage.blocks.update(blocks)
            if edges:
                self._coverage.edges.update(edges)
            new_blocks = len(self._coverage.blocks) - prev_blocks
            new_edges = len(self._coverage.edges) - prev_edges
            self._history.append(CoverageInfo(
                blocks=self._coverage.blocks.copy(),
                edges=self._coverage.edges.copy(),
                total_blocks=self._coverage.total_blocks,
                total_edges=self._coverage.total_edges
            ))

            # 停滞检测
            current = len(self._coverage.blocks)
            if current == self._last_block_count:
                self._stagnant_steps += 1
            else:
                self._stagnant_steps = 0
                self._last_block_count = current

            return new_blocks

    @property
    def coverage(self):
        """当前覆盖率快照"""
        return self._coverage

    @property
    def stagnant_steps(self) -> int:
        return self._stagnant_steps

    def get_current(self) -> CoverageInfo:
        """线程安全地返回当前覆盖率副本"""
        with self._lock:
            return self._coverage

    def set_total(self, total_blocks: int, total_edges: int):
        """设置覆盖率比例计算的分母"""
        with self._lock:
            self._coverage.total_blocks = total_blocks
            self._coverage.total_edges = total_edges

    def coverage_gain_recent(self, window: int = 10) -> float:
        """最近 window 个快照的平均块覆盖率增量"""
        with self._lock:
            if len(self._history) < 2:
                return 0.0
            recent = self._history[-window:]
            if len(recent) < 2:
                return 0.0
            first = len(recent[0].blocks)
            last = len(recent[-1].blocks)
            return (last - first) / max(1, len(recent))


# CoverageDeltaTracker — 环形缓冲区追踪每步增量，自动检测覆盖衰退
#
# 设计意图：当覆盖增长进入平台期（最近10步均值 < 历史峰值的10%）
# 说明当前搜索方向已耗尽潜力，需要触发遗传变异增强来引入新的搜索方向
# cov_ring 用 deque(maxlen=50) 实现，O(1) 追加和滑动窗口查询
# peak_delta 记录单步最大增益，all_time_peak 记录整个探索周期的峰值
# 两者区分用于不同粒度的衰退判断
class CoverageDeltaTracker:
    """环形缓冲区追踪每步覆盖率增量

    在固定大小 deque (cov_ring) 中存储每步新增块数,
    当最近 trigger_window 步均值低于 trigger_ratio × 历史峰值时
    触发增强信号 — 表示探索已饱和, 需要更大的扰动来逃离局部最优

    环形缓冲区最大长度 50, 触发窗口 10, 触发比率 0.1
    """

    def __init__(self, window_size: int = 50, trigger_window: int = 10,
                 trigger_ratio: float = 0.1):
        self._window_size = window_size
        self._trigger_window = trigger_window
        self._trigger_ratio = trigger_ratio
        self.cov_ring: deque = deque(maxlen=window_size)
        self.peak_delta: float = 0.0
        self.all_time_peak: float = 0.0

    def record(self, new_blocks: int):
        """将新增量样本推入环形缓冲区

        同步更新 peak_delta (单步记录) 和 all_time_peak (全局记录)
        """
        self.cov_ring.append(new_blocks)
        if new_blocks > self.peak_delta:
            self.peak_delta = float(new_blocks)
        if new_blocks > self.all_time_peak:
            self.all_time_peak = float(new_blocks)

    def should_trigger_boost(self) -> bool:
        """覆盖率速度崩塌时返回 True

        触发条件: cov_ring 至少已填充 trigger_window 个样本,
        且最近 trigger_window 步均值 < trigger_ratio × all_time_peak,
        表示当前探索效率已严重低于历史水平
        """
        if len(self.cov_ring) < self._trigger_window:
            return False
        if self.all_time_peak == 0.0:
            return False
        recent = list(self.cov_ring)[-self._trigger_window:]
        trailing_mean = sum(recent) / len(recent)
        return trailing_mean < self._trigger_ratio * self.all_time_peak

    def reset_peak_delta(self):
        """重置单步峰值 (用于探索阶段切换)"""
        self.peak_delta = 0.0


# AdaptiveEpsilon — 指数衰减 epsilon，替代硬编码常量
#
# 公式：eps = min_eps + (max_eps - min_eps) * exp(-step / decay_rate)
# 默认 min_eps=0.02, max_eps=0.15, decay_rate=30.0
#
# 早期（step 小）epsilon 接近 0.15，偏向随机探索，快速覆盖程序空间；
# 后期（step 大）epsilon 衰减到 0.02，几乎纯贪心，精耕高收益路径
# 30.0 的衰减常数意味着大约 90 步后 epsilon 降至 0.02 附近
class AdaptiveEpsilon:
    """epsilon-greedy 探索的指数衰减 epsilon

    用调度函数替代固定 epsilon 常数: 早期偏向探索,
    后期覆盖率饱和时偏向利用

    公式: eps = 0.02 + (0.15 - 0.02) * exp(-step / 30.0)
    """

    def __init__(self, min_eps: float = 0.02, max_eps: float = 0.15,
                 decay_rate: float = 30.0):
        self._min_eps = min_eps
        self._max_eps = max_eps
        self.eps_decay_rate = decay_rate

    @property
    def min_eps(self) -> float:
        return self._min_eps

    @property
    def max_eps(self) -> float:
        return self._max_eps

    def get(self, step: int) -> float:
        """计算指定探索步的 epsilon

        步数为 0 时返回 max_eps, 随 step 增加指数衰减至 min_eps
        """
        return self._min_eps + (self._max_eps - self._min_eps) * math.exp(
            -step / max(1.0, self.eps_decay_rate))


class GeneticPathOptimizer:
    """轮盘赌选择、单点交叉、逐字节变异; 精英保留每代前 N 个个体

    停滞检测触发自适应突变率提升 — 连续 20 步无覆盖率增长时
    临时将 mutation_rate 翻倍 5 轮后恢复原值。
    原理: 种群可能过早收敛, 需要更大的基因扰动跳出局部最优
    """

    def __init__(self, population_size: int = 50, mutation_rate: float = 0.1,
                 crossover_rate: float = 0.7, elitism: int = 5):
        self._population_size = population_size
        self._mutation_rate = mutation_rate
        self._base_mutation_rate = mutation_rate
        self._crossover_rate = crossover_rate
        self._elitism = elitism
        self.population: List[GeneticSeed] = []
        self.generation = 0
        self._boost_rounds_remaining = 0

    @property
    def population_size(self):
        return self._population_size

    @property
    def mutation_rate(self):
        return self._mutation_rate

    @property
    def crossover_rate(self):
        return self._crossover_rate

    @property
    def elitism(self):
        return self._elitism

    def trigger_mutation_boost(self):
        """外部检测到覆盖率停滞时调用"""
        if self._boost_rounds_remaining == 0:
            self._mutation_rate = min(0.5, self._base_mutation_rate * 2.0)
            self._boost_rounds_remaining = 5

    def _tick_boost(self):
        if self._boost_rounds_remaining > 0:
            self._boost_rounds_remaining -= 1
            if self._boost_rounds_remaining == 0:
                self._mutation_rate = self._base_mutation_rate

    def initialize(self, seed_inputs: List[bytes]):
        """用初始字节输入列表初始化种群"""
        self.population = [
            GeneticSeed(input_bytes=s, generation=0, byte_entropy=_entropy_of_bytes(s))
            for s in seed_inputs[:self.population_size]
        ]

    def evaluate(self, evaluator):
        """用提供的适应度评估器对个体评分"""
        for seed in self.population:
            fitness_val, cov_bits = evaluator(seed.input_bytes)
            seed.fitness = fitness_val + seed.byte_entropy * 0.05
            seed.coverage_bits = cov_bits

    def select(self) -> Tuple[GeneticSeed, GeneticSeed]:
        """轮盘赌选择: 概率正比于适应度"""
        total_fitness = sum(s.fitness for s in self.population)
        if total_fitness == 0:
            return tuple(random.sample(self.population, 2))

        def _pick():
            r = random.uniform(0, total_fitness)
            cum = 0.0
            for s in self.population:
                cum += s.fitness
                if cum >= r:
                    return s
            return self.population[-1]

        return _pick(), _pick()

    def crossover(self, parent1: GeneticSeed, parent2: GeneticSeed) -> bytes:
        """在随机字节索引处单点交叉"""
        if random.random() > self.crossover_rate:
            return parent1.input_bytes
        if len(parent1.input_bytes) == 0 or len(parent2.input_bytes) == 0:
            return parent1.input_bytes or parent2.input_bytes
        cut = random.randint(0, min(len(parent1.input_bytes), len(parent2.input_bytes)))
        return parent1.input_bytes[:cut] + parent2.input_bytes[cut:]

    def mutate(self, seed: bytes) -> bytes:
        """逐字节变异: 以 mutation_rate 概率翻转每个字节"""
        arr = bytearray(seed)
        for i in range(len(arr)):
            if random.random() < self._mutation_rate:
                arr[i] = random.randint(0, 255)
        return bytes(arr)

    def evolve(self):
        """产生下一代: 精英保留 + 选择后代"""
        self.generation += 1
        self._tick_boost()
        new_pop = sorted(self.population, key=lambda s: s.fitness, reverse=True)[:self.elitism]

        while len(new_pop) < self.population_size:
            p1, p2 = self.select()
            child_data = self.crossover(p1, p2)
            child_data = self.mutate(child_data)
            child = GeneticSeed(
                input_bytes=child_data,
                generation=self.generation,
                parent_ids=[p1.compute_id(), p2.compute_id()],
                byte_entropy=_entropy_of_bytes(child_data)
            )
            new_pop.append(child)

        self.population = new_pop

    def get_best(self) -> Optional[GeneticSeed]:
        """返回适应度最高的个体, 种群为空时返回 None"""
        if not self.population:
            return None
        return max(self.population, key=lambda s: s.fitness)


class GreedyPathSelector:
    """维护未探索路径候选集合, 始终选择得分最高的路径"""

    def __init__(self, danger_threshold: float = 0.7):
        self._danger_threshold = danger_threshold
        self.paths: Dict[str, PathState] = {}
        self._lock = threading.RLock()

    @property
    def danger_threshold(self):
        return self._danger_threshold

    def add_path(self, path_id: str, constraints: List[str], depth: int = 0):
        """注册新的路径候选"""
        with self._lock:
            if path_id not in self.paths:
                self.paths[path_id] = PathState(
                    path_id=path_id,
                    constraints=constraints,
                    depth=depth,
                    timestamp=time.time()
                )

    def update_path(self, path_id: str, coverage_gain: float = 0.0, risk_score: float = 0.0):
        """更新已有路径的评分元数据"""
        with self._lock:
            if path_id in self.paths:
                self.paths[path_id].coverage_gain = coverage_gain
                self.paths[path_id].risk_score = risk_score
                self.paths[path_id].timestamp = time.time()

    def select_next(self, exclude: Optional[Set[str]] = None) -> Optional[str]:
        """返回得分最高的未探索路径, 并标记为已探索"""
        with self._lock:
            candidates = [
                pid for pid, state in self.paths.items()
                if not state.explored and (exclude is None or pid not in exclude)
            ]
            if not candidates:
                return None
            best = max(candidates, key=lambda pid: self.paths[pid].score())
            self.paths[best].explored = True
            return best

    def select_random(self, exclude: Optional[Set[str]] = None) -> Optional[str]:
        """epsilon-greedy 的随机分支：从未探索路径中均匀采样"""
        with self._lock:
            candidates = [
                pid for pid, state in self.paths.items()
                if not state.explored and (exclude is None or pid not in exclude)
            ]
            if not candidates:
                return None
            chosen = random.choice(candidates)
            self.paths[chosen].explored = True
            return chosen

    def mark_explored(self, path_id: str):
        """标记路径为已探索 (不经过选择)"""
        with self._lock:
            if path_id in self.paths:
                self.paths[path_id].explored = True


class CoverageGuidedSymbolicExecutor:
    """调度器: 组合覆盖率追踪、路径选择与遗传优化为单一探索循环

    增强要点:
    - epsilon-greedy 策略以 AdaptiveEpsilon 指数衰减概率随机探索
    - CoverageDeltaTracker 环形缓冲区检测覆盖衰退, 自动触发变异增强
    - 连续 20 步无覆盖率增长时, 临时切换到随机策略 5 轮
    """

    _STAGNATION_THRESHOLD = 20
    _EPSILON_DEFAULT = 0.1

    def __init__(self, strategy: ExplorationStrategy = ExplorationStrategy.HYBRID):
        self._strategy = strategy
        self._coverage_tracker = CoverageTracker()
        self._greedy_selector = GreedyPathSelector()
        self._genetic_optimizer = GeneticPathOptimizer()
        self._delta_tracker = CoverageDeltaTracker()
        self._adaptive_epsilon = AdaptiveEpsilon()
        self._lock = threading.RLock()
        self._running = False
        self._exploration_count = 0
        self._max_explorations = 1000
        self._binary_path = None
        self._epsilon = self._EPSILON_DEFAULT
        self._random_burst_remaining = 0
        self._step_new_edges: int = 0

    @property
    def strategy(self):
        return self._strategy

    @property
    def coverage_tracker(self):
        return self._coverage_tracker

    @property
    def greedy_selector(self):
        return self._greedy_selector

    @property
    def genetic_optimizer(self):
        return self._genetic_optimizer

    @property
    def delta_tracker(self) -> CoverageDeltaTracker:
        """暴露每步增量环形缓冲区供外部检查"""
        return self._delta_tracker

    @property
    def adaptive_epsilon(self) -> AdaptiveEpsilon:
        """暴露自适应 epsilon 调度供外部检查"""
        return self._adaptive_epsilon

    @property
    def binary_path(self):
        return self._binary_path

    @property
    def exploration_count(self) -> int:
        return self._exploration_count

    def set_target_binary(self, binary_path: str, total_blocks: int = 0, total_edges: int = 0):
        """设置分析目标二进制及其总块/边数, 用于覆盖率比例计算"""
        self._binary_path = binary_path
        self._coverage_tracker.set_total(total_blocks, total_edges)

    # 停滞自适应：覆盖率不动 → mutation boost + 随机探索 burst
    # 两路触发源：覆盖率Tracker 的 stagnant_steps 计数器
    # 以及 CoverageDeltaTracker 的环形缓冲区衰退检测
    def _check_stagnation(self):
        """基于两个独立信号评估停滞并做出反应

        信号1 — CoverageTracker.stagnant_steps: 连续无新块覆盖的步数
        信号2 — CoverageDeltaTracker.should_trigger_boost: 环形缓冲区
        中最近10步均值低于历史峰值10%, 说明覆盖速度已断崖式下跌

        任一信号触发即启动变异增强和随机探索爆发
        """
        triggered = False
        if self._coverage_tracker.stagnant_steps >= self._STAGNATION_THRESHOLD:
            triggered = True
        if self._delta_tracker.should_trigger_boost():
            triggered = True
        if triggered:
            self._genetic_optimizer.trigger_mutation_boost()
            self._random_burst_remaining = 5

    def _greedy_explore(self) -> Dict[str, Any]:
        """选择并模拟下一个贪心路径候选"""
        if self._random_burst_remaining > 0:
            self._random_burst_remaining -= 1
            next_path = self._greedy_selector.select_random()
        else:
            next_path = self._greedy_selector.select_next()

        if next_path is None:
            return {'status': 'done', 'path': None}

        prev_edges = len(self._coverage_tracker.get_current().edges)
        result = self._simulate_path_execution(next_path)
        self._step_new_edges = len(self._coverage_tracker.get_current().edges) - prev_edges
        self._exploration_count += 1
        self._check_stagnation()
        return result

    def _genetic_explore(self) -> Dict[str, Any]:
        """评估种群, 模拟最佳种子, 进化下一代"""
        if not self._genetic_optimizer.population:
            return {'status': 'waiting', 'path': None}

        self._genetic_optimizer.evaluate(self._evaluate_input)
        best = self._genetic_optimizer.get_best()
        if best:
            prev_edges = len(self._coverage_tracker.get_current().edges)
            result = self._simulate_input_execution(best.input_bytes)
            self._step_new_edges = len(self._coverage_tracker.get_current().edges) - prev_edges
            cov_gain = result.get('coverage_gain', 0.0)
            if cov_gain > 0:
                self._exploration_count += 1
                self._genetic_optimizer.evolve()
                self._check_stagnation()
                return result

        self._genetic_optimizer.evolve()
        self._check_stagnation()
        return {'status': 'evolving', 'path': None}

    def _hybrid_explore(self) -> Dict[str, Any]:
        """交替: 每5步遗传, 其余贪心"""
        if self._exploration_count % 5 == 0:
            return self._genetic_explore()
        return self._greedy_explore()

    def _epsilon_greedy_explore(self) -> Dict[str, Any]:
        """epsilon-greedy: 以 AdaptiveEpsilon 指数衰减概率随机探索, 其余贪心

        与硬编码 epsilon 不同, AdaptiveEpsilon 随 exploration_count 增加
        自动衰减: 前期偏向探索 (eps 接近 0.15), 后期偏向利用 (eps 接近 0.02)
        """
        eps = self._adaptive_epsilon.get(self._exploration_count)
        if random.random() < eps:
            next_path = self._greedy_selector.select_random()
        else:
            next_path = self._greedy_selector.select_next()

        if next_path is None:
            return {'status': 'done', 'path': None}

        prev_edges = len(self._coverage_tracker.get_current().edges)
        result = self._simulate_path_execution(next_path)
        self._step_new_edges = len(self._coverage_tracker.get_current().edges) - prev_edges
        self._exploration_count += 1
        self._check_stagnation()
        return result

    def _evaluate_input(self, input_bytes: bytes) -> Tuple[float, int]:
        """遗传优化器的适应度函数

        fitness 中加入字节熵奖励项 (权重 0.05), 在
        GeneticPathOptimizer.evaluate() 中叠加, 此处返回原始值"""
        result = self._simulate_input_execution(input_bytes)
        cov_delta = result.get('coverage_gain', 0.0)
        risk = result.get('risk_score', 0.0)
        fitness = cov_delta * 0.7 + risk * 0.3
        return fitness, result.get('new_blocks', 0)

    def _simulate_path_execution(self, path_id: str) -> Dict[str, Any]:
        """模拟路径执行, 随机构造覆盖率增量"""
        new_blocks = random.randint(0, 5)
        new_edges = random.randint(0, 3)
        risk_score = random.random()
        self._coverage_tracker.record(
            set(range(1000 + self._exploration_count,
                      1000 + self._exploration_count + new_blocks)),
            edges=set((random.randint(0, 9999), random.randint(0, 9999))
                      for _ in range(new_edges))
        )
        # 将每步增量推入环形缓冲区，用于衰退检测
        self._delta_tracker.record(new_blocks)
        return {
            'status': 'executed',
            'path_id': path_id,
            'coverage_gain': new_blocks * 0.1,
            'risk_score': risk_score,
            'new_blocks': new_blocks,
            'new_edges': new_edges,
            'depth': random.randint(1, 20)
        }

    def _simulate_input_execution(self, input_bytes: bytes) -> Dict[str, Any]:
        """模拟具体输入执行, 随机构造覆盖率增量"""
        new_blocks = random.randint(0, 10)
        new_edges = random.randint(0, 5)
        self._coverage_tracker.record(
            set(range(2000 + self._exploration_count,
                      2000 + self._exploration_count + new_blocks)),
            edges=set((random.randint(0, 9999), random.randint(0, 9999))
                      for _ in range(new_edges))
        )
        # 将每步增量推入环形缓冲区，用于衰退检测
        self._delta_tracker.record(new_blocks)
        return {
            'status': 'executed',
            'coverage_gain': new_blocks * 0.1,
            'risk_score': random.random(),
            'new_blocks': new_blocks,
            'new_edges': new_edges,
        }

    def explore(self, iterations: int = 100) -> Dict[str, Any]:
        """运行固定步数的探索循环"""
        results = []
        dispatch = {
            ExplorationStrategy.GREEDY: self._greedy_explore,
            ExplorationStrategy.GENETIC: self._genetic_explore,
            ExplorationStrategy.RANDOM: lambda: {'status': 'random'},
            ExplorationStrategy.HYBRID: self._hybrid_explore,
            ExplorationStrategy.EPSILON_GREEDY: self._epsilon_greedy_explore,
        }
        explorer = dispatch.get(self._strategy, self._hybrid_explore)

        for _ in range(iterations):
            if self._exploration_count >= self._max_explorations:
                break
            res = explorer()
            results.append(res)

        coverage = self._coverage_tracker.get_current()
        return {
            'success': True,
            'explorations': self._exploration_count,
            'coverage_ratio': coverage.coverage_ratio(CoverageMetric.BLOCK),
            'total_blocks': len(coverage.blocks),
            'stagnant_steps': self._coverage_tracker.stagnant_steps,
            'results': results
        }

    def step(self) -> Dict[str, Any]:
        """执行单步探索，返回该步结果。"""
        if self._exploration_count >= self._max_explorations:
            return {'status': 'done', 'path': None}
        dispatch = {
            ExplorationStrategy.GREEDY: self._greedy_explore,
            ExplorationStrategy.GENETIC: self._genetic_explore,
            ExplorationStrategy.RANDOM: lambda: {'status': 'random'},
            ExplorationStrategy.HYBRID: self._hybrid_explore,
            ExplorationStrategy.EPSILON_GREEDY: self._epsilon_greedy_explore,
        }
        explorer = dispatch.get(self._strategy, self._hybrid_explore)
        return explorer()

    def add_seed_input(self, input_bytes: bytes):
        """将具体输入注入遗传种群"""
        self._genetic_optimizer.population.append(GeneticSeed(
            input_bytes=input_bytes,
            generation=self._genetic_optimizer.generation,
            byte_entropy=_entropy_of_bytes(input_bytes)
        ))

    def add_path_candidate(self, path_id: str, constraints: List[str], depth: int = 0):
        """注册符号路径供贪心选择"""
        self._greedy_selector.add_path(path_id, constraints, depth)

    def get_stats(self) -> Dict[str, Any]:
        """返回当前探索与覆盖率统计"""
        coverage = self._coverage_tracker.get_current()
        current_eps = self._adaptive_epsilon.get(self._exploration_count)
        return {
            'explorations': self._exploration_count,
            'block_coverage': coverage.coverage_ratio(CoverageMetric.BLOCK),
            'edge_coverage': coverage.coverage_ratio(CoverageMetric.EDGE),
            'total_blocks_covered': len(coverage.blocks),
            'total_blocks_target': coverage.total_blocks,
            'generation': self._genetic_optimizer.generation,
            'population_size': len(self._genetic_optimizer.population),
            'mutation_rate': self._genetic_optimizer.mutation_rate,
            'stagnant_steps': self._coverage_tracker.stagnant_steps,
            'epsilon': current_eps,
            'peak_delta': self._delta_tracker.peak_delta,
            'all_time_peak': self._delta_tracker.all_time_peak,
        }


# Streaming覆盖率Reporter — 异步生成器产出覆盖快照
#
# 设计意图：实时监控面板或 webhook 消费者可以逐帧迭代覆盖快照
# 无需拉取整个探索结束后的结果。每条快照包含当前步数、块覆盖比、
# 边覆盖比、该步新增边数、使用的探索策略
#
# 使用方式:
# async for snap reporter.stream(executor):
#       dashboard.update(snap)
#
# stop_checker 回调允许外部在每次 yield 后检查是否应终止流
# 返回 None 表示正常退出，否则返回哨兵值
class StreamingCoverageReporter:
    """以异步生成器产出覆盖率快照, 供实时消费者使用

    快照包含 {step, block_coverage, edge_coverage,
    new_edges_this_step, strategy_used}。生成器定期轮询 executor,
    在有新覆盖率数据时产出差异快照。

    stop_checker 为可选回调, 每次 yield 后调用,
    返回真值时生成器退出
    """

    def __init__(self, poll_interval_sec: float = 0.1):
        self._poll_interval = poll_interval_sec
        self._last_block_count: int = 0
        self._last_edge_count: int = 0

    async def stream(self, executor: CoverageGuidedSymbolicExecutor,
                     stop_checker: Optional[Callable[[], Any]] = None
                     ) -> AsyncIterator[Dict[str, Any]]:
        """异步生成器, 逐步产出覆盖率快照。

        stop_checker 返回 truthy 时停止; 快照键: step/block_覆盖率/
        edge_覆盖率/new_edges_this_step/strategy_used。
        """
        import asyncio
        step = 0
        while True:
            await asyncio.sleep(self._poll_interval)
            stats = executor.get_stats()
            current_blocks = stats.get('total_blocks_covered', 0)
            current_block_cov = stats.get('block_coverage', 0.0)
            current_edge_cov = stats.get('edge_coverage', 0.0)

            # 从 executor 内部取新增边数（本次探索步的增量）
            new_edges = getattr(executor, '_step_new_edges', 0)

            # 只在有变化时产出快照，避免下游收到大量重复数据
            if current_blocks == self._last_block_count and new_edges == 0:
                if stop_checker and stop_checker():
                    return
                continue

            self._last_block_count = current_blocks
            self._last_edge_count = int(current_edge_cov * stats.get('total_blocks_target', 1))

            yield {
                'step': step,
                'block_coverage': current_block_cov,
                'edge_coverage': current_edge_cov,
                'new_edges_this_step': new_edges,
                'strategy_used': executor.strategy.value,
            }
            step += 1

            if stop_checker and stop_checker():
                return

    def stream_sync(self, executor: CoverageGuidedSymbolicExecutor,
                    stop_checker: Optional[Callable[[], Any]] = None
                    ) -> Iterator[Dict[str, Any]]:
        """非异步消费者的同步生成器版本

        产出与 stream() 相同的快照结构,
        适用于不使用 asyncio 的消费者
        """
        step = 0
        while True:
            time.sleep(self._poll_interval)
            stats = executor.get_stats()
            current_blocks = stats.get('total_blocks_covered', 0)
            current_block_cov = stats.get('block_coverage', 0.0)
            current_edge_cov = stats.get('edge_coverage', 0.0)
            new_edges = getattr(executor, '_step_new_edges', 0)

            if current_blocks == self._last_block_count and new_edges == 0:
                if stop_checker and stop_checker():
                    return
                continue

            self._last_block_count = current_blocks
            self._last_edge_count = int(current_edge_cov * stats.get('total_blocks_target', 1))

            yield {
                'step': step,
                'block_coverage': current_block_cov,
                'edge_coverage': current_edge_cov,
                'new_edges_this_step': new_edges,
                'strategy_used': executor.strategy.value,
            }
            step += 1

            if stop_checker and stop_checker():
                return


# DictionaryGenerator — 从高适应度遗传种子中提取 magic byte 序列
#
# 从遗传优化器的种群中选取 fitness 前 N 的个体（默认 top_k=20）
# 对每个种子的 input_bytes 滑动窗口扫描，提取长度为 2~8 字节的
# 高频重复子序列作为 "magic" 候选
#
# 输出 AFL 兼容字典格式（每个 token 一行 "@@ 开头" 的格式不对 —
# AFL 字典实际上是 name="." value="." 的纯文本格式）
# 每个字典条目的名称包含种子 lineage（parent_ids 链的前两级 hash）
#
# min_occurrences 控制子序列在单一种子内至少出现多少次才被收录
# 默认为 2，避免收录偶然的单次匹配
class DictionaryGenerator:
    """从高适应度遗传种子中提取 magic byte 序列, 输出 AFL 兼容字典

    种子的 input_bytes 通过滑动窗口 (长度 2-8) 扫描,
    查找高频重复子序列, 写入 AFL 字典 token,
    名称源自种子谱系
    """

    _MIN_MAGIC_LEN = 2
    _MAX_MAGIC_LEN = 8

    def __init__(self, top_k: int = 20, min_occurrences: int = 2):
        self._top_k = max(1, top_k)
        self._min_occurrences = max(1, min_occurrences)

    @staticmethod
    def extract_tokens(data: bytes, min_len: int = 2) -> List[str]:
        """从字节流中提取可打印 token 序列。"""
        if not data:
            return []
        tokens: List[str] = []
        current: List[str] = []
        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    tokens.append(''.join(current))
                current = []
        if len(current) >= min_len:
            tokens.append(''.join(current))
        return tokens

    def generate(self, optimizer: GeneticPathOptimizer) -> List[Dict[str, str]]:
        """从适应度最高的 top-K 种子中提取 magic token

        返回:
            字典列表, 每项含 'name' (谱系标签) 和 'value' (转义 hex 字符串)
        """
        if not optimizer.population:
            return []

        # 按 fitness 降序取前 top_k
        sorted_pop = sorted(optimizer.population,
                           key=lambda s: s.fitness, reverse=True)
        elite = sorted_pop[:self._top_k]

        tokens: List[Dict[str, str]] = []
        seen_values: Set[str] = set()

        for seed in elite:
            seed_id = seed.compute_id()
            lineage_tag = self._build_lineage_tag(seed)

            # 对种子字节进行滑动窗口扫描
            data = seed.input_bytes
            n = len(data)
            for win_len in range(self._MIN_MAGIC_LEN, self._MAX_MAGIC_LEN + 1):
                if win_len > n:
                    break
                # 统计每个窗口值的出现次数
                occurrence: Dict[bytes, int] = defaultdict(int)
                for i in range(n - win_len + 1):
                    chunk = data[i:i + win_len]
                    occurrence[chunk] += 1

                for chunk, count in occurrence.items():
                    if count >= self._min_occurrences:
                        hex_str = ''.join(f'\\x{b:02x}' for b in chunk)
                        if hex_str in seen_values:
                            continue
                        seen_values.add(hex_str)
                        tokens.append({
                            'name': f'autodict_{lineage_tag}_len{win_len}_{seed_id[:8]}',
                            'value': hex_str,
                        })

        return tokens

    def _build_lineage_tag(self, seed: GeneticSeed) -> str:
        """构建基于 lineage 的标签字符串

        取 parent_ids 列表中前两个 hash 的前6个字符拼接
        如果没有 parent_ids 则使用 seed 自己的 compute_id
        """
        if seed.parent_ids:
            parts = [pid[:6] for pid in seed.parent_ids[:2]]
            return '_'.join(parts)
        return seed.compute_id()[:6]

    def write_dictionary(self, optimizer: GeneticPathOptimizer,
                         output_path: str) -> int:
        """把 tokens 写入 AFL 兼容字典文件。

        格式为单行 entry: name="." value=".", # 开头为注释。
        从 optimizer 提取 tokens, 返回写入数量。
        """
        tokens = self.generate(optimizer)
        if not tokens:
            return 0

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f"# AFL dictionary generated by DictionaryGenerator\n")
            f.write(f"# Generation: {optimizer.generation}\n")
            f.write(f"# Population size: {len(optimizer.population)}\n")
            f.write(f"# Tokens extracted: {len(tokens)}\n\n")
            for token in tokens:
                f.write(f'name="{token["name"]}" value="{token["value"]}"\n')

        _log.info("AFL dictionary written to %s (%d tokens)", output_path, len(tokens))
        return len(tokens)


# Crash签名Builder — 构建 crash 去重签名
#
# crash 签名由三个字段组成：(crash_address, crash_type, top_3_栈_frames_hash)
# crash_type 为异常类型字符串（如 "SIGSEGV", "AccessViolation", "堆-缓冲区-overflow"）
# top_3_栈_frames_hash 是栈顶 3 帧地址拼接后的 SHA256 前 16 字符
#
# 相同签名的 crash 视为同源，用于分组去重——避免同一 root cause 的不同
# 输入变体淹没 triage 队列
@dataclass
class CrashSignature:
    """崩溃去重签名, 用于分组相似崩溃

    由 crash_address (int)、crash_type (str)、栈顶 3 帧地址哈希 (str) 组成。
    签名相同的崩溃视为同源根因
    """
    crash_address: int
    crash_type: str
    top_3_stack_frames_hash: str

    def to_key(self) -> str:
        """返回复合键字符串, 用于 dict/set 去重"""
        return f"{self.crash_address:x}:{self.crash_type}:{self.top_3_stack_frames_hash}"

    def to_dict(self) -> Dict[str, Any]:
        """序列化为普通 dict, 用于 JSON 输出"""
        return {
            'crash_address': hex(self.crash_address),
            'crash_type': self.crash_type,
            'top_3_stack_frames_hash': self.top_3_stack_frames_hash,
        }


class CrashSignatureBuilder:
    """构建崩溃去重签名

    签名由 {crash_address, crash_type, top_3_stack_frames_hash} 派生。
    支持对崩溃分组去重, 避免存储完整栈回溯

    用法:
    builder = CrashSignatureBuilder()
    sig = builder.build(0x7fffdead, "SIGSEGV", [0x401000, 0x402000, 0x403000])
    key = sig.to_key() # 作为崩溃分桶的 dict key
    """

    _TOP_FRAMES_COUNT = 3
    _HASH_LENGTH = 16

    def build(self, crash_address: int, crash_type: str,
              stack_frames: List[int]) -> CrashSignature:
        """由崩溃元数据构造 CrashSignature。

        crash_address 为指令指针或故障地址; crash_type 为异常类型
        字符串 (如 "SIGSEGV"); stack_frames 为栈回溯地址列表
        (最近在前), 取前 _TOP_FRAMES_COUNT 帧哈希。
        """
        top_frames = stack_frames[:self._TOP_FRAMES_COUNT]
        # 将 top frame 地址序列化为固定长度字节再哈希
        frame_bytes = struct.pack(f'<{len(top_frames)}Q', *top_frames)
        frames_hash = hashlib.sha256(frame_bytes).hexdigest()[:self._HASH_LENGTH]

        return CrashSignature(
            crash_address=crash_address,
            crash_type=crash_type,
            top_3_stack_frames_hash=frames_hash,
        )

    def build_from_dict(self, crash_info: Dict[str, Any]) -> CrashSignature:
        """便捷封装: 由 dict 构建 CrashSignature。

        crash_info 键: crash_address (int 或 hex 字符串)、crash_type、
        stack_frames (int 列表); 键缺失时抛 KeyError。
        """
        addr = crash_info['crash_address']
        if isinstance(addr, str):
            addr = int(addr, 16) if addr.startswith('0x') else int(addr)
        return self.build(
            crash_address=int(addr),
            crash_type=str(crash_info['crash_type']),
            stack_frames=[int(f) for f in crash_info['stack_frames']],
        )

    def group_by_signature(self, crashes: List[Dict[str, Any]]
                           ) -> Dict[str, List[Dict[str, Any]]]:
        """把崩溃 dict 列表按签名键分桶。

        返回 {签名键: 崩溃 dict 列表}。
        """
        buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for crash in crashes:
            try:
                sig = self.build_from_dict(crash)
                buckets[sig.to_key()].append(crash)
            except (KeyError, ValueError, TypeError) as exc:
                _log.warning("Failed to build crash signature: %s", exc)
                # 无法归类的 crash 归入单独桶
                buckets['__unclassifiable__'].append(crash)
        return dict(buckets)


def run_coverage_guided_symbex(
    binary_path: str,
    strategy: str = "hybrid",
    iterations: int = 100,
    seeds: Optional[List[bytes]] = None
) -> Dict[str, Any]:
    """一次性接口: 配置执行器, 注入种子, 运行探索, 返回统计"""
    try:
        strat = ExplorationStrategy(strategy.lower())
    except ValueError:
        strat = ExplorationStrategy.HYBRID

    executor = CoverageGuidedSymbolicExecutor(strategy=strat)
    executor.set_target_binary(binary_path, total_blocks=10000, total_edges=20000)

    if seeds:
        for seed in seeds:
            executor.add_seed_input(seed)
    else:
        executor.add_seed_input(b'\x00' * 64)
        executor.add_seed_input(b'\xff' * 64)
        executor.add_seed_input(b'A' * 256)

    for i in range(5):
        executor.add_path_candidate(f"path_{i}", [f"cond_{i}=true"], depth=i)

    result = executor.explore(iterations=iterations)
    result['stats'] = executor.get_stats()
    return result


# 检查点序列化/反序列化 — 遗传优化器种群的持久化
#
# 保存内容：population 列表（每个 GeneticSeed 的完整字段）、generation
# 计数器、peak_delta、all_time_peak。使用 pickle 协议 4（兼容 Python 3.4+）
# 在速度与文件大小之间取得平衡
#
# 恢复时调用方负责将 population 赋值回 优化器.population
# generation 赋值回 优化器.generation，并将 delta 值恢复到 tracker
def serialize_checkpoint(optimizer: GeneticPathOptimizer,
                         delta_tracker: CoverageDeltaTracker,
                         filepath: str):
    """序列化遗传优化器的种群与 delta tracker 状态。

    保存 population/generation/peak_delta/all_time_peak 到 pickle
    文件以便后续恢复。
    """
    data = {
        'population': optimizer.population,
        'generation': optimizer.generation,
        'peak_delta': delta_tracker.peak_delta,
        'all_time_peak': delta_tracker.all_time_peak,
    }
    with open(filepath, 'wb') as f:
        pickle.dump(data, f, protocol=4)
    _log.info("Checkpoint serialized to %s (gen=%d, pop=%d, peak_delta=%.1f)",
               filepath, optimizer.generation, len(optimizer.population),
               delta_tracker.peak_delta)


def deserialize_checkpoint(filepath: str) -> Dict[str, Any]:
    """反序列化检查点, 返回 population/generation/delta peaks。

    调用方负责把返回值恢复到 GeneticPathOptimizer 与
    CoverageDeltaTracker 实例。返回键: population/generation/
    peak_delta/all_time_peak。
    """
    with open(filepath, 'rb') as f:
        data = pickle.load(f)
    _log.info("Checkpoint deserialized from %s (gen=%d, pop=%d, peak_delta=%.1f)",
               filepath, data.get('generation', 0),
               len(data.get('population', [])),
               data.get('peak_delta', 0.0))
    return data
