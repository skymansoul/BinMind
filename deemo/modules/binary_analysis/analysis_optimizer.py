"""分析策略自优化模块。

功能:
    1. 强化学习在线调优分析流水线参数
    2. 贝叶斯优化参数配置
    3. 动态资源分配调整
    4. 分析性能监控与反馈

核心方法: 强化学习策略优化 / 贝叶斯优化 / 性能指标监控 / 自适应调参。
"""

import json
import logging
import math
import os
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class OptimizationStrategy(str, Enum):
    """优化策略。"""
    REINFORCEMENT_LEARNING = "reinforcement_learning"
    BAYESIAN = "bayesian"
    GRADIENT_DESCENT = "gradient_descent"
    SIMULATED_ANNEALING = "simulated_annealing"
    GENETIC = "genetic"

class ExplorationStrategy(str, Enum):
    """探索策略。"""
    EPSILON_GREEDY = "epsilon_greedy"
    SOFTMAX = "softmax"
    UCB = "ucb"


@dataclass
class OptimizationParameter:
    """优化参数定义。"""
    name: str
    min_value: float
    max_value: float
    default_value: float
    step: float = 0.01
    param_type: str = 'float'
    categories: list = field(default_factory=list)


@dataclass
class OptimizationState:
    """优化状态。"""
    parameters: Dict[str, Any]
    reward: float = 0.0
    timestamp: float = 0.0
    iteration: int = 0


@dataclass
class PerformanceMetrics:
    """性能指标。"""
    analysis_time: float = 0.0
    coverage: float = 0.0
    vulnerability_count: int = 0
    false_positives: int = 0
    memory_usage: float = 0.0
    cpu_usage: float = 0.0
    throughput: float = 0.0


@dataclass
class RLState:
    """强化学习状态。"""
    normalized_features: List[float]
    action: int
    reward: float
    next_state: Any


class BayesianOptimizer:
    """贝叶斯优化器。"""

    def __init__(self, params: List[OptimizationParameter]):
        """初始化: 构建 GP 模型, sklearn 缺失时退化为随机搜索。"""
        self._params = params
        self._history = []
        self._gaussian_process = None
        self._init_gp()

    def _init_gp(self):
        """初始化高斯过程模型。"""
        try:
            from sklearn.gaussian_process import GaussianProcessRegressor
            from sklearn.gaussian_process.kernels import RBF, ConstantKernel
            kernel = ConstantKernel(1.0) * RBF(length_scale=1.0)
            self._gaussian_process = GaussianProcessRegressor(
                kernel=kernel,
                alpha=1e-10,
                n_restarts_optimizer=10
            )
            logger.info("Bayesian optimizer initialized (using sklearn)")
        except ImportError:
            logger.warning("sklearn not available, using simplified Bayesian optimization")

    def _acquisition_function(self, x: List[float], exploration_weight: float = 0.1) -> float:
        """采集函数 (UCB): 均值 + 探索权重 * 标准差。"""
        if self._gaussian_process is None or len(self._history) < 2:
            return random.uniform(0, 1)

        try:
            mean, std = self._gaussian_process.predict([x], return_std=True)
            return mean + exploration_weight * std
        except Exception:
            return random.uniform(0, 1)

    def suggest(self) -> Dict[str, float]:
        """给出下一组参数建议。"""
        if len(self._history) == 0:
            return {p.name: p.default_value for p in self._params}

        # sklearn 缺失时退化为随机搜索
        if self._gaussian_process is None:
            suggestion = {}
            for p in self._params:
                if p.param_type == 'categorical':
                    suggestion[p.name] = random.choice(p.categories)
                else:
                    suggestion[p.name] = random.uniform(p.min_value, p.max_value)
            return suggestion

        # 随机采样 100 组候选, 取采集函数最大者
        best_acquisition = float('-inf')
        best_params = None

        for _ in range(100):
            params = []
            for p in self._params:
                params.append(random.uniform(p.min_value, p.max_value))

            acquisition = self._acquisition_function(params)
            if acquisition > best_acquisition:
                best_acquisition = acquisition
                best_params = params

        return {p.name: best_params[i] for i, p in enumerate(self._params)}

    def update(self, params: Dict[str, float], reward: float):
        """记录 (参数, 奖励) 并增量拟合 GP。"""
        self._history.append((params, reward))

        if self._gaussian_process and len(self._history) >= 2:
            X = []
            y = []
            for p, r in self._history:
                X.append([p.get(param.name, param.default_value) for param in self._params])
                y.append(r)

            try:
                self._gaussian_process.fit(X, y)
            except Exception as e:
                logger.debug(f"Gaussian process fit failed: {e}")


class QLearningAgent:
    """Q-learning 智能体 (Q 表 + ε-greedy/softmax/UCB 探索)。"""

    def __init__(self,
        state_dim: int,
        action_dim: int,
        learning_rate: float = 0.1,
        discount_factor: float = 0.95,
        exploration_strategy: ExplorationStrategy = ExplorationStrategy.EPSILON_GREEDY,
        epsilon: float = 0.1,
        temperature: float = 1.0
    ):
        """初始化 Q 表与超参数。"""
        self._state_dim = state_dim
        self._action_dim = action_dim
        self._alpha = learning_rate
        self._gamma = discount_factor
        self._exploration_strategy = exploration_strategy
        self._epsilon = epsilon
        self._temperature = temperature

        self._q_table = {}

        logger.info(f"Q-learning agent initialized, state dim: {state_dim}, action dim: {action_dim}")

    def _get_state_key(self, state: List[float]) -> tuple:
        """状态向量 → 表键 (3 位小数取整)。"""
        return tuple(round(s, 3) for s in state)

    def _init_q_values(self, state_key: tuple):
        """缺省初始化 Q 值。"""
        if state_key not in self._q_table:
            self._q_table[state_key] = [0.0] * self._action_dim

    def select_action(self, state: List[float]) -> int:
        """按探索策略选动作, 返回动作下标。"""
        state_key = self._get_state_key(state)
        self._init_q_values(state_key)

        if self._exploration_strategy == ExplorationStrategy.EPSILON_GREEDY:
            if random.random() < self._epsilon:
                return random.randint(0, self._action_dim - 1)
            else:
                return self._q_table[state_key].index(max(self._q_table[state_key]))

        elif self._exploration_strategy == ExplorationStrategy.SOFTMAX:
            q_values = self._q_table[state_key]
            exp_values = [math.exp(q / self._temperature) for q in q_values]
            total = sum(exp_values)
            probabilities = [e / total for e in exp_values]
            return random.choices(range(self._action_dim), weights=probabilities)[0]

        elif self._exploration_strategy == ExplorationStrategy.UCB:
            q_values = self._q_table[state_key]
            return q_values.index(max(q_values))

        return random.randint(0, self._action_dim - 1)

    def learn(self, state: List[float], action: int, reward: float, next_state: List[float]):
        """Q 值更新: Q(s,a) += α*(r + γ*max Q(s') - Q(s,a))。"""
        state_key = self._get_state_key(state)
        next_state_key = self._get_state_key(next_state)

        self._init_q_values(state_key)
        self._init_q_values(next_state_key)

        current_q = self._q_table[state_key][action]
        max_next_q = max(self._q_table[next_state_key])
        new_q = current_q + self._alpha * (reward + self._gamma * max_next_q - current_q)

        self._q_table[state_key][action] = new_q

    def decay_epsilon(self, rate: float = 0.99):
        """ε 衰减, 下限 0.01。"""
        self._epsilon = max(0.01, self._epsilon * rate)


class AnalysisOptimizer:
    """分析策略优化器。"""

    DEFAULT_PARAMS = [
        OptimizationParameter(
            name='symbolic_timeout',
            min_value=30.0,
            max_value=300.0,
            default_value=120.0,
            step=10.0,
            param_type='float'
        ),
        OptimizationParameter(
            name='max_paths',
            min_value=10.0,
            max_value=500.0,
            default_value=100.0,
            step=10.0,
            param_type='int'
        ),
        OptimizationParameter(
            name='exploration_depth',
            min_value=50.0,
            max_value=500.0,
            default_value=200.0,
            step=10.0,
            param_type='int'
        ),
        OptimizationParameter(
            name='taint_sensitivity',
            min_value=0.1,
            max_value=1.0,
            default_value=0.5,
            step=0.05,
            param_type='float'
        ),
        OptimizationParameter(
            name='parallel_workers',
            min_value=1.0,
            max_value=8.0,
            default_value=4.0,
            step=1.0,
            param_type='int'
        ),
        OptimizationParameter(
            name='memory_limit_mb',
            min_value=512.0,
            max_value=8192.0,
            default_value=2048.0,
            step=256.0,
            param_type='int'
        ),
        OptimizationParameter(
            name='analysis_mode',
            min_value=0.0,
            max_value=2.0,
            default_value=1.0,
            param_type='categorical',
            categories=['fast', 'balanced', 'deep']
        )
    ]

    def __init__(self,
        strategy: OptimizationStrategy = OptimizationStrategy.BAYESIAN,
        params: List[OptimizationParameter] = None
    ):
        """初始化: 按策略装配贝叶斯优化器或 Q-learning 智能体。"""
        self._strategy = strategy
        self._params = params or self.DEFAULT_PARAMS
        self._current_params = {p.name: p.default_value for p in self._params}
        self._iteration = 0
        self._last_action = 0
        self._metrics_history: List[PerformanceMetrics] = []
        self._reward_history: List[float] = []

        if strategy == OptimizationStrategy.BAYESIAN:
            self._bayesian_optimizer = BayesianOptimizer(self._params)
        elif strategy == OptimizationStrategy.REINFORCEMENT_LEARNING:
            self._rl_agent = QLearningAgent(
                state_dim=5,
                action_dim=len(self._params) * 3
            )

        logger.info(f"Analysis optimizer initialized, strategy: {strategy.value}")

    def _normalize_metrics(self, metrics: PerformanceMetrics) -> List[float]:
        """性能指标归一化为 5 维特征向量 [时间, 覆盖, 漏洞数, 准确率, 吞吐]。"""
        features = []

        normalized_time = min(max(metrics.analysis_time / 600.0, 0.0), 1.0)
        features.append(1.0 - normalized_time)

        features.append(min(max(metrics.coverage, 0.0), 1.0))

        features.append(min(max(metrics.vulnerability_count / 10.0, 0.0), 1.0))

        total_detected = max(1, metrics.vulnerability_count + metrics.false_positives)
        features.append(1.0 - (metrics.false_positives / total_detected))

        features.append(min(max(metrics.throughput / 10.0, 0.0), 1.0))

        return features

    def _calculate_reward(self, metrics: PerformanceMetrics) -> float:
        """加权奖励: 覆盖 0.3 + 漏洞数 0.03/个 + 时效 0.2 + 准确率 0.2。"""
        reward = 0.0

        reward += metrics.coverage * 0.3

        reward += min(max(metrics.vulnerability_count, 0), 10) * 0.03

        time_penalty = min(max(metrics.analysis_time / 60.0, 0.0), 1.0)
        reward += (1.0 - time_penalty) * 0.2

        total_detected = max(1, metrics.vulnerability_count + metrics.false_positives)
        accuracy = 1.0 - (metrics.false_positives / total_detected)
        reward += accuracy * 0.2

        return reward

    def get_current_params(self) -> Dict[str, Any]:
        """返回当前参数副本。"""
        return self._current_params.copy()

    def suggest_params(self) -> Dict[str, Any]:
        """按策略给出下一组参数。"""
        if self._strategy == OptimizationStrategy.BAYESIAN:
            return self._bayesian_optimizer.suggest()
        elif self._strategy == OptimizationStrategy.REINFORCEMENT_LEARNING:
            if self._metrics_history:
                latest_metrics = self._metrics_history[-1]
                state = self._normalize_metrics(latest_metrics)
                action = self._rl_agent.select_action(state)
                # 记录所选动作, 供 update() 回放学习
                self._last_action = action
                return self._action_to_params(action)
            else:
                return self._current_params.copy()

        return self._current_params.copy()

    def _action_to_params(self, action: int) -> Dict[str, Any]:
        """动作下标 → 参数调整: action//3 定位参数, action%3 为减/加/不变。"""
        params = self._current_params.copy()
        param_index = action // 3
        action_type = action % 3

        if param_index < len(self._params):
            param = self._params[param_index]
            step = param.step

            if action_type == 0:
                params[param.name] = max(param.min_value, params[param.name] - step)
            elif action_type == 1:
                params[param.name] = min(param.max_value, params[param.name] + step)

        return params

    def update(self, metrics: PerformanceMetrics):
        """记录指标并更新优化器状态, 随后给出新参数。"""
        self._metrics_history.append(metrics)
        reward = self._calculate_reward(metrics)
        self._reward_history.append(reward)

        logger.debug(f"Optimizer update - reward: {reward:.4f}, iteration: {self._iteration}")

        if self._strategy == OptimizationStrategy.BAYESIAN:
            self._bayesian_optimizer.update(self._current_params, reward)
        elif self._strategy == OptimizationStrategy.REINFORCEMENT_LEARNING:
            if len(self._metrics_history) >= 2:
                prev_metrics = self._metrics_history[-2]
                prev_state = self._normalize_metrics(prev_metrics)
                current_state = self._normalize_metrics(metrics)

                self._rl_agent.learn(prev_state, self._last_action, reward, current_state)
                self._rl_agent.decay_epsilon()

        self._current_params = self.suggest_params()
        self._iteration += 1

    def save_state(self, filepath: str):
        """序列化优化器状态到 JSON。"""
        state = {
            'strategy': self._strategy.value,
            'current_params': self._current_params,
            'iteration': self._iteration,
            'reward_history': self._reward_history,
            'metrics_history': [
                {
                    'analysis_time': m.analysis_time,
                    'coverage': m.coverage,
                    'vulnerability_count': m.vulnerability_count,
                    'false_positives': m.false_positives,
                    'memory_usage': m.memory_usage,
                    'cpu_usage': m.cpu_usage,
                    'throughput': m.throughput
                } for m in self._metrics_history
            ]
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2)

        logger.info(f"Optimizer state saved: {filepath}")

    def load_state(self, filepath: str) -> bool:
        """从 JSON 反序列化优化器状态, 失败返回 False。"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                state = json.load(f)

            self._strategy = OptimizationStrategy(state['strategy'])
            self._current_params = state['current_params']
            self._iteration = state.get('iteration', 0)
            self._reward_history = state.get('reward_history', [])

            self._metrics_history = []
            for m in state.get('metrics_history', []):
                self._metrics_history.append(PerformanceMetrics(
                    analysis_time=m.get('analysis_time', 0.0),
                    coverage=m.get('coverage', 0.0),
                    vulnerability_count=m.get('vulnerability_count', 0),
                    false_positives=m.get('false_positives', 0),
                    memory_usage=m.get('memory_usage', 0.0),
                    cpu_usage=m.get('cpu_usage', 0.0),
                    throughput=m.get('throughput', 0.0)
                ))

            logger.info(f"Optimizer state loaded: {filepath}")
            return True

        except Exception as e:
            logger.error(f"Failed to load optimizer state: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """优化统计概要。"""
        if not self._reward_history:
            return {
                'iteration': self._iteration,
                'average_reward': 0.0,
                'best_reward': 0.0,
                'current_params': self._current_params
            }

        return {
            'iteration': self._iteration,
            'average_reward': sum(self._reward_history) / len(self._reward_history),
            'best_reward': max(self._reward_history),
            'current_params': self._current_params,
            'exploration_rate': self._rl_agent._epsilon if hasattr(self, '_rl_agent') else 0.1
        }


class ResourceManager:
    """资源管理器。"""

    def __init__(self):
        """初始化: 探测内存上限与 CPU 核数。"""
        self._max_memory = self._detect_max_memory()
        self._max_cpu = self._detect_cpu_count()
        self._current_allocation = {
            'memory': 2048,
            'cpu_cores': 4,
            'workers': 4
        }

        logger.info(f"Resource manager initialized - max memory: {self._max_memory}MB, CPU cores: {self._max_cpu}")

    def _detect_max_memory(self) -> int:
        """探测可用内存上限 (MB), 失败回退 8192。"""
        try:
            import psutil
            return int(psutil.virtual_memory().total / (1024 * 1024))
        except ImportError:
            return 8192

    def _detect_cpu_count(self) -> int:
        """探测 CPU 核数, 失败回退 4。"""
        try:
            import psutil
            return psutil.cpu_count() or 4
        except ImportError:
            import multiprocessing
            return multiprocessing.cpu_count() or 4

    def adjust_resources(self, metrics: PerformanceMetrics) -> Dict[str, int]:
        """按性能指标调整资源分配。

        内存 >80% 加 512MB, <30% 减 256MB;
        CPU >90% 加核; 吞吐 <1 加 worker, >5 减 worker。
        """
        new_allocation = self._current_allocation.copy()

        memory_ratio = metrics.memory_usage / self._max_memory
        if memory_ratio > 0.8 and self._current_allocation['memory'] < self._max_memory:
            new_allocation['memory'] = min(self._max_memory, self._current_allocation['memory'] + 512)
            logger.info(f"Memory insufficient, increasing allocation: {new_allocation['memory']}MB")
        elif memory_ratio < 0.3 and self._current_allocation['memory'] > 512:
            new_allocation['memory'] = max(512, self._current_allocation['memory'] - 256)

        if metrics.cpu_usage > 90 and self._current_allocation['cpu_cores'] < self._max_cpu:
            new_allocation['cpu_cores'] = min(self._max_cpu, self._current_allocation['cpu_cores'] + 1)
            logger.info(f"CPU usage high, increasing cores: {new_allocation['cpu_cores']}")

        if metrics.throughput < 1.0 and self._current_allocation['workers'] < 8:
            new_allocation['workers'] = min(8, self._current_allocation['workers'] + 1)
        elif metrics.throughput > 5.0 and self._current_allocation['workers'] > 1:
            new_allocation['workers'] = max(1, self._current_allocation['workers'] - 1)

        self._current_allocation = new_allocation
        return new_allocation

    def get_current_allocation(self) -> Dict[str, int]:
        """返回当前资源分配副本。"""
        return self._current_allocation.copy()


def create_optimizer(strategy: str = 'bayesian', params: List[OptimizationParameter] = None) -> AnalysisOptimizer:
    """工厂: 按策略名创建优化器, 未知策略回退贝叶斯。"""
    try:
        strategy_enum = OptimizationStrategy(strategy.lower())
    except ValueError:
        logger.warning(f"Unknown optimization strategy: {strategy}, using default")
        strategy_enum = OptimizationStrategy.BAYESIAN

    return AnalysisOptimizer(strategy=strategy_enum, params=params)


def create_resource_manager() -> ResourceManager:
    """创建资源管理器。"""
    return ResourceManager()
