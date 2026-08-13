"""
Analysis strategy self-optimization module.

Features:
    1. Reinforcement learning online tuning of analysis pipeline parameters
    2. Bayesian optimization of parameter configuration
    3. Dynamic resource configuration adjustment
    4. Analysis performance monitoring and feedback

Core technologies:
    - Reinforcement learning strategy optimization
    - Bayesian optimization
    - Performance metric monitoring
    - Adaptive parameter tuning
"""

import logging
import random
import math
import json
import os
import time
from typing import Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from scipy.optimize import minimize
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False


class OptimizationStrategy(str, Enum):
    """Optimization strategy."""
    REINFORCEMENT_LEARNING = "reinforcement_learning"
    BAYESIAN = "bayesian"
    GRADIENT_DESCENT = "gradient_descent"
    SIMULATED_ANNEALING = "simulated_annealing"
    GENETIC = "genetic"

class ExplorationStrategy(str, Enum):
    """Exploration strategy."""
    EPSILON_GREEDY = "epsilon_greedy"
    SOFTMAX = "softmax"
    UCB = "ucb"


@dataclass
class OptimizationParameter:
    """Optimization parameter."""
    name: str
    min_value: float
    max_value: float
    default_value: float
    step: float = 0.01
    param_type: str = 'float'
    categories: list = field(default_factory=list)


@dataclass
class OptimizationState:
    """Optimization state."""
    parameters: Dict[str, Any]
    reward: float = 0.0
    timestamp: float = 0.0
    iteration: int = 0


@dataclass
class PerformanceMetrics:
    """Performance metrics."""
    analysis_time: float = 0.0
    coverage: float = 0.0
    vulnerability_count: int = 0
    false_positives: int = 0
    memory_usage: float = 0.0
    cpu_usage: float = 0.0
    throughput: float = 0.0


@dataclass
class RLState:
    """Reinforcement learning state."""
    normalized_features: List[float]
    action: int
    reward: float
    next_state: Any


class BayesianOptimizer:
    """Bayesian optimizer."""

    def __init__(self, params: List[OptimizationParameter]):
        """
        Initialize Bayesian optimizer.

        Args:
            params: Optimization parameter list.
        """
        self._params = params
        self._history = []
        self._gaussian_process = None
        self._init_gp()

    def _init_gp(self):
        """Initialize Gaussian Process model."""
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
        """
        Acquisition function (Upper Confidence Bound).

        Args:
            x: Input parameter vector.
            exploration_weight: Exploration weight.

        Returns:
            UCB value.
        """
        if self._gaussian_process is None or len(self._history) < 2:
            return random.uniform(0, 1)

        try:
            mean, std = self._gaussian_process.predict([x], return_std=True)
            return mean + exploration_weight * std
        except Exception:
            return random.uniform(0, 1)

    def suggest(self) -> Dict[str, float]:
        """
        Suggest next parameter set.

        Returns:
            Parameter suggestion dict.
        """
        if len(self._history) == 0:
            return {p.name: p.default_value for p in self._params}

        # Simple random search (when sklearn unavailable)
        if self._gaussian_process is None:
            suggestion = {}
            for p in self._params:
                if p.param_type == 'categorical':
                    suggestion[p.name] = random.choice(p.categories)
                else:
                    suggestion[p.name] = random.uniform(p.min_value, p.max_value)
            return suggestion

        # Use acquisition function optimization
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
        """
        Update model.

        Args:
            params: Parameter dict.
            reward: Reward value.
        """
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
    """Q-learning agent."""

    def __init__(self,
        state_dim: int,
        action_dim: int,
        learning_rate: float = 0.1,
        discount_factor: float = 0.95,
        exploration_strategy: ExplorationStrategy = ExplorationStrategy.EPSILON_GREEDY,
        epsilon: float = 0.1,
        temperature: float = 1.0
    ):
        """
        Initialize Q-learning agent.

        Args:
            state_dim: State dimension.
            action_dim: Action dimension.
            learning_rate: Learning rate.
            discount_factor: Discount factor.
            exploration_strategy: Exploration strategy.
            epsilon: Epsilon value.
            temperature: Temperature parameter.
        """
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
        """Convert state to key."""
        return tuple(round(s, 3) for s in state)

    def _init_q_values(self, state_key: tuple):
        """Initialize Q-values."""
        if state_key not in self._q_table:
            self._q_table[state_key] = [0.0] * self._action_dim

    def select_action(self, state: List[float]) -> int:
        """
        Select action based on state.

        Args:
            state: State vector.

        Returns:
            Action index.
        """
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
        """
        Learn and update Q-values.

        Args:
            state: Current state.
            action: Action taken.
            reward: Reward value.
            next_state: Next state.
        """
        state_key = self._get_state_key(state)
        next_state_key = self._get_state_key(next_state)

        self._init_q_values(state_key)
        self._init_q_values(next_state_key)

        current_q = self._q_table[state_key][action]
        max_next_q = max(self._q_table[next_state_key])
        new_q = current_q + self._alpha * (reward + self._gamma * max_next_q - current_q)

        self._q_table[state_key][action] = new_q

    def decay_epsilon(self, rate: float = 0.99):
        """Decay epsilon value."""
        self._epsilon = max(0.01, self._epsilon * rate)


class AnalysisOptimizer:
    """Analysis strategy optimizer."""

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
        """
        Initialize analysis optimizer.

        Args:
            strategy: Optimization strategy.
            params: Optimization parameter list.
        """
        self._strategy = strategy
        self._params = params or self.DEFAULT_PARAMS
        self._current_params = {p.name: p.default_value for p in self._params}
        self._iteration = 0
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
        """
        Normalize performance metrics.

        Args:
            metrics: Performance metrics.

        Returns:
            Normalized feature vector.
        """
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
        """
        Calculate reward value.

        Args:
            metrics: Performance metrics.

        Returns:
            Reward value.
        """
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
        """Get current parameter configuration."""
        return self._current_params.copy()

    def suggest_params(self) -> Dict[str, Any]:
        """Suggest new parameter configuration."""
        if self._strategy == OptimizationStrategy.BAYESIAN:
            return self._bayesian_optimizer.suggest()
        elif self._strategy == OptimizationStrategy.REINFORCEMENT_LEARNING:
            if self._metrics_history:
                latest_metrics = self._metrics_history[-1]
                state = self._normalize_metrics(latest_metrics)
                action = self._rl_agent.select_action(state)
                return self._action_to_params(action)
            else:
                return self._current_params.copy()

        return self._current_params.copy()

    def _action_to_params(self, action: int) -> Dict[str, Any]:
        """
        Convert action to parameter adjustments.

        Args:
            action: Action index.

        Returns:
            Adjusted parameter dict.
        """
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
        """
        Update optimizer state.

        Args:
            metrics: Performance metrics.
        """
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

                self._rl_agent.learn(prev_state, 0, reward, current_state)
                self._rl_agent.decay_epsilon()

        self._current_params = self.suggest_params()
        self._iteration += 1

    def save_state(self, filepath: str):
        """
        Save optimizer state.

        Args:
            filepath: File path.
        """
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
        """
        Load optimizer state.

        Args:
            filepath: File path.

        Returns:
            Whether loading succeeded.
        """
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
        """
        Get optimization statistics.

        Returns:
            Statistics dict.
        """
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
    """Resource manager."""

    def __init__(self):
        """Initialize resource manager."""
        self._max_memory = self._detect_max_memory()
        self._max_cpu = self._detect_cpu_count()
        self._current_allocation = {
            'memory': 2048,
            'cpu_cores': 4,
            'workers': 4
        }

        logger.info(f"Resource manager initialized - max memory: {self._max_memory}MB, CPU cores: {self._max_cpu}")

    def _detect_max_memory(self) -> int:
        """Detect maximum available memory (MB)."""
        try:
            import psutil
            return int(psutil.virtual_memory().total / (1024 * 1024))
        except ImportError:
            return 8192

    def _detect_cpu_count(self) -> int:
        """Detect CPU core count."""
        try:
            import psutil
            return psutil.cpu_count() or 4
        except ImportError:
            import multiprocessing
            return multiprocessing.cpu_count() or 4

    def adjust_resources(self, metrics: PerformanceMetrics) -> Dict[str, int]:
        """
        Adjust resource allocation based on performance metrics.

        Args:
            metrics: Performance metrics.

        Returns:
            New resource allocation.
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
        """Get current resource allocation."""
        return self._current_allocation.copy()


def create_optimizer(strategy: str = 'bayesian', params: List[OptimizationParameter] = None) -> AnalysisOptimizer:
    """
    Create analysis optimizer.

    Args:
        strategy: Strategy name.
        params: Parameter list.

    Returns:
        Analysis optimizer instance.
    """
    try:
        strategy_enum = OptimizationStrategy(strategy.lower())
    except ValueError:
        logger.warning(f"Unknown optimization strategy: {strategy}, using default")
        strategy_enum = OptimizationStrategy.BAYESIAN

    return AnalysisOptimizer(strategy=strategy_enum, params=params)


def create_resource_manager() -> ResourceManager:
    """Create resource manager."""
    return ResourceManager()
