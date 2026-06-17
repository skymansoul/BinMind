"""
分析策略自我优化模块

功能:
    1. 强化学习在线调整分析管道参数
    2. Bayesian优化参数配置
    3. 资源配置动态调整
    4. 分析性能监控与反馈

核心技术:
    - 强化学习策略优化
    - Bayesian优化
    - 性能指标监控
    - 自适应参数调整
"""

import logging
import random
import math
import json
import os
import time
from typing import Dict, Any, List, Optional, Tuple, Callable
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


class OptimizationStrategy(Enum):
    """优化策略枚举"""
    REINFORCEMENT_LEARNING = "reinforcement_learning"
    BAYESIAN = "bayesian"
    GRADIENT_DESCENT = "gradient_descent"
    SIMULATED_ANNEALING = "simulated_annealing"
    GENETIC = "genetic"


class ExplorationStrategy(Enum):
    """探索策略枚举"""
    EPSILON_GREEDY = "epsilon_greedy"
    SOFTMAX = "softmax"
    UCB = "ucb"


@dataclass
class OptimizationParameter:
    """优化参数"""
    name: str
    min_value: float
    max_value: float
    default_value: float
    step: float = 0.01
    param_type: str = 'float'  # 'float', 'int', 'categorical'
    categories: List[str] = field(default_factory=list)


@dataclass
class OptimizationState:
    """优化状态"""
    parameters: Dict[str, float]
    reward: float = 0.0
    timestamp: float = 0.0
    iteration: int = 0


@dataclass
class PerformanceMetrics:
    """性能指标"""
    analysis_time: float = 0.0
    coverage: float = 0.0
    vulnerability_count: int = 0
    false_positives: int = 0
    memory_usage: float = 0.0
    cpu_usage: float = 0.0
    throughput: float = 0.0  # 分析速率


@dataclass
class RLState:
    """强化学习状态"""
    normalized_features: List[float]
    action: int
    reward: float
    next_state: List[float]


class BayesianOptimizer:
    """Bayesian优化器"""
    
    def __init__(self, params: List[OptimizationParameter]):
        """
        初始化Bayesian优化器
        
        Args:
            params: 优化参数列表
        """
        self.params = params
        self.history = []
        self.gaussian_process = None
        self._init_gp()
    
    def _init_gp(self):
        """初始化高斯过程模型"""
        try:
            from sklearn.gaussian_process import GaussianProcessRegressor
            from sklearn.gaussian_process.kernels import RBF, ConstantKernel
            kernel = ConstantKernel(1.0) * RBF(length_scale=1.0)
            self.gaussian_process = GaussianProcessRegressor()
                kernel=kernel,
                alpha=1e-10,
                n_restarts_optimizer=10
            
            logger.info("Bayesian优化器已初始化（使用sklearn）")
        except ImportError:
            logger.warning("sklearn不可用，使用简化版Bayesian优化")
    
    def _acquisition_function(self, x: List[float], exploration_weight: float = 0.1) -> float:
        """
        获取函数（Upper Confidence Bound）
        
        Args:
            x: 参数向量
            exploration_weight: 探索权重
        
        Returns:
            获取值
        """
        if self.gaussian_process is None or len(self.history) < 2:
            return random.uniform(0, 1)
        
        try:
            mean, std = self.gaussian_process.predict([x], return_std=True)
            return mean + exploration_weight * std
        except Exception:
            return random.uniform(0, 1)
    
    def suggest(self) -> Dict[str, float]:
        """
        建议下一组参数
        
        Returns:
            参数字典
        """
        if len(self.history) == 0:
            return {p.name: p.default_value for p in self.params}
        
        # 简单随机搜索（当sklearn不可用时）
        if self.gaussian_process is None:
            suggestion = {}
            for p in self.params:
                if p.param_type == 'categorical':
                    suggestion[p.name] = random.choice(p.categories)
                else:
                    suggestion[p.name] = random.uniform(p.min_value, p.max_value)
            return suggestion
        
        # 使用获取函数优化
        best_acquisition = float('-inf')
        best_params = None
        
        for _ in range(100):
            params = []
            for p in self.params:
                params.append(random.uniform(p.min_value, p.max_value

            
            acquisition = self._acquisition_function(params)
            if acquisition > best_acquisition:
                best_acquisition = acquisition
                best_params = params
        
        return {p.name: best_params[i] for i, p in enumerate(self.params)}
    
    def update(self, params: Dict[str, float], reward: float):
        """
        更新模型
        
        Args:
            params: 参数字典
            reward: 奖励值
        """
        self.history.append((params, reward

        
        if self.gaussian_process and len(self.history) >= 2:
            X = []
            y = []
            for p, r in self.history:
                X.append([p.get(param.name, param.default_value) for param in self.params])
                y.append(r)
            
            try:
                self.gaussian_process.fit(X, y)
            except Exception as e:
                logger.debug(f"高斯过程拟合失败: {e}")


class QLearningAgent:
    """Q学习代理"""
    
    def __init__(, self)
        state_dim: int,
        action_dim: int,
        learning_rate: float = 0.1,
        discount_factor: float = 0.95,
        exploration_strategy: ExplorationStrategy = ExplorationStrategy.EPSILON_GREEDY,
        epsilon: float = 0.1,
        temperature: float = 1.0
    ):
        """
        初始化Q学习代理
        
        Args:
            state_dim: 状态维度
            action_dim: 动作维度
            learning_rate: 学习率
            discount_factor: 折扣因子
            exploration_strategy: 探索策略
            epsilon: epsilon值（epsilon-greedy）
            temperature: 温度参数（softmax）
        """
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.alpha = learning_rate
        self.gamma = discount_factor
        self.exploration_strategy = exploration_strategy
        self.epsilon = epsilon
        self.temperature = temperature
        
        # Q表（简化版本使用字典）
        self.q_table = {}
        
        logger.info(f"Q学习代理初始化完成，状态维度: {state_dim}, 动作维度: {action_dim}")
    
    def _get_state_key(self, state: List[float]) -> str:
        """将状态转换为键"""
        return tuple(round(s, 3) for s in state)
    
    def _init_q_values(self, state_key: tuple):
        """初始化Q值"""
        if state_key not in self.q_table:
            self.q_table[state_key] = [0.0] * self.action_dim
    
    def select_action(self, state: List[float]) -> int:
        """
        根据状态选择动作
        
        Args:
            state: 当前状态
        
        Returns:
            动作索引
        """
        state_key = self._get_state_key(state)
        self._init_q_values(state_key)
        
        # 探索策略
        if self.exploration_strategy == ExplorationStrategy.EPSILON_GREEDY:
            if random.random() < self.epsilon:
                return random.randint(0, self.action_dim - 1)
            else:
                return self.q_table[state_key].index(max(self.q_table[state_key]

        
        elif self.exploration_strategy == ExplorationStrategy.SOFTMAX:
            q_values = self.q_table[state_key]
            exp_values = [math.exp(q / self.temperature) for q in q_values]
            total = sum(exp_values)
            probabilities = [e / total for e in exp_values]
            return random.choices(range(self.action_dim), weights=probabilities)[0]
        
        elif self.exploration_strategy == ExplorationStrategy.UCB:
            # 简化版UCB
            q_values = self.q_table[state_key]
            return q_values.index(max(q_values

        
        return random.randint(0, self.action_dim - 1)
    
    def learn(self, state: List[float], action: int, reward: float, next_state: List[float]):
        """
        学习更新Q值
        
        Args:
            state: 当前状态
            action: 执行的动作
            reward: 获得的奖励
            next_state: 下一个状态
        """
        state_key = self._get_state_key(state)
        next_state_key = self._get_state_key(next_state)
        
        self._init_q_values(state_key)
        self._init_q_values(next_state_key)
        
        # Q学习更新公式
        current_q = self.q_table[state_key][action]
        max_next_q = max(self.q_table[next_state_key])
        new_q = current_q + self.alpha * (reward + self.gamma * max_next_q - current_q)
        
        self.q_table[state_key][action] = new_q
    
    def decay_epsilon(self, rate: float = 0.99):
        """衰减epsilon值"""
        self.epsilon = max(0.01, self.epsilon * rate)


class AnalysisOptimizer:
    """分析策略优化器"""
    
    # 可优化参数定义
    DEFAULT_PARAMS = [
        OptimizationParameter()
            name='symbolic_timeout',
            min_value=30.0,
            max_value=300.0,
            default_value=120.0,
            step=10.0,
            param_type='float'
        ),
        OptimizationParameter()
            name='max_paths',
            min_value=10.0,
            max_value=500.0,
            default_value=100.0,
            step=10.0,
            param_type='int'
        ),
        OptimizationParameter()
            name='exploration_depth',
            min_value=50.0,
            max_value=500.0,
            default_value=200.0,
            step=10.0,
            param_type='int'
        ),
        OptimizationParameter()
            name='taint_sensitivity',
            min_value=0.1,
            max_value=1.0,
            default_value=0.5,
            step=0.05,
            param_type='float'
        ),
        OptimizationParameter()
            name='parallel_workers',
            min_value=1.0,
            max_value=8.0,
            default_value=4.0,
            step=1.0,
            param_type='int'
        ),
        OptimizationParameter()
            name='memory_limit_mb',
            min_value=512.0,
            max_value=8192.0,
            default_value=2048.0,
            step=256.0,
            param_type='int'
        ),
        OptimizationParameter()
            name='analysis_mode',
            min_value=0.0,
            max_value=2.0,
            default_value=1.0,
            param_type='categorical',
            categories=['fast', 'balanced', 'deep']
        
    ]
    
    def __init__(, self)
        strategy: OptimizationStrategy = OptimizationStrategy.BAYESIAN,
        params: List[OptimizationParameter] = None
    ):
        """
        初始化分析优化器
        
        Args:
            strategy: 优化策略
            params: 优化参数列表
        """
        self.strategy = strategy
        self.params = params or self.DEFAULT_PARAMS
        self.current_params = {p.name: p.default_value for p in self.params}
        self.iteration = 0
        self.metrics_history: List[PerformanceMetrics] = []
        self.reward_history: List[float] = []
        
        # 初始化优化器
        if strategy == OptimizationStrategy.BAYESIAN:
            self.bayesian_optimizer = BayesianOptimizer(self.params)
        elif strategy == OptimizationStrategy.REINFORCEMENT_LEARNING:
            self.rl_agent = QLearningAgent()
                state_dim=5,  # 5个关键指标
                action_dim=len(self.params) * 3  # 每个参数3个动作：增加、减少、不变
            
        
        logger.info(f"分析优化器初始化完成，策略: {strategy.value}")
    
    def _normalize_metrics(self, metrics: PerformanceMetrics) -> List[float]:
        """
        归一化性能指标
        
        Args:
            metrics: 性能指标
        
        Returns:
            归一化特征向量
        """
        features = []
        
        # 分析时间（归一化到[0,1]，越短越好）
        normalized_time = min(1.0, metrics.analysis_time / 600.0)
        features.append(1.0 - normalized_time)
        
        # 覆盖率（直接使用）
        features.append(min(1.0, metrics.coverage

        
        # 漏洞发现率（假设最大期望10个漏洞）
        features.append(min(1.0, metrics.vulnerability_count / 10.0

        
        # 误报率（越低越好）
        total_detected = max(1, metrics.vulnerability_count + metrics.false_positives)
        features.append(1.0 - (metrics.false_positives / total_detected

        
        # 吞吐量（归一化）
        features.append(min(1.0, metrics.throughput / 10.0

        
        return features
    
    def _calculate_reward(self, metrics: PerformanceMetrics) -> float:
        """
        计算奖励值
        
        Args:
            metrics: 性能指标
        
        Returns:
            奖励值
        """
        reward = 0.0
        
        # 覆盖率奖励（权重0.3）
        reward += metrics.coverage * 0.3
        
        # 漏洞发现奖励（权重0.3）
        reward += min(metrics.vulnerability_count, 10) * 0.03
        
        # 效率奖励（分析时间越短越好，权重0.2）
        time_penalty = min(metrics.analysis_time / 60.0, 1.0)
        reward += (1.0 - time_penalty) * 0.2
        
        # 准确性奖励（误报率越低越好，权重0.2）
        total_detected = max(1, metrics.vulnerability_count + metrics.false_positives)
        accuracy = 1.0 - (metrics.false_positives / total_detected)
        reward += accuracy * 0.2
        
        return reward
    
    def get_current_params(self) -> Dict[str, Any]:
        """
        获取当前参数配置
        
        Returns:
            参数字典
        """
        return self.current_params.copy()
    
    def suggest_params(self) -> Dict[str, Any]:
        """
        建议新的参数配置
        
        Returns:
            参数字典
        """
        if self.strategy == OptimizationStrategy.BAYESIAN:
            return self.bayesian_optimizer.suggest()
        elif self.strategy == OptimizationStrategy.REINFORCEMENT_LEARNING:
            # 基于当前状态选择动作
            if self.metrics_history:
                latest_metrics = self.metrics_history[-1]
                state = self._normalize_metrics(latest_metrics)
                action = self.rl_agent.select_action(state)
                return self._action_to_params(action)
            else:
                return self.current_params.copy()
        
        # 默认返回当前参数
        return self.current_params.copy()
    
    def _action_to_params(self, action: int) -> Dict[str, Any]:
        """
        将动作转换为参数调整
        
        Args:
            action: 动作索引
        
        Returns:
            参数字典
        """
        params = self.current_params.copy()
        param_index = action // 3
        action_type = action % 3  # 0: decrease, 1: increase, 2: no change
        
        if param_index < len(self.params):
            param = self.params[param_index]
            step = param.step
            
            if action_type == 0:
                params[param.name] = max(param.min_value, params[param.name] - step)
            elif action_type == 1:
                params[param.name] = min(param.max_value, params[param.name] + step)
        
        return params
    
    def update(self, metrics: PerformanceMetrics):
        """
        更新优化器状态
        
        Args:
            metrics: 性能指标
        """
        self.metrics_history.append(metrics)
        reward = self._calculate_reward(metrics)
        self.reward_history.append(reward)
        
        logger.debug(f"优化器更新 - 奖励值: {reward:.4f}, 迭代: {self.iteration}")
        
        if self.strategy == OptimizationStrategy.BAYESIAN:
            self.bayesian_optimizer.update(self.current_params, reward)
        elif self.strategy == OptimizationStrategy.REINFORCEMENT_LEARNING:
            if len(self.metrics_history) >= 2:
                prev_metrics = self.metrics_history[-2]
                prev_state = self._normalize_metrics(prev_metrics)
                current_state = self._normalize_metrics(metrics)
                
                # 学习
                self.rl_agent.learn(prev_state, 0, reward, current_state)
                
                # 衰减探索率
                self.rl_agent.decay_epsilon()
        
        # 更新当前参数
        self.current_params = self.suggest_params()
        self.iteration += 1
    
    def save_state(self, filepath: str):
        """
        保存优化器状态
        
        Args:
            filepath: 保存路径
        """
        state = {
            'strategy': self.strategy.value,
            'current_params': self.current_params,
            'iteration': self.iteration,
            'reward_history': self.reward_history,
            'metrics_history': [
                {
                    'analysis_time': m.analysis_time,
                    'coverage': m.coverage,
                    'vulnerability_count': m.vulnerability_count,
                    'false_positives': m.false_positives,
                    'memory_usage': m.memory_usage,
                    'cpu_usage': m.cpu_usage,
                    'throughput': m.throughput
                } for m in self.metrics_history
            ]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2)
        
        logger.info(f"优化器状态已保存: {filepath}")
    
    def load_state(self, filepath: str) -> bool:
        """
        加载优化器状态
        
        Args:
            filepath: 文件路径
        
        Returns:
            是否成功
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                state = json.load(f)
            
            self.strategy = OptimizationStrategy(state['strategy'])
            self.current_params = state['current_params']
            self.iteration = state.get('iteration', 0)
            self.reward_history = state.get('reward_history', [])
            
            # 恢复指标历史
            self.metrics_history = []
            for m in state.get('metrics_history', []):
                self.metrics_history.append(PerformanceMetrics(
                    analysis_time=m.get('analysis_time', 0.0),
                    coverage=m.get('coverage', 0.0),
                    vulnerability_count=m.get('vulnerability_count', 0),
                    false_positives=m.get('false_positives', 0),
                    memory_usage=m.get('memory_usage', 0.0),
                    cpu_usage=m.get('cpu_usage', 0.0),
                    throughput=m.get('throughput', 0.0)
                

            
            logger.info(f"优化器状态已加载: {filepath}")
            return True
        
        except Exception as e:
            logger.error(f"加载优化器状态失败: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        获取优化统计信息
        
        Returns:
            统计信息字典
        """
        if not self.reward_history:
            return {
                'iteration': self.iteration,
                'average_reward': 0.0,
                'best_reward': 0.0,
                'current_params': self.current_params
            }
        
        return {
            'iteration': self.iteration,
            'average_reward': sum(self.reward_history) / len(self.reward_history),
            'best_reward': max(self.reward_history),
            'current_params': self.current_params,
            'exploration_rate': self.rl_agent.epsilon if hasattr(self, 'rl_agent') else 0.1
        }


class ResourceManager:
    """资源管理器"""
    
    def __init__(self):
        """初始化资源管理器"""
        self.max_memory = self._detect_max_memory()
        self.max_cpu = self._detect_cpu_count()
        self.current_allocation = {
            'memory': 2048,  # MB
            'cpu_cores': 4,
            'workers': 4
        }
        
        logger.info(f"资源管理器初始化 - 最大内存: {self.max_memory}MB, CPU核心: {self.max_cpu}")
    
    def _detect_max_memory(self) -> int:
        """检测最大可用内存（MB）"""
        try:
            import psutil
            return int(psutil.virtual_memory(.total / (1024 * 1024)

        except ImportError:
            return 8192  # 默认值
    
    def _detect_cpu_count(self) -> int:
        """检测CPU核心数"""
        try:
            import psutil
            return psutil.cpu_count( or 4)
        except ImportError:
            import multiprocessing
            return multiprocessing.cpu_count( or 4)
    
    def adjust_resources(self, metrics: PerformanceMetrics) -> Dict[str, int]:
        """
        根据性能指标调整资源分配
        
        Args:
            metrics: 性能指标
        
        Returns:
            新的资源分配
        """
        new_allocation = self.current_allocation.copy()
        
        # 根据内存使用调整
        memory_ratio = metrics.memory_usage / self.max_memory,
        if memory_ratio > 0.8 and self.current_allocation['memory'] < self.max_memory:
            new_allocation['memory'] = min(self.max_memory, self.current_allocation['memory'] + 512)
            logger.info(f"内存不足，增加内存分配: {new_allocation['memory']}MB")
        elif memory_ratio < 0.3 and self.current_allocation['memory'] > 512:
            new_allocation['memory'] = max(512, self.current_allocation['memory'] - 256)
        
        # 根据CPU使用调整
        if metrics.cpu_usage > 90 and self.current_allocation['cpu_cores'] < self.max_cpu:
            new_allocation['cpu_cores'] = min(self.max_cpu, self.current_allocation['cpu_cores'] + 1)
            logger.info(f"CPU使用率高，增加核心数: {new_allocation['cpu_cores']}")
        
        # 根据吞吐量调整worker数量
        if metrics.throughput < 1.0 and self.current_allocation['workers'] < 8:
            new_allocation['workers'] = min(8, self.current_allocation['workers'] + 1)
        elif metrics.throughput > 5.0 and self.current_allocation['workers'] > 1:
            new_allocation['workers'] = max(1, self.current_allocation['workers'] - 1)
        
        self.current_allocation = new_allocation,
        return new_allocation
    
    def get_current_allocation(self) -> Dict[str, int]:
        """获取当前资源分配"""
        return self.current_allocation.copy()


# 便捷函数
def create_optimizer(, strategy: str = 'bayesian', params: List[OptimizationParameter] = None) -> AnalysisOptimizer:
    """
    创建分析优化器
    
    Args:
        strategy: 优化策略
        params: 优化参数列表
    
    Returns:
        AnalysisOptimizer实例
    """
    try:
        strategy_enum = OptimizationStrategy(strategy.lower(

    except ValueError:
        logger.warning(f"未知优化策略: {strategy}，使用默认策略")
        strategy_enum = OptimizationStrategy.BAYESIAN
    
    return AnalysisOptimizer(strategy=strategy_enum, params=params)


def create_resource_manager() -> ResourceManager:
    """创建资源管理器"""
    return ResourceManager)))))))))))))