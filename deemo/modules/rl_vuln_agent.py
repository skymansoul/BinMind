#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
强化学习自主漏洞挖掘代理模块

功能：
1. 在模拟环境中观察状态（内存、寄存器）
2. 自主决定输入突变策略
3. 最大化崩溃/漏洞发现奖励
4. 学习有效的漏洞挖掘策略

数据流：
1. 输入：二进制程序、初始输入、执行环境
2. 处理：RL代理观察状态 → 选择动作（输入突变）→ 执行程序 → 获得奖励 → 更新策略
3. 输出：发现的漏洞、触发输入、利用路径

与其他模块的交互：
- 与符号执行模块协作获取路径信息
- 与崩溃分析模块协作分析漏洞
- 与模糊测试模块共享输入生成策略
"""

import logging
import random
import json
import os
import time
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

# 尝试导入可选依赖
TENSORFLOW_AVAILABLE = False
PYTORCH_AVAILABLE = False

try:
    import tensorflow as tf
    TENSORFLOW_AVAILABLE = True
except ImportError:
    logger.warning("TensorFlow未安装")

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    PYTORCH_AVAILABLE = True
except ImportError:
    logger.warning("PyTorch未安装")
    nn = None


class VulnerabilityType(Enum):
    """漏洞类型"""
    STACK_OVERFLOW = "stack_overflow"
    HEAP_OVERFLOW = "heap_overflow"
    USE_AFTER_FREE = "use_after_free"
    BUFFER_OVERFLOW = "buffer_overflow"
    FORMAT_STRING = "format_string"
    INTEGER_OVERFLOW = "integer_overflow"
    NULL_POINTER = "null_pointer"
    TYPE_CONFUSION = "type_confusion"
    UNSAFE_UNLINK = "unsafe_unlink"
    RACE_CONDITION = "race_condition"
    MEMORY_CORRUPTION = "memory_corruption"


class MutateAction(Enum):
    """突变动作"""
    INSERT_BYTE = "insert_byte"
    DELETE_BYTE = "delete_byte"
    FLIP_BIT = "flip_bit"
    OVERWRITE_BYTE = "overwrite_byte"
    REPEAT_PAYLOAD = "repeat_payload"
    APPEND_PATTERN = "append_pattern"
    APPEND_BYTE = "append_byte"
    SET_MAX_VALUE = "set_max_value"
    RANDOMIZE = "randomize"
    SHRINK = "shrink"
    EXPAND = "expand"
    REPLACE_SEGMENT = "replace_segment"


class ExecutionStatus(Enum):
    """执行状态"""
    NORMAL = "normal"
    CRASH = "crash"
    TIMEOUT = "timeout"
    ERROR = "error"
    VULNERABILITY = "vulnerability"


@dataclass
class ExecutionState:
    """执行状态"""
    pc: int = 0
    sp: int = 0
    bp: int = 0
    registers: Dict[str, int] = field(default_factory=dict)
    memory_snapshot: Dict[int, bytes] = field(default_factory=dict)
    status: ExecutionStatus = ExecutionStatus.NORMAL
    crash_reason: str = ""
    crash_address: int = 0
    coverage: float = 0.0
    new_coverage: bool = False
    depth: int = 0


@dataclass
class RLAction:
    """强化学习动作"""
    action_type: MutateAction
    position: Optional[int] = None
    value: Optional[int] = None
    length: Optional[int] = None
    pattern: Optional[str] = None


@dataclass
class RLState:
    """强化学习状态"""
    input_length: int
    input_entropy: float
    coverage: float
    depth: int
    status: ExecutionStatus
    crash_count: int
    unique_crashes: int
    new_coverage: bool = False
    recent_actions: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityDiscovery:
    """漏洞发现结果"""
    vulnerability_type: VulnerabilityType
    input_payload: bytes
    crash_address: int
    registers: Dict[str, int]
    stack_trace: List[str]
    confidence: float
    timestamp: float = 0.0


@dataclass
class RLTrainingResult:
    """强化学习训练结果"""
    total_episodes: int
    successful_episodes: int
    discovered_vulnerabilities: List[VulnerabilityDiscovery]
    best_strategy: List[RLAction]
    total_crashes: int
    unique_crashes: int
    total_unique_crashes: int = 0
    coverage: float = 0.0
    reward_history: List[float] = field(default_factory=list)
    average_reward: float = 0.0
    analysis_summary: Dict[str, Any] = field(default_factory=dict)


class RewardCalculator(ABC):
    """奖励计算器抽象基类"""

    @abstractmethod
    def calculate(self, state: RLState, action: RLAction, next_state: RLState, 
                  crash_info: Optional[Dict[str, Any]] = None) -> float:
        """
        计算奖励
        
        Args:
            state: 当前状态
            action: 执行的动作
            next_state: 下一个状态
            crash_info: 崩溃信息
        
        Returns:
            奖励值
        """
        pass


class VulnRewardCalculator(RewardCalculator):
    """漏洞挖掘奖励计算器"""

    def __init__(self, crash_reward: float = 100.0, coverage_reward: float = 10.0, 
                 unique_crash_reward: float = 500.0, timeout_penalty: float = -10.0):
        self.crash_reward = crash_reward
        self.coverage_reward = coverage_reward
        self.unique_crash_reward = unique_crash_reward
        self.timeout_penalty = timeout_penalty

    def calculate(self, state: RLState, action: RLAction, next_state: RLState,
                  crash_info: Optional[Dict[str, Any]] = None) -> float:
        """计算奖励"""
        reward = -0.1  # 基础惩罚，鼓励高效探索
        
        # 覆盖奖励
        coverage_gain = next_state.coverage - state.coverage
        if coverage_gain > 0:
            reward += coverage_gain * self.coverage_reward
        
        # 新路径奖励
        if next_state.new_coverage:
            reward += self.coverage_reward * 2
        
        # 深度奖励
        if next_state.depth > state.depth:
            reward += next_state.depth * 0.1
        
        # 崩溃奖励
        if next_state.status == ExecutionStatus.CRASH:
            reward += self.crash_reward
            
            # 唯一崩溃奖励
            if next_state.unique_crashes > state.unique_crashes:
                reward += self.unique_crash_reward
        
        # 漏洞奖励
        if next_state.status == ExecutionStatus.VULNERABILITY:
            reward += self.unique_crash_reward * 2
        
        # 超时惩罚
        if next_state.status == ExecutionStatus.TIMEOUT:
            reward += self.timeout_penalty
        
        # 错误惩罚
        if next_state.status == ExecutionStatus.ERROR:
            reward -= 5.0
        
        return reward


class ProgramSimulator(ABC):
    """程序模拟器抽象基类"""

    @abstractmethod
    def execute(self, input_data: bytes) -> ExecutionState:
        """
        执行程序并返回状态
        
        Args:
            input_data: 输入数据
        
        Returns:
            执行状态
        """
        pass

    @abstractmethod
    def reset(self):
        """重置模拟器"""
        pass


class MockProgramSimulator(ProgramSimulator):
    """模拟程序模拟器"""

    def __init__(self, target_binary: str = ""):
        self.target_binary = target_binary
        self.coverage = 0.0
        self.crash_count = 0
        self.unique_crashes = set()
        self.known_vulnerabilities = [
            VulnerabilityType.BUFFER_OVERFLOW,
            VulnerabilityType.USE_AFTER_FREE,
            VulnerabilityType.FORMAT_STRING
        ]

    def execute(self, input_data: bytes) -> ExecutionState:
        """执行程序并返回状态"""
        state = ExecutionState()
        
        # 模拟执行
        input_len = len(input_data)
        
        # 根据输入特征决定执行结果
        if input_len > 100 and b'A' * 50 in input_data:
            # 模拟缓冲区溢出
            state.status = ExecutionStatus.CRASH
            state.crash_reason = "Buffer overflow detected"
            state.crash_address = 0x7ffffff000 + (input_len % 0x100)
            self.crash_count += 1
            crash_hash = hashlib.md5(input_data[:100]).hexdigest()
            self.unique_crashes.add(crash_hash)
        elif b'%s' in input_data or b'%x' in input_data:
            # 模拟格式字符串漏洞
            state.status = ExecutionStatus.CRASH
            state.crash_reason = "Format string vulnerability"
            state.crash_address = 0x401000
            self.crash_count += 1
            crash_hash = hashlib.md5(input_data[:50]).hexdigest()
            self.unique_crashes.add(crash_hash)
        elif any(b'free' in input_data.lower() for _ in range(2)):
            # 模拟UAF
            state.status = ExecutionStatus.VULNERABILITY
            state.crash_reason = "Use-after-free vulnerability"
            self.crash_count += 1
            crash_hash = hashlib.md5(input_data).hexdigest()
            self.unique_crashes.add(crash_hash)
        elif input_len > 500:
            # 模拟超时
            state.status = ExecutionStatus.TIMEOUT
        else:
            state.status = ExecutionStatus.NORMAL
            # 随机增加覆盖率
            if random.random() < 0.3:
                self.coverage = min(1.0, self.coverage + 0.05)
        
        state.coverage = self.coverage
        state.depth = min(100, input_len)
        state.registers = {'pc': 0x401000 + input_len, 'sp': 0x7ffffff000 - input_len}
        
        return state

    def reset(self):
        """重置模拟器"""
        self.coverage = 0.0
        self.crash_count = 0
        self.unique_crashes = set()


class InputMutator:
    """输入突变器"""

    def __init__(self):
        self.patterns = {
            'nopsled': b'\x90' * 100,
            'cyclic': self._generate_cyclic(1000),
            'buffer': b'A' * 1000,
            'format': b'%x.' * 50,
            'shellcode': b'\x48\x31\xc0\x48\x89\xc2\x48\x89\xc6\x48\x8d\x3d\x00\x00\x00\x00\xff\xd6',
            'rop_chain': b'\x00' * 8 * 20
        }

    def _generate_cyclic(self, length: int) -> bytes:
        """生成循环模式"""
        pattern = []
        for i in range(length):
            pattern.append(ord('a') + (i % 26))
        return bytes(pattern)

    def random_mutate(self, input_data: bytes) -> bytes:
        """随机突变输入"""
        action_type = random.choice(list(MutateAction))
        action = RLAction(
            action_type=action_type,
            position=random.randint(0, len(input_data) if input_data else 0),
            value=random.randint(0, 255),
            length=random.randint(1, 50),
            pattern=random.choice(list(self.patterns.keys()))
        )
        return self.mutate(input_data, action)

    def mutate(self, input_data: bytes, action) -> bytes:
        """
        根据动作突变输入
        
        Args:
            input_data: 原始输入
            action: 突变动作 (RLAction 或 MutateAction)
        
        Returns:
            突变后的输入
        """
        # 支持直接传入 MutateAction 枚举
        if isinstance(action, MutateAction):
            action = RLAction(action_type=action)
        
        data = bytearray(input_data)
        length = len(data)
        
        if action.action_type == MutateAction.INSERT_BYTE:
            pos = action.position % length if length > 0 and action.position is not None else random.randint(0, max(0, length - 1)) if length > 0 else 0
            value = action.value % 256 if action.value is not None else random.randint(0, 255)
            data.insert(pos, value)
        
        elif action.action_type == MutateAction.DELETE_BYTE:
            if length > 1:
                pos = action.position % length if action.position is not None else random.randint(0, length - 1)
                del data[pos]
        
        elif action.action_type == MutateAction.FLIP_BIT:
            if length > 0:
                pos = action.position % length if action.position is not None else random.randint(0, length - 1)
                bit_pos = (action.value or 0) % 8
                data[pos] ^= (1 << bit_pos)
        
        elif action.action_type == MutateAction.OVERWRITE_BYTE:
            if length > 0:
                pos = action.position % length if action.position is not None else random.randint(0, length - 1)
                value = action.value % 256 if action.value is not None else random.randint(0, 255)
                data[pos] = value
        
        elif action.action_type == MutateAction.REPEAT_PAYLOAD:
            repeat_times = min(10, action.length or 2)
            data = data * repeat_times
        
        elif action.action_type == MutateAction.APPEND_BYTE:
            value = action.value % 256 if action.value else random.randint(0, 255)
            data.append(value)
        
        elif action.action_type == MutateAction.APPEND_PATTERN:
            pattern_name = action.pattern or 'buffer'
            pattern = self.patterns.get(pattern_name, self.patterns['buffer'])
            append_len = min(500, action.length or 100)
            data.extend(pattern[:append_len])
        
        elif action.action_type == MutateAction.RANDOMIZE:
            rand_len = min(len(data), action.length or 10)
            for i in range(rand_len):
                if length > 0:
                    pos = random.randint(0, length - 1)
                    data[pos] = random.randint(0, 255)
        
        elif action.action_type == MutateAction.SHRINK:
            target_len = max(1, len(data) - (action.length or 10))
            data = data[:target_len]
        
        elif action.action_type == MutateAction.EXPAND:
            expand_len = action.length or 50
            data.extend(bytes([random.randint(0, 255) for _ in range(expand_len)]))
        
        elif action.action_type == MutateAction.REPLACE_SEGMENT:
            if length > 0:
                start = action.position % length if action.position else 0
                seg_len = min(action.length or 20, length - start)
                replacement = bytes([random.randint(0, 255) for _ in range(seg_len)])
                data[start:start+seg_len] = replacement
        
        elif action.action_type == MutateAction.SET_MAX_VALUE:
            if length > 0:
                for i in range(length):
                    data[i] = 0xFF
        
        return bytes(data)


class RLAgent(ABC):
    """强化学习代理抽象基类"""

    @abstractmethod
    def select_action(self, state: RLState) -> RLAction:
        """
        选择动作
        
        Args:
            state: 当前状态
        
        Returns:
            选择的动作
        """
        pass

    @abstractmethod
    def learn(self, state: RLState, action: RLAction, reward: float, 
              next_state: RLState, done: bool):
        """
        更新策略
        
        Args:
            state: 当前状态
            action: 执行的动作
            reward: 获得的奖励
            next_state: 下一个状态
            done: 是否结束
        """
        pass


class QLearningAgent(RLAgent):
    """Q学习代理"""

    def __init__(self, actions: List[MutateAction], learning_rate: float = 0.1,
                 discount_factor: float = 0.99, exploration_rate: float = 1.0,
                 exploration_decay: float = 0.995, min_exploration: float = 0.01,
                 alpha: float = None, gamma: float = None, epsilon: float = None):
        # 支持别名参数
        if alpha is not None:
            learning_rate = alpha
        if gamma is not None:
            discount_factor = gamma
        if epsilon is not None:
            exploration_rate = epsilon
        self.actions = actions
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.exploration_rate = exploration_rate
        self.exploration_decay = exploration_decay
        self.min_exploration = min_exploration
        self.q_table = defaultdict(lambda: {a: 0.0 for a in actions})

    def get_state_key(self, state: RLState) -> str:
        """生成状态的唯一键"""
        return json.dumps({
            'input_length': state.input_length,
            'coverage': round(state.coverage, 2),
            'status': state.status.value,
            'crash_count': state.crash_count
        })

    def select_action(self, state):
        """选择动作（ε-贪心策略）
        
        支持传入 RLState 或 tuple
        返回 MutateAction 或 RLAction
        """
        # 将 tuple 转换为 RLState
        if isinstance(state, tuple):
            state = RLState(
                input_length=0,
                input_entropy=state[0] if len(state) > 0 else 0.0,
                coverage=state[1] if len(state) > 1 else 0.0,
                depth=state[2] if len(state) > 2 else 0,
                status=ExecutionStatus.NORMAL,
                crash_count=state[3] if len(state) > 3 else 0,
                unique_crashes=0
            )
        
        if random.random() < self.exploration_rate:
            return self._random_action_raw()
        
        state_key = self.get_state_key(state)
        q_values = self.q_table[state_key]
        best_action = max(q_values, key=q_values.get)
        
        return best_action
    
    def _random_action_raw(self) -> MutateAction:
        """生成随机 MutateAction"""
        return random.choice(self.actions)

    def _random_action(self) -> RLAction:
        """生成随机动作"""
        action_type = random.choice(self.actions)
        return self._create_action(action_type)

    def _create_action(self, action_type: MutateAction) -> RLAction:
        """创建动作对象"""
        return RLAction(
            action_type=action_type,
            position=random.randint(0, 100),
            value=random.randint(0, 255),
            length=random.randint(1, 50),
            pattern=random.choice(['buffer', 'format', 'cyclic', 'nopsled'])
        )

    def learn(self, state, action, reward: float,
              next_state=None, done: bool = False):
        """更新Q表"""
        # 支持传入 MutateAction
        action_type = action.action_type if isinstance(action, RLAction) else action
        
        state_key = self.get_state_key(state)
        next_state_key = self.get_state_key(next_state) if next_state else state_key
        
        old_value = self.q_table[state_key][action_type]
        
        if done:
            target = reward
        else:
            max_next_q = max(self.q_table[next_state_key].values())
            target = reward + self.discount_factor * max_next_q
        
        self.q_table[state_key][action_type] = old_value + \
            self.learning_rate * (target - old_value)
        
        self.exploration_rate = max(self.min_exploration, 
                                    self.exploration_rate * self.exploration_decay)


class DQNAgent(RLAgent):
    """深度Q网络代理"""

    def __init__(self, actions: List[MutateAction], state_size: int = 6, 
                 learning_rate: float = 0.001, discount_factor: float = 0.99):
        self.actions = actions
        self.discount_factor = discount_factor
        self.exploration_rate = 1.0
        self.exploration_decay = 0.995
        self.min_exploration = 0.01
        
        if PYTORCH_AVAILABLE:
            self.model = self._build_model(state_size, len(actions))
            self.optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)
            self.criterion = nn.MSELoss()
        else:
            self.use_fallback = True
            logger.warning("PyTorch不可用，使用Q学习回退")
            self.q_table = defaultdict(lambda: {a: 0.0 for a in actions})

    def _build_model(self, state_size: int, action_size: int) -> "nn.Module":
        """构建DQN模型"""
        model = nn.Sequential(
            nn.Linear(state_size, 64),
            nn.ReLU(),
            nn.Linear(64, 64),
            nn.ReLU(),
            nn.Linear(64, action_size)
        )
        return model

    def select_action(self, state):
        """选择动作
        
        支持传入 RLState 或 tuple
        返回 MutateAction
        """
        # 将 tuple 转换为 RLState
        if isinstance(state, tuple):
            state = RLState(
                input_length=0,
                input_entropy=state[0] if len(state) > 0 else 0.0,
                coverage=state[1] if len(state) > 1 else 0.0,
                depth=state[2] if len(state) > 2 else 0,
                status=ExecutionStatus.NORMAL,
                crash_count=state[3] if len(state) > 3 else 0,
                unique_crashes=0
            )
        
        if self.use_fallback:
            return self._fallback_select_action_raw(state)
        
        if random.random() < self.exploration_rate:
            return random.choice(self.actions)
        
        state_tensor = self._state_to_tensor(state)
        with torch.no_grad():
            q_values = self.model(state_tensor)
            action_idx = torch.argmax(q_values).item()
        
        return self.actions[action_idx]
    
    def _fallback_select_action_raw(self, state: RLState) -> MutateAction:
        """回退动作选择"""
        if random.random() < self.exploration_rate:
            return random.choice(self.actions)
        
        state_key = self._get_fallback_state_key(state)
        q_values = self.q_table[state_key]
        return max(q_values, key=q_values.get)

    def _fallback_select_action(self, state: RLState) -> RLAction:
        """回退动作选择"""
        if random.random() < self.exploration_rate:
            return self._random_action()
        
        state_key = self._get_fallback_state_key(state)
        q_values = self.q_table[state_key]
        best_action = max(q_values, key=q_values.get)
        return self._create_action(best_action)

    def _get_fallback_state_key(self, state: RLState) -> str:
        """生成回退状态键"""
        return json.dumps({
            'coverage': round(state.coverage, 2),
            'status': state.status.value,
            'crash_count': state.crash_count
        })

    def _random_action(self) -> RLAction:
        """生成随机动作"""
        action_type = random.choice(self.actions)
        return self._create_action(action_type)

    def _create_action(self, action_type: MutateAction) -> RLAction:
        """创建动作对象"""
        return RLAction(
            action_type=action_type,
            position=random.randint(0, 100),
            value=random.randint(0, 255),
            length=random.randint(1, 50),
            pattern=random.choice(['buffer', 'format', 'cyclic', 'nopsled'])
        )

    def _state_to_tensor(self, state: RLState) -> "torch.Tensor":
        """将状态转换为张量"""
        features = [
            state.input_length / 1000.0,
            state.input_entropy / 8.0,
            state.coverage,
            state.depth / 100.0,
            1.0 if state.status == ExecutionStatus.CRASH else 0.0,
            state.crash_count / 100.0
        ]
        return torch.tensor(features, dtype=torch.float32).unsqueeze(0)

    def learn(self, state, action, reward: float,
              next_state=None, done: bool = False):
        """更新策略"""
        # 支持传入 MutateAction
        action_type = action.action_type if isinstance(action, RLAction) else action
        
        if self.use_fallback:
            self._fallback_learn(state, action_type, reward, next_state, done)
            return
        
        if not PYTORCH_AVAILABLE:
            return
        
        self.optimizer.zero_grad()
        
        state_tensor = self._state_to_tensor(state)
        next_state_tensor = self._state_to_tensor(next_state) if next_state else state_tensor
        
        q_values = self.model(state_tensor)
        next_q_values = self.model(next_state_tensor)
        
        action_idx = self.actions.index(action_type)
        target_q = q_values.clone()
        
        if done:
            target_q[0, action_idx] = reward
        else:
            target_q[0, action_idx] = reward + self.discount_factor * torch.max(next_q_values)
        
        loss = self.criterion(q_values, target_q)
        loss.backward()
        self.optimizer.step()
        
        self.exploration_rate = max(self.min_exploration,
                                    self.exploration_rate * self.exploration_decay)

    def _fallback_learn(self, state, action, reward: float,
                        next_state=None, done: bool = False):
        """回退学习方法"""
        state_key = self._get_fallback_state_key(state)
        next_state_key = self._get_fallback_state_key(next_state) if next_state else state_key
        
        old_value = self.q_table[state_key][action]
        
        if done:
            target = reward
        else:
            max_next_q = max(self.q_table[next_state_key].values())
            target = reward + self.discount_factor * max_next_q
        
        self.q_table[state_key][action.action_type] = old_value + 0.1 * (target - old_value)
        
        self.exploration_rate = max(self.min_exploration,
                                    self.exploration_rate * self.exploration_decay)


class RLVulnAgent:
    """
    强化学习自主漏洞挖掘代理
    
    功能：
    1. 观察程序执行状态（内存、寄存器）
    2. 自主决定输入突变策略
    3. 最大化崩溃/漏洞发现奖励
    4. 学习有效的漏洞挖掘策略
    """

    def __init__(self, target_binary: str = "", agent_type: str = "qlearning"):
        """
        初始化漏洞挖掘代理
        
        Args:
            target_binary: 目标二进制文件
            agent_type: 代理类型 ("qlearning" 或 "dqn")
        """
        self.target_binary = target_binary
        self.agent_type = agent_type
        self.actions = list(MutateAction)
        self.reward_calculator = VulnRewardCalculator()
        self.mutator = InputMutator()
        self.simulator = MockProgramSimulator(target_binary)
        
        if agent_type == "qlearning":
            self.agent = QLearningAgent(self.actions)
        else:
            self.agent = DQNAgent(self.actions)
        
        self.discovered_vulnerabilities: List[VulnerabilityDiscovery] = []
        self.crash_signatures = set()
        self.best_input: Optional[bytes] = None
        self.best_reward = float('-inf')
        self.best_strategy: List[RLAction] = []
        
        logger.info(f"使用 {agent_type} 强化学习代理")

    def _calculate_reward(self, state=None, action=None, next_state=None, 
                         crash=False, new_crash=False, coverage=0.0, 
                         prev_coverage=0.0, input_entropy=0.0) -> float:
        """计算奖励（便捷方法）
        
        支持两种调用方式:
        1. _calculate_reward(state, action, next_state)
        2. _calculate_reward(crash=..., new_crash=..., coverage=...)
        """
        # 方式1: 传入 RLState 对象
        if isinstance(state, RLState) and isinstance(next_state, RLState):
            return self.reward_calculator.calculate(state, action, next_state)
        
        # 方式2: 传入简单参数（用于测试）
        reward = 0.0
        if crash:
            reward += 100.0
            if new_crash:
                reward += 500.0
        if coverage > prev_coverage:
            reward += (coverage - prev_coverage) * 100
        reward += input_entropy * 0.1
        return reward

    def collect_statistics(self) -> Dict[str, Any]:
        """收集统计信息"""
        return {
            'total_inputs_tested': 0,
            'crash_count': len(self.crash_signatures),
            'unique_crash_count': len(self.crash_signatures),
            'total_crashes': len(self.crash_signatures),
            'unique_crashes': len(self.crash_signatures),
            'discovered_vulnerabilities': len(self.discovered_vulnerabilities),
            'coverage': 0.0,
            'average_reward': self.best_reward if self.best_reward != float('-inf') else 0.0,
            'best_reward': self.best_reward,
            'agent_type': self.agent_type,
            'target_binary': self.target_binary
        }

    def _calculate_entropy(self, data: bytes) -> float:
        """计算输入数据的熵"""
        if not data:
            return 0.0
        
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        
        entropy = 0.0
        total = len(data)
        for count in freq.values():
            prob = count / total
            entropy -= prob * (prob ** 0.5)
        
        return entropy

    def _create_rl_state(self, execution_state: ExecutionState, input_data: bytes, 
                         crash_count: int, unique_crashes: int) -> RLState:
        """创建RL状态"""
        return RLState(
            input_length=len(input_data),
            input_entropy=self._calculate_entropy(input_data),
            coverage=execution_state.coverage,
            depth=execution_state.depth,
            status=execution_state.status,
            crash_count=crash_count,
            unique_crashes=unique_crashes,
            recent_actions=[]
        )

    def _detect_vulnerability(self, execution_state: ExecutionState, 
                              input_data: bytes) -> Optional[VulnerabilityDiscovery]:
        """检测漏洞"""
        if execution_state.status not in [ExecutionStatus.CRASH, ExecutionStatus.VULNERABILITY]:
            return None
        
        crash_hash = hashlib.md5(input_data).hexdigest()
        if crash_hash in self.crash_signatures:
            return None
        
        self.crash_signatures.add(crash_hash)
        
        # 根据崩溃原因推断漏洞类型
        reason = execution_state.crash_reason.lower()
        vuln_type = VulnerabilityType.MEMORY_CORRUPTION
        
        if 'buffer overflow' in reason:
            vuln_type = VulnerabilityType.BUFFER_OVERFLOW
        elif 'use-after-free' in reason:
            vuln_type = VulnerabilityType.USE_AFTER_FREE
        elif 'format' in reason:
            vuln_type = VulnerabilityType.FORMAT_STRING
        
        return VulnerabilityDiscovery(
            vulnerability_type=vuln_type,
            input_payload=input_data,
            crash_address=execution_state.crash_address,
            registers=execution_state.registers,
            stack_trace=[],
            confidence=0.85,
            timestamp=time.time()
        )

    def train(self, episodes: int = 1000, max_steps: int = 50, 
              initial_input: Optional[bytes] = None, verbose: bool = False):
        """
        训练强化学习代理
        
        Args:
            episodes: 训练回合数
            max_steps: 每回合最大步数
            initial_input: 初始输入
            verbose: 是否输出详细信息
        """
        total_rewards = []
        crash_count = 0
        unique_crash_count = 0
        
        for episode in range(episodes):
            # 重置状态
            current_input = initial_input or b'A' * 20
            self.simulator.reset()
            episode_reward = 0
            episode_crashes = 0
            episode_strategy = []
            
            for step in range(max_steps):
                # 执行当前输入
                exec_state = self.simulator.execute(current_input)
                
                # 创建RL状态
                rl_state = self._create_rl_state(exec_state, current_input, 
                                                 crash_count, unique_crash_count)
                
                # 选择动作
                action = self.agent.select_action(rl_state)
                episode_strategy.append(action)
                
                # 突变输入
                mutated_input = self.mutator.mutate(current_input, action)
                
                # 执行突变后的输入
                next_exec_state = self.simulator.execute(mutated_input)
                
                # 更新统计
                if next_exec_state.status == ExecutionStatus.CRASH:
                    episode_crashes += 1
                    crash_count += 1
                    if next_exec_state.crash_reason not in self.crash_signatures:
                        unique_crash_count += 1
                
                # 检测漏洞
                vuln = self._detect_vulnerability(next_exec_state, mutated_input)
                if vuln:
                    self.discovered_vulnerabilities.append(vuln)
                    if verbose:
                        logger.info(f"发现漏洞: {vuln.vulnerability_type.value}")
                
                # 创建下一状态
                next_rl_state = self._create_rl_state(next_exec_state, mutated_input,
                                                      crash_count, unique_crash_count)
                
                # 计算奖励
                reward = self.reward_calculator.calculate(rl_state, action, next_rl_state)
                episode_reward += reward
                
                # 更新最佳策略
                if episode_reward > self.best_reward:
                    self.best_reward = episode_reward
                    self.best_input = mutated_input
                    self.best_strategy = episode_strategy.copy()
                
                # 学习
                done = (next_exec_state.status == ExecutionStatus.CRASH or 
                        next_exec_state.status == ExecutionStatus.TIMEOUT or 
                        step == max_steps - 1)
                self.agent.learn(rl_state, action, reward, next_rl_state, done)
                
                # 更新当前输入
                current_input = mutated_input
                
                if done:
                    break
            
            total_rewards.append(episode_reward)
            
            if verbose and (episode + 1) % 100 == 0:
                avg_reward = sum(total_rewards[-100:]) / min(100, episode + 1)
                logger.info(f"Episode {episode + 1}/{episodes}: 平均奖励: {avg_reward:.2f}, "
                          f"崩溃数: {crash_count}, 唯一崩溃: {unique_crash_count}, "
                          f"发现漏洞: {len(self.discovered_vulnerabilities)}")
        
        return RLTrainingResult(
            total_episodes=episodes,
            successful_episodes=len(self.discovered_vulnerabilities),
            discovered_vulnerabilities=self.discovered_vulnerabilities,
            best_strategy=self.best_strategy,
            total_crashes=crash_count,
            unique_crashes=unique_crash_count,
            reward_history=total_rewards,
            average_reward=sum(total_rewards) / episodes if episodes > 0 else 0.0,
            analysis_summary={
                'vulnerability_types': [v.vulnerability_type.value for v in self.discovered_vulnerabilities],
                'best_input_length': len(self.best_input) if self.best_input else 0
            }
        )

    def run(self, initial_input: Optional[bytes] = None, max_iterations: int = 1000) -> RLTrainingResult:
        """
        运行漏洞挖掘
        
        Args:
            initial_input: 初始输入
            max_iterations: 最大迭代次数
        
        Returns:
            训练结果
        """
        return self.train(episodes=max_iterations, initial_input=initial_input)

    def save(self, output_dir: str) -> bool:
        """
        保存代理状态
        
        Args:
            output_dir: 输出目录
        
        Returns:
            是否成功
        """
        try:
            os.makedirs(output_dir, exist_ok=True)
            state = {
                'agent_type': self.agent_type,
                'best_reward': self.best_reward,
                'crash_signatures': list(self.crash_signatures),
                'discovered_vulnerabilities': [
                    {
                        'vulnerability_type': v.vulnerability_type.value,
                        'crash_address': v.crash_address,
                        'confidence': v.confidence,
                        'timestamp': v.timestamp
                    }
                    for v in self.discovered_vulnerabilities
                ]
            }
            output_path = os.path.join(output_dir, 'rl_agent_state.json')
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(state, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.error(f"保存代理状态失败: {e}")
            return False
    
    @classmethod
    def load(cls, output_dir: str) -> "RLVulnAgent":
        """
        加载代理状态
        
        Args:
            output_dir: 输出目录
        
        Returns:
            加载的代理实例
        """
        agent = cls()
        try:
            output_path = os.path.join(output_dir, 'rl_agent_state.json')
            with open(output_path, 'r', encoding='utf-8') as f:
                state = json.load(f)
            agent.agent_type = state.get('agent_type', agent.agent_type)
            agent.best_reward = state.get('best_reward', agent.best_reward)
            agent.crash_signatures = set(state.get('crash_signatures', []))
            return agent
        except Exception as e:
            logger.error(f"加载代理状态失败: {e}")
            return agent

    def export_results(self, output_path: str) -> bool:
        """
        导出挖掘结果
        
        Args:
            output_path: 输出路径
        
        Returns:
            是否成功
        """
        results = {
            'discovered_vulnerabilities': [],
            'total_crashes': len(self.crash_signatures),
            'best_strategy': [a.action_type.value for a in self.best_strategy],
            'timestamp': time.time()
        }
        
        for vuln in self.discovered_vulnerabilities:
            results['discovered_vulnerabilities'].append({
                'vulnerability_type': vuln.vulnerability_type.value,
                'crash_address': hex(vuln.crash_address),
                'input_length': len(vuln.input_payload),
                'input_hex': vuln.input_payload.hex()[:200],
                'confidence': vuln.confidence,
                'timestamp': vuln.timestamp
            })
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            logger.info(f"挖掘结果已导出到: {output_path}")
            return True
        except Exception as e:
            logger.error(f"导出结果失败: {e}")
            return False


def run_rl_vuln_mining(target_binary: str = "", episodes: int = 1000, 
                       agent_type: str = "dqn") -> RLTrainingResult:
    """
    便捷的漏洞挖掘函数
    
    Args:
        target_binary: 目标二进制文件
        episodes: 训练回合数
        agent_type: 代理类型
    
    Returns:
        训练结果
    """
    agent = RLVulnAgent(target_binary, agent_type)
    return agent.run(max_iterations=episodes)


def simulate_fuzzing(episodes: int = 1000, agent_type: str = "qlearning", 
                     initial_input: Optional[bytes] = None, verbose: bool = False) -> RLTrainingResult:
    """
    模拟模糊测试的便捷函数
    
    Args:
        episodes: 训练回合数
        agent_type: 代理类型 ("qlearning" 或 "dqn")
        initial_input: 初始输入
        verbose: 是否输出详细信息
    
    Returns:
        RLTrainingResult 训练结果
    """
    agent = RLVulnAgent(target_binary="", agent_type=agent_type)
    return agent.train(episodes=episodes, initial_input=initial_input, verbose=verbose)


def format_vuln_report(result: RLTrainingResult) -> str:
    """
    格式化漏洞挖掘报告
    
    Args:
        result: RLTrainingResult
    
    Returns:
        格式化的报告字符串
    """
    parts = [
        "# 强化学习漏洞挖掘报告",
        "",
        f"总回合数: {result.total_episodes}",
        f"成功发现漏洞: {result.successful_episodes}",
        f"总崩溃数: {result.total_crashes}",
        f"唯一崩溃数: {result.unique_crashes}",
        f"平均奖励: {result.average_reward:.2f}",
        ""
    ]
    
    if result.discovered_vulnerabilities:
        parts.append("## 发现的漏洞")
        
        for i, vuln in enumerate(result.discovered_vulnerabilities, 1):
            parts.extend([
                f"\n### {i}. {vuln.vulnerability_type.value}",
                f"- 崩溃地址: {hex(vuln.crash_address)}",
                f"- 输入长度: {len(vuln.input_payload)}",
                f"- 置信度: {vuln.confidence:.1%}",
                f"- 时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(vuln.timestamp))}"
            ])
    
    if result.best_strategy:
        parts.append("")
        parts.append("## 最佳策略")
        parts.append(f"策略长度: {len(result.best_strategy)}")
        parts.append("动作序列:")
        for i, action in enumerate(result.best_strategy[:20], 1):
            parts.append(f"{i}. {action.action_type.value}")
        if len(result.best_strategy) > 20:
            parts.append("...")
    
    if result.analysis_summary:
        parts.append("")
        parts.append("## 分析摘要")
        vuln_types = result.analysis_summary.get('vulnerability_types', [])
        if vuln_types:
            parts.append(f"漏洞类型分布: {', '.join(vuln_types)}")
        best_len = result.analysis_summary.get('best_input_length', 0)
        parts.append(f"最佳输入长度: {best_len}")
    
    return "\n".join(parts)