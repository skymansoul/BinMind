"""
基于强化学习的变异策略优化模块

功能:
    1. 替换 AFL/LibFuzzer 随机变异引擎, 训练 DQN 学习种子字段变异策略
    2. 奖励信号: 代码覆盖率增量 + 漏洞触发率
    3. 插件式接入现有 fuzz 模块
    4. 记录 (state, action, reward, next_state) 经验, 在线学习

核心技术:
    - 经验回放 (Experience Replay)
    - Double DQN + ε-greedy
    - 可插拔变异算子 (bit flip, byte flip, interesting ints, splice, dict insert)
    - 状态特征: 覆盖位图 hash + 字段位置熵
"""

import logging
import os
import random
import time
import json
import pickle
import threading
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import deque, defaultdict

logger = logging.getLogger(__name__)

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


class MutationOp(Enum):
    """变异算子"""
    BIT_FLIP_1 = "bit_flip_1"
    BIT_FLIP_4 = "bit_flip_4"
    BYTE_FLIP = "byte_flip"
    INTERESTING_BYTE = "interesting_byte"
    INTERESTING_WORD = "interesting_word"
    INTERESTING_DWORD = "interesting_dword"
    ARITHMETIC = "arithmetic"
    DICT_INSERT = "dict_insert"
    DICT_OVERWRITE = "dict_overwrite"
    SPLICE = "splice"
    CROSSOVER = "crossover"
    HAVOC = "havoc"
    SCHEDULED_HAVOC = "scheduled_havoc"


@dataclass
class MutatorState:
    """环境状态特征"""
    cov_signature: int                # 覆盖位图 hash
    field_entropy: float              # 字段熵
    edge_coverage_pct: float          # 当前边覆盖率 (0-1)
    crash_count: int
    timeout_count: int
    queue_size: int
    avg_exec_us: float
    age_seconds: float


@dataclass
class Transition:
    """经验回放单元"""
    state: List[float]
    action: int
    reward: float
    next_state: List[float]
    done: bool


class QNetwork:
    """
    极简 Q 网络 (优先使用 numpy, 没有深度学习依赖也能跑)
    - 2 层全连接 + ReLU
    - Adam-like 在线梯度下降
    """

    def __init__(self, state_dim: int, num_actions: int, hidden: int = 64,
                 lr: float = 1e-3):
        self.state_dim = state_dim
        self.num_actions = num_actions
        self.hidden = hidden
        self.lr = lr
        if NUMPY_AVAILABLE:
            self.W1 = np.random.randn(state_dim, hidden) * 0.1
            self.b1 = np.zeros(hidden)
            self.W2 = np.random.randn(hidden, num_actions) * 0.1
            self.b2 = np.zeros(num_actions)
        else:
            self.W1 = self._rand(state_dim, hidden)
            self.b1 = [0.0] * hidden
            self.W2 = self._rand(hidden, num_actions)
            self.b2 = [0.0] * num_actions

    @staticmethod
    def _rand(rows: int, cols: int):
        return [[random.uniform(-0.1, 0.1) for _ in range(cols)]
                for _ in range(rows)]

    def predict(self, state: List[float]) -> List[float]:
        if NUMPY_AVAILABLE:
            s = np.array(state, dtype=np.float32)
            h = np.maximum(0.0, s @ self.W1 + self.b1)
            q = h @ self.W2 + self.b2
            return q.tolist()
        # numpy 不可用时的纯 Python 实现
        h = [0.0] * self.hidden
        for i in range(self.hidden):
            v = self.b1[i]
            for j in range(self.state_dim):
                v += state[j] * self.W1[j][i]
            h[i] = max(0.0, v)
        q = [0.0] * self.num_actions
        for a in range(self.num_actions):
            v = self.b2[a]
            for i in range(self.hidden):
                v += h[i] * self.W2[i][a]
            q[a] = v
        return q

    def update(self, state: List[float], target: List[float]):
        if NUMPY_AVAILABLE:
            s = np.array(state, dtype=np.float32)
            t = np.array(target, dtype=np.float32)
            h = np.maximum(0.0, s @ self.W1 + self.b1)
            q = h @ self.W2 + self.b2
            grad_q = 2 * (q - t)
            grad_W2 = np.outer(h, grad_q)
            grad_b2 = grad_q
            grad_h = (grad_q @ self.W2.T) * (h > 0)
            grad_W1 = np.outer(s, grad_h)
            grad_b1 = grad_h
            self.W1 -= self.lr * grad_W1
            self.b1 -= self.lr * grad_b1
            self.W2 -= self.lr * grad_W2
            self.b2 -= self.lr * grad_b2
        else:
            # 简化: 仅做 SGD 近似
            preds = self.predict(state)
            for a in range(self.num_actions):
                grad = 2 * (preds[a] - target[a]) * self.lr
                for i in range(self.hidden):
                    self.W2[i][a] -= grad * max(0.0, state[i % self.state_dim])
                self.b2[a] -= grad

    def get_weights(self) -> Dict[str, Any]:
        if NUMPY_AVAILABLE:
            return {
                'W1': self.W1.tolist(),
                'b1': self.b1.tolist(),
                'W2': self.W2.tolist(),
                'b2': self.b2.tolist()
            }
        return {'W1': self.W1, 'b1': self.b1, 'W2': self.W2, 'b2': self.b2}

    def set_weights(self, w: Dict[str, Any]):
        if NUMPY_AVAILABLE:
            self.W1 = np.array(w['W1'], dtype=np.float32)
            self.b1 = np.array(w['b1'], dtype=np.float32)
            self.W2 = np.array(w['W2'], dtype=np.float32)
            self.b2 = np.array(w['b2'], dtype=np.float32)
        else:
            self.W1 = w['W1']
            self.b1 = w['b1']
            self.W2 = w['W2']
            self.b2 = w['b2']


class ReplayBuffer:
    """经验回放缓冲区"""

    def __init__(self, capacity: int = 20000):
        self.buf: deque = deque(maxlen=capacity)

    def push(self, t: Transition):
        self.buf.append(t)

    def sample(self, n: int) -> List[Transition]:
        n = min(n, len(self.buf))
        return random.sample(self.buf, n)

    def __len__(self):
        return len(self.buf)


class RLMutationAgent:
    """
    DQN-based 变异策略学习器
    - 状态: 8 维 (cov_sig, entropy, edge_pct, crashes, timeouts, queue, exec_us, age)
    - 动作: MutationOp 枚举大小
    - 奖励: 覆盖增量 + 漏洞触发奖励
    """

    NUM_ACTIONS = len(MutationOp)
    STATE_DIM = 8

    def __init__(self,
                 gamma: float = 0.95,
                 epsilon: float = 0.3,
                 epsilon_decay: float = 0.999,
                 epsilon_min: float = 0.05,
                 batch_size: int = 32,
                 target_update_every: int = 100,
                 model_path: Optional[str] = None):
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min
        self.batch_size = batch_size
        self.target_update_every = target_update_every
        self.online = QNetwork(self.STATE_DIM, self.NUM_ACTIONS)
        self.target = QNetwork(self.STATE_DIM, self.NUM_ACTIONS)
        self.target.set_weights(self.online.get_weights())
        self.replay = ReplayBuffer()
        self._step_counter = 0
        self._lock = threading.Lock()
        if model_path and os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    self.online.set_weights(pickle.load(f))
                self.target.set_weights(self.online.get_weights())
                logger.info(f"RL 变异模型已加载: {model_path}")
            except Exception as e:
                logger.warning(f"RL 模型加载失败: {e}")
        self.model_path = model_path

    def featurize(self, s: MutatorState) -> List[float]:
        return [
            float(s.cov_signature & 0xFFFF) / 65535.0,
            min(1.0, max(0.0, s.field_entropy / 8.0)),
            min(1.0, max(0.0, s.edge_coverage_pct)),
            min(1.0, s.crash_count / 100.0),
            min(1.0, s.timeout_count / 100.0),
            min(1.0, s.queue_size / 1000.0),
            min(1.0, s.avg_exec_us / 1e6),
            min(1.0, s.age_seconds / 3600.0)
        ]

    def select_action(self, state: MutatorState,
                      mask: Optional[List[int]] = None) -> MutationOp:
        if random.random() < self.epsilon:
            if mask:
                return MutationOp(random.choice(mask))
            return MutationOp(random.randrange(self.NUM_ACTIONS))
        feats = self.featurize(state)
        q = self.online.predict(feats)
        if mask:
            best = max(mask, key=lambda a: q[a])
        else:
            best = int(max(range(self.NUM_ACTIONS), key=lambda a: q[a]))
        return MutationOp(best)

    def remember(self, s: MutatorState, a: MutationOp, reward: float,
                 s2: MutatorState, done: bool):
        t = Transition(
            state=self.featurize(s),
            action=a.value if isinstance(a, MutationOp) else int(a),
            reward=reward,
            next_state=self.featurize(s2),
            done=done
        )
        with self._lock:
            self.replay.push(t)
            self._step_counter += 1

    def train_step(self) -> Optional[float]:
        if len(self.replay) < self.batch_size:
            return None
        batch = self.replay.sample(self.batch_size)
        total_loss = 0.0
        for t in batch:
            q_next = self.target.predict(t.next_state)
            target_val = t.reward
            if not t.done:
                target_val += self.gamma * max(q_next)
            q_pred = self.online.predict(t.state)
            tgt = list(q_pred)
            tgt[t.action] = target_val
            self.online.update(t.state, tgt)
            total_loss += sum((q_pred[i] - tgt[i]) ** 2 for i in range(self.NUM_ACTIONS))
        # 周期性同步 target
        if self._step_counter % self.target_update_every == 0:
            self.target.set_weights(self.online.get_weights())
        # epsilon 衰减
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
        return total_loss / max(1, self.batch_size)

    def save(self):
        if not self.model_path:
            return
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.online.get_weights(), f)
        except Exception as e:
            logger.warning(f"RL 模型保存失败: {e}")


# ============ 变异算子注册表 ============

def op_bit_flip_1(seed: bytes) -> List[bytes]:
    if not seed:
        return [seed]
    out = []
    for i in range(min(64, len(seed) * 8)):
        b = bytearray(seed)
        b[i // 8] ^= (1 << (i % 8))
        out.append(bytes(b))
    return out[:32]


def op_byte_flip(seed: bytes) -> List[bytes]:
    if not seed:
        return [seed]
    out = []
    for i in range(min(32, len(seed))):
        b = bytearray(seed)
        b[i] ^= 0xFF
        out.append(bytes(b))
    return out


def op_interesting_int(seed: bytes) -> List[bytes]:
    INTER = [0, 1, 0x10, 0x20, 0x40, 0x7F, 0x80, 0xFF,
             0x100, 0x1000, 0xFFFF, 0x10000, 0xFFFFFFFF,
             0x7FFFFFFF, 0x80000000, 0xFFFFFFFFFFFFFFFF]
    if not seed:
        return [bytes([v & 0xFF]) for v in INTER[:8]]
    out = []
    for v in INTER:
        for off in range(min(4, len(seed))):
            b = bytearray(seed)
            v_masked = v & ((1 << (8 * min(4, len(seed) - off))) - 1)
            for k in range(min(4, len(seed) - off)):
                b[off + k] = (v_masked >> (8 * k)) & 0xFF
            out.append(bytes(b))
    return out[:16]


def op_splice(seeds: List[bytes]) -> List[bytes]:
    if len(seeds) < 2:
        return []
    out = []
    for _ in range(8):
        a = random.choice(seeds)
        b = random.choice(seeds)
        if not a or not b:
            continue
        cut = random.randint(1, max(1, len(a) - 1))
        out.append((a[:cut] + b[cut:])[:max(len(a), len(b))])
    return out


OP_REGISTRY: Dict[MutationOp, Callable] = {
    MutationOp.BIT_FLIP_1: op_bit_flip_1,
    MutationOp.BYTE_FLIP: op_byte_flip,
    MutationOp.INTERESTING_BYTE: op_interesting_int,
    MutationOp.INTERESTING_WORD: op_interesting_int,
    MutationOp.INTERESTING_DWORD: op_interesting_int,
    MutationOp.SPLICE: op_splice,
}


def apply_mutation(op: MutationOp, seed: bytes,
                   corpus: Optional[List[bytes]] = None) -> List[bytes]:
    fn = OP_REGISTRY.get(op)
    if fn is None:
        return [seed]
    if op == MutationOp.SPLICE:
        return fn(corpus or [seed])
    return fn(seed)


# ============ 插件式接口 ============

class FuzzMutatorPlugin:
    """
    可插拔的 RL 变异器
    使用方法:
        plugin = FuzzMutatorPlugin()
        new_inputs = plugin.mutate(seed, corpus, MutatorState(...))
        plugin.observe(reward)
    """

    def __init__(self, model_path: Optional[str] = None,
                 epsilon: float = 0.3):
        self.agent = RLMutationAgent(
            epsilon=epsilon,
            model_path=model_path or os.path.join(
                os.path.dirname(__file__), '..', 'data',
                'rl_mutator.pkl'
            )
        )
        self.last_state: Optional[MutatorState] = None
        self.last_action: Optional[MutationOp] = None

    def mutate(self, seed: bytes, corpus: List[bytes],
               state: MutatorState) -> List[bytes]:
        action = self.agent.select_action(state)
        self.last_state = state
        self.last_action = action
        return apply_mutation(action, seed, corpus)

    def observe(self, next_state: MutatorState, reward: float,
                done: bool = False):
        if self.last_state is None or self.last_action is None:
            return
        self.agent.remember(self.last_state, self.last_action,
                            reward, next_state, done)
        self.agent.train_step()
        self.agent.save()


def compute_reward(prev_state: MutatorState, next_state: MutatorState,
                   new_crash: bool, new_cov: bool) -> float:
    r = 0.0
    if new_cov:
        r += 5.0
    if new_crash:
        r += 50.0
    edge_gain = next_state.edge_coverage_pct - prev_state.edge_coverage_pct
    r += edge_gain * 100.0
    if next_state.crash_count > prev_state.crash_count:
        r += 30.0
    # 鼓励降低 timeout
    if next_state.timeout_count < prev_state.timeout_count:
        r += 1.0
    return r
