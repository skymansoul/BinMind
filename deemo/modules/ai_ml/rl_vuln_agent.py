"""
RL Vulnerability Agent - Q-learning for vulnerability discovery pipeline optimization.

Uses reinforcement learning to optimize fuzzing strategy selection,
mutation scheduling, and analysis prioritization in the vulnerability
discovery pipeline.
"""

from __future__ import annotations

import json
import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import numpy as np


_FUZZ_ACTIONS: Tuple[str, ...] = (
    "mutate_bit_flip",
    "mutate_byte_flip",
    "mutate_arithmetic_inc",
    "mutate_arithmetic_dec",
    "mutate_interesting_value",
    "mutate_havoc",
    "mutate_splice",
    "mutate_dictionary",
    "mutate_grammar",
    "mutate_custom",
    "analyze_crash",
    "analyze_coverage",
    "analyze_symbolic",
    "analyze_taint",
    "prioritize_seed",
    "de_prioritize_seed",
    "switch_fuzzer",
    "increase_energy",
    "decrease_energy",
    "restart_session",
)


class RewardSignal(Enum):
    """Types of reward signals for the RL agent."""
    CRASH_FOUND = auto()
    UNIQUE_CRASH = auto()
    COVERAGE_INCREASE = auto()
    NEW_PATH = auto()
    VULNERABILITY_CONFIRMED = auto()
    TIMEOUT = auto()
    NO_PROGRESS = auto()
    BUG_REPORTED = auto()


@dataclass
class AgentAction:
    """An action executed by the agent in a pipeline step."""
    action_type: str
    action_index: int
    parameters: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0

    @property
    def name(self) -> str:
        return self.action_type


@dataclass
class PipelineState:
    """State of the vulnerability discovery pipeline."""
    current_fuzzer: str = "afl"
    coverage_percent: float = 0.0
    crashes_found: int = 0
    unique_crashes: int = 0
    confirmed_vulns: int = 0
    total_executions: int = 0
    current_energy: float = 1.0
    active_seeds: int = 0
    elapsed_time: float = 0.0
    stalled_cycles: int = 0
    last_crash_time: float = 0.0

    def to_vector(self) -> np.ndarray:
        """Convert state to feature vector for the RL agent."""
        return np.array([
            float(hash(self.current_fuzzer) % 100) / 100.0,
            self.coverage_percent / 100.0,
            min(self.crashes_found / 50.0, 1.0),
            min(self.unique_crashes / 20.0, 1.0),
            min(self.confirmed_vulns / 5.0, 1.0),
            min(self.total_executions / 1_000_000.0, 1.0),
            self.current_energy,
            min(self.active_seeds / 1000.0, 1.0),
            min(self.elapsed_time / 3600.0, 1.0),
            min(self.stalled_cycles / 10.0, 1.0),
        ], dtype=np.float32)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'current_fuzzer': self.current_fuzzer,
            'coverage_percent': self.coverage_percent,
            'crashes_found': self.crashes_found,
            'unique_crashes': self.unique_crashes,
            'confirmed_vulns': self.confirmed_vulns,
            'total_executions': self.total_executions,
            'current_energy': self.current_energy,
            'active_seeds': self.active_seeds,
            'elapsed_time': self.elapsed_time,
            'stalled_cycles': self.stalled_cycles,
        }


@dataclass
class PolicyResult:
    """Result of a policy evaluation step."""
    action: AgentAction
    reward: float
    new_state: PipelineState
    signal: RewardSignal
    metadata: Dict[str, Any] = field(default_factory=dict)


class QLearningAgent:
    """Q-learning agent with state discretization for pipeline optimization."""

    def __init__(
        self,
        n_actions: int,
        learning_rate: float = 0.1,
        discount_factor: float = 0.95,
        epsilon: float = 0.2,
        epsilon_decay: float = 0.998,
        epsilon_min: float = 0.01,
        discretization_bins: int = 5,
    ) -> None:
        self.n_actions = n_actions
        self.lr = learning_rate
        self.gamma = discount_factor
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min
        self.discretization_bins = discretization_bins

        self.q_table: Dict[int, np.ndarray] = {}
        self.action_counts: Dict[int, int] = defaultdict(int)
        self.reward_memory: List[float] = []
        self.total_steps: int = 0

    def discretize_state(self, state_vector: np.ndarray) -> int:
        """Convert continuous state vector to discrete bucket key.

        Args:
            state_vector: Normalized state features.

        Returns:
            Integer bucket key.
        """
        bins = np.digitize(
            state_vector,
            np.linspace(0, 1, self.discretization_bins + 1)[1:-1],
        )
        return hash(tuple(bins))

    def get_q_values(self, state_key: int) -> np.ndarray:
        """Get or initialize Q-values for a state.

        Args:
            state_key: Discretized state key.

        Returns:
            Q-value array for all actions.
        """
        if state_key not in self.q_table:
            self.q_table[state_key] = np.zeros(self.n_actions, dtype=np.float32)
        return self.q_table[state_key]

    def choose_action(
        self,
        state_vector: np.ndarray,
        training: bool = True,
    ) -> int:
        """Epsilon-greedy action selection.

        Args:
            state_vector: Current state features.
            training: If True, use epsilon-greedy; else greedy.

        Returns:
            Selected action index.
        """
        if training and random.random() < self.epsilon:
            return random.randint(0, self.n_actions - 1)

        state_key = self.discretize_state(state_vector)
        q_values = self.get_q_values(state_key)
        max_q = np.max(q_values)
        best_actions = np.where(q_values == max_q)[0]
        return int(random.choice(best_actions))

    def learn(
        self,
        state_vector: np.ndarray,
        action: int,
        reward: float,
        next_state_vector: np.ndarray,
        done: bool,
    ) -> float:
        """Perform a Q-learning update step.

        Args:
            state_vector: State before action.
            action: Action index taken.
            reward: Observed reward.
            next_state_vector: State after action.
            done: Whether episode is done.

        Returns:
            TD error magnitude.
        """
        state_key = self.discretize_state(state_vector)
        next_key = self.discretize_state(next_state_vector)

        q_values = self.get_q_values(state_key)
        next_q = self.get_q_values(next_key)

        target = reward
        if not done:
            target += self.gamma * np.max(next_q)

        td_error = target - q_values[action]
        self.q_table[state_key][action] += self.lr * td_error

        self.action_counts[action] += 1
        self.reward_memory.append(reward)
        self.total_steps += 1

        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)

        return abs(float(td_error))

    def compute_reward(
        self,
        signal: RewardSignal,
        metrics: Optional[Dict[str, float]] = None,
    ) -> float:
        """Compute reward from signal and metrics.

        Args:
            signal: The reward signal type.
            metrics: Additional numeric metrics.

        Returns:
            Scalar reward.
        """
        base_rewards = {
            RewardSignal.CRASH_FOUND: 5.0,
            RewardSignal.UNIQUE_CRASH: 15.0,
            RewardSignal.COVERAGE_INCREASE: 2.0,
            RewardSignal.NEW_PATH: 3.0,
            RewardSignal.VULNERABILITY_CONFIRMED: 25.0,
            RewardSignal.TIMEOUT: -1.0,
            RewardSignal.NO_PROGRESS: -2.0,
            RewardSignal.BUG_REPORTED: 20.0,
        }

        reward = base_rewards.get(signal, 0.0)

        if metrics:
            coverage_gain = metrics.get('coverage_gain', 0.0)
            reward += coverage_gain * 10.0

            crash_uniqueness = metrics.get('crash_uniqueness', 0.0)
            reward += crash_uniqueness * 5.0

        return reward

    def save(self, filepath: str) -> None:
        """Save Q-table to JSON file."""
        data = {
            'n_actions': self.n_actions,
            'epsilon': self.epsilon,
            'total_steps': self.total_steps,
            'q_table': {str(k): v.tolist() for k, v in self.q_table.items()},
        }
        with open(filepath, 'w') as f:
            json.dump(data, f)

    def load(self, filepath: str) -> None:
        """Load Q-table from JSON file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        self.n_actions = data['n_actions']
        self.epsilon = data['epsilon']
        self.total_steps = data['total_steps']
        self.q_table = {
            int(k): np.array(v, dtype=np.float32)
            for k, v in data['q_table'].items()
        }


class RLVulnAgent:
    """Reinforcement learning agent for vulnerability discovery optimization."""

    def __init__(
        self,
        learning_rate: float = 0.1,
        discount_factor: float = 0.95,
        epsilon: float = 0.2,
        epsilon_decay: float = 0.998,
    ) -> None:
        self.q_agent = QLearningAgent(
            n_actions=len(_FUZZ_ACTIONS),
            learning_rate=learning_rate,
            discount_factor=discount_factor,
            epsilon=epsilon,
            epsilon_decay=epsilon_decay,
        )
        self.state: Optional[PipelineState] = None
        self.history: List[PolicyResult] = []
        self.action_history: List[Tuple[str, float]] = []

    def reset(self, initial_state: Optional[PipelineState] = None) -> PipelineState:
        """Reset agent to initial state.

        Args:
            initial_state: Starting pipeline state.

        Returns:
            The reset pipeline state.
        """
        if initial_state:
            self.state = initial_state
        else:
            self.state = PipelineState()
        self.history = []
        return self.state

    def step(
        self,
        signal: RewardSignal,
        metrics: Optional[Dict[str, float]] = None,
    ) -> PolicyResult:
        """Execute one agent step based on observed signal.

        Args:
            signal: Reward signal from last action.
            metrics: Additional metrics for reward computation.

        Returns:
            PolicyResult with action taken, reward, and new state.
        """
        if self.state is None:
            self.reset()

        assert self.state is not None

        reward = self.q_agent.compute_reward(signal, metrics)

        state_vec = self.state.to_vector()
        action_idx = self.q_agent.choose_action(state_vec, training=True)

        new_state = PipelineState(
            current_fuzzer=self.state.current_fuzzer,
            coverage_percent=self.state.coverage_percent,
            crashes_found=self.state.crashes_found,
            unique_crashes=self.state.unique_crashes,
            confirmed_vulns=self.state.confirmed_vulns,
            total_executions=self.state.total_executions,
            current_energy=self.state.current_energy,
            active_seeds=self.state.active_seeds,
            elapsed_time=self.state.elapsed_time,
            stalled_cycles=self.state.stalled_cycles,
        )

        action = AgentAction(
            action_type=_FUZZ_ACTIONS[action_idx],
            action_index=action_idx,
        )

        self._apply_action(action, new_state, metrics)

        new_state_vec = new_state.to_vector()
        done = signal == RewardSignal.VULNERABILITY_CONFIRMED

        self.q_agent.learn(state_vec, action_idx, reward, new_state_vec, done)

        self.state = new_state

        result = PolicyResult(
            action=action,
            reward=reward,
            new_state=new_state,
            signal=signal,
            metadata=metrics or {},
        )
        self.history.append(result)
        self.action_history.append((action.name, reward))

        return result

    def _apply_action(
        self,
        action: AgentAction,
        state: PipelineState,
        metrics: Optional[Dict[str, float]],
    ) -> None:
        """Apply action effects to pipeline state.

        Args:
            action: Action to apply.
            state: State to modify in place.
            metrics: Optional metrics for state updates.
        """
        if 'coverage' in action.action_type and metrics:
            state.coverage_percent += metrics.get('coverage_gain', 0.0)
        elif action.action_type == 'increase_energy':
            state.current_energy = min(10.0, state.current_energy * 1.5)
        elif action.action_type == 'decrease_energy':
            state.current_energy = max(0.1, state.current_energy * 0.7)
        elif 'prioritize_seed' in action.action_type:
            state.active_seeds += 1
        elif 'de_prioritize_seed' in action.action_type:
            state.active_seeds = max(0, state.active_seeds - 1)
        elif action.action_type == 'switch_fuzzer':
            state.current_fuzzer = 'custom'

        state.total_executions += 1

    def select_action(
        self,
        state: Optional[PipelineState] = None,
    ) -> Tuple[str, float]:
        """Select best action for current state (greedy, no training).

        Args:
            state: Pipeline state. Uses current state if None.

        Returns:
            Tuple of (action_name, q_value).
        """
        s = state or self.state
        if s is None:
            return (_FUZZ_ACTIONS[0], 0.0)

        state_vec = s.to_vector()
        state_key = self.q_agent.discretize_state(state_vec)
        q_values = self.q_agent.get_q_values(state_key)

        best_idx = int(np.argmax(q_values))
        return (_FUZZ_ACTIONS[best_idx], float(q_values[best_idx]))

    def get_top_actions(
        self,
        state: Optional[PipelineState] = None,
        top_k: int = 3,
    ) -> List[Tuple[str, float]]:
        """Get top-k recommended actions.

        Args:
            state: Pipeline state. Uses current state if None.
            top_k: Number of actions to return.

        Returns:
            List of (action_name, q_value) tuples.
        """
        s = state or self.state
        if s is None:
            return [(_FUZZ_ACTIONS[0], 0.0)]

        state_vec = s.to_vector()
        state_key = self.q_agent.discretize_state(state_vec)
        q_values = self.q_agent.get_q_values(state_key)

        indices = np.argsort(q_values)[::-1][:top_k]
        return [(_FUZZ_ACTIONS[i], float(q_values[i])) for i in indices]

    def train_episode(
        self,
        steps: int = 100,
        initial_state: Optional[PipelineState] = None,
    ) -> List[PolicyResult]:
        """Run a training episode with simulated signals.

        Args:
            steps: Number of steps.
            initial_state: Starting state.

        Returns:
            List of policy results for the episode.
        """
        self.reset(initial_state)
        results: List[PolicyResult] = []

        for i in range(steps):
            rand_val = random.random()

            if rand_val < 0.05:
                signal = RewardSignal.VULNERABILITY_CONFIRMED
                metrics = {'crash_uniqueness': 1.0, 'coverage_gain': 0.02}
            elif rand_val < 0.15:
                signal = RewardSignal.UNIQUE_CRASH
                metrics = {'crash_uniqueness': 0.8, 'coverage_gain': 0.01}
            elif rand_val < 0.25:
                signal = RewardSignal.CRASH_FOUND
                metrics = {'crash_uniqueness': 0.3, 'coverage_gain': 0.005}
            elif rand_val < 0.45:
                signal = RewardSignal.COVERAGE_INCREASE
                metrics = {'coverage_gain': 0.03}
            elif rand_val < 0.55:
                signal = RewardSignal.NEW_PATH
                metrics = {'coverage_gain': 0.01}
            elif rand_val < 0.70:
                signal = RewardSignal.NO_PROGRESS
                metrics = {}
            else:
                signal = RewardSignal.TIMEOUT
                metrics = {}

            result = self.step(signal, metrics)
            results.append(result)

        return results

    def save(self, filepath: str) -> None:
        """Save agent state."""
        self.q_agent.save(filepath)

    def load(self, filepath: str) -> None:
        """Load agent state."""
        self.q_agent.load(filepath)

    @property
    def epsilon(self) -> float:
        return self.q_agent.epsilon

    @property
    def action_distribution(self) -> Dict[str, int]:
        """Return how many times each action has been selected."""
        return {
            _FUZZ_ACTIONS[i]: self.q_agent.action_counts.get(i, 0)
            for i in range(len(_FUZZ_ACTIONS))
        }


def create_rl_agent(
    learning_rate: float = 0.1,
    discount_factor: float = 0.95,
    epsilon: float = 0.2,
) -> RLVulnAgent:
    """Factory function to create a configured RL vulnerability agent.

    Args:
        learning_rate: Q-learning learning rate.
        discount_factor: Future reward discount (gamma).
        epsilon: Initial exploration rate.

    Returns:
        Configured RLVulnAgent instance.
    """
    return RLVulnAgent(
        learning_rate=learning_rate,
        discount_factor=discount_factor,
        epsilon=epsilon,
    )
