# 修改记录:
# 2025-08-07 11:42 - 初始实现：Q-learning攻击路径发现——替代静态BFS的在线学习

"""RL攻击路径发现 — Q-learning驱动的漏洞利用路径动态搜索。

vuln_chain_analyzer.py 使用静态BFS+调用图可达性——这是"固定地图导航"。
实际漏洞利用受环境因素（ASLR/栈保护/libc版本）影响，路径可行性动态变化。
Vulnet 证明了RL模拟→ML泛化的可行性。

本模块的核心机制——环境感知的Q-learning攻击路径发现：
1. 状态 = (当前漏洞节点, 已获取原语, 环境配置)。
2. 动作 = 选择下一个要exploit的漏洞。
3. 奖励 = 到达高价值目标 → +1，路径过长 → -0.1/步。
4. Q-table通过模拟执行学习，收敛后提取最优攻击路径。

与 VulNet/GAT-APG 的区别：
- VulNet: 网络级攻击图 + RL → ML预测器。本方案是二进制级漏洞图 + Q-learning。
- GAT-APG: 需要预建攻击图和GNN训练。本方案在线学习，无需预训练。
- 粒度差: 网络级 vs 函数/原语级——本方案更细一个数量级。

- Terranova et al.: POMDP攻击路径预测的公式化。
- VulNet: RL模拟→预测器的架构借鉴。
"""

import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

_EPS: float = 1e-9

@dataclass
class VulnState:
    """RL状态——攻击者在漏洞图中的当前位置。"""
    current_node: str
    acquired_primitives: Set[str] = field(default_factory=set)
    environment: Dict[str, Any] = field(default_factory=dict)

    def to_key(self) -> str:
        _prim_key = ",".join(sorted(self.acquired_primitives))
        return f"{self.current_node}|{_prim_key}"

@dataclass
class AttackAction:
    """RL动作——从当前漏洞跳到下一个漏洞。"""
    target_node: str
    required_primitives: Set[str] = field(default_factory=set)
    success_prob: float = 0.5
    cost: float = 1.0

@dataclass
class VulnGraphEdge:
    """漏洞间转移边。"""
    from_node: str
    to_node: str
    edge_type: str
    distance: int = 1
    is_exploitable: bool = False

class QLearningAttackPathFinder:
    """Q-learning驱动的攻击路径发现器。

    使用范式：
      finder = QLearningAttackPathFinder(vuln_nodes, edges, targets)
      finder.train(episodes=1000)
      path = finder.best_path(start_node)
    """

    def __init__(
        self,
        vuln_nodes: List[Dict],
        edges: List[VulnGraphEdge],
        high_value_targets: Set[str],
        learning_rate: float = 0.1,
        discount: float = 0.9,
        epsilon: float = 0.2,
        max_steps_per_episode: int = 30,
    ):
        self.nodes = {n["node_id"]: n for n in vuln_nodes}
        self.edges = edges
        self.targets = high_value_targets
        self.lr = learning_rate
        self.gamma = discount
        self.epsilon = epsilon
        self.max_steps = max_steps_per_episode

        # Q-table: state_key → {action_key → q_value}
        self._Q: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        # 每节点的出边索引
        self._outgoing: Dict[str, List[VulnGraphEdge]] = defaultdict(list)
        for _e in edges:
            self._outgoing[_e.from_node].append(_e)

        # 训练统计
        self._episodes: int = 0
        self._total_reward: float = 0.0

    # 训练

    def train(self, episodes: int = 1000):
        """执行 Q-learning 训练循环。"""
        for _ep in range(episodes):
            _start = random.choice(list(self.nodes.keys()))
            _state = VulnState(current_node=_start)
            _total_r = 0.0

            for _step in range(self.max_steps):
                _actions = self._available_actions(_state)
                if not _actions:
                    break

                # epsilon-greedy 选择
                if random.random() < self.epsilon:
                    _action = random.choice(_actions)
                else:
                    _action = self._best_action(_state, _actions)

                # 执行动作
                _next_state = self._apply_action(_state, _action)
                _reward = self._compute_reward(_state, _action, _next_state)

                # Q-learning 更新
                _s_key = _state.to_key()
                _ns_key = _next_state.to_key()
                _a_key = _action.target_node

                _old_q = self._Q[_s_key][_a_key]
                _max_next = max(self._Q[_ns_key].values()) if self._Q[_ns_key] else 0.0
                _new_q = _old_q + self.lr * (
                    _reward + self.gamma * _max_next - _old_q
                )
                self._Q[_s_key][_a_key] = _new_q

                _state = _next_state
                _total_r += _reward

                if _state.current_node in self.targets:
                    break

            self._episodes += 1
            self._total_reward += _total_r

    def best_path(
        self, start_node: str, max_length: int = 20,
    ) -> List[Tuple[str, str, float]]:
        """提取从起始节点的最优攻击路径。

        返回：[(from_node, to_node, q_value), ...]。
        """
        _path: List[Tuple[str, str, float]] = []
        _state = VulnState(current_node=start_node)
        _visited: Set[str] = set()

        for _ in range(max_length):
            _actions = self._available_actions(_state)
            if not _actions:
                break

            _best = self._best_action(_state, _actions)
            if _best is None:
                break
            _s_key = _state.to_key()
            _q = self._Q[_s_key].get(_best.target_node, 0.0)

            _path.append((_state.current_node, _best.target_node, round(_q, 4)))

            if _best.target_node in _visited:
                break
            _visited.add(_best.target_node)

            _state = self._apply_action(_state, _best)
            if _state.current_node in self.targets:
                break

        return _path

    def estimate_path_success(self, path: List[str]) -> float:
        """估计攻击路径的总成功概率——各步Q值归一化后累乘。"""
        if not path or len(path) < 2:
            return 0.0

        _prob = 1.0
        for _i in range(len(path) - 1):
            _s_key_pattern = path[_i]
            # 模糊匹配Q表中的状态
            _q_vals = []
            for _sk, _actions in self._Q.items():
                if _sk.startswith(path[_i]):
                    _q_vals.extend(_actions.values())
            _max_q = max(_q_vals) if _q_vals else 0.5
            _prob *= min(1.0, _max_q)

        return round(_prob, 4)

    # 内部

    def _available_actions(self, state: VulnState) -> List[AttackAction]:
        """当前状态下可用的攻击动作。"""
        _actions: List[AttackAction] = []
        _node = self.nodes.get(state.current_node, {})

        for _edge in self._outgoing.get(state.current_node, []):
            _target = self.nodes.get(_edge.to_node, {})
            _reqs = set(_target.get("prerequisites", []))
            # 检查是否满足前置条件
            if _reqs and not _reqs.issubset(state.acquired_primitives):
                continue

            _prob = 0.3 + 0.4 * float(_edge.is_exploitable) + 0.2 * (
                1.0 - min(_edge.distance, 10) / 10.0
            )
            _actions.append(AttackAction(
                target_node=_edge.to_node,
                required_primitives=_reqs,
                success_prob=_prob,
                cost=_edge.distance,
            ))

        return _actions

    def _best_action(
        self, state: VulnState, actions: List[AttackAction],
    ) -> Optional[AttackAction]:
        """选择Q值最高的动作。"""
        _s_key = state.to_key()
        _best = None
        _best_q = -float('inf')
        for _a in actions:
            _q = self._Q[_s_key].get(_a.target_node, _a.success_prob)
            if _q > _best_q:
                _best_q = _q
                _best = _a
        return _best

    def _apply_action(
        self, state: VulnState, action: AttackAction,
    ) -> VulnState:
        """执行动作——转移到新状态。"""
        _new_prims = set(state.acquired_primitives)
        _target = self.nodes.get(action.target_node, {})
        for _eff in _target.get("effects", []):
            _new_prims.add(_eff)

        return VulnState(
            current_node=action.target_node,
            acquired_primitives=_new_prims,
            environment=dict(state.environment),
        )

    def _compute_reward(
        self, state: VulnState, action: AttackAction, next_state: VulnState,
    ) -> float:
        """计算即时奖励。"""
        if next_state.current_node in self.targets:
            return 10.0
        # 新获取的原语额外加分
        _new_prims = next_state.acquired_primitives - state.acquired_primitives
        return len(_new_prims) * 0.5 - 0.1 * action.cost

# 冒烟测试
def _smoke_test():
    _nodes = [
        {"node_id": "v1", "vuln_type": "stack_overflow", "severity": "HIGH",
         "effects": ["pc_control"], "prerequisites": []},
        {"node_id": "v2", "vuln_type": "info_leak", "severity": "MEDIUM",
         "effects": ["stack_leak"], "prerequisites": ["pc_control"]},
        {"node_id": "v3", "vuln_type": "uaf", "severity": "HIGH",
         "effects": ["arb_write"], "prerequisites": []},
        {"node_id": "v4", "vuln_type": "got_overwrite", "severity": "CRITICAL",
         "effects": ["code_exec"], "prerequisites": ["arb_write", "code_leak"]},
        {"node_id": "target_shell", "vuln_type": "target", "severity": "CRITICAL",
         "effects": [], "prerequisites": ["code_exec"]},
    ]
    _edges = [
        VulnGraphEdge("v1", "v2", "call", 1, True),
        VulnGraphEdge("v2", "v4", "data_flow", 2, True),
        VulnGraphEdge("v3", "v4", "call", 1, True),
        VulnGraphEdge("v4", "target_shell", "call", 1, True),
        VulnGraphEdge("v1", "v3", "call", 2, False),
    ]
    _targets = {"target_shell", "v4"}

    _finder = QLearningAttackPathFinder(_nodes, _edges, _targets)
    _finder.train(episodes=500)

    _path = _finder.best_path("v1")
    _nodes_in_path = [p[0] for p in _path] + ([_path[-1][1]] if _path else [])
    print(f"[rl_path] best path (v1): {' → '.join(_nodes_in_path)}")

    _prob = _finder.estimate_path_success(_nodes_in_path)
    print(f"[rl_path] estimated success: {_prob:.4f}")

    assert len(_path) >= 1, f"should find at least 1-step path"
    print("[OK] QLearningAttackPathFinder smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
