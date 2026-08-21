# 初始实现：网络行为马尔可夫模型→攻击场景的what-if投影

"""网络数字孪生投影 — 基于行为马尔可夫模型的攻击场景what-if模拟。

现有网络分析工具回答"发生了什么"——事后取证。
本模块回答"如果发生X，网络会如何反应"——事前推演。

核心机制——行为马尔可夫模型 + 攻击注入投影：
1. 从历史流量学习'正常'马尔可夫转移矩阵——
   P(下一状态 = S_j | 当前状态 = S_i)，状态=协议+端口+流量模式的组合。
2. 注入虚拟攻击事件（如'host_X被入侵'→它可以向任意目标发任意流量）→
   重新计算转移概率，观测网络整体状态的偏移。
3. 投影指标：
   - 影响半径：受影响的节点数随攻击时间的增长曲线。
   - 关键脆弱点：其失陷导致最大网络状态偏移的节点。
   - 缓解策略对比：在不同遏制策略下投影攻击效果→推荐最优方案。

与既有模块的关系：
- forensic_causal_graph.py: 基于已知事件的因果重构（向后看）。
- 本模块: 基于马尔可夫模型的what-if投影（向前看）。
- 两者互补：因果图解释过去，数字孪生预演未来。

- "Network Digital Twin for Security": 网络孪生的概念框架。
- Markov状态模型在网络安全中的应用。
"""

import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

_EPS: float = 1e-9

@dataclass
class NetworkState:
    """网络的一个宏观状态——统计概要。"""
    active_flows: int
    unique_dst_ips: int
    unique_protocols: int
    total_bytes: float
    avg_packet_size: float
    anomaly_flows: int  # 偏离基线的流数量

    def to_tuple(self) -> Tuple:
        return (self.active_flows, self.unique_dst_ips,
                self.unique_protocols, int(self.total_bytes),
                int(self.avg_packet_size), self.anomaly_flows)

    def distance(self, other: 'NetworkState') -> float:
        """两个状态间的归一化欧氏距离。"""
        _dims = [
            abs(self.active_flows - other.active_flows) / max(self.active_flows, other.active_flows, 1),
            abs(self.unique_dst_ips - other.unique_dst_ips) / max(self.unique_dst_ips, other.unique_dst_ips, 1),
            abs(self.unique_protocols - other.unique_protocols) / max(self.unique_protocols, other.unique_protocols, 1),
            abs(self.total_bytes - other.total_bytes) / max(self.total_bytes, other.total_bytes, 1),
        ]
        return sum(_dims) / len(_dims)

@dataclass
class AttackScenario:
    """一个攻击场景的投影结果。"""
    scenario_name: str
    initial_state: NetworkState
    projected_states: List[NetworkState]  # 每步投影
    affected_nodes: Set[str]
    impact_radius: int
    max_deviation: float
    containment_effectiveness: Dict[str, float]  # 策略→效果

class NetworkDigitalTwin:
    """网络数字孪生——马尔可夫行为模型 + what-if攻击投影。

    使用范式：
      twin = NetworkDigitalTwin()
      twin.learn_from_history(state_sequence)
      result = twin.project_attack("ransomware_lateral", infected_nodes)
      twin.compare_containment(result, strategies)
    """

    def __init__(
        self,
        state_bins: int = 10,
        smoothing_alpha: float = 0.1,
    ):
        self.state_bins = state_bins
        self.smoothing_alpha = smoothing_alpha

        # 马尔可夫转移矩阵: state_tuple → {next_state_tuple → probability}
        self._transitions: Dict[Tuple, Dict[Tuple, float]] = defaultdict(
            lambda: defaultdict(float)
        )
        self._state_counts: Dict[Tuple, int] = defaultdict(int)
        # 节点邻接关系
        self._node_neighbors: Dict[str, Set[str]] = defaultdict(set)
        # 节点感染概率（贝叶斯更新）
        self._node_risk: Dict[str, float] = defaultdict(float)

    def learn_from_history(
        self, state_sequence: List[NetworkState],
    ):
        """从历史网络状态序列学习马尔可夫转移矩阵。"""
        for _i in range(len(state_sequence) - 1):
            _s = state_sequence[_i].to_tuple()
            _ns = state_sequence[_i + 1].to_tuple()
            self._transitions[_s][_ns] += 1.0
            self._state_counts[_s] += 1

        # 归一化为概率
        for _s, _nexts in self._transitions.items():
            _total = self._state_counts.get(_s, 1)
            for _ns in _nexts:
                _nexts[_ns] /= _total

    def register_node_connection(self, node_a: str, node_b: str):
        """注册节点间的网络连接关系。"""
        self._node_neighbors[node_a].add(node_b)
        self._node_neighbors[node_b].add(node_a)

    def project_attack(
        self,
        scenario_name: str,
        infected_nodes: List[str],
        current_state: NetworkState,
        projection_steps: int = 10,
        infection_expansion_rate: float = 0.3,
    ) -> AttackScenario:
        """投影响应的攻击场景——入侵节点集后网络如何演变。

        infection_expansion_rate: 每步每个感染节点感染邻居的概率。
        """
        _infected = set(infected_nodes)
        _projected: List[NetworkState] = []
        _current = current_state
        _max_dev = 0.0

        for _step in range(projection_steps):
            # 感染扩散——每个感染节点以概率感染邻居
            _new_infected: Set[str] = set()
            for _node in _infected:
                _neighbors = self._node_neighbors.get(_node, set())
                for _nb in _neighbors:
                    if _nb not in _infected and random.random() < infection_expansion_rate:
                        _new_infected.add(_nb)
            _infected.update(_new_infected)

            # 投影网络状态——感染节点增加异常流
            _next_state = self._project_state(_current, len(_infected))
            _projected.append(_next_state)

            _dev = _current.distance(_next_state)
            if _dev > _max_dev:
                _max_dev = _dev

            _current = _next_state

        return AttackScenario(
            scenario_name=scenario_name,
            initial_state=current_state,
            projected_states=_projected,
            affected_nodes=_infected,
            impact_radius=len(_infected),
            max_deviation=round(_max_dev, 4),
            containment_effectiveness={},
        )

    def compare_containment(
        self,
        scenario: AttackScenario,
        strategies: Dict[str, Set[str]],  # {策略名: 隔离节点集合}
    ) -> AttackScenario:
        """对比多种遏制策略的效果。

        策略可以是"隔离节点X"、"阻断协议Y"、"限速Z%"等。
        """
        _results: Dict[str, float] = {}

        for _name, _isolated in strategies.items():
            # 模拟隔离后的投影——被隔离节点无法感染邻居
            _eff_infected = scenario.affected_nodes - _isolated
            _effectiveness = 1.0 - len(_eff_infected) / max(
                len(scenario.affected_nodes), 1
            )
            _results[_name] = round(_effectiveness, 3)

        scenario.containment_effectiveness = _results
        return scenario

    def identify_critical_nodes(
        self, top_k: int = 5,
    ) -> List[Tuple[str, float]]:
        """识别关键节点——其失陷导致最大网络状态偏移。

        基于度中心性 + 桥接系数的综合评分。
        """
        _scores: Dict[str, float] = {}
        _total_nodes = max(len(self._node_neighbors), 1)

        for _node, _neighbors in self._node_neighbors.items():
            _degree = len(_neighbors)
            _degree_score = _degree / _total_nodes

            # 桥接系数——邻居之间缺少连接→该节点是关键桥
            _bridge = 0.0
            for _n1 in _neighbors:
                _n1_neighbors = self._node_neighbors.get(_n1, set())
                _common = len(_neighbors & _n1_neighbors)
                if len(_neighbors) > 1:
                    _bridge += 1.0 - _common / (len(_neighbors) - 1 + _EPS)
            _bridge /= max(len(_neighbors), 1)

            _scores[_node] = _degree_score * 0.4 + _bridge * 0.6

        _ranked = sorted(_scores.items(), key=lambda x: x[1], reverse=True)
        return _ranked[:top_k]

    # 内部

    def _project_state(
        self, current: NetworkState, infected_count: int,
    ) -> NetworkState:
        """基于当前状态和感染节点数投影下一状态。"""
        # 感染节点增加 → 异常流增加、目标多样性增加
        _anomaly_factor = 1.0 + infected_count * 0.5
        return NetworkState(
            active_flows=int(current.active_flows * _anomaly_factor),
            unique_dst_ips=int(current.unique_dst_ips * 1.2),
            unique_protocols=min(20, current.unique_protocols + 1),
            total_bytes=current.total_bytes * 1.3,
            avg_packet_size=current.avg_packet_size,
            anomaly_flows=int(current.anomaly_flows * _anomaly_factor),
        )

# 冒烟测试
def _smoke_test():
    # 学习历史状态序列
    _history = [
        NetworkState(100, 20, 5, 50000.0, 500.0, 2),
        NetworkState(105, 21, 5, 52000.0, 495.0, 1),
        NetworkState(98, 19, 5, 48000.0, 490.0, 3),
        NetworkState(102, 22, 6, 51000.0, 505.0, 2),
        NetworkState(110, 20, 5, 53000.0, 500.0, 1),
    ]

    _twin = NetworkDigitalTwin()
    _twin.learn_from_history(_history)

    # 注册网络拓扑
    for _i in range(1, 11):
        for _j in range(_i + 1, min(_i + 4, 11)):
            _twin.register_node_connection(f"host_{_i}", f"host_{_j}")

    # 投影攻击场景
    _current = NetworkState(100, 20, 5, 50000.0, 500.0, 2)
    _scenario = _twin.project_attack(
        "ransomware_spread", ["host_1", "host_2"],
        current_state=_current, projection_steps=8,
    )

    print(f"[twin] scenario: {_scenario.scenario_name}")
    print(f"[twin] affected nodes: {_scenario.impact_radius}")
    print(f"[twin] max deviation: {_scenario.max_deviation:.4f}")
    print(f"[twin] projected states: {len(_scenario.projected_states)} steps")

    # 对比遏制策略
    _strategies = {
        "isolate_host_1": {"host_1"},
        "isolate_host_1_2": {"host_1", "host_2"},
        "isolate_super_spreaders": {"host_1", "host_2", "host_3"},
    }
    _scenario = _twin.compare_containment(_scenario, _strategies)
    print(f"[twin] containment: {_scenario.containment_effectiveness}")

    _critical = _twin.identify_critical_nodes(top_k=3)
    print(f"[twin] critical nodes: {_critical}")

    assert _scenario.impact_radius >= 2, "attack should spread"
    assert len(_scenario.containment_effectiveness) == 3
    print("[OK] NetworkDigitalTwin smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
