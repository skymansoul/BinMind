import logging, os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Tuple
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


@dataclass
class ProtocolState:
    name: str
    is_authenticated: bool = False
    is_privileged: bool = False
    allowed_actions: List[str] = field(default_factory=list)


@dataclass
class StateTransition:
    source: str; target: str; trigger: str
    conditions: List[str] = field(default_factory=list)
    guard_str: str = ""


@dataclass
class StateMachineModel:
    states: Dict[str, ProtocolState]
    transitions: List[StateTransition]
    initial_state: str


@dataclass
class FuzzingResult:
    success: bool; model: StateMachineModel
    anomalous_transitions: List[StateTransition]
    test_sequences: List[List[str]]


# ── SAEG (ESORICS 2024) 启发的状态ful利用图 ────────────────────────────────
# 将SAEG的Exploit Graph概念移植到协议状态机fuzzing：
# 每个状态迁移对应一个"利用步骤"——未认证→认证→提权。
# 异常迁移（绕过认证的提权）标记为高危利用路径。


class ExploitStateGraph:
    """SAEG风格的利用状态图——将状态机Fuzzing结果映射到利用路径。"""

    def __init__(self, model: StateMachineModel):
        self._model = model

    def find_privilege_escalation_paths(self) -> List[List[str]]:
        """发现提权路径——从任何状态直接到达privileged状态的迁移。"""
        paths: List[List[str]] = []
        privileged = {name for name, s in self._model.states.items() if s.is_privileged}
        for t in self._model.transitions:
            if t.target in privileged:
                src = self._model.states.get(t.source)
                # 若源状态未认证且目标已提权→异常路径
                if src and not src.is_authenticated:
                    paths.append([t.source, t.trigger, t.target])
        return paths

    def compute_attack_surface(self) -> Dict[str, int]:
        """计算每个状态的攻击面——入度（可达方式数）+出度（可攻击目标数）。"""
        in_deg: Dict[str, int] = defaultdict(int)
        out_deg: Dict[str, int] = defaultdict(int)
        for t in self._model.transitions:
            out_deg[t.source] += 1
            in_deg[t.target] += 1
        surface: Dict[str, int] = {}
        for name in self._model.states:
            surface[name] = in_deg.get(name, 0) + out_deg.get(name, 0)
        return surface


class StateMachineInferrer:
    def infer_from_binary(self, binary_path: str) -> StateMachineModel:
        states = {
            "init": ProtocolState(name="init"),
            "connected": ProtocolState(name="connected"),
            "authenticated": ProtocolState(name="authenticated", is_authenticated=True),
            "privileged": ProtocolState(name="privileged", is_privileged=True),
            "error": ProtocolState(name="error"),
        }
        transitions = [
            StateTransition("init", "connected", "connect"),
            StateTransition("connected", "authenticated", "login"),
            StateTransition("authenticated", "privileged", "escalate"),
            StateTransition("connected", "error", "timeout"),
            StateTransition("authenticated", "error", "auth_fail"),
        ]
        return StateMachineModel(states=states, transitions=transitions, initial_state="init")

    def infer_from_network_trace(self, packets: List[Dict[str, Any]]) -> StateMachineModel:
        states: Dict[str, ProtocolState] = {"init": ProtocolState(name="init")}
        transitions: List[StateTransition] = []
        current = "init"
        seen_states: Set[str] = {"init"}
        for pkt in packets:
            trigger = pkt.get('type', 'unknown')
            if trigger not in seen_states:
                seen_states.add(trigger)
                states[trigger] = ProtocolState(name=trigger)
            transitions.append(StateTransition(current, trigger, trigger))
            current = trigger
        return StateMachineModel(states=states, transitions=transitions, initial_state="init")


class StateGuidedFuzzer:
    def __init__(self, model: StateMachineModel):
        self.model = model
        self._adjacency: Dict[str, List[StateTransition]] = defaultdict(list)
        for t in model.transitions:
            self._adjacency[t.source].append(t)
        self._exploit_graph = ExploitStateGraph(model)

    def generate_sequences(self, max_length: int = 5) -> List[List[str]]:
        sequences = []
        queue = deque([(self.model.initial_state, [])])
        visited = set()
        while queue:
            state, path = queue.popleft()
            if len(path) >= max_length:
                continue
            key = (state, tuple(path))
            if key in visited:
                continue
            visited.add(key)
            for t in self._adjacency.get(state, []):
                new_path = path + [t.trigger]
                sequences.append(new_path)
                queue.append((t.target, new_path))
        return sequences

    def find_anomalous_transitions(self) -> List[StateTransition]:
        anomalies = []
        for t in self.model.transitions:
            src = self.model.states.get(t.source)
            tgt = self.model.states.get(t.target)
            if tgt and tgt.is_privileged and src and not src.is_authenticated:
                anomalies.append(t)
        return anomalies

    def find_unreachable_states(self) -> List[str]:
        reachable: Set[str] = set()
        queue = deque([self.model.initial_state])
        while queue:
            s = queue.popleft()
            if s in reachable: continue
            reachable.add(s)
            for t in self._adjacency.get(s, []):
                if t.target not in reachable:
                    queue.append(t.target)
        return list(set(self.model.states.keys()) - reachable)

    def run(self) -> FuzzingResult:
        sequences = self.generate_sequences()
        anomalies = self.find_anomalous_transitions()
        unreachable = self.find_unreachable_states()
        esc_paths = self._exploit_graph.find_privilege_escalation_paths()
        attack_surface = self._exploit_graph.compute_attack_surface()
        logger.info(
            f"State fuzzing complete: {len(sequences)} sequences, "
            f"{len(anomalies)} anomalous, {len(unreachable)} unreachable, "
            f"{len(esc_paths)} escalation paths"
        )
        return FuzzingResult(
            success=True, model=self.model,
            anomalous_transitions=anomalies, test_sequences=sequences
        )


def create_state_fuzzer(binary_path: str) -> StateGuidedFuzzer:
    inferrer = StateMachineInferrer()
    model = inferrer.infer_from_binary(binary_path)
    return StateGuidedFuzzer(model)
