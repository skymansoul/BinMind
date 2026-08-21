import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List
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
    source: str
    target: str
    trigger: str
    conditions: List[str] = field(default_factory=list)


@dataclass
class StateMachineModel:
    states: Dict[str, ProtocolState]
    transitions: List[StateTransition]
    initial_state: str


@dataclass
class FuzzingResult:
    success: bool
    model: StateMachineModel
    anomalous_transitions: List[StateTransition]
    test_sequences: List[List[str]]


class StateMachineInferrer:
    def infer_from_binary(self, binary_path: str) -> StateMachineModel:
        if not binary_path or not os.path.isfile(binary_path):
            logger.warning("binary_path 缺失或无效，返回空状态机模型")
            return StateMachineModel(
                states={}, transitions=[], initial_state=""
            )
        # 协议状态机推断需上层符号执行引擎支持，此处仅构建空模型骨架
        logger.info("状态机推断需配合符号执行引擎，当前返回空模型: %s", binary_path)
        return StateMachineModel(
            states={}, transitions=[], initial_state=""
        )


class StateGuidedFuzzer:
    def __init__(self, model: StateMachineModel):
        self.model = model
        self._adjacency: Dict[str, List[StateTransition]] = defaultdict(list)
        for t in model.transitions:
            self._adjacency[t.source].append(t)

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
            if (tgt and tgt.is_privileged and src and not src.is_authenticated):
                anomalies.append(t)
        return anomalies

    def run(self) -> FuzzingResult:
        sequences = self.generate_sequences()
        anomalies = self.find_anomalous_transitions()
        logger.info(
            f"State fuzzing complete: {len(sequences)} sequences, "
            f"{len(anomalies)} anomalous transitions"
        )
        return FuzzingResult(
            success=True, model=self.model,
            anomalous_transitions=anomalies, test_sequences=sequences
        )


def create_state_fuzzer(binary_path: str) -> StateGuidedFuzzer:
    inferrer = StateMachineInferrer()
    model = inferrer.infer_from_binary(binary_path)
    return StateGuidedFuzzer(model)
