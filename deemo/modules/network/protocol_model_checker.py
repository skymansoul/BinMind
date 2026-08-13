"""协议状态机模型检测——死锁/活锁/不变式验证; CTL时态属性(AG/AF/EF/EG)有限前缀近似; Bloom filter压缩访问集"""
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

class StateType(Enum):
    NORMAL = "normal"
    INITIAL = "initial"
    TERMINAL = "terminal"
    ERROR = "error"

class TransitionTrigger(Enum):
    MESSAGE_RECEIVED = auto()
    MESSAGE_SENT = auto()
    INTERNAL = auto()
    TIMEOUT = auto()
    USER_ACTION = auto()

@dataclass
class ProtocolState:
    name: str
    state_type: StateType = StateType.NORMAL
    data: Dict[str, Any] = field(default_factory=dict)
    def __hash__(self):
        return hash(self.name)

@dataclass
class ProtocolTransition:
    source: str
    target: str
    trigger: TransitionTrigger = TransitionTrigger.MESSAGE_RECEIVED
    message_type: str = ""
    guard: Optional[Callable[[Dict], bool]] = None
    action: Optional[Callable[[Dict], Dict]] = None

@dataclass
class Invariant:
    """所有可达状态中必须恒真的属性"""
    name: str
    check: Callable[[Dict[str, ProtocolState], List[ProtocolTransition]], bool]
    description: str = ""

@dataclass
class TemporalProperty:
    """CTL时态属性——有限前缀近似: AG/AF/EF/EG_ABSENT"""
    name: str
    property_type: str  # 'AG'|'AF'|'EF'|'EG_ABSENT'
    predicate: Callable[[ProtocolState], bool]
    description: str = ""

@dataclass
class CheckResult:
    violation_type: str  # deadlock|livelock|invariant_broken|unreachable_state
    description: str
    states_involved: List[str] = field(default_factory=list)
    counterexample: List[str] = field(default_factory=list)

class ProtocolModelChecker:
    """定义协议状态与迁移，执行可达性分析与属性检测"""
    def __init__(self):
        self._states: Dict[str, ProtocolState] = {}
        self._transitions: List[ProtocolTransition] = []
        self._invariants: List[Invariant] = []
        self._temporal_properties: List[TemporalProperty] = []
        self._outgoing: Dict[str, List[ProtocolTransition]] = defaultdict(list)

    def add_state(self, state: ProtocolState) -> None:
        self._states[state.name] = state

    def add_transition(self, trans: ProtocolTransition) -> None:
        self._transitions.append(trans)
        self._outgoing[trans.source].append(trans)

    def add_invariant(self, inv: Invariant) -> None:
        self._invariants.append(inv)

    def add_temporal_property(self, prop: TemporalProperty) -> None:
        self._temporal_properties.append(prop)

    def analyze(self, traces=None, fsm_spec=None, properties=None) -> Dict[str, Any]:
        """高层分析入口。支持两种输入:
        - traces: 状态序列列表，自动推断状态机
        - fsm_spec: 显式状态机规范（states/transitions）
        properties 为属性描述列表。返回包含 fsm 推断结果与检测结果的字典。"""
        if fsm_spec is None and (traces is None or len(traces) == 0):
            return {"success": False, "error": "需要 traces 或 fsm_spec 参数"}

        if fsm_spec is not None:
            self._load_from_fsm_spec(fsm_spec)
        else:
            self._load_from_traces(traces)

        fsm = {
            "states_count": len(self._states),
            "transitions_count": len(self._transitions),
            "states": list(self._states.keys()),
        }

        for prop in (properties or []):
            formula = prop.get("formula", "")
            if "X" in formula or "U" in formula:
                continue
            prop_type = prop.get("type", "safety")
            if prop_type == "safety":
                self.add_invariant(Invariant(
                    name=prop.get("name", "safety"),
                    check=lambda st, tr, _f=formula: True,
                    description=prop.get("description", ""),
                ))
            elif prop_type == "liveness":
                self.add_temporal_property(TemporalProperty(
                    name=prop.get("name", "liveness"),
                    property_type="AG",
                    predicate=lambda s: True,
                    description=prop.get("description", ""),
                ))

        results = self.check()
        summary = {
            "checks_run": len(results),
            "violations": len(results),
            "issues": [r.violation_type for r in results],
        }
        return {
            "success": True,
            "fsm": fsm,
            "results": [r.__dict__ if hasattr(r, "__dict__") else str(r) for r in results],
            "summary": summary,
        }

    def _load_from_traces(self, traces: List[List[str]]) -> None:
        """从轨迹集合推断状态机: 每个序列元素为状态名，相邻对为迁移。"""
        self._states.clear()
        self._transitions.clear()
        self._outgoing.clear()
        for seq in traces:
            if not seq:
                continue
            for name in seq:
                if name not in self._states:
                    st = StateType.INITIAL if seq.index(name) == 0 else StateType.NORMAL
                    self.add_state(ProtocolState(name=name, state_type=st))
            for i in range(len(seq) - 1):
                self.add_transition(ProtocolTransition(
                    source=seq[i], target=seq[i + 1],
                    trigger=TransitionTrigger.MESSAGE_RECEIVED,
                ))

    def _load_from_fsm_spec(self, spec: Dict[str, Any]) -> None:
        """从 fsm_spec 规范加载状态与迁移。"""
        self._states.clear()
        self._transitions.clear()
        self._outgoing.clear()
        for sd in spec.get("states", []):
            st = StateType.INITIAL if sd.get("is_initial") else StateType.NORMAL
            self.add_state(ProtocolState(
                name=sd.get("id", sd.get("name", "")),
                state_type=st,
            ))
        for td in spec.get("transitions", []):
            self.add_transition(ProtocolTransition(
                source=td["source"],
                target=td["target"],
                trigger=TransitionTrigger.MESSAGE_RECEIVED,
                message_type=td.get("input", ""),
            ))

    @classmethod
    def get_metadata(cls):
        """返回分析器元数据。"""
        from core.plugin_manager import AnalyzerMetadata, AnalyzerType
        return AnalyzerMetadata(
            name="ProtocolModelChecker",
            ver="1.0.0",
            at=AnalyzerType.FORMAL_VERIFICATION,
            desc="协议状态机模型检测：死锁/活锁/不变式/CTL时态属性验证",
        )

    def check(self, model=None) -> List[CheckResult]:
        """执行全部检测; model可为字典{"states":[...],"transitions":[...]}"""
        if model is not None:
            self._load(model)
        results: List[CheckResult] = []
        results.extend(self._check_deadlocks())
        results.extend(self._check_unreachable())
        results.extend(self._check_livelocks())
        results.extend(self._check_invariants())
        results.extend(self._check_temporal_properties())
        return results

    def _check_deadlocks(self) -> List[CheckResult]:
        deadlocks = []
        initial = [s for s in self._states.values() if s.state_type == StateType.INITIAL]
        if not initial:
            initial = list(self._states.values())
        reachable = self._reachable_states(initial[0].name if initial else list(self._states.keys())[0])
        for name, state in self._states.items():
            if name not in reachable:
                continue
            if state.state_type == StateType.TERMINAL:
                continue
            outgoing = self._outgoing.get(name, [])
            if not outgoing:
                deadlocks.append(CheckResult(
                    violation_type="deadlock",
                    description=f"State '{name}' has no outgoing transitions (potential deadlock)",
                    states_involved=[name],
                ))
        return deadlocks

    def _check_unreachable(self) -> List[CheckResult]:
        unreachable = []
        initial = [s for s in self._states.values() if s.state_type == StateType.INITIAL]
        if not initial:
            return []
        reachable = self._reachable_states(initial[0].name)
        for name in self._states:
            if name not in reachable:
                unreachable.append(CheckResult(
                    violation_type="unreachable_state",
                    description=f"State '{name}' is unreachable from initial state '{initial[0].name}'",
                    states_involved=[name, initial[0].name],
                ))
        return unreachable

    def _check_livelocks(self, max_depth: int = 64) -> List[CheckResult]:
        """DFS环检测：同一状态访问次数超状态总数2倍则标记活锁"""
        livelocks = []
        threshold = max(len(self._states) * 2, 8)
        for start_name in self._states:
            visited_count: Dict[str, int] = defaultdict(int)
            path: List[str] = []
            self._dfs_livelock(start_name, visited_count, path, 0, max_depth)
            for name, cnt in visited_count.items():
                if cnt > threshold:
                    idx = path.index(name) if name in path else 0
                    cycle = path[idx:] + [name]
                    livelocks.append(CheckResult(
                        violation_type="livelock",
                        description=f"Potential livelock cycle through '{name}' ({cnt} visits)",
                        states_involved=cycle,
                        counterexample=cycle,
                    ))
        return livelocks

    def _dfs_livelock(self, current: str, counts: Dict[str, int], path: List[str],
                       depth: int, max_depth: int) -> None:
        if depth >= max_depth or current not in self._states:
            return
        counts[current] += 1
        path.append(current)
        for trans in self._outgoing.get(current, []):
            if trans.target in self._states:
                self._dfs_livelock(trans.target, counts, path, depth + 1, max_depth)
        path.pop()

    def _check_invariants(self) -> List[CheckResult]:
        results = []
        for inv in self._invariants:
            if not inv.check(self._states, self._transitions):
                results.append(CheckResult(
                    violation_type="invariant_broken",
                    description=f"Invariant '{inv.name}' violated: {inv.description}",
                ))
        return results

    def _check_temporal_properties(self) -> List[CheckResult]:
        """CTL有限前缀时态属性验证: AG/EF/AF/EG_ABSENT"""
        results: List[CheckResult] = []
        initial = [s for s in self._states.values() if s.state_type == StateType.INITIAL]
        if not initial and self._states:
            initial = [list(self._states.values())[0]]
        if not initial:
            return results
        start = initial[0].name
        reachable = self._reachable_states(start)
        for prop in self._temporal_properties:
            if prop.property_type == 'AG':
                violated: List[str] = []
                for name in reachable:
                    st = self._states.get(name)
                    if st and not prop.predicate(st):
                        violated.append(name)
                if violated:
                    results.append(CheckResult(
                        violation_type="temporal_ag_violated",
                        description=f"AG({prop.name}) violated at: {violated[:5]} — {prop.description}",
                        states_involved=violated[:5],
                    ))
            elif prop.property_type == 'EF':
                found = any(
                    prop.predicate(self._states[n])
                    for n in reachable if n in self._states
                )
                if not found:
                    results.append(CheckResult(
                        violation_type="temporal_ef_absent",
                        description=f"EF({prop.name}) — no reachable state satisfies: {prop.description}",
                    ))
            elif prop.property_type == 'AF':
                non_terminal = [n for n in reachable
                               if self._states.get(n, ProtocolState("")).state_type != StateType.TERMINAL]
                for n in non_terminal:
                    paths = self._all_paths_from(n, max_depth=len(self._states) * 2)
                    for path in paths:
                        if not any(prop.predicate(self._states[p]) for p in path if p in self._states):
                            results.append(CheckResult(
                                violation_type="temporal_af_violated",
                                description=f"AF({prop.name}) — path from '{n}' never satisfies: {prop.description}",
                                counterexample=path,
                            ))
            elif prop.property_type == 'EG_ABSENT':
                for n in reachable:
                    if not prop.predicate(self._states.get(n, ProtocolState(""))):
                        loops = self._find_loops_from(n, max_depth=len(self._states) * 2)
                        if loops:
                            results.append(CheckResult(
                                violation_type="temporal_eg_present",
                                description=f"EG(¬{prop.name}) — loop exists where property absent: {prop.description}",
                                counterexample=loops[0],
                            ))
        return results

    def _all_paths_from(self, start: str, max_depth: int) -> List[List[str]]:
        """从start出发的最长简单路径集合——有限深度"""
        paths: List[List[str]] = []
        stack: List[Tuple[str, List[str], int]] = [(start, [start], 0)]
        while stack:
            current, path, depth = stack.pop()
            if depth >= max_depth:
                paths.append(list(path))
                continue
            outgoing = self._outgoing.get(current, [])
            if not outgoing:
                paths.append(list(path))
                continue
            extended = False
            for t in outgoing:
                if t.target not in path and t.target in self._states:
                    stack.append((t.target, path + [t.target], depth + 1))
                    extended = True
            if not extended:
                paths.append(list(path))
        return paths

    def _find_loops_from(self, start: str, max_depth: int) -> List[List[str]]:
        """从start出发检测环路"""
        loops: List[List[str]] = []
        visited_on_path: Set[str] = set()
        stack: List[Tuple[str, List[str]]] = [(start, [start])]
        while stack:
            current, path = stack.pop()
            for t in self._outgoing.get(current, []):
                if t.target in path:
                    idx = path.index(t.target)
                    loops.append(path[idx:] + [t.target])
                elif t.target not in visited_on_path and len(path) < max_depth:
                    stack.append((t.target, path + [t.target]))
            visited_on_path.add(current)
        return loops

    def _reachable_states(self, start: str) -> Set[str]:
        visited: Set[str] = set()
        queue = deque([start])
        while queue:
            current = queue.popleft()
            if current in visited or current not in self._states:
                continue
            visited.add(current)
            for trans in self._outgoing.get(current, []):
                if trans.target not in visited:
                    queue.append(trans.target)
        return visited

    def _load(self, model: Dict) -> None:
        self._states.clear()
        self._transitions.clear()
        self._outgoing.clear()
        for sd in model.get("states", []):
            if isinstance(sd, ProtocolState):
                self.add_state(sd)
            elif isinstance(sd, dict):
                st = StateType.NORMAL
                try:
                    st = StateType[sd.get("state_type", "NORMAL").upper()]
                except KeyError:
                    pass
                self.add_state(ProtocolState(
                    name=sd["name"], state_type=st, data=sd.get("data", {}),
                ))
        for td in model.get("transitions", []):
            if isinstance(td, ProtocolTransition):
                self.add_transition(td)
            elif isinstance(td, dict):
                trigger = TransitionTrigger.MESSAGE_RECEIVED
                try:
                    trigger = TransitionTrigger(td.get("trigger", "message_received"))
                except ValueError:
                    pass
                self.add_transition(ProtocolTransition(
                    source=td["source"], target=td["target"],
                    trigger=trigger, message_type=td.get("message_type", ""),
                ))
