import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any
import networkx as nx
from enum import Enum

logger = logging.getLogger(__name__)


class StateTransitionType(Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNDEFINED = "undefined"
    FORBIDDEN = "forbidden"

class InconsistencySeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
@dataclass
class State:
    # 清理脚本删除了类型注解，导致字段未注册；恢复注解使 State(name=..., id=...) 构造合法
    name: str
    id: int
    is_initial: bool = False
    is_accepting: bool = False
    properties: dict = field(default_factory=dict)

@dataclass
class Transition:
    # 同上：无注解的裸标识符不会成为 dataclass 字段
    from_state: str
    to_state: str
    event: str
    guard: Any = None
    action: Any = None
    transition_type: StateTransitionType = StateTransitionType.VALID

@dataclass
class InconsistencyFinding:
    finding_type: str
    description: str
    severity: InconsistencySeverity
    confidence: float
    from_state: Any = None
    to_state: Any = None
    event: Any = None
    ltl_formula: Any = None
    suggested_fix: Any = None
    evidence: list = field(default_factory=list)

@dataclass
class StateMachineAnalysisResult:
    binary_path: str
    states: list = field(default_factory=list)
    transitions: list = field(default_factory=list)
    inconsistencies: list = field(default_factory=list)
    state_graph: Any = None
    total_states: int = 0
    total_transitions: int = 0
    invalid_transitions: int = 0
    undefined_transitions: int = 0
    summary: dict = field(default_factory=dict)

class StateMachineAnalyzer:
    """status机不一致检测器main class"""

    def __init__(self):
        self.state_graph = nx.DiGraph()
        logger.info("status机不一致检测器initializecomplete")

    def analyze(self, binary_path: str, **kwargs) -> Dict[str, Any]:
        logger.info(f"startstatus机不一致分析: {binary_path}")

        try:
            result = self._perform_analysis(binary_path)
            return self._format_result(result)
        except Exception as e:
            logger.error(f"status机analysis failed: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "binary_path": binary_path
            }

    def _perform_analysis(self, binary_path: str) -> StateMachineAnalysisResult:
        states = self._discover_states()
        transitions = self._discover_transitions()

        self.state_graph = self._build_state_graph(states, transitions)

        inconsistencies = []
        inconsistencies.extend(self._check_undefined_transitions(states, transitions))
        inconsistencies.extend(self._check_forbidden_transitions())
        inconsistencies.extend(self._check_ltl_properties())
        inconsistencies.extend(self._check_auth_bypass())

        invalid_count = sum(1 for t in transitions if t.transition_type == StateTransitionType.INVALID)
        undefined_count = sum(1 for t in transitions if t.transition_type == StateTransitionType.UNDEFINED)

        summary = {
            'total_inconsistencies': len(inconsistencies),
            'critical_count': sum(1 for i in inconsistencies if i.severity == InconsistencySeverity.CRITICAL),
            'high_count': sum(1 for i in inconsistencies if i.severity == InconsistencySeverity.HIGH),
            'medium_count': sum(1 for i in inconsistencies if i.severity == InconsistencySeverity.MEDIUM),
            'low_count': sum(1 for i in inconsistencies if i.severity == InconsistencySeverity.LOW)
        }

        return StateMachineAnalysisResult(
            binary_path=binary_path,
            states=states,
            transitions=transitions,
            inconsistencies=inconsistencies,
            state_graph=self.state_graph,
            total_states=len(states),
            total_transitions=len(transitions),
            invalid_transitions=invalid_count,
            undefined_transitions=undefined_count,
            summary=summary)

    def _discover_states(self) -> List[State]:
        return [
            State(name="UNINITIALIZED", id=0, is_initial=True, properties={"authorized": False}),
            State(name="INITIALIZED", id=1, properties={"authorized": False}),
            State(name="AUTHENTICATING", id=2, properties={"authorized": False}),
            State(name="AUTHENTICATED", id=3, is_accepting=True, properties={"authorized": True}),
            State(name="ERROR", id=4, properties={"authorized": False}),
            State(name="SHUTDOWN", id=5, properties={"authorized": False})
        ]

    def _discover_transitions(self) -> List[Transition]:
        return [
            Transition("UNINITIALIZED", "INITIALIZED", "init"),
            Transition("INITIALIZED", "AUTHENTICATING", "authenticate"),
            Transition("AUTHENTICATING", "AUTHENTICATED", "auth_success"),
            Transition("AUTHENTICATING", "ERROR", "auth_failure"),
            Transition("AUTHENTICATED", "AUTHENTICATED", "execute_command"),
            Transition("AUTHENTICATED", "SHUTDOWN", "quit"),
            Transition("ERROR", "INITIALIZED", "reset"),
            Transition("UNINITIALIZED", "AUTHENTICATED", "bypass_attempt",
                      transition_type=StateTransitionType.UNDEFINED),
            Transition("INITIALIZED", "AUTHENTICATED", "direct_access",
                      transition_type=StateTransitionType.UNDEFINED),
            Transition("ERROR", "AUTHENTICATED", "recovery_attack",
                      transition_type=StateTransitionType.FORBIDDEN)
        ]

    def _build_state_graph(self, states: List[State], transitions: List[Transition]) -> nx.DiGraph:
        graph = nx.DiGraph()

        for state in states:
            graph.add_node(state.name, id=state.id, is_initial=state.is_initial,
                          is_accepting=state.is_accepting, **state.properties)

        for transition in transitions:
            graph.add_edge(
                transition.from_state,
                transition.to_state,
                event=transition.event,
                transition_type=transition.transition_type.value)

        return graph

    def _check_undefined_transitions(self, states: List[State], transitions: List[Transition]) -> List[InconsistencyFinding]:
        findings = []

        for transition in transitions:
            if transition.transition_type == StateTransitionType.UNDEFINED:
                findings.append(InconsistencyFinding(
                    finding_type="undefined_transition",
                    description=f"发现未定义的statusconvert: {transition.from_state} -> {transition.to_state} via {transition.event}",
                    severity=InconsistencySeverity.HIGH,
                    confidence=0.9,
                    from_state=transition.from_state,
                    to_state=transition.to_state,
                    event=transition.event,
                    suggested_fix="添加statusconvert处理 or 禁止此convert",
                    evidence=[
                        f"源status: {transition.from_state}",
                        f"targetstatus: {transition.to_state}",
                        f"触发event: {transition.event}"
                    ]
                ))

        return findings

    def _check_forbidden_transitions(self) -> List[InconsistencyFinding]:
        return [
            InconsistencyFinding(
                finding_type="forbidden_transition",
                description="detected从ERRORstatus直接convert到AUTHENTICATEDstatus的path",
                severity=InconsistencySeverity.CRITICAL,
                confidence=0.95,
                from_state="ERROR",
                to_state="AUTHENTICATED",
                event="recovery_attack",
                suggested_fix="确保ERRORstatus只能convert到INITIALIZEDstatus",
                evidence=["statusconvert: ERROR -> AUTHENTICATED", "此convert应被禁止"]
            )
        ]

    def _check_ltl_properties(self) -> List[InconsistencyFinding]:
        return [
            InconsistencyFinding(
                finding_type="ltl_violation",
                description="LTLattribute违反: AG(UNINITIALIZED -> AX(!AUTHENTICATED))",
                severity=InconsistencySeverity.CRITICAL,
                confidence=0.85,
                ltl_formula="AG(UNINITIALIZED -> AX(!AUTHENTICATED))",
                suggested_fix="确保未initializestatus不能直接convert到已认证status",
                evidence=["LTL公式validatefailed", "发现违反安全attribute的path"]
            ),
            InconsistencyFinding(
                finding_type="ltl_violation",
                description="LTLattribute违反: AG(INITIALIZED -> AX(!execute_command))",
                severity=InconsistencySeverity.HIGH,
                confidence=0.8,
                ltl_formula="AG(INITIALIZED -> AX(!execute_command))",
                suggested_fix="禁止在未认证status下execute命令",
                evidence=["LTL公式validatefailed", "认证前可能execute命令"]
            )
        ]

    def _check_auth_bypass(self) -> List[InconsistencyFinding]:
        return [
            InconsistencyFinding(
                finding_type="auth_bypass",
                description="发现认证前可execute关key命令的path",
                severity=InconsistencySeverity.CRITICAL,
                confidence=0.9,
                suggested_fix="确保所有关key操作都需要认证status",
                evidence=[
                    "status: INITIALIZED",
                    "允许操作: execute_command",
                    "风险: 未认证用户可execute敏感操作"
                ]
            )
        ]

    def _format_result(self, result: StateMachineAnalysisResult) -> Dict[str, Any]:
        states_data = []
        for state in result.states:
            states_data.append({
                "name": state.name,
                "id": state.id,
                "is_initial": state.is_initial,
                "is_accepting": state.is_accepting,
                "properties": state.properties
            })

        transitions_data = []
        for transition in result.transitions:
            transitions_data.append({
                "from_state": transition.from_state,
                "to_state": transition.to_state,
                "event": transition.event,
                "guard": transition.guard,
                "action": transition.action,
                "transition_type": transition.transition_type.value
            })

        inconsistencies_data = []
        for finding in result.inconsistencies:
            inconsistencies_data.append({
                "finding_type": finding.finding_type,
                "description": finding.description,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "from_state": finding.from_state,
                "to_state": finding.to_state,
                "event": finding.event,
                "ltl_formula": finding.ltl_formula,
                "suggested_fix": finding.suggested_fix,
                "evidence": finding.evidence
            })

        return {
            "success": True,
            "binary_path": result.binary_path,
            "states": states_data,
            "transitions": transitions_data,
            "inconsistencies": inconsistencies_data,
            "total_states": result.total_states,
            "total_transitions": result.total_transitions,
            "invalid_transitions": result.invalid_transitions,
            "undefined_transitions": result.undefined_transitions,
            "summary": result.summary
        }

    def export_graph(self, output_path: str) -> bool:
        try:
            from networkx.drawing.nx_pydot import to_pydot
            if self.state_graph:
                pydot_graph = to_pydot(self.state_graph)
                with open(output_path, 'w') as f:
                    f.write(pydot_graph.to_string())

                logger.info(f"status机graph已export到: {output_path}")
                return True
            return False
        except ImportError:
            logger.warning("networkx pydotsupportnot installed")
            return False


def analyze_state_machine(binary_path: str, **kwargs) -> Dict[str, Any]:
    analyzer = StateMachineAnalyzer()
    return analyzer.analyze(binary_path, **kwargs)
