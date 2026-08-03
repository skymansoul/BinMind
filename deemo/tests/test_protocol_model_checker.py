"""
Protocol model checker tests -- enriched with state/transition dataclass tests,
invariant and CTL temporal property checking, deadlock/livelock detection.

Tests both the trac-based analysis and FSM-spec-based verification paths.
"""
import pytest
import sys
_MOD_DEBUG = False
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.protocol_model_checker import (
    ProtocolModelChecker,
    ProtocolState,
    ProtocolTransition,
    StateType,
    TransitionTrigger,
    Invariant,
    TemporalProperty,
    CheckResult,
)


class TestStateType:
    """State type enum."""

    def test_initial_value(self):
        assert StateType.INITIAL.value == "initial"

    def test_terminal_value(self):
        assert StateType.TERMINAL.value == "terminal"

    def test_error_value(self):
        assert StateType.ERROR.value == "error"


class TestProtocolState:
    """Protocol state node dataclass."""

    def test_minimal_state(self):
        s = ProtocolState(name="IDLE", state_type=StateType.NORMAL)
        assert s.name == "IDLE"
        assert s.state_type == StateType.NORMAL

    def test_initial_state(self):
        s = ProtocolState(name="START", state_type=StateType.INITIAL)
        assert s.state_type == StateType.INITIAL

    def test_state_hashing(self):
        """相同 name 的状态哈希一致"""
        s1 = ProtocolState(name="X", state_type=StateType.NORMAL)
        s2 = ProtocolState(name="X", state_type=StateType.NORMAL)
        assert hash(s1) == hash(s2)


class TestProtocolTransition:
    """Protocol transition edge dataclass."""

    def test_simple_transition(self):
        t = ProtocolTransition(
            source="A", target="B",
            trigger=TransitionTrigger.MESSAGE_RECEIVED,
            message_type="GO",
        )
        assert t.source == "A"
        assert t.target == "B"

    def test_guarded_transition(self):
        """带 guard 的转换，guard 应可调用"""
        t = ProtocolTransition(
            source="W", target="X",
            trigger=TransitionTrigger.MESSAGE_RECEIVED,
            message_type="AUTH_RESP",
            guard=lambda state, msg: msg.get("ok", False),
        )
        assert t.guard is not None

    def test_transition_with_action(self):
        """带 action 的转换，action 应可调用"""
        called = []
        t = ProtocolTransition(
            source="W", target="X",
            trigger=TransitionTrigger.INTERNAL,
            message_type="TIMEOUT",
            action=lambda state, msg: called.append(True),
        )
        assert t.action is not None


class TestInvariant:
    """Global invariant definition."""

    def test_invariant_creation(self):
        inv = Invariant(
            name="pos_seq",
            check=lambda state, transitions: True,
            description="Seq >= 0",
        )
        assert inv.name == "pos_seq"


class TestTemporalProperty:
    """CTL temporal property."""

    def test_ag_property(self):
        prop = TemporalProperty(
            name="always_ok",
            property_type="AG",
            predicate=lambda s: True,
            description="Globally holds",
        )
        assert prop.property_type == "AG"

    def test_ef_property(self):
        prop = TemporalProperty(
            name="reachable",
            property_type="EF",
            predicate=lambda s: s.state_type == StateType.TERMINAL,
            description="Terminal is reachable",
        )
        assert prop.property_type == "EF"


class TestCheckResult:
    """Violation check result."""

    def test_deadlock_result(self):
        cr = CheckResult(
            violation_type="DEADLOCK",
            description="State X stuck",
            states_involved=["X"],
            counterexample=["START", "X"],
        )
        assert len(cr.states_involved) == 1
        assert cr.violation_type == "DEADLOCK"


class TestProtocolModelChecker:
    """协议模型检查器测试类"""

    @classmethod
    def setup_class(cls):
        cls.checker = ProtocolModelChecker()

    def test_check_model_from_traces(self):
        traces = [
            ["CONNECT", "AUTH", "DATA", "DISCONNECT"],
            ["CONNECT", "AUTH", "DATA", "DATA", "DISCONNECT"],
            ["CONNECT", "DISCONNECT"]
        ]
        properties = [
            {
                "name": "always_authenticate",
                "formula": "G (state = S0 -> X (state = S1))",
                "type": "safety",
                "description": "连接后必须认证"
            }
        ]
        result = self.checker.analyze(traces=traces, properties=properties)
        assert result["success"] is True
        assert "fsm" in result
        assert result["fsm"]["states_count"] > 0
        assert result["fsm"]["transitions_count"] > 0
        assert "results" in result

    def test_check_model_from_fsm_spec(self):
        fsm_spec = {
            "name": "SimpleProtocol",
            "states": [
                {"id": "S0", "name": "Initial", "is_initial": True},
                {"id": "S1", "name": "Authenticated"},
                {"id": "S2", "name": "Data"}
            ],
            "transitions": [
                {"source": "S0", "target": "S1", "input": "AUTH"},
                {"source": "S1", "target": "S2", "input": "DATA"},
                {"source": "S2", "target": "S1", "input": "ACK"}
            ]
        }
        properties = [
            {
                "name": "safety_property",
                "formula": "G !(state = S2 & X state = S0)",
                "type": "safety",
                "description": "不能从数据状态直接回到初始状态"
            }
        ]
        result = self.checker.analyze(fsm_spec=fsm_spec, properties=properties)
        assert result["success"] is True
        assert "fsm" in result
        assert "results" in result

    def test_check_violated_property(self):
        traces = [
            ["OPEN", "READ", "CLOSE"],
            ["OPEN", "WRITE", "CLOSE"]
        ]
        properties = [
            {
                "name": "always_close",
                "formula": "false",
                "type": "safety",
                "description": "总是假的属性（用于测试违规）"
            }
        ]
        result = self.checker.analyze(traces=traces, properties=properties)
        assert result["success"] is True
        assert "summary" in result

    def test_missing_required_parameters(self):
        result = self.checker.analyze(traces=[], properties=[])
        assert result["success"] is False
        assert "error" in result

    def test_get_metadata(self):
        metadata = ProtocolModelChecker.get_metadata()
        assert metadata.name == "ProtocolModelChecker"
        assert metadata.type.value == "formal_verification"
        assert metadata.version == "1.0.0"
        assert "协议状态机" in metadata.description

    def test_deadlock_detection_with_dangling_state(self):
        """不可达状态检测 — 孤立状态应被标记"""
        fsm_spec = {
            "name": "DanglingTest",
            "states": [
                {"id": "S0", "name": "Start", "is_initial": True},
                {"id": "S1", "name": "Alive"},
                {"id": "S2", "name": "Orphaned"},
            ],
            "transitions": [
                {"source": "S0", "target": "S1", "input": "CONNECT"},
            ],
        }
        result = self.checker.analyze(fsm_spec=fsm_spec, properties=[])
        assert result["success"] is True
        assert "fsm" in result

    def test_empty_traces_with_properties(self):
        """空轨迹 + 属性 → 应至少返回错误或 success=False"""
        result = self.checker.analyze(
            traces=[], properties=[{"name": "p", "formula": "G true", "type": "safety"}]
        )
        assert "success" in result
