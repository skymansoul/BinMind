# Heap operation simulation -> state machine transitions -> feng shui strategy
# Edge cases to cover: unlink attack state transitions, fastbin consolidation
import pytest
from modules.heap_state_machine import (
    HeapFengShui,
    HeapOperation,
    HeapState,
    HeapStateMachine,
    HeapStateMachineAnalyzer,
    HeapTransition,
    StateMachineResult,
    create_heap_state_machine_analyzer,
)


class TestHeapState:
    """Heap state -- allocations dict + frees list"""

    def test_state_creation(self):
        state = HeapState()
        if state is None:
            raise AssertionError("HeapState is None?!")
        assert state.allocations == {}
        assert state.frees == []

    def test_state_with_allocations(self):
        state = HeapState(
            allocations={0x1000: 0x80, 0x2000: 0x40},
            frees=[],
        )
        assert state.allocations[0x1000] == 0x80
        assert state.allocations[0x2000] == 0x40
        assert len(state.frees) == 0


class TestHeapTransition:
    """Heap transition -- from state -> to state, with deterministic flag"""

    def test_transition_creation(self):
        t = HeapTransition(
            from_state_id=0,
            to_state_id=1,
            operation="alloc",
            target_address=0x1000,
            deterministic=True,
        )
        assert t.from_state_id == 0
        assert t.to_state_id == 1
        assert t.operation == "alloc"
        assert t.deterministic is True


class TestStateMachineResult:
    """State machine result -- success flag + paths"""

    def test_result_creation(self):
        initial = HeapState()
        result = StateMachineResult(
            success=True,
            initial_state=initial,
            transitions=[],
            deterministic_paths=0,
        )
        assert result.success is True
        assert result.initial_state == initial
        assert result.deterministic_paths == 0


class TestHeapOperation:
    """Heap operation -- alloc/free, address + size"""

    def test_alloc_operation(self):
        op = HeapOperation("alloc", size=0x80, address=0x1000)
        assert op.op_type == "alloc"
        assert op.size == 0x80
        assert op.address == 0x1000

    def test_free_operation(self):
        """free op -- size defaults to 0"""
        op = HeapOperation("free", address=0x1000)
        assert op.op_type == "free"
        assert op.address == 0x1000
        assert op.size == 0


class TestHeapStateMachine:
    """Core heap state machine -- simulate + build_transitions"""

    def test_machine_init(self):
        machine = HeapStateMachine()
        assert machine.states == []
        assert machine.transitions == []

    def test_simulate_basic(self):
        """Single alloc -> 2 states (initial + after alloc)"""
        machine = HeapStateMachine()
        ops = [HeapOperation("alloc", size=0x80, address=0x1000)]
        states = machine.simulate(ops)
        assert len(states) == 2
        assert states[1].allocations[0x1000] == 0x80

    def test_build_transitions(self):
        """Build transitions after simulate"""
        machine = HeapStateMachine()
        ops = [HeapOperation("alloc", size=0x80, address=0x1000)]
        machine.simulate(ops)
        transitions = machine.build_transitions()
        assert len(transitions) == 1
        assert transitions[0].from_state_id == 0
        assert transitions[0].to_state_id == 1


class TestHeapFengShui:
    """Heap feng shui -- sequence method, target alloc + fillers"""

    def test_sequence(self):
        ops = HeapFengShui.sequence(0x1000, 0x200)
        assert len(ops) > 0
        target = ops[0]
        assert target.op_type == "alloc"
        assert target.address == 0x1000
        assert target.size == 0x200


class TestLegacyHeapStateMachine:
    """Legacy HeapStateMachine tests (removed APIs)"""

    def test_analyze_basic(self):
        pytest.skip(
            "analyze removed -- replaced by HeapStateMachine.simulate + build_transitions"
        )

    def test_apply_malloc(self):
        pytest.skip("_apply_malloc removed -- replaced by HeapStateMachine.simulate")

    def test_apply_free(self):
        pytest.skip("_apply_free removed -- replaced by HeapStateMachine.simulate")

    def test_clone_state(self):
        pytest.skip(
            "_clone_state removed -- manual copy used in simulate loop"
        )

    def test_get_chunk_state(self):
        pytest.skip(
            "ChunkState removed -- allocations/frees list track state directly"
        )

    def test_metadata(self):
        pytest.skip("get_metadata removed")

    def test_state_initialization_legacy(self):
        pytest.skip(
            "HeapState fields arena_base/top_chunk/chunks removed -- now allocations/frees"
        )


class TestLegacyHeapState:
    """Legacy HeapState -- arena_base/top_chunk/chunks removed"""

    def test_state_initialization(self):
        pytest.skip(
            "HeapState fields arena_base/top_chunk/chunks removed -- now allocations/frees"
        )

    def test_state_id_generation(self):
        pytest.skip("_generate_state_id removed")


