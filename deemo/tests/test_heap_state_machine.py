# Heap operation simulation -> state machine transitions -> feng shui strategy
# 真实 API 断言：simulate/build_transitions/count_non_deterministic/analyzer
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
    """Heap transition -- from -> to, with deterministic flag"""

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

    def test_result_non_deterministic_default(self):
        result = StateMachineResult(success=False, initial_state=HeapState(), transitions=[])
        assert result.non_deterministic_branches == 0


class TestHeapOperation:
    def test_alloc_operation(self):
        op = HeapOperation("alloc", size=0x80, address=0x1000)
        assert op.op_type == "alloc"
        assert op.size == 0x80
        assert op.address == 0x1000

    def test_free_operation(self):
        op = HeapOperation("free", address=0x1000)
        assert op.op_type == "free"
        assert op.address == 0x1000
        assert op.size == 0


class TestHeapStateMachine:
    """核心状态机：simulate 推进 + build_transitions + 非确定性"""

    def test_machine_init(self):
        machine = HeapStateMachine()
        assert machine.states == []
        assert machine.transitions == []

    def test_simulate_basic(self):
        machine = HeapStateMachine()
        ops = [HeapOperation("alloc", size=0x80, address=0x1000)]
        states = machine.simulate(ops)
        assert len(states) == 2
        assert states[1].allocations[0x1000] == 0x80

    def test_simulate_alloc_then_free(self):
        # 修复后：simulate 正确推进 state，free 能命中前序 alloc
        machine = HeapStateMachine()
        ops = [
            HeapOperation("alloc", size=0x80, address=0x1000),
            HeapOperation("free", address=0x1000),
        ]
        states = machine.simulate(ops)
        assert len(states) == 3
        # alloc 后登记
        assert states[1].allocations[0x1000] == 0x80
        # free 后移除并记录
        assert states[2].allocations == {}
        assert states[2].frees == [0x1000]

    def test_simulate_free_unknown_address(self):
        # free 未分配地址：allocations 不变，frees 不追加
        machine = HeapStateMachine()
        states = machine.simulate([HeapOperation("free", address=0x9999)])
        assert len(states) == 2
        assert states[1].allocations == {}
        assert states[1].frees == []

    def test_build_transitions(self):
        machine = HeapStateMachine()
        ops = [HeapOperation("alloc", size=0x80, address=0x1000)]
        machine.simulate(ops)
        transitions = machine.build_transitions()
        assert len(transitions) == 1
        assert transitions[0].from_state_id == 0
        assert transitions[0].to_state_id == 1
        assert transitions[0].operation == "alloc"
        assert transitions[0].target_address == 0x1000

    def test_build_transitions_count_is_states_minus_one(self):
        machine = HeapStateMachine()
        ops = [
            HeapOperation("alloc", size=0x80, address=0x1000),
            HeapOperation("alloc", size=0x40, address=0x2000),
            HeapOperation("free", address=0x1000),
        ]
        machine.simulate(ops)
        transitions = machine.build_transitions()
        assert len(transitions) == len(machine.states) - 1
        assert all(t.deterministic for t in transitions)

    def test_build_transitions_no_duplicate(self):
        # 修复后：build_transitions 每次调用清空重建，不累积
        machine = HeapStateMachine()
        ops = [HeapOperation("alloc", size=0x80, address=0x1000)]
        machine.simulate(ops)
        t1 = machine.build_transitions()
        t2 = machine.build_transitions()
        assert len(t1) == len(t2) == 1

    def test_count_non_deterministic_initial(self):
        machine = HeapStateMachine()
        assert machine.count_non_deterministic() == 0


class TestHeapFengShui:
    def test_sequence(self):
        ops = HeapFengShui.sequence(0x1000, 0x200)
        assert len(ops) == 6
        target = ops[0]
        assert target.op_type == "alloc"
        assert target.address == 0x1000
        assert target.size == 0x200
        # 后续 5 个填充块，地址递减 0x100
        for i, op in enumerate(ops[1:], start=1):
            assert op.op_type == "alloc"
            assert op.size == 0x100
            assert op.address == 0x1000 - 0x100 * i


class TestHeapStateMachineAnalyzer:
    """Analyzer 不依赖真实二进制，run() 返回 success=True"""

    def test_run_returns_success_result(self):
        analyzer = HeapStateMachineAnalyzer("/nonexistent/binary")
        result = analyzer.run()
        assert isinstance(result, StateMachineResult)
        assert result.success is True
        assert result.transitions
        # feng_shui.sequence(0x1000, 0x200) -> 6 个 op -> 7 个状态 -> 6 条转移
        assert len(result.transitions) == 6

    def test_create_analyzer(self):
        analyzer = create_heap_state_machine_analyzer("/nonexistent/binary")
        assert isinstance(analyzer, HeapStateMachineAnalyzer)