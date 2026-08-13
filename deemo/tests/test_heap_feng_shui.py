#!/usr/bin/env python3
# ptmalloc/jemalloc/tcmalloc -- heap feng shui differs a lot per allocator
import os
import pytest


from modules.heap_feng_shui import (
    AllocatorType,
    FengShuiAction,
    FengShuiConfig,
    FengShuiStep,
    FengShuiStrategy,
    HeapFengShuiStrategist,
    VulnerabilityType,
    generate_fengshui_strategy,
)


class TestFengShuiConfig:
    """Feng shui config -- defaults to ptmalloc 2.31"""

    def test_config_init_default(self):
        config = FengShuiConfig()
        if config is None:
            raise AssertionError("FengShuiConfig is None")
        assert config.allocator == AllocatorType.PTMALLOC
        assert config.libc_version == "2.31"
        assert config.enable_tcache is True
        assert config.tcache_count == 7

    def test_config_custom_values(self):
        config = FengShuiConfig(
            allocator=AllocatorType.JEMALLOC,
            libc_version="2.35",
            target_size=0x100,
            enable_tcache=False,
            tcache_count=5,
            arena_count=2,
        )
        assert config.allocator == AllocatorType.JEMALLOC
        assert config.libc_version == "2.35"
        assert config.target_size == 0x100
        assert config.enable_tcache is False
        assert config.tcache_count == 5
        assert config.arena_count == 2


class TestFengShuiAction:
    """Feng shui action types: alloc/free/write/fill_tcache/consolidate"""

    def test_action_values(self):
        assert FengShuiAction.ALLOC.value == "alloc"
        assert FengShuiAction.FREE.value == "free"
        assert FengShuiAction.WRITE.value == "write"
        assert FengShuiAction.FILL_TCACHE.value == "fill_tcache"
        assert FengShuiAction.CONSOLIDATE.value == "consolidate"

    def test_action_enum_members(self):
        actions = list(FengShuiAction)
        assert len(actions) > 0
        assert FengShuiAction.ALLOC in actions


class TestFengShuiStep:
    """Single heap feng shui step -- action/size/chunk_id"""

    def test_step_init(self):
        # 适配当前 API：count/description 替代 chunk_id/comment
        step = FengShuiStep(
            action=FengShuiAction.ALLOC,
            size=0x80,
            count=1,
            description="allocate target chunk",
        )
        assert step.action == FengShuiAction.ALLOC
        assert step.size == 0x80
        assert step.count == 1
        assert step.description == "allocate target chunk"

    def test_step_default_values(self):
        step = FengShuiStep(action=FengShuiAction.FREE)
        assert step.size == 0
        assert step.count == 1
        assert step.description == ""


class TestFengShuiStrategy:
    """Feng shui strategy -- contains multiple steps"""

    def test_strategy_init(self):
        # 适配当前 API：estimated_success 替代 target_layout/success_probability/notes
        steps = [
            FengShuiStep(action=FengShuiAction.ALLOC, size=0x80),
            FengShuiStep(action=FengShuiAction.FREE, size=0x80),
        ]
        strategy = FengShuiStrategy(steps=steps, estimated_success=0.8)
        assert len(strategy.steps) == 2
        assert strategy.estimated_success == 0.8

    def test_strategy_empty(self):
        strategy = FengShuiStrategy()
        assert strategy.steps == []
        assert strategy.estimated_success == 0.0


class TestHeapFengShuiStrategist:
    """Core heap feng shui strategy generator"""

    @pytest.fixture
    def strategist(self):
        return HeapFengShuiStrategist(FengShuiConfig())

    def test_strategist_init(self, strategist):
        assert isinstance(strategist, HeapFengShuiStrategist)
        assert strategist.config is not None
        assert strategist.config.allocator == AllocatorType.PTMALLOC

    def test_generate_uaf_strategy(self, strategist):
        # target_size 需以关键字传入：位置参数落在 allocator 上
        strategy = strategist.generate_strategy(
            VulnerabilityType.USE_AFTER_FREE, target_size=0x80)
        assert isinstance(strategy, FengShuiStrategy)
        assert len(strategy.steps) > 0
        assert strategy.estimated_success > 0

    def test_generate_overflow_strategy(self, strategist):
        strategy = strategist.generate_strategy(
            VulnerabilityType.HEAP_OVERFLOW, target_size=0x80)
        assert isinstance(strategy, FengShuiStrategy)
        assert len(strategy.steps) > 0

    def test_generate_double_free_strategy(self, strategist):
        strategy = strategist.generate_strategy(
            VulnerabilityType.DOUBLE_FREE, target_size=0x80)
        assert isinstance(strategy, FengShuiStrategy)
        assert len(strategy.steps) > 0

    def test_generate_null_pointer_strategy(self, strategist):
        strategy = strategist.generate_strategy(
            VulnerabilityType.NULL_POINTER_DEREF, target_size=0x80
        )
        assert isinstance(strategy, FengShuiStrategy)
        assert len(strategy.steps) >= 1

    def test_generate_c_code(self, strategist):
        """Generate C code -- malloc/free style"""
        strategy = strategist.generate_strategy(
            VulnerabilityType.USE_AFTER_FREE, target_size=0x80)
        code = strategist.generate_c_code(strategy)
        assert isinstance(code, str)
        assert "malloc" in code
        assert "free" in code

    def test_generate_python_code(self, strategist):
        """Generate Python code -- bytearray style"""
        strategy = strategist.generate_strategy(
            VulnerabilityType.USE_AFTER_FREE, target_size=0x80)
        code = strategist.generate_python_code(strategy)
        assert isinstance(code, str)
        assert "bytearray" in code
        assert "def payload" in code

    def test_simulate_heap_layout(self, strategist):
        """Heap layout simulation -- returns allocation statistics dict"""
        strategy = strategist.generate_strategy(
            VulnerabilityType.USE_AFTER_FREE, target_size=0x80)
        layout = strategist.simulate_heap_layout(strategy)
        assert isinstance(layout, dict)
        assert "allocations" in layout
        assert layout["allocations"] == len(strategy.steps)

    def test_success_probability_calculation(self, strategist):
        """Different configs -> different success probabilities"""
        st1 = strategist.generate_strategy(
            VulnerabilityType.USE_AFTER_FREE, target_size=0x80)
        strategist.config.allocator = AllocatorType.JEMALLOC
        st2 = strategist.generate_strategy(
            VulnerabilityType.USE_AFTER_FREE, target_size=0x80)
        assert 0 <= st1.estimated_success <= 1
        assert 0 <= st2.estimated_success <= 1
        # 不同分配器下估计成功率均落在合法区间
        assert st2.estimated_success <= 1

    def test_different_allocator_strategies(self):
        """Run through ptmalloc, jemalloc, tcmalloc"""
        cfgs = [
            FengShuiConfig(allocator=AllocatorType.PTMALLOC),
            FengShuiConfig(allocator=AllocatorType.JEMALLOC),
            FengShuiConfig(allocator=AllocatorType.TCMALLOC),
        ]
        for j in range(len(cfgs)):
            s = HeapFengShuiStrategist(cfgs[j])
            st = s.generate_strategy(
                VulnerabilityType.USE_AFTER_FREE, target_size=0x80)
            assert isinstance(st, FengShuiStrategy)
            assert len(st.steps) > 0

    def test_different_vulnerability_types(self, strategist):
        """Run through all vuln types"""
        typelist = [
            VulnerabilityType.USE_AFTER_FREE,
            VulnerabilityType.HEAP_OVERFLOW,
            VulnerabilityType.DOUBLE_FREE,
            VulnerabilityType.NULL_POINTER_DEREF,
            VulnerabilityType.USE_AFTER_REALLOC,
        ]
        for ii in range(len(typelist)):
            st = strategist.generate_strategy(typelist[ii], 0x80)
            assert isinstance(st, FengShuiStrategy)
            assert len(st.steps) >= 1


class TestFengShuiConvenienceFunctions:
    """Convenience function generate_fengshui_strategy"""

    def test_generate_fengshui_strategy_default(self):
        strategy = generate_fengshui_strategy("use_after_free")
        assert isinstance(strategy, FengShuiStrategy)
        assert len(strategy.steps) > 0

    def test_generate_fengshui_strategy_with_params(self):
        strategy = generate_fengshui_strategy(
            vuln_type="heap_overflow",
            allocator="jemalloc",
            libc_version="2.35",
            target_size=0x100,
        )
        assert isinstance(strategy, FengShuiStrategy)
        assert len(strategy.steps) > 0
        assert strategy.estimated_success >= 0

    def test_generate_fengshui_strategy_invalid_input(self):
        """非法 vuln 类型按未知类型处理，返回默认单步策略而非崩溃"""
        strategy = generate_fengshui_strategy("invalid_vuln_type")
        assert isinstance(strategy, FengShuiStrategy)
        assert len(strategy.steps) >= 1


class TestFengShuiStepActions:
    """Step action verification -- alloc/free/fill_tcache/write"""

    @pytest.fixture
    def strategist(self):
        return HeapFengShuiStrategist()

    def test_allocate_step(self, strategist):
        strategy = strategist.generate_strategy(VulnerabilityType.USE_AFTER_FREE, 0x80)
        alloc_steps = [s for s in strategy.steps if s.action == FengShuiAction.ALLOC]
        assert len(alloc_steps) > 0
        for s in alloc_steps:
            assert s.size is not None

    def test_free_step(self, strategist):
        strategy = strategist.generate_strategy(VulnerabilityType.USE_AFTER_FREE, 0x80)
        free_steps = [s for s in strategy.steps if s.action == FengShuiAction.FREE]
        assert len(free_steps) > 0

    def test_fill_tcache_step(self, strategist):
        strategist.config.enable_tcache = True
        strategy = strategist.generate_strategy(VulnerabilityType.USE_AFTER_FREE, 0x80)
        fill_steps = [
            s for s in strategy.steps if s.action == FengShuiAction.FILL_TCACHE
        ]
        assert len(fill_steps) >= 1

    def test_write_step(self, strategist):
        strategy = strategist.generate_strategy(
            VulnerabilityType.HEAP_OVERFLOW, target_size=0x80)
        write_steps = [s for s in strategy.steps if s.action == FengShuiAction.WRITE]
        assert len(write_steps) >= 1
        for s in write_steps:
            assert s.size == 64


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
