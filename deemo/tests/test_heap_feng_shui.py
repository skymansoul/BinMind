#!/usr/bin/env python3
"""
堆风水策略生成模块单元测试

使用pytest框架测试堆风水策略生成器的各项功能。
"""

import os
import sys
import pytest

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.heap_feng_shui import (
    HeapFengShuiStrategist,
    FengShuiConfig,
    VulnerabilityType,
    AllocatorType,
    FengShuiAction,
    FengShuiStrategy,
    FengShuiStep,
    generate_fengshui_strategy
)


class TestFengShuiConfig:
    """测试堆风水配置类"""
    
    def test_config_init_default(self):
        """测试默认配置初始化"""
        config = FengShuiConfig()
        assert config.allocator == AllocatorType.PTMALLOC
        assert config.libc_version == "2.31"
        assert config.enable_tcache is True
        assert config.tcache_count == 7
    
    def test_config_custom_values(self):
        """测试自定义配置值"""
        config = FengShuiConfig(
            allocator=AllocatorType.JEMALLOC,
            libc_version="2.35",
            target_size=0x100,
            enable_tcache=False,
            tcache_count=5,
            arena_count=2
        )
        assert config.allocator == AllocatorType.JEMALLOC
        assert config.libc_version == "2.35"
        assert config.target_size == 0x100
        assert config.enable_tcache is False
        assert config.tcache_count == 5
        assert config.arena_count == 2


class TestFengShuiAction:
    """测试堆风水操作类型枚举"""
    
    def test_action_values(self):
        """测试操作类型值"""
        assert FengShuiAction.ALLOC.value == "alloc"
        assert FengShuiAction.FREE.value == "free"
        assert FengShuiAction.WRITE.value == "write"
        assert FengShuiAction.FILL_TCACHE.value == "fill_tcache"
        assert FengShuiAction.CONSOLIDATE.value == "consolidate"
    
    def test_action_enum_members(self):
        """测试枚举成员"""
        actions = list(FengShuiAction)
        assert len(actions) > 0
        assert FengShuiAction.ALLOC in actions


class TestFengShuiStep:
    """测试堆风水步骤数据类"""
    
    def test_step_init(self):
        """测试步骤初始化"""
        step = FengShuiStep(
            action=FengShuiAction.ALLOC,
            size=0x80,
            chunk_id=1,
            comment="分配目标chunk"
        )
        assert step.action == FengShuiAction.ALLOC
        assert step.size == 0x80
        assert step.chunk_id == 1
        assert step.comment == "分配目标chunk"
    
    def test_step_default_values(self):
        """测试步骤默认值"""
        step = FengShuiStep(action=FengShuiAction.FREE)
        assert step.size is None
        assert step.chunk_id is None
        assert step.comment == ""


class TestFengShuiStrategy:
    """测试堆风水策略数据类"""
    
    def test_strategy_init(self):
        """测试策略初始化"""
        steps = [
            FengShuiStep(action=FengShuiAction.ALLOC, size=0x80),
            FengShuiStep(action=FengShuiAction.FREE, chunk_id=1)
        ]
        strategy = FengShuiStrategy(
            steps=steps,
            target_layout="test layout",
            success_probability=0.8,
            notes=["test note"]
        )
        assert len(strategy.steps) == 2
        assert strategy.target_layout == "test layout"
        assert strategy.success_probability == 0.8
        assert strategy.notes == ["test note"]
    
    def test_strategy_empty(self):
        """测试空策略"""
        strategy = FengShuiStrategy()
        assert strategy.steps == []
        assert strategy.success_probability == 0.0
        assert strategy.notes == []


class TestHeapFengShuiStrategist:
    """测试堆风水策略生成器类"""
    
    @pytest.fixture
    def strategist(self):
        """创建策略生成器实例"""
        config = FengShuiConfig()
        return HeapFengShuiStrategist(config)
    
    def test_strategist_init(self, strategist):
        """测试策略生成器初始化"""
        assert isinstance(strategist, HeapFengShuiStrategist)
        assert strategist.config is not None
        assert strategist.config.allocator == AllocatorType.PTMALLOC
    
    def test_generate_uaf_strategy(self, strategist):
        """测试生成UAF漏洞策略"""
        strategy = strategist.generate_strategy(VulnerabilityType.USE_AFTER_FREE, 0x80)
        
        assert isinstance(strategy, FengShuiStrategy)
        assert len(strategy.steps) > 0
        assert strategy.success_probability > 0
        assert any(VulnerabilityType.USE_AFTER_FREE.value in note for note in strategy.notes if "漏洞类型" in note)
    
    def test_generate_overflow_strategy(self, strategist):
        """测试生成堆溢出漏洞策略"""
        strategy = strategist.generate_strategy(VulnerabilityType.HEAP_OVERFLOW, 0x80)
        
        assert isinstance(strategy, FengShuiStrategy)
        assert len(strategy.steps) > 0
        assert any(VulnerabilityType.HEAP_OVERFLOW.value in note for note in strategy.notes if "漏洞类型" in note)
    
    def test_generate_double_free_strategy(self, strategist):
        """测试生成double free漏洞策略"""
        strategy = strategist.generate_strategy(VulnerabilityType.DOUBLE_FREE, 0x80)
        
        assert isinstance(strategy, FengShuiStrategy)
        assert len(strategy.steps) > 0
        assert any(VulnerabilityType.DOUBLE_FREE.value in note for note in strategy.notes if "漏洞类型" in note)
    
    def test_generate_null_pointer_strategy(self, strategist):
        """测试生成空指针解引用漏洞策略"""
        strategy = strategist.generate_strategy(VulnerabilityType.NULL_POINTER_DEREF, 0x80)
        
        assert isinstance(strategy, FengShuiStrategy)
        assert len(strategy.steps) >= 1
    
    def test_generate_c_code(self, strategist):
        """测试生成C代码"""
        strategy = strategist.generate_strategy(VulnerabilityType.USE_AFTER_FREE, 0x80)
        code = strategist.generate_c_code(strategy)
        
        assert isinstance(code, str)
        assert "malloc" in code
        assert "free" in code
        assert "fengshui" in code
    
    def test_generate_python_code(self, strategist):
        """测试生成Python代码"""
        strategy = strategist.generate_strategy(VulnerabilityType.USE_AFTER_FREE, 0x80)
        code = strategist.generate_python_code(strategy)
        
        assert isinstance(code, str)
        assert "malloc" in code
        assert "free" in code
        assert "def fengshui" in code
    
    def test_simulate_heap_layout(self, strategist):
        """测试模拟堆布局"""
        strategy = strategist.generate_strategy(VulnerabilityType.USE_AFTER_FREE, 0x80)
        layout = strategist.simulate_heap_layout(strategy)
        
        assert isinstance(layout, str)
        assert "ALLOC" in layout
    
    def test_success_probability_calculation(self, strategist):
        """测试成功概率计算"""
        # 测试不同配置下的概率
        strategy1 = strategist.generate_strategy(VulnerabilityType.USE_AFTER_FREE, 0x80)
        
        # 修改配置测试不同概率
        strategist.config.allocator = AllocatorType.JEMALLOC
        strategy2 = strategist.generate_strategy(VulnerabilityType.USE_AFTER_FREE, 0x80)
        
        assert 0 <= strategy1.success_probability <= 1
        assert 0 <= strategy2.success_probability <= 1
        # JEMALLOC通常比PTMALLOC成功率低
        assert strategy2.success_probability <= strategy1.success_probability
    
    def test_different_allocator_strategies(self):
        """测试不同分配器策略"""
        configs = [
            FengShuiConfig(allocator=AllocatorType.PTMALLOC),
            FengShuiConfig(allocator=AllocatorType.JEMALLOC),
            FengShuiConfig(allocator=AllocatorType.TCMALLOC),
        ]
        
        for config in configs:
            strategist = HeapFengShuiStrategist(config)
            strategy = strategist.generate_strategy(VulnerabilityType.USE_AFTER_FREE, 0x80)
            
            assert isinstance(strategy, FengShuiStrategy)
            assert len(strategy.steps) > 0
            assert any(config.allocator.value in note for note in strategy.notes if "分配器" in note)
    
    def test_different_vulnerability_types(self, strategist):
        """测试不同漏洞类型"""
        vuln_types = [
            VulnerabilityType.USE_AFTER_FREE,
            VulnerabilityType.HEAP_OVERFLOW,
            VulnerabilityType.DOUBLE_FREE,
            VulnerabilityType.NULL_POINTER_DEREF,
            VulnerabilityType.USE_AFTER_REALLOC,
        ]
        
        for vuln_type in vuln_types:
            strategy = strategist.generate_strategy(vuln_type, 0x80)
            assert isinstance(strategy, FengShuiStrategy)
            assert len(strategy.steps) >= 1


class TestFengShuiConvenienceFunctions:
    """测试堆风水便捷函数"""
    
    def test_generate_fengshui_strategy_default(self):
        """测试便捷函数默认参数"""
        strategy = generate_fengshui_strategy("use_after_free")
        
        assert isinstance(strategy, FengShuiStrategy)
        assert len(strategy.steps) > 0
    
    def test_generate_fengshui_strategy_with_params(self):
        """测试便捷函数带参数"""
        strategy = generate_fengshui_strategy(
            vuln_type="heap_overflow",
            allocator="jemalloc",
            libc_version="2.35",
            target_size=0x100
        )
        
        assert isinstance(strategy, FengShuiStrategy)
        assert len(strategy.steps) > 0
        assert any("heap_overflow" in note for note in strategy.notes if "漏洞类型" in note)
        assert any("jemalloc" in note for note in strategy.notes if "分配器" in note)
    
    def test_generate_fengshui_strategy_invalid_input(self):
        """测试便捷函数无效输入"""
        with pytest.raises(ValueError):
            generate_fengshui_strategy("invalid_vuln_type")


class TestFengShuiStepActions:
    """测试各种堆风水操作步骤"""
    
    @pytest.fixture
    def strategist(self):
        """创建策略生成器实例"""
        return HeapFengShuiStrategist()
    
    def test_allocate_step(self, strategist):
        """测试分配步骤"""
        strategy = strategist.generate_strategy(VulnerabilityType.USE_AFTER_FREE, 0x80)
        alloc_steps = [step for step in strategy.steps if step.action == FengShuiAction.ALLOC]
        
        assert len(alloc_steps) > 0
        for step in alloc_steps:
            assert step.size is not None
    
    def test_free_step(self, strategist):
        """测试释放步骤"""
        strategy = strategist.generate_strategy(VulnerabilityType.USE_AFTER_FREE, 0x80)
        free_steps = [step for step in strategy.steps if step.action == FengShuiAction.FREE]
        
        assert len(free_steps) > 0
    
    def test_fill_tcache_step(self, strategist):
        """测试填充tcache步骤"""
        strategist.config.enable_tcache = True
        strategy = strategist.generate_strategy(VulnerabilityType.USE_AFTER_FREE, 0x80)
        fill_steps = [step for step in strategy.steps if step.action == FengShuiAction.FILL_TCACHE]
        
        assert len(fill_steps) >= 1
    
    def test_write_step(self, strategist):
        """测试写操作步骤"""
        strategy = strategist.generate_strategy(VulnerabilityType.HEAP_OVERFLOW, 0x80)
        write_steps = [step for step in strategy.steps if step.action == FengShuiAction.WRITE]
        
        assert len(write_steps) >= 1
        for step in write_steps:
            assert step.content == "overflow_payload"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])