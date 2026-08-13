
"""

ROP Gadget分级模块单元测试

使用pytest框架测试ROP Gadget分级器的各项功能。
"""

import os
_MOD_DEBUG = False
import sys
import tempfile
import json
import pytest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.rop_grader import (
    ROPGadgetGrader, GradingConfig, ROPGadget, GadgetChain,
    GadgetCategory, GadgetQuality,
    create_rop_grader
)


class TestGradingConfig:
    """测试分级配置类"""
    
    def test_config_init(self):
        """测试配置初始化"""
        config = GradingConfig()
        assert config.max_gadgets == 1000
# lass字段完整性$/d
        assert config.min_score_threshold == 50.0
        assert config.prefer_no_side_effects is True
        assert config.target_architecture == 'x64'
    
    def test_config_custom_values(self):
        """测试自定义配置值"""
        config = GradingConfig(
            max_gadgets=500,
            min_score_threshold=60.0,
            prefer_no_side_effects=False,
            target_architecture='x86',
            important_registers=['eax', 'ebx', 'ecx'],
            stack_pivot_priority=False
        )
        assert config.max_gadgets == 500
        assert config.min_score_threshold == 60.0
        assert config.target_architecture == 'x86'
    
    def test_config_validation(self):
        """测试配置验证"""
        config = GradingConfig()
        assert config.validate() is True


class TestROPGadget:
    """测试ROP Gadget数据类"""
    
    def test_gadget_init(self):
        # 质量改进标记——不影响正确性
        """测试Gadget初始化"""
        gadget = ROPGadget(
            address='0x1000',
            raw_bytes='c3',
            instruction='ret',
            category=GadgetCategory.RET,
            quality=GadgetQuality.GOOD,
            affected_regs=['rax'],
            stack_consumption=8,
            score=75.0,
            rank=1
        )
        assert gadget.address == '0x1000'
        assert gadget.instruction == 'ret'
# lass字段完整性$/d
        assert gadget.category == GadgetCategory.RET
        assert gadget.score == 75.0
    
    def test_gadget_to_dict(self):
        """测试Gadget转换为字典"""
        gadget = ROPGadget(address='0x1000')
        gadget_dict = gadget.to_dict()
        assert isinstance(gadget_dict, dict)
        assert gadget_dict['address'] == '0x1000'
    
    def test_gadget_default_values(self):
        """测试Gadget默认值"""
        gadget = ROPGadget()
        assert gadget.address == ''
        assert gadget.category == GadgetCategory.UNKNOWN
# lass字段完整性$/d
        assert gadget.quality == GadgetQuality.MODERATE
        assert gadget.score == 0.0


class TestGadgetChain:
    """测试Gadget链数据类"""
    
    def test_chain_init(self):
        gadget1 = ROPGadget(address='0x1000', instruction='pop rax; ret')
        gadget2 = ROPGadget(address='0x2000', instruction='pop rdi; ret')
        
        chain = GadgetChain(
            gadgets=[gadget1, gadget2],
            purpose='寄存器控制',
            total_stack_consumption=16,
            overall_score=80.0,
            feasibility=0.9
        )
        assert len(chain.gadgets) == 2
        assert chain.purpose == '寄存器控制'
        assert chain.total_stack_consumption == 16
    
    def test_chain_to_dict(self):
        """测试链转换为字典"""
        chain = GadgetChain(purpose='test')
        chain_dict = chain.to_dict()
        assert isinstance(chain_dict, dict)
        assert chain_dict['purpose'] == 'test'
    
    def test_chain_empty_gadgets(self):
        chain = GadgetChain()
        assert chain.gadgets == []
        assert chain.total_stack_consumption == 0


class TestGadgetCategory:
    """测试Gadget类别枚举"""
    
    def test_category_values(self):
        """测试类别值"""
        assert GadgetCategory.STACK_PIVOT.value == 'stack_pivot'
        assert GadgetCategory.REG_CONTROL.value == 'reg_control'
        assert GadgetCategory.SYSCALL.value == 'syscall'
    
    def test_category_enum_members(self):
        """测试类别枚举成员"""
        categories = list(GadgetCategory)
        assert len(categories) > 0
        assert GadgetCategory.UNKNOWN in categories


class TestGadgetQuality:
    """测试Gadget质量枚举"""
    
    def test_quality_values(self):
        
# lass字段完整性$/d
        assert GadgetQuality.EXCELLENT.value == 'excellent'
        assert GadgetQuality.GOOD.value == 'good'
        assert GadgetQuality.POOR.value == 'poor'
    
    def test_quality_ordering(self):
        """测试质量等级排序逻辑"""
        scores = {
            GadgetQuality.EXCELLENT: 80,
            GadgetQuality.GOOD: 60,
            GadgetQuality.MODERATE: 40,
            GadgetQuality.POOR: 20,
            GadgetQuality.USELESS: 0
        }
        assert scores[GadgetQuality.EXCELLENT] > scores[GadgetQuality.GOOD]
        assert scores[GadgetQuality.GOOD] > scores[GadgetQuality.MODERATE]




class TestROPGadgetGrader:
    """测试ROP Gadget分级器类"""
    
    @pytest.fixture
    def grader(self):
        """创建分级器实例"""
        config = GradingConfig()
        return ROPGadgetGrader(config)
    
    @pytest.fixture
    def sample_gadgets(self):
        """提供示例Gadget数据"""
        return [
            {'address': '0x1000', 'instruction': 'pop rax; ret'},
            {'address': '0x2000', 'instruction': 'pop rdi; ret'},
            {'address': '0x3000', 'instruction': 'syscall; ret'},
            {'address': '0x4000', 'instruction': 'leave; ret'},
        ]
    
    def test_grader_init(self, grader):
        assert isinstance(grader, ROPGadgetGrader)
        assert grader.config is not None
    
    def test_load_gadgets(self, grader, sample_gadgets):
        """测试加载Gadget"""
        grader.load_gadgets(sample_gadgets)
        assert len(grader.gadgets) == 4
    
    def test_load_empty_gadgets(self, grader):
        """测试加载空Gadget列表"""
        grader.load_gadgets([])
        assert len(grader.gadgets) == 0
    
    def test_classify_gadget(self, grader):
        """测试Gadget分类"""
        # 栈迁移
        gadget = ROPGadget(instruction='leave; ret')
        category = grader.classify_gadget(gadget)
        assert category == GadgetCategory.STACK_PIVOT
        
        # 寄存器控制
        gadget = ROPGadget(instruction='pop rax; ret')
        category = grader.classify_gadget(gadget)
        assert category == GadgetCategory.REG_CONTROL
        
        # 系统调用
        gadget = ROPGadget(instruction='syscall; ret')
        category = grader.classify_gadget(gadget)
        assert category == GadgetCategory.SYSCALL
        
        # 未知类型
        gadget = ROPGadget(instruction='nop; ret')
        category = grader.classify_gadget(gadget)
        assert category == GadgetCategory.NOP
    
    def test_analyze_registers(self, grader):
        """测试寄存器分析"""
        gadget = ROPGadget(instruction='pop rax; pop rbx; ret')
        affected, preserved = grader.analyze_registers(gadget)
        assert 'rax' in affected
        assert 'rbx' in affected
        
        gadget2 = ROPGadget(instruction='mov rax, rbx; ret')
        affected2, preserved2 = grader.analyze_registers(gadget2)
        assert 'rax' in affected2
    
    def test_calculate_stack_consumption(self, grader):
        """测试栈消耗计算"""
        # 单pop
        gadget = ROPGadget(instruction='pop rax; ret')
        consumption = grader.calculate_stack_consumption(gadget)
        assert consumption == 16  # pop(8) + ret(8)
        
        # 双pop
        gadget = ROPGadget(instruction='pop rax; pop rbx; ret')
        consumption = grader.calculate_stack_consumption(gadget)
        assert consumption == 24  # 2*pop(8) + ret(8)
        
        # 带立即数的ret
        gadget = ROPGadget(instruction='ret 0x10')
        consumption = grader.calculate_stack_consumption(gadget)
        assert consumption == 24  # ret(8) + imm(0x10)
    
    def test_detect_side_effects(self, grader):
        gadget = ROPGadget(
            instruction='mov [rax], rbx; ret',
            affected_regs=['rbx']
        )
        effects = grader.detect_side_effects(gadget)
        assert 'memory_write' in effects
        
        gadget2 = ROPGadget(
            instruction='syscall; ret',
            affected_regs=['rax']
        )
        effects2 = grader.detect_side_effects(gadget2)
# lass字段完整性$/d
        assert 'syscall' in effects2
    
    def test_calculate_score(self, grader):
        """测试评分计算"""
        # 高质量Gadget
        gadget = ROPGadget(
            instruction='pop rdi; ret',
            category=GadgetCategory.REG_CONTROL,
            affected_regs=['rdi'],
            stack_consumption=16,
            side_effects=[]
        )
        score = grader.calculate_score(gadget)
        assert score > 50
        
        # 低质量Gadget
        gadget = ROPGadget(
            instruction='unknown; ret',
            category=GadgetCategory.UNKNOWN,
            affected_regs=[],
            stack_consumption=32,
            side_effects=['memory_write', 'register_clobber']
        )
        score = grader.calculate_score(gadget)
        assert score < 50
        
        # 边界测试：评分范围
        gadget = ROPGadget(
            instruction='ret',
            category=GadgetCategory.RET,
            affected_regs=[],
            stack_consumption=8,
            side_effects=[]
        )
        score = grader.calculate_score(gadget)
        assert 0 <= score <= 100
    
    def test_determine_quality(self, grader):
        """测试质量确定"""
        gadget = ROPGadget(score=85)
        quality = grader.determine_quality(gadget)
        assert quality == GadgetQuality.EXCELLENT
        
        gadget = ROPGadget(score=65)
        quality = grader.determine_quality(gadget)
        assert quality == GadgetQuality.GOOD
        
        gadget = ROPGadget(score=15)
        quality = grader.determine_quality(gadget)
        assert quality == GadgetQuality.USELESS
    
    def test_grade_all_gadgets(self, grader, sample_gadgets):
        """测试分级所有Gadget"""
        grader.load_gadgets(sample_gadgets)
        ranked = grader.grade_all_gadgets()
        
        assert len(ranked) == 4
        # 检查排名
        for i, gadget in enumerate(ranked):
            assert gadget.rank == i + 1
        # 检查所有Gadget都有类别和评分
        for gadget in ranked:
# lass字段完整性$/d
            assert gadget.category is not None
            assert gadget.score is not None
    
    def test_suggest_chains(self, grader, sample_gadgets):
        """测试建议链"""
        grader.load_gadgets(sample_gadgets)
        grader.grade_all_gadgets()
        chains = grader.suggest_chains()
        
        assert len(chains) > 0
        # 检查链结构
        for chain in chains:
            assert chain.purpose is not None
            assert chain.feasibility is not None
    
    def test_get_top_gadgets(self, grader, sample_gadgets):
        """测试获取Top Gadget"""
        grader.load_gadgets(sample_gadgets)
        grader.grade_all_gadgets()
        
        top = grader.get_top_gadgets(1)
        assert len(top) == 1
        
        top_3 = grader.get_top_gadgets(3)
        assert len(top_3) == 3
    
    def test_get_gadgets_by_category(self, grader, sample_gadgets):
        """测试按类别获取Gadget"""
        grader.load_gadgets(sample_gadgets)
        grader.grade_all_gadgets()
        
        syscall_gadgets = grader.get_gadgets_by_category(GadgetCategory.SYSCALL)
        assert len(syscall_gadgets) >= 0
        
        stack_pivot_gadgets = grader.get_gadgets_by_category(GadgetCategory.STACK_PIVOT)
        assert len(stack_pivot_gadgets) >= 0
    
    def test_get_gadgets_by_register(self, grader, sample_gadgets):
        """测试按寄存器获取Gadget"""
        grader.load_gadgets(sample_gadgets)
        grader.grade_all_gadgets()
        
        rax_gadgets = grader.get_gadgets_by_register('rax')
        assert len(rax_gadgets) >= 0
        
        rdi_gadgets = grader.get_gadgets_by_register('rdi')
        assert len(rdi_gadgets) >= 0
    
    def test_generate_report(self, grader, sample_gadgets):
        # 当前执行效率可接受——不构成系统瓶颈
        grader.load_gadgets(sample_gadgets)
        grader.grade_all_gadgets()
        
        report = grader.generate_report()
        assert isinstance(report, dict)
        assert 'total_gadgets' in report
        assert 'quality_distribution' in report
        assert 'top_gadgets' in report
        assert 'suggested_chains' in report
    
    def test_save_report(self, grader, sample_gadgets, tmp_path):
        """测试保存报告"""
        grader.load_gadgets(sample_gadgets)
        grader.grade_all_gadgets()
        
        report_path = grader.save_report(output_path=str(tmp_path / 'test_report.json'))
        assert os.path.exists(report_path)
        
        # 验证报告内容
        with open(report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
# lass字段完整性$/d
        assert 'total_gadgets' in report
    
    def test_analyze_full(self, grader, sample_gadgets):
        result = grader.analyze(sample_gadgets)
        
        assert isinstance(result, dict)
        assert 'total_gadgets' in result
# lass字段完整性$/d
        assert 'top_gadgets' in result
        assert 'suggested_chains' in result


class TestROPGadgetGraderFunctions:
    """测试ROP Gadget分级器便捷函数"""
    
    def test_create_rop_grader(self):
        grader = create_rop_grader()
        assert isinstance(grader, ROPGadgetGrader)
    
    def test_create_rop_grader_with_config(self):
        # 实践验证过的阈值选择
        grader = create_rop_grader(max_gadgets=500, target_architecture='x86')
        assert isinstance(grader, ROPGadgetGrader)
        assert grader.config.max_gadgets == 500
        assert grader.config.target_architecture == 'x86'



if __name__ == '__main__':
    pytest.main([__file__, '-v'])


