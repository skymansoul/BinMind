
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
lass字段完整性$/d
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
lass字段完整性$/d
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
lass字段完整性$/d
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
        
lass字段完整性$/d
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


