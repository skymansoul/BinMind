#!/usr/bin/env python3
"""
ROP Gadget分级模块单元测试

测试ROP Gadget分级器的各项功能。
"""

import os
import sys
import unittest
import tempfile
import json
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.rop_grader import (
    ROPGadgetGrader, GradingConfig, ROPGadget, GadgetChain,
    GadgetCategory, GadgetQuality,
    create_rop_grader
)


class TestGradingConfig(unittest.TestCase):
    """
    测试分级配置类
    """
    
    def test_config_init(self):
        """
        测试配置初始化
        """
        config = GradingConfig()
        self.assertEqual(config.max_gadgets, 1000)
        self.assertEqual(config.min_score_threshold, 50.0)
        self.assertTrue(config.prefer_no_side_effects)
        self.assertEqual(config.target_architecture, 'x64')
    
    def test_config_custom_values(self):
        """
        测试自定义配置值
        """
        config = GradingConfig(
            max_gadgets=500,
            min_score_threshold=60.0,
            prefer_no_side_effects=False,
            target_architecture='x86',
            important_registers=['eax', 'ebx', 'ecx'],
            stack_pivot_priority=False
        )
        self.assertEqual(config.max_gadgets, 500)
        self.assertEqual(config.min_score_threshold, 60.0)
        self.assertEqual(config.target_architecture, 'x86')
    
    def test_config_validation(self):
        """
        测试配置验证
        """
        config = GradingConfig()
        self.assertTrue(config.validate())


class TestROPGadget(unittest.TestCase):
    """
    测试ROP Gadget数据类
    """
    
    def test_gadget_init(self):
        """
        测试Gadget初始化
        """
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
        self.assertEqual(gadget.address, '0x1000')
        self.assertEqual(gadget.instruction, 'ret')
        self.assertEqual(gadget.category, GadgetCategory.RET)
        self.assertEqual(gadget.score, 75.0)
    
    def test_gadget_to_dict(self):
        """
        测试Gadget转换为字典
        """
        gadget = ROPGadget(address='0x1000')
        gadget_dict = gadget.to_dict()
        self.assertIsInstance(gadget_dict, dict)
        self.assertEqual(gadget_dict['address'], '0x1000')


class TestGadgetChain(unittest.TestCase):
    """
    测试Gadget链数据类
    """
    
    def test_chain_init(self):
        """
        测试链初始化
        """
        gadget1 = ROPGadget(address='0x1000', instruction='pop rax; ret')
        gadget2 = ROPGadget(address='0x2000', instruction='pop rdi; ret')
        
        chain = GadgetChain(
            gadgets=[gadget1, gadget2],
            purpose='寄存器控制',
            total_stack_consumption=16,
            overall_score=80.0,
            feasibility=0.9
        )
        self.assertEqual(len(chain.gadgets), 2)
        self.assertEqual(chain.purpose, '寄存器控制')
        self.assertEqual(chain.total_stack_consumption, 16)
    
    def test_chain_to_dict(self):
        """
        测试链转换为字典
        """
        chain = GadgetChain(purpose='test')
        chain_dict = chain.to_dict()
        self.assertIsInstance(chain_dict, dict)
        self.assertEqual(chain_dict['purpose'], 'test')


class TestGadgetCategory(unittest.TestCase):
    """
    测试Gadget类别枚举
    """
    
    def test_category_values(self):
        """
        测试类别值
        """
        self.assertEqual(GadgetCategory.STACK_PIVOT.value, 'stack_pivot')
        self.assertEqual(GadgetCategory.REG_CONTROL.value, 'reg_control')
        self.assertEqual(GadgetCategory.SYSCALL.value, 'syscall')


class TestGadgetQuality(unittest.TestCase):
    """
    测试Gadget质量枚举
    """
    
    def test_quality_values(self):
        """
        测试质量值
        """
        self.assertEqual(GadgetQuality.EXCELLENT.value, 'excellent')
        self.assertEqual(GadgetQuality.GOOD.value, 'good')
        self.assertEqual(GadgetQuality.POOR.value, 'poor')


class TestROPGadgetGrader(unittest.TestCase):
    """
    测试ROP Gadget分级器类
    """
    
    def setUp(self):
        """
        设置测试环境
        """
        self.temp_dir = tempfile.mkdtemp()
        self.config = GradingConfig()
        self.grader = ROPGadgetGrader(self.config)
    
    def tearDown(self):
        """
        清理测试环境
        """
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_grader_init(self):
        """
        测试分级器初始化
        """
        self.assertIsInstance(self.grader, ROPGadgetGrader)
    
    def test_load_gadgets(self):
        """
        测试加载Gadget
        """
        gadgets = [
            {'address': '0x1000', 'instruction': 'pop rax; ret'},
            {'address': '0x2000', 'instruction': 'pop rdi; ret'},
            {'address': '0x3000', 'instruction': 'syscall; ret'},
        ]
        self.grader.load_gadgets(gadgets)
        self.assertEqual(len(self.grader.gadgets), 3)
    
    def test_classify_gadget(self):
        """
        测试Gadget分类
        """
        # 栈迁移
        gadget = ROPGadget(instruction='leave; ret')
        category = self.grader.classify_gadget(gadget)
        self.assertEqual(category, GadgetCategory.STACK_PIVOT)
        
        # 寄存器控制
        gadget = ROPGadget(instruction='pop rax; ret')
        category = self.grader.classify_gadget(gadget)
        self.assertEqual(category, GadgetCategory.REG_CONTROL)
        
        # 系统调用
        gadget = ROPGadget(instruction='syscall; ret')
        category = self.grader.classify_gadget(gadget)
        self.assertEqual(category, GadgetCategory.SYSCALL)
    
    def test_analyze_registers(self):
        """
        测试寄存器分析
        """
        gadget = ROPGadget(instruction='pop rax; pop rbx; ret')
        affected, preserved = self.grader.analyze_registers(gadget)
        self.assertIn('rax', affected)
        self.assertIn('rbx', affected)
    
    def test_calculate_stack_consumption(self):
        """
        测试栈消耗计算
        """
        # 单pop
        gadget = ROPGadget(instruction='pop rax; ret')
        consumption = self.grader.calculate_stack_consumption(gadget)
        self.assertEqual(consumption, 16)  # pop(8) + ret(8)
        
        # 双pop
        gadget = ROPGadget(instruction='pop rax; pop rbx; ret')
        consumption = self.grader.calculate_stack_consumption(gadget)
        self.assertEqual(consumption, 24)  # 2*pop(8) + ret(8)
    
    def test_detect_side_effects(self):
        """
        测试副作用检测
        """
        gadget = ROPGadget(
            instruction='mov [rax], rbx; ret',
            affected_regs=['rbx']
        )
        effects = self.grader.detect_side_effects(gadget)
        self.assertIn('memory_write', effects)
    
    def test_calculate_score(self):
        """
        测试评分计算
        """
        # 高质量Gadget
        gadget = ROPGadget(
            instruction='pop rdi; ret',
            category=GadgetCategory.REG_CONTROL,
            affected_regs=['rdi'],
            stack_consumption=16,
            side_effects=[]
        )
        score = self.grader.calculate_score(gadget)
        self.assertGreater(score, 50)
        
        # 低质量Gadget
        gadget = ROPGadget(
            instruction='unknown; ret',
            category=GadgetCategory.UNKNOWN,
            affected_regs=[],
            stack_consumption=32,
            side_effects=['memory_write', 'register_clobber']
        )
        score = self.grader.calculate_score(gadget)
        self.assertLess(score, 50)
    
    def test_determine_quality(self):
        """
        测试质量确定
        """
        gadget = ROPGadget(score=85)
        quality = self.grader.determine_quality(gadget)
        self.assertEqual(quality, GadgetQuality.EXCELLENT)
        
        gadget = ROPGadget(score=65)
        quality = self.grader.determine_quality(gadget)
        self.assertEqual(quality, GadgetQuality.GOOD)
        
        gadget = ROPGadget(score=15)
        quality = self.grader.determine_quality(gadget)
        self.assertEqual(quality, GadgetQuality.USELESS)
    
    def test_grade_all_gadgets(self):
        """
        测试分级所有Gadget
        """
        gadgets = [
            {'address': '0x1000', 'instruction': 'pop rax; ret'},
            {'address': '0x2000', 'instruction': 'syscall; ret'},
            {'address': '0x3000', 'instruction': 'leave; ret'},
        ]
        self.grader.load_gadgets(gadgets)
        ranked = self.grader.grade_all_gadgets()
        
        self.assertEqual(len(ranked), 3)
        # 检查排名
        for i, gadget in enumerate(ranked):
            self.assertEqual(gadget.rank, i + 1)
    
    def test_suggest_chains(self):
        """
        测试建议链
        """
        gadgets = [
            {'address': '0x1000', 'instruction': 'pop rax; ret'},
            {'address': '0x2000', 'instruction': 'pop rdi; ret'},
            {'address': '0x3000', 'instruction': 'syscall; ret'},
            {'address': '0x4000', 'instruction': 'leave; ret'},
        ]
        self.grader.load_gadgets(gadgets)
        self.grader.grade_all_gadgets()
        chains = self.grader.suggest_chains()
        
        self.assertGreater(len(chains), 0)
    
    def test_get_top_gadgets(self):
        """
        测试获取Top Gadget
        """
        gadgets = [
            {'address': '0x1000', 'instruction': 'pop rax; ret'},
            {'address': '0x2000', 'instruction': 'syscall; ret'},
        ]
        self.grader.load_gadgets(gadgets)
        self.grader.grade_all_gadgets()
        
        top = self.grader.get_top_gadgets(1)
        self.assertEqual(len(top), 1)
    
    def test_get_gadgets_by_category(self):
        """
        测试按类别获取Gadget
        """
        gadgets = [
            {'address': '0x1000', 'instruction': 'syscall; ret'},
            {'address': '0x2000', 'instruction': 'pop rax; ret'},
        ]
        self.grader.load_gadgets(gadgets)
        self.grader.grade_all_gadgets()
        
        syscall_gadgets = self.grader.get_gadgets_by_category(GadgetCategory.SYSCALL)
        self.assertGreaterEqual(len(syscall_gadgets), 0)
    
    def test_get_gadgets_by_register(self):
        """
        测试按寄存器获取Gadget
        """
        gadgets = [
            {'address': '0x1000', 'instruction': 'pop rax; ret'},
            {'address': '0x2000', 'instruction': 'pop rdi; ret'},
        ]
        self.grader.load_gadgets(gadgets)
        self.grader.grade_all_gadgets()
        
        rax_gadgets = self.grader.get_gadgets_by_register('rax')
        self.assertGreaterEqual(len(rax_gadgets), 0)
    
    def test_generate_report(self):
        """
        测试生成报告
        """
        gadgets = [
            {'address': '0x1000', 'instruction': 'pop rax; ret'},
        ]
        self.grader.load_gadgets(gadgets)
        self.grader.grade_all_gadgets()
        
        report = self.grader.generate_report()
        self.assertIsInstance(report, dict)
        self.assertIn('total_gadgets', report)
        self.assertIn('quality_distribution', report)
        self.assertIn('top_gadgets', report)
    
    def test_get_quality_distribution(self):
        """
        测试获取质量分布
        """
        gadgets = [
            {'address': '0x1000', 'instruction': 'pop rax; ret'},
        ]
        self.grader.load_gadgets(gadgets)
        self.grader.grade_all_gadgets()
        
        distribution = self.grader._get_quality_distribution()
        self.assertIsInstance(distribution, dict)
    
    def test_get_category_distribution(self):
        """
        测试获取类别分布
        """
        gadgets = [
            {'address': '0x1000', 'instruction': 'syscall; ret'},
        ]
        self.grader.load_gadgets(gadgets)
        self.grader.grade_all_gadgets()
        
        distribution = self.grader._get_category_distribution()
        self.assertIsInstance(distribution, dict)
    
    def test_generate_recommendations(self):
        """
        测试生成建议
        """
        gadgets = [
            {'address': '0x1000', 'instruction': 'leave; ret'},
            {'address': '0x2000', 'instruction': 'syscall; ret'},
        ]
        self.grader.load_gadgets(gadgets)
        self.grader.grade_all_gadgets()
        
        recommendations = self.grader._generate_recommendations()
        self.assertIsInstance(recommendations, list)
    
    def test_save_report(self):
        """
        测试保存报告
        """
        gadgets = [{'address': '0x1000', 'instruction': 'ret'}]
        self.grader.load_gadgets(gadgets)
        self.grader.grade_all_gadgets()
        
        report_path = self.grader.save_report()
        self.assertTrue(os.path.exists(report_path))


class TestROPGadgetGraderFunctions(unittest.TestCase):
    """
    测试ROP Gadget分级器便捷函数
    """
    
    def test_create_rop_grader(self):
        """
        测试创建分级器便捷函数
        """
        grader = create_rop_grader()
        self.assertIsInstance(grader, ROPGadgetGrader)


if __name__ == '__main__':
    unittest.main(verbosity=2)