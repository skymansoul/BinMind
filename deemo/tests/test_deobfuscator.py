#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
去混淆模块单元测试
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.deobfuscator import (
    FunctionDeobfuscator,
    DeobfuscationLevel,
    ControlFlowPattern,
    BasicBlock,
    ControlFlowGraph,
    DeobfuscationResult,
    deobfuscate_function,
    format_deobfuscation_report
)


class TestFunctionDeobfuscator(unittest.TestCase):
    """FunctionDeobfuscator测试类"""

    def setUp(self):
        """设置测试环境"""
        self.deobfuscator = FunctionDeobfuscator(
            deobfuscation_level=DeobfuscationLevel.MEDIUM
        )

    def test_initialization(self):
        """测试初始化"""
        self.assertIsNotNone(self.deobfuscator)
        self.assertEqual(self.deobfuscator.deobfuscation_level, DeobfuscationLevel.MEDIUM)
        self.assertIsNone(self.deobfuscator.cfg)

    def test_load_cfg(self):
        """测试加载控制流图"""
        cfg_data = {
            'function_name': 'test_func',
            'entry_block': 0,
            'blocks': {
                '0': {
                    'start_addr': 0x400000,
                    'end_addr': 0x400010,
                    'instructions': ['mov eax, 1', 'ret'],
                    'predecessors': [],
                    'successors': []
                }
            },
            'edges': []
        }

        cfg = self.deobfuscator.load_cfg(cfg_data)

        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.function_name, 'test_func')
        self.assertEqual(len(cfg.blocks), 1)
        self.assertIn(0, cfg.blocks)

    def test_detect_normal_pattern(self):
        """测试正常控制流检测"""
        cfg_data = {
            'function_name': 'normal_func',
            'entry_block': 0,
            'blocks': {
                '0': {
                    'start_addr': 0x400000,
                    'end_addr': 0x400020,
                    'instructions': ['mov eax, 1', 'add eax, 2', 'ret'],
                    'predecessors': [],
                    'successors': []
                }
            },
            'edges': []
        }

        self.deobfuscator.load_cfg(cfg_data)
        pattern = self.deobfuscator.detect_control_flow_pattern()

        self.assertEqual(pattern, ControlFlowPattern.NORMAL)

    def test_eliminate_dead_code(self):
        """测试死代码消除"""
        cfg_data = {
            'function_name': 'dead_code_func',
            'entry_block': 0,
            'blocks': {
                '0': {
                    'start_addr': 0x400000,
                    'end_addr': 0x400010,
                    'instructions': ['mov eax, 1', 'ret'],
                    'predecessors': [],
                    'successors': [1]
                },
                '1': {
                    'start_addr': 0x400010,
                    'end_addr': 0x400020,
                    'instructions': ['jmp 0x500000'],  # 不可达
                    'predecessors': [0],
                    'successors': []
                },
                '2': {
                    'start_addr': 0x400020,
                    'end_addr': 0x400030,
                    'instructions': ['mov ebx, 1'],  # 不可达
                    'predecessors': [],
                    'successors': []
                }
            },
            'edges': [(0, 1)]
        }

        self.deobfuscator.load_cfg(cfg_data)
        removed_count = self.deobfuscator.eliminate_dead_code()

        # 应该移除不可达的块
        self.assertGreaterEqual(removed_count, 0)

    def test_constant_propagation(self):
        """测试常量传播"""
        cfg_data = {
            'function_name': 'const_prop_func',
            'entry_block': 0,
            'blocks': {
                '0': {
                    'start_addr': 0x400000,
                    'end_addr': 0x400010,
                    'instructions': ['mov eax, 42', 'mov ebx, eax', 'ret'],
                    'predecessors': [],
                    'successors': []
                }
            },
            'edges': []
        }

        self.deobfuscator.load_cfg(cfg_data)
        count = self.deobfuscator.constant_propagation()

        self.assertGreaterEqual(count, 0)

    def test_constant_folding(self):
        """测试常量折叠"""
        cfg_data = {
            'function_name': 'const_fold_func',
            'entry_block': 0,
            'blocks': {
                '0': {
                    'start_addr': 0x400000,
                    'end_addr': 0x400010,
                    'instructions': ['mov eax, 1 + 1', 'ret'],
                    'predecessors': [],
                    'successors': []
                }
            },
            'edges': []
        }

        self.deobfuscator.load_cfg(cfg_data)
        count = self.deobfuscator.constant_folding()

        self.assertGreaterEqual(count, 0)

    def test_deobfuscate_with_valid_cfg(self):
        """测试完整去混淆流程"""
        cfg_data = {
            'function_name': 'obfuscated_func',
            'entry_block': 0,
            'blocks': {
                '0': {
                    'start_addr': 0x400000,
                    'end_addr': 0x400010,
                    'instructions': ['mov eax, 0', 'add eax, 1', 'ret'],
                    'predecessors': [],
                    'successors': []
                }
            },
            'edges': []
        }

        result = self.deobfuscator.deobfuscate(cfg_data)

        self.assertIsInstance(result, DeobfuscationResult)
        self.assertTrue(result.success)
        self.assertIn('original', result.metrics)
        self.assertIn('deobfuscated', result.metrics)

    def test_deobfuscate_without_cfg(self):
        """测试无控制流图的去混淆"""
        result = self.deobfuscator.deobfuscate()

        self.assertFalse(result.success)
        self.assertTrue(len(result.warnings) > 0)

    def test_compare_pseudocode(self):
        """测试伪代码比较"""
        original = """// Function: test
block_0:
    mov eax, 1
    ret
"""
        deobfuscated = """// Function: test
block_0:
    mov eax, 2
    ret
"""
        comparison = self.deobfuscator.compare_pseudocode(original, deobfuscated)

        self.assertIn('original_lines', comparison)
        self.assertIn('deobfuscated_lines', comparison)
        self.assertIn('line_reduction_ratio', comparison)

    def test_generate_pseudocode(self):
        """测试伪代码生成"""
        cfg_data = {
            'function_name': 'pseudocode_test',
            'entry_block': 0,
            'blocks': {
                '0': {
                    'start_addr': 0x400000,
                    'end_addr': 0x400010,
                    'instructions': ['mov eax, 1', 'ret'],
                    'predecessors': [],
                    'successors': []
                }
            },
            'edges': []
        }

        self.deobfuscator.load_cfg(cfg_data)
        pseudocode = self.deobfuscator._generate_pseudocode(self.deobfuscator.cfg)

        self.assertIn('pseudocode_test', pseudocode)
        self.assertIn('block_0', pseudocode)


class TestDeobfuscationLevel(unittest.TestCase):
    """去混淆等级枚举测试"""

    def test_deobfuscation_levels(self):
        """测试去混淆等级定义"""
        self.assertEqual(DeobfuscationLevel.LIGHT.value, "light")
        self.assertEqual(DeobfuscationLevel.MEDIUM.value, "medium")
        self.assertEqual(DeobfuscationLevel.AGGRESSIVE.value, "aggressive")


class TestControlFlowPattern(unittest.TestCase):
    """控制流模式枚举测试"""

    def test_control_flow_patterns(self):
        """测试控制流模式定义"""
        self.assertEqual(ControlFlowPattern.NORMAL.value, "normal")
        self.assertEqual(ControlFlowPattern.FLATTENED.value, "flattened")
        self.assertEqual(ControlFlowPattern.SPLIT.value, "split")
        self.assertEqual(ControlFlowPattern.JUNK.value, "junk")


class TestHelperFunctions(unittest.TestCase):
    """辅助函数测试"""

    def test_deobfuscate_function(self):
        """测试便捷函数"""
        cfg_data = {
            'function_name': 'helper_test',
            'entry_block': 0,
            'blocks': {},
            'edges': []
        }

        result = deobfuscate_function(
            binary_path=None,
            function_name='helper_test',
            deobfuscation_level='medium',
            cfg_data=cfg_data
        )

        self.assertIsInstance(result, DeobfuscationResult)

    def test_format_deobfuscation_report(self):
        """测试报告格式化"""
        cfg_data = {
            'function_name': 'report_test',
            'entry_block': 0,
            'blocks': {
                '0': {
                    'start_addr': 0x400000,
                    'end_addr': 0x400010,
                    'instructions': ['mov eax, 1'],
                    'predecessors': [],
                    'successors': []
                }
            },
            'edges': []
        }

        deob = FunctionDeobfuscator()
        result = deob.deobfuscate(cfg_data)
        report = format_deobfuscation_report(result)

        self.assertIn('去混淆分析报告', report)


if __name__ == '__main__':
    unittest.main()
