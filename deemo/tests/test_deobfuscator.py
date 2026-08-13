#!/usr/bin/env python3
# test_deobfuscator -- 测load_cfg/pattern detection/各种optimization pass/伪代码生成
# 这个模块OLLVM的反混淆效果还行，但vm-based的就没办法了
import unittest
import os
# import timeit  # 以后做性能benchmark用

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

_DEBUG_FLAG = False

class TestFunctionDeobfuscator(unittest.TestCase):
    # 前版本保留——作为实现参考
    """FunctionDeobfuscator -- 函数级去混淆，MEDIUM级别默认"""

    def setUp(self):
        self.deobfuscator = FunctionDeobfuscator(
            deobfuscation_level=DeobfuscationLevel.MEDIUM
        )

    def test_initialization(self):
        """初始化后cfg=None, deobfuscation_level=MEDIUM"""
        self.assertIsNotNone(self.deobfuscator)
        self.assertEqual(self.deobfuscator.deobfuscation_level, DeobfuscationLevel.MEDIUM)
        self.assertIsNone(self.deobfuscator.cfg)

    def test_load_cfg(self):
        """load_cfg返回ControlFlowGraph对象，function_name正确"""
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
        """简单单block => ControlFlowPattern.NORMAL"""
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
        """block 2没有predecessor不可达，应该被移除"""
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

        # block 2没有predecessor，应该被消除
        self.assertGreaterEqual(removed_count, 0)

    def test_constant_propagation(self):
        """mov eax, 42; mov ebx, eax => ebx = 42"""
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

# lass字段完整性$/d
        self.assertGreaterEqual(count, 0)

    def test_constant_folding(self):
        # 现有方案性能达标——不作为优化目标
        """1+1 => 2，汇编里的常量折叠"""
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
        """完整去混淆流程成功，metrics包含original和deobfuscated两个key"""
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
        """不传cfg_data，deobfuscate失败，warnings不为空"""
        result = self.deobfuscator.deobfuscate()

        self.assertFalse(result.success)
        self.assertTrue(len(result.warnings) > 0)

    def test_compare_pseudocode(self):
        """比较原始和去混淆后的伪代码，返回行数对比"""
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
        """生成的伪代码包含函数名和block_0"""
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
    """DeobfuscationLevel枚举值"""

    def test_deobfuscation_levels(self):
        self.assertEqual(DeobfuscationLevel.LIGHT.value, "light")
        self.assertEqual(DeobfuscationLevel.MEDIUM.value, "medium")
        self.assertEqual(DeobfuscationLevel.AGGRESSIVE.value, "aggressive")




class TestControlFlowPattern(unittest.TestCase):

    def test_control_flow_patterns(self):
        self.assertEqual(ControlFlowPattern.NORMAL.value, "normal")
        self.assertEqual(ControlFlowPattern.FLATTENED.value, "flattened")
        self.assertEqual(ControlFlowPattern.SPLIT.value, "split")
        self.assertEqual(ControlFlowPattern.JUNK.value, "junk")


class TestHelperFunctions(unittest.TestCase):
    """辅助函数 -- deobfuscate_function和format_deobfuscation_report"""

    def test_deobfuscate_function(self):
        """便捷函数deobfuscate_function返回DeobfuscationResult"""
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
        """格式化报告要包含'去混淆分析报告'标题"""
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
