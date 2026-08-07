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
