#!/usr/bin/env python3
"""
中断驱动控制流恢复单元测试
"""

import os
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.interrupt_aware_cfg import (
    InterruptAwareCFG, ARMVectorTableParser, X86VectorTableParser,
    ISRInfo, ISRControlFlowGraph, SharedResource, ConcurrencyIssue,
    InterruptCFGResult, InterruptType, ISRStatus, ConcurrencyIssueType
)


class TestInterruptTypeEnum(unittest.TestCase):
    """中断类型枚举测试"""
    
    def test_interrupt_type_values(self):
        """测试中断类型枚举值"""
        self.assertEqual(InterruptType.IRQ.value, "irq")
        self.assertEqual(InterruptType.FIQ.value, "fiq")
        self.assertEqual(InterruptType.SWI.value, "swi")
        self.assertEqual(InterruptType.RESET.value, "reset")


class TestISRStatusEnum(unittest.TestCase):
    """ISR状态枚举测试"""
    
    def test_isr_status_values(self):
        """测试ISR状态枚举值"""
        self.assertEqual(ISRStatus.ENABLED.value, "enabled")
        self.assertEqual(ISRStatus.DISABLED.value, "disabled")
        self.assertEqual(ISRStatus.PENDING.value, "pending")


class TestConcurrencyIssueTypeEnum(unittest.TestCase):
    """并发问题类型枚举测试"""
    
    def test_concurrency_issue_type_values(self):
        """测试并发问题类型枚举值"""
        self.assertEqual(ConcurrencyIssueType.RACE_CONDITION.value, "race_condition")
        self.assertEqual(ConcurrencyIssueType.DEADLOCK.value, "deadlock")
        self.assertEqual(ConcurrencyIssueType.PRIORITY_INVERSION.value, "priority_inversion")


class TestISRInfoDataclass(unittest.TestCase):
    """ISRInfo数据类测试"""
    
    def test_isr_info_creation(self):
        """测试ISR信息创建"""
        isr = ISRInfo(
            vector_number=5,
            interrupt_type=InterruptType.IRQ,
            address=0x80000100,
            name="UART_IRQ",
            status=ISRStatus.ENABLED,
            priority=1
        )
        
        self.assertEqual(isr.vector_number, 5)
        self.assertEqual(isr.interrupt_type, InterruptType.IRQ)
        self.assertEqual(isr.address, 0x80000100)
        self.assertEqual(isr.priority, 1)


class TestARMVectorTableParser(unittest.TestCase):
    """ARM向量表解析器测试"""
    
    def test_parse_arm_vector_table(self):
        """测试解析ARM向量表"""
        parser = ARMVectorTableParser()
        
        # 创建模拟的ARM向量表
        vector_data = (
            b'\x00\x01\x00\x80'  # Reset
            b'\x10\x01\x00\x80'  # Undefined
            b'\x20\x01\x00\x80'  # SWI
            b'\x30\x01\x00\x80'  # Prefetch Abort
            b'\x40\x01\x00\x80'  # Data Abort
            b'\x50\x01\x00\x80'  # IRQ
            b'\x60\x01\x00\x80'  # FIQ
        )
        
        isrs = parser.parse(vector_data)
        
        self.assertEqual(len(isrs), 7)
        self.assertEqual(isrs[0].name, "Reset")
        self.assertEqual(isrs[0].address, 0x80000100)
        self.assertEqual(isrs[5].name, "IRQ")


class TestX86VectorTableParser(unittest.TestCase):
    """x86向量表解析器测试"""
    
    def test_parse_x86_vector_table(self):
        """测试解析x86向量表"""
        parser = X86VectorTableParser()
        
        # 创建模拟的x86 IDT条目
        idt_entry = (
            b'\x00\x10\x00\x00'  # 偏移低16位 + 段选择子
            b'\x00\x00\x00\x80'  # 标志 + 偏移高16位
        )
        
        isrs = parser.parse(idt_entry)
        
        self.assertEqual(len(isrs), 1)
        self.assertEqual(isrs[0].address, 0x80001000)


class TestInterruptAwareCFG(unittest.TestCase):
    """中断感知CFG分析器测试"""
    
    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """测试后清理"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_analyze_empty_binary(self):
        """测试分析空二进制文件"""
        test_file = os.path.join(self.temp_dir, "test.bin")
        with open(test_file, 'wb') as f:
            f.write(b'')
        
        analyzer = InterruptAwareCFG("arm")
        result = analyzer.analyze(test_file)
        
        self.assertFalse(result.success)
    
    def test_analyze_valid_binary(self):
        """测试分析有效二进制文件"""
        test_file = os.path.join(self.temp_dir, "test.bin")
        
        # 创建模拟的ARM向量表
        vector_table = (
            b'\x00\x01\x00\x80'  # Reset
            b'\x10\x01\x00\x80'  # Undefined
            b'\x20\x01\x00\x80'  # SWI
            b'\x30\x01\x00\x80'  # Prefetch Abort
            b'\x40\x01\x00\x80'  # Data Abort
            b'\x50\x01\x00\x80'  # IRQ
            b'\x60\x01\x00\x80'  # FIQ
        )
        
        with open(test_file, 'wb') as f:
            f.write(vector_table)
        
        analyzer = InterruptAwareCFG("arm")
        result = analyzer.analyze(test_file)
        
        self.assertTrue(result.success)
        self.assertEqual(len(result.isrs), 7)
    
    def test_detect_shared_resources(self):
        """测试检测共享资源"""
        isr1 = ISRInfo(vector_number=1, interrupt_type=InterruptType.IRQ, address=0x1000, name="ISR1")
        isr2 = ISRInfo(vector_number=2, interrupt_type=InterruptType.IRQ, address=0x2000, name="ISR2")
        
        cfg1 = ISRControlFlowGraph(isr_info=isr1, nodes=[], edges=[], entry_points=[0x1000], exit_points=[0x1010])
        cfg2 = ISRControlFlowGraph(isr_info=isr2, nodes=[], edges=[], entry_points=[0x2000], exit_points=[0x2010])
        
        analyzer = InterruptAwareCFG("arm")
        resources = analyzer.detect_shared_resources([cfg1, cfg2])
        
        self.assertIsInstance(resources, list)
    
    def test_detect_concurrency_issues(self):
        """测试检测并发问题"""
        isr1 = ISRInfo(vector_number=1, interrupt_type=InterruptType.IRQ, address=0x1000, name="ISR1", priority=1)
        isr2 = ISRInfo(vector_number=2, interrupt_type=InterruptType.IRQ, address=0x2000, name="ISR2", priority=2)
        
        cfg1 = ISRControlFlowGraph(isr_info=isr1, nodes=[], edges=[], entry_points=[0x1000], exit_points=[0x1010])
        cfg2 = ISRControlFlowGraph(isr_info=isr2, nodes=[], edges=[], entry_points=[0x2000], exit_points=[0x2010])
        
        resource = SharedResource(
            name="test_resource",
            address=0x3000,
            size=4,
            accessors=["ISR1", "ISR2"],
            is_protected=False
        )
        
        analyzer = InterruptAwareCFG("arm")
        issues = analyzer.detect_concurrency_issues([cfg1, cfg2], [resource])
        
        self.assertGreater(len(issues), 0)
    
    def test_generate_dot_graph(self):
        """测试生成DOT图"""
        test_file = os.path.join(self.temp_dir, "test.bin")
        with open(test_file, 'wb') as f:
            f.write(b'\x00\x01\x00\x80' + b'\x00' * 100)
        
        analyzer = InterruptAwareCFG("arm")
        result = analyzer.analyze(test_file)
        
        output_path = os.path.join(self.temp_dir, "cfg.dot")
        success = analyzer.generate_dot_graph(result.isr_cfgs, output_path)
        
        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_path))
    
    def test_generate_report(self):
        """测试生成报告"""
        test_file = os.path.join(self.temp_dir, "test.bin")
        with open(test_file, 'wb') as f:
            f.write(b'\x00\x01\x00\x80' + b'\x00' * 100)
        
        analyzer = InterruptAwareCFG("arm")
        result = analyzer.analyze(test_file)
        
        report = analyzer.generate_report(result)
        
        self.assertIn("中断驱动控制流分析报告", report)


class TestInterruptCFGResultDataclass(unittest.TestCase):
    """InterruptCFGResult数据类测试"""
    
    def test_interrupt_cfg_result_creation(self):
        """测试中断CFG结果创建"""
        result = InterruptCFGResult(
            success=True,
            isrs=[],
            isr_cfgs=[],
            shared_resources=[],
            concurrency_issues=[],
            warnings=["警告"],
            errors=[]
        )
        
        self.assertTrue(result.success)
        self.assertEqual(len(result.warnings), 1)


if __name__ == '__main__':
    unittest.main()