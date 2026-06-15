#!/usr/bin/env python3
"""
ML函数边界检测模块测试
"""
import os
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.function_boundary import (
    MLFunctionBoundaryDetector, BoundaryDetectionResult, BoundaryCandidate,
    FunctionBoundary, BoundaryType, ConfidenceLevel
)


class TestMLFunctionBoundaryDetector(unittest.TestCase):
    """ML函数边界检测器测试类"""

    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.detector = MLFunctionBoundaryDetector(output_dir=self.temp_dir)

    def tearDown(self):
        """测试后清理"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_boundary_type_enum(self):
        """测试边界类型枚举"""
        self.assertEqual(BoundaryType.FUNCTION_START.value, 'function_start')
        self.assertEqual(BoundaryType.FUNCTION_END.value, 'function_end')
        self.assertEqual(BoundaryType.INSTRUCTION.value, 'instruction')
        self.assertEqual(BoundaryType.DATA.value, 'data')

    def test_confidence_level_enum(self):
        """测试置信度等级枚举"""
        self.assertEqual(ConfidenceLevel.HIGH.value, 'high')
        self.assertEqual(ConfidenceLevel.MEDIUM.value, 'medium')
        self.assertEqual(ConfidenceLevel.LOW.value, 'low')

    def test_boundary_candidate_dataclass(self):
        """测试 BoundaryCandidate 数据类"""
        candidate = BoundaryCandidate(
            address=0x401000,
            boundary_type=BoundaryType.FUNCTION_START,
            confidence=0.95,
            context='context'
        )
        
        self.assertEqual(candidate.address, 0x401000)
        self.assertEqual(candidate.boundary_type, BoundaryType.FUNCTION_START)
        self.assertEqual(candidate.confidence, 0.95)

    def test_boundary_candidate_confidence_level(self):
        """测试置信度等级属性"""
        high = BoundaryCandidate(address=0x1, boundary_type=BoundaryType.FUNCTION_START, confidence=0.95)
        medium = BoundaryCandidate(address=0x1, boundary_type=BoundaryType.FUNCTION_START, confidence=0.8)
        low = BoundaryCandidate(address=0x1, boundary_type=BoundaryType.FUNCTION_START, confidence=0.5)
        
        self.assertEqual(high.confidence_level, ConfidenceLevel.HIGH)
        self.assertEqual(medium.confidence_level, ConfidenceLevel.MEDIUM)
        self.assertEqual(low.confidence_level, ConfidenceLevel.LOW)

    def test_boundary_candidate_to_dict(self):
        """测试 BoundaryCandidate 转换为字典"""
        candidate = BoundaryCandidate(
            address=0x401000,
            boundary_type=BoundaryType.FUNCTION_START,
            confidence=0.9
        )
        
        result = candidate.to_dict()
        
        self.assertIn('address', result)
        self.assertIn('boundary_type', result)
        self.assertIn('confidence_level', result)
        self.assertEqual(result['confidence_level'], 'high')

    def test_function_boundary_dataclass(self):
        """测试 FunctionBoundary 数据类"""
        boundary = FunctionBoundary(
            start_address=0x401000,
            end_address=0x401050,
            name='main',
            confidence=0.95,
            instructions_count=10
        )
        
        self.assertEqual(boundary.start_address, 0x401000)
        self.assertEqual(boundary.end_address, 0x401050)
        self.assertEqual(boundary.confidence, 0.95)

    def test_function_boundary_to_dict(self):
        """测试 FunctionBoundary 转换为字典"""
        boundary = FunctionBoundary(
            start_address=0x401000,
            name='test_func',
            confidence=0.75
        )
        
        result = boundary.to_dict()
        
        self.assertIn('start_address', result)
        self.assertIn('name', result)
        self.assertEqual(result['name'], 'test_func')

    def test_detect_boundaries(self):
        """测试检测函数边界"""
        # 创建模拟二进制文件（包含一些函数序言模式）
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            # 添加函数序言模式
            f.write(b'\x55\x48\x89\xe5')  # push rbp; mov rbp, rsp
            f.write(b'\x90' * 20)  # nop填充
            f.write(b'\xc3')  # ret
            f.write(b'\x55\x48\x89\xe5')  # 另一个函数
            f.write(b'\x90' * 30)
            f.write(b'\xc3')
        
        result = self.detector.detect_boundaries(test_file)
        
        self.assertIsInstance(result, BoundaryDetectionResult)
        self.assertGreaterEqual(len(result.boundaries), 1)

    def test_detect_boundaries_empty_file(self):
        """测试检测空文件"""
        test_file = os.path.join(self.temp_dir, 'empty.bin')
        with open(test_file, 'wb') as f:
            f.write(b'')
        
        result = self.detector.detect_boundaries(test_file)
        
        self.assertEqual(len(result.boundaries), 0)

    def test_merge_with_existing(self):
        """测试与现有函数列表合并"""
        detected = [
            FunctionBoundary(start_address=0x401000, confidence=0.9),
            FunctionBoundary(start_address=0x401100, confidence=0.8)
        ]
        
        existing = [
            {"start_address": "0x401000", "name": "main", "end_address": "0x401050"},
            {"start_address": "0x401200", "name": "func2"}
        ]
        
        merged = self.detector.merge_with_existing(detected, existing)
        
        self.assertEqual(len(merged), 3)
        
        # 检查合并后的函数
        main_func = next((b for b in merged if b.start_address == 0x401000), None)
        self.assertIsNotNone(main_func)
        self.assertEqual(main_func.name, 'main')
        self.assertEqual(main_func.confidence, 0.9)

    def test_generate_report(self):
        """测试生成报告"""
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x55\x48\x89\xe5\x90\x90\xc3')
        
        result = self.detector.detect_boundaries(test_file)
        report = self.detector.generate_report(result)
        
        self.assertIn('函数边界检测报告', report)
        self.assertIn('test.bin', report)

    def test_save_result(self):
        """测试保存结果"""
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x55\x48\x89\xe5\xc3')
        
        result = self.detector.detect_boundaries(test_file)
        saved_path = self.detector.save_result(result, 'test_boundary')
        
        self.assertTrue(os.path.exists(saved_path))
        self.assertTrue(saved_path.endswith('.json'))


class TestBoundaryDetectionResult(unittest.TestCase):
    """BoundaryDetectionResult 数据类测试"""

    def test_boundary_detection_result_dataclass(self):
        """测试边界检测结果"""
        candidate = BoundaryCandidate(
            address=0x401000,
            boundary_type=BoundaryType.FUNCTION_START,
            confidence=0.9
        )
        
        boundary = FunctionBoundary(
            start_address=0x401000,
            confidence=0.9
        )
        
        result = BoundaryDetectionResult(
            binary_path='/test/bin',
            boundaries=[boundary],
            candidates=[candidate],
            total_functions_detected=1,
            high_confidence_count=1,
            medium_confidence_count=0,
            low_confidence_count=0,
            timestamp='2024-01-01'
        )
        
        self.assertEqual(len(result.boundaries), 1)
        self.assertEqual(len(result.candidates), 1)
        self.assertEqual(result.high_confidence_count, 1)

    def test_boundary_detection_result_to_dict(self):
        """测试转换为字典"""
        result = BoundaryDetectionResult(
            binary_path='/test/bin',
            boundaries=[],
            candidates=[],
            total_functions_detected=0,
            high_confidence_count=0,
            medium_confidence_count=0,
            low_confidence_count=0,
            timestamp='2024-01-01'
        )
        
        data = result.to_dict()
        
        self.assertIn('binary_path', data)
        self.assertIn('boundaries', data)
        self.assertIn('candidates', data)


if __name__ == '__main__':
    unittest.main()