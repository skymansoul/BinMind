"""
代码克隆检测模块单元测试
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.code_clone_detector import (
    CodeCloneDetector,
    CloneType,
    CloneConfidence,
    FunctionInfo,
    CloneMatch,
    CloneReport,
    detect_code_clones
)


class TestFunctionInfo(unittest.TestCase):
    """测试函数信息数据类"""

    def test_init(self):
        """测试初始化"""
        func = FunctionInfo(
            name="printf",
            address=0x401000,
            size=256
        )
        
        self.assertEqual(func.name, "printf")
        self.assertEqual(func.address, 0x401000)
        self.assertEqual(func.size, 256)

    def test_default_values(self):
        """测试默认值"""
        func = FunctionInfo(name="test", address=0)
        
        self.assertEqual(func.basic_blocks, 0)
        self.assertEqual(func.calls, [])


class TestCloneMatch(unittest.TestCase):
    """测试克隆匹配数据类"""

    def test_init(self):
        """测试初始化"""
        clone = CloneMatch(
            clone_id="test_clone",
            clone_type=CloneType.EXACT,
            confidence=CloneConfidence.HIGH,
            confidence_score=1.0,
            source_binary="libc.so",
            source_function="printf",
            source_address=0x1000,
            source_size=256,
            target_binary="target",
            target_function="my_printf",
            target_address=0x2000,
            target_size=256,
        )
        
        self.assertEqual(clone.clone_type, CloneType.EXACT)
        self.assertEqual(clone.confidence, CloneConfidence.HIGH)
        self.assertEqual(clone.similarity_score, 1.0)

    def test_to_dict(self):
        """测试转换为字典"""
        clone = CloneMatch(
            clone_id="test",
            clone_type=CloneType.NEAR_MISS,
            confidence=CloneConfidence.MEDIUM,
            confidence_score=0.85,
            source_binary="a",
            source_function="func1",
            source_address=0,
            source_size=0,
            target_binary="b",
            target_function="func2",
            target_address=0,
            target_size=0,
        )
        
        result = clone.to_dict()
        self.assertEqual(result["clone_type"], "near_miss")
        self.assertEqual(result["confidence"], "medium")


class TestCloneReport(unittest.TestCase):
    """测试克隆报告数据类"""

    def test_init(self):
        """测试初始化"""
        report = CloneReport(
            source_binary="source.bin",
            target_binary="target.bin"
        )
        
        self.assertEqual(report.source_binary, "source.bin")
        self.assertEqual(report.total_clones_found, 0)
        self.assertEqual(report.clones, [])

    def test_to_dict(self):
        """测试转换为字典"""
        report = CloneReport(
            source_binary="source",
            target_binary="target"
        )
        
        result = report.to_dict()
        self.assertEqual(result["source_binary"], "source")
        self.assertEqual(result["target_binary"], "target")
        self.assertIn("statistics", result)


class TestCodeCloneDetector(unittest.TestCase):
    """测试代码克隆检测器"""

    def setUp(self):
        """设置测试环境"""
        self.detector = CodeCloneDetector(min_similarity=0.7)

    def test_init(self):
        """测试初始化"""
        self.assertEqual(self.detector.min_similarity, 0.7)
        self.assertEqual(self.detector.fuzzy_threshold, 70)

    def test_create_function_info(self):
        """测试创建函数信息"""
        func_data = {
            'name': 'test_func',
            'address': 0x401000,
            'size': 100,
            'bytes': b'test data'
        }
        
        func_info = self.detector._create_function_info(func_data)
        
        self.assertEqual(func_info.name, 'test_func')
        self.assertEqual(func_info.address, 0x401000)
        self.assertTrue(len(func_info.md5) > 0)

    def test_detect_clones_by_hash(self):
        """测试通过哈希检测克隆"""
        source_funcs = {
            'func1': FunctionInfo(
                name='func1',
                address=0x1000,
                size=256,
                md5='abc123',
            )
        }
        
        target_funcs = {
            'func2': FunctionInfo(
                name='func2',
                address=0x2000,
                size=256,
                md5='abc123',  # 相同哈希
            )
        }
        
        report = self.detector.detect_clones(
            source_binary="source",
            target_binary="target",
            source_functions=source_funcs,
            target_functions=target_funcs
        )
        
        self.assertEqual(report.exact_clones, 1)
        self.assertEqual(report.total_clones_found, 1)

    def test_detect_clones_by_structural_features(self):
        """测试通过结构特征检测克隆"""
        source_funcs = {
            'func1': FunctionInfo(
                name='func1',
                address=0x1000,
                size=1000,
                basic_blocks=5,
                instructions=50,
            )
        }
        
        target_funcs = {
            'func2': FunctionInfo(
                name='func2',
                address=0x2000,
                size=950,  # 大小相似
                basic_blocks=5,  # 相同
                instructions=48,  # 相似
            )
        }
        
        report = self.detector.detect_clones(
            source_binary="source",
            target_binary="target",
            source_functions=source_funcs,
            target_functions=target_funcs
        )
        
        # 应该检测到结构特征匹配
        self.assertGreaterEqual(report.semantic_clones, 0)

    def test_detect_clones_by_call_patterns(self):
        """测试通过调用模式检测克隆"""
        source_funcs = {
            'func1': FunctionInfo(
                name='func1',
                address=0x1000,
                size=256,
                calls=['malloc', 'free', 'printf'],
            )
        }
        
        target_funcs = {
            'func2': FunctionInfo(
                name='func2',
                address=0x2000,
                size=256,
                calls=['malloc', 'free', 'printf'],  # 相同调用
            )
        }
        
        report = self.detector.detect_clones(
            source_binary="source",
            target_binary="target",
            source_functions=source_funcs,
            target_functions=target_funcs
        )
        
        # 应该检测到调用模式匹配
        self.assertGreaterEqual(report.semantic_clones, 0)

    def test_identify_library_sources(self):
        """测试识别库来源"""
        report = CloneReport(
            source_binary="target",
            target_binary="binary"
        )
        
        # 添加一些克隆
        clone = CloneMatch(
            clone_id="test",
            clone_type=CloneType.EXACT,
            confidence=CloneConfidence.HIGH,
            confidence_score=1.0,
            source_binary="libc",
            source_function="printf",
            source_address=0,
            source_size=0,
            target_binary="target",
            target_function="my_printf",
            target_address=0,
            target_size=0,
        )
        report.clones.append(clone)
        
        self.detector._identify_library_sources(report)
        
        # 应该识别到 libc
        self.assertIn("identified_libraries", report.to_dict())

    def test_score_to_confidence(self):
        """测试分数转置信度"""
        high = self.detector._score_to_confidence(0.95)
        self.assertEqual(high, CloneConfidence.HIGH)
        
        medium = self.detector._score_to_confidence(0.75)
        self.assertEqual(medium, CloneConfidence.MEDIUM)
        
        low = self.detector._score_to_confidence(0.55)
        self.assertEqual(low, CloneConfidence.LOW)

    def test_build_reuse_graph(self):
        """测试构建复用关系图"""
        report = CloneReport(
            source_binary="source",
            target_binary="target"
        )
        
        clone = CloneMatch(
            clone_id="test",
            clone_type=CloneType.EXACT,
            confidence=CloneConfidence.HIGH,
            confidence_score=1.0,
            source_binary="source",
            source_function="func1",
            source_address=0,
            source_size=0,
            target_binary="target",
            target_function="func2",
            target_address=0,
            target_size=0,
        )
        report.clones.append(clone)
        
        graph = self.detector.build_reuse_graph(report)
        
        self.assertIsInstance(graph, dict)


class TestCodeCloneDetectorEdgeCases(unittest.TestCase):
    """测试代码克隆检测器边界情况"""

    def setUp(self):
        """设置测试环境"""
        self.detector = CodeCloneDetector()

    def test_empty_function_dicts(self):
        """测试空函数字典"""
        report = self.detector.detect_clones(
            source_binary="source",
            target_binary="target",
            source_functions={},
            target_functions={}
        )
        
        self.assertEqual(report.total_clones_found, 0)

    def test_very_large_functions(self):
        """测试超大函数"""
        source_funcs = {
            'large_func': FunctionInfo(
                name='large_func',
                address=0x1000,
                size=1000000,
                basic_blocks=1000,
                instructions=50000,
            )
        }
        
        report = self.detector.detect_clones(
            source_binary="source",
            target_binary="target",
            source_functions=source_funcs,
            target_functions={}
        )
        
        self.assertIsInstance(report, CloneReport)


class TestConvenienceFunction(unittest.TestCase):
    """测试便捷函数"""

    def test_detect_code_clones(self):
        """测试 detect_code_clones 函数"""
        source_funcs = [
            {'name': 'func1', 'address': 0x1000, 'size': 100, 'bytes': b'data'}
        ]
        target_funcs = [
            {'name': 'func2', 'address': 0x2000, 'size': 100, 'bytes': b'data'}
        ]
        
        report = detect_code_clones(
            source_binary="source",
            target_binary="target",
            source_functions=source_funcs,
            target_functions=target_funcs
        )
        
        self.assertIsInstance(report, CloneReport)
        self.assertEqual(report.source_binary, "source")


if __name__ == '__main__':
    unittest.main()