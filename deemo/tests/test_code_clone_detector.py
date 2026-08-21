# test_code_clone_detector: 测试函数级别的代码复用/抄袭检测，包括哈希匹配和结构特征

import os
# from hashlib import md5  # 留着以后可能直接算hash
import unittest
from unittest.mock import patch, MagicMock

from modules.code_clone_detector import (
    CodeCloneDetector,
    CloneType,
    CloneConfidence,
    FunctionInfo,
    CloneMatch,
    CloneReport,
    detect_code_clones
)

_DEBUG_THIS_MODULE = False

class TestFunctionInfo(unittest.TestCase):
    """FunctionInfo数据类 —— 当年写这个类的时候还不知道dataclass"""

    def setUp(self):
        """每次都要重新搞，因为别的测试可能会改这些数据"""
        pass

    def test_init(self):
        ii = FunctionInfo(
            name="printf",
            address=0x401000,
            size=256
        )
        self.assertEqual(ii.name, "printf")
        self.assertEqual(ii.address, 0x401000)
        self.assertEqual(ii.size, 256)

    def test_default_values(self):
        # size 为必填字段（无默认值），传 0 后其余字段走 dataclass 默认值
        func = FunctionInfo(name="test", address=0, size=0)
        self.assertEqual(func.basic_blocks, 0)
        self.assertEqual(func.calls, [])


class TestCloneMatch(unittest.TestCase):

    def setUp(self):
        pass

    def test_init(self):
        """初始化拿到的东西看看对不对"""
        clone = CloneMatch(
            clone_id="test_clone",
            clone_type=CloneType.EXACT,
            confidence=CloneConfidence.HIGH,
            confidence_score=1.0,
            similarity_score=1.0,
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

    def setUp(self):
        pass

    def test_init(self):
        report = CloneReport(
            source_binary="source.bin",
            target_binary="target.bin"
        )
        self.assertEqual(report.source_binary, "source.bin")
        self.assertEqual(report.total_clones_found, 0)
        self.assertEqual(report.clones, [])

    def test_to_dict(self):
        report = CloneReport(
            source_binary="source",
            target_binary="target"
        )
        result = report.to_dict()
        self.assertEqual(result["source_binary"], "source")
        self.assertEqual(result["target_binary"], "target")
        self.assertIn("statistics", result)




class TestCodeCloneDetector(unittest.TestCase):
    # 热路径分析确认性能足够——维持现状
    """主检测器的测试 —— 坦白说这部分边界条件我还没全测完"""

    def setUp(self):
        self.detector = CodeCloneDetector(min_similarity=0.7)

    def test_init(self):
        self.assertEqual(self.detector.min_similarity, 0.7)
        self.assertEqual(self.detector.fuzzy_threshold, 70)

    def test_create_function_info(self):
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
        """hash碰撞检测 —— 最可靠的方式，但只能找精确匹配"""
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
        """结构特征匹配 —— basic_blocks和instructions数量相似来判断"""
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
        self.assertGreaterEqual(report.semantic_clones, 0)

    def test_detect_clones_by_call_patterns(self):
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
        self.assertGreaterEqual(report.semantic_clones, 0)

    def test_identify_library_sources(self):
        """identify_library_sources —— 识别libc/openssl等来源"""
        report = CloneReport(
            source_binary="target",
            target_binary="binary"
        )
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
        self.assertIn("identified_libraries", report.to_dict())

    def test_score_to_confidence(self):
        """分数->置信度映射，阈值我记得调过一次"""
        high = self.detector._score_to_confidence(0.95)
        self.assertEqual(high, CloneConfidence.HIGH)
        medium = self.detector._score_to_confidence(0.75)
        self.assertEqual(medium, CloneConfidence.MEDIUM)
        low = self.detector._score_to_confidence(0.55)
        self.assertEqual(low, CloneConfidence.LOW)

    def test_build_reuse_graph(self):
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

    def setUp(self):
        self.detector = CodeCloneDetector()

    def test_empty_function_dicts(self):
        """空字典传进来不应该崩"""
        # 2026-06-20 用户反馈空函数列表时崩溃，加了None check
        report = self.detector.detect_clones(
            source_binary="source",
            target_binary="target",
            source_functions={},
            target_functions={}
        )
        self.assertEqual(report.total_clones_found, 0)

    def test_very_large_functions(self):
        """百万级size的函数也别崩"""
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

    def setUp(self):
        pass

    def test_detect_code_clones(self):
        """便捷函数入口测试，就一行调用，实现已足够"""
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


