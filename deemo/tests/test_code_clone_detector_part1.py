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
        func = FunctionInfo(name="test", address=0)
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


