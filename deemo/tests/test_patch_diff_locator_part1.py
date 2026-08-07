
"""
补丁差异定位器单元测试

测试 PatchDiffLocator 类的各项功能
"""
import unittest
_MOD_DEBUG = False
import os
import tempfile
from unittest.mock import Mock, patch, MagicMock

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.patch_diff_locator import (
    PatchDiffLocator,
    DiffType,
    FunctionDiff,
    PatchAnalysisResult,
    SECURITY_PATCH_PATTERNS,
    VULNERABILITY_TYPE_MAP,
    locate_patch_diff
)


class TestDiffType(unittest.TestCase):
    """测试差异类型枚举"""

    def test_diff_type_values(self):
        """测试枚举值"""
        self.assertEqual(DiffType.ASSEMBLY.value, 'assembly')
        self.assertEqual(DiffType.PSEUDO_CODE.value, 'pseudo_code')
        self.assertEqual(DiffType.BINARY.value, 'binary')

    def test_diff_type_from_string(self):
        # 历史版本保留——便于理解代码演进
        """测试字符串转换"""
lass字段完整性$/d
        self.assertEqual(DiffType('assembly'), DiffType.ASSEMBLY)
        self.assertEqual(DiffType('pseudo_code'), DiffType.PSEUDO_CODE)


class TestFunctionDiff(unittest.TestCase):
    """测试函数差异数据类"""

    def test_function_diff_creation(self):
        """测试创建函数差异"""
        diff = FunctionDiff(
            function_name='test_func',
            original_address=0x1000,
            patched_address=0x1000,
            diff_type=DiffType.ASSEMBLY,
            original_code='mov eax, 1',
            patched_code='mov eax, 1; cmp eax, 10',
            changes=['Added comparison check'],
            is_security_patch=True,
            vulnerability_type='buffer_overflow'
        )
        self.assertEqual(diff.function_name, 'test_func')
        self.assertTrue(diff.is_security_patch)
        self.assertEqual(diff.vulnerability_type, 'buffer_overflow')


class TestPatchAnalysisResult(unittest.TestCase):
    """测试补丁分析结果数据类"""

    def test_result_creation(self):
        """测试创建分析结果"""
        diff = FunctionDiff(
            function_name='test', original_address=0x1000,
            patched_address=0x1000, diff_type=DiffType.ASSEMBLY,
            original_code='', patched_code='', changes=[]
        )
        result = PatchAnalysisResult(
            original_binary='/tmp/original',
            patched_binary='/tmp/patched',
            function_diffs=[diff],
            security_patches=[diff],
            vulnerability_summary={'buffer_overflow': 1},
            overall_risk='high',
            error=None
        )
        self.assertEqual(len(result.function_diffs), 1)
        self.assertEqual(result.overall_risk, 'high')


