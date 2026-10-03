
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
        """测试字符串转换"""

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




class TestPatchDiffLocator(unittest.TestCase):
    """测试补丁差异定位器"""

    def setUp(self):
        """设置测试环境"""
        self.locator = PatchDiffLocator()
        self.m_tmp = tempfile.mkdtemp()

    def tearDown(self):
        """清理测试环境"""
        import shutil
        if os.path.exists(self.m_tmp):
            shutil.rmtree(self.m_tmp)

    def test_detect_security_patch_boundary_check(self):
        original = 'char buf[10]; strcpy(buf, input);'
        patched = 'char buf[10]; if(strlen(input) < 10) strcpy(buf, input);'

        is_security, vuln_type = self.locator._detect_security_patch(
            original, patched
        )
        self.assertTrue(is_security)
        self.assertEqual(vuln_type, 'buffer_overflow')

    def test_detect_security_patch_input_validation(self):
        """测试检测输入验证安全补丁"""
        original = 'process(user_input);'
        patched = 'if(validate_input(user_input)) process(user_input);'

        is_security, vuln_type = self.locator._detect_security_patch(
            original, patched
        )
        self.assertTrue(is_security)

    def test_detect_security_patch_null_check(self):
        original = 'ptr->value = x;'
        patched = 'if(ptr != NULL) ptr->value = x;'

        is_security, vuln_type = self.locator._detect_security_patch(
            original, patched
        )
        self.assertTrue(is_security)
        self.assertEqual(vuln_type, 'null_pointer_dereference')

    def test_extract_diff_changes(self):
        """测试提取差异变更"""
        original_lines = ['line1', 'line2', 'line3']
        patched_lines = ['line1', 'line2_modified', 'line3', 'line4']

        changes = self.locator._extract_diff_changes(original_lines, patched_lines)

        self.assertIsInstance(changes, list)
        self.assertTrue(len(changes) > 0)

    def test_match_functions(self):
        """测试函数匹配"""
        original_funcs = [
            {'name': 'main', 'address': 0x1000},
            {'name': 'helper', 'address': 0x1100},
        ]
        patched_funcs = [
            {'name': 'main', 'address': 0x1000},
            {'name': 'helper', 'address': 0x1100},
            {'name': 'new_func', 'address': 0x1200},
        ]

        matches = self.locator._match_functions(original_funcs, patched_funcs)

        self.assertEqual(len(matches), 2)
        self.assertTrue(any(m['name'] == 'main' for m in matches))

    def test_analyze_nonexistent_files(self):
        """测试分析不存在文件"""
        result = self.locator.analyze('/nonexistent/original', '/nonexistent/patched')
        self.assertIsNotNone(result.error)

    def test_generate_diff_report(self):
        """测试生成差异报告"""
        diff = FunctionDiff(
            function_name='vulnerable_func',
            original_address=0x1000,
            patched_address=0x1000,
            diff_type=DiffType.PSEUDO_CODE,
            original_code='memcpy(dest, src, size);',
            patched_code='if(size < MAX_SIZE) memcpy(dest, src, size);',
            changes=['Added size check before memcpy'],
            is_security_patch=True,
            vulnerability_type='buffer_overflow'
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

        report = self.locator._generate_diff_report(result)

        self.assertIn('vulnerable_func', report)
        self.assertIn('buffer_overflow', report)

    def test_identify_vulnerability_type(self):
        """测试识别漏洞类型"""
        # 测试边界检查 -> buffer_overflow
        changes = ['Added length check', 'Added boundary check']
        vuln_type = self.locator._identify_vulnerability_type(changes)
        self.assertEqual(vuln_type, 'buffer_overflow')

        # 测试空指针检查 -> null_pointer_dereference
        changes = ['Added NULL pointer check']
        vuln_type = self.locator._identify_vulnerability_type(changes)
        self.assertEqual(vuln_type, 'null_pointer_dereference')


class TestSecurityPatchPatterns(unittest.TestCase):
    """测试安全补丁模式"""

    def test_patterns_exist(self):
        """测试安全补丁模式存在"""
        self.assertIn('boundary_check', SECURITY_PATCH_PATTERNS)
        self.assertIn('input_validation', SECURITY_PATCH_PATTERNS)

        self.assertIn('memory_safety', SECURITY_PATCH_PATTERNS)

    def test_pattern_keywords(self):
        boundary_pattern = SECURITY_PATCH_PATTERNS['boundary_check']
        self.assertIn('keywords', boundary_pattern)
        self.assertTrue(len(boundary_pattern['keywords']) > 0)


class TestVulnerabilityTypeMap(unittest.TestCase):
    """测试漏洞类型映射"""

    def test_map_exist(self):
        """测试漏洞类型映射存在"""
        self.assertIn('boundary_check', VULNERABILITY_TYPE_MAP)
        self.assertIn('null_check', VULNERABILITY_TYPE_MAP)

    def test_map_values(self):
        self.assertEqual(VULNERABILITY_TYPE_MAP['boundary_check'], 'buffer_overflow')
        self.assertEqual(VULNERABILITY_TYPE_MAP['null_check'], 'null_pointer_dereference')


class TestConvenienceFunction(unittest.TestCase):
    """测试便捷函数"""

    def test_locate_patch_diff_function(self):
        """测试locate_patch_diff便捷函数"""
        temp_dir = tempfile.mkdtemp()
        original = os.path.join(temp_dir, 'original')
        patched = os.path.join(temp_dir, 'patched')

        with open(original, 'wb') as f:
            f.write(b'test')
        with open(patched, 'wb') as f:
            f.write(b'test')

        result = locate_patch_diff(original, patched)
        self.assertIsInstance(result, dict)

        import shutil
        shutil.rmtree(temp_dir)


class TestInputValidation(unittest.TestCase):
    """测试输入校验"""

    def test_path_traversal_prevention(self):
        """测试路径遍历防护"""
        locator = PatchDiffLocator()

        result = locator.analyze('../../../etc/passwd', '/tmp/patched')
        self.assertIsNotNone(result.error)

    def test_same_file_analysis(self):
        """测试分析相同文件"""
        locator = PatchDiffLocator()

        temp_dir = tempfile.mkdtemp()
        test_file = os.path.join(temp_dir, 'test')
        with open(test_file, 'wb') as f:
            f.write(b'test')

        # 分析相同文件应该返回无差异
        result = locator.analyze(test_file, test_file)
        self.assertIsNotNone(result)

        import shutil
        shutil.rmtree(temp_dir)


class TestRiskAssessment(unittest.TestCase):
    """测试风险评估"""

    def test_high_risk_patches(self):
        locator = PatchDiffLocator()

        diffs = [
            FunctionDiff(
                function_name='critical', original_address=0x1000,
                patched_address=0x1000, diff_type=DiffType.ASSEMBLY,
                original_code='', patched_code='', changes=[],
                is_security_patch=True, vulnerability_type='use_after_free'
            )
        ]

        risk = locator._assess_overall_risk(diffs)
        self.assertEqual(risk, 'high')

    def test_low_risk_patches(self):
        locator = PatchDiffLocator()

        diffs = [
            FunctionDiff(
                function_name='minor', original_address=0x1000,
                patched_address=0x1000, diff_type=DiffType.ASSEMBLY,
                original_code='', patched_code='', changes=['Refactored code'],
                is_security_patch=False, vulnerability_type=None
            )
        ]

        risk = locator._assess_overall_risk(diffs)
        self.assertEqual(risk, 'low')



if __name__ == '__main__':
    unittest.main()


