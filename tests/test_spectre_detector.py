
"""
Spectre Gadget 检测模块单元测试

测试内容：
1. Spectre V1/V2/V4/Meltdown 模式检测
2. 架构支持
3. 风险评估
4. 缓解措施识别
"""

import os
import sys
import unittest
import tempfile
from unittest.mock import Mock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestSpectreGadgetDetector(unittest.TestCase):
    """
    Spectre Gadget 检测器测试
    """

    def setUp(self):
        """
        测试前初始化
        """
        self.m_tmp = tempfile.mkdtemp(prefix='spectre_test_')

        # 创建测试二进制文件
        self.m_test_bin = os.path.join(self.m_tmp, 'test.bin')
        with open(self.m_test_bin, 'wb') as f:
            f.write(b'\x7fELF' + b'\x00' * 100)

    def tearDown(self):
        """
        测试后清理
        """
        import shutil
        if os.path.exists(self.m_tmp):
            shutil.rmtree(self.m_tmp)

    def test_spectre_detector_module_import(self):
        """
        测试 Spectre 检测模块导入
        """
        try:
            from modules.spectre_detector import SpectreGadgetDetector, CAPSTONE_AVAILABLE
            self.assertTrue(True)
        except ImportError as e:
            self.skipTest(f"Spectre 检测模块导入失败: {e}")

    def test_spectre_type_enum(self):
        """
        测试 Spectre 类型枚举
        """
        from modules.spectre_detector import SpectreType

        self.assertEqual(SpectreType.SPECTRE_V1.value, 'Spectre V1 (Bounds Check Bypass)')
        self.assertEqual(SpectreType.SPECTRE_V2.value, 'Spectre V2 (Branch Target Injection)')
        self.assertEqual(SpectreType.MELTDOWN.value, 'Meltdown (Kernel Data Leakage)')

    def test_risk_level_enum(self):
        from modules.spectre_detector import RiskLevel

        self.assertEqual(RiskLevel.CRITICAL.value, 'Critical')
        self.assertEqual(RiskLevel.HIGH.value, 'High')
        self.assertEqual(RiskLevel.MEDIUM.value, 'Medium')
        self.assertEqual(RiskLevel.LOW.value, 'Low')

    def test_spectre_v1_patterns(self):

        """
        测试 Spectre V1 模式定义
        """
        from modules.spectre_detector import SPECTRE_V1_PATTERNS

        self.assertIsInstance(SPECTRE_V1_PATTERNS, dict)
        self.assertIn('x86', SPECTRE_V1_PATTERNS)
        self.assertIn('arm', SPECTRE_V1_PATTERNS)

        # 检查 x86 模式
        x86_patterns = SPECTRE_V1_PATTERNS['x86']
        self.assertTrue(len(x86_patterns) > 0)

    def test_spectre_v2_patterns(self):
        """
        测试 Spectre V2 模式定义
        """
        from modules.spectre_detector import SPECTRE_V2_PATTERNS

        self.assertIsInstance(SPECTRE_V2_PATTERNS, dict)
        self.assertIn('x86', SPECTRE_V2_PATTERNS)

        # 检查间接跳转模式
        x86_patterns = SPECTRE_V2_PATTERNS['x86']
        indirect_patterns = [p for p in x86_patterns if 'call' in p['pattern'] or 'jmp' in p['pattern']]
        self.assertTrue(len(indirect_patterns) > 0)

    def test_meltdown_patterns(self):
        """
        测试 Meltdown 模式定义
        """
        from modules.spectre_detector import MELTDOWN_PATTERNS

        self.assertIsInstance(MELTDOWN_PATTERNS, dict)
        self.assertIn('x86', MELTDOWN_PATTERNS)

        # 检查内核地址访问模式
        x86_patterns = MELTDOWN_PATTERNS['x86']
        kernel_patterns = [p for p in x86_patterns if '0xffff' in p['pattern'] or 'kernel' in p['pattern']]
        self.assertTrue(len(kernel_patterns) > 0)

    def test_cache_side_channel_patterns(self):
        """
        测试缓存侧信道模式
        """
        from modules.spectre_detector import CACHE_SIDE_CHANNEL_PATTERNS

        self.assertIsInstance(CACHE_SIDE_CHANNEL_PATTERNS, list)

        # 检查关键指令
        critical_patterns = ['clflush', 'rdtsc']
        for pattern in critical_patterns:
            found = any(p['pattern'] == pattern for p in CACHE_SIDE_CHANNEL_PATTERNS)
            self.assertTrue(found)

    def test_mitigation_patterns(self):
        """
        测试缓解措施模式
        """
        from modules.spectre_detector import MITIGATION_PATTERNS

        self.assertIsInstance(MITIGATION_PATTERNS, list)

        # 检查关键缓解
        mitigations = ['lfence', 'retpoline', 'endbr64']
        for mitigation in mitigations:
            found = any(mitigation in p['pattern'] for p in MITIGATION_PATTERNS)
            self.assertTrue(found)

    def test_spectre_gadget_dataclass(self):
        """
        测试 Spectre Gadget 数据类
        """
        from modules.spectre_detector import SpectreGadget, SpectreType, RiskLevel

        gadget = SpectreGadget(
            gadget_id='SV1_001',
            spectre_type=SpectreType.SPECTRE_V1,
            risk_level=RiskLevel.HIGH,
            location='main+0x50',
            description='边界检查绕过'
        )

        self.assertEqual(gadget.gadget_id, 'SV1_001')
        self.assertEqual(gadget.spectre_type, SpectreType.SPECTRE_V1)
        self.assertIsInstance(gadget.recommendations, list)

    def test_detector_initialization(self):
        from modules.spectre_detector import SpectreGadgetDetector

        detector = SpectreGadgetDetector(
            binary_path=self.m_test_bin,
            architecture='x86'
        )

        self.assertEqual(detector.architecture, 'x86')
        self.assertEqual(detector.binary_path, self.m_test_bin)

    def test_path_validation(self):
        from modules.spectre_detector import SpectreGadgetDetector

        # 测试空路径
        with self.assertRaises(ValueError):
            SpectreGadgetDetector('')

        # 测试路径遍历
        with self.assertRaises(ValueError):
            SpectreGadgetDetector('../../../etc/passwd')

    def test_pattern_matching(self):
        """
        测试模式匹配功能
        """
        from modules.spectre_detector import SpectreGadgetDetector

        detector = SpectreGadgetDetector.__new__(SpectreGadgetDetector)
        detector.binary_path = self.m_test_bin
        detector.disassembly = [
            '0x1000: cmp eax, ebx',
            '0x1002: jl 0x1010',
            '0x1004: mov eax, [ecx+eax*4]'
        ]

        # 测试边界检查模式
        matches = detector._find_pattern_in_disassembly('cmp.*jl.*mov')
        self.assertTrue(len(matches) > 0)


class TestSpectreAnalysisResult(unittest.TestCase):
    """
    Spectre 分析结果测试
    """

    def test_analysis_result_dataclass(self):
        """
        测试分析结果数据类
        """
        from modules.spectre_detector import SpectreAnalysisResult, RiskLevel

        result = SpectreAnalysisResult(
            binary_path='/test/binary',
            architecture='x86',
            total_gadgets=10,
            critical_gadgets=2,
            high_gadgets=3
        )

        self.assertEqual(result.binary_path, '/test/binary')
        self.assertEqual(result.total_gadgets, 10)
        self.assertIsInstance(result.gadgets, list)
        self.assertIsInstance(result.mitigations_found, list)



if __name__ == '__main__':
    unittest.main(verbosity=2)


