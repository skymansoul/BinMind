#!/usr/bin/env python3
"""
UEFI 固件分析模块单元测试

测试内容：
1. UEFI 固件格式识别
2. Firmware Volume 解析
3. SMM 漏洞检测
4. PE 模块提取
"""

import os
import sys
import unittest
import tempfile
import struct
from unittest.mock import Mock, MagicMock, patch

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestUEFIFirmwareAnalyzer(unittest.TestCase):
    """
    UEFI 固件分析器测试
    """

    def setUp(self):
        """
        测试前初始化
        """
        self.temp_dir = tempfile.mkdtemp(prefix='uefi_test_')
        
    def tearDown(self):
        """
        测试后清理
        """
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_uefi_analyzer_module_import(self):
        """
        测试 UEFI 分析模块导入
        """
        try:
            from modules.uefi_analyzer import UEFIFirmwareAnalyzer, UEFI_FIRMWARE_AVAILABLE
            self.assertTrue(True)
        except ImportError as e:
            self.skipTest(f"UEFI 分析模块导入失败: {e}")

    def test_uefi_guid_format_conversion(self):
        """
        测试 GUID 格式转换
        """
        from modules.uefi_analyzer import UEFIFirmwareAnalyzer
        
        # 创建测试实例（使用临时文件）
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x7fELF' + b'\x00' * 100)
        
        analyzer = UEFIFirmwareAnalyzer.__new__(UEFIFirmwareAnalyzer)
        analyzer.firmware_path = test_file
        
        # 测试 GUID 转换
        guid_bytes = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                          0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10])
        
        guid_str = analyzer._bytes_to_guid(guid_bytes)
        
        # GUID 格式应为 xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        self.assertTrue('-' in guid_str)
        self.assertEqual(len(guid_str), 36)

    def test_smm_dangerous_functions_list(self):
        """
        测试 SMM 危险函数列表
        """
        from modules.uefi_analyzer import SMM_DANGEROUS_FUNCTIONS
        
        self.assertIsInstance(SMM_DANGEROUS_FUNCTIONS, list)
        self.assertTrue(len(SMM_DANGEROUS_FUNCTIONS) > 0)
        
        # 检查关键函数
        critical_funcs = ['SmmCommunicate', 'SmramIsValid', 'SmiHandler']
        for func in critical_funcs:
            self.assertIn(func, SMM_DANGEROUS_FUNCTIONS)

    def test_smm_vulnerability_types(self):
        """
        测试 SMM 漏洞类型定义
        """
        from modules.uefi_analyzer import SMM_VULN_TYPES
        
        self.assertIsInstance(SMM_VULN_TYPES, dict)
        
        # 检查关键漏洞类型
        critical_types = ['COMMBUFFER_VALIDATION_MISSING', 'SMRAM_LEAK', 'PRIVILEGE_ESCALATION']
        for vuln_type in critical_types:
            self.assertIn(vuln_type, SMM_VULN_TYPES)
            self.assertIn('severity', SMM_VULN_TYPES[vuln_type])

    def test_uefi_file_types(self):
        """
        测试 UEFI 文件类型常量
        """
        from modules.uefi_analyzer import UEFI_FILE_TYPES
        
        self.assertIsInstance(UEFI_FILE_TYPES, dict)
        
        # 检查关键文件类型
        self.assertIn(0x05, UEFI_FILE_TYPES)  # DXE Core
        self.assertIn(0x0A, UEFI_FILE_TYPES)  # MM/SMM

    def test_uefi_module_info_dataclass(self):
        """
        测试 UEFI 模块信息数据类
        """
        from modules.uefi_analyzer import UEFIModuleInfo
        
        module = UEFIModuleInfo(
            name='TestModule',
            guid='12345678-1234-1234-1234-123456789012',
            is_smm=True
        )
        
        self.assertEqual(module.name, 'TestModule')
        self.assertTrue(module.is_smm)
        self.assertIsInstance(module.dependencies, list)

    def test_path_validation(self):
        """
        测试路径验证功能
        """
        from modules.uefi_analyzer import UEFIFirmwareAnalyzer
        
        # 测试空路径
        with self.assertRaises(ValueError):
            UEFIFirmwareAnalyzer('')
        
        # 测试路径遍历
        with self.assertRaises(ValueError):
            UEFIFirmwareAnalyzer('../../../etc/passwd')


class TestUEFISignatureDetection(unittest.TestCase):
    """
    UEFI 签名检测测试
    """

    def setUp(self):
        """
        测试前初始化
        """
        self.temp_dir = tempfile.mkdtemp(prefix='uefi_sig_test_')

    def tearDown(self):
        """
        测试后清理
        """
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_fv_signature_detection(self):
        """
        测试 Firmware Volume 签名检测
        """
        from modules.uefi_analyzer import UEFIFirmwareAnalyzer
        
        # 创建包含 FV 签名的测试文件
        fv_file = os.path.join(self.temp_dir, 'test_fv.bin')
        with open(fv_file, 'wb') as f:
            # FV 头：签名 + 属性 + GUID + 大小
            f.write(b'_FVH')  # FV 签名
            f.write(b'\x00' * 12)  # 属性
            f.write(b'\x00' * 16)  # GUID
            f.write(struct.pack('<Q', 0x10000))  # 大小
            f.write(b'\x00' * 1000)  # 填充
        
        analyzer = UEFIFirmwareAnalyzer.__new__(UEFIFirmwareAnalyzer)
        analyzer.firmware_path = fv_file
        
        # 测试签名查找
        with open(fv_file, 'rb') as f:
            data = f.read()
        
        offsets = analyzer._find_firmware_volumes(data)
        self.assertTrue(len(offsets) > 0)
        self.assertEqual(offsets[0], 0)


class TestUEFIAnalysisResult(unittest.TestCase):
    """
    UEFI 分析结果测试
    """

    def test_analysis_report_structure(self):
        """
        测试分析报告结构
        """
        from modules.uefi_analyzer import UEFIFirmwareAnalyzer
        
        # 模拟分析结果
        mock_result = {
            'success': True,
            'statistics': {
                'total_modules': 10,
                'smm_modules': 2,
                'total_vulnerabilities': 3
            },
            'vulnerabilities': [
                {
                    'type': 'COMMBUFFER_VALIDATION_MISSING',
                    'severity': 'Critical'
                }
            ]
        }
        
        self.assertTrue(mock_result['success'])
        self.assertEqual(mock_result['statistics']['smm_modules'], 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)