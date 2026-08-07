
"""
内核模块分析单元测试

测试功能:
1. 二进制格式检测 - Linux内核模块(.ko)和Windows驱动(.sys)
2. 内核危险函数识别
3. 内核信息收集函数
4. --kernel命令行参数解析
5. 内核利用策略生成
"""

import unittest
import sys
import os
import tempfile
import argparse
from unittest.mock import Mock, MagicMock, patch, call

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)


class TestKernelBinaryFormatDetection(unittest.TestCase):
    """
    测试二进制格式检测功能
    """

    def setUp(self):
        """
        测试前初始化
        """
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """
        测试后清理
        """
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_detect_ko_file_by_extension(self):
        """
        测试通过扩展名检测Linux内核模块(.ko)
        """
        from modules.info.info_collect import detect_binary_format

        ko_path = os.path.join(self.temp_dir, 'test_module.ko')
        with open(ko_path, 'wb') as f:
            f.write(b'\x7fELF' + b'\x00' * 100)

        result = detect_binary_format(ko_path)
        self.assertEqual(result, 'KO')

    def test_detect_sys_file_by_extension(self):
        """
        测试通过扩展名检测Windows驱动(.sys)
        """
        from modules.info.info_collect import detect_binary_format

        sys_path = os.path.join(self.temp_dir, 'test_driver.sys')
        with open(sys_path, 'wb') as f:
            f.write(b'MZ' + b'\x00' * 100)

        result = detect_binary_format(sys_path)
        self.assertEqual(result, 'SYS')


class TestKernelDangerousFunctions(unittest.TestCase):
    """
    测试内核危险函数识别功能
    """

    def test_kernel_dangerous_functions_defined(self):
        """
        测试内核危险函数列表是否已定义
        """
        from modules.info.info_collect import KERNEL_DANGEROUS_FUNCTIONS, KERNEL_DRIVER_DANGEROUS_FUNCTIONS

        self.assertIsInstance(KERNEL_DANGEROUS_FUNCTIONS, list)
        self.assertIsInstance(KERNEL_DRIVER_DANGEROUS_FUNCTIONS, list)

    def test_kernel_dangerous_functions_contains_key_functions(self):

        """
        测试关键内核危险函数是否在列表中
        """
        from modules.info.info_collect import KERNEL_DANGEROUS_FUNCTIONS, KERNEL_DRIVER_DANGEROUS_FUNCTIONS

        key_linux_functions = [
            'copy_from_user',
            'copy_to_user',
            'kmalloc',
            'kzalloc',
            'kfree',
            'ioremap',
            'request_mem_region',
            'sprintf'
        ]

        for func in key_linux_functions:
            self.assertIn(func, KERNEL_DANGEROUS_FUNCTIONS)

        key_windows_functions = [
            'MmCopyVirtualMemory',
            'ExAllocatePool',
            'ExAllocatePoolWithTag',
            'IoCreateDevice',
            'IoCreateSymbolicLink'
        ]

        for func in key_windows_functions:
            self.assertIn(func, KERNEL_DRIVER_DANGEROUS_FUNCTIONS)


class TestKernelPrompts(unittest.TestCase):
    """
    测试内核漏洞分析提示模板
    """

    def test_kernel_vuln_analysis_template_exists(self):
        """
        测试内核漏洞分析模板是否存在
        """
        from prompts import KERNEL_VULN_ANALYSIS_TEMPLATE

        self.assertIsInstance(KERNEL_VULN_ANALYSIS_TEMPLATE, str)
        self.assertGreater(len(KERNEL_VULN_ANALYSIS_TEMPLATE), 0)

    def test_kernel_vuln_analysis_template_contains_keywords(self):
        from prompts import KERNEL_VULN_ANALYSIS_TEMPLATE

        keywords = [
            'copy_from_user',
            'copy_to_user',
            '空指针解引用',
            '竞争条件',
            '整数溢出',
            'IOCTL',
            '权限提升',
            '信息泄漏'
        ]

        for keyword in keywords:
            self.assertIn(keyword, KERNEL_VULN_ANALYSIS_TEMPLATE)

    def test_kernel_exploit_strategy_template_exists(self):
        """
        测试内核利用策略模板是否存在
        """
        from prompts import KERNEL_EXPLOIT_STRATEGY_TEMPLATE

        self.assertIsInstance(KERNEL_EXPLOIT_STRATEGY_TEMPLATE, str)
        self.assertGreater(len(KERNEL_EXPLOIT_STRATEGY_TEMPLATE), 0)

    def test_kernel_exploit_strategy_template_contains_disclaimer(self):
        """
        测试内核利用策略模板是否包含免责声明
        """
        from prompts import KERNEL_EXPLOIT_STRATEGY_TEMPLATE

        self.assertIn('不生成可执行的利用脚本', KERNEL_EXPLOIT_STRATEGY_TEMPLATE)
        self.assertIn('理论分析', KERNEL_EXPLOIT_STRATEGY_TEMPLATE)


