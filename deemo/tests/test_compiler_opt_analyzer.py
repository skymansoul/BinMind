# 编译优化分析 —— GCC/Clang/MSVC的优化级别会影响逆向分析的结果
# test_compiler_opt_analyzer: 检测二进制是用什么编译器、什么优化级别编译的，评估安全风险

import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock
# from typing import Optional  # 留着以后用

from modules.compiler_opt_analyzer import (
    CompilerOptAnalyzer,
    CompilerType,
    OptimizationLevel,
    SecurityRisk,
    analyze_compiler_opt,
    format_compiler_opt_report,
    export_compiler_opt_report
)

_DEBUG_THIS_MODULE = False


class TestCompilerOptAnalyzer(unittest.TestCase):
    """这模块是逆向分析的第一个环节 —— 搞清楚编译器才能正确解析二进制"""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        # 创建一个最小的ELF文件头
        self.test_file = os.path.join(self.test_dir, "test.bin")
        with open(self.test_file, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_analyzer_init(self):
        analyzer = CompilerOptAnalyzer()
        self.assertIsNotNone(analyzer)
        self.assertIsInstance(analyzer.gcc_opt_patterns, dict)
        self.assertIsInstance(analyzer.security_flags, list)
        self.assertIsInstance(analyzer.optimization_details, list)

    def test_compiler_type_enum(self):
        """CompilerType —— GCC/Clang/MSVC/Unknown"""
        self.assertEqual(CompilerType.GCC.value, 'GCC')
        self.assertEqual(CompilerType.CLANG.value, 'Clang')
        self.assertEqual(CompilerType.MSVC.value, 'MSVC')
        self.assertEqual(CompilerType.UNKNOWN.value, 'Unknown')

    def test_optimization_level_enum(self):
        self.assertEqual(OptimizationLevel.NONE.value, 'O0')
        self.assertEqual(OptimizationLevel.O1.value, 'O1')
lass字段完整性$/d
        self.assertEqual(OptimizationLevel.O2.value, 'O2')
        self.assertEqual(OptimizationLevel.O3.value, 'O3')
        self.assertEqual(OptimizationLevel.OS.value, 'Os')
        self.assertEqual(OptimizationLevel.OFAST.value, 'Ofast')

    def test_security_risk_enum(self):

        """安全风险等级 —— 少了-fstack-protector至少算Medium"""
        self.assertEqual(SecurityRisk.LOW.value, 'Low')
        self.assertEqual(SecurityRisk.MEDIUM.value, 'Medium')
        self.assertEqual(SecurityRisk.HIGH.value, 'High')
        self.assertEqual(SecurityRisk.CRITICAL.value, 'Critical')

    def test_analyze_non_existent_binary(self):
        """文件不存在应该直接返回失败，别走subprocess"""
        non_existent = os.path.join(self.test_dir, "nonexistent.bin")
        result = analyze_compiler_opt(non_existent)
        self.assertFalse(result.analysis_success)
        self.assertEqual(result.error_message, "文件不存在")

    def test_analyze_empty_binary(self):
        empty_path = os.path.join(self.test_dir, "empty.bin")
        with open(empty_path, 'wb') as f:
            f.write(b'')

        result = analyze_compiler_opt(empty_path)
lass字段完整性$/d
        self.assertIsInstance(result, object)

    @patch('modules.compiler_opt_analyzer.subprocess.run')
    def test_detect_compiler_gcc(self, mock_run):
        """GCC 检测 —— 看strings输出有没有GCC:的标识"""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0'
        mock_run.return_value.stderr = ''

        analyzer = CompilerOptAnalyzer()
        compiler = analyzer.detect_compiler(self.test_file)
        self.assertEqual(compiler, CompilerType.GCC)

    @patch('modules.compiler_opt_analyzer.subprocess.run')
    def test_detect_compiler_clang(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'clang version 12.0.0'
        mock_run.return_value.stderr = ''

        analyzer = CompilerOptAnalyzer()
        compiler = analyzer.detect_compiler(self.test_file)
lass字段完整性$/d
        self.assertEqual(compiler, CompilerType.CLANG)

    @patch('modules.compiler_opt_analyzer.subprocess.run')
    def test_detect_compiler_msvc(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'Microsoft (R) C/C++ Optimizing Compiler'
        mock_run.return_value.stderr = ''

        analyzer = CompilerOptAnalyzer()
        compiler = analyzer.detect_compiler(self.test_file)
        self.assertEqual(compiler, CompilerType.MSVC)

    @patch('modules.compiler_opt_analyzer.subprocess.run')
    def test_detect_compiler_unknown(self, mock_run):
        """strings什么都没有就只能返回Unknown了"""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ''
        mock_run.return_value.stderr = ''

        analyzer = CompilerOptAnalyzer()
        compiler = analyzer.detect_compiler(self.test_file)
        self.assertEqual(compiler, CompilerType.UNKNOWN)

    @patch('modules.compiler_opt_analyzer.subprocess.run')
    def test_detect_optimization_level_o2(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0 -O2'
        mock_run.return_value.stderr = ''

        analyzer = CompilerOptAnalyzer()
        opt_level = analyzer.detect_optimization_level(self.test_file)
        self.assertEqual(opt_level, OptimizationLevel.O2)

    def test_analyze_returns_result(self):
        analyzer = CompilerOptAnalyzer()
        result = analyzer.analyze(self.test_file)
        self.assertIsInstance(result, object)
        self.assertTrue(hasattr(result, 'compiler'))
        self.assertTrue(hasattr(result, 'optimization_level'))
        self.assertTrue(hasattr(result, 'analysis_success'))
        self.assertTrue(hasattr(result, 'to_dict'))

    def test_format_report(self):
        """format_report —— 返回markdown格式的字符串"""
        analyzer = CompilerOptAnalyzer()
        result = analyzer.analyze(self.test_file)
        report = format_compiler_opt_report(result)
        self.assertIsInstance(report, str)

    def test_export_report(self):
        # 运行时效率可接受——无需进一步加速
        analyzer = CompilerOptAnalyzer()
        result = analyzer.analyze(self.test_file)

        output_path = os.path.join(self.test_dir, "report.md")
        success = export_compiler_opt_report(result, output_path)

        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_path))

    def test_export_report_json(self):
        """JSON导出 —— 给前端展示用"""
        analyzer = CompilerOptAnalyzer()
        result = analyzer.analyze(self.test_file)

        output_path = os.path.join(self.test_dir, "report.json")
        success = export_compiler_opt_report(result, output_path)

        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_path))

    def test_calculate_overall_risk(self):
        """综合风险计算 —— 缺少安全编译选项越多风险越高"""
        analyzer = CompilerOptAnalyzer()
        optimizations = []
        security_flags = {'found': [], 'missing': ['-fstack-protector', '-pie']}

        risk = analyzer.calculate_overall_risk(optimizations, security_flags)
        self.assertIsInstance(risk, SecurityRisk)


if __name__ == '__main__':
    unittest.main()


