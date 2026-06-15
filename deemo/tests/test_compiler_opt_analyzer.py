import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.compiler_opt_analyzer import (
    CompilerOptAnalyzer,
    CompilerType,
    OptimizationLevel,
    SecurityRisk,
    analyze_compiler_opt,
    format_compiler_opt_report,
    export_compiler_opt_report
)


class TestCompilerOptAnalyzer(unittest.TestCase):
    """编译器优化分析器单元测试"""

    def setUp(self):
        """设置测试环境"""
        self.test_dir = tempfile.mkdtemp()
        # 创建一个测试文件
        self.test_file = os.path.join(self.test_dir, "test.bin")
        with open(self.test_file, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00')

    def tearDown(self):
        """清理测试环境"""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_analyzer_init(self):
        """测试分析器初始化"""
        analyzer = CompilerOptAnalyzer()
        self.assertIsNotNone(analyzer)
        self.assertIsInstance(analyzer.gcc_opt_patterns, dict)
        self.assertIsInstance(analyzer.security_flags, list)
        self.assertIsInstance(analyzer.optimization_details, list)

    def test_compiler_type_enum(self):
        """测试编译器类型枚举"""
        self.assertEqual(CompilerType.GCC.value, 'GCC')
        self.assertEqual(CompilerType.CLANG.value, 'Clang')
        self.assertEqual(CompilerType.MSVC.value, 'MSVC')
        self.assertEqual(CompilerType.UNKNOWN.value, 'Unknown')

    def test_optimization_level_enum(self):
        """测试优化级别枚举"""
        self.assertEqual(OptimizationLevel.NONE.value, 'O0')
        self.assertEqual(OptimizationLevel.O1.value, 'O1')
        self.assertEqual(OptimizationLevel.O2.value, 'O2')
        self.assertEqual(OptimizationLevel.O3.value, 'O3')
        self.assertEqual(OptimizationLevel.OS.value, 'Os')
        self.assertEqual(OptimizationLevel.OFAST.value, 'Ofast')

    def test_security_risk_enum(self):
        """测试安全风险枚举"""
        self.assertEqual(SecurityRisk.LOW.value, 'Low')
        self.assertEqual(SecurityRisk.MEDIUM.value, 'Medium')
        self.assertEqual(SecurityRisk.HIGH.value, 'High')
        self.assertEqual(SecurityRisk.CRITICAL.value, 'Critical')

    def test_analyze_non_existent_binary(self):
        """测试分析不存在的文件"""
        non_existent = os.path.join(self.test_dir, "nonexistent.bin")
        result = analyze_compiler_opt(non_existent)
        self.assertFalse(result.analysis_success)
        self.assertEqual(result.error_message, "文件不存在")

    def test_analyze_empty_binary(self):
        """测试分析空文件"""
        empty_path = os.path.join(self.test_dir, "empty.bin")
        with open(empty_path, 'wb') as f:
            f.write(b'')
        
        result = analyze_compiler_opt(empty_path)
        self.assertIsInstance(result, object)

    @patch('modules.compiler_opt_analyzer.subprocess.run')
    def test_detect_compiler_gcc(self, mock_run):
        """测试检测 GCC 编译器"""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0'
        mock_run.return_value.stderr = ''
        
        analyzer = CompilerOptAnalyzer()
        compiler = analyzer.detect_compiler(self.test_file)
        self.assertEqual(compiler, CompilerType.GCC)

    @patch('modules.compiler_opt_analyzer.subprocess.run')
    def test_detect_compiler_clang(self, mock_run):
        """测试检测 Clang 编译器"""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'clang version 12.0.0'
        mock_run.return_value.stderr = ''
        
        analyzer = CompilerOptAnalyzer()
        compiler = analyzer.detect_compiler(self.test_file)
        self.assertEqual(compiler, CompilerType.CLANG)

    @patch('modules.compiler_opt_analyzer.subprocess.run')
    def test_detect_compiler_msvc(self, mock_run):
        """测试检测 MSVC 编译器"""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'Microsoft (R) C/C++ Optimizing Compiler'
        mock_run.return_value.stderr = ''
        
        analyzer = CompilerOptAnalyzer()
        compiler = analyzer.detect_compiler(self.test_file)
        self.assertEqual(compiler, CompilerType.MSVC)

    @patch('modules.compiler_opt_analyzer.subprocess.run')
    def test_detect_compiler_unknown(self, mock_run):
        """测试检测未知编译器"""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ''
        mock_run.return_value.stderr = ''
        
        analyzer = CompilerOptAnalyzer()
        compiler = analyzer.detect_compiler(self.test_file)
        self.assertEqual(compiler, CompilerType.UNKNOWN)

    @patch('modules.compiler_opt_analyzer.subprocess.run')
    def test_detect_optimization_level_o2(self, mock_run):
        """测试检测 O2 优化级别"""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0 -O2'
        mock_run.return_value.stderr = ''
        
        analyzer = CompilerOptAnalyzer()
        opt_level = analyzer.detect_optimization_level(self.test_file)
        self.assertEqual(opt_level, OptimizationLevel.O2)

    def test_analyze_returns_result(self):
        """测试 analyze 方法返回 CompilerOptAnalysisResult"""
        analyzer = CompilerOptAnalyzer()
        result = analyzer.analyze(self.test_file)
        self.assertIsInstance(result, object)
        self.assertTrue(hasattr(result, 'compiler'))
        self.assertTrue(hasattr(result, 'optimization_level'))
        self.assertTrue(hasattr(result, 'analysis_success'))
        self.assertTrue(hasattr(result, 'to_dict'))

    def test_format_report(self):
        """测试格式化报告"""
        analyzer = CompilerOptAnalyzer()
        result = analyzer.analyze(self.test_file)
        report = format_compiler_opt_report(result)
        self.assertIsInstance(report, str)

    def test_export_report(self):
        """测试导出报告"""
        analyzer = CompilerOptAnalyzer()
        result = analyzer.analyze(self.test_file)
        
        output_path = os.path.join(self.test_dir, "report.md")
        success = export_compiler_opt_report(result, output_path)
        
        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_path))

    def test_export_report_json(self):
        """测试导出 JSON 报告"""
        analyzer = CompilerOptAnalyzer()
        result = analyzer.analyze(self.test_file)
        
        output_path = os.path.join(self.test_dir, "report.json")
        success = export_compiler_opt_report(result, output_path)
        
        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_path))

    def test_calculate_overall_risk(self):
        """测试计算整体风险"""
        analyzer = CompilerOptAnalyzer()
        optimizations = []
        security_flags = {'found': [], 'missing': ['-fstack-protector', '-pie']}
        
        risk = analyzer.calculate_overall_risk(optimizations, security_flags)
        self.assertIsInstance(risk, SecurityRisk)


if __name__ == '__main__':
    unittest.main()