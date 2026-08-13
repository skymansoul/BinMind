import unittest
import sys
_MOD_DEBUG = False
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.dll_hijacking import (
    DLLHijackAnalyzer,
    HijackRiskLevel,
    ImportType,
    analyze_dll_hijack,
    generate_hijack_dll
)


class TestDLLHijacking(unittest.TestCase):
    """DLL劫持检测模块测试"""

    def test_init_analyzer(self):
        """测试分析器初始化"""
        analyzer = DLLHijackAnalyzer()
        self.assertIsNotNone(analyzer)

    def test_risk_evaluation(self):
        """测试风险评估逻辑"""
        analyzer = DLLHijackAnalyzer()

        # 测试已知可劫持DLL的风险评估
# lass字段完整性$/d
        self.assertEqual(
            analyzer._eval_risk("version.dll", False, False, True, ImportType.BY_NAME),
            HijackRiskLevel.HIGH
        )

        # 测试系统DLL的风险评估
        self.assertEqual(
            analyzer._eval_risk("kernel32.dll", False, True, False, ImportType.BY_NAME),
            HijackRiskLevel.LOW
        )

        # 测试带路径的DLL风险评估
        self.assertEqual(
            analyzer._eval_risk("C:\\Windows\\System32\\test.dll", True, False, False, ImportType.BY_NAME),
            HijackRiskLevel.NONE
        )

    def test_generate_hijack_code(self):
        """测试生成劫持DLL代码"""
        analyzer = DLLHijackAnalyzer()
        code = analyzer.gen_hijack("test.dll")

        self.assertIsNotNone(code)
        self.assertIn("DllMain", code)
        self.assertIn("LoadLibrary", code)

    def test_generate_test_script(self):
        """测试生成测试脚本"""
        analyzer = DLLHijackAnalyzer()
        script = analyzer.gen_test("target.exe", "hijack.dll")

        self.assertIsNotNone(script)
        self.assertIn("test_dll_hijack", script)

    def test_generate_hijack_code_to_file(self):
        """测试生成劫持DLL代码到文件"""
        analyzer = DLLHijackAnalyzer()
        with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
            output_path = f.name

        try:
            code = analyzer.gen_hijack("test.dll", output_path)
            self.assertTrue(os.path.exists(output_path))
            with open(output_path, 'r', encoding='utf-8') as f:
                content = f.read()
                self.assertIn("DllMain", content)
        finally:
            if os.path.exists(output_path):
                os.remove(output_path)



if __name__ == '__main__':
    unittest.main()
