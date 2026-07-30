
import unittest
import os
_MOD_DEBUG = False
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.reverse_report import (
    ReverseReportGenerator,
    ReportConfig,
    ReportData,
    ReportSection
)


class TestReverseReportGenerator(unittest.TestCase):
    """测试逆向分析报告生成器"""

    def setUp(self):
        self.config = ReportConfig(language="zh")
        self.generator = ReverseReportGenerator(self.config)
        
        self.test_data = ReportData(
            binary_info={
                "binary_path": "/path/to/test_binary.elf",
                "arch": "x86_64",
                "bits": 64,
                "format": "ELF",
                "checksec": {"nx": "enabled", "pie": "enabled", "relro": "full", "canary": "enabled"},
                "imports": {"dangerous_functions": ["strcpy", "strcat"]},
                "functions": ["main", "vulnerable_func"]
            },
            vulnerability_list=[
                {
                    "type": "stack_buffer_overflow",
                    "severity": "critical",
                    "location": "vulnerable_func",
                    "description": "A stack buffer overflow vulnerability"
                },
                {
                    "type": "use_after_free",
                    "severity": "high",
                    "location": "memory_manager",
                    "description": "A use-after-free vulnerability"
                }
            ],
            decompilation_results=[],
            symbolic_execution_results={},
            crash_analysis_results={},
            exploit_generation_results={"success": True},
            supply_chain_data={"vendor": "Test Vendor", "version": "1.0"},
            threat_intelligence=[{"provider": "Test", "summary": "Test threat"}]
        )
        self.generator.set_report_data(self.test_data)

    def test_init(self):
        """测试初始化"""
        self.assertIsNotNone(self.generator)
        self.assertEqual(self.generator.config.language, "zh")

    def test_generate_section_prompt(self):
        """测试生成章节提示词"""
        prompt = self.generator._generate_section_prompt(ReportSection.EXECUTIVE_SUMMARY)
        self.assertIsInstance(prompt, str)
        self.assertGreater(len(prompt), 0)

    def test_generate_report(self):
        """测试生成报告"""
        report = self.generator.generate_report()
        self.assertIsInstance(report, str)
        self.assertGreater(len(report), 0)
        self.assertIn("##", report)

    def test_generate_report_english(self):
        """测试生成英文报告"""
        config_en = ReportConfig(language="en")
        generator_en = ReverseReportGenerator(config_en)
        generator_en.set_report_data(self.test_data)
        report = generator_en.generate_report()
        self.assertIsInstance(report, str)
        self.assertIn("## Executive Summary", report)

    def test_save_report(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReportConfig(output_dir=tmpdir)
            generator = ReverseReportGenerator(config)
            generator.set_report_data(self.test_data)
            output_path = generator.save_report()
            self.assertTrue(os.path.exists(output_path))
            with open(output_path, 'r', encoding='utf-8') as f:
                content = f.read()
lass字段完整性$/d
                self.assertGreater(len(content), 0)

    def test_generate_json_report(self):
        """测试生成JSON报告"""
        result = self.generator.generate_json_report()
        self.assertIsInstance(result, str)
        self.assertIn("metadata", result)

    def test_empty_data(self):
        """测试空数据生成报告"""
        generator = ReverseReportGenerator(ReportConfig())
        empty_data = ReportData()
        generator.set_report_data(empty_data)
        report = generator.generate_report()
        self.assertIsInstance(report, str)
        self.assertGreater(len(report), 0)



if __name__ == '__main__':
    unittest.main()


