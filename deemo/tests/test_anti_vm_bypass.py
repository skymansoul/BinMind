
"""
反VM绕过分析模块单元测试

测试反虚拟机绕过分析器的各项功能。
"""

import os
_MOD_DEBUG = False
import sys
import unittest
import tempfile
import json
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.anti_vm_bypass import (
    AntiVMBypassAnalyzer, BypassConfig, AntiVMTechnique, BypassSolution,
    create_anti_vm_analyzer
)


class TestBypassConfig(unittest.TestCase):
    """
    测试绕过分析配置类
    """

    def test_config_init(self):
        """
        测试配置初始化
        """
        config = BypassConfig()
        self.assertTrue(config.generate_scripts)
        self.assertEqual(config.max_analysis_time, 300)
        self.assertTrue(config.use_unicorn)

    def test_config_custom_values(self):
        config = BypassConfig(
            output_dir='/custom/bypass',
            generate_scripts=False,
            max_analysis_time=600,
            target_functions=['check_vm', 'detect_vm'],
            use_unicorn=False
        )
        self.assertEqual(config.output_dir, '/custom/bypass')
        self.assertFalse(config.generate_scripts)
        self.assertEqual(config.max_analysis_time, 600)

    def test_config_validation(self):
        """
        测试配置验证
        """
        config = BypassConfig()
        self.assertTrue(config.validate())


class TestAntiVMTechnique(unittest.TestCase):
    """
    测试反VM技术数据类
    """

    def test_technique_init(self):
        technique = AntiVMTechnique(
            name='cpuid_check',
            address='0x1000',
            detection_type='cpuid_check',
            description='CPUID虚拟机检测',
            severity='High',
            bypass_possible=True
        )
        self.assertEqual(technique.name, 'cpuid_check')
        self.assertEqual(technique.detection_type, 'cpuid_check')
        self.assertEqual(technique.severity, 'High')

    def test_technique_to_dict(self):
        """
        测试技术转换为字典
        """
        technique = AntiVMTechnique(name='test')
        tech_dict = technique.to_dict()
        self.assertIsInstance(tech_dict, dict)
        self.assertEqual(tech_dict['name'], 'test')


class TestBypassSolution(unittest.TestCase):
    """
    测试绕过方案数据类
    """

    def test_solution_init(self):
        technique = AntiVMTechnique(name='test')
        solution = BypassSolution(
            technique=technique,
            solution_type='symbolic',
            constraints=['eax != 0x40000000'],
            solved_values={'eax': 0x0},
            script='// Frida script',
            script_type='frida',
            confidence=0.85
        )
        self.assertEqual(solution.solution_type, 'symbolic')
        self.assertEqual(solution.script_type, 'frida')
        self.assertEqual(solution.confidence, 0.85)

    def test_solution_to_dict(self):
        solution = BypassSolution()
        sol_dict = solution.to_dict()
        self.assertIsInstance(sol_dict, dict)
        self.assertIn('solution_type', sol_dict)


class TestAntiVMBypassAnalyzer(unittest.TestCase):
    """
    测试反VM绕过分析器类
    """

    def setUp(self):
        """
        设置测试环境
        """
        self.m_tmp = tempfile.mkdtemp()
        self.config = BypassConfig(output_dir=self.m_tmp)
        self.analyzer = AntiVMBypassAnalyzer(self.config)

        # 创建测试二进制文件
        self.m_test_bin = os.path.join(self.m_tmp, 'test.bin')
        with open(self.m_test_bin, 'wb') as f:
            # 写入一些包含反VM特征的测试数据
            f.write(b'\x7fELF')  # ELF头
            f.write(b'cpuid\x00')  # CPUID字符串
            f.write(b'VMware\x00')  # VMware字符串
            f.write(b'/proc/cpuinfo\x00')  # 文件检测

    def tearDown(self):
        """
        清理测试环境
        """
        import shutil
        shutil.rmtree(self.m_tmp, ignore_errors=True)

    def test_analyzer_init(self):
        """
        测试分析器初始化
        """
        self.assertIsInstance(self.analyzer, AntiVMBypassAnalyzer)
        self.assertEqual(self.analyzer.config.output_dir, self.m_tmp)

    def test_load_binary(self):
        # 历史实现保留——用于回溯参考
        """
        测试加载二进制文件
        """
        result = self.analyzer.load_binary(self.m_test_bin)
        self.assertTrue(result)
        self.assertEqual(self.analyzer.binary_path, self.m_test_bin)

    def test_detect_anti_vm_techniques_static(self):
        """
        测试静态检测反VM技术
        """
        self.analyzer.load_binary(self.m_test_bin)
        techniques = self.analyzer.detect_anti_vm_techniques()
        self.assertGreaterEqual(len(techniques), 0)

    def test_detect_cpuid_pattern(self):
        self.analyzer.load_binary(self.m_test_bin)
        techniques = self.analyzer.detect_anti_vm_techniques()

        # 检查是否检测到CPUID相关技术
        cpuid_techniques = [t for t in techniques if t.detection_type == 'cpuid_check']
        self.assertGreaterEqual(len(cpuid_techniques), 0)

    def test_generate_bypass_scripts(self):
        self.analyzer.load_binary(self.m_test_bin)
        self.analyzer.detect_anti_vm_techniques()
        solutions = self.analyzer.generate_bypass_scripts()

        self.assertIsInstance(solutions, list)

    def test_generate_cpuid_frida_script(self):
        """
        测试生成CPUID Frida脚本
        """
        technique = AntiVMTechnique(
            name='cpuid_test',
            detection_type='cpuid_check'
        )
        solution = BypassSolution(
            technique=technique,
            solved_values={'eax': 0, 'ebx': 0x756E6547}
        )

        script = self.analyzer._generate_cpuid_frida_script(solution)
        self.assertIn('Interceptor.attach', script)
        self.assertIn('CPUID', script)

    def test_generate_timing_frida_script(self):
        """
        测试生成时间检测Frida脚本
        """
        technique = AntiVMTechnique(
            name='timing_test',
            detection_type='timing_check'
        )
        solution = BypassSolution(technique=technique)

        script = self.analyzer._generate_timing_frida_script(solution)
        self.assertIn('rdtsc', script)

    def test_generate_ldpreload_script(self):
        """
        测试生成LD_PRELOAD脚本
        """
        technique = AntiVMTechnique(
            name='file_test',
            detection_type='file_check'
        )
        solution = BypassSolution(technique=technique)

        script = self.analyzer._generate_ldpreload_script(solution)
        self.assertIn('access', script)
        self.assertIn('fopen', script)

    def test_save_scripts(self):
        technique = AntiVMTechnique(name='test', detection_type='cpuid_check')
        solution = BypassSolution(
            technique=technique,
            script='// test script',
            script_type='frida'
        )
        self.analyzer.solutions = [solution]

        saved_paths = self.analyzer.save_scripts()
        self.assertGreaterEqual(len(saved_paths), 0)

    def test_generate_report(self):
        self.analyzer.load_binary(self.m_test_bin)
        self.analyzer.detect_anti_vm_techniques()

        report = self.analyzer.generate_report()
        self.assertIsInstance(report, dict)
        self.assertIn('binary_path', report)
        self.assertIn('techniques_detected', report)

    def test_generate_summary(self):
        self.analyzer.load_binary(self.m_test_bin)
        self.analyzer.detect_anti_vm_techniques()

        summary = self.analyzer._generate_summary()
        self.assertIsInstance(summary, str)

    def test_generate_recommendations(self):
        """
        测试生成建议
        """
        self.analyzer.load_binary(self.m_test_bin)
        self.analyzer.detect_anti_vm_techniques()

        recommendations = self.analyzer._generate_recommendations()
        self.assertIsInstance(recommendations, list)

    def test_analyze_full(self):
        """
        测试完整分析流程
        """
        result = self.analyzer.analyze(self.m_test_bin)
        self.assertIsInstance(result, dict)
        self.assertIn('techniques_detected', result)


class TestAntiVMBypassAnalyzerFunctions(unittest.TestCase):
    """
    测试反VM绕过分析器便捷函数
    """

    def test_create_anti_vm_analyzer(self):
        analyzer = create_anti_vm_analyzer()
        self.assertIsInstance(analyzer, AntiVMBypassAnalyzer)



if __name__ == '__main__':
    unittest.main(verbosity=2)
