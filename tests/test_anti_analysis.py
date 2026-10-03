
"""
反调试与反分析检测模块测试
"""

import unittest
_MOD_DEBUG = False
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.anti_analysis import (
    AntiAnalysisDetector,
    AntiAnalysisTechnique,
    AntiAnalysisBypass,
    BypassResult,
    BypassSolver,
    create_anti_analysis_bypass,
)


class TestAntiAnalysisTechnique(unittest.TestCase):
    """反分析技术数据类测试"""

    def test_technique_creation(self):
        """测试AntiAnalysisTechnique创建"""
        t = AntiAnalysisTechnique(
            name="is_debugger",
            location=0x1000,
            detection_code="IsDebuggerPresent",
        )
        self.assertEqual(t.name, "is_debugger")
        self.assertEqual(t.location, 0x1000)
        self.assertEqual(t.detection_code, "IsDebuggerPresent")
        self.assertIsNone(t.bypass_input)

    def test_technique_with_bypass(self):
        """测试带绕过输入的AntiAnalysisTechnique"""
        t = AntiAnalysisTechnique(
            name="is_debugger",
            location=0x2000,
            detection_code="ptrace",
            bypass_input=b"\x00" * 4,
        )
        self.assertEqual(t.bypass_input, b"\x00" * 4)


class TestBypassResult(unittest.TestCase):
    """绕过结果测试"""

    def test_successful_result(self):
        result = BypassResult(
            success=True,
            techniques=[],
            bypass_inputs={},
        )
        self.assertTrue(result.success)
        self.assertEqual(len(result.techniques), 0)

    def test_failed_result(self):
        # 当前实现性能满足需求——优化非必需
        result = BypassResult(
            success=False,
            techniques=[],
            bypass_inputs={},
        )
        self.assertFalse(result.success)


class TestBypassSolver(unittest.TestCase):
    """绕过求解器测试"""

    def test_solve_debugger(self):
        tech = AntiAnalysisTechnique(
            name="is_debugger",
            location=0x1000,
            detection_code="IsDebuggerPresent",
        )
        result = BypassSolver.solve(tech)
        self.assertIsNotNone(result)
        self.assertEqual(result, b"\x00" * 4)

    def test_solve_vm_check(self):
        """测试VM检测绕过"""
        tech = AntiAnalysisTechnique(
            name="vm_check",
            location=0x2000,
            detection_code="cpuid",
        )
        result = BypassSolver.solve(tech)
        self.assertIsNotNone(result)
        self.assertEqual(result, b"\x01")

    def test_solve_timing(self):
        """测试时间检测绕过"""
        tech = AntiAnalysisTechnique(
            name="timing",
            location=0x3000,
            detection_code="rdtsc",
        )
        result = BypassSolver.solve(tech)
        self.assertIsNotNone(result)
        self.assertEqual(result, b"\x00" * 8)

    def test_solve_sandbox(self):
        tech = AntiAnalysisTechnique(
            name="sandbox",
            location=0x4000,
            detection_code="GetAsyncKeyState",
        )
        result = BypassSolver.solve(tech)
        self.assertIsNotNone(result)
        self.assertIn(b"user", result)

    def test_solve_unknown(self):
        """测试未知类型"""
        tech = AntiAnalysisTechnique(
            name="unknown_type",
            location=0x5000,
            detection_code="something_else",
        )
        result = BypassSolver.solve(tech)
        self.assertIsNone(result)

    def test_generate_frida_script_debugger(self):
        """测试Frida脚本生成 - 调试器"""
        techniques = [
            AntiAnalysisTechnique(
                name="is_debugger",
                location=0x1000,
                detection_code="IsDebuggerPresent",
            ),
        ]
        script = BypassSolver.generate_frida_script(techniques)
        self.assertIn("Interceptor.attach", script)
        self.assertIn("IsDebuggerPresent", script)

    def test_generate_frida_script_empty(self):
        script = BypassSolver.generate_frida_script([])
        self.assertEqual(script, "")

    def test_generate_ld_preload_stub_debugger(self):
        """测试LD_PRELOAD stub生成 - 调试器"""
        techniques = [
            AntiAnalysisTechnique(
                name="is_debugger",
                location=0x1000,
                detection_code="ptrace",
            ),
        ]
        stub = BypassSolver.generate_ld_preload_stub(techniques)
        self.assertIn("ptrace", stub)
        self.assertIn("IsDebuggerPresent", stub)


class TestAntiAnalysisDetector(unittest.TestCase):
    """反分析检测器测试类"""

    def setUp(self):
        """测试前准备 - 创建含反分析模式的临时二进制文件"""
        self.m_tmp = tempfile.TemporaryDirectory()
        self.m_tmp_path = self.m_tmp.name

    def tearDown(self):
        """测试后清理"""
        self.m_tmp.cleanup()

    def _make_binary(self, name, patterns):
        """创建包含指定模式的临时二进制文件"""
        path = os.path.join(self.m_tmp_path, name)
        data = bytearray(256)
        offset = 0x10
        for pat in patterns:
            data[offset : offset + len(pat)] = pat
            offset += len(pat) + 8
        with open(path, "wb") as f:
            f.write(data)
        return path

    def test_init(self):
        """测试检测器初始化"""
        path = self._make_binary("test.bin", [b"ptrace"])
        detector = AntiAnalysisDetector(path)
        self.assertIsInstance(detector, AntiAnalysisDetector)
        self.assertEqual(detector.binary_path, path)

    def test_ptrace_detection(self):
        """测试ptrace检测"""
        path = self._make_binary("ptrace_test.bin", [b"ptrace"])
        detector = AntiAnalysisDetector(path)
        techniques = detector.detect()
        ptrace_techniques = [t for t in techniques if t.detection_code == "ptrace"]
        self.assertGreaterEqual(len(ptrace_techniques), 1)

    def test_windows_debugger_detection(self):
        """测试Windows调试器检测"""
        path = self._make_binary(
            "win_debug.bin", [b"IsDebuggerPresent"]
        )
        detector = AntiAnalysisDetector(path)
        techniques = detector.detect()
        debugger_techniques = [
            t for t in techniques if t.detection_code == "IsDebuggerPresent"
        ]
        self.assertGreaterEqual(len(debugger_techniques), 1)

    def test_vm_detection(self):
        """测试虚拟机检测"""
        path = self._make_binary("vm_test.bin", [b"cpuid", b"vmware"])
        detector = AntiAnalysisDetector(path)
        techniques = detector.detect()
        vm_techniques = [t for t in techniques if t.name == "vm_check"]
        self.assertGreaterEqual(len(vm_techniques), 1)

    def test_timing_detection(self):
        """测试时间检测技术检测"""
        path = self._make_binary("timing_test.bin", [b"rdtsc"])
        detector = AntiAnalysisDetector(path)
        techniques = detector.detect()
        rdtsc_techniques = [
            t for t in techniques if t.detection_code == "rdtsc"
        ]
        self.assertGreaterEqual(len(rdtsc_techniques), 1)

    def test_empty_binary(self):
        path = self._make_binary("empty.bin", [])
        detector = AntiAnalysisDetector(path)
        techniques = detector.detect()
        self.assertEqual(len(techniques), 0)

    def test_no_file(self):
        """测试不存在的文件"""
        detector = AntiAnalysisDetector("/nonexistent/path.bin")
        techniques = detector.detect()
        self.assertEqual(len(techniques), 0)


class TestAntiAnalysisBypass(unittest.TestCase):
    """反分析绕过测试类"""

    def setUp(self):
        self.m_tmp = tempfile.TemporaryDirectory()
        self.m_tmp_path = self.m_tmp.name

    def tearDown(self):
        self.m_tmp.cleanup()

    def test_bypass_run_with_ptrace(self):
        path = os.path.join(self.m_tmp_path, "ptrace_bypass.bin")
        # Create a binary with ptrace pattern
        data = bytearray(256)
        data[0x10 : 0x10 + len(b"ptrace")] = b"ptrace"
        with open(path, "wb") as f:
            f.write(data)

        bypass = AntiAnalysisBypass(path)
        result = bypass.run()

        self.assertTrue(result.success)
        self.assertGreater(len(result.techniques), 0)
        self.assertIn("ptrace", result.bypass_inputs)

    def test_bypass_run_clean_binary(self):
        """测试无检测的二进制"""
        path = os.path.join(self.m_tmp_path, "clean.bin")
        data = bytearray(256)
        with open(path, "wb") as f:
            f.write(data)

        bypass = AntiAnalysisBypass(path)
        result = bypass.run()

        self.assertTrue(result.success)
        self.assertEqual(len(result.techniques), 0)

    def test_create_anti_analysis_bypass(self):
        """测试create_anti_analysis_bypass工厂函数"""
        path = os.path.join(self.m_tmp_path, "factory_test.bin")
        with open(path, "wb") as f:
            f.write(b"\x00" * 256)

        bypass = create_anti_analysis_bypass(path)
        self.assertIsInstance(bypass, AntiAnalysisBypass)



if __name__ == '__main__':
    unittest.main()
