#!/usr/bin/env python3
"""
反调试与反分析检测模块测试
"""

import unittest
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.anti_analysis import AntiAnalysisDetector, detect_anti_analysis


class TestAntiAnalysisDetector(unittest.TestCase):
    """
    反分析检测器测试类
    """
    
    def setUp(self):
        """
        测试前准备
        """
        self.ptrace_code = """
#include <sys/ptrace.h>
#include <unistd.h>

int check_debugger() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        return 1; // debugger detected
    }
    ptrace(PTRACE_DETACH, 0, 0, 0);
    return 0;
}
"""
        
        self.windows_debug_code = """
#include <windows.h>

BOOL CheckDebugger() {
    if (IsDebuggerPresent()) {
        ExitProcess(1);
    }
    return TRUE;
}
"""
        
        self.vm_detection_code = """
#include <string.h>

int check_vm() {
    char vendor[13];
    __cpuid(0, 0, (int*)vendor, (int*)(vendor+4), (int*)(vendor+8));
    if (strstr(vendor, "VMware") != NULL) {
        return 1;
    }
    return 0;
}
"""
        
        self.integrity_check_code = """
#include <string.h>

unsigned int crc32(const unsigned char *buf, int len) {
    unsigned int crc = 0xFFFFFFFF;
    // CRC calculation
    return crc;
}

void verify_self() {
    unsigned int expected = 0x12345678;
    unsigned int actual = crc32((unsigned char*)main, 0x1000);
    if (actual != expected) {
        // tampered
    }
}
"""
        
        self.timing_check_code = """
#include <stdint.h>

uint64_t rdtsc() {
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

int check_timing() {
    uint64_t start = rdtsc();
    // some operation
    uint64_t end = rdtsc();
    if (end - start > 1000000) {
        return 1; // debugger detected
    }
    return 0;
}
"""

    def test_init(self):
        """
        测试检测器初始化
        """
        detector = AntiAnalysisDetector(self.ptrace_code)
        self.assertIsInstance(detector, AntiAnalysisDetector)

    def test_ptrace_detection(self):
        """
        测试ptrace检测
        """
        detector = AntiAnalysisDetector(self.ptrace_code)
        techniques = detector.detected_techniques
        ptrace_techniques = [t for t in techniques if t.name == 'ptrace']
        self.assertGreaterEqual(len(ptrace_techniques), 1)
        self.assertEqual(ptrace_techniques[0].technique_type, 'debugger_detection')
        self.assertEqual(ptrace_techniques[0].severity, 'High')

    def test_windows_debugger_detection(self):
        """
        测试Windows调试器检测
        """
        detector = AntiAnalysisDetector(self.windows_debug_code)
        techniques = detector.detected_techniques
        debugger_techniques = [t for t in techniques if t.name == 'IsDebuggerPresent']
        self.assertEqual(len(debugger_techniques), 1)
        self.assertEqual(debugger_techniques[0].severity, 'High')

    def test_vm_detection(self):
        """
        测试虚拟机检测
        """
        detector = AntiAnalysisDetector(self.vm_detection_code)
        techniques = detector.detected_techniques
        vm_techniques = [t for t in techniques if 'vmware' in t.name.lower()]
        self.assertGreaterEqual(len(vm_techniques), 1)

    def test_integrity_check_detection(self):
        """
        测试完整性校验检测
        """
        detector = AntiAnalysisDetector(self.integrity_check_code)
        techniques = detector.detected_techniques
        crc_techniques = [t for t in techniques if t.name == 'crc']
        self.assertGreaterEqual(len(crc_techniques), 1)
        self.assertEqual(crc_techniques[0].technique_type, 'integrity_check')
        self.assertEqual(crc_techniques[0].severity, 'High')

    def test_timing_check_detection(self):
        """
        测试时间检测技术检测
        """
        detector = AntiAnalysisDetector(self.timing_check_code)
        techniques = detector.detected_techniques
        rdtsc_techniques = [t for t in techniques if t.name == 'rdtsc']
        self.assertEqual(len(rdtsc_techniques), 1)
        self.assertEqual(rdtsc_techniques[0].technique_type, 'timing_check')

    def test_frida_script_generation(self):
        """
        测试Frida脚本生成
        """
        detector = AntiAnalysisDetector(self.ptrace_code)
        with tempfile.TemporaryDirectory() as tmpdir:
            scripts = detector.generate_bypass_scripts(tmpdir)
            frida_scripts = [s for s in scripts if s.script_type == 'frida']
            self.assertEqual(len(frida_scripts), 1)
            self.assertIn('Interceptor.attach', frida_scripts[0].content)
            self.assertIn('ptrace', frida_scripts[0].content)

    def test_ld_preload_generation(self):
        """
        测试LD_PRELOAD源码生成
        """
        detector = AntiAnalysisDetector(self.ptrace_code)
        with tempfile.TemporaryDirectory() as tmpdir:
            scripts = detector.generate_bypass_scripts(tmpdir)
            ld_preload_scripts = [s for s in scripts if s.script_type == 'ld_preload']
            self.assertEqual(len(ld_preload_scripts), 1)
            self.assertIn('ptrace', ld_preload_scripts[0].content)
            self.assertIn('RTLD_NEXT', ld_preload_scripts[0].content)

    def test_gdb_script_generation(self):
        """
        测试GDB脚本生成
        """
        detector = AntiAnalysisDetector(self.ptrace_code)
        with tempfile.TemporaryDirectory() as tmpdir:
            scripts = detector.generate_bypass_scripts(tmpdir)
            gdb_scripts = [s for s in scripts if s.script_type == 'gdb_script']
            self.assertEqual(len(gdb_scripts), 1)
            self.assertIn('break ptrace', gdb_scripts[0].content)

    def test_bypass_commands(self):
        """
        测试绕过命令生成
        """
        detector = AntiAnalysisDetector(self.ptrace_code)
        with tempfile.TemporaryDirectory() as tmpdir:
            detector.generate_bypass_scripts(tmpdir)
            commands = detector.get_bypass_commands()
            self.assertGreaterEqual(len(commands), 3)
            self.assertTrue(any('frida' in cmd for cmd in commands))
            self.assertTrue(any('LD_PRELOAD' in cmd for cmd in commands))
            self.assertTrue(any('gdb' in cmd for cmd in commands))

    def test_analyze_full(self):
        """
        测试完整分析流程
        """
        result = detect_anti_analysis(self.ptrace_code)
        self.assertIn('detected_techniques', result)
        self.assertIn('bypass_scripts', result)
        self.assertIn('bypass_commands', result)
        self.assertIn('summary', result)

    def test_empty_pseudocode(self):
        """
        测试空伪代码输入
        """
        result = detect_anti_analysis('')
        self.assertEqual(result['summary']['total_techniques'], 0)

    def test_detect_with_bypass(self):
        """
        测试带绕过脚本生成的检测
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            result = detect_anti_analysis(
                self.ptrace_code,
                generate_bypass=True,
                output_dir=tmpdir
            )
            self.assertEqual(result['summary']['bypass_scripts_generated'], 3)


if __name__ == '__main__':
    unittest.main()
