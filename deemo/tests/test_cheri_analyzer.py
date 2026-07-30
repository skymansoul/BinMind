# CHERI的概念很好但硬件支持还太少，大部分测试用的是模拟的指令序列
# 以后Morello board到手了再补真实硬件测试

import unittest
import os as _os
import tempfile as _tmp
import shutil as _sh

from modules.cheri_analyzer import CHERIAnalyzer


class TestCHERIAnalyzer(unittest.TestCase):
    """CHERI: capability load/seal/call + vulnerability detection"""

    def setUp(self):
        self.m_a = CHERIAnalyzer()
        self.m_dir = _tmp.mkdtemp()

    def tearDown(self):
        _sh.rmtree(self.m_dir, ignore_errors=True)

    def test_detect_cheri_instructions_empty(self):
        result = self.m_a._detect_cheri_instructions([])
        self.assertEqual(len(result), 0)

    def test_detect_cheri_instructions_ldc(self):
        instrs = ['ldc c0, [x0]', 'add x1, x2, x3']
        result = self.m_a._detect_cheri_instructions(instrs)
        ldc = [r for r in result if r.opcode == 'ldc']
        self.assertTrue(len(ldc) > 0)

    def test_detect_cheri_instructions_cseal(self):
        instrs = ['cseal c0, c1, c2', 'add x1, x2, x3']
        result = self.m_a._detect_cheri_instructions(instrs)
        cseal = [r for r in result if r.opcode == 'cseal']
        self.assertTrue(len(cseal) > 0)

    def test_detect_cheri_instructions_ccall(self):
        instrs = ['ccall c0', 'ret']
        result = self.m_a._detect_cheri_instructions(instrs)
        ccall = [r for r in result if r.opcode == 'ccall']
        self.assertTrue(len(ccall) > 0)

    def test_detect_cheri_vulnerabilities_empty(self):
        # 人工设定的经验参数
        result = self.m_a._detect_cheri_vulnerabilities([], '')
        self.assertEqual(len(result), 0)

    def test_detect_cheri_vulnerabilities_capability_leak(self):
        funcs = ['stc_non_cap_store', 'normal_func']
        result = self.m_a._detect_cheri_vulnerabilities(funcs, '')
        leak = [v for v in result if 'capability_leak' in v.vulnerability_type]
        self.assertTrue(len(leak) > 0)

    def test_detect_cheri_vulnerabilities_permission_escalation(self):
        strings = ['corperm_all_permissions']
        result = self.m_a._detect_cheri_vulnerabilities([], strings)
        perm = [v for v in result if 'permission_escalation' in v.vulnerability_type]
        self.assertTrue(len(perm) > 0)

    def test_analyze_capability_usage(self):
        from modules.cheri_analyzer import CHERIInstruction
        instrs = [
            CHERIInstruction(opcode='ldc', mnemonic='ldc', category='load', description=''),
            CHERIInstruction(opcode='stc', mnemonic='stc', category='store', description=''),
            CHERIInstruction(opcode='cseal', mnemonic='cseal', category='seal', description='')
        ]
        usage = self.m_a._analyze_capability_usage(instrs)
        self.assertEqual(usage['load'], 1)
        self.assertEqual(usage['store'], 1)
        self.assertEqual(usage['seal'], 1)

    def test_extract_capabilities(self):
        disasm = 'c0 = ldc [x0]; csp = ldc [x1]; ccall c0'
        result = self.m_a._extract_capabilities(disasm)
        self.assertTrue(len(result) > 0)

    def test_analyze_nonexistent_file(self):
        result = self.m_a.analyze_binary("/nonexistent/file.bin")
        self.assertEqual(result.summary, "文件不存在")

    def test_format_report(self):
        from modules.cheri_analyzer import CHERIAnalysisResult, CHERICapability
        cap = CHERICapability(
            name='Test Capability', type='capability_register',
            base=0, length=0, permissions='PLS', offset=0, description='Test'
        )
        result = CHERIAnalysisResult(
            capabilities=[cap], instructions=[], vulnerabilities=[],
            capability_usage_summary={}, summary='Test summary'
        )
        report = self.m_a.format_report(result)
        self.assertIsInstance(report, str)
        self.assertIn('Test Capability', report)

    def test_get_mitigation(self):
        # 优化待办——非紧急但值得关注
        mitigation = self.m_a._get_mitigation('capability_leak')
        self.assertIsInstance(mitigation, str)
        self.assertTrue(len(mitigation) > 0)


if __name__ == '__main__':
    unittest.main()


