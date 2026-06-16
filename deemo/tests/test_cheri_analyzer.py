import unittest
import os
import tempfile
from modules.cheri_analyzer import CHERIAnalyzer

class TestCHERIAnalyzer(unittest.TestCase):
    """
    CHERIAnalyzer 模块测试类
    """

    def setUp(self):
        """设置测试环境"""
        self.analyzer = CHERIAnalyzer()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """清理测试环境"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detect_cheri_instructions_empty(self):
        """测试检测空指令列表"""
        result = self.analyzer._detect_cheri_instructions([])
        self.assertEqual(len(result), 0)

    def test_detect_cheri_instructions_ldc(self):
        """测试检测能力加载指令"""
        instructions = ['ldc c0, [x0]', 'add x1, x2, x3']
        result = self.analyzer._detect_cheri_instructions(instructions)
        
        ldc_instr = [r for r in result if r.opcode == 'ldc']
        self.assertTrue(len(ldc_instr) > 0)

    def test_detect_cheri_instructions_cseal(self):
        """测试检测密封指令"""
        instructions = ['cseal c0, c1, c2', 'add x1, x2, x3']
        result = self.analyzer._detect_cheri_instructions(instructions)
        
        cseal_instr = [r for r in result if r.opcode == 'cseal']
        self.assertTrue(len(cseal_instr) > 0)

    def test_detect_cheri_instructions_ccall(self):
        """测试检测能力调用指令"""
        instructions = ['ccall c0', 'ret']
        result = self.analyzer._detect_cheri_instructions(instructions)
        
        ccall_instr = [r for r in result if r.opcode == 'ccall']
        self.assertTrue(len(ccall_instr) > 0)

    def test_detect_cheri_vulnerabilities_empty(self):
        """测试检测空输入"""
        result = self.analyzer._detect_cheri_vulnerabilities([], '')
        self.assertEqual(len(result), 0)

    def test_detect_cheri_vulnerabilities_capability_leak(self):
        """测试检测能力泄露漏洞"""
        functions = ['stc_non_cap_store', 'normal_func']
        result = self.analyzer._detect_cheri_vulnerabilities(functions, '')
        
        leak_vulns = [v for v in result if 'capability_leak' in v.vulnerability_type]
        self.assertTrue(len(leak_vulns) > 0)

    def test_detect_cheri_vulnerabilities_permission_escalation(self):
        """测试检测权限提升漏洞"""
        strings = ['corperm_all_permissions']
        result = self.analyzer._detect_cheri_vulnerabilities([], strings)
        
        perm_vulns = [v for v in result if 'permission_escalation' in v.vulnerability_type]
        self.assertTrue(len(perm_vulns) > 0)

    def test_analyze_capability_usage(self):
        """测试分析能力使用"""
        from modules.cheri_analyzer import CHERIInstruction
        
        instructions = [
            CHERIInstruction(opcode='ldc', mnemonic='ldc', category='load', description=''),
            CHERIInstruction(opcode='stc', mnemonic='stc', category='store', description=''),
            CHERIInstruction(opcode='cseal', mnemonic='cseal', category='seal', description='')
        ]
        
        usage = self.analyzer._analyze_capability_usage(instructions)
        
        self.assertEqual(usage['load'], 1)
        self.assertEqual(usage['store'], 1)
        self.assertEqual(usage['seal'], 1)

    def test_extract_capabilities(self):
        """测试提取能力信息"""
        disassembly = 'c0 = ldc [x0]; csp = ldc [x1]; ccall c0'
        result = self.analyzer._extract_capabilities(disassembly)
        
        self.assertTrue(len(result) > 0)

    def test_analyze_nonexistent_file(self):
        """测试分析不存在的文件"""
        result = self.analyzer.analyze_binary("/nonexistent/file.bin")
        self.assertEqual(result.summary, "文件不存在")

    def test_format_report(self):
        """测试报告格式化"""
        from modules.cheri_analyzer import CHERIAnalysisResult, CHERICapability
        
        cap = CHERICapability(
            name='Test Capability',
            type='capability_register',
            base=0,
            length=0,
            permissions='PLS',
            offset=0,
            description='Test'
        )
        
        result = CHERIAnalysisResult(
            capabilities=[cap],
            instructions=[],
            vulnerabilities=[],
            capability_usage_summary={},
            summary='Test summary'
        )
        
        report = self.analyzer.format_report(result)
        self.assertIsInstance(report, str)
        self.assertIn('Test Capability', report)

    def test_get_mitigation(self):
        """测试获取缓解建议"""
        mitigation = self.analyzer._get_mitigation('capability_leak')
        self.assertIsInstance(mitigation, str)
        self.assertTrue(len(mitigation) > 0)


if __name__ == '__main__':
    unittest.main()
