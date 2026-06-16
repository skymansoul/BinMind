import unittest
import os
import tempfile
from modules.riscv_ext_analyzer import RISCVExtAnalyzer

class TestRISCVExtAnalyzer(unittest.TestCase):
    """
    RISCVExtAnalyzer 模块测试类
    """

    def setUp(self):
        """设置测试环境"""
        self.analyzer = RISCVExtAnalyzer()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """清理测试环境"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detect_vector_instructions_empty(self):
        """测试检测空指令列表"""
        result = self.analyzer._detect_vector_instructions([])
        self.assertEqual(len(result), 0)

    def test_detect_vector_instructions_vadd(self):
        """测试检测向量加法指令"""
        instructions = ['vadd.vv v0, v1, v2', 'add a0, a1, a2']
        result = self.analyzer._detect_vector_instructions(instructions)
        
        vadd_instr = [r for r in result if r.opcode == 'vadd']
        self.assertTrue(len(vadd_instr) > 0)

    def test_detect_vector_instructions_vsetvli(self):
        """测试检测vsetvli指令"""
        instructions = ['vsetvli a0, a1, e32,m8', 'addi a0, zero, 1']
        result = self.analyzer._detect_vector_instructions(instructions)
        
        vsetvli_instr = [r for r in result if r.opcode == 'vsetvli']
        self.assertTrue(len(vsetvli_instr) > 0)

    def test_detect_crypto_instructions_empty(self):
        """测试检测空指令列表"""
        result = self.analyzer._detect_crypto_instructions([])
        self.assertEqual(len(result), 0)

    def test_detect_crypto_instructions_aesenc(self):
        """测试检测AES加密指令"""
        instructions = ['aesenc.s a0, a1, a2', 'add a0, a1, a2']
        result = self.analyzer._detect_crypto_instructions(instructions)
        
        aes_instr = [r for r in result if r.opcode == 'aesenc']
        self.assertTrue(len(aes_instr) > 0)

    def test_detect_crypto_instructions_sm4key(self):
        """测试检测SM4密钥扩展指令"""
        instructions = ['sm4key.i a0, a1, a2']
        result = self.analyzer._detect_crypto_instructions(instructions)
        
        sm4_instr = [r for r in result if r.opcode == 'sm4key']
        self.assertTrue(len(sm4_instr) > 0)

    def test_detect_vector_loops_empty(self):
        """测试检测空反汇编"""
        result = self.analyzer._detect_vector_loops('')
        self.assertEqual(len(result), 0)

    def test_detect_vector_loops_element_wise(self):
        """测试检测逐元素操作循环"""
        disassembly = 'vsetvli a0, a1, e32,m8; vadd.vv v0, v1, v2; loop:'
        result = self.analyzer._detect_vector_loops(disassembly)
        
        element_loops = [r for r in result if r.operation_type == 'compute']
        self.assertTrue(len(element_loops) > 0)

    def test_analyze_extension_usage(self):
        """测试分析扩展使用"""
        from modules.riscv_ext_analyzer import RISCVVectorInstruction, RISCV_CryptoInstruction
        
        vector_instr = [RISCVVectorInstruction(opcode='vadd', mnemonic='vadd', vtype='arithmetic', description='')]
        crypto_instr = [RISCV_CryptoInstruction(opcode='aesenc', mnemonic='aesenc', extension='Zkne', description='', security_risk='low')]
        
        usage = self.analyzer._analyze_extension_usage(vector_instr, crypto_instr)
        
        self.assertEqual(usage['Zve'], 1)
        self.assertEqual(usage['Zkne'], 1)

    def test_detect_security_issues(self):
        """测试检测安全问题"""
        from modules.riscv_ext_analyzer import RISCV_CryptoInstruction
        
        crypto_instr = [
            RISCV_CryptoInstruction(opcode='sm4key', mnemonic='sm4key', extension='Zksh', description='SM4密钥扩展', security_risk='high')
        ]
        
        issues = self.analyzer._detect_security_issues(crypto_instr)
        self.assertTrue(len(issues) > 0)

    def test_analyze_nonexistent_file(self):
        """测试分析不存在的文件"""
        result = self.analyzer.analyze_binary("/nonexistent/file.bin")
        self.assertEqual(result.summary, "文件不存在")

    def test_format_report(self):
        """测试报告格式化"""
        from modules.riscv_ext_analyzer import RISCVExtAnalysisResult, RISCVVectorInstruction
        
        instr = RISCVVectorInstruction(opcode='vadd', mnemonic='vadd', vtype='arithmetic', description='向量加法')
        
        result = RISCVExtAnalysisResult(
            vector_instructions=[instr],
            crypto_instructions=[],
            vector_loops=[],
            extension_usage={'Zve': 1},
            security_issues=[],
            summary='Test summary'
        )
        
        report = self.analyzer.format_report(result)
        self.assertIsInstance(report, str)
        self.assertIn('vadd', report)


if __name__ == '__main__':
    unittest.main()
