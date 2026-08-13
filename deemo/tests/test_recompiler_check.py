
import unittest
import sys
_MOD_DEBUG = False
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.recompiler_check import (
    RecompilerVerifier,
    CompilationStatus,
    EquivalenceLevel,
    verify_decompilation,
    verify_single_function
)


class TestRecompilerChecker(unittest.TestCase):
    """反编译重编译验证模块测试"""
    
    def test_init_verifier(self):
        """测试验证器初始化"""
        verifier = RecompilerVerifier()
        self.assertIsNotNone(verifier)
    
    def test_fix_decompiled_code(self):
        """测试修复反编译代码"""
        verifier = RecompilerVerifier()
        
        code = "undefined4 __fastcall test(int a) { return a; }"
        fixed = verifier._fix_decompiled_code(code)
        
        self.assertIn("uint32_t", fixed)
        self.assertNotIn("__fastcall", fixed)
    
    def test_calculate_equivalence(self):
        """测试计算等价性"""
        verifier = RecompilerVerifier()
        
        simple_code = "int test() { return 1; }"
        score1 = verifier._calculate_equivalence(simple_code)
        self.assertGreater(score1, 0)
        
        complex_code = "int test(int a) { if (a > 0) { while(a--) { a += 1; } } return a; }"
        score2 = verifier._calculate_equivalence(complex_code)
        self.assertGreater(score2, score1)
    
    def test_determine_equivalence_level(self):
        """测试确定等价性等级"""
        verifier = RecompilerVerifier()
        
        self.assertEqual(verifier._determine_equivalence_level(0.95), EquivalenceLevel.FULL)
        self.assertEqual(verifier._determine_equivalence_level(0.75), EquivalenceLevel.HIGH)
        self.assertEqual(verifier._determine_equivalence_level(0.55), EquivalenceLevel.MEDIUM)
        self.assertEqual(verifier._determine_equivalence_level(0.35), EquivalenceLevel.LOW)
        self.assertEqual(verifier._determine_equivalence_level(0.1), EquivalenceLevel.NONE)
    
    def test_generate_header(self):
        """测试生成头文件"""
        verifier = RecompilerVerifier()
        header = verifier._generate_header()
        
        self.assertIn("#include", header)
        self.assertIn("stdio.h", header)
        self.assertIn("stdint.h", header)
    
    def test_verify_single_function(self):
        verifier = RecompilerVerifier()
        simple_code = "int test_function() { return 42; }"
        
        result = verifier.verify_function("test_function", simple_code)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "test_function")
    
    def test_generate_report(self):
        """测试生成报告"""
        verifier = RecompilerVerifier()
        result = type('obj', (), {
            'functions': [
                type('obj', (), {
                    'name': 'test',
                    'compiled_success': True,
                    'equivalence_score': 0.8,
                    'equivalence_level': EquivalenceLevel.HIGH,
                    'compilation_errors': [],
                    'notes': []
                })
            ],
            'overall_compilation_rate': 1.0,
            'overall_equivalence_score': 0.8,
            'overall_equivalence_level': EquivalenceLevel.HIGH,
            'compilation_time': 0.1,
            'notes': []
        })
        
        report = verifier.generate_report(result)
        self.assertIsNotNone(report)
        self.assertIn("反编译", report)



if __name__ == '__main__':
    unittest.main()


