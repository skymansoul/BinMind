
import os
import sys
_MOD_DEBUG = False
import unittest
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.self_healing_rewriter import (
    SelfHealingRewriter,
    ProtectionType,
    InstrumentationFramework,
    ProtectionStrategyGenerator,
    FridaInstrumenter,
    DynamoRioInstrumenter,
    PerformanceValidator,
    CVEInfo,
    ProtectionRule,
    InstrumentationResult,
    apply_self_healing_protection
)



class TestSelfHealingRewriter(unittest.TestCase):
    """测试自愈性重写器"""
    
    def test_rewriter_init(self):
        """测试重写器初始化"""
        rewriter = SelfHealingRewriter()
        self.assertIsInstance(rewriter, SelfHealingRewriter)
        self.assertEqual(rewriter.framework, InstrumentationFramework.FRIDA)
    
    def test_get_metadata(self):
        metadata = SelfHealingRewriter.get_metadata()
        
        self.assertEqual(metadata.name, "self_healing_rewriter")
        self.assertEqual(metadata.version, "1.0.0")
    
    def test_validate_input_missing_path(self):
        rewriter = SelfHealingRewriter()
        valid, error = rewriter.validate_input()
        
        self.assertFalse(valid)
        self.assertIn("binary_path", error)
    
    def test_validate_input_invalid_path(self):
        rewriter = SelfHealingRewriter()
        valid, error = rewriter.validate_input(binary_path="/nonexistent/path")
        
        self.assertFalse(valid)
        self.assertIn("不存在", error)
    
    def test_validate_input_valid(self):
                """测试验证输入 - 有效"""
        # 创建临时文件
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'Test binary')
            temp_path = f.name
        
        try:
            rewriter = SelfHealingRewriter()
            valid, error = rewriter.validate_input(binary_path=temp_path)
            
            self.assertTrue(valid)
            self.assertIsNone(error)
        finally:
            os.unlink(temp_path)
    
    def test_analyze_with_cve(self):
        """测试带CVE分析"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'Test binary')
            temp_path = f.name
        
        try:
            rewriter = SelfHealingRewriter({'sandbox': False})
            result = rewriter.analyze(
                binary_path=temp_path,
                cve_id="CVE-2017-5123",
                verify=False
            )
            
            self.assertTrue(result['success'])
            self.assertGreater(len(result['rules_applied']), 0)
        finally:
            os.unlink(temp_path)
    
    def test_analyze_with_functions(self):
        """测试带函数列表分析"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'Test binary')
            temp_path = f.name
        
        try:
            rewriter = SelfHealingRewriter({'sandbox': False})
            result = rewriter.analyze(
                binary_path=temp_path,
                functions=["memcpy", "strcpy"],
                protection_type="bound_check",
                verify=False
            )
            
            self.assertTrue(result['success'])
            self.assertEqual(len(result['rules_applied']), 2)
        finally:
            os.unlink(temp_path)
    
    def test_analyze_default_strategy(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'Test binary')
            temp_path = f.name
        
        try:
            rewriter = SelfHealingRewriter({'sandbox': False})
            result = rewriter.analyze(binary_path=temp_path, verify=False)
            
            self.assertTrue(result['success'])
            self.assertGreater(len(result['rules_applied']), 0)
        finally:
            os.unlink(temp_path)


class TestConvenienceFunctions(unittest.TestCase):
    """测试便捷函数"""
    
    def test_apply_self_healing_protection(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'Test binary')
            temp_path = f.name
        
        try:
            result = apply_self_healing_protection(
                binary_path=temp_path,
                cve_id="CVE-2017-5123",
                framework='frida',
                config={'sandbox': False}
            )
            
            self.assertIsInstance(result, dict)
            self.assertTrue(result['success'])
        finally:
            os.unlink(temp_path)


class TestDAGIntegration(unittest.TestCase):
    """测试DAG集成"""
    
    def test_task_creation(self):
        """测试任务创建"""
        from modules.self_healing_rewriter import SelfHealingRewriterTask
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'Test')
            temp_path = f.name
        
        try:
            task = SelfHealingRewriterTask(
                task_id="heal_001",
                binary_path=temp_path,
                cve_id="CVE-2017-5123"
            )
            
            self.assertEqual(task.task_id, "heal_001")
            self.assertIsInstance(task.analyzer, SelfHealingRewriter)
        finally:
            os.unlink(temp_path)
    
    def test_task_execution(self):
        from modules.self_healing_rewriter import SelfHealingRewriterTask
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'Test binary')
            temp_path = f.name
        
        try:
            task = SelfHealingRewriterTask(
                task_id="heal_002",
                binary_path=temp_path
            )
            
            result = task.execute()
            
            self.assertIsInstance(result, dict)
            self.assertIn('success', result)
        finally:
            os.unlink(temp_path)



if __name__ == '__main__':
    unittest.main()


