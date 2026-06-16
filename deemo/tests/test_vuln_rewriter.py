"""
测试漏洞函数自动重写模块
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.vuln_rewriter import (
    VulnerabilityRewriter,
    VulnerabilityType,
    RewriteStrategy,
    IRBuilder,
    IRNode,
    CodeSynthesizer,
    ConstraintSolver,
    FunctionSummary,
    RewriteResult,
    rewrite_vulnerable_function
)


class TestIRBuilder(unittest.TestCase):
    """测试IR构建器"""
    
    def test_ir_builder_init(self):
        """测试IR构建器初始化"""
        builder = IRBuilder()
        self.assertIsInstance(builder, IRBuilder)
        self.assertEqual(len(builder.variables), 0)
    
    def test_build_from_code_simple(self):
        """测试从简单代码构建IR"""
        builder = IRBuilder()
        code = "void test() { return; }"
        ir = builder.build_from_code(code)
        
        self.assertIsInstance(ir, IRNode)
        self.assertEqual(ir.node_type, "Program")
    
    def test_build_from_code_function(self):
        """测试从函数代码构建IR"""
        builder = IRBuilder()
        code = "int add(int a, int b) { return a + b; }"
        ir = builder.build_from_code(code)
        
        self.assertIsInstance(ir, IRNode)
        # 检查是否有函数节点
        has_function = any(c.node_type == "Function" for c in ir.children)
        self.assertTrue(has_function)
    
    def test_generate_summary(self):
        """测试生成函数摘要"""
        builder = IRBuilder()
        code = "int multiply(int x, int y)"
        ir = builder.build_from_code(code)
        summary = builder.generate_summary("multiply", ir)
        
        self.assertIsInstance(summary, FunctionSummary)
        self.assertEqual(summary.name, "multiply")


class TestCodeSynthesizer(unittest.TestCase):
    """测试代码合成器"""
    
    def test_synthesizer_init(self):
        """测试合成器初始化"""
        synthesizer = CodeSynthesizer()
        self.assertIsInstance(synthesizer, CodeSynthesizer)
        self.assertIsNotNone(synthesizer.templates)
    
    def test_synthesize_buffer_overflow(self):
        """测试合成缓冲区溢出修复"""
        synthesizer = CodeSynthesizer()
        summary = FunctionSummary(
            name="vulnerable_copy",
            inputs=["dst", "src"],
            outputs=["void"],
            side_effects=[],
            constraints=[],
            semantics=""
        )
        
        result = synthesizer.synthesize(
            VulnerabilityType.BUFFER_OVERFLOW,
            "void vulnerable_copy(char *dst, char *src) { strcpy(dst, src); }",
            summary
        )
        
        self.assertIsNotNone(result)
        self.assertIn("safe", result.lower())
    
    def test_synthesize_null_pointer(self):
        """测试合成空指针修复"""
        synthesizer = CodeSynthesizer()
        summary = FunctionSummary(
            name="unsafe_free",
            inputs=["ptr"],
            outputs=["void"],
            side_effects=[],
            constraints=[],
            semantics=""
        )
        
        result = synthesizer.synthesize(
            VulnerabilityType.NULL_POINTER,
            "void unsafe_free(void *ptr) { free(ptr); }",
            summary
        )
        
        self.assertIsNotNone(result)
        self.assertIn("NULL", result)


class TestConstraintSolver(unittest.TestCase):
    """测试约束求解器"""
    
    def test_solver_init(self):
        """测试求解器初始化"""
        solver = ConstraintSolver()
        self.assertIsInstance(solver, ConstraintSolver)
    
    def test_add_constraint(self):
        """测试添加约束"""
        solver = ConstraintSolver()
        solver.add_constraint("no_overflow")
        self.assertEqual(len(solver.constraints), 1)


class TestVulnerabilityRewriter(unittest.TestCase):
    """测试漏洞重写器"""
    
    def test_rewriter_init(self):
        """测试重写器初始化"""
        rewriter = VulnerabilityRewriter()
        self.assertIsInstance(rewriter, VulnerabilityRewriter)
        self.assertEqual(rewriter.strategy, RewriteStrategy.TEMPLATE_BASED)
    
    def test_get_metadata(self):
        """测试获取元数据"""
        metadata = VulnerabilityRewriter.get_metadata()
        
        self.assertEqual(metadata.name, "vulnerability_rewriter")
        self.assertEqual(metadata.version, "1.0.0")
    
    def test_validate_input_missing_code(self):
        """测试验证输入 - 缺少code"""
        rewriter = VulnerabilityRewriter()
        valid, error = rewriter.validate_input(vuln_type="buffer_overflow")
        
        self.assertFalse(valid)
        self.assertIn("code", error)
    
    def test_validate_input_missing_vuln_type(self):
        """测试验证输入 - 缺少vuln_type"""
        rewriter = VulnerabilityRewriter()
        valid, error = rewriter.validate_input(code="void test() {}")
        
        self.assertFalse(valid)
        self.assertIn("vuln_type", error)
    
    def test_validate_input_valid(self):
        """测试验证输入 - 有效"""
        rewriter = VulnerabilityRewriter()
        valid, error = rewriter.validate_input(
            code="void test() {}",
            vuln_type="buffer_overflow"
        )
        
        self.assertTrue(valid)
        self.assertIsNone(error)
    
    def test_analyze_buffer_overflow(self):
        """测试分析缓冲区溢出"""
        rewriter = VulnerabilityRewriter({'sandbox': False})
        code = "void copy(char *dst, char *src) { strcpy(dst, src); }"
        
        result = rewriter.analyze(
            code=code,
            vuln_type="buffer_overflow",
            verify=False
        )
        
        self.assertTrue(result['success'])
        self.assertIsNotNone(result['rewritten_code'])
        self.assertEqual(result['strategy'], 'template_based')
    
    def test_analyze_format_string(self):
        """测试分析格式字符串漏洞"""
        rewriter = VulnerabilityRewriter({'sandbox': False, 'strategy': 'pattern_matching'})
        code = "void log(char *msg) { printf(msg); }"
        
        result = rewriter.analyze(
            code=code,
            vuln_type="format_string",
            verify=False
        )
        
        self.assertTrue(result['success'])
    
    def test_analyze_unknown_vuln_type(self):
        """测试分析未知漏洞类型"""
        rewriter = VulnerabilityRewriter({'sandbox': False})
        code = "void test() { return; }"
        
        result = rewriter.analyze(
            code=code,
            vuln_type="unknown_type",
            verify=False
        )
        
        # 未知类型应该回退到OTHER，可能没有模板所以失败
        # 这是预期行为
        self.assertIn('success', result)


class TestConvenienceFunctions(unittest.TestCase):
    """测试便捷函数"""
    
    def test_rewrite_vulnerable_function(self):
        """测试重写漏洞函数便捷函数"""
        code = "void unsafe_copy(char *dst, char *src) { strcpy(dst, src); }"
        
        result = rewrite_vulnerable_function(
            code=code,
            vuln_type="buffer_overflow",
            config={'sandbox': False}
        )
        
        self.assertIsInstance(result, dict)
        self.assertTrue(result['success'])


class TestDAGIntegration(unittest.TestCase):
    """测试DAG集成"""
    
    def test_task_creation(self):
        """测试任务创建"""
        from modules.vuln_rewriter import VulnerabilityRewriterTask
        
        task = VulnerabilityRewriterTask(
            task_id="rewrite_001",
            code="void test() {}",
            vuln_type="buffer_overflow"
        )
        
        self.assertEqual(task.task_id, "rewrite_001")
        self.assertIsInstance(task.analyzer, VulnerabilityRewriter)
    
    def test_task_execution(self):
        """测试任务执行"""
        from modules.vuln_rewriter import VulnerabilityRewriterTask
        
        task = VulnerabilityRewriterTask(
            task_id="rewrite_002",
            code="void unsafe(char *dst, char *src) { strcpy(dst, src); }",
            vuln_type="buffer_overflow"
        )
        
        result = task.execute()
        
        self.assertIsInstance(result, dict)
        self.assertIn('success', result)


if __name__ == '__main__':
    unittest.main()