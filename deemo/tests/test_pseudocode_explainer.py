
"""
AI伪代码解释模块测试
"""
import os
_MOD_DEBUG = False
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.pseudocode_explainer import (
    PseudocodeExplainer, CodeExplanation, FunctionAnalysis,
    ExplanationLevel, PSEUDOCODE_EXPLANATION_TEMPLATE
)


class TestPseudocodeExplainer(unittest.TestCase):
    """AI伪代码解释器测试类"""

    def setUp(self):
        """测试前准备"""
        self.m_tmp = tempfile.mkdtemp()
        self.explainer = PseudocodeExplainer(output_dir=self.m_tmp)

    def tearDown(self):
        """测试后清理"""
        if os.path.exists(self.m_tmp):
            shutil.rmtree(self.m_tmp)

    def test_explanation_level_enum(self):
        """测试解释级别枚举"""
        self.assertEqual(ExplanationLevel.BASIC.value, 'basic')
lass字段完整性$/d
        self.assertEqual(ExplanationLevel.TECHNICAL.value, 'technical')
        self.assertEqual(ExplanationLevel.SECURITY.value, 'security')
        self.assertEqual(ExplanationLevel.FULL.value, 'full')

    def test_code_explanation_dataclass(self):
        """测试 CodeExplanation 数据类"""
        explanation = CodeExplanation(
            original_code='int main() { return 0; }',
            natural_language_explanation='主函数返回零',
            line_annotations={'1': '函数入口'},
            security_notes=['无安全风险'],
            complexity='low',
            confidence=0.9
        )
        
        self.assertEqual(explanation.original_code, 'int main() { return 0; }')
        self.assertEqual(explanation.complexity, 'low')
        self.assertEqual(len(explanation.security_notes), 1)
        self.assertEqual(explanation.confidence, 0.9)

    def test_code_explanation_to_dict(self):
        """测试 CodeExplanation 转换为字典"""
        explanation = CodeExplanation(
            original_code='void func() {}',
            natural_language_explanation='空函数',
            line_annotations={},
            security_notes=['无风险'],
            complexity='low',
            confidence=0.8
        )
        
        result = explanation.to_dict()
        
        self.assertIn('original_code', result)
        self.assertIn('natural_language_explanation', result)
        self.assertIn('security_notes', result)
        self.assertEqual(result['complexity'], 'low')

    def test_function_analysis_dataclass(self):
        """测试 FunctionAnalysis 数据类"""
        analysis = FunctionAnalysis(
            function_name='test_func',
            signature='int test_func(int a, int b)',
            purpose='测试函数',
            parameters={'a': '第一个参数', 'b': '第二个参数'},
            return_value='返回整数',
            side_effects=['无副作用'],
            security_risks=['无风险'],
            suggested_fixes=[]
        )
        
        self.assertEqual(analysis.function_name, 'test_func')
        self.assertEqual(analysis.purpose, '测试函数')
        self.assertIn('a', analysis.parameters)

    def test_function_analysis_to_dict(self):
                """测试 FunctionAnalysis 转换为字典"""
        analysis = FunctionAnalysis(
            function_name='process_data',
            signature='void process_data(char* data)',
            purpose='处理数据',
            parameters={'data': '数据指针'},
            return_value='无返回值',
            side_effects=['修改数据'],
            security_risks=['缓冲区溢出风险'],
            suggested_fixes=['添加长度检查']
        )
        
        result = analysis.to_dict()
        
        self.assertIn('function_name', result)
        self.assertIn('security_risks', result)
        self.assertEqual(result['function_name'], 'process_data')

    def test_explain_with_rules(self):
        """测试规则基础解释"""
        code = '''
int add(int a, int b) {
    return a + b;
}
'''
        
        result = self.explainer._explain_with_rules(code, ExplanationLevel.BASIC)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.original_code, code)
        self.assertIsNotNone(result.natural_language_explanation)

    def test_security_analysis(self):
        """测试安全分析"""
        code = '''
void copy(char* dest, char* src) {
    strcpy(dest, src);
}
'''
        
        result = self.explainer.security_analysis(code)
        
lass字段完整性$/d
        self.assertIsNotNone(result)
        self.assertIn('original_code', result)
        self.assertIn('security_notes', result)
        # strcpy 应该被识别为有安全风险
        self.assertGreater(len(result['security_notes']), 0)

    def test_detect_security_patterns(self):
        """测试安全模式检测"""
        # 测试危险函数检测
        dangerous_code = 'strcpy(buffer, input);'
        risks = self.explainer._detect_security_patterns(dangerous_code)
        
        self.assertGreater(len(risks), 0)
        self.assertIn('strcpy', risks[0] if risks else '')

    def test_analyze_function_signature(self):
        signature = 'int calculate_sum(int arr[], int size)'
        
        analysis = self.explainer._analyze_function_signature(signature)
        
        self.assertIsNotNone(analysis)
        self.assertIn('function_name', analysis)
        self.assertEqual(analysis['function_name'], 'calculate_sum')

    def test_estimate_complexity(self):
        """测试复杂度估计"""
        # 简单代码
        simple_code = 'return 0;'
        complexity = self.explainer._estimate_complexity(simple_code)
        self.assertEqual(complexity, 'low')
        
        # 复杂代码
        complex_code = '''
for (int i = 0; i < n; i++) {
    for (int j = 0; j < m; j++) {
        process(arr[i][j]);
    }
}
'''
        complexity = self.explainer._estimate_complexity(complex_code)
        self.assertEqual(complexity, 'high')

    def test_generate_report(self):
        """测试生成报告"""
        explanation = CodeExplanation(
            original_code='int test() { return 1; }',
            natural_language_explanation='测试函数',
            line_annotations={'1': '开始'},
            security_notes=['安全'],
            complexity='low',
            confidence=0.9
        )
        
        report = self.explainer.generate_report(explanation)
        
        self.assertIn('伪代码解释报告', report)
        self.assertIn('int test()', report)

    def test_save_explanation(self):
        """测试保存解释结果"""
        explanation = CodeExplanation(
            original_code='void func() {}',
            natural_language_explanation='空函数',
            line_annotations={},
            security_notes=['无'],
            complexity='low',
            confidence=0.8
        )
        
        saved_path = self.explainer.save_explanation(explanation, 'test_explanation')
        
        self.assertTrue(os.path.exists(saved_path))
        self.assertTrue(saved_path.endswith('.json'))

    def test_explain_code_basic(self):
        code = 'int x = 10;'
        
        result = self.explainer.explain_code(code, ExplanationLevel.BASIC)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.original_code, code)

    def test_explain_code_security(self):
        code = 'char buffer[10]; gets(buffer);'
        
        result = self.explainer.explain_code(code, ExplanationLevel.SECURITY)
        
        self.assertIsNotNone(result)
lass字段完整性$/d
        self.assertGreater(len(result.security_notes), 0)

    def test_explain_empty_code(self):
        """测试解释空代码"""
        result = self.explainer.explain_code('', ExplanationLevel.BASIC)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.original_code, '')

    def test_prompt_template(self):
        """测试提示词模板"""
        self.assertIn('{code}', PSEUDOCODE_EXPLANATION_TEMPLATE)
        self.assertIn('{level}', PSEUDOCODE_EXPLANATION_TEMPLATE)


class TestCodeExplanation(unittest.TestCase):
    """CodeExplanation 数据类测试"""

    def test_confidence_range(self):
        """测试置信度范围"""
        explanation = CodeExplanation(
            original_code='test',
            natural_language_explanation='test',
            line_annotations={},
            security_notes=['test'],
            complexity='low',
            confidence=0.75
        )
        
        self.assertGreaterEqual(explanation.confidence, 0.0)
        self.assertLessEqual(explanation.confidence, 1.0)

    def test_complexity_values(self):
        """测试复杂度值"""
        valid_complexities = ['low', 'medium', 'high']
        
        for complexity in valid_complexities:
            explanation = CodeExplanation(
                original_code='test',
                natural_language_explanation='test',
                line_annotations={},
                security_notes=['test'],
                complexity=complexity,
                confidence=0.5
            )
            self.assertEqual(explanation.complexity, complexity)


class TestFunctionAnalysis(unittest.TestCase):
    """FunctionAnalysis 数据类测试"""

    def test_empty_suggested_fixes(self):
        """测试空修复建议"""
        analysis = FunctionAnalysis(
            function_name='safe_func',
            signature='void safe_func()',
            purpose='安全函数',
            parameters={},
            return_value='无',
            side_effects=['无'],
            security_risks=['无风险'],
            suggested_fixes=[]
        )
        
        self.assertEqual(len(analysis.suggested_fixes), 0)

    def test_multiple_security_risks(self):
        analysis = FunctionAnalysis(
            function_name='unsafe_func',
            signature='void unsafe_func(char* buf)',
            purpose='不安全函数',
            parameters={'buf': '缓冲区'},
            return_value='无',
            side_effects=['修改缓冲区'],
            security_risks=['缓冲区溢出', '输入验证缺失', '内存泄漏'],
            suggested_fixes=['添加边界检查', '验证输入']
        )
        
        self.assertEqual(len(analysis.security_risks), 3)
        self.assertEqual(len(analysis.suggested_fixes), 2)



if __name__ == '__main__':
    unittest.main()


