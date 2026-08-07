

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


