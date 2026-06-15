import unittest
import os
import sys
import importlib.util

def load_module(module_name, file_name):
    module_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules", file_name)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

type_confusion = load_module("type_confusion", "type_confusion.py")
TypeConfusionAnalyzer = type_confusion.TypeConfusionAnalyzer

class TestTypeConfusionAnalyzer(unittest.TestCase):
    """类型混淆分析器测试"""
    
    def setUp(self):
        """测试前准备"""
        self.analyzer = TypeConfusionAnalyzer()
    
    def test_initialization(self):
        """测试初始化"""
        self.assertIsNotNone(self.analyzer)
        self.assertEqual(self.analyzer.binary_path, None)
        self.assertEqual(self.analyzer.suspicious_casts, [])
        self.assertEqual(self.analyzer.vtable_hijack_risk, [])
    
    def test_set_binary_path(self):
        """测试设置二进制路径"""
        test_path = '/tmp/test_binary'
        analyzer = TypeConfusionAnalyzer(test_path)
        self.assertEqual(analyzer.binary_path, test_path)
    
    def test_is_suspicious_conversion(self):
        """测试判断可疑类型转换"""
        self.assertTrue(self.analyzer._is_suspicious_conversion('void*', 'ptr'))
        self.assertTrue(self.analyzer._is_suspicious_conversion('char*', 'buffer'))
        self.assertTrue(self.analyzer._is_suspicious_conversion('unsigned char*', 'data'))
        self.assertFalse(self.analyzer._is_suspicious_conversion('int', 'value'))
    
    def test_is_high_risk(self):
        """测试判断高风险类型转换"""
        self.assertTrue(self.analyzer._is_high_risk('void*'))
        self.assertTrue(self.analyzer._is_high_risk('char*'))
        self.assertTrue(self.analyzer._is_high_risk('unsigned char*'))
        self.assertFalse(self.analyzer._is_high_risk('int*'))
    
    def test_find_suspicious_casts(self):
        """测试查找可疑类型转换"""
        pseudocode = """
            void* ptr = static_cast<void*>(buffer);
            char* str = reinterpret_cast<char*>(data);
            int val = (int)ptr;
        """
        casts = self.analyzer._find_suspicious_casts('test_func', pseudocode)
        
        self.assertEqual(len(casts), 3)
        self.assertEqual(casts[0]['cast_type'], 'static_cast')
        self.assertEqual(casts[1]['cast_type'], 'reinterpret_cast')
        self.assertEqual(casts[2]['cast_type'], 'c_style_cast')
    
    def test_extract_types_from_pseudocode(self):
        """测试从伪代码提取类型信息"""
        pseudocode = """
            class MyClass
            void method1();
            void method2();
            MyClass* obj = new MyClass();
            obj->method1();
        """
        types = self.analyzer._extract_types_from_pseudocode(pseudocode)
        
        self.assertIn('MyClass', types)
        self.assertEqual(types['MyClass']['type'], 'class')
    
    def test_calculate_risk_level(self):
        """测试计算风险等级"""
        self.analyzer.suspicious_casts = []
        self.analyzer.vtable_hijack_risk = []
        self.assertEqual(self.analyzer._calculate_risk_level(), 'none')
        
        self.analyzer.suspicious_casts = [{'risk': 'low'}]
        self.assertEqual(self.analyzer._calculate_risk_level(), 'low')
        
        self.analyzer.suspicious_casts = [{'risk': 'high'}]
        self.assertEqual(self.analyzer._calculate_risk_level(), 'medium')
        
        self.analyzer.suspicious_casts = [{'risk': 'high'}, {'risk': 'high'}]
        self.assertEqual(self.analyzer._calculate_risk_level(), 'high')
        
        self.analyzer.suspicious_casts = []
        self.analyzer.vtable_hijack_risk = [{}]
        self.assertEqual(self.analyzer._calculate_risk_level(), 'high')
    
    def test_generate_exploit(self):
        """测试生成利用代码"""
        vuln_info = {
            'function': 'vuln_func',
            'target_type': 'void*'
        }
        exploit = self.analyzer.generate_exploit(vuln_info)
        
        self.assertIsInstance(exploit, str)
        self.assertIn('Type Confusion', exploit)
        self.assertIn('vtable', exploit)
    
    def test_analyze(self):
        """测试分析方法"""
        analyzer = TypeConfusionAnalyzer('/tmp/nonexistent')
        result = analyzer.analyze()
        
        self.assertIsInstance(result, dict)
        self.assertIn('suspicious_casts', result)
        self.assertIn('vtable_hijack_risk', result)
        self.assertIn('risk_level', result)

if __name__ == '__main__':
    unittest.main()