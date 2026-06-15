#!/usr/bin/env python3
"""
二进制文档生成模块单元测试

测试文档生成器的各项功能。
"""

import os
import sys
import unittest
import tempfile
import json
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.binary_documenter import (
    BinaryDocumenter, DocumenterConfig, FunctionDoc,
    create_documenter
)


class TestDocumenterConfig(unittest.TestCase):
    """
    测试文档生成器配置类
    """
    
    def test_config_init(self):
        """
        测试配置初始化
        """
        config = DocumenterConfig(project_name='test_project')
        self.assertEqual(config.project_name, 'test_project')
        self.assertEqual(config.format, 'markdown')
        self.assertTrue(config.include_pseudocode)
        self.assertTrue(config.include_risk_analysis)
    
    def test_config_validation(self):
        """
        测试配置验证
        """
        config = DocumenterConfig(project_name='test')
        self.assertTrue(config.validate())
        
        config = DocumenterConfig(project_name='test', format='invalid')
        self.assertFalse(config.validate())
    
    def test_config_custom_values(self):
        """
        测试自定义配置值
        """
        config = DocumenterConfig(
            project_name='custom',
            output_dir='/custom/docs',
            format='json',
            include_pseudocode=False,
            language='en-US'
        )
        self.assertEqual(config.output_dir, '/custom/docs')
        self.assertEqual(config.format, 'json')
        self.assertFalse(config.include_pseudocode)
        self.assertEqual(config.language, 'en-US')


class TestFunctionDoc(unittest.TestCase):
    """
    测试函数文档数据类
    """
    
    def test_function_doc_init(self):
        """
        测试函数文档初始化
        """
        func_doc = FunctionDoc(
            name='main',
            address='0x1000',
            description='程序入口函数',
            parameters=[{'name': 'argc', 'type': 'int'}],
            return_value='int',
            calling_convention='cdecl',
            risk_level='Low'
        )
        self.assertEqual(func_doc.name, 'main')
        self.assertEqual(func_doc.address, '0x1000')
        self.assertEqual(func_doc.risk_level, 'Low')
    
    def test_function_doc_to_dict(self):
        """
        测试函数文档转换为字典
        """
        func_doc = FunctionDoc(name='test')
        doc_dict = func_doc.to_dict()
        self.assertIsInstance(doc_dict, dict)
        self.assertEqual(doc_dict['name'], 'test')
    
    def test_function_doc_to_markdown(self):
        """
        测试函数文档转换为Markdown
        """
        func_doc = FunctionDoc(
            name='test_func',
            address='0x1000',
            description='测试函数',
            parameters=[{'name': 'arg1', 'type': 'int', 'description': '参数1'}],
            risk_level='Medium'
        )
        md = func_doc.to_markdown()
        self.assertIn('## test_func', md)
        self.assertIn('0x1000', md)
        self.assertIn('测试函数', md)


class TestBinaryDocumenter(unittest.TestCase):
    """
    测试二进制文档生成器类
    """
    
    def setUp(self):
        """
        设置测试环境
        """
        self.temp_dir = tempfile.mkdtemp()
        self.config = DocumenterConfig(
            project_name='test_project',
            output_dir=self.temp_dir
        )
        self.documenter = BinaryDocumenter(self.config)
    
    def tearDown(self):
        """
        清理测试环境
        """
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_documenter_init(self):
        """
        测试文档生成器初始化
        """
        self.assertIsInstance(self.documenter, BinaryDocumenter)
        self.assertEqual(self.documenter.config.project_name, 'test_project')
    
    def test_load_pseudocode(self):
        """
        测试加载伪代码
        """
        pseudocode = """
        int main(int argc, char** argv) {
            return 0;
        }
        
        void test_func() {
            printf("test");
        }
        """
        self.documenter.load_pseudocode(pseudocode)
        self.assertEqual(self.documenter.pseudocode, pseudocode)
    
    def test_extract_functions(self):
        """
        测试函数提取
        """
        pseudocode = """
        int main() { return 0; }
        void helper() { }
        int calculate(int x) { return x * 2; }
        """
        self.documenter.load_pseudocode(pseudocode)
        functions = self.documenter.extract_functions()
        self.assertGreater(len(functions), 0)
    
    def test_analyze_function(self):
        """
        测试函数分析
        """
        func_info = {
            'name': 'main',
            'return_type': 'int',
            'params': '',
            'body': 'return 0;'
        }
        func_doc = self.documenter.analyze_function(func_info)
        self.assertEqual(func_doc.name, 'main')
        self.assertEqual(func_doc.risk_level, 'Low')
    
    def test_parse_parameters(self):
        """
        测试参数解析
        """
        params_str = 'int argc, char** argv, char* envp'
        params = self.documenter._parse_parameters(params_str)
        self.assertEqual(len(params), 3)
    
    def test_detect_calling_convention(self):
        """
        测试调用约定检测
        """
        func_body = '__stdcall void func() { }'
        convention = self.documenter._detect_calling_convention(func_body)
        self.assertEqual(convention, 'stdcall')
    
    def test_assess_risk_level(self):
        """
        测试风险等级评估
        """
        # 高风险函数
        func_body = 'system("ls"); execvp(...);'
        risk = self.documenter._assess_risk_level('exec_func', func_body)
        self.assertEqual(risk, 'Critical')
        
        # 低风险函数
        func_body = 'printf("hello");'
        risk = self.documenter._assess_risk_level('print_func', func_body)
        self.assertEqual(risk, 'Low')
    
    def test_detect_side_effects(self):
        """
        测试副作用检测
        """
        func_body = 'malloc(100); free(ptr);'
        effects = self.documenter._detect_side_effects(func_body)
        self.assertIn('动态内存分配/释放', effects)
    
    def test_detect_dependencies(self):
        """
        测试依赖检测
        """
        func_body = 'helper(); calculate(x); printf("%d", y);'
        deps = self.documenter._detect_dependencies(func_body)
        self.assertIn('helper', deps)
        self.assertIn('calculate', deps)
    
    def test_generate_all_docs(self):
        """
        测试生成所有文档
        """
        pseudocode = """
        int main() { return 0; }
        void helper() { }
        """
        self.documenter.load_pseudocode(pseudocode)
        docs = self.documenter.generate_all_docs()
        self.assertGreater(len(docs), 0)
    
    def test_generate_document(self):
        """
        测试生成完整文档
        """
        pseudocode = "int main() { return 0; }"
        self.documenter.load_pseudocode(pseudocode)
        self.documenter.generate_all_docs()
        document = self.documenter.generate_document()
        self.assertIn('# test_project', document)
        self.assertIn('## 目录', document)
    
    def test_save_document(self):
        """
        测试保存文档
        """
        pseudocode = "int main() { return 0; }"
        self.documenter.load_pseudocode(pseudocode)
        self.documenter.generate_all_docs()
        
        path = self.documenter.save_document()
        self.assertTrue(os.path.exists(path))
        
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('test_project', content)
    
    def test_save_json(self):
        """
        测试保存JSON文档
        """
        pseudocode = "int main() { return 0; }"
        self.documenter.load_pseudocode(pseudocode)
        self.documenter.generate_all_docs()
        
        path = self.documenter.save_json()
        self.assertTrue(os.path.exists(path))
        
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertIn('functions', data)
    
    def test_get_function_doc(self):
        """
        测试获取指定函数文档
        """
        pseudocode = "int main() { return 0; }"
        self.documenter.load_pseudocode(pseudocode)
        self.documenter.generate_all_docs()
        
        doc = self.documenter.get_function_doc('main')
        self.assertIsNotNone(doc)
        self.assertEqual(doc.name, 'main')
    
    def test_search_functions(self):
        """
        测试搜索函数
        """
        pseudocode = """
        int init() { }
        int calculate_value() { }
        void cleanup() { }
        """
        self.documenter.load_pseudocode(pseudocode)
        self.documenter.generate_all_docs()
        
        results = self.documenter.search_functions('init')
        self.assertGreater(len(results), 0)
    
    def test_analyze_with_ai_results(self):
        """
        测试带AI结果的分析
        """
        pseudocode = "int vulnerable_func(char* buf) { strcpy(buf, input); }"
        ai_results = {
            'vulnerabilities': [{
                'function': 'vulnerable_func',
                'type': 'buffer_overflow',
                'description': 'strcpy可能导致缓冲区溢出'
            }]
        }
        
        self.documenter.load_pseudocode(pseudocode)
        self.documenter.load_ai_analysis(ai_results)
        self.documenter.generate_all_docs()
        
        doc = self.documenter.get_function_doc('vulnerable_func')
        if doc:
            self.assertIn('strcpy', doc.description)


class TestBinaryDocumenterFunctions(unittest.TestCase):
    """
    测试文档生成器便捷函数
    """
    
    def test_create_documenter(self):
        """
        测试创建文档生成器便捷函数
        """
        documenter = create_documenter('test_project')
        self.assertIsInstance(documenter, BinaryDocumenter)
        self.assertEqual(documenter.config.project_name, 'test_project')


if __name__ == '__main__':
    unittest.main(verbosity=2)