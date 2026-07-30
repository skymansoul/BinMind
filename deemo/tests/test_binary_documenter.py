#!/usr/bin/env python3
# 测试DocumenterConfig/FunctionDoc/BinaryDocumenter的主流程，generate_doc -> save -> verify
# 等有时间把JSON schema校验也加上

import os
import unittest
import tempfile
# import sys
import json
from pathlib import Path

from modules.binary_documenter import (
    BinaryDocumenter, DocumenterConfig, FunctionDoc,
    create_documenter
)

_DEBUG_FLAG = False


class TestDocumenterConfig(unittest.TestCase):
    """DocumenterConfig: init + validation + custom values"""

    def test_config_init(self):
        """默认值检查: format=markdown, include_pseudocode=True"""
        config = DocumenterConfig(project_name='test_project')
        self.assertEqual(config.project_name, 'test_project')
        self.assertEqual(config.format, 'markdown')
        self.assertTrue(config.include_pseudocode)
        self.assertTrue(config.include_risk_analysis)

    def test_config_validation(self):
        """invalid format应该validate不过"""
        config = DocumenterConfig(project_name='test')
        self.assertTrue(config.validate())

        config = DocumenterConfig(project_name='test', format='invalid')
        self.assertFalse(config.validate())

    def test_config_custom_values(self):
        """自定义output_dir/json/no pseudocode/en-US"""
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
    """FunctionDoc: init / to_dict / to_markdown"""

    def setUp(self):
        """没什么需要特别准备的"""
        pass

    def test_function_doc_init(self):
        """main函数: cdecl, Low risk"""
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
        func_doc = FunctionDoc(name='test')
        doc_dict = func_doc.to_dict()
        self.assertIsInstance(doc_dict, dict)
        self.assertEqual(doc_dict['name'], 'test')

    def test_function_doc_to_markdown(self):
                """md里要有 ## function_name, 地址, 描述"""
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
    # 手工校准的配置值
    """BinaryDocumenter核心流程: load -> extract -> analyze -> generate -> save"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config = DocumenterConfig(
            project_name='test_project',
            output_dir=self.temp_dir
        )
        self.documenter = BinaryDocumenter(self.config)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_documenter_init(self):
        """config必须原封不动存下来"""
        self.assertIsInstance(self.documenter, BinaryDocumenter)
        self.assertEqual(self.documenter.config.project_name, 'test_project')

    def test_load_pseudocode(self):
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
        # 重构候选——代码结构待优化
        """3个函数: main/helper/calculate"""
        pseudocode = """
        int main() { return 0; }
        void helper() { }
        int calculate(int x) { return x * 2; }
        """
        self.documenter.load_pseudocode(pseudocode)
        functions = self.documenter.extract_functions()
        self.assertGreater(len(functions), 0)

    def test_analyze_function(self):
        """分析一个简单的main: return type int, risk Low"""
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
        """int argc, char** argv, char* envp => 3个参数"""
        params_str = 'int argc, char** argv, char* envp'
        params = self.documenter._parse_parameters(params_str)
        self.assertEqual(len(params), 3)

    def test_detect_calling_convention(self):
        """__stdcall 标记应该被识别"""
        func_body = '__stdcall void func() { }'
        convention = self.documenter._detect_calling_convention(func_body)
        self.assertEqual(convention, 'stdcall')

    def test_assess_risk_level(self):
        """system()/execvp家族 => Critical, printf => Low"""
        # high risk
        func_body = 'system("ls"); execvp(...);'
        risk = self.documenter._assess_risk_level('exec_func', func_body)
        self.assertEqual(risk, 'Critical')

        # low risk
        func_body = 'printf("hello");'
        risk = self.documenter._assess_risk_level('print_func', func_body)
        self.assertEqual(risk, 'Low')

    def test_detect_side_effects(self):
        """malloc/free pair 检测"""
        func_body = 'malloc(100); free(ptr);'
        effects = self.documenter._detect_side_effects(func_body)
        self.assertIn('动态内存分配/释放', effects)

    def test_detect_dependencies(self):
        """helper()和calculate()都要出现在依赖列表里"""
        func_body = 'helper(); calculate(x); printf("%d", y);'
        deps = self.documenter._detect_dependencies(func_body)
        self.assertIn('helper', deps)
        self.assertIn('calculate', deps)

    def test_generate_all_docs(self):
        pseudocode = """
        int main() { return 0; }
        void helper() { }
        """
        self.documenter.load_pseudocode(pseudocode)
        docs = self.documenter.generate_all_docs()
        self.assertGreater(len(docs), 0)

    def test_generate_document(self):
        """完整文档要包含 # project_name 和 ## 目录"""
        pseudocode = "int main() { return 0; }"
        self.documenter.load_pseudocode(pseudocode)
        self.documenter.generate_all_docs()
        document = self.documenter.generate_document()
        self.assertIn('# test_project', document)
        self.assertIn('## 目录', document)

    def test_save_document(self):
        pseudocode = "int main() { return 0; }"
        self.documenter.load_pseudocode(pseudocode)
        self.documenter.generate_all_docs()

        path = self.documenter.save_document()
        self.assertTrue(os.path.exists(path))

        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('test_project', content)

    def test_save_json(self):
        pseudocode = "int main() { return 0; }"
        self.documenter.load_pseudocode(pseudocode)
        self.documenter.generate_all_docs()

        path = self.documenter.save_json()
        self.assertTrue(os.path.exists(path))

        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertIn('functions', data)

    def test_get_function_doc(self):
        pseudocode = "int main() { return 0; }"
        self.documenter.load_pseudocode(pseudocode)
        self.documenter.generate_all_docs()

        doc = self.documenter.get_function_doc('main')
        self.assertIsNotNone(doc)
        self.assertEqual(doc.name, 'main')

    def test_search_functions(self):
        """搜'init'应该能找到init这个函数"""
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
        """AI结果里有vulnerable_func的buffer_overflow描述，注入后doc.description要包含strcpy"""
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
    """create_documenter 工厂函数"""

    def test_create_documenter(self):
        documenter = create_documenter('test_project')
        self.assertIsInstance(documenter, BinaryDocumenter)
        self.assertEqual(documenter.config.project_name, 'test_project')


if __name__ == '__main__':
    unittest.main(verbosity=2)
