import unittest
import os
import json
from modules.test_generator import (
    TestCaseType,
    InputType,
    TestResultType,
    TestInput,
    TestCase,
    TestResult,
    TestSuite,
    TestGenerator
)


class TestTestCaseTypeEnum(unittest.TestCase):
    """TestCaseType枚举测试"""
    
    def test_test_case_type_values(self):
        """测试测试用例类型枚举值"""
        self.assertEqual(TestCaseType.UNIT_TEST.value, "unit_test")
        self.assertEqual(TestCaseType.FUZZ_TEST.value, "fuzz_test")
        self.assertEqual(TestCaseType.SECURITY_TEST.value, "security_test")
        self.assertEqual(TestCaseType.PERFORMANCE_TEST.value, "performance_test")


class TestInputTypeEnum(unittest.TestCase):
    """InputType枚举测试"""
    
    def test_input_type_values(self):
        """测试输入类型枚举值"""
        self.assertEqual(InputType.INTEGER.value, "integer")
        self.assertEqual(InputType.STRING.value, "string")
        self.assertEqual(InputType.BUFFER.value, "buffer")
        self.assertEqual(InputType.POINTER.value, "pointer")


class TestTestResultTypeEnum(unittest.TestCase):
    """TestResultType枚举测试"""
    
    def test_test_result_type_values(self):
        """测试测试结果类型枚举值"""
        self.assertEqual(TestResultType.PASS.value, "pass")
        self.assertEqual(TestResultType.FAIL.value, "fail")
        self.assertEqual(TestResultType.CRASH.value, "crash")
        self.assertEqual(TestResultType.TIMEOUT.value, "timeout")


class TestTestInputDataclass(unittest.TestCase):
    """TestInput数据类测试"""
    
    def test_test_input_creation(self):
        """测试测试输入创建"""
        inp = TestInput(name="param1", input_type=InputType.INTEGER, value=42)
        self.assertEqual(inp.name, "param1")
        self.assertEqual(inp.input_type, InputType.INTEGER)
        self.assertEqual(inp.value, 42)


class TestTestCaseDataclass(unittest.TestCase):
    """TestCase数据类测试"""
    
    def test_test_case_creation(self):
        """测试测试用例创建"""
        inputs = [TestInput(name="param1", input_type=InputType.INTEGER, value=42)]
        test_case = TestCase(
            name="test_case_1",
            test_type=TestCaseType.UNIT_TEST,
            function_name="target_func",
            inputs=inputs,
            description="测试描述"
        )
        self.assertEqual(test_case.name, "test_case_1")
        self.assertEqual(test_case.test_type, TestCaseType.UNIT_TEST)
        self.assertEqual(len(test_case.inputs), 1)


class TestTestResultDataclass(unittest.TestCase):
    """TestResult数据类测试"""
    
    def test_test_result_creation(self):
        """测试测试结果创建"""
        inputs = [TestInput(name="param1", input_type=InputType.INTEGER, value=42)]
        test_case = TestCase(
            name="test_case_1",
            test_type=TestCaseType.UNIT_TEST,
            function_name="target_func",
            inputs=inputs
        )
        result = TestResult(
            test_case=test_case,
            result_type=TestResultType.PASS,
            execution_time=0.1
        )
        self.assertEqual(result.result_type, TestResultType.PASS)
        self.assertEqual(result.execution_time, 0.1)


class TestTestSuiteDataclass(unittest.TestCase):
    """TestSuite数据类测试"""
    
    def test_test_suite_creation(self):
        """测试测试套件创建"""
        suite = TestSuite(
            name="test_suite_1",
            target_binary="test.bin",
            target_functions=["func1", "func2"]
        )
        self.assertEqual(suite.name, "test_suite_1")
        self.assertEqual(suite.target_binary, "test.bin")
        self.assertEqual(len(suite.target_functions), 2)


class TestTestGenerator(unittest.TestCase):
    """TestGenerator测试"""
    
    def setUp(self):
        """设置测试环境"""
        self.generator = TestGenerator()
    
    def test_generate_test_suite(self):
        """测试生成测试套件"""
        suite = self.generator.generate_test_suite("test.bin", ["func1", "func2"], test_count=5)
        self.assertEqual(suite.name, "test.bin_test_suite")
        self.assertEqual(len(suite.test_cases), 10)
    
    def test_generate_fuzz_test_cases(self):
        """测试生成模糊测试用例"""
        cases = self.generator.generate_fuzz_test_cases("target_func", count=10)
        self.assertEqual(len(cases), 10)
    
    def test_generate_security_test_cases(self):
        """测试生成安全测试用例"""
        cases = self.generator.generate_security_test_cases("target_func")
        self.assertEqual(len(cases), 5)
    
    def test_export_to_pytest(self):
        """测试导出为pytest文件"""
        suite = self.generator.generate_test_suite("test.bin", ["func1"], test_count=2)
        output_file = "test_generated.py"
        self.generator.export_to_pytest(suite, output_file)
        
        self.assertTrue(os.path.exists(output_file))
        os.remove(output_file)
    
    def test_export_to_json(self):
        """测试导出为JSON文件"""
        suite = self.generator.generate_test_suite("test.bin", ["func1"], test_count=2)
        output_file = "test_generated.json"
        self.generator.export_to_json(suite, output_file)
        
        self.assertTrue(os.path.exists(output_file))
        
        with open(output_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            self.assertEqual(data["name"], "test.bin_test_suite")
        
        os.remove(output_file)


if __name__ == '__main__':
    unittest.main()
