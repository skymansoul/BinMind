#!/usr/bin/env python3
"""
二进制测试生成模块测试
"""
import os
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.test_generator import (
    BinaryTestGenerator, TestSuite, TestCase, FunctionSignature,
    FunctionParameter, TestOutputLanguage, ParameterType
)


class TestBinaryTestGenerator(unittest.TestCase):
    """二进制测试生成器测试类"""

    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.generator = BinaryTestGenerator(output_dir=self.temp_dir)

    def tearDown(self):
        """测试后清理"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_test_output_language_enum(self):
        """测试输出语言枚举"""
        self.assertEqual(TestOutputLanguage.C.value, 'c')
        self.assertEqual(TestOutputLanguage.PYTHON.value, 'python')
        self.assertEqual(TestOutputLanguage.FUZZER.value, 'fuzzer')

    def test_parameter_type_enum(self):
        """测试参数类型枚举"""
        self.assertEqual(ParameterType.INT.value, 'int')
        self.assertEqual(ParameterType.UINT.value, 'uint')
        self.assertEqual(ParameterType.STRING.value, 'string')
        self.assertEqual(ParameterType.POINTER.value, 'pointer')
        self.assertEqual(ParameterType.VOID.value, 'void')

    def test_function_parameter_dataclass(self):
        """测试 FunctionParameter 数据类"""
        param = FunctionParameter(
            name='buf',
            type=ParameterType.POINTER,
            is_pointer=True
        )
        
        self.assertEqual(param.name, 'buf')
        self.assertEqual(param.type, ParameterType.POINTER)
        self.assertTrue(param.is_pointer)

    def test_function_parameter_to_dict(self):
        """测试 FunctionParameter 转换为字典"""
        param = FunctionParameter(
            name='size',
            type=ParameterType.UINT,
            size=4
        )
        
        result = param.to_dict()
        
        self.assertIn('name', result)
        self.assertIn('type', result)
        self.assertIn('size', result)
        self.assertEqual(result['type'], 'uint')

    def test_function_signature_dataclass(self):
        """测试 FunctionSignature 数据类"""
        params = [
            FunctionParameter(name='arg1', type=ParameterType.INT),
            FunctionParameter(name='arg2', type=ParameterType.STRING, is_pointer=True)
        ]
        
        signature = FunctionSignature(
            name='my_func',
            return_type=ParameterType.INT,
            parameters=params,
            address=0x401000
        )
        
        self.assertEqual(signature.name, 'my_func')
        self.assertEqual(len(signature.parameters), 2)
        self.assertEqual(signature.address, 0x401000)

    def test_function_signature_to_dict(self):
        """测试 FunctionSignature 转换为字典"""
        signature = FunctionSignature(
            name='test_func',
            return_type=ParameterType.VOID,
            parameters=[],
            address=0x402000
        )
        
        result = signature.to_dict()
        
        self.assertIn('name', result)
        self.assertIn('return_type', result)
        self.assertEqual(result['address'], '0x402000')

    def test_test_case_dataclass(self):
        """测试 TestCase 数据类"""
        case = TestCase(
            function_name='test_func',
            parameters=[1, 'test'],
            expected_result=0,
            description='边界测试',
            test_type='boundary'
        )
        
        self.assertEqual(case.function_name, 'test_func')
        self.assertEqual(len(case.parameters), 2)
        self.assertEqual(case.test_type, 'boundary')

    def test_test_case_to_dict(self):
        """测试 TestCase 转换为字典"""
        case = TestCase(
            function_name='func',
            parameters=[42],
            expected_result=42,
            description='测试'
        )
        
        result = case.to_dict()
        
        self.assertIn('function_name', result)
        self.assertIn('parameters', result)
        self.assertEqual(result['expected_result'], 42)

    def test_extract_function_signatures(self):
        """测试提取函数签名"""
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * 100)
        
        signatures = self.generator.extract_function_signatures(test_file)
        
        self.assertGreater(len(signatures), 0)
        for sig in signatures:
            self.assertIsInstance(sig, FunctionSignature)

    def test_generate_test_cases(self):
        """测试生成测试用例"""
        signature = FunctionSignature(
            name='test_func',
            return_type=ParameterType.INT,
            parameters=[
                FunctionParameter(name='x', type=ParameterType.INT),
                FunctionParameter(name='y', type=ParameterType.UINT)
            ]
        )
        
        cases = self.generator.generate_test_cases(signature, num_cases=3)
        
        self.assertEqual(len(cases), 3)
        for case in cases:
            self.assertEqual(case.function_name, 'test_func')
            self.assertEqual(len(case.parameters), 2)

    def test_generate_c_test_code(self):
        """测试生成C测试代码"""
        signatures = [
            FunctionSignature(
                name='add',
                return_type=ParameterType.INT,
                parameters=[
                    FunctionParameter(name='a', type=ParameterType.INT),
                    FunctionParameter(name='b', type=ParameterType.INT)
                ]
            )
        ]
        
        cases = [
            TestCase(function_name='add', parameters=[1, 2], expected_result=3)
        ]
        
        code = self.generator.generate_c_test_code(signatures, cases)
        
        self.assertIn('#include', code)
        self.assertIn('add', code)
        self.assertIn('extern', code)

    def test_generate_python_test_code(self):
        """测试生成Python测试代码"""
        signatures = [
            FunctionSignature(
                name='test',
                return_type=ParameterType.INT,
                parameters=[FunctionParameter(name='x', type=ParameterType.INT)]
            )
        ]
        
        cases = [TestCase(function_name='test', parameters=[10])]
        
        code = self.generator.generate_python_test_code(signatures, cases)
        
        self.assertIn('import ctypes', code)
        self.assertIn('unittest', code)
        self.assertIn('test', code)

    def test_generate_fuzz_harness(self):
        """测试生成Fuzz harness"""
        signatures = [
            FunctionSignature(
                name='process',
                return_type=ParameterType.INT,
                parameters=[
                    FunctionParameter(name='buf', type=ParameterType.POINTER, is_pointer=True),
                    FunctionParameter(name='len', type=ParameterType.UINT)
                ]
            )
        ]
        
        code = self.generator.generate_fuzz_harness(signatures)
        
        self.assertIn('LLVMFuzzerTestOneInput', code)
        self.assertIn('process', code)

    def test_generate_tests(self):
        """测试生成测试套件"""
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * 100)
        
        suite = self.generator.generate_tests(test_file, TestOutputLanguage.C)
        
        self.assertIsInstance(suite, TestSuite)
        self.assertGreater(len(suite.functions), 0)
        self.assertGreater(len(suite.test_cases), 0)

    def test_generate_report(self):
        """测试生成报告"""
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * 100)
        
        suite = self.generator.generate_tests(test_file, TestOutputLanguage.C)
        report = self.generator.generate_report(suite)
        
        self.assertIn('二进制测试生成报告', report)
        self.assertIn('test.bin', report)

    def test_save_result(self):
        """测试保存结果"""
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * 100)
        
        suite = self.generator.generate_tests(test_file, TestOutputLanguage.C)
        saved_path = self.generator.save_result(suite, 'test_tests')
        
        self.assertTrue(os.path.exists(saved_path))
        self.assertTrue(saved_path.endswith('.json'))


class TestTestSuite(unittest.TestCase):
    """TestSuite 数据类测试"""

    def test_test_suite_dataclass(self):
        """测试测试套件"""
        signature = FunctionSignature(
            name='func',
            return_type=ParameterType.INT,
            parameters=[]
        )
        
        case = TestCase(function_name='func', parameters=[])
        
        suite = TestSuite(
            binary_path='/test/bin',
            functions=[signature],
            test_cases=[case],
            timestamp='2024-01-01'
        )
        
        self.assertEqual(len(suite.functions), 1)
        self.assertEqual(len(suite.test_cases), 1)

    def test_test_suite_to_dict(self):
        """测试转换为字典"""
        suite = TestSuite(
            binary_path='/test/bin',
            functions=[],
            test_cases=[],
            timestamp='2024-01-01'
        )
        
        data = suite.to_dict()
        
        self.assertIn('binary_path', data)
        self.assertIn('functions', data)
        self.assertIn('test_cases', data)


if __name__ == '__main__':
    unittest.main()