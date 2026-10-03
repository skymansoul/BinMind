# -*- coding: utf-8 -*-

import unittest
import os
import tempfile
import struct
from unittest.mock import Mock, patch, MagicMock

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.managed_code_analyzer import (
    ManagedCodeAnalyzer,
    ManagedCodeType,
    MethodInfo,
    ClassInfo,
    ManagedCodeAnalysisResult,
    JAVA_DANGEROUS_METHODS,
    DOTNET_DANGEROUS_METHODS,
    analyze_managed_code,
)


class TestManagedCodeType(unittest.TestCase):

    def test_enum_values(self):
        self.assertEqual(ManagedCodeType.JAVA.value, 'java')
        self.assertEqual(ManagedCodeType.DOTNET.value, 'dotnet')
        self.assertEqual(ManagedCodeType.UNKNOWN.value, 'unknown')

    def test_from_string(self):
        self.assertEqual(ManagedCodeType('java'), ManagedCodeType.JAVA)
        self.assertEqual(ManagedCodeType('dotnet'), ManagedCodeType.DOTNET)


class TestMethodInfo(unittest.TestCase):

    def test_creation(self):
        method = MethodInfo(
            name='testMethod',
            return_type='void',
            parameters=['String param1', 'int param2'],
            bytecode='aload_0\ninvokevirtual',
            is_dangerous=False,
            danger_reasons=[],
        )
        self.assertEqual(method.name, 'testMethod')
        self.assertEqual(method.return_type, 'void')
        self.assertEqual(len(method.parameters), 2)
        self.assertFalse(method.is_dangerous)

    def test_dangerous_flag(self):
        method = MethodInfo(
            name='execCommand',
            return_type='Process',
            parameters=['String cmd'],
            bytecode='invokestatic Runtime.exec',
            is_dangerous=True,
            danger_reasons=['Command execution via Runtime.exec'],
        )
        self.assertTrue(method.is_dangerous)
        self.assertEqual(len(method.danger_reasons), 1)


class TestClassInfo(unittest.TestCase):

    def test_creation(self):
        method = MethodInfo(
            name='main', return_type='void', parameters=[], bytecode=''
        )
        class_info = ClassInfo(
            name='TestClass',
            namespace='com.example',
            methods=[method],
            fields=['private int value'],
            interfaces=['Runnable'],
            is_dangerous=False,
        )
        self.assertEqual(class_info.name, 'TestClass')
        self.assertEqual(len(class_info.methods), 1)
        self.assertFalse(class_info.is_dangerous)


class TestManagedCodeAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = ManagedCodeAnalyzer()
        self.m_tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        if os.path.exists(self.m_tmp):
            shutil.rmtree(self.m_tmp)

    def test_detect_java_magic(self):
        java_file = os.path.join(self.m_tmp, 'test.class')
        with open(java_file, 'wb') as f:
            f.write(struct.pack('>I', 0xCAFEBABE))
            f.write(b'\x00\x00' * 10)
        code_type = self.analyzer._detect_code_type(java_file)
        self.assertEqual(code_type, ManagedCodeType.JAVA)

    def test_detect_unknown_file(self):
        unknown_file = os.path.join(self.m_tmp, 'test.txt')
        with open(unknown_file, 'wb') as f:
            f.write(b'Hello World')
        code_type = self.analyzer._detect_code_type(unknown_file)
        self.assertEqual(code_type, ManagedCodeType.UNKNOWN)

    def test_parse_constant_pool(self):
        pool_data = (
            b'\x00\x01'
            b'\x01'
            b'\x00\x04'
            b'test'
        )
        result = self.analyzer._parse_constant_pool(pool_data)
        self.assertIsInstance(result, dict)

    def test_java_method_danger_check(self):
        bytecode = (
            'invokestatic java/lang/Runtime.exec '
            '(Ljava/lang/String;)Ljava/lang/Process;'
        )
        is_dangerous, reasons = self.analyzer._check_java_method_danger(
            bytecode, 'exec'
        )
        self.assertTrue(is_dangerous)
        self.assertIn('Command execution', reasons[0])

        bytecode = 'invokestatic java/lang/Math.sqrt (D)D'
        is_dangerous, reasons = self.analyzer._check_java_method_danger(
            bytecode, 'sqrt'
        )
        self.assertFalse(is_dangerous)
        self.assertEqual(len(reasons), 0)

    def test_dotnet_method_danger_check(self):
        il_code = 'call System.Diagnostics.Process::Start(string)'
        is_dangerous, reasons = self.analyzer._check_dotnet_method_danger(
            il_code, 'StartProcess'
        )
        self.assertTrue(is_dangerous)

        il_code = (
            'call System.Runtime.Serialization.Formatters.Binary.'
            'BinaryFormatter::Deserialize(stream)'
        )
        is_dangerous, reasons = self.analyzer._check_dotnet_method_danger(
            il_code, 'LoadData'
        )
        self.assertTrue(is_dangerous)

    def test_analyze_nonexistent_file(self):
        result = self.analyzer.analyze('/nonexistent/file.class')
        self.assertEqual(result.code_type, ManagedCodeType.UNKNOWN)
        self.assertIn('File not found', result.error)

    def test_analyze_empty_file(self):
        empty_file = os.path.join(self.m_tmp, 'empty.class')
        with open(empty_file, 'wb') as f:
            pass
        result = self.analyzer.analyze(empty_file)
        self.assertEqual(result.code_type, ManagedCodeType.UNKNOWN)

    def test_get_danger_summary(self):
        method1 = MethodInfo(
            name='exec', return_type='Process', parameters=['String'],
            bytecode='', is_dangerous=True,
            danger_reasons=['Command execution'],
        )
        method2 = MethodInfo(
            name='deserialize', return_type='Object', parameters=['Stream'],
            bytecode='', is_dangerous=True,
            danger_reasons=['Deserialization vulnerability'],
        )
        class_info = ClassInfo(
            name='TestClass', namespace='test',
            methods=[method1, method2], fields=[], interfaces=[],
            is_dangerous=True,
        )
        result = ManagedCodeAnalysisResult(
            code_type=ManagedCodeType.JAVA,
            classes=[class_info],
            dangerous_methods=[method1, method2],
            vulnerabilities=['Command injection', 'Deserialization'],
            error=None,
        )
        summary = self.analyzer.get_danger_summary(result)
        self.assertIn('dangerous_methods', summary)
        self.assertEqual(summary['dangerous_methods'], 2)
        self.assertIn('vulnerabilities', summary)


class TestDangerousMethodsDict(unittest.TestCase):

    def test_java_dangerous_methods_exist(self):
        self.assertIn('Runtime.exec', JAVA_DANGEROUS_METHODS)
        self.assertIn('ObjectInputStream', JAVA_DANGEROUS_METHODS)
        self.assertIn('Class.forName', JAVA_DANGEROUS_METHODS)

    def test_dotnet_dangerous_methods_exist(self):
        self.assertIn('Process.Start', DOTNET_DANGEROUS_METHODS)
        self.assertIn('BinaryFormatter.Deserialize', DOTNET_DANGEROUS_METHODS)
        self.assertIn('Type.InvokeMember', DOTNET_DANGEROUS_METHODS)

    def test_dangerous_methods_severity(self):
        self.assertEqual(
            JAVA_DANGEROUS_METHODS['Runtime.exec']['severity'], 'Critical'
        )
        self.assertEqual(
            DOTNET_DANGEROUS_METHODS['BinaryFormatter.Deserialize']['severity'],
            'Critical',
        )


class TestConvenienceFunction(unittest.TestCase):

    def test_analyze_managed_code(self):
        temp_dir = tempfile.mkdtemp()
        try:
            java_file = os.path.join(temp_dir, 'test.class')
            with open(java_file, 'wb') as f:
                f.write(struct.pack('>I', 0xCAFEBABE))
                f.write(b'\x00\x00' * 10)
            result = analyze_managed_code(java_file)
            self.assertIsInstance(result, ManagedCodeAnalysisResult)
        finally:
            import shutil
            shutil.rmtree(temp_dir)


class TestInputValidation(unittest.TestCase):

    def test_path_traversal_prevention(self):
        analyzer = ManagedCodeAnalyzer()
        result = analyzer.analyze('../../../etc/passwd')
        self.assertIsNotNone(result)

    def test_special_characters_in_path(self):
        analyzer = ManagedCodeAnalyzer()
        result = analyzer.analyze('/tmp/test<>.class')
        self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()
