#!/usr/bin/env python3
"""
托管代码分析器单元测试

测试 ManagedCodeAnalyzer 类的各项功能
"""
import unittest
import os
import tempfile
import struct
from unittest.mock import Mock, patch, MagicMock

# 添加项目根目录到路径
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
    analyze_managed_code
)


class TestManagedCodeType(unittest.TestCase):
    """测试托管代码类型枚举"""
    
    def test_code_type_values(self):
        """测试枚举值"""
        self.assertEqual(ManagedCodeType.JAVA.value, 'java')
        self.assertEqual(ManagedCodeType.DOTNET.value, 'dotnet')
        self.assertEqual(ManagedCodeType.UNKNOWN.value, 'unknown')
    
    def test_code_type_from_string(self):
        """测试字符串转换"""
        self.assertEqual(ManagedCodeType('java'), ManagedCodeType.JAVA)
        self.assertEqual(ManagedCodeType('dotnet'), ManagedCodeType.DOTNET)


class TestMethodInfo(unittest.TestCase):
    """测试方法信息数据类"""
    
    def test_method_info_creation(self):
        """测试创建方法信息"""
        method = MethodInfo(
            name='testMethod',
            return_type='void',
            parameters=['String param1', 'int param2'],
            bytecode='aload_0\ninvokevirtual',
            is_dangerous=False,
            danger_reasons=[]
        )
        self.assertEqual(method.name, 'testMethod')
        self.assertEqual(method.return_type, 'void')
        self.assertEqual(len(method.parameters), 2)
        self.assertFalse(method.is_dangerous)
    
    def test_method_info_dangerous(self):
        """测试危险方法标记"""
        method = MethodInfo(
            name='execCommand',
            return_type='Process',
            parameters=['String cmd'],
            bytecode='invokestatic Runtime.exec',
            is_dangerous=True,
            danger_reasons=['Command execution via Runtime.exec']
        )
        self.assertTrue(method.is_dangerous)
        self.assertEqual(len(method.danger_reasons), 1)


class TestClassInfo(unittest.TestCase):
    """测试类信息数据类"""
    
    def test_class_info_creation(self):
        """测试创建类信息"""
        method = MethodInfo(name='main', return_type='void', parameters=[], bytecode='')
        class_info = ClassInfo(
            name='TestClass',
            namespace='com.example',
            methods=[method],
            fields=['private int value'],
            interfaces=['Runnable'],
            is_dangerous=False
        )
        self.assertEqual(class_info.name, 'TestClass')
        self.assertEqual(len(class_info.methods), 1)
        self.assertFalse(class_info.is_dangerous)


class TestManagedCodeAnalyzer(unittest.TestCase):
    """测试托管代码分析器"""
    
    def setUp(self):
        """设置测试环境"""
        self.analyzer = ManagedCodeAnalyzer()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """清理测试环境"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_detect_java_magic_number(self):
        """测试Java魔数检测"""
        # 创建模拟Java class文件（魔数 0xCAFEBABE）
        java_file = os.path.join(self.temp_dir, 'test.class')
        with open(java_file, 'wb') as f:
            f.write(struct.pack('>I', 0xCAFEBABE))
            f.write(b'\x00\x00' * 10)  # 填充
        
        code_type = self.analyzer._detect_code_type(java_file)
        self.assertEqual(code_type, ManagedCodeType.JAVA)
    
    def test_detect_unknown_file(self):
        """测试未知文件类型检测"""
        unknown_file = os.path.join(self.temp_dir, 'test.txt')
        with open(unknown_file, 'wb') as f:
            f.write(b'Hello World')
        
        code_type = self.analyzer._detect_code_type(unknown_file)
        self.assertEqual(code_type, ManagedCodeType.UNKNOWN)
    
    def test_parse_constant_pool(self):
        """测试常量池解析"""
        # 创建简单的常量池数据
        # 常量池项: tag + data
        # ConstantClass: tag=7, name_index
        # ConstantUtf8: tag=1, length + bytes
        pool_data = (
            b'\x00\x01'  # constant_pool_count = 1
            b'\x01'      # tag = CONSTANT_Utf8
            b'\x00\x04'  # length = 4
            b'test'      # bytes
        )
        
        result = self.analyzer._parse_constant_pool(pool_data)
        self.assertIsInstance(result, dict)
    
    def test_check_java_method_danger(self):
        """测试Java方法危险检测"""
        # 测试Runtime.exec
        bytecode = 'invokestatic java/lang/Runtime.exec (Ljava/lang/String;)Ljava/lang/Process;'
        is_dangerous, reasons = self.analyzer._check_java_method_danger(bytecode, 'exec')
        self.assertTrue(is_dangerous)
        self.assertIn('Command execution', reasons[0])
        
        # 测试安全方法
        bytecode = 'invokestatic java/lang/Math.sqrt (D)D'
        is_dangerous, reasons = self.analyzer._check_java_method_danger(bytecode, 'sqrt')
        self.assertFalse(is_dangerous)
        self.assertEqual(len(reasons), 0)
    
    def test_check_dotnet_method_danger(self):
        """测试.NET方法危险检测"""
        # 测试Process.Start
        il_code = 'call System.Diagnostics.Process::Start(string)'
        is_dangerous, reasons = self.analyzer._check_dotnet_method_danger(il_code, 'StartProcess')
        self.assertTrue(is_dangerous)
        
        # 测试BinaryFormatter.Deserialize
        il_code = 'call System.Runtime.Serialization.Formatters.Binary.BinaryFormatter::Deserialize(stream)'
        is_dangerous, reasons = self.analyzer._check_dotnet_method_danger(il_code, 'LoadData')
        self.assertTrue(is_dangerous)
    
    def test_analyze_nonexistent_file(self):
        """测试分析不存在文件"""
        result = self.analyzer.analyze('/nonexistent/file.class')
        self.assertEqual(result.code_type, ManagedCodeType.UNKNOWN)
        self.assertIn('File not found', result.error)
    
    def test_analyze_empty_file(self):
        """测试分析空文件"""
        empty_file = os.path.join(self.temp_dir, 'empty.class')
        with open(empty_file, 'wb') as f:
            pass
        
        result = self.analyzer.analyze(empty_file)
        self.assertEqual(result.code_type, ManagedCodeType.UNKNOWN)
    
    def test_get_danger_summary(self):
        """测试获取危险摘要"""
        method1 = MethodInfo(
            name='exec', return_type='Process', parameters=['String'],
            bytecode='', is_dangerous=True,
            danger_reasons=['Command execution']
        )
        method2 = MethodInfo(
            name='deserialize', return_type='Object', parameters=['Stream'],
            bytecode='', is_dangerous=True,
            danger_reasons=['Deserialization vulnerability']
        )
        
        class_info = ClassInfo(
            name='TestClass', namespace='test',
            methods=[method1, method2], fields=[], interfaces=[],
            is_dangerous=True
        )
        
        result = ManagedCodeAnalysisResult(
            code_type=ManagedCodeType.JAVA,
            classes=[class_info],
            dangerous_methods=[method1, method2],
            vulnerabilities=['Command injection', 'Deserialization'],
            error=None
        )
        
        summary = self.analyzer.get_danger_summary(result)
        self.assertIn('dangerous_methods', summary)
        self.assertEqual(summary['dangerous_methods'], 2)
        self.assertIn('vulnerabilities', summary)


class TestDangerousMethodsDict(unittest.TestCase):
    """测试危险方法字典"""
    
    def test_java_dangerous_methods_exist(self):
        """测试Java危险方法字典存在"""
        self.assertIn('Runtime.exec', JAVA_DANGEROUS_METHODS)
        self.assertIn('ObjectInputStream', JAVA_DANGEROUS_METHODS)
        self.assertIn('Class.forName', JAVA_DANGEROUS_METHODS)
    
    def test_dotnet_dangerous_methods_exist(self):
        """测试.NET危险方法字典存在"""
        self.assertIn('Process.Start', DOTNET_DANGEROUS_METHODS)
        self.assertIn('BinaryFormatter.Deserialize', DOTNET_DANGEROUS_METHODS)
        self.assertIn('Type.InvokeMember', DOTNET_DANGEROUS_METHODS)
    
    def test_dangerous_methods_severity(self):
        """测试危险方法严重程度"""
        self.assertEqual(JAVA_DANGEROUS_METHODS['Runtime.exec']['severity'], 'Critical')
        self.assertEqual(DOTNET_DANGEROUS_METHODS['BinaryFormatter.Deserialize']['severity'], 'Critical')


class TestConvenienceFunction(unittest.TestCase):
    """测试便捷函数"""
    
    def test_analyze_managed_code_function(self):
        """测试analyze_managed_code便捷函数"""
        # 创建测试文件
        temp_dir = tempfile.mkdtemp()
        java_file = os.path.join(temp_dir, 'test.class')
        with open(java_file, 'wb') as f:
            f.write(struct.pack('>I', 0xCAFEBABE))
            f.write(b'\x00\x00' * 10)
        
        result = analyze_managed_code(java_file)
        self.assertIsInstance(result, ManagedCodeAnalysisResult)
        
        # 清理
        import shutil
        shutil.rmtree(temp_dir)


class TestInputValidation(unittest.TestCase):
    """测试输入校验"""
    
    def test_path_traversal_prevention(self):
        """测试路径遍历防护"""
        analyzer = ManagedCodeAnalyzer()
        
        # 尝试路径遍历
        malicious_path = '../../../etc/passwd'
        result = analyzer.analyze(malicious_path)
        # 应该安全处理，不泄露系统文件
        self.assertIsNotNone(result)
    
    def test_special_characters_in_path(self):
        """测试路径特殊字符处理"""
        analyzer = ManagedCodeAnalyzer()
        
        # 特殊字符路径
        special_path = '/tmp/test<>.class'
        result = analyzer.analyze(special_path)
        self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()