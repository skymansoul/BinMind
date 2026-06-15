#!/usr/bin/env python3
"""
C++虚函数表恢复模块测试
"""
import os
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.cpp_vtbl_recovery import (
    CppVtblRecovery, VtblRecoveryResult, VtableInfo, VtblEntry,
    ClassInfo, RttiInfo, VtblAnalysisStatus
)


class TestCppVtblRecovery(unittest.TestCase):
    """C++虚表恢复器测试类"""

    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.recoverer = CppVtblRecovery(output_dir=self.temp_dir)

    def tearDown(self):
        """测试后清理"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_vtbl_analysis_status_enum(self):
        """测试分析状态枚举"""
        self.assertEqual(VtblAnalysisStatus.SUCCESS.value, 'success')
        self.assertEqual(VtblAnalysisStatus.PARTIAL.value, 'partial')
        self.assertEqual(VtblAnalysisStatus.FAILED.value, 'failed')

    def test_vtbl_entry_dataclass(self):
        """测试 VtblEntry 数据类"""
        entry = VtblEntry(
            vtable_addr=0x100000,
            entry_index=0,
            function_addr=0x401000,
            function_name='virtual_func',
            is_overridden=False,
            class_name='TestClass'
        )
        
        self.assertEqual(entry.vtable_addr, 0x100000)
        self.assertEqual(entry.entry_index, 0)
        self.assertEqual(entry.function_name, 'virtual_func')

    def test_vtbl_entry_to_dict(self):
        """测试 VtblEntry 转换为字典"""
        entry = VtblEntry(
            vtable_addr=0x200000,
            entry_index=1,
            function_addr=0x402000,
            function_name='func2',
            is_overridden=True
        )
        
        result = entry.to_dict()
        
        self.assertIn('vtable_addr', result)
        self.assertIn('entry_index', result)
        self.assertEqual(result['entry_index'], 1)
        self.assertTrue(result['is_overridden'])

    def test_vtable_info_dataclass(self):
        """测试 VtableInfo 数据类"""
        entries = [
            VtblEntry(vtable_addr=0x100000, entry_index=0, function_addr=0x401000),
            VtblEntry(vtable_addr=0x100000, entry_index=1, function_addr=0x401010)
        ]
        
        vtable = VtableInfo(
            vtable_addr=0x100000,
            entries=entries,
            class_name='MyClass',
            is_primary=True
        )
        
        self.assertEqual(vtable.class_name, 'MyClass')
        self.assertEqual(len(vtable.entries), 2)
        self.assertTrue(vtable.is_primary)

    def test_vtable_info_to_dict(self):
        """测试 VtableInfo 转换为字典"""
        entries = [VtblEntry(vtable_addr=0x100000, entry_index=0, function_addr=0x401000)]
        vtable = VtableInfo(
            vtable_addr=0x100000,
            entries=entries,
            class_name='Test'
        )
        
        result = vtable.to_dict()
        
        self.assertIn('vtable_addr', result)
        self.assertIn('entries', result)
        self.assertEqual(len(result['entries']), 1)

    def test_class_info_dataclass(self):
        """测试 ClassInfo 数据类"""
        entries = [VtblEntry(vtable_addr=0x100000, entry_index=0, function_addr=0x401000)]
        vtable = VtableInfo(vtable_addr=0x100000, entries=entries)
        
        class_info = ClassInfo(
            name='DerivedClass',
            vtable_addr=0x100000,
            vtable=vtable,
            parent_classes=['BaseClass'],
            child_classes=['ConcreteClass'],
            size=1024,
            constructor_addr=0x401000,
            destructor_addr=0x401050,
            has_virtual_methods=True,
            potential_vtable_hijack=True
        )
        
        self.assertEqual(class_info.name, 'DerivedClass')
        self.assertEqual(len(class_info.parent_classes), 1)
        self.assertTrue(class_info.potential_vtable_hijack)

    def test_class_info_to_dict(self):
        """测试 ClassInfo 转换为字典"""
        entries = [VtblEntry(vtable_addr=0x100000, entry_index=0, function_addr=0x401000)]
        vtable = VtableInfo(vtable_addr=0x100000, entries=entries)
        
        class_info = ClassInfo(
            name='TestClass',
            vtable_addr=0x100000,
            vtable=vtable
        )
        
        result = class_info.to_dict()
        
        self.assertIn('name', result)
        self.assertIn('vtable_addr', result)
        self.assertIn('vtable', result)

    def test_rtti_info_dataclass(self):
        """测试 RttiInfo 数据类"""
        rtti = RttiInfo(
            type_info_addr=0x200000,
            class_name='MyClass',
            base_classes=[{'name': 'Base', 'offset': 0}],
            source_vtable=0x100000
        )
        
        self.assertEqual(rtti.class_name, 'MyClass')
        self.assertEqual(len(rtti.base_classes), 1)

    def test_rtti_info_to_dict(self):
        """测试 RttiInfo 转换为字典"""
        rtti = RttiInfo(
            type_info_addr=0x200000,
            class_name='Test',
            base_classes=[]
        )
        
        result = rtti.to_dict()
        
        self.assertIn('type_info_addr', result)
        self.assertIn('class_name', result)

    def test_recover_vtbls(self):
        """测试恢复虚表"""
        # 创建一个模拟的二进制文件
        test_file = os.path.join(self.temp_dir, 'test_binary.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * 1024)
        
        result = self.recoverer.recover_vtbls(test_file)
        
        self.assertIsInstance(result, VtblRecoveryResult)
        self.assertEqual(result.status, VtblAnalysisStatus.SUCCESS)
        self.assertGreaterEqual(len(result.vtables), 1)

    def test_generate_uml_diagram(self):
        """测试生成UML图"""
        test_file = os.path.join(self.temp_dir, 'test_binary.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * 1024)
        
        result = self.recoverer.recover_vtbls(test_file)
        dot_content = self.recoverer.generate_uml_diagram(result)
        
        self.assertIn('digraph', dot_content)
        self.assertIn('ClassHierarchy', dot_content)

    def test_generate_report(self):
        """测试生成报告"""
        test_file = os.path.join(self.temp_dir, 'test_binary.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * 1024)
        
        result = self.recoverer.recover_vtbls(test_file)
        report = self.recoverer.generate_report(result)
        
        self.assertIn('C++虚函数表分析报告', report)
        self.assertIn('test_binary.bin', report)

    def test_save_result(self):
        """测试保存结果"""
        test_file = os.path.join(self.temp_dir, 'test_binary.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * 1024)
        
        result = self.recoverer.recover_vtbls(test_file)
        saved_path = self.recoverer.save_result(result, 'test_vtbl')
        
        self.assertTrue(os.path.exists(saved_path))
        self.assertTrue(saved_path.endswith('.json'))


class TestVtblRecoveryResult(unittest.TestCase):
    """VtblRecoveryResult 数据类测试"""

    def test_vtbl_recovery_result_dataclass(self):
        """测试虚表恢复结果"""
        vtable = VtableInfo(
            vtable_addr=0x100000,
            entries=[VtblEntry(vtable_addr=0x100000, entry_index=0, function_addr=0x401000)]
        )
        
        result = VtblRecoveryResult(
            binary_path='/test/bin',
            status=VtblAnalysisStatus.SUCCESS,
            vtables=[vtable],
            classes=[],
            rtti_info=[],
            inheritance_graph={},
            potential_hijack_classes=['TestClass'],
            timestamp='2024-01-01',
            errors=[]
        )
        
        self.assertEqual(len(result.vtables), 1)
        self.assertEqual(len(result.potential_hijack_classes), 1)

    def test_vtbl_recovery_result_to_dict(self):
        """测试转换为字典"""
        result = VtblRecoveryResult(
            binary_path='/test/bin',
            status=VtblAnalysisStatus.SUCCESS,
            vtables=[],
            classes=[],
            rtti_info=[],
            inheritance_graph={},
            potential_hijack_classes=[],
            timestamp='2024-01-01'
        )
        
        data = result.to_dict()
        
        self.assertIn('binary_path', data)
        self.assertIn('status', data)
        self.assertIn('vtables', data)


if __name__ == '__main__':
    unittest.main()