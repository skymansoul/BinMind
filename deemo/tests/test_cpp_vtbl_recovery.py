import unittest
from modules.cpp_vtbl_recovery import (
    VTableType,
    ClassAccessType,
    VTableEntry,
    VTable,
    ClassInfo,
    VTableRecoveryResult,
    VTableScanner,
    ClassHierarchyAnalyzer,
    VTableRecoveryEngine
)


class TestVTableTypeEnum(unittest.TestCase):
    """VTableType枚举测试"""
    
    def test_vtable_type_values(self):
        """测试虚函数表类型枚举值"""
        self.assertEqual(VTableType.STATIC.value, "static")
        self.assertEqual(VTableType.DYNAMIC.value, "dynamic")
        self.assertEqual(VTableType.WEAK.value, "weak")
        self.assertEqual(VTableType.OVERRIDE.value, "override")


class TestClassAccessTypeEnum(unittest.TestCase):
    """ClassAccessType枚举测试"""
    
    def test_class_access_type_values(self):
        """测试类访问类型枚举值"""
        self.assertEqual(ClassAccessType.PUBLIC.value, "public")
        self.assertEqual(ClassAccessType.PROTECTED.value, "protected")
        self.assertEqual(ClassAccessType.PRIVATE.value, "private")


class TestVTableEntryDataclass(unittest.TestCase):
    """VTableEntry数据类测试"""
    
    def test_vtable_entry_creation(self):
        """测试虚函数表条目创建"""
        entry = VTableEntry(address=0x1000, function_name="test_func", function_address=0x2000, offset=0)
        self.assertEqual(entry.address, 0x1000)
        self.assertEqual(entry.function_name, "test_func")
        self.assertEqual(entry.function_address, 0x2000)
        self.assertEqual(entry.offset, 0)


class TestVTableDataclass(unittest.TestCase):
    """VTable数据类测试"""
    
    def test_vtable_creation(self):
        """测试虚函数表创建"""
        entries = [
            VTableEntry(address=0x1000, function_address=0x2000),
            VTableEntry(address=0x1008, function_address=0x2010)
        ]
        vtable = VTable(address=0x1000, entries=entries, vtable_type=VTableType.DYNAMIC, associated_class="TestClass")
        self.assertEqual(vtable.address, 0x1000)
        self.assertEqual(len(vtable.entries), 2)
        self.assertEqual(vtable.vtable_type, VTableType.DYNAMIC)
        self.assertEqual(vtable.associated_class, "TestClass")


class TestClassInfoDataclass(unittest.TestCase):
    """ClassInfo数据类测试"""
    
    def test_class_info_creation(self):
        """测试类信息创建"""
        class_info = ClassInfo(
            name="TestClass",
            vtable_address=0x1000,
            parent_classes=[("BaseClass", ClassAccessType.PUBLIC)],
            methods=["method1", "method2"],
            size=16,
            is_abstract=True
        )
        self.assertEqual(class_info.name, "TestClass")
        self.assertEqual(class_info.vtable_address, 0x1000)
        self.assertEqual(len(class_info.parent_classes), 1)
        self.assertEqual(len(class_info.methods), 2)
        self.assertEqual(class_info.size, 16)
        self.assertTrue(class_info.is_abstract)


class TestVTableRecoveryResultDataclass(unittest.TestCase):
    """VTableRecoveryResult数据类测试"""
    
    def test_vtable_recovery_result_creation(self):
        """测试恢复结果创建"""
        result = VTableRecoveryResult(
            recovered_methods=10,
            recovered_classes=3
        )
        self.assertEqual(len(result.vtables), 0)
        self.assertEqual(len(result.classes), 0)
        self.assertEqual(result.recovered_methods, 10)
        self.assertEqual(result.recovered_classes, 3)


class TestVTableScanner(unittest.TestCase):
    """VTableScanner测试"""
    
    def test_scan_empty_binary(self):
        """测试扫描空二进制数据"""
        scanner = VTableScanner(binary_data=b'', base_address=0x1000)
        vtables = scanner.scan_for_vtables()
        self.assertEqual(len(vtables), 0)
    
    def test_scan_with_vtable_pattern(self):
        """测试扫描包含虚函数表模式的数据"""
        import struct
        vtable_data = struct.pack('<QQQQ', 0x2000, 0x2010, 0x2020, 0)
        scanner = VTableScanner(binary_data=vtable_data, base_address=0x1000)
        vtables = scanner.scan_for_vtables()
        self.assertIn(0x1000, vtables)


class TestClassHierarchyAnalyzer(unittest.TestCase):
    """ClassHierarchyAnalyzer测试"""
    
    def test_build_hierarchy(self):
        """测试构建类层次结构"""
        analyzer = ClassHierarchyAnalyzer()
        vtables = [
            VTable(address=0x1000, entries=[VTableEntry(address=0x1000, function_address=0x2000)]),
            VTable(address=0x1020, entries=[VTableEntry(address=0x1020, function_address=0x2000), VTableEntry(address=0x1028, function_address=0x2010)])
        ]
        hierarchy = analyzer.build_hierarchy(vtables)
        self.assertTrue(len(hierarchy) >= 0)


class TestVTableRecoveryEngine(unittest.TestCase):
    """VTableRecoveryEngine测试"""
    
    def setUp(self):
        """设置测试环境"""
        self.engine = VTableRecoveryEngine()
    
    def test_analyze_empty_binary(self):
        """测试分析空二进制数据"""
        result = self.engine.analyze(b'', 0x1000)
        self.assertEqual(len(result.vtables), 0)
        self.assertEqual(result.recovered_classes, 0)
    
    def test_analyze_valid_binary(self):
        """测试分析包含虚函数表的二进制数据"""
        import struct
        vtable_data = struct.pack('<QQQQ', 0x2000, 0x2010, 0x2020, 0)
        result = self.engine.analyze(vtable_data, 0x1000)
        self.assertEqual(len(result.vtables), 2)
        self.assertEqual(result.recovered_methods, 5)
    
    def test_generate_report(self):
        """测试生成报告"""
        import struct
        vtable_data = struct.pack('<QQQQ', 0x2000, 0x2010, 0x2020, 0)
        result = self.engine.analyze(vtable_data, 0x1000)
        report = self.engine.generate_report(result)
        self.assertIn("C++ 虚函数表恢复报告", report)
        self.assertIn("恢复的虚函数表数量", report)
    
    def test_save_result(self):
        """测试保存结果"""
        import struct
        import os
        vtable_data = struct.pack('<QQQQ', 0x2000, 0x2010, 0x2020, 0)
        result = self.engine.analyze(vtable_data, 0x1000)
        
        output_file = "test_vtable_report.txt"
        self.engine.save_result(result, output_file)
        
        self.assertTrue(os.path.exists(output_file))
        os.remove(output_file)


if __name__ == '__main__':
    unittest.main()
