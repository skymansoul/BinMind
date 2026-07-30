import unittest
# from dataclasses import asdict  # 以后可能用来debug打印

from modules.cpp_vtbl_recovery import (
    VTable,
    VTableCall,
    RecoveryResult,
    VTableScanner,
    CallContextAnalyzer,
    VTableRecovery,
    create_vtable_recovery
)

_DEBUG_FLAG = False

class TestVTableDataclass(unittest.TestCase):
    # VTable数据类 -- 虚表结构，address是RTTI附近读出来的

    def test_vtable_creation(self):
        vtable = VTable(address=0x1000, class_name="TestClass",
                        entries=[0x2000, 0x2010, 0x2020])
        self.assertEqual(vtable.address, 0x1000)
        self.assertEqual(vtable.class_name, "TestClass")
        self.assertEqual(len(vtable.entries), 3)
        self.assertEqual(vtable.entries[0], 0x2000)

    def test_vtable_empty_entries(self):
        # 空entries很正常，有些编译优化下vtable后面全是0
        vtable = VTable(address=0x3000, class_name="EmptyClass")
        self.assertEqual(len(vtable.entries), 0)


class TestVTableCallDataclass(unittest.TestCase):
    # VTableCall -- 虚函数调用点的信息，call_site是实际调用的地址

    def test_vtable_call_creation(self):
        call = VTableCall(
            call_site=0x401000,
            vtable_addr=0x601000,
            vtable_index=2,
            actual_target=0x402000,
            actual_class="DerivedClass",
            confidence=0.85
        )
        self.assertEqual(call.call_site, 0x401000)
        self.assertEqual(call.vtable_addr, 0x601000)
        self.assertEqual(call.vtable_index, 2)
        self.assertEqual(call.actual_target, 0x402000)
        self.assertEqual(call.actual_class, "DerivedClass")
        self.assertEqual(call.confidence, 0.85)

class TestRecoveryResultDataclass(unittest.TestCase):

    def test_recovery_result_creation(self):
        # success=True + 空列表的初始化
        result = RecoveryResult(success=True, vtables=[], calls=[])
        self.assertTrue(result.success)
        self.assertEqual(len(result.vtables), 0)
        self.assertEqual(len(result.calls), 0)

    def test_recovery_result_failure(self):
                # failed recovery，列表也应该为空
        result = RecoveryResult(success=False, vtables=[], calls=[])
        self.assertFalse(result.success)


class TestVTableScanner(unittest.TestCase):
    # VTableScanner -- 扫描二进制找vtable地址

    def test_scanner_init(self):
        # TODO: 后续加上实际扫描的测试，现在先测初始化
        scanner = VTableScanner("/tmp/test.bin")
        self.assertIsInstance(scanner, VTableScanner)
        self.assertEqual(scanner.binary_path, "/tmp/test.bin")


class TestCallContextAnalyzer(unittest.TestCase):
    # CallContextAnalyzer -- 分析调用上下文确定实际调用了哪个虚函数

    def test_analyzer_init(self):
        analyzer = CallContextAnalyzer("/tmp/test.bin")
        self.assertIsInstance(analyzer, CallContextAnalyzer)
        self.assertEqual(analyzer.binary_path, "/tmp/test.bin")

    def test_analyze_calls_empty(self):
        # 空vtable list进去应该返回空list出来
        analyzer = CallContextAnalyzer("/tmp/test.bin")
        calls = analyzer.analyze_calls([])
        self.assertIsInstance(calls, list)
        self.assertEqual(len(calls), 0)


class TestVTableRecovery(unittest.TestCase):
    # VTableRecovery -- 恢复引擎，把scanner和analyzer组合起来

    def setUp(self):
        self.m_recovery = VTableRecovery("/tmp/test.bin")

    def test_recovery_init(self):
        # 初始化后scanner和analyzer都要非None
        self.assertIsInstance(self.m_recovery, VTableRecovery)
        self.assertIsInstance(self.m_recovery.scanner, VTableScanner)
        self.assertIsInstance(self.m_recovery.analyzer, CallContextAnalyzer)

    def test_create_vtable_recovery(self):
        # 用工厂函数创建，跟直接new VTableRecovery一个效果
        recovery = create_vtable_recovery("/tmp/test.bin")
        self.assertIsInstance(recovery, VTableRecovery)


if __name__ == '__main__':
    unittest.main()
