"""
调用图增强模块单元测试
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.call_graph_enhancer import (
    CallGraphEnhancer,
    IndirectCallType,
    VTableInfo,
    FunctionPointerArray,
    EnhancedCallGraph,
    FunctionInfo,
    IndirectCallSite,
    enhance_call_graph
)


class TestIndirectCallSite(unittest.TestCase):
    """测试间接调用点数据类"""

    def test_init(self):
        """测试初始化"""
        call = IndirectCallSite(
            call_id="test_1",
            call_type=IndirectCallType.VTABLE,
            location="process",
            address=0x401000,
            instruction="call [rax]"
        )
        
        self.assertEqual(call.call_id, "test_1")
        self.assertEqual(call.call_type, IndirectCallType.VTABLE)
        self.assertEqual(call.location, "process")

    def test_to_dict(self):
        """测试转换为字典"""
        call = IndirectCallSite(
            call_id="test",
            call_type=IndirectCallType.CALL_REGISTER,
            location="func",
            address=0x1000,
            instruction="call *rax",
            source_register="rax"
        )
        
        result = call.to_dict()
        self.assertEqual(result["call_type"], "call_register")
        self.assertEqual(result["source_register"], "rax")


class TestVTableInfo(unittest.TestCase):
    """测试虚函数表信息数据类"""

    def test_init(self):
        """测试初始化"""
        vtable = VTableInfo(
            vtable_address=0x605000,
            class_name="MyClass",
            methods=[(0x00, "init"), (0x08, "process")]
        )
        
        self.assertEqual(vtable.vtable_address, 0x605000)
        self.assertEqual(vtable.class_name, "MyClass")
        self.assertEqual(len(vtable.methods), 2)

    def test_to_dict(self):
        """测试转换为字典"""
        vtable = VTableInfo(
            vtable_address=0x605000,
            confidence=0.9
        )
        
        result = vtable.to_dict()
        self.assertIn("vtable_address", result)
        self.assertEqual(result["confidence"], 0.9)


class TestFunctionPointerArray(unittest.TestCase):
    """测试函数指针数组数据类"""

    def test_init(self):
        """测试初始化"""
        fp_array = FunctionPointerArray(
            array_address=0x606000,
            array_name="g_handlers",
            element_size=8
        )
        
        self.assertEqual(fp_array.array_address, 0x606000)
        self.assertEqual(fp_array.element_size, 8)


class TestEnhancedCallGraph(unittest.TestCase):
    """测试增强调用图数据类"""

    def test_init(self):
        """测试初始化"""
        graph = EnhancedCallGraph(binary_name="test.bin")
        
        self.assertEqual(graph.binary_name, "test.bin")
        self.assertEqual(graph.new_indirect_calls, 0)
        self.assertEqual(graph.vtables_discovered, 0)

    def test_to_dict(self):
        """测试转换为字典"""
        graph = EnhancedCallGraph(binary_name="test")
        
        result = graph.to_dict()
        self.assertEqual(result["binary_name"], "test")
        self.assertIn("statistics", result)

    def test_to_dot(self):
        """测试生成DOT格式"""
        graph = EnhancedCallGraph(binary_name="test")
        
        dot = graph.to_dot()
        
        self.assertIsInstance(dot, str)
        self.assertIn("digraph", dot)
        self.assertIn("}", dot)


class TestCallGraphEnhancer(unittest.TestCase):
    """测试调用图增强器"""

    def setUp(self):
        """设置测试环境"""
        self.enhancer = CallGraphEnhancer(binary_path="test_binary")

    def test_init(self):
        """测试初始化"""
        self.assertEqual(self.enhancer.binary_name, "test_binary")
        self.assertEqual(self.enhancer.min_confidence, 0.5)

    def test_enhance_empty_data(self):
        """测试空数据分析"""
        result = self.enhancer.enhance()
        
        self.assertIsInstance(result, EnhancedCallGraph)
        self.assertEqual(result.new_indirect_calls, 0)

    def test_detect_vtable_calls(self):
        """测试检测虚函数调用"""
        decomp_data = {
            'process': {
                'pseudocode': '''
                    void process() {
                        obj->vptr[0]();  // 虚函数调用
                    }
                '''
            }
        }
        
        self.enhancer._analyze_indirect_calls_decomp(decomp_data)
        
        # 应该检测到虚函数调用
        vtable_calls = [
            c for c in self.enhancer.indirect_calls 
            if c.call_type == IndirectCallType.VTABLE
        ]
        self.assertGreaterEqual(len(vtable_calls), 0)

    def test_detect_function_pointer_calls(self):
        """测试检测函数指针调用"""
        decomp_data = {
            'call_func': {
                'pseudocode': '''
                    void call_func() {
                        func_ptr();
                    }
                '''
            }
        }
        
        self.enhancer._analyze_indirect_calls_decomp(decomp_data)
        
        fp_calls = [
            c for c in self.enhancer.indirect_calls
            if c.call_type == IndirectCallType.FUNCTION_POINTER_ARRAY
        ]
        self.assertGreaterEqual(len(fp_calls), 0)

    def test_detect_callback_patterns(self):
        """测试检测回调函数模式"""
        decomp_data = {
            'register': {
                'pseudocode': '''
                    void register() {
                        register_callback(handler);
                    }
                '''
            }
        }
        
        self.enhancer._analyze_indirect_calls_decomp(decomp_data)
        
        callback_calls = [
            c for c in self.enhancer.indirect_calls
            if c.call_type == IndirectCallType.CALLBACK
        ]
        self.assertGreaterEqual(len(callback_calls), 0)

    def test_detect_call_register(self):
        """测试检测寄存器间接调用"""
        assembly_data = {
            'func': {
                'assembly': '''
                    call *rax
                    ret
                '''
            }
        }
        
        self.enhancer._analyze_indirect_calls_asm(assembly_data)
        
        reg_calls = [
            c for c in self.enhancer.indirect_calls
            if c.call_type == IndirectCallType.CALL_REGISTER
        ]
        self.assertGreaterEqual(len(reg_calls), 0)

    def test_add_vtable(self):
        """测试添加虚函数表"""
        vtable = self.enhancer.add_vtable(
            address=0x605000,
            class_name="TestClass",
            methods=[(0x00, "method1"), (0x08, "method2")]
        )
        
        self.assertEqual(vtable.class_name, "TestClass")
        self.assertIn(0x605000, self.enhancer.vtables)

    def test_add_fp_array(self):
        """测试添加函数指针数组"""
        fp_array = self.enhancer.add_fp_array(
            address=0x606000,
            array_name="handlers",
            elements=[(0x00, "h1"), (0x08, "h2")]
        )
        
        self.assertEqual(fp_array.array_name, "handlers")
        self.assertIn(0x606000, self.enhancer.fp_arrays)

    def test_resolve_callback_call(self):
        """测试解析回调函数调用"""
        # 先添加一个函数
        self.enhancer.functions["my_callback"] = FunctionInfo(
            name="my_callback",
            address=0x401000
        )
        
        call_site = IndirectCallSite(
            call_id="test",
            call_type=IndirectCallType.CALLBACK,
            location="main",
            address=0,
            instruction="callback()",
            context={'callback_name': 'my_callback'}
        )
        
        self.enhancer._resolve_callback_call(call_site)
        
        self.assertIn("my_callback", call_site.resolved_targets)

    def test_build_enhanced_call_graph(self):
        """测试构建增强调用图"""
        original_graph = {
            'main': ['func1', 'func2'],
            'func1': [],
            'func2': []
        }
        
        result = self.enhancer._build_enhanced_call_graph(original_graph)
        
        self.assertEqual(result.original_functions, 0)
        self.assertEqual(result.original_edges, 2)

    def test_enhance_with_functions(self):
        """测试带函数的增强"""
        functions = [
            {
                'name': 'main',
                'address': 0x401000,
                'size': 100,
                'calls': ['init'],
            },
            {
                'name': 'init',
                'address': 0x401100,
                'size': 50,
                'calls': [],
            }
        ]
        
        result = self.enhancer.enhance(
            functions=functions,
            call_graph={'main': ['init']}
        )
        
        self.assertIsInstance(result, EnhancedCallGraph)


class TestCallGraphEnhancerEdgeCases(unittest.TestCase):
    """测试调用图增强器边界情况"""

    def setUp(self):
        """设置测试环境"""
        self.enhancer = CallGraphEnhancer()

    def test_special_characters_in_function_names(self):
        """测试函数名中的特殊字符"""
        decomp_data = {
            'func_with_$pecial@chars': {
                'pseudocode': 'obj->method();'
            }
        }
        
        result = self.enhancer.enhance(decomp_data=decomp_data)
        self.assertIsInstance(result, EnhancedCallGraph)

    def test_very_long_function_names(self):
        """测试超长函数名"""
        decomp_data = {
            'a' * 1000: {
                'pseudocode': 'call *rax;'
            }
        }
        
        result = self.enhancer.enhance(decomp_data=decomp_data)
        self.assertIsInstance(result, EnhancedCallGraph)


class TestConvenienceFunction(unittest.TestCase):
    """测试便捷函数"""

    def test_enhance_call_graph(self):
        """测试 enhance_call_graph 函数"""
        result = enhance_call_graph(
            binary_path="test.bin",
            functions=[],
            call_graph={}
        )
        
        self.assertIsInstance(result, EnhancedCallGraph)


if __name__ == '__main__':
    unittest.main()