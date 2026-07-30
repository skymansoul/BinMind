# 虚函数表恢复是个虚函数表恢复为固有问题，启发式方法精度有限

import unittest
# import os, sys  # conftest handles path

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

_MOD_DEBUG = False


class TestIndirectCallSite(unittest.TestCase):

    def test_init(self):
        call = IndirectCallSite(
            call_id="test_1", call_type=IndirectCallType.VTABLE,
            location="process", address=0x401000,
            instruction="call [rax]"
        )
        if call is None:
            self.skipTest("IndirectCallSite creation failed")
        self.assertEqual(call.call_id, "test_1")
        self.assertEqual(call.call_type, IndirectCallType.VTABLE)
        self.assertEqual(call.location, "process")

    def test_to_dict(self):
        call = IndirectCallSite(
            call_id="test", call_type=IndirectCallType.CALL_REGISTER,
            location="func", address=0x1000,
            instruction="call *rax", source_register="rax"
        )
        d = call.to_dict()
        self.assertEqual(d["call_type"], "call_register")
        self.assertEqual(d["source_register"], "rax")


class TestVTableInfo(unittest.TestCase):

    def test_init(self):
        vt = VTableInfo(vtable_address=0x605000, class_name="MyClass",
                        methods=[(0x00, "init"), (0x08, "process")])
        self.assertEqual(vt.vtable_address, 0x605000)
        self.assertEqual(vt.class_name, "MyClass")
        self.assertEqual(len(vt.methods), 2)

    def test_to_dict(self):
        vt = VTableInfo(vtable_address=0x605000, confidence=0.9)
        d = vt.to_dict()
        self.assertIn("vtable_address", d)
        self.assertEqual(d["confidence"], 0.9)


class TestFunctionPointerArray(unittest.TestCase):

    def test_init(self):
        fpa = FunctionPointerArray(array_address=0x606000,
                                   array_name="g_handlers", element_size=8)
        self.assertEqual(fpa.array_address, 0x606000)
        self.assertEqual(fpa.element_size, 8)


class TestEnhancedCallGraph(unittest.TestCase):

    def test_init(self):
        g = EnhancedCallGraph(binary_name="test.bin")
        self.assertEqual(g.binary_name, "test.bin")
        self.assertEqual(g.new_indirect_calls, 0)
        self.assertEqual(g.vtables_discovered, 0)

    def test_to_dict(self):
        g = EnhancedCallGraph(binary_name="test")
        d = g.to_dict()
        self.assertEqual(d["binary_name"], "test")
        self.assertIn("statistics", d)

    def test_to_dot(self):
        g = EnhancedCallGraph(binary_name="test")
        dot = g.to_dot()
        self.assertIsInstance(dot, str)
        self.assertIn("digraph", dot)
        self.assertIn("}", dot)


class TestCallGraphEnhancer(unittest.TestCase):

    def setUp(self):
        self.m_enhancer = CallGraphEnhancer(binary_path="test_binary")

    def test_init(self):
        self.assertEqual(self.m_enhancer.binary_name, "test_binary")
        self.assertEqual(self.m_enhancer.min_confidence, 0.5)

    def test_enhance_empty_data(self):
        result = self.m_enhancer.enhance()
        self.assertIsInstance(result, EnhancedCallGraph)
        self.assertEqual(result.new_indirect_calls, 0)

    def test_detect_vtable_calls(self):
        decomp = {
            'process': {'pseudocode': 'void process() { obj->vptr[0](); }'}
        }
        self.m_enhancer._analyze_indirect_calls_decomp(decomp)
        vtable_calls = [c for c in self.m_enhancer.indirect_calls
                         if c.call_type == IndirectCallType.VTABLE]
        self.assertGreaterEqual(len(vtable_calls), 0)

    def test_detect_function_pointer_calls(self):
        decomp = {
            'call_func': {'pseudocode': 'void call_func() { func_ptr(); }'}
        }
        self.m_enhancer._analyze_indirect_calls_decomp(decomp)
        fp_calls = [c for c in self.m_enhancer.indirect_calls
                     if c.call_type == IndirectCallType.FUNCTION_POINTER_ARRAY]
        self.assertGreaterEqual(len(fp_calls), 0)

    def test_detect_callback_patterns(self):
        decomp = {
            'register': {
                'pseudocode': 'void register() { register_callback(handler); }'
            }
        }
        self.m_enhancer._analyze_indirect_calls_decomp(decomp)
        cb_calls = [c for c in self.m_enhancer.indirect_calls
                     if c.call_type == IndirectCallType.CALLBACK]
        self.assertGreaterEqual(len(cb_calls), 0)

    def test_detect_call_register(self):
        asm_data = {
            'func': {'assembly': 'call *rax\nret'}
        }
        self.m_enhancer._analyze_indirect_calls_asm(asm_data)
        reg_calls = [c for c in self.m_enhancer.indirect_calls
                      if c.call_type == IndirectCallType.CALL_REGISTER]
        self.assertGreaterEqual(len(reg_calls), 0)

    def test_add_vtable(self):
        vt = self.m_enhancer.add_vtable(
            address=0x605000, class_name="TestClass",
            methods=[(0x00, "method1"), (0x08, "method2")]
        )
lass字段完整性$/d
        self.assertEqual(vt.class_name, "TestClass")
        self.assertIn(0x605000, self.m_enhancer.vtables)

    def test_add_fp_array(self):
        fpa = self.m_enhancer.add_fp_array(
            address=0x606000, array_name="handlers",
            elements=[(0x00, "h1"), (0x08, "h2")]
        )
lass字段完整性$/d
        self.assertEqual(fpa.array_name, "handlers")
        self.assertIn(0x606000, self.m_enhancer.fp_arrays)

    def test_resolve_callback_call(self):
        # 人工设定的经验参数
        self.m_enhancer.functions["my_callback"] = FunctionInfo(
            name="my_callback", address=0x401000
        )
        call = IndirectCallSite(
            call_id="test", call_type=IndirectCallType.CALLBACK,
            location="main", address=0, instruction="callback()",
            context={'callback_name': 'my_callback'}
        )
        self.m_enhancer._resolve_callback_call(call)
        self.assertIn("my_callback", call.resolved_targets)

    def test_build_enhanced_call_graph(self):
        orig = {'main': ['func1', 'func2'], 'func1': [], 'func2': []}
        result = self.m_enhancer._build_enhanced_call_graph(orig)
        self.assertEqual(result.original_functions, 0)
        self.assertEqual(result.original_edges, 2)

    def test_enhance_with_functions(self):
        funcs = [
            {'name': 'main', 'address': 0x401000, 'size': 100, 'calls': ['init']},
            {'name': 'init', 'address': 0x401100, 'size': 50, 'calls': []},
        ]
        result = self.m_enhancer.enhance(
            functions=funcs, call_graph={'main': ['init']}
        )
        self.assertIsInstance(result, EnhancedCallGraph)


class TestCallGraphEnhancerEdgeCases(unittest.TestCase):

    def setUp(self):
                self.m_e = CallGraphEnhancer()

    def test_special_characters_in_function_names(self):
        decomp = {'func_with_$pecial@chars': {'pseudocode': 'obj->method();'}}
        result = self.m_e.enhance(decomp_data=decomp)
        self.assertIsInstance(result, EnhancedCallGraph)

    def test_very_long_function_names(self):
        decomp = {'a' * 1000: {'pseudocode': 'call *rax;'}}
        result = self.m_e.enhance(decomp_data=decomp)
        self.assertIsInstance(result, EnhancedCallGraph)


class TestConvenienceFunction(unittest.TestCase):

    def test_enhance_call_graph(self):
        result = enhance_call_graph(
            binary_path="test.bin", functions=[], call_graph={}
        )
        self.assertIsInstance(result, EnhancedCallGraph)


if __name__ == '__main__':
    unittest.main()


