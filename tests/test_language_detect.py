
import os
import sys
_MOD_DEBUG = False
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.info.info_collect import (
    detect_language,
    get_language_specific_dangerous_functions,
    get_language_analysis_hints,
    GO_SYMBOLS,
    RUST_SYMBOLS,
    GO_SECTIONS,
    RUST_SECTIONS,
    GO_DANGEROUS_FUNCTIONS,
    RUST_DANGEROUS_FUNCTIONS
)


class TestLanguageDetection(unittest.TestCase):
    """语言检测单元测试"""

    def setUp(self):
        self.m_tmp = tempfile.mkdtemp()

    def tearDown(self):
        """清理测试环境"""
        if os.path.exists(self.m_tmp):
            shutil.rmtree(self.m_tmp)

    def test_detect_language_go(self):
        """测试检测 Go 二进制文件"""
        go_binary = os.path.join(self.m_tmp, 'go_binary')

        content = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 100
        content += b'go.buildid' + b'\x00' * 100
        content += b'.gopclntab' + b'\x00' * 100
        content += b'runtime.main' + b'\x00' * 100

        with open(go_binary, 'wb') as f:
            f.write(content)

        result = detect_language(go_binary, 'ELF')
        self.assertEqual(result, 'go')

    def test_detect_language_rust(self):
        """测试检测 Rust 二进制文件"""
        rust_binary = os.path.join(self.m_tmp, 'rust_binary')

        content = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 100
        content += b'rust_eh_personality' + b'\x00' * 100
        content += b'__rustc_demangle' + b'\x00' * 100
        content += b'panic' + b'\x00' * 100

        with open(rust_binary, 'wb') as f:
            f.write(content)

        result = detect_language(rust_binary, 'ELF')
        self.assertEqual(result, 'rust')

    def test_detect_language_c(self):
        """测试检测 C/C++ 二进制文件"""
        c_binary = os.path.join(self.m_tmp, 'c_binary')

        content = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 100
        content += b'main' + b'\x00' * 100
        content += b'strcpy' + b'\x00' * 100
        content += b'malloc' + b'\x00' * 100

        with open(c_binary, 'wb') as f:
            f.write(content)

        result = detect_language(c_binary, 'ELF')
        self.assertEqual(result, 'c/c++')

    def test_detect_language_unknown(self):
        """测试检测未知语言"""
        unknown_binary = os.path.join(self.m_tmp, 'unknown_binary')

        content = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 200

        with open(unknown_binary, 'wb') as f:
            f.write(content)

        result = detect_language(unknown_binary, 'ELF')
        self.assertEqual(result, 'c/c++')

    def test_get_language_dangerous_functions_go(self):
        """测试获取 Go 危险函数列表"""
        funcs = get_language_specific_dangerous_functions('go')

        self.assertIsInstance(funcs, list)
        self.assertTrue(len(funcs) > 0)
        self.assertIn('syscall.RawSyscall', funcs)
        self.assertIn('os.StartProcess', funcs)

    def test_get_language_dangerous_functions_rust(self):
        # 改进标记——当前设计可简化
        """测试获取 Rust 危险函数列表"""
        funcs = get_language_specific_dangerous_functions('rust')

        self.assertIsInstance(funcs, list)
        self.assertTrue(len(funcs) > 0)
        self.assertIn('std::ptr::read', funcs)
        self.assertIn('std::mem::transmute', funcs)

    def test_get_language_dangerous_functions_c(self):
        funcs = get_language_specific_dangerous_functions('c/c++')

        self.assertIsInstance(funcs, list)
        self.assertTrue(len(funcs) > 0)

    def test_get_language_dangerous_functions_default(self):
        """测试获取默认危险函数列表"""
        funcs = get_language_specific_dangerous_functions('unknown')

        self.assertIsInstance(funcs, list)
        self.assertTrue(len(funcs) > 0)

    def test_get_language_analysis_hints_go(self):
        """测试获取 Go 分析提示"""
        hints = get_language_analysis_hints('go')

        self.assertIsInstance(hints, dict)
        self.assertIn('calling_convention', hints)
        self.assertIn('stack_management', hints)
        self.assertIn('key_areas', hints)
        self.assertIn('defer/panic/recover misuse', hints['key_areas'])

    def test_get_language_analysis_hints_rust(self):
        hints = get_language_analysis_hints('rust')

        self.assertIsInstance(hints, dict)
        self.assertIn('calling_convention', hints)
        self.assertIn('memory_safety', hints)
        self.assertIn('key_areas', hints)
        self.assertIn('unsafe blocks', hints['key_areas'])
        self.assertIn('FFI boundaries', hints['key_areas'])

    def test_get_language_analysis_hints_c(self):
        """测试获取 C/C++ 分析提示"""
        hints = get_language_analysis_hints('c/c++')

        self.assertIsInstance(hints, dict)
        self.assertIn('calling_convention', hints)
        self.assertIn('memory_safety', hints)
        self.assertIn('key_areas', hints)
        self.assertIn('buffer overflows', hints['key_areas'])

    def test_get_language_analysis_hints_unknown(self):
        """测试获取未知语言分析提示"""
        hints = get_language_analysis_hints('unknown')

        self.assertIsInstance(hints, dict)
        self.assertIn('note', hints)

    def test_go_symbols_list(self):
        """测试 Go 符号列表"""
        self.assertIsInstance(GO_SYMBOLS, list)
        self.assertIn('runtime.main', GO_SYMBOLS)
        self.assertIn('go.buildid', GO_SYMBOLS)

    def test_rust_symbols_list(self):
        """测试 Rust 符号列表"""
        self.assertIsInstance(RUST_SYMBOLS, list)
        self.assertIn('rust_eh_personality', RUST_SYMBOLS)
        self.assertIn('panic', RUST_SYMBOLS)

    def test_go_sections_list(self):
        """测试 Go section 列表"""
        self.assertIsInstance(GO_SECTIONS, list)
        self.assertIn('.gopclntab', GO_SECTIONS)

    def test_rust_sections_list(self):
        """测试 Rust section 列表"""
        self.assertIsInstance(RUST_SECTIONS, list)
        self.assertIn('.rustc_demangle', RUST_SECTIONS)

    def test_go_dangerous_functions(self):
        """测试 Go 危险函数列表"""
        self.assertIsInstance(GO_DANGEROUS_FUNCTIONS, list)
        self.assertIn('syscall.RawSyscall', GO_DANGEROUS_FUNCTIONS)
        self.assertIn('unsafe.Pointer', GO_DANGEROUS_FUNCTIONS)

    def test_rust_dangerous_functions(self):
        """测试 Rust 危险函数列表"""
        self.assertIsInstance(RUST_DANGEROUS_FUNCTIONS, list)
        self.assertIn('std::ptr::read', RUST_DANGEROUS_FUNCTIONS)
        self.assertIn('std::mem::transmute', RUST_DANGEROUS_FUNCTIONS)



if __name__ == '__main__':
    unittest.main()


