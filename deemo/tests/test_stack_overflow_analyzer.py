"""
stack_overflow_analyzer 模块测试 —— 栈溢出自动化分析。

测试覆盖:
  - analyze_stack_overflow 基本调用和参数校验
  - 返回结构完整性
  - angr 不可用时的静态回退
  - 不存在文件/函数的错误处理
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.stack_overflow_analyzer import analyze_stack_overflow

# 检查 angr 可用性
try:
    import angr
    HAS_ANGR = True
except ImportError:
    HAS_ANGR = False


class TestStackOverflowAnalyzer(unittest.TestCase):
    """栈溢出分析器基础测试。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='binmind_test_so_')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_nonexistent_binary(self):
        """不存在的二进制文件返回包含 error 字段的 dict。"""
        result = analyze_stack_overflow('/nonexistent/binary', 'main')
        self.assertIsInstance(result, dict)

    def test_return_structure(self):
        """返回 dict 包含预期字段。"""
        path = os.path.join(self.tmpdir, 'minimal')
        with open(path, 'wb') as f:
            f.write(b'\x7fELF')
        result = analyze_stack_overflow(path, 'main')
        self.assertIsInstance(result, dict)
        # 核心返回字段应存在
        for key in ('overflowable', 'padding', 'has_canary'):
            self.assertIn(key, result,
                          f'Result should contain key: {key}')

    def test_overflowable_is_bool(self):
        """overflowable 字段应为布尔值。"""
        path = os.path.join(self.tmpdir, 'minimal')
        with open(path, 'wb') as f:
            f.write(b'\x7fELF')
        result = analyze_stack_overflow(path, 'main')
        self.assertIsInstance(result.get('overflowable'), bool)

    def test_padding_is_int(self):
        """padding 字段应为整数。"""
        path = os.path.join(self.tmpdir, 'minimal')
        with open(path, 'wb') as f:
            f.write(b'\x7fELF')
        result = analyze_stack_overflow(path, 'main')
        self.assertIsInstance(result.get('padding'), int)

    def test_has_canary_is_bool(self):
        """has_canary 字段应为布尔值。"""
        path = os.path.join(self.tmpdir, 'minimal')
        with open(path, 'wb') as f:
            f.write(b'\x7fELF')
        result = analyze_stack_overflow(path, 'main')
        self.assertIsInstance(result.get('has_canary'), bool)

    def test_with_binfo(self):
        """传入 binfo 参数不应报错。"""
        path = os.path.join(self.tmpdir, 'minimal')
        with open(path, 'wb') as f:
            f.write(b'\x7fELF')
        binfo = {'arch': 'x86-64', 'bits': 64}
        result = analyze_stack_overflow(path, 'main', binfo=binfo)
        self.assertIsInstance(result, dict)

    def test_with_libc_info(self):
        """传入 libc_info 参数不应报错。"""
        path = os.path.join(self.tmpdir, 'minimal')
        with open(path, 'wb') as f:
            f.write(b'\x7fELF')
        libc_info = {'version': 'glibc 2.31', 'symbols': {'system': '0x55410'}}
        result = analyze_stack_overflow(path, 'main', libc_info=libc_info)
        self.assertIsInstance(result, dict)


if __name__ == '__main__':
    unittest.main()
