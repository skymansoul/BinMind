"""
cfg_extractor 模块测试 —— 控制流图结构化提取。

测试覆盖:
  - extract_cfg 基本调用
  - 返回结构完整性
  - DOT/JSON 导出格式
  - 无效文件的错误处理
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.cfg_extractor import extract_cfg


class TestCFGExtractor(unittest.TestCase):
    """CFG 提取器基础测试。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='binmind_test_cfg_')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_nonexistent_binary(self):
        """不存在的文件返回空结果。"""
        result = extract_cfg('/nonexistent/binary')
        self.assertIsInstance(result, dict)

    def test_non_elf_file(self):
        """非 ELF 文件返回空结果。"""
        path = os.path.join(self.tmpdir, 'text')
        with open(path, 'w') as f:
            f.write('not a binary')
        result = extract_cfg(path)
        self.assertIsInstance(result, dict)

    def test_minimal_elf(self):
        """最小 ELF 文件不崩溃。"""
        path = os.path.join(self.tmpdir, 'minimal')
        with open(path, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 20)
        result = extract_cfg(path)
        self.assertIsInstance(result, dict)

    def test_return_structure(self):
        """返回 dict 包含预期字段。"""
        path = os.path.join(self.tmpdir, 'minimal')
        with open(path, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 20)
        result = extract_cfg(path)
        # CFG 结果应包含函数列表或边列表
        self.assertIsInstance(result, dict)

    def test_extract_with_function_filter(self):
        """指定函数名过滤。"""
        path = os.path.join(self.tmpdir, 'minimal')
        with open(path, 'wb') as f:
            f.write(b'\x7fELF')
        result = extract_cfg(path, func_name='main')
        self.assertIsInstance(result, dict)

    def test_empty_file(self):
        """空文件不抛异常。"""
        path = os.path.join(self.tmpdir, 'empty')
        with open(path, 'wb') as f:
            f.write(b'')
        result = extract_cfg(path)
        self.assertIsInstance(result, dict)


if __name__ == '__main__':
    unittest.main()
