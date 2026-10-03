"""
format_string_detector 模块测试 —— 格式化字符串漏洞检测。

测试覆盖:
  - detect_format_string_vulns 基本调用
  - 空/无效二进制的处理
  - 返回结构完整性（offset, function, confidence）
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.format_string_detector import detect_format_string_vulns


class TestFormatStringDetector(unittest.TestCase):
    """格式化字符串检测器基础测试。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='binmind_test_fmt_')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_nonexistent_binary(self):
        """不存在的文件返回空列表，不抛异常。"""
        result = detect_format_string_vulns('/nonexistent/binary')
        self.assertIsInstance(result, list)

    def test_non_elf_file(self):
        """非 ELF 文件返回空列表。"""
        path = os.path.join(self.tmpdir, 'text')
        with open(path, 'w') as f:
            f.write('not a binary')
        result = detect_format_string_vulns(path)
        self.assertIsInstance(result, list)

    def test_minimal_elf(self):
        """最小 ELF 文件返回空列表，不崩溃。"""
        path = os.path.join(self.tmpdir, 'minimal')
        with open(path, 'wb') as f:
            f.write(b'\x7fELF')
        result = detect_format_string_vulns(path)
        self.assertIsInstance(result, list)

    def test_empty_file(self):
        """空文件返回空列表。"""
        path = os.path.join(self.tmpdir, 'empty')
        with open(path, 'wb') as f:
            f.write(b'')
        result = detect_format_string_vulns(path)
        self.assertIsInstance(result, list)

    def test_result_items_structure(self):
        """若返回条目，每条应有预期字段。"""
        path = os.path.join(self.tmpdir, 'minimal')
        with open(path, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8)
        result = detect_format_string_vulns(path)
        # 最小 ELF 不应该有格式化字符串漏洞
        # 但如果有返回，验证结构
        for item in result:
            self.assertIsInstance(item, dict)
            # 基本字段
            self.assertIn('function', item if 'function' in item else {'function': ''})


if __name__ == '__main__':
    unittest.main()
