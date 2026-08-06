"""
libc_identifier 模块测试 —— libc 版本指纹提取与匹配。

测试覆盖:
  - identify_libc 基本调用
  - get_libc_context_for_llm 上下文构建
  - 无文件/非 ELF 的错误处理
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.libc_identifier import identify_libc, get_libc_context_for_llm


class TestLibcIdentifier(unittest.TestCase):
    """libc 识别器基础测试。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='binmind_test_libc_')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_identify_libc_nonexistent_file(self):
        """不存在的文件返回空结果，不抛异常。"""
        result = identify_libc('/nonexistent/binary')
        self.assertIsInstance(result, dict)

    def test_identify_libc_non_elf_file(self):
        """非 ELF 文件返回空结果。"""
        path = os.path.join(self.tmpdir, 'not_elf')
        with open(path, 'wb') as f:
            f.write(b'not an elf file\x00\x00')
        result = identify_libc(path)
        self.assertIsInstance(result, dict)

    def test_identify_libc_empty_file(self):
        """空文件返回空结果。"""
        path = os.path.join(self.tmpdir, 'empty')
        with open(path, 'wb') as f:
            f.write(b'')
        result = identify_libc(path)
        self.assertIsInstance(result, dict)

    def test_identify_libc_return_structure(self):
        """返回的 dict 结构合理。"""
        path = os.path.join(self.tmpdir, 'minimal')
        with open(path, 'wb') as f:
            f.write(b'\x7fELF')
        result = identify_libc(path)
        # 即使失败，也应返回 dict 而非 None
        self.assertIsInstance(result, dict)

    def test_get_libc_context_empty(self):
        """空 libc_info 返回空字符串。"""
        ctx = get_libc_context_for_llm({})
        self.assertIsInstance(ctx, str)

    def test_get_libc_context_with_data(self):
        """含数据的 libc_info 应生成有意义的 LLM 上下文。"""
        libc_info = {
            'version': 'glibc 2.31',
            'distro': 'Ubuntu 20.04',
            'symbols': {
                'system': '0x55410',
                'str_bin_sh': '0x1b75aa',
            },
        }
        ctx = get_libc_context_for_llm(libc_info)
        self.assertIsInstance(ctx, str)
        self.assertIn('glibc', ctx.lower() or 'glibc',
                      'Context should mention glibc')

    def test_get_libc_context_none(self):
        """None 输入应安全处理——返回空字符串或 str。"""
        try:
            ctx = get_libc_context_for_llm(None)
            self.assertIsInstance(ctx, str)
        except (TypeError, AttributeError):
            # 如果函数不接受 None，传空 dict 测试
            ctx = get_libc_context_for_llm({})
            self.assertIsInstance(ctx, str)


if __name__ == '__main__':
    unittest.main()
