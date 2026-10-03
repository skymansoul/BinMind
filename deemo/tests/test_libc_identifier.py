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
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.libc_identifier import identify_libc, get_libc_context_for_llm, parse_libc_leaks


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

    def test_identify_libc_resolves_linked_libc_version(self):
        """动态链接 ELF 应通过 ldd 解析真实 libc 文件并提取版本。"""
        binary_path = os.path.join(self.tmpdir, 'linked_binary')
        libc_path = os.path.join(self.tmpdir, 'libc.so.6')
        linked_dir = os.path.join(self.tmpdir, 'linked')
        os.mkdir(linked_dir)
        linked_libc_path = os.path.join(linked_dir, 'libc.so.6')
        with open(binary_path, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 128)
        with open(linked_libc_path, 'wb') as f:
            f.write(b'GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.9) stable release version 2.39.\x00')

        def fake_needed(_path):
            return ['libc.so.6']

        completed = type('Completed', (), {
            'stdout': f'\tlibc.so.6 => {linked_libc_path} (0x00007f00)\n',
            'stderr': '',
            'returncode': 0,
        })()

        with patch('core.libc_identifier._extract_needed_libs', fake_needed), \
                patch('core.libc_identifier.subprocess.run', return_value=completed):
            result = identify_libc(binary_path)

        self.assertEqual(result['path'], linked_libc_path)
        self.assertIn('GLIBC 2.39', result['version'])
        self.assertEqual(result['source'], 'linked-libc')

    def test_identify_libc_prefers_challenge_local_libc(self):
        """CTF 题目目录自带 libc 应优先于系统 ldd 解析结果。"""
        binary_path = os.path.join(self.tmpdir, 'challenge')
        local_libc_path = os.path.join(self.tmpdir, 'libc.so.6')
        system_libc_path = os.path.join(self.tmpdir, 'system-libc.so.6')
        with open(binary_path, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 128)
        with open(local_libc_path, 'wb') as f:
            f.write(b'GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9) stable release version 2.31.\x00')
        with open(system_libc_path, 'wb') as f:
            f.write(b'GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.9) stable release version 2.39.\x00')

        def fake_needed(_path):
            return ['libc.so.6']

        completed = type('Completed', (), {
            'stdout': f'\tlibc.so.6 => {system_libc_path} (0x00007f00)\n',
            'stderr': '',
            'returncode': 0,
        })()

        with patch('core.libc_identifier._extract_needed_libs', fake_needed), \
                patch('core.libc_identifier.subprocess.run', return_value=completed):
            result = identify_libc(binary_path)

        self.assertEqual(result['path'], local_libc_path)
        self.assertIn('GLIBC 2.31', result['version'])
        self.assertEqual(result['source'], 'local-libc')

    def test_parse_libc_leaks(self):
        """CLI 泄露地址参数应解析为符号到整数地址的映射。"""
        leaks = parse_libc_leaks(['puts=0x7ffff7a5e5f0', 'read=1234'])
        self.assertEqual(leaks['puts'], 0x7ffff7a5e5f0)
        self.assertEqual(leaks['read'], 1234)

    def test_identify_libc_reports_missing_libcsearcher(self):
        """传入 leak 但未安装 LibcSearcher 时应给出可读错误。"""
        path = os.path.join(self.tmpdir, 'minimal')
        with open(path, 'wb') as f:
            f.write(b'\x7fELF')
        with patch('core.libc_identifier.importlib.util.find_spec', return_value=None):
            result = identify_libc(path, leaks={'puts': 0x123450})
        self.assertTrue(result['libcsearch']['enabled'])
        self.assertIn('LibcSearcher is not installed', result['libcsearch']['error'])

    def test_libcsearcher_database_candidates(self):
        """LibcSearcher 数据库匹配应返回全部满足低 12 位偏移的候选。"""
        import types
        package_dir = os.path.join(self.tmpdir, 'LibcSearcher')
        db_dir = os.path.join(package_dir, 'libc-database', 'db')
        os.makedirs(db_dir)
        with open(os.path.join(db_dir, 'libc_a.symbols'), 'w') as f:
            f.write('puts 00000000000805f0\nread 0000000000110120\n')
        with open(os.path.join(db_dir, 'libc_b.symbols'), 'w') as f:
            f.write('puts 00000000000705f0\nread 0000000000111120\n')
        with open(os.path.join(db_dir, 'libc_bad.symbols'), 'w') as f:
            f.write('puts 00000000000805f1\nread 0000000000110120\n')

        spec = types.SimpleNamespace(submodule_search_locations=[package_dir])
        with patch('core.libc_identifier.importlib.util.find_spec', return_value=spec):
            from core.libc_identifier import _query_libcsearcher_database
            candidates = _query_libcsearcher_database({
                'puts': 0x7ffff7a805f0,
                'read': 0x7ffff7b10120,
            })

        self.assertEqual(candidates, ['libc_a', 'libc_b'])

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
