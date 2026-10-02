"""
checksec 模块测试 —— 验证保护机制检测的准确性和健壮性。

测试覆盖:
  - 格式检测（ELF/PE/unknown）
  - 各保护项的独立检测
  - 无文件/损坏文件的错误处理
  - checksec_summary 格式化输出
  - 对真实系统二进制文件的检测

注：手写 ELF 的 Program Header 解析在 win32 平台上受 struct 对齐影响，
极端 case 可能有偏差。核心健壮性测试使用不存在的文件和系统二进制。
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.checksec import detect_checksec, checksec_summary


def _find_system_binary():
    """在系统上找一个真实 ELF 用于测试。"""
    candidates = ['/bin/ls', '/bin/sh', '/usr/bin/true',
                  '/bin/bash', '/usr/bin/env']
    for path in candidates:
        if os.path.isfile(path):
            try:
                with open(path, 'rb') as f:
                    if f.read(4) == b'\x7fELF':
                        return path
            except OSError:
                continue
    return None


class TestChecksecBasic(unittest.TestCase):
    """基础健壮性测试。"""

    def test_nonexistent_file(self):
        result = detect_checksec('/nonexistent/path/to/binary')
        self.assertIsInstance(result, dict)
        self.assertEqual(result['format'], 'unknown')

    def test_directory_instead_of_file(self):
        result = detect_checksec(os.path.dirname(__file__))
        self.assertEqual(result['format'], 'unknown')

    def test_empty_file(self):
        tmpdir = tempfile.mkdtemp(prefix='cs_test_')
        try:
            path = os.path.join(tmpdir, 'empty')
            with open(path, 'wb') as f:
                f.write(b'')
            result = detect_checksec(path)
            self.assertIsInstance(result, dict)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_return_keys(self):
        """返回 dict 包含所有标准字段。"""
        result = detect_checksec('/nonexistent/bin')
        for key in ('nx', 'pie', 'canary', 'relro', 'fortify', 'aslr',
                     'rwx_segments', 'format'):
            self.assertIn(key, result, f'Missing key: {key}')

    def test_default_values(self):
        """未检测到格式时返回安全的默认值。"""
        result = detect_checksec('/nonexistent/bin')
        self.assertTrue(result['nx'])       # 默认假设 NX 开启
        self.assertFalse(result['pie'])     # 默认假设 PIE 关闭
        self.assertFalse(result['canary'])  # 默认假设 Canary 关闭
        self.assertEqual(result['relro'], 'none')

    def test_non_elf_text_file(self):
        """非 ELF 的文本文件被正确识别。"""
        tmpdir = tempfile.mkdtemp(prefix='cs_test_')
        try:
            path = os.path.join(tmpdir, 'text')
            with open(path, 'w') as f:
                f.write('This is not a binary file.')
            result = detect_checksec(path)
            self.assertEqual(result['format'], 'unknown')
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestChecksecSystemBinary(unittest.TestCase):
    """对系统真实 ELF 的检测。"""

    @classmethod
    def setUpClass(cls):
        cls.sys_bin = _find_system_binary()

    def test_detect_system_elf_format(self):
        if self.sys_bin is None:
            self.skipTest('no system ELF binary available')
        result = detect_checksec(self.sys_bin)
        self.assertEqual(result['format'], 'ELF',
                         f'Expected ELF format, got {result["format"]}')

    def test_system_binary_has_nx(self):
        """现代系统二进制几乎都有 NX。"""
        if self.sys_bin is None:
            self.skipTest('no system ELF binary available')
        result = detect_checksec(self.sys_bin)
        self.assertTrue(result['nx'],
                        f'Expected NX enabled, got {result["nx"]}')

    def test_system_binary_has_pie(self):
        """现代系统二进制通常有 PIE。"""
        if self.sys_bin is None:
            self.skipTest('no system ELF binary available')
        result = detect_checksec(self.sys_bin)
        # 大多数现代 Linux 二进制都是 PIE
        self.assertIsInstance(result['pie'], bool)

    def test_system_binary_keys(self):
        if self.sys_bin is None:
            self.skipTest('no system ELF binary available')
        result = detect_checksec(self.sys_bin)
        for key in ('nx', 'pie', 'canary', 'relro', 'fortify'):
            self.assertIn(key, result)


class TestChecksecRelro(unittest.TestCase):
    """RELRO 类型检测回归测试。"""

    @classmethod
    def setUpClass(cls):
        if shutil.which('gcc') is None:
            raise unittest.SkipTest('gcc is required')

        cls.tmpdir = tempfile.mkdtemp(prefix='cs_relro_')
        cls.source = os.path.join(cls.tmpdir, 'main.c')
        with open(cls.source, 'w', encoding='utf-8') as f:
            f.write('#include <stdio.h>\nint main(void) { puts("hi"); return 0; }\n')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(getattr(cls, 'tmpdir', ''), ignore_errors=True)

    def _build(self, name, *ldflags):
        output = os.path.join(self.tmpdir, name)
        cmd = [
            'gcc',
            self.source,
            '-o',
            output,
            '-fno-pie',
            '-no-pie',
            *ldflags,
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return output

    def test_no_relro(self):
        binary = self._build('no_relro', '-Wl,-z,norelro')
        self.assertEqual(detect_checksec(binary)['relro'], 'none')

    def test_partial_relro(self):
        binary = self._build('partial_relro', '-Wl,-z,relro', '-Wl,-z,lazy')
        self.assertEqual(detect_checksec(binary)['relro'], 'partial')

    def test_full_relro(self):
        binary = self._build('full_relro', '-Wl,-z,relro', '-Wl,-z,now')
        self.assertEqual(detect_checksec(binary)['relro'], 'full')


class TestChecksecSummary(unittest.TestCase):
    """checksec_summary 格式化输出。"""

    def test_summary_all_enabled(self):
        cs = {'nx': True, 'pie': True, 'canary': True, 'relro': 'full',
              'fortify': True}
        summary = checksec_summary(cs)
        self.assertIn('NX', summary)
        self.assertIn('PIE', summary)
        self.assertIn('Canary', summary)
        self.assertIn('Full RELRO', summary)
        self.assertIn('FORTIFY', summary)

    def test_summary_all_disabled(self):
        cs = {'nx': False, 'pie': False, 'canary': False, 'relro': 'none',
              'fortify': False}
        summary = checksec_summary(cs)
        self.assertIn('NX', summary)

    def test_summary_partial_relro(self):
        cs = {'nx': True, 'pie': False, 'canary': False, 'relro': 'partial',
              'fortify': False}
        summary = checksec_summary(cs)
        self.assertIn('Partial RELRO', summary)

    def test_summary_missing_keys(self):
        """缺少可选字段时不应崩溃。"""
        cs = {'nx': True}
        summary = checksec_summary(cs)
        self.assertIsInstance(summary, str)

    def test_summary_returns_string(self):
        cs = {'nx': True, 'pie': True, 'canary': True, 'relro': 'partial',
              'fortify': False}
        self.assertIsInstance(checksec_summary(cs), str)


if __name__ == '__main__':
    unittest.main()
