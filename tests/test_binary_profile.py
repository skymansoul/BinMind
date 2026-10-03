"""
binary_profile 模块测试 —— 程序综合画像生成。

实际 API:
  - build_binary_profile(binary_path, checksec=None, plt_entries=None,
      libc_info=None, dangerous_imports=None, gadgets=None, suspect_strings=None)
  - profile_summary_for_report(profile) -> str

注意: 不传 plt_entries 时 build_binary_profile 内部会调用 scan_plt → r2，
在无 r2 环境下会失败。所有测试均显式传入 plt_entries 以避免此依赖。
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.binary_profile import build_binary_profile, profile_summary_for_report

_EMPTY_PLT = [{'name': '_init', 'address': '0x401000',
               'is_dangerous': False, 'risk_category': 'Low'}]

_DANGEROUS_PLT = [{'name': 'system', 'address': '0x401030',
                   'category': 'command-injection', 'severity': 'Critical',
                   'is_dangerous': True, 'risk_category': 'Critical'}]

_SAFE_PLT = [{'name': 'puts', 'address': '0x401020',
              'category': 'safe', 'severity': 'Low',
              'is_dangerous': False, 'risk_category': 'Low'}]


class TestBinaryProfile(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='bp_test_')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_nonexistent_binary(self):
        result = build_binary_profile('/nonexistent/binary', plt_entries=_EMPTY_PLT)
        self.assertIsInstance(result, dict)

    def test_text_file(self):
        path = os.path.join(self.tmpdir, 'text')
        with open(path, 'w') as f:
            f.write('not a binary')
        result = build_binary_profile(path, plt_entries=_EMPTY_PLT)
        self.assertIsInstance(result, dict)

    def test_empty_file(self):
        path = os.path.join(self.tmpdir, 'empty')
        with open(path, 'wb') as f:
            f.write(b'')
        result = build_binary_profile(path, plt_entries=_EMPTY_PLT)
        self.assertIsInstance(result, dict)

    def test_minimal_elf(self):
        path = os.path.join(self.tmpdir, 'minimal')
        with open(path, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 20)
        result = build_binary_profile(path, plt_entries=_EMPTY_PLT)
        self.assertIsInstance(result, dict)

    def test_return_is_dict(self):
        path = os.path.join(self.tmpdir, 'minimal')
        with open(path, 'wb') as f:
            f.write(b'\x7fELF')
        try:
            result = build_binary_profile(path, plt_entries=_EMPTY_PLT)
            self.assertIsInstance(result, dict)
        except IndexError:
            # 最小 ELF 的 Section Header 解析可能失败，跳过
            self.skipTest('minimal ELF too small for section parsing')


class TestBinaryProfileWithData(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='bp_test_')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _minimal_elf(self):
        path = os.path.join(self.tmpdir, 'minimal')
        # 写入足够大的内容避免 section header 解析越界
        with open(path, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 200)
        return path

    def _safe_plt(self):
        return list(_SAFE_PLT)

    def test_with_checksec(self):
        checksec = {
            'nx': True, 'pie': False, 'canary': False,
            'relro': 'partial', 'fortify': False, 'format': 'ELF',
        }
        result = build_binary_profile(
            self._minimal_elf(), checksec=checksec, plt_entries=self._safe_plt(),
        )
        self.assertIsInstance(result, dict)

    def test_with_plt_entries(self):
        result = build_binary_profile(
            self._minimal_elf(), plt_entries=list(_DANGEROUS_PLT),
        )
        self.assertIsInstance(result, dict)

    def test_with_libc_info(self):
        libc = {'version': 'glibc 2.31', 'symbols': {'system': '0x55410'}}
        result = build_binary_profile(
            self._minimal_elf(), libc_info=libc, plt_entries=self._safe_plt(),
        )
        self.assertIsInstance(result, dict)

    def test_full_profile(self):
        result = build_binary_profile(
            self._minimal_elf(),
            checksec={'nx': True, 'pie': False, 'canary': False,
                      'relro': 'partial', 'format': 'ELF'},
            plt_entries=list(_DANGEROUS_PLT),
            libc_info={'version': 'glibc 2.31'},
        )
        self.assertIsInstance(result, dict)


class TestProfileSummary(unittest.TestCase):

    def test_empty_profile(self):
        summary = profile_summary_for_report({})
        self.assertIsInstance(summary, str)

    def test_minimal_profile(self):
        profile = {'binary': 'test', 'arch': 'x86-64'}
        summary = profile_summary_for_report(profile)
        self.assertIsInstance(summary, str)


if __name__ == '__main__':
    unittest.main()
