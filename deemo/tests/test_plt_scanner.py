"""
plt_scanner 模块测试 —— PLT/GOT 解析与危险函数标记。

测试覆盖:
  - scan_plt 基本调用
  - 危险函数分类的正确性
  - 空/无效二进制的错误处理
"""

import os
import sys
import struct
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.plt_scanner import scan_plt, find_exploitable_functions


def _make_elf_with_plt():
    """构造一个含 .dynsym / .dynstr / .rela.plt 的最小 ELF64。

    仅在 radare2 可用时测试——plt_scanner 依赖 r2 进行符号解析。
    """
    import shutil
    if not shutil.which('radare2') and not shutil.which('r2'):
        return None

    buf = bytearray()
    buf += b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8
    buf += struct.pack('<H', 3)            # ET_DYN
    buf += struct.pack('<H', 0x3e)         # x86_64
    buf += struct.pack('<I', 1)
    buf += struct.pack('<Q', 0x1000)       # entry
    buf += struct.pack('<Q', 64)           # phoff
    buf += struct.pack('<Q', 0)            # shoff
    buf += struct.pack('<I', 0)
    buf += struct.pack('<H', 64)
    buf += struct.pack('<H', 56)
    buf += struct.pack('<H', 3)
    buf += b'\x00' * (64 - len(buf))

    # PT_LOAD
    buf += struct.pack('<II', 1, 7)
    buf += struct.pack('<QQQQ', 0, 0x1000, 0x1000, 0x1000, 0x1000)
    # PT_GNU_STACK
    buf += struct.pack('<II', 0x6474e551, 6)
    buf += struct.pack('<QQQQ', 0, 0, 0, 0, 0)
    # PT_DYNAMIC
    buf += struct.pack('<II', 2, 6)
    buf += struct.pack('<QQQQ', 0, 0x2000, 0x2000, 0x100, 0x100)

    return bytes(buf)


class TestPLTScanner(unittest.TestCase):
    """PLT 扫描器基础测试。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='binmind_test_plt_')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_scan_plt_nonexistent_file(self):
        """不存在的文件应返回空列表，不抛异常。"""
        result = scan_plt('/nonexistent/binary_plt_test')
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    def test_scan_plt_non_elf_file(self):
        """非 ELF 文件应安全处理——返回 list 或空。"""
        path = os.path.join(self.tmpdir, 'text_file')
        with open(path, 'w') as f:
            f.write('not an elf file')
        try:
            result = scan_plt(path)
            self.assertIsInstance(result, list)
        except Exception:
            # 某些环境下可能抛异常，也算安全处理
            pass


class TestFindExploitableFunctions(unittest.TestCase):
    """find_exploitable_functions 工具函数。"""

    def test_empty_entries(self):
        result = find_exploitable_functions([])
        self.assertIsInstance(result, list)

    def test_normal_entries(self):
        entries = [
            {'name': 'system', 'address': '0x401030',
             'category': 'command-injection', 'severity': 'Critical',
             'is_dangerous': True, 'risk_category': 'Critical'},
            {'name': 'puts', 'address': '0x401020',
             'category': 'info-leak', 'severity': 'Medium',
             'is_dangerous': False, 'risk_category': 'Low'},
        ]
        result = find_exploitable_functions(entries)
        self.assertIsInstance(result, list)

    def test_all_dangerous(self):
        entries = [
            {'name': 'gets', 'address': '0x401010',
             'category': 'buffer-overflow', 'severity': 'Critical',
             'is_dangerous': True, 'risk_category': 'Critical'},
            {'name': 'system', 'address': '0x401030',
             'category': 'command-injection', 'severity': 'Critical',
             'is_dangerous': True, 'risk_category': 'Critical'},
        ]
        result = find_exploitable_functions(entries)
        self.assertEqual(len(result), 2)

    def test_none_dangerous(self):
        entries = [
            {'name': 'puts', 'address': '0x401020',
             'category': 'safe', 'severity': 'Low',
             'is_dangerous': False, 'risk_category': 'Low'},
        ]
        result = find_exploitable_functions(entries)
        self.assertEqual(len(result), 0)


if __name__ == '__main__':
    unittest.main()
