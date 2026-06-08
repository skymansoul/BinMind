import os
import sys
import unittest
import tempfile
import unittest
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from modules.info_collect import (
        validate_elf_file,
        DANGEROUS_FUNCTIONS,
        KEY_STRING_PATTERNS
    )
    PWNTOOLS_AVAILABLE = True
except ImportError:
    PWNTOOLS_AVAILABLE = False


class TestValidateElfFile(unittest.TestCase):

    def test_file_not_exists(self):
        result = validate_elf_file('/nonexistent/file/path.elf')
        self.assertFalse(result)

    def test_directory_instead_of_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = validate_elf_file(temp_dir)
            self.assertFalse(result)

    def test_file_too_small(self):
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b'\x7fEL')
            temp_path = f.name
        
        try:
            result = validate_elf_file(temp_path)
            self.assertFalse(result)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_not_elf_format(self):
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b'\x7fPE\x00\x00\x00\x00')
            temp_path = f.name
        
        try:
            result = validate_elf_file(temp_path)
            self.assertFalse(result)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_valid_elf_magic(self):
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b'\x7fELF\x02\x01\x01\x00')
            temp_path = f.name
        
        try:
            result = validate_elf_file(temp_path)
            self.assertTrue(result)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


class TestDangerousFunctions(unittest.TestCase):

    def test_dangerous_functions_contains_common_ones(self):
        self.assertIn('gets', DANGEROUS_FUNCTIONS)
        self.assertIn('strcpy', DANGEROUS_FUNCTIONS)
        self.assertIn('system', DANGEROUS_FUNCTIONS)
        self.assertIn('execve', DANGEROUS_FUNCTIONS)
        self.assertIn('scanf', DANGEROUS_FUNCTIONS)
        self.assertIn('free', DANGEROUS_FUNCTIONS)

    def test_key_string_patterns(self):
        self.assertIn('system', KEY_STRING_PATTERNS)
        self.assertIn('bin/sh', KEY_STRING_PATTERNS)
        self.assertIn('flag', KEY_STRING_PATTERNS)
        self.assertIn('password', KEY_STRING_PATTERNS)
        self.assertIn('secret', KEY_STRING_PATTERNS)


@unittest.skipUnless(PWNTOOLS_AVAILABLE, "pwntools not installed")
class TestFormatInfoForReport(unittest.TestCase):

    def test_format_empty_info(self):
        from modules.info_collect import format_info_for_report
        result = format_info_for_report({})
        self.assertIn('二进制信息', result)

    def test_format_basic_info(self):
        from modules.info_collect import format_info_for_report
        info = {
            'binary_path': '/path/to/binary',
            'arch': 'amd64',
            'bits': 64,
            'endian': 'little',
            'checksec': {
                'nx': True,
                'pie': True,
                'relro': 'Full',
                'canary': True
            }
        }
        result = format_info_for_report(info)
        
        self.assertIn('amd64', result)
        self.assertIn('64', result)
        self.assertIn('NX', result)
        self.assertIn('PIE', result)
        self.assertIn('RELRO', result)
        self.assertIn('Canary', result)

    def test_format_with_dangerous_functions(self):
        from modules.info_collect import format_info_for_report
        info = {
            'binary_path': '/path/to/binary',
            'arch': 'amd64',
            'bits': 64,
            'checksec': {},
            'imports': {
                'dangerous_functions': ['gets', 'system']
            }
        }
        result = format_info_for_report(info)
        
        self.assertIn('危险函数', result)
        self.assertIn('gets', result)
        self.assertIn('system', result)

    def test_format_with_key_strings(self):
        from modules.info_collect import format_info_for_report
        info = {
            'binary_path': '/path/to/binary',
            'arch': 'amd64',
            'bits': 64,
            'checksec': {},
            'key_strings': ['/bin/sh', 'password', 'flag.txt']
        }
        result = format_info_for_report(info)
        
        self.assertIn('关键字符串', result)
        self.assertIn('/bin/sh', result)
        self.assertIn('password', result)

    def test_format_with_symbols(self):
        from modules.info_collect import format_info_for_report
        info = {
            'binary_path': '/path/to/binary',
            'arch': 'amd64',
            'bits': 64,
            'checksec': {},
            'symbols': {
                'main': 0x114a,
                'win': 0x1234,
                'system': 0x5678
            }
        }
        result = format_info_for_report(info)
        
        self.assertIn('重要符号', result)
        self.assertIn('main', result)
        self.assertIn('win', result)
        self.assertIn('0x114a', result)


if __name__ == '__main__':
    unittest.main()
