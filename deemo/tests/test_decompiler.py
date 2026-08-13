import unittest
from unittest.mock import patch, MagicMock

from core.decompiler import strip_ansi


class TestStripAnsi(unittest.TestCase):

    def test_no_ansi(self):
        self.assertEqual(strip_ansi('hello world'), 'hello world')

    def test_color_code_removed(self):
        text = '\x1b[31mred text\x1b[0m'
        self.assertEqual(strip_ansi(text), 'red text')

    def test_complex_ansi_sequence(self):
        text = '\x1b[1;32;44mbold green on blue\x1b[0m'
        self.assertEqual(strip_ansi(text), 'bold green on blue')

    def test_multiple_ansi_in_one_line(self):
        text = '\x1b[31mERROR\x1b[0m: \x1b[33mwarning\x1b[0m'
        self.assertEqual(strip_ansi(text), 'ERROR: warning')

    def test_empty_string(self):
        self.assertEqual(strip_ansi(''), '')


class TestDecompileFunction(unittest.TestCase):
    """Test decompile_function return structure without a real binary."""

    def test_return_structure(self):
        """即使r2unavailable，返回结构也应包含必要field"""
        from core.decompiler import decompile_function

        # 用一个几乎肯定does not exist的binarypath，子process会failed
        # 但函数不应该抛exception，应该返回带默认value的dict
        try:
            result = decompile_function('/dev/null/nonexistent', 'main',
                                        decompiler='auto')
        except Exception as e:
            self.fail(f'decompile_function raised {type(e).__name__}: {e}')

        self.assertIsInstance(result, dict)
        self.assertIn('name', result)
        self.assertIn('pseudocode', result)
        self.assertIn('raw_asm', result)
        self.assertIn('decompiler', result)
        self.assertEqual(result['name'], 'main')


class TestListFunctionsReturnType(unittest.TestCase):
    """test list_functions 返回type"""

    def test_returns_list_on_failure(self):
        from core.decompiler import list_functions

        # file not found时也应返回空list，不抛exception
        try:
            funcs = list_functions('/tmp/nonexistent_binary_xyz')
        except Exception as e:
            self.fail(f'list_functions raised {type(e).__name__}: {e}')

        self.assertIsInstance(funcs, list)


if __name__ == '__main__':
    unittest.main()
