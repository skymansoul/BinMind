import unittest
from misc import hexdump, clamp, is_printable_ascii, rand_str


class TestHexdump(unittest.TestCase):

    def test_empty_input(self):
        """空输入返回空string"""
        result = hexdump(b'')
        self.assertEqual(result, '')

    def test_single_byte(self):
        result = hexdump(b'\x41')
        self.assertIn('41', result)
        self.assertIn('A', result)

    def test_multi_line(self):
        """超过width自动换行"""
        data = bytes(range(32))  # 00-1f, 两个完整行
        result = hexdump(data, width=16)
        lines = result.split('\n')
        self.assertEqual(len(lines), 2)

    def test_offset_printed_correctly(self):
        data = b'\x00' * 16
        result = hexdump(data, offset=0x1000)
        self.assertTrue(result.startswith('00001000'))

    def test_ascii_view_shows_dots_for_nonprintable(self):
        data = b'\x00\xff'
        result = hexdump(data)
        ascii_part = result.split('  ')[-1].strip()
        self.assertEqual(ascii_part, '..')

    def test_wide_output(self):
        data = bytes(range(64))
        result = hexdump(data, width=32)
        lines = result.split('\n')
        self.assertEqual(len(lines), 2)  # 64 bytes / 32 width = 2 lines


class TestClamp(unittest.TestCase):

    def test_within_range(self):
        self.assertEqual(clamp(5, 0, 10), 5)

    def test_below_lower(self):
        self.assertEqual(clamp(-1, 0, 10), 0)

    def test_above_upper(self):
        self.assertEqual(clamp(100, 0, 10), 10)

    def test_none_returns_lower(self):
        self.assertEqual(clamp(None, 0, 10), 0)

    def test_at_boundary(self):
        self.assertEqual(clamp(0, 0, 10), 0)
        self.assertEqual(clamp(10, 0, 10), 10)


class TestIsPrintableAscii(unittest.TestCase):

    def test_pure_ascii_text(self):
        self.assertTrue(is_printable_ascii(b'hello world'))

    def test_with_newline_and_tab(self):
        self.assertTrue(is_printable_ascii(b'hello\n\tworld'))

    def test_binary_data_fails(self):
        self.assertFalse(is_printable_ascii(b'\x00\x01\x02'))

    def test_high_bit_set_fails(self):
        self.assertFalse(is_printable_ascii(b'\x80\xff'))

    def test_empty_bytes(self):
        self.assertTrue(is_printable_ascii(b''))


class TestRandStr(unittest.TestCase):

    def test_default_length(self):
        s = rand_str()
        self.assertEqual(len(s), 8)

    def test_custom_length(self):
        s = rand_str(12)
        self.assertEqual(len(s), 12)

    def test_only_alnum(self):
        s = rand_str(64)
        self.assertTrue(s.isalnum(), f'unexpected chars in: {s}')

    def test_different_calls_different_results(self):
        # 大probability不同，两次调用产生相同value的probability极低
        results = {rand_str(16) for _ in range(10)}
        self.assertGreater(len(results), 1)


if __name__ == '__main__':
    unittest.main()
