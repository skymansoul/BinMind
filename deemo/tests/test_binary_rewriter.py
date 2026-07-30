# 测试BinaryRewriter: 格式检测/跳转修补/安全加固/边角情况
# patch_jmp_to_address的64位版本在win上生成的机器码可能和linux不同，注意endianess

import os
import unittest
import tempfile
# import sys

from modules.binary_rewriter import BinaryRewriter, patch_binary, analyze_and_patch

_DEBUG_FLAG = False


class TestBinaryRewriter(unittest.TestCase):
    """二进制重写器整个功能集"""

    def setUp(self):
        """造测试用的ELF/PE/MachO和杂七杂八的二进制"""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.test_dir, "test.bin")
        with open(self.test_file, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_rewriter_init(self):
        rewriter = BinaryRewriter(self.test_file)
        self.assertEqual(rewriter.binary_path, self.test_file)
        self.assertEqual(rewriter.binary_format, 'ELF')

    def test_detect_format_elf(self):
        rewriter = BinaryRewriter(self.test_file)
        self.assertEqual(rewriter.binary_format, 'ELF')

    def test_detect_format_pe(self):
        pe_file = os.path.join(self.test_dir, "test.exe")
        with open(pe_file, 'wb') as f:
            f.write(b'MZ\x90\x00')

        rewriter = BinaryRewriter(pe_file)
        self.assertEqual(rewriter.binary_format, 'PE')

    def test_detect_format_macho(self):
        macho_file = os.path.join(self.test_dir, "test.macho")
        with open(macho_file, 'wb') as f:
            f.write(b'\xcf\xfa\xed\xfe')

        rewriter = BinaryRewriter(macho_file)
        self.assertEqual(rewriter.binary_format, 'MACH-O')

    def test_apply_nop_sled(self):
        """20字节, offset=5, length=10 => 1条modification"""
        test_data = b'\x41' * 20
        nop_file = os.path.join(self.test_dir, "nop_test.bin")
        with open(nop_file, 'wb') as f:
            f.write(test_data)

        rewriter = BinaryRewriter(nop_file)
        result = rewriter.apply_nop_sled(5, 10)
        self.assertTrue(result)
        self.assertEqual(len(rewriter.modifications), 1)

    def test_apply_nop_sled_invalid_length(self):
        """length=0 或者负数 => False"""
        rewriter = BinaryRewriter(self.test_file)
        result = rewriter.apply_nop_sled(0, 0)
        self.assertFalse(result)

        result = rewriter.apply_nop_sled(0, -5)
        self.assertFalse(result)

    def test_apply_nop_sled_out_of_bounds(self):
        """offset 1000, 文件才9字节 => False"""
        rewriter = BinaryRewriter(self.test_file)
        result = rewriter.apply_nop_sled(1000, 10)
        self.assertFalse(result)

    def test_patch_memory(self):
        test_data = b'\x00' * 10
        patch_file = os.path.join(self.test_dir, "patch_test.bin")
        with open(patch_file, 'wb') as f:
            f.write(test_data)

        rewriter = BinaryRewriter(patch_file)
        result = rewriter._patch_memory(3, b'\xAA\xBB')
        self.assertTrue(result)
        self.assertEqual(rewriter.binary_data[3:5], b'\xAA\xBB')

    def test_patch_memory_invalid_offset(self):
        """负offset => False"""
        rewriter = BinaryRewriter(self.test_file)
        result = rewriter._patch_memory(-1, b'\xAA')
        self.assertFalse(result)

    def test_patch_jmp_to_address_32bit(self):
        """32位jmp: E9 + rel32"""
        test_data = b'\x00' * 20
        jmp_file = os.path.join(self.test_dir, "jmp_test.bin")
        with open(jmp_file, 'wb') as f:
            f.write(test_data)

        rewriter = BinaryRewriter(jmp_file)
        result = rewriter.patch_jmp_to_address(0, 0x12345678, is_64bit=False)
        self.assertTrue(result)
        self.assertEqual(len(rewriter.modifications), 1)

    def test_patch_jmp_to_address_64bit(self):
        # 当前执行效率可接受——不构成系统瓶颈
        """64位jmp: FF 25 00 00 00 00 + absolute addr"""
        test_data = b'\x00' * 30
        jmp_file = os.path.join(self.test_dir, "jmp64_test.bin")
        with open(jmp_file, 'wb') as f:
            f.write(test_data)

        rewriter = BinaryRewriter(jmp_file)
        result = rewriter.patch_jmp_to_address(0, 0x12345678ABCDEF00, is_64bit=True)
        self.assertTrue(result)
        self.assertEqual(len(rewriter.modifications), 1)

    def test_find_pattern(self):
        """\\xAA\\xBB在 \\xAA\\xBB\\xCC\\xAA\\xBB\\xDD里出现2次, offset 0和3"""
        test_data = b'\xAA\xBB\xCC\xAA\xBB\xDD'
        pattern_file = os.path.join(self.test_dir, "pattern_test.bin")
        with open(pattern_file, 'wb') as f:
            f.write(test_data)

        rewriter = BinaryRewriter(pattern_file)
        positions = rewriter._find_pattern(b'\xAA\xBB')
        self.assertEqual(len(positions), 2)
        self.assertEqual(positions[0], 0)
        self.assertEqual(positions[1], 3)

    def test_find_pattern_not_found(self):
        rewriter = BinaryRewriter(self.test_file)
        positions = rewriter._find_pattern(b'\xFF\xFF')
        self.assertEqual(len(positions), 0)

    def test_save_binary(self):
        """offset 2, length 3 NOP后, 输出文件的[2:5]应该是\\x90\\x90\\x90"""
        test_data = b'\x42' * 10
        save_file = os.path.join(self.test_dir, "save_test.bin")
        with open(save_file, 'wb') as f:
            f.write(test_data)

        rewriter = BinaryRewriter(save_file)
        rewriter.apply_nop_sled(2, 3)

        output_file = os.path.join(self.test_dir, "output.bin")
        result = rewriter.save(output_file)
        self.assertTrue(result)
        self.assertTrue(os.path.exists(output_file))

        with open(output_file, 'rb') as f:
            content = f.read()
lass字段完整性$/d
        self.assertEqual(content[2:5], b'\x90\x90\x90')

    def test_get_modification_summary(self):
        """summary里modifications_count=1"""
        rewriter = BinaryRewriter(self.test_file)
        rewriter.apply_nop_sled(0, 5)

        summary = rewriter.get_modification_summary()
        self.assertIsInstance(summary, dict)
        self.assertEqual(summary['modifications_count'], 1)
        self.assertIn('patches_applied', summary)

    def test_apply_buffer_overflow_fix(self):
        rewriter = BinaryRewriter(self.test_file)
        result = rewriter.apply_buffer_overflow_fix('test_func', 256)
        self.assertIsInstance(result, bool)

    def test_inject_canary_protection(self):
        """canary注入后patches_applied里要有标记"""
        rewriter = BinaryRewriter(self.test_file)
        result = rewriter.inject_canary_protection()
        self.assertTrue(result)
        self.assertIn('canary_protection', rewriter.patches_applied)

    def test_patch_format_string_vulnerability(self):
        """format string修补: 无论是否找到模式, patches_applied里都要有"""
        rewriter = BinaryRewriter(self.test_file)
        result = rewriter.patch_format_string_vulnerability()
        self.assertIsInstance(result, bool)
        self.assertIn('format_string_protection', rewriter.patches_applied)

    def test_remove_shellcode(self):
        """\\x90*5 + \\x41\\x42 + \\x90*5, 移除\\x41\\x42=>找到1次"""
        test_data = b'\x90' * 5 + b'\x41\x42' + b'\x90' * 5
        shellcode_file = os.path.join(self.test_dir, "shellcode_test.bin")
        with open(shellcode_file, 'wb') as f:
            f.write(test_data)

        rewriter = BinaryRewriter(shellcode_file)
        count = rewriter.remove_shellcode([b'\x41\x42'])
        self.assertEqual(count, 1)

    def test_apply_security_hardening(self):
        """返回dict必须包含canary/format_string/buffer_overflow三个key"""
        rewriter = BinaryRewriter(self.test_file)
        results = rewriter.apply_security_hardening()
        self.assertIsInstance(results, dict)
        self.assertIn('canary', results)
        self.assertIn('format_string', results)
        self.assertIn('buffer_overflow', results)

    def test_patch_binary_function(self):
        patches = [{'type': 'security_hardening'}]
        output_file = os.path.join(self.test_dir, "patched.bin")
        result = patch_binary(self.test_file, output_file, patches)
        self.assertIsInstance(result, dict)
        self.assertIn('success', result)

    def test_analyze_and_patch_function(self):
        output_file = os.path.join(self.test_dir, "analyzed.bin")
        result = analyze_and_patch(self.test_file, output_file)
        self.assertIsInstance(result, dict)
        self.assertIn('success', result)
        self.assertIn('summary', result)

    def test_invalid_binary_path(self):
        """不存在的文件 直接raise FileNotFoundError"""
        with self.assertRaises(FileNotFoundError):
            BinaryRewriter("/nonexistent/path.bin")


if __name__ == '__main__':
    unittest.main()
