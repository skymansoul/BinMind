import os
import sys
import unittest
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.binary_rewriter import BinaryRewriter, patch_binary, analyze_and_patch


class TestBinaryRewriter(unittest.TestCase):
    """二进制重写器单元测试"""

    def setUp(self):
        """设置测试环境"""
        self.test_dir = tempfile.mkdtemp()
        # 创建一个测试二进制文件
        self.test_file = os.path.join(self.test_dir, "test.bin")
        with open(self.test_file, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00')

    def tearDown(self):
        """清理测试环境"""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_rewriter_init(self):
        """测试重写器初始化"""
        rewriter = BinaryRewriter(self.test_file)
        self.assertEqual(rewriter.binary_path, self.test_file)
        self.assertEqual(rewriter.binary_format, 'ELF')

    def test_detect_format_elf(self):
        """测试检测 ELF 格式"""
        rewriter = BinaryRewriter(self.test_file)
        self.assertEqual(rewriter.binary_format, 'ELF')

    def test_detect_format_pe(self):
        """测试检测 PE 格式"""
        pe_file = os.path.join(self.test_dir, "test.exe")
        with open(pe_file, 'wb') as f:
            f.write(b'MZ\x90\x00')
        
        rewriter = BinaryRewriter(pe_file)
        self.assertEqual(rewriter.binary_format, 'PE')

    def test_detect_format_macho(self):
        """测试检测 Mach-O 格式"""
        macho_file = os.path.join(self.test_dir, "test.macho")
        with open(macho_file, 'wb') as f:
            f.write(b'\xcf\xfa\xed\xfe')
        
        rewriter = BinaryRewriter(macho_file)
        self.assertEqual(rewriter.binary_format, 'MACH-O')

    def test_apply_nop_sled(self):
        """测试应用 NOP sled"""
        test_data = b'\x41' * 20
        nop_file = os.path.join(self.test_dir, "nop_test.bin")
        with open(nop_file, 'wb') as f:
            f.write(test_data)
        
        rewriter = BinaryRewriter(nop_file)
        result = rewriter.apply_nop_sled(5, 10)
        
        self.assertTrue(result)
        self.assertEqual(len(rewriter.modifications), 1)

    def test_apply_nop_sled_invalid_length(self):
        """测试应用无效长度的 NOP sled"""
        rewriter = BinaryRewriter(self.test_file)
        result = rewriter.apply_nop_sled(0, 0)
        self.assertFalse(result)
        
        result = rewriter.apply_nop_sled(0, -5)
        self.assertFalse(result)

    def test_apply_nop_sled_out_of_bounds(self):
        """测试越界的 NOP sled"""
        rewriter = BinaryRewriter(self.test_file)
        result = rewriter.apply_nop_sled(1000, 10)
        self.assertFalse(result)

    def test_patch_memory(self):
        """测试内存修补"""
        test_data = b'\x00' * 10
        patch_file = os.path.join(self.test_dir, "patch_test.bin")
        with open(patch_file, 'wb') as f:
            f.write(test_data)
        
        rewriter = BinaryRewriter(patch_file)
        result = rewriter._patch_memory(3, b'\xAA\xBB')
        
        self.assertTrue(result)
        self.assertEqual(rewriter.binary_data[3:5], b'\xAA\xBB')

    def test_patch_memory_invalid_offset(self):
        """测试无效偏移的内存修补"""
        rewriter = BinaryRewriter(self.test_file)
        result = rewriter._patch_memory(-1, b'\xAA')
        self.assertFalse(result)

    def test_patch_jmp_to_address_32bit(self):
        """测试32位跳转修补"""
        test_data = b'\x00' * 20
        jmp_file = os.path.join(self.test_dir, "jmp_test.bin")
        with open(jmp_file, 'wb') as f:
            f.write(test_data)
        
        rewriter = BinaryRewriter(jmp_file)
        result = rewriter.patch_jmp_to_address(0, 0x12345678, is_64bit=False)
        
        self.assertTrue(result)
        self.assertEqual(len(rewriter.modifications), 1)

    def test_patch_jmp_to_address_64bit(self):
        """测试64位跳转修补"""
        test_data = b'\x00' * 30
        jmp_file = os.path.join(self.test_dir, "jmp64_test.bin")
        with open(jmp_file, 'wb') as f:
            f.write(test_data)
        
        rewriter = BinaryRewriter(jmp_file)
        result = rewriter.patch_jmp_to_address(0, 0x12345678ABCDEF00, is_64bit=True)
        
        self.assertTrue(result)
        self.assertEqual(len(rewriter.modifications), 1)

    def test_find_pattern(self):
        """测试模式查找"""
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
        """测试查找不存在的模式"""
        rewriter = BinaryRewriter(self.test_file)
        positions = rewriter._find_pattern(b'\xFF\xFF')
        
        self.assertEqual(len(positions), 0)

    def test_save_binary(self):
        """测试保存二进制文件"""
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
        
        self.assertEqual(content[2:5], b'\x90\x90\x90')

    def test_get_modification_summary(self):
        """测试获取修改摘要"""
        rewriter = BinaryRewriter(self.test_file)
        rewriter.apply_nop_sled(0, 5)
        
        summary = rewriter.get_modification_summary()
        
        self.assertIsInstance(summary, dict)
        self.assertEqual(summary['modifications_count'], 1)
        self.assertIn('patches_applied', summary)

    def test_apply_buffer_overflow_fix(self):
        """测试应用缓冲区溢出修复"""
        rewriter = BinaryRewriter(self.test_file)
        result = rewriter.apply_buffer_overflow_fix('test_func', 256)
        
        self.assertIsInstance(result, bool)

    def test_inject_canary_protection(self):
        """测试注入金丝雀保护"""
        rewriter = BinaryRewriter(self.test_file)
        result = rewriter.inject_canary_protection()
        
        self.assertTrue(result)
        self.assertIn('canary_protection', rewriter.patches_applied)

    def test_patch_format_string_vulnerability(self):
        """测试修补格式化字符串漏洞"""
        rewriter = BinaryRewriter(self.test_file)
        result = rewriter.patch_format_string_vulnerability()
        
        # 返回值表示是否找到模式，补丁总是会被记录
        self.assertIsInstance(result, bool)
        self.assertIn('format_string_protection', rewriter.patches_applied)

    def test_remove_shellcode(self):
        """测试移除 Shellcode"""
        test_data = b'\x90' * 5 + b'\x41\x42' + b'\x90' * 5
        shellcode_file = os.path.join(self.test_dir, "shellcode_test.bin")
        with open(shellcode_file, 'wb') as f:
            f.write(test_data)
        
        rewriter = BinaryRewriter(shellcode_file)
        count = rewriter.remove_shellcode([b'\x41\x42'])
        
        self.assertEqual(count, 1)

    def test_apply_security_hardening(self):
        """测试应用安全加固"""
        rewriter = BinaryRewriter(self.test_file)
        results = rewriter.apply_security_hardening()
        
        self.assertIsInstance(results, dict)
        self.assertIn('canary', results)
        self.assertIn('format_string', results)
        self.assertIn('buffer_overflow', results)

    def test_patch_binary_function(self):
        """测试 patch_binary 便捷函数"""
        patches = [{'type': 'security_hardening'}]
        output_file = os.path.join(self.test_dir, "patched.bin")
        
        result = patch_binary(self.test_file, output_file, patches)
        
        self.assertIsInstance(result, dict)
        self.assertIn('success', result)

    def test_analyze_and_patch_function(self):
        """测试 analyze_and_patch 便捷函数"""
        output_file = os.path.join(self.test_dir, "analyzed.bin")
        
        result = analyze_and_patch(self.test_file, output_file)
        
        self.assertIsInstance(result, dict)
        self.assertIn('success', result)
        self.assertIn('summary', result)

    def test_invalid_binary_path(self):
        """测试无效的二进制路径"""
        with self.assertRaises(FileNotFoundError):
            BinaryRewriter("/nonexistent/path.bin")


if __name__ == '__main__':
    unittest.main()
