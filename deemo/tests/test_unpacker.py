import unittest
import os
import tempfile
from unittest.mock import patch, MagicMock
from modules.unpacker import Unpacker


class TestUnpacker(unittest.TestCase):
    """
    Unpacker 模块测试类
    """

    def setUp(self):
        """设置测试环境"""
        self.unpacker = Unpacker()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """清理测试环境"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detect_packer_empty_path(self):
        """测试检测空路径"""
        result = self.unpacker.detect_packer("")
        self.assertEqual(result, ('unknown', 0.0))

    def test_detect_packer_nonexistent_file(self):
        """测试检测不存在的文件"""
        result = self.unpacker.detect_packer("/nonexistent/file.bin")
        self.assertEqual(result, ('unknown', 0.0))

    def test_detect_packer_elf_file(self):
        """测试检测普通 ELF 文件（未加壳）"""
        # 创建一个简单的 ELF 头文件
        elf_header = b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        test_file = os.path.join(self.temp_dir, 'test.elf')
        with open(test_file, 'wb') as f:
            f.write(elf_header)
        
        result = self.unpacker.detect_packer(test_file)
        self.assertEqual(result[0], 'unknown')

    def test_detect_packer_pe_file(self):
        """测试检测普通 PE 文件（未加壳）"""
        pe_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
        test_file = os.path.join(self.temp_dir, 'test.exe')
        with open(test_file, 'wb') as f:
            f.write(pe_header)
        
        result = self.unpacker.detect_packer(test_file)
        self.assertEqual(result[0], 'unknown')

    def test_is_packed_empty_path(self):
        """测试 is_packed 方法空路径"""
        result = self.unpacker.is_packed("")
        self.assertFalse(result)

    def test_unpack_if_needed_nonexistent(self):
        """测试 unpack_if_needed 不存在的文件"""
        result = self.unpacker.unpack_if_needed("/nonexistent/file.bin")
        self.assertIsNone(result)

    @patch('subprocess.run')
    def test_unpack_with_upx_success(self, mock_run):
        """测试 UPX 脱壳成功"""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        test_file = os.path.join(self.temp_dir, 'packed.exe')
        with open(test_file, 'wb') as f:
            f.write(b'MZ\x90')
        
        with patch.object(self.unpacker, 'detect_packer', return_value=('UPX', 0.9)):
            result = self.unpacker.unpack_if_needed(test_file)
            self.assertIsNotNone(result)
            self.assertTrue(result.get('unpacked', False))

    @patch('subprocess.run')
    def test_unpack_with_upx_failure(self, mock_run):
        """测试 UPX 脱壳失败"""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result

        test_file = os.path.join(self.temp_dir, 'packed.exe')
        with open(test_file, 'wb') as f:
            f.write(b'MZ\x90')
        
        with patch.object(self.unpacker, 'detect_packer', return_value=('UPX', 0.9)):
            result = self.unpacker.unpack_if_needed(test_file)
            self.assertIsNotNone(result)
            self.assertFalse(result.get('unpacked', False))
            self.assertTrue(result.get('needs_unpack', False))

    def test_calculate_entropy(self):
        """测试熵计算"""
        high_entropy_data = os.urandom(256)
        low_entropy_data = b'\x00' * 256
        
        high_entropy = self.unpacker._calculate_entropy(high_entropy_data)
        low_entropy = self.unpacker._calculate_entropy(low_entropy_data)
        
        self.assertTrue(high_entropy > 7.0)
        self.assertTrue(low_entropy < 1.0)

    def test_detect_obfuscation_no_binary(self):
        """测试检测混淆（无二进制对象）"""
        result = self.unpacker.detect_obfuscation(None)
        self.assertEqual(result, {'obfuscated': False, 'techniques': [], 'severity': 'low'})


if __name__ == '__main__':
    unittest.main()