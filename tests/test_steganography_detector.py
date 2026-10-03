
import unittest
import sys
import os
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.steganography_detector import (
    SteganoDetector,
    HiddenDataType,
    DetectionConfidence,
    scan_steganography,
    extract_hidden_data
)


class TestSteganographyDetector(unittest.TestCase):
    """隐写检测模块测试"""

    def test_init_detector(self):
        """测试检测器初始化"""
        detector = SteganoDetector()
        self.assertIsNotNone(detector)
        self.assertEqual(detector.entropy_threshold, 0.8)

    def test_calculate_entropy(self):
        """测试计算熵值"""
        detector = SteganoDetector()

        # 高熵数据（随机数据）
        high_entropy_data = bytes([i % 256 for i in range(256)])
        entropy = detector.calculate_entropy(high_entropy_data)
        self.assertGreater(entropy, 0.7)

        # 低熵数据（重复数据）
        low_entropy_data = b'\x00' * 256
        entropy = detector.calculate_entropy(low_entropy_data)
        self.assertLess(entropy, 0.1)

    def test_detect_magic(self):
        detector = SteganoDetector()

        self.assertEqual(detector._detect_magic(b'\x50\x4B\x03\x04'), 'ZIP')
        self.assertEqual(detector._detect_magic(b'\x7F\x45\x4C\x46'), 'ELF')
        self.assertEqual(detector._detect_magic(b'\x4D\x5A'), 'PE/EXE')
        self.assertIsNone(detector._detect_magic(b'\x00\x00\x00\x00'))

    def test_detect_embedded_archives(self):
        """测试检测嵌入的归档文件"""
        detector = SteganoDetector()

        # 创建包含ZIP的测试数据
        import io
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('test.txt', 'hello world')
        zip_data = zip_buffer.getvalue()

        results = detector.detect_embedded_archives(zip_data)

        self.assertTrue(len(results) > 0)
        self.assertEqual(results[0].magic, 'ZIP')
        self.assertEqual(results[0].data_type, HiddenDataType.ZIP_EMBEDDED)

    def test_detect_high_entropy_regions(self):

        """测试检测高熵区域"""
        detector = SteganoDetector()

        # 创建高熵数据（需要至少4096字节才能被检测到）
        high_entropy_data = bytes(range(256)) * 32  # 8192字节高熵数据

        results = detector.detect_high_entropy_regions(high_entropy_data)

        self.assertTrue(len(results) > 0)
        self.assertEqual(results[0].data_type, HiddenDataType.HIGH_ENTROPY)

    def test_scan_file(self):
        """测试扫描文件"""
        detector = SteganoDetector()

        # 创建临时文件
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'hello world' * 100)
            temp_path = f.name

        try:
            result = detector.scan_file(temp_path)
            self.assertIsNotNone(result)
            self.assertEqual(result.file_path, temp_path)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_generate_report(self):
        """测试生成报告"""
        detector = SteganoDetector()
        result = type('obj', (), {
            'file_path': '/test/file.bin',
            'is_suspicious': False,
            'hidden_data': [],
            'notes': []
        })

        report = detector.generate_report(result)
        self.assertIsNotNone(report)
        self.assertIn("隐写", report)



if __name__ == '__main__':
    unittest.main()


