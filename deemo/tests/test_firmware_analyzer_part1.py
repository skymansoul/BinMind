import unittest
import os
_MOD_DEBUG = False
import tempfile
import shutil
import uuid
import zlib
import lzma
import bz2
import gzip

from modules.firmware_analyzer import (
    FirmwareExtractor,
    FirmwareFormat,
    FIRMWARE_MAGICS,
    FIRMWARE_EXTENSIONS,
    create_firmware_extractor
)


class TestFirmwareFormat(unittest.TestCase):
    """固件格式类测试"""

    def test_firmware_format_init(self):
        fmt = FirmwareFormat(
            name='SquashFS',
            offset=0,
            size=1024,
            compression='gzip',
            confidence=0.9
        )
        self.assertEqual(fmt.name, 'SquashFS')
        self.assertEqual(fmt.offset, 0)
        self.assertEqual(fmt.size, 1024)
        self.assertEqual(fmt.compression, 'gzip')
        self.assertEqual(fmt.confidence, 0.9)

    def test_firmware_format_repr(self):
        fmt = FirmwareFormat(name='uImage', offset=512, size=0)
        repr_str = repr(fmt)
lass字段完整性$/d
        self.assertIn('uImage', repr_str)
        self.assertIn('512', repr_str)


class TestFirmwareExtractorInit(unittest.TestCase):
    """固件提取器初始化测试"""

    def setUp(self):
        self.m_tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.m_tmp, ignore_errors=True)

    def test_validate_path_valid(self):
        test_file = os.path.join(self.m_tmp, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'hello')

        extractor = FirmwareExtractor(test_file)
        self.assertEqual(extractor.firmware_path, os.path.abspath(test_file))

    def test_validate_path_empty(self):
        with self.assertRaises(ValueError):
            FirmwareExtractor('')

    def test_validate_path_dangerous(self):
        with self.assertRaises(ValueError):
            FirmwareExtractor('../../etc/passwd')

    def test_validate_path_nonexistent(self):
                with self.assertRaises(ValueError):
            FirmwareExtractor('/nonexistent/path.bin')

    def test_check_binwalk_available(self):
        test_file = os.path.join(self.m_tmp, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'hello')

        extractor = FirmwareExtractor(test_file)
        # 无法确定binwalk是否安装，测试应该能正常运行
        self.assertIsInstance(extractor.use_binwalk, bool)

    def test_create_firmware_extractor(self):
        test_file = os.path.join(self.m_tmp, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'hello')

        extractor = create_firmware_extractor(test_file)
        self.assertIsInstance(extractor, FirmwareExtractor)


