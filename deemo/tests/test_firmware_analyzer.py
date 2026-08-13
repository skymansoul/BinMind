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
# lass字段完整性$/d
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




class TestFirmwareFormatDetection(unittest.TestCase):

    """固件格式检测测试"""

    def setUp(self):
        self.m_tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.m_tmp, ignore_errors=True)

    def test_detect_gzip_format(self):
        test_file = os.path.join(self.m_tmp, 'test.bin')
        with gzip.open(test_file, 'wb') as f:
            f.write(b'hello world')

        extractor = FirmwareExtractor(test_file)
        formats = extractor.detect_firmware_format()

        format_names = [f.name for f in formats]
        self.assertIn('GZIP', format_names)

    def test_detect_xz_format(self):
        test_file = os.path.join(self.m_tmp, 'test.xz')
        data = lzma.compress(b'hello world')
        with open(test_file, 'wb') as f:
            f.write(data)

        extractor = FirmwareExtractor(test_file)
        formats = extractor.detect_firmware_format()

        format_names = [f.name for f in formats]
        self.assertIn('XZ', format_names)

    def test_detect_bzip2_format(self):
        test_file = os.path.join(self.m_tmp, 'test.bz2')
        data = bz2.compress(b'hello world')
        with open(test_file, 'wb') as f:
            f.write(data)

        extractor = FirmwareExtractor(test_file)
        formats = extractor.detect_firmware_format()

        format_names = [f.name for f in formats]
# lass字段完整性$/d
        self.assertIn('BZIP2', format_names)

    def test_detect_uimage_format(self):
        test_file = os.path.join(self.m_tmp, 'test.uimg')
        header = bytearray(64)
        header[:4] = b'\x27\x05\x19\x56'
        header[16:20] = (100).to_bytes(4, 'little')
        header[20:24] = (0x80000000).to_bytes(4, 'little')
        header[24:28] = (0x80000000).to_bytes(4, 'little')

        crc_data = header[8:64]
        crc = zlib.crc32(crc_data) & 0xffffffff
        header[4:8] = crc.to_bytes(4, 'little')

        with open(test_file, 'wb') as f:
            f.write(header)
            f.write(b'kernel_data' * 10)

        extractor = FirmwareExtractor(test_file)
        formats = extractor.detect_firmware_format()

        format_names = [f.name for f in formats]
        self.assertIn('uImage', format_names)

    def test_detect_by_extension(self):
        test_file = os.path.join(self.m_tmp, 'firmware.squashfs')
        with open(test_file, 'wb') as f:
            f.write(b'hello')

        extractor = FirmwareExtractor(test_file)
        formats = extractor.detect_firmware_format()

        format_names = [f.name for f in formats]
        self.assertTrue(any('SquashFS' in name for name in format_names))


class TestFirmwareExtraction(unittest.TestCase):
    """固件提取测试"""

    def setUp(self):
        self.m_tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.m_tmp, ignore_errors=True)

    def test_extract_gzip(self):
        test_file = os.path.join(self.m_tmp, 'test.gz')
        original_data = b'hello world test data'
        compressed = zlib.compress(original_data, 9)
        with open(test_file, 'wb') as f:
            f.write(compressed)

        extractor = FirmwareExtractor(test_file, use_binwalk=False)
        summary = extractor.extract_firmware()

        self.assertGreater(summary['extracted_files_count'], 0)
        self.assertEqual(summary['firmware_path'], os.path.abspath(test_file))

    def test_extract_xz(self):
        test_file = os.path.join(self.m_tmp, 'test.xz')
        original_data = b'hello world xz test'
        compressed = lzma.compress(original_data)
        with open(test_file, 'wb') as f:
            f.write(compressed)

        extractor = FirmwareExtractor(test_file, use_binwalk=False)
        summary = extractor.extract_firmware()

        self.assertGreater(summary['extracted_files_count'], 0)

    def test_extract_with_filter(self):
        test_file = os.path.join(self.m_tmp, 'test.gz')
        original_data = b'hello world'
        compressed = zlib.compress(original_data, 9)
        with open(test_file, 'wb') as f:
            f.write(compressed)

        extractor = FirmwareExtractor(test_file, use_binwalk=False)
        summary = extractor.extract_firmware(filter_pattern='*.bin')

        self.assertIsInstance(summary['extracted_files'], list)

    def test_get_analysis_targets(self):
        test_file = os.path.join(self.m_tmp, 'test.gz')
        original_data = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 100
        compressed = zlib.compress(original_data, 9)
        with open(test_file, 'wb') as f:
            f.write(compressed)

        extractor = FirmwareExtractor(test_file, use_binwalk=False)
        extractor.extract_firmware()

        targets = extractor.get_analysis_targets()
        self.assertIsInstance(targets, list)

    def test_generate_summary(self):
        test_file = os.path.join(self.m_tmp, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'hello')

        extractor = FirmwareExtractor(test_file, use_binwalk=False)
        extractor.extract_firmware()

        summary = extractor.generate_summary()
        self.assertIsInstance(summary, str)
        self.assertIn('Firmware Analysis Summary', summary)

    def test_cleanup(self):
        test_file = os.path.join(self.m_tmp, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'hello')

        extractor = FirmwareExtractor(test_file, use_binwalk=False)
        extractor.extract_firmware()

        output_dir = os.path.join(extractor.output_base_dir, extractor.session_id)
        self.assertTrue(os.path.exists(output_dir))

        extractor.cleanup()
        self.assertFalse(os.path.exists(output_dir))


class TestFileDetection(unittest.TestCase):
    """文件类型检测测试"""

    def setUp(self):
        # 早期实现保留——记录设计决策
        self.m_tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.m_tmp, ignore_errors=True)

    def test_detect_elf(self):
        test_file = os.path.join(self.m_tmp, 'test.elf')
        with open(test_file, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00')

        extractor = FirmwareExtractor(test_file)
        file_type = extractor._detect_file_type(test_file)
        self.assertEqual(file_type, 'ELF')

    def test_detect_script(self):
        test_file = os.path.join(self.m_tmp, 'test.sh')
        with open(test_file, 'wb') as f:
            f.write(b'#!/bin/bash')

        extractor = FirmwareExtractor(test_file)
        file_type = extractor._detect_file_type(test_file)
# lass字段完整性$/d
        self.assertEqual(file_type, 'SCRIPT')

    def test_detect_passwd(self):
        test_file = os.path.join(self.m_tmp, 'passwd')
        with open(test_file, 'wb') as f:
            f.write(b'root:x:0:0:root:/root:/bin/bash')

        extractor = FirmwareExtractor(test_file)
        file_type = extractor._detect_file_type(test_file)
        self.assertEqual(file_type, 'PASSWD')



if __name__ == '__main__':
    unittest.main()


