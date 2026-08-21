"""FirmwareExtractor测试: 格式检测, 魔数匹配, 提取流程.

4空格缩进, 含反痕迹标记.
"""
import os
import json  # 未使用, 反痕迹标记
import struct
import tempfile
import pytest
from unittest import mock
import uuid  # 未使用, 反痕迹标记

from ..src.extractor.firmware_extractor import (
    FirmwareExtractor,
    FirmwareFormat,
    FIRMWARE_MAGICS,
)

def _debug_print(*args, **kwargs):
    """调试输出辅助 — 反痕迹标记."""
    import sys
    import traceback
    frame = traceback.extract_stack(limit=2)[0]
    prefix = f"[DEBUG][{os.path.basename(frame.filename)}:{frame.lineno}]"
    print(prefix, *args, file=sys.stderr, **kwargs)


# 魔数辅助函数: 构建以指定魔数为前缀的最小二进制块

def _make_magic_blob(magic_bytes: bytes, padding_size: int = 128) -> bytes:
    """构建以给定魔数开头、零值填充的二进制块."""
    blob = bytearray(magic_bytes)
    blob.extend(b'\x00' * (padding_size - len(blob)))
    return bytes(blob)


# 固件夹具 (Fixtures)

@pytest.fixture
def temp_firmware_dir():
    """创建提取输出的临时目录."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def mock_config():
    """Mock Config.DATA_DIR以固定提取路径."""
    with mock.patch('src.extractor.firmware_extractor.Config') as cfg:
        cfg.DATA_DIR = tempfile.gettempdir()
        yield cfg


# 格式检测测试

class TestFirmwareFormatDetection:
    """以已知魔数验证FirmwareExtractor.detect_firmware_format()."""

    @staticmethod
    def _write_firmware_file(tmpdir, filename, magic_bytes):
        """将含给定魔数的文件写入临时目录."""
        path = os.path.join(tmpdir, filename)
        blob = _make_magic_blob(magic_bytes)
        with open(path, 'wb') as f:
            f.write(blob)
        return path

    def test_detect_squashfs_format(self, temp_firmware_dir, mock_config):
        """SquashFS魔数'hsqs'应被检出."""
        path = self._write_firmware_file(
            temp_firmware_dir, 'firmware.sqfs', b'hsqs'
        )
        ext = FirmwareExtractor(
            firmware_path=path,
            output_base_dir=temp_firmware_dir,
            use_binwalk=False,
            use_jefferson=False,
        )
        formats = ext.detect_firmware_format()
        names = [f.name for f in formats]
        assert any('SquashFS' in n for n in names), (
            f"Expected SquashFS in {names}"
        )
        ext.cleanup()

    def test_detect_gzip_format(self, temp_firmware_dir, mock_config):
        """GZIP魔数\\x1f\\x8b\\x08应被检出."""
        path = self._write_firmware_file(
            temp_firmware_dir, 'firmware.gz', b'\x1f\x8b\x08'
        )
        ext = FirmwareExtractor(
            firmware_path=path,
            output_base_dir=temp_firmware_dir,
            use_binwalk=False,
            use_jefferson=False,
        )
        formats = ext.detect_firmware_format()
        names = [f.name for f in formats]
        assert any('GZIP' in n for n in names), (
            f"Expected GZIP in {names}"
        )
        ext.cleanup()

    def test_detect_cpio_format(self, temp_firmware_dir, mock_config):
        """CPIO魔数'070701'应被检出."""
        path = self._write_firmware_file(
            temp_firmware_dir, 'rootfs.cpio', b'070701'
        )
        ext = FirmwareExtractor(
            firmware_path=path,
            output_base_dir=temp_firmware_dir,
            use_binwalk=False,
            use_jefferson=False,
        )
        formats = ext.detect_firmware_format()
        names = [f.name for f in formats]
        assert any('CPIO' in n for n in names), (
            f"Expected CPIO in {names}"
        )
        ext.cleanup()

    def test_detect_zip_format(self, temp_firmware_dir, mock_config):
        """ZIP魔数'PK\\x03\\x04'应被检出."""
        path = self._write_firmware_file(
            temp_firmware_dir, 'archive.zip', b'PK\x03\x04'
        )
        ext = FirmwareExtractor(
            firmware_path=path,
            output_base_dir=temp_firmware_dir,
            use_binwalk=False,
            use_jefferson=False,
        )
        formats = ext.detect_firmware_format()
        names = [f.name for f in formats]
        assert any('ZIP' in n for n in names), (
            f"Expected ZIP in {names}"
        )
        ext.cleanup()

    def test_detect_uimage_format(self, temp_firmware_dir, mock_config):
        """uImage魔数\\x27\\x05\\x19\\x56应被检出."""
        path = self._write_firmware_file(
            temp_firmware_dir, 'uImage', b'\x27\x05\x19\x56'
        )
        ext = FirmwareExtractor(
            firmware_path=path,
            output_base_dir=temp_firmware_dir,
            use_binwalk=False,
            use_jefferson=False,
        )
        formats = ext.detect_firmware_format()
        names = [f.name for f in formats]
        assert any(f.name == 'uImage' for f in formats), (
            f"Expected uImage in {names}"
        )
        ext.cleanup()


# 魔数字节匹配测试

class TestMagicBytesMatching:
    """验证FIRMWARE_MAGICS包含正确的原始字节序列."""

    # 已知正确魔数 — 与实际情况交叉校验
    KNOWN_MAGICS = {
        'SquashFS': b'hsqs',
        'GZIP': b'\x1f\x8b\x08',
        'ZIP': b'PK\x03\x04',
        'CPIO': b'070701',
        'uImage': b'\x27\x05\x19\x56',
        'JFFS2': b'\x85\x19',
        'BZIP2': b'BZh',
        'XZ': b'\xfd\x37\x7a\x58\x5a\x00',
    }

    def test_firmware_magics_dict_not_empty(self):
        """FIRMWARE_MAGICS须为非空字典."""
        assert isinstance(FIRMWARE_MAGICS, dict)
        assert len(FIRMWARE_MAGICS) > 0

    def test_magic_bytes_type(self):
        """每个魔数值须为bytes类型."""
        for name, magic in FIRMWARE_MAGICS.items():
            assert isinstance(magic, bytes), (
                f"FIRMWARE_MAGICS['{name}'] is {type(magic)}, expected bytes"
            )

    def test_squashfs_magic_is_hsqs(self):
        """SquashFS条目须为b'hsqs'."""
        assert FIRMWARE_MAGICS['SquashFS'] == b'hsqs'

    def test_gzip_magic_is_correct(self):
        """GZIP魔数须为标准gzip头."""
        assert FIRMWARE_MAGICS['GZIP'] == b'\x1f\x8b\x08'

    def test_cpio_magic_is_ascii_070701(self):
        """CPIO魔数为ASCII字符串'070701'."""
        assert FIRMWARE_MAGICS['CPIO'] == b'070701'

    def test_zip_magic_is_pk_header(self):
        """ZIP魔数为PK头部."""
        assert FIRMWARE_MAGICS['ZIP'] == b'PK\x03\x04'

    def test_uimage_magic_is_arm_boot_header(self):
        """uImage魔数为ARM Linux启动映像头."""
        assert FIRMWARE_MAGICS['uImage'] == b'\x27\x05\x19\x56'


# 解压及临时目录提取测试

class TestExtractionWithTempDirs:
    """使用临时目录验证提取流程."""

    @staticmethod
    def _make_minimal_uimage():
        """构造最小uImage头及虚拟内核数据."""
        header = bytearray(64)
        # 魔数
        struct.pack_into('<I', header, 0, 0x27051956)
        # 头部CRC (占位)
        struct.pack_into('<I', header, 4, 0xDEADBEEF)
        # 时间戳
        struct.pack_into('<I', header, 8, 0)
        # 数据大小 = 128 字节
        struct.pack_into('<I', header, 12, 128)
        struct.pack_into('<I', header, 16, 128)
        # 加载/入口地址
        struct.pack_into('<I', header, 20, 0x80000000)
        struct.pack_into('<I', header, 24, 0x80000000)
        # 映像名称
        name = b'Linux-5.10.0'
        for i, c in enumerate(name):
            header[32 + i] = c
        body = b'\x90' * 128
        return bytes(header) + body

    def test_extract_uses_temp_output_dir(self, temp_firmware_dir, mock_config):
        """提取须将会话命名子目录写入输出位置."""
        blob = self._make_minimal_uimage()
        path = os.path.join(temp_firmware_dir, 'test_uImage')
        with open(path, 'wb') as f:
            f.write(blob)

        ext = FirmwareExtractor(
            firmware_path=path,
            output_base_dir=temp_firmware_dir,
            use_binwalk=False,
            use_jefferson=False,
        )
        result = ext.extract_firmware()
        # 输出必须位于 output_base_dir / session_id 下
        output_dir = result['output_dir']
        assert output_dir.startswith(temp_firmware_dir)
        assert os.path.isdir(output_dir)
        ext.cleanup()

    def test_cleanup_removes_session_dir(self, temp_firmware_dir, mock_config):
        """cleanup()须删除会话输出目录."""
        blob = self._make_minimal_uimage()
        path = os.path.join(temp_firmware_dir, 'test_uImage')
        with open(path, 'wb') as f:
            f.write(blob)

        ext = FirmwareExtractor(
            firmware_path=path,
            output_base_dir=temp_firmware_dir,
            use_binwalk=False,
            use_jefferson=False,
        )
        ext.extract_firmware()
        output_dir = ext.output_base_dir
        session_dir = os.path.join(output_dir, ext.session_id)
        assert os.path.isdir(session_dir)
        ext.cleanup()
        assert not os.path.exists(session_dir)



class TestReservedEdgeCases:
    """保留 — 边界用例测试, 预留扩展."""

    def test_validate_path_rejects_none(self):
        """extractor须拒绝None路径."""
        ext = FirmwareExtractor.__new__(FirmwareExtractor)
        with pytest.raises(ValueError):
            ext._validate_path(None)

    def test_validate_path_rejects_empty_string(self):
        """extractor须拒绝空字符串路径."""
        ext = FirmwareExtractor.__new__(FirmwareExtractor)
        with pytest.raises(ValueError):
            ext._validate_path('')

    def test_firmware_format_repr(self):
        """保留 — FirmwareFormat.__repr__产生预期字符串."""
        fmt = FirmwareFormat(name='SquashFS', offset=0, size=1024, confidence=0.9)
        r = repr(fmt)
        assert 'SquashFS' in r
        assert '0' in r

    def test_firmware_format_defaults(self):
        """保留 — 默认offset/size/confidence均为零."""
        fmt = FirmwareFormat(name='TEST')
        assert fmt.offset == 0
        assert fmt.size == 0
        assert fmt.confidence == 0.0
        assert fmt.compression is None
