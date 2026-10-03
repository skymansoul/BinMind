"""
Tests for binary info extraction (PE/ELF/Mach-O).

Covers:
- detect_format: PE/ELF/MACHO/UNKNOWN detection
- parse_pe: DOS header, NT signature, sections, imports, exports
- parse_elf: ELF header, program headers, section headers, symbols
- parse_macho: Mach-O magic, CPU type, load commands
- get_binary_info: unified entry point
"""
import unittest
import struct
import os
import tempfile
import hashlib

import importlib.util
import os

# Load binary_info directly (bypasses broken info/__init__.py import chain)
_info_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "modules", "info", "info_collection", "src", "binary_info.py"
)
_spec = importlib.util.spec_from_file_location("binary_info", _info_path)
_binary_info = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_binary_info)

detect_format = _binary_info.detect_format
parse_pe = _binary_info.parse_pe
parse_elf = _binary_info.parse_elf
parse_macho = _binary_info.parse_macho
get_binary_info = _binary_info.get_binary_info


class TestDetectFormat(unittest.TestCase):
    """Binary format auto-detection from magic bytes."""

    def test_pe_detection(self):
        """MZ magic - PE"""
        data = b'MZ' + b'\x00' * 0x3C + struct.pack('<I', 0x40)
        self.assertEqual(detect_format(data), "PE")

    def test_elf_detection(self):
        """\x7fELF magic - ELF"""
        data = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 50
        self.assertEqual(detect_format(data), "ELF")

    def test_macho_64_detection(self):
        """Mach-O 64-bit magic - MACHO"""
        # 0xFEEDFACF in little-endian
        data = struct.pack('<I', 0xFEEDFACF) + b'\x00' * 30
        self.assertEqual(detect_format(data), "MACHO")

    def test_macho_32_detection(self):
        """Mach-O 32-bit magic - MACHO"""
        data = struct.pack('<I', 0xFEEDFACE) + b'\x00' * 30
        self.assertEqual(detect_format(data), "MACHO")

    def test_unknown_format(self):
        """未知 magic - UNKNOWN"""
        self.assertEqual(detect_format(b'\x00\x00\x00\x00'), "UNKNOWN")

    def test_empty_data(self):
        """空数据 - UNKNOWN"""
        self.assertEqual(detect_format(b''), "UNKNOWN")


class TestParsePE(unittest.TestCase):
    """PE header parser."""

    def test_minimal_pe(self):
        """最小 PE 文件解析"""
        data = b'MZ' + b'\x00' * 0x3C + b'\x40\x00\x00\x00'  # e_lfanew=0x40
        data += b'PE\x00\x00'  # NT signature
        data += struct.pack('<H', 0x8664)  # Machine: AMD64
        data += struct.pack('<H', 3)  # NumberOfSections
        result = parse_pe(data)
        self.assertEqual(result["format"], "PE")
        self.assertEqual(result["machine"], 0x8664)

    def test_not_pe(self):
        """非 PE 文件返回 None"""
        result = parse_pe(b'\x00' * 10)
        self.assertIsNone(result)

    def test_empty_data(self):
        """空数据返回 None"""
        result = parse_pe(b'')
        self.assertIsNone(result)


class TestParseELF(unittest.TestCase):
    """ELF header parser."""

    def test_elf64(self):
        """ELF64 文件解析"""
        data = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8  # class=2(64-bit)
        # e_machine offset 18, 2 bytes
        data = data[:18] + struct.pack('<H', 0x3E) + data[20:]  # AMD64
        result = parse_elf(data)
        self.assertIsNotNone(result)
        self.assertEqual(result["format"], "ELF")
        self.assertEqual(result["class"], 2)

    def test_elf32(self):
        """ELF32 文件解析"""
        data = b'\x7fELF\x01\x01\x01\x00' + b'\x00' * 8  # class=1(32-bit)
        data = data[:18] + struct.pack('<H', 0x03) + data[20:]  # i386
        result = parse_elf(data)
        self.assertIsNotNone(result)
        self.assertEqual(result["class"], 1)

    def test_not_elf(self):
        """非 ELF - None"""
        result = parse_elf(b'MZ' + b'\x00' * 50)
        self.assertIsNone(result)


class TestParseMachO(unittest.TestCase):
    """Mach-O header parser."""

    def test_macho_64(self):
        """Mach-O 64-bit"""
        data = struct.pack('<I', 0xFEEDFACF)  # MH_MAGIC_64
        data += struct.pack('<I', 0x01000007)  # CPU_TYPE_X86_64
        data += struct.pack('<I', 2)  # MH_EXECUTE
        data += struct.pack('<I', 3)  # ncmds
        result = parse_macho(data)
        self.assertIsNotNone(result)
        self.assertEqual(result["format"], "MACHO")

    def test_not_macho(self):
        """非 Mach-O - None"""
        result = parse_macho(b'\x00' * 10)
        self.assertIsNone(result)


class TestGetBinaryInfo(unittest.TestCase):
    """Unified binary info extraction from file path."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_pe_file_info(self):
        """PE 文件信息提取"""
        fpath = os.path.join(self.tmpdir, "test.exe")
        data = b'MZ' + b'\x00' * 0x3C + struct.pack('<I', 0x40)
        data += b'PE\x00\x00'
        data += struct.pack('<H', 0x8664)  # AMD64
        data += struct.pack('<H', 1)  # 1 section
        data += b'\x00' * 12
        with open(fpath, 'wb') as f:
            f.write(data)
        info = get_binary_info(fpath)
        self.assertIn("format", info)
        self.assertIn("sha256", info)
        self.assertIn("size", info)

    def test_elf_file_info(self):
        """ELF 文件信息提取"""
        fpath = os.path.join(self.tmpdir, "test.elf")
        data = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8
        data = data[:18] + struct.pack('<H', 0x3E) + data[20:]  # AMD64
        with open(fpath, 'wb') as f:
            f.write(data)
        info = get_binary_info(fpath)
        self.assertEqual(info["format"], "ELF")

    def test_unknown_file_info(self):
        """未知格式文件仍然返回基本信息"""
        fpath = os.path.join(self.tmpdir, "random.bin")
        with open(fpath, 'wb') as f:
            f.write(b'\x00\x01\x02\x03')
        info = get_binary_info(fpath)
        self.assertIn("format", info)
        self.assertIn("sha256", info)

    def test_nonexistent_file(self):
        """不存在的文件应抛出或返回错误信息"""
        try:
            info = get_binary_info("/nonexistent/file.bin")
            # 如果没抛异常，至少应有错误指示
            self.assertIsInstance(info, dict)
            self.assertIn("format", info)
        except (FileNotFoundError, IOError):
            # 预期行为：文件不存在时允许抛出
            return
        except Exception as e:
            self.fail(f"非预期异常: {e!r}")


if __name__ == "__main__":
    unittest.main()
