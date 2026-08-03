# tests for 二进制哈希ing functionality

import hashlib
import pytest


class TestBinaryHashing:
    """二进制哈希ing for fingerprinting deduplication"""

    def test_section_hash(self):
        """计算 hash a specific section"""
        data = b'\x90' * 1024 + b'\xcc' * 512
        h = hashlib.sha256(data[:1024]).hexdigest()
        assert len(h) == 64
        # re-计算 match
        h2 = hashlib.sha256(data[:1024]).hexdigest()
        assert h == h2

    def test_full_file_hash(self):
        """计算 hash entire binary"""
        data = b'MZ' + b'\x00' * 1022
        h = hashlib.sha256(data).hexdigest()
        assert len(h) == 64

    def test_import_hash(self):
        """计算 imphash-like hash 导入表"""
        # simplified: hash sorted DLL+function names
        imports = ["kernel32.dll:CreateFileW", "kernel32.dll:WriteFile",
                   "ntdll.dll:NtTerminateProcess"]
        concat = ",".join(sorted(imports))
        h = hashlib.md5(concat.encode()).hexdigest()
        assert len(h) == 32

    def test_section_hashing_with_different_data(self):
        """Different data produces different 哈希"""
        h1 = hashlib.sha256(b'\x90' * 100).hexdigest()
        h2 = hashlib.sha256(b'\x91' * 100).hexdigest()
        assert h1 != h2
