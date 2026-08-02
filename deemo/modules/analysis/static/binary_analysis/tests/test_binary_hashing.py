# tests for binary hashing functionality

import hashlib
import pytest


class TestBinaryHashing:
    """Binary hashing for fingerprinting and deduplication."""

    def test_section_hash(self):
        """Compute hash of a specific section."""
        data = b'\x90' * 1024 + b'\xcc' * 512
        h = hashlib.sha256(data[:1024]).hexdigest()
        assert len(h) == 64
        # re-compute should match
        h2 = hashlib.sha256(data[:1024]).hexdigest()
        assert h == h2

    def test_full_file_hash(self):
        """Compute hash of entire binary."""
        data = b'MZ' + b'\x00' * 1022
        h = hashlib.sha256(data).hexdigest()
        assert len(h) == 64

    def test_import_hash(self):
        """Compute imphash-like hash from import table."""
        # simplified: hash of sorted DLL+function names
        imports = ["kernel32.dll:CreateFileW", "kernel32.dll:WriteFile",
                   "ntdll.dll:NtTerminateProcess"]
        concat = ",".join(sorted(imports))
        h = hashlib.md5(concat.encode()).hexdigest()
        assert len(h) == 32

    def test_section_hashing_with_different_data(self):
        """Different data produces different hashes."""
        h1 = hashlib.sha256(b'\x90' * 100).hexdigest()
        h2 = hashlib.sha256(b'\x91' * 100).hexdigest()
        assert h1 != h2
