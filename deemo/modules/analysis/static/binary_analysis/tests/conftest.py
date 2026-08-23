# shared fixtures for binary_analysis tests
# minimal ELF32 PE32 stubs for testing real binaries

import os
import struct
import tempfile
import pytest


def _make_elf32_stub():
    """构建 a minimal 32-bit ELF: ELF header + 1 null PHDR + 1 code section"""
    # ELF header (52 bytes for 32-bit)
    e_ident = b'\x7fELF\x01\x01\x01\x00' + b'\x00' * 8  # EI_DATA=1 (LE), EI_VERSION=1
    e_type = struct.pack('<H', 2)  # ET_EXEC
    e_machine = struct.pack('<H', 3)  # EM_386
    e_version = struct.pack('<I', 1)
    e_entry = struct.pack('<I', 0x08048054)
    e_phoff = struct.pack('<I', 52)
    e_shoff = struct.pack('<I', 0)
    e_flags = struct.pack('<I', 0)
    e_ehsize = struct.pack('<H', 52)
    e_phentsize = struct.pack('<H', 32)
    e_phnum = struct.pack('<H', 1)
    e_shentsize = struct.pack('<H', 40)
    e_shnum = struct.pack('<H', 0)
    e_shstrndx = struct.pack('<H', 0)

    elf_header = (e_ident + e_type + e_machine + e_version + e_entry +
                  e_phoff + e_shoff + e_flags + e_ehsize + e_phentsize +
                  e_phnum + e_shentsize + e_shnum + e_shstrndx)

    # program header (32 bytes): PT_LOAD
    p_type = struct.pack('<I', 1)   # PT_LOAD
    p_offset = struct.pack('<I', 0x54)
    p_vaddr = struct.pack('<I', 0x08048054)
    p_paddr = struct.pack('<I', 0x08048054)
    p_filesz = struct.pack('<I', 4)
    p_memsz = struct.pack('<I', 4)
    p_flags = struct.pack('<I', 5)  # R+X
    p_align = struct.pack('<I', 0x1000)

    phdr = p_type + p_offset + p_vaddr + p_paddr + p_filesz + p_memsz + p_flags + p_align
    return elf_header + phdr + b'\x90\x90\x90\x90'  # 4 NOPs


def _make_pe32_stub():
    """构建 a minimal 32-bit PE文件"""
    # MZ header
    mz = b'MZ' + b'\x00' * 58 + struct.pack('<I', 0x80)  # e_lfanew = 128

    # PE 签名 + COFF header + Optional header (minimal)
    pe_sig = b'PE\x00\x00'
    coff = struct.pack('<HHIIIHH', 0x014c, 1, 0, 0, 0, 0, 0)  # i386, 1 section

    # minimal optional header
    opt = struct.pack('<HH', 0x010b, 0) + b'\x00' * 92  # PE32 magic + 填充

    # one section header (40 bytes):.text
    sect = b'.text\x00\x00\x00'
    sect += struct.pack('<IIIIIIIIHHI', 4, 0x1000, 4, 0x200, 0, 0, 0, 0, 0, 0, 0)

    data = mz + b'\x00' * (128 - len(mz)) + pe_sig + coff + opt + sect + b'\x00' * (512 - len(opt) - len(sect))
    return data


@pytest.fixture
def elf32_stub():
    """用于测试的最小 x86 ELF 二进制"""
    return _make_elf32_stub()


@pytest.fixture
def pe32_stub():
    """用于测试的最小 x86 PE 二进制"""
    return _make_pe32_stub()


@pytest.fixture
def temp_binary_dir():
    """测试二进制的临时目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        elf_path = os.path.join(tmpdir, "test.elf")
        pe_path = os.path.join(tmpdir, "test.exe")
        with open(elf_path, "wb") as f:
            f.write(_make_elf32_stub())
        with open(pe_path, "wb") as f:
            f.write(_make_pe32_stub())
        yield tmpdir
