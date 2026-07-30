"""
ELF binary parsing helpers. Lightweight wrappers around pyelftools
with reasonable fallbacks for stripped binaries.
"""

import struct
import os

# ELF magic
ELFMAG = b'\x7fELF'
ELFCLASS32 = 1
ELFCLASS64 = 2


def get_elf_class(path: str) -> int:
    """Read the EI_CLASS byte. Returns ELFCLASS32, ELFCLASS64, or 0 on failure."""
    try:
        with open(path, 'rb') as f:
            magic = f.read(5)
            if magic[:4] != ELFMAG:
                return 0
            return magic[4]
    except (OSError, IOError):
        return 0


def is_elf(path: str) -> bool:
    return get_elf_class(path) in (ELFCLASS32, ELFCLASS64)


def elf_arch_name(path: str) -> str:
    """Map ELF machine field to a human name."""
    try:
        with open(path, 'rb') as f:
            if f.read(4) != ELFMAG:
                return 'unknown'
            ei_class = f.read(1)[0]
            if ei_class == ELFCLASS64:
                f.seek(0x12)
                machine = struct.unpack('<H', f.read(2))[0]
            elif ei_class == ELFCLASS32:
                f.seek(0x12)
                machine = struct.unpack('<H', f.read(2))[0]
            else:
                return 'unknown'
    except (OSError, IOError):
        return 'unknown'

    _ARCH_MAP = {
        0x03: 'x86',
        0x28: 'ARM',
        0x3E: 'x86-64',
        0xB7: 'AArch64',
        0xF3: 'RISC-V',
        0x08: 'MIPS',
    }
    return _ARCH_MAP.get(machine, f'unknown(0x{machine:04x})')


def read_elf_sections(path: str):
    """Return a minimal list of {name, addr, size, type} dicts using pyelftools."""
    try:
        from elftools.elf.elffile import ELFFile
        sections = []
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                sections.append({
                    'name': sec.name,
                    'addr': sec.header.sh_addr,
                    'size': sec.header.sh_size,
                    'type': sec.header.sh_type,
                })
        return sections
    except ImportError:
        return []
    except Exception:
        return []
