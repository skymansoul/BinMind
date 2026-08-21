"""
PE (Portable Executable) parsing. Requires pefile.
"""

import struct
import os

PE_MAGIC = b'MZ'


def is_pe(path: str) -> bool:
    try:
        with open(path, 'rb') as f:
            return f.read(2) == PE_MAGIC
    except (OSError, IOError):
        return False


def pe_arch_name(path: str) -> str:
    """Return 'x86', 'x86-64', 'ARM64', or 'unknown'."""
    try:
        import pefile
        p = pefile.PE(path)
        machine = p.FILE_HEADER.Machine
        _map = {
            0x014C: 'x86',
            0x8664: 'x86-64',
            0xAA64: 'ARM64',
            0x01C4: 'ARM',
        }
        return _map.get(machine, f'unknown(0x{machine:04X})')
    except ImportError:
        # fallback: try to parse COFF header offset manually
        try:
            with open(path, 'rb') as f:
                f.seek(0x3C)
                pe_offset = struct.unpack('<I', f.read(4))[0]
                f.seek(pe_offset + 4)
                machine = struct.unpack('<H', f.read(2))[0]
                _map = {0x014C: 'x86', 0x8664: 'x86-64', 0xAA64: 'ARM64'}
                return _map.get(machine, f'unknown(0x{machine:04X})')
        except Exception:
            return 'unknown'
    except Exception:
        return 'unknown'


def read_pe_sections(path: str):
    """Return list of {name, addr, size} dicts."""
    try:
        import pefile
        p = pefile.PE(path)
        return [
            {'name': s.Name.decode('utf-8', 'replace').rstrip('\x00'),
             'addr': s.VirtualAddress,
             'size': s.SizeOfRawData}
            for s in p.sections
        ]
    except ImportError:
        return []
    except Exception:
        return []
