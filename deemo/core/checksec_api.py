"""
Public API: format dispatch and summary generation.

格式识别后分派到对应检测器，汇总硬化状态。对外稳定接口为 detect_checksec
和 checksec_summary。
"""


import os
from typing import Any, Dict

from .checksec_constants import ELFMAG
from .checksec_detectors import (
    _detect_elf_checksec,
    _detect_macho_checksec,
    _detect_pe_checksec,
)

# Mach-O 魔数前缀
_MACHO_MAGICS = (
    b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
    b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
)


def detect_checksec(path: str) -> Dict[str, Any]:
    """
    Detect binary hardening / protection mechanisms.

    Args:
        path: path to ELF or PE file

    Returns:
        Standardized hardening dictionary:
        {
            'nx': bool,
            'pie': bool,
            'canary': bool,
            'relro': str,         # 'full' | 'partial' | 'none'
            'fortify': bool,
            'aslr': bool,
            'rwx_segments': bool,
            'format': str,        # 'ELF' | 'PE' | 'Mach-O' | 'unknown'
        }
    """
    result: Dict[str, Any] = {
        'nx': True,
        'pie': False,
        'canary': False,
        'relro': 'none',
        'fortify': False,
        'aslr': True,
        'rwx_segments': False,
        'format': 'unknown',
    }

    if not os.path.isfile(path):
        return result

    # 格式识别
    try:
        with open(path, 'rb') as f:
            magic = f.read(4)
    except OSError:
        return result

    if magic[:4] == ELFMAG:
        result['format'] = 'ELF'
        _detect_elf_checksec(path, result)
    elif magic[:2] == b'MZ':
        result['format'] = 'PE'
        _detect_pe_checksec(path, result)
    elif magic[:4] in _MACHO_MAGICS:
        result['format'] = 'Mach-O'
        _detect_macho_checksec(path, result)

    return result


def checksec_summary(checksec: Dict[str, Any]) -> str:
    """
    Generate a text summary of hardening status for reports and LLM prompts.

    Args:
        checksec: return value from detect_checksec()

    Returns:
        Single-line summary, e.g. "NX✓ PIE✗ Canary✓ Full RELRO FORTIFY✗"
    """
    parts = [
        f"NX{'✓' if checksec.get('nx') else '✗'}",
        f"PIE{'✓' if checksec.get('pie') else '✗'}",
        f"Canary{'✓' if checksec.get('canary') else '✗'}",
        f"{checksec.get('relro', 'none').title()} RELRO",
        f"FORTIFY{'✓' if checksec.get('fortify') else '✗'}",
    ]
    return ' '.join(parts)
