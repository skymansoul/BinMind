"""
JIT compiler security analysis. Detects JIT engines in binaries
and flags security-relevant patterns (RWX pages, missing W^X).
"""

import logging
import os
import re
from typing import Dict, List

logger = logging.getLogger(__name__)

JIT_INDICATORS = [
    # V8 / JavaScriptCore / SpiderMonkey
    (b'v8::internal', 'V8 (Chrome/Node.js)'),
    (b'JavaScriptCore', 'JavaScriptCore (WebKit)'),
    (b'SpiderMonkey', 'SpiderMonkey (Firefox)'),
    # .NET
    (b'clrjit', '.NET CLR JIT'),
    (b'coreclr', '.NET CoreCLR'),
    # Java
    (b'HotSpot', 'HotSpot JVM'),
    (b'libjvm', 'JVM'),
    # Lua
    (b'LuaJIT', 'LuaJIT'),
    # Other
    (b'LLVMJIT', 'LLVM JIT'),
    (b'AsmJit', 'AsmJit'),
]


def detect_jit(binary_path: str) -> List[Dict]:
    """Detect known JIT engines embedded in a binary."""
    findings = []
    try:
        with open(binary_path, 'rb') as f:
            data = f.read(1048576)  # read first 1MB
    except OSError:
        return findings

    for needle, name in JIT_INDICATORS:
        if needle in data:
            findings.append({
                'engine': name,
                'indicator': needle.decode('utf-8', errors='replace'),
                'risk': 'JIT requires RWX memory',
            })

    return findings


def check_rwx_pages(binary_path: str) -> Dict:
    """
    Check ELF for RWX (read-write-execute) segments.
    RWX is required by JIT but is a security anti-pattern
    (defeats W^X).
    """
    result = {'has_rwx': False, 'segments': []}

    try:
        from elftools.elf.elffile import ELFFile
        with open(binary_path, 'rb') as f:
            elf = ELFFile(f)
            for seg in elf.iter_segments():
                flags = seg.header.p_flags
                # PF_R=4, PF_W=2, PF_X=1 → RWX = 7
                if (flags & 7) == 7:
                    result['has_rwx'] = True
                    result['segments'].append({
                        'type': seg.header.p_type,
                        'vaddr': hex(seg.header.p_vaddr),
                        'flags': 'RWX',
                        'size': seg.header.p_memsz,
                    })
    except ImportError:
        pass
    except Exception as e:
        logger.debug("ELF segment check failed: %s", e)

    return result


def analyze_jit_security(binary_path: str) -> Dict:
    """Run JIT security checks and return findings."""
    engines = detect_jit(binary_path)
    rwx = check_rwx_pages(binary_path)

    summary = {
        'jit_engines': engines,
        'rwx_segments': rwx,
        'warnings': [],
    }

    if engines and rwx['has_rwx']:
        summary['warnings'].append(
            'Binary contains JIT engine AND RWX segments. '
            'Consider using JIT hardening (mprotect switching, W^X).')
    elif engines:
        summary['warnings'].append(
            'JIT engine detected. Verify that JIT code pages are '
            'properly transitioned between W and X.')

    return summary
