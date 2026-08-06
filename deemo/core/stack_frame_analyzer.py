"""
Cross-compiler stack frame analysis via function prologue disassembly.

Determines stack frame size and canary presence by matching prologue
bytecode patterns for GCC/Clang/MSVC across optimization levels.

7 prologue patterns (in frequency order):
  P1 [GCC -O0]:    push rbp; mov rbp, rsp; sub rsp, IMM
  P2 [GCC -O1/2]:  push rbx/r12-r15; sub rsp, IMM
  P3 [Clang -O0]:   push rbp; mov rbp, rsp; sub rsp, IMM
  P4 [Clang -O1/2]: sub rsp, IMM (no frame pointer)
  P5 [MSVC /GS]:    push rbp; mov rbp, rsp; sub rsp, IMM; mov rax, __security_cookie
  P6 [MSVC noGS]:   push rbp; mov rbp, rsp; sub rsp, IMM
  P7 [GCC -Os]:     push rbp; mov rbp, rsp (no sub rsp, no locals)

4 canary patterns:
  C1 [GCC]:   mov rax, fs:0x28; mov [rbp-8], rax
  C2 [Clang]: same as C1
  C3 [MSVC]:  mov eax, __security_cookie; mov [rbp-4], eax
  C4 [i386]:  mov eax, gs:0x14; mov [ebp-4], eax

Prologue matching is the most reliable cross-compiler method for frame
size extraction since pseudocode regex (char buf[N]) is inconsistent
across Clang/MSVC output.

Reference: Di Federico et al., 2017, NDSS, "How the ELF Ruined Christmas"
"""

from __future__ import annotations

import logging
import re
import struct
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)


# Max scan range for prologue instructions (most compiler prologues fit in 32B)
_PROLOGUE_SCAN_BYTES = 64

# Canary detection patterns
_CANARY_PATTERNS = [
    (b'\x64\x48\x8b\x04\x25\x28\x00\x00\x00', 'gcc-x64-fs0x28'),    # mov rax, fs:0x28
    (b'\x65\x48\x8b\x04\x25\x28\x00\x00\x00', 'gcc-x64-gs0x28'),    # mov rax, gs:0x28
    (b'\x64\x8b\x04\x25\x14\x00\x00\x00', 'i386-fs0x14'),           # mov eax, fs:0x14
    (b'\x65\x8b\x04\x25\x14\x00\x00\x00', 'i386-gs0x14'),           # mov eax, gs:0x14
    (b'\x64\xa1\x14\x00\x00\x00', 'i386-fs0x14-alt'),               # mov eax, fs:0x14 (alt encoding)
    (b'\xa1', 'msvc-cookie'),  # mov eax, __security_cookie (needs context verification)
]


def _disassemble_prologue(binary_path: str, func_name: str) -> Optional[bytes]:
    """Extract the first 64 bytes of a function for prologue pattern matching."""
    try:
        import subprocess
        from config import R2_PATH

        proc = subprocess.run(
            [R2_PATH, '-q', '-e', 'io.color=false',
             '-c', f's {func_name}', '-c', 'afi~addr', binary_path],
            capture_output=True, text=True, timeout=15,
        )
        for line in proc.stdout.splitlines():
            m = re.search(r'(0x[0-9a-fA-F]+)', line)
            if m:
                addr = int(m.group(1), 16)
                break
        else:
            return None

        proc2 = subprocess.run(
            [R2_PATH, '-q', '-e', 'io.color=false',
             '-c', f'p8 {_PROLOGUE_SCAN_BYTES} @ {addr}', binary_path],
            capture_output=True, text=True, timeout=15,
        )
        return bytes.fromhex(proc2.stdout.strip())
    except Exception as e:
        _log.debug("Disassembly failed for %s: %s", func_name, e)
        return None


def analyze_stack_frame(binary_path: str, func_name: str,
                        arch_bits: int = 64) -> Dict[str, Any]:
    """Analyze function stack frame structure (cross-compiler robust).

    Returns:
        {frame_size: int, has_frame_pointer: bool, has_canary: bool,
         prologue_type: str, canary_pattern: str|null, confidence: float}
    """
    result: Dict[str, Any] = {
        'frame_size': 0,
        'has_frame_pointer': False,
        'has_canary': False,
        'prologue_type': 'unknown',
        'canary_pattern': None,
        'confidence': 0.0,
    }

    raw = _disassemble_prologue(binary_path, func_name)
    if raw is None or len(raw) < 4:
        return result

    # Frame pointer detection
    # push rbp = 0x55, mov rbp,rsp = 0x48 0x89 0xe5
    has_push_rbp = raw[0] == 0x55
    has_mov_rbp = len(raw) >= 3 and raw[1:4] == b'\x48\x89\xe5'

    if has_push_rbp and has_mov_rbp:
        result['has_frame_pointer'] = True
        scan_start = 4  # skip push rbp + mov rbp, rsp
    elif has_push_rbp:
        result['has_frame_pointer'] = True
        scan_start = 1  # push rbp only, no mov
    else:
        scan_start = 0

    # Stack frame size extraction
    # sub rsp, IMM = 0x48 0x81 0xec IMM(4B LE)
    # sub rsp, imm8 = 0x48 0x83 0xec IMM(1B)
    frame_size = 0
    confidence = 0.0

    for i in range(scan_start, min(len(raw) - 3, _PROLOGUE_SCAN_BYTES)):
        # sub rsp, imm32: 48 81 ec XX XX XX XX
        if raw[i:i+3] == b'\x48\x81\xec' and i + 7 <= len(raw):
            frame_size = struct.unpack('<I', raw[i+3:i+7])[0]
            confidence = 0.90
            break
        # sub rsp, imm8: 48 83 ec XX
        if raw[i:i+3] == b'\x48\x83\xec' and i + 4 <= len(raw):
            frame_size = raw[i+3]
            confidence = 0.85
            break
        # i386: sub esp, IMM: 81 ec XX XX XX XX
        if raw[i:i+2] == b'\x81\xec' and i + 6 <= len(raw) and arch_bits == 32:
            frame_size = struct.unpack('<I', raw[i+2:i+6])[0]
            confidence = 0.85
            break
        # i386: sub esp, imm8: 83 ec XX
        if raw[i:i+2] == b'\x83\xec' and i + 3 <= len(raw) and arch_bits == 32:
            frame_size = raw[i+2]
            confidence = 0.80
            break

    # Prologue type classification
    if has_push_rbp and has_mov_rbp and frame_size > 0:
        result['prologue_type'] = 'P1-GCC-Clang-O0' if frame_size <= 256 else 'P5-MSVC-GS'
    elif has_push_rbp and not has_mov_rbp and frame_size > 0:
        result['prologue_type'] = 'P2-GCC-O1-O2-regsave'
    elif not has_push_rbp and frame_size > 0:
        result['prologue_type'] = 'P4-Clang-no-frame-pointer'
    elif has_push_rbp and has_mov_rbp and frame_size == 0:
        result['prologue_type'] = 'P7-GCC-Os-no-locals'
    else:
        result['prologue_type'] = (
            f'unknown:{raw[:min(len(raw),6)].hex()}')

    # Canary detection
    for pattern_bytes, pattern_name in _CANARY_PATTERNS:
        if pattern_bytes in raw:
            result['has_canary'] = True
            result['canary_pattern'] = pattern_name
            break

    result['frame_size'] = frame_size
    result['confidence'] = confidence
    return result


def estimate_buffer_padding(binary_path: str, func_name: str,
                            arch_bits: int = 64) -> Tuple[int, str]:
    """Estimate padding from buffer to return address.

    Algorithm:
      1. Analyze stack frame size (from prologue)
      2. padding = frame_size (with frame pointer)
         padding = frame_size + 8 (without frame pointer)
      3. Fall back to default value 72 if prologue match is unconfident

    Returns:
        (padding_bytes, method_description)
    """
    frame = analyze_stack_frame(binary_path, func_name, arch_bits)

    if frame['confidence'] >= 0.80 and frame['frame_size'] > 0:
        if frame['has_frame_pointer']:
            padding = frame['frame_size']
            method = (f'prologue-match({frame["prologue_type"]}): '
                      f'frame={frame["frame_size"]}B, fp=yes → padding={padding}')
        else:
            padding = frame['frame_size'] + 8
            method = (f'prologue-match({frame["prologue_type"]}): '
                      f'frame={frame["frame_size"]}B, fp=no → padding={padding}')
    else:
        padding = 72  # fallback default
        method = f'fallback-default: prologue unconfident (type={frame["prologue_type"]})'

    return padding, method
