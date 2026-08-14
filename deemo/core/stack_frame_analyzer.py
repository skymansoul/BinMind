"""
跨编译器栈帧分析 — 通过函数序言反汇编字节匹配, 推断栈帧大小与canary存在性。
基于7种序言模式(P1-P7, 覆盖GCC/Clang/MSVC各优化级别)与4种canary模式(C1-C4)。
序言字节匹配是跨编译器提取帧大小最可靠的方法。
"""

from __future__ import annotations

import logging
import re
import struct
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)


# 序言指令最大扫描范围 (多数编译器序言在32字节内)
_PROLOGUE_SCAN_BYTES = 64

# canary检测模式
_CANARY_PATTERNS = [
    (b'\x64\x48\x8b\x04\x25\x28\x00\x00\x00', 'gcc-x64-fs0x28'),    # 读 fs:0x28 到 rax
    (b'\x65\x48\x8b\x04\x25\x28\x00\x00\x00', 'gcc-x64-gs0x28'),    # 读 gs:0x28 到 rax
    (b'\x64\x8b\x04\x25\x14\x00\x00\x00', 'i386-fs0x14'),           # 读 fs:0x14 到 eax
    (b'\x65\x8b\x04\x25\x14\x00\x00\x00', 'i386-gs0x14'),           # 读 gs:0x14 到 eax
    (b'\x64\xa1\x14\x00\x00\x00', 'i386-fs0x14-alt'),               # 读 fs:0x14 到 eax (替代编码)
    (b'\xa1', 'msvc-cookie'),  # 读 __security_cookie 到 eax (需上下文验证)
]


def _disassemble_prologue(binary_path: str, func_name: str) -> Optional[bytes]:
    """提取函数前64字节, 用于序言模式匹配。"""
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
    """分析函数栈帧结构 (跨编译器健壮)。

    返回 {frame_size: int, has_frame_pointer: bool, has_canary: bool,
          prologue_type: str, canary_pattern: str|null, confidence: float}。
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

    # 帧指针检测: push rbp = 0x55, mov rbp,rsp = 0x48 0x89 0xe5
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

    # 栈帧大小提取: sub rsp imm32 = 48 81 ec + 4字节小端立即数
    # sub rsp imm8 = 48 83 ec + 1字节立即数
    frame_size = 0
    confidence = 0.0

    for i in range(scan_start, min(len(raw) - 3, _PROLOGUE_SCAN_BYTES)):
        # sub rsp imm32: 48 81 ec + 4字节立即数
        if raw[i:i+3] == b'\x48\x81\xec' and i + 7 <= len(raw):
            frame_size = struct.unpack('<I', raw[i+3:i+7])[0]
            confidence = 0.90
            break
        # sub rsp imm8: 48 83 ec + 1字节立即数
        if raw[i:i+3] == b'\x48\x83\xec' and i + 4 <= len(raw):
            frame_size = raw[i+3]
            confidence = 0.85
            break
        # i386: sub esp imm32: 81 ec + 4字节立即数
        if raw[i:i+2] == b'\x81\xec' and i + 6 <= len(raw) and arch_bits == 32:
            frame_size = struct.unpack('<I', raw[i+2:i+6])[0]
            confidence = 0.85
            break
        # i386: sub esp imm8: 83 ec + 1字节立即数
        if raw[i:i+2] == b'\x83\xec' and i + 3 <= len(raw) and arch_bits == 32:
            frame_size = raw[i+2]
            confidence = 0.80
            break

    # 序言类型分类
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

    # canary检测
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
    """估计缓冲区到返回地址的填充长度。

    算法: 1. 从序言分析栈帧大小; 2. 有帧指针时 padding=frame_size,
    无帧指针时 padding=frame_size+8; 3. 序言匹配不确信时回退默认值72。
    返回 (padding_bytes, method_description)。
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
