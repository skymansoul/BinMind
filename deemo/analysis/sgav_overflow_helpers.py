"""
SGAV overflow verifier 辅助函数 — 递归检测与栈帧分析.

栈帧大小计算提取为独立函数.
"""

from __future__ import annotations
import re
from typing import List, Tuple

_FUNC_DEF = re.compile(
    r'(?:void|int|char|long|short|float|double|unsigned|signed|static|'
    r'const|inline|size_t)\s+(?:\w+\s*\*?\s+)?(\w+)\s*\(')
_SELF_CALL = re.compile(r'\b(\w+)\s*\(')
_KEYWORDS = frozenset({
    'if', 'else', 'while', 'for', 'return', 'int', 'char', 'void', 'long',
    'short', 'float', 'double', 'size_t', 'unsigned', 'signed', 'static',
    'const', 'sizeof', 'NULL', 'nullptr', 'malloc', 'calloc', 'realloc',
    'free', 'alloca', 'printf', 'main', 'include', 'struct', 'typedef',
    'switch', 'case', 'default', 'goto', 'break', 'continue', 'exit',
    'puts', 'strlen', 'memset', 'memcpy', 'strcmp', 'strncmp', 'strcat',
    'strcpy', 'sprintf', 'strncpy', 'snprintf', 'gets', 'scanf', 'read',
    'fgets', 'recv', 'atoi', 'sscanf', 'memmove', 'volatile', 'asm',
    'attribute', 'noinline',
})
_RECURSE_FRAME_THRESHOLD = 512
_EXCESSIVE_FRAME = 32768


def build_func_map(lines: List[str]) -> List[tuple]:
    """构建函数名→(起始行, 结束行)映射."""
    funcs = []
    full = '\n'.join(lines)
    for m in _FUNC_DEF.finditer(full):
        name = m.group(1)
        if name in _KEYWORDS:
            continue
        start = full[:m.start()].count('\n') + 1
        depth = 0
        end = start
        for j in range(start, len(lines) + 1):
            ln = lines[j - 1]
            depth += ln.count('{') - ln.count('}')
            if depth <= 0:
                end = j
                break
        funcs.append((name, start, end))
    return funcs


def is_recursive(name: str, start: int, end: int,
                 lines: List[str]) -> bool:
    """判断函数是否递归调用自身."""
    for i in range(start, min(end + 1, len(lines) + 1)):
        text = lines[i - 1].strip()
        if text.startswith(('//', '/*')):
            continue
        if i == start:
            brace = text.find('{')
            if brace >= 0:
                text = text[brace + 1:]
            else:
                continue
        for m in _SELF_CALL.finditer(text):
            if m.group(1) == name:
                return True
    return False


def frame_size(name: str, start: int, end: int,
               lines: List[str]) -> int:
    """估算函数栈帧大小 (字节)."""
    total = 0
    for i in range(start, min(end + 1, len(lines) + 1)):
        text = lines[i - 1].strip()
        if text.startswith(('//', '/*')):
            continue
        for m in re.finditer(
                r'(?:char|int|unsigned|short|long|float|double)\s+'
                r'\w+\s*\[\s*(\d+)\s*\]', text):
            total += int(m.group(1))
    return total


__all__ = [
    'build_func_map', 'is_recursive', 'frame_size',
    '_RECURSE_FRAME_THRESHOLD', '_EXCESSIVE_FRAME',
]
