"""
Binary→IR extraction — objdump fallback + cached IR loading.
 modularity.

Priority: .c source → .decomp.txt cache → objdump -d
"""

import re, os, subprocess
from typing import List

from core.source_ir_extractor import (
    extract_from_source, extract_from_file,
)

_HEAP_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc'}
_HEAP_WRITE_FUNCS = {'memcpy', 'memmove', 'strcpy', 'strncpy', 'strcat',
                     'strncat', 'sprintf', 'snprintf', 'memset', 'bcopy'}

def extract_from_binary(binary_path: str, source_dir: str = None) -> List[str]:
    """从二进制提取IR — 优先查C源码, 回退到objdump。

    策略:
      1. 在同目录或 source_dir 下查找 .c 源文件
      2. 若有源码 → extract_from_file
      3. 若无源码 → 尝试 objdump -d 提取 (basic block级)
    """
    binary_dir = os.path.dirname(binary_path)
    binary_base = os.path.splitext(os.path.basename(binary_path))[0]
    if binary_base.endswith('.exe'):
        binary_base = binary_base[:-4]

    search_dirs = [binary_dir]
    if source_dir:
        search_dirs.append(source_dir)

    for d in search_dirs:
        for name in ['vuln.c', f'{binary_base}.c', 'main.c',
                     'exploit.c', 'test.c']:
            c_path = os.path.join(d, name)
            if os.path.isfile(c_path):
                return extract_from_file(c_path)

    return _extract_via_objdump(binary_path)

def _extract_via_objdump(binary_path: str) -> List[str]:
    """通过objdump提取汇编IR (minimal fallback)。"""
    try:
        proc = subprocess.run(
            ['objdump', '-d', binary_path],
            capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            return []
        asm = proc.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    ir_lines = []
    for line in asm.splitlines():
        if 'call' in line:
            m = re.search(r'call\s+(?:.*<)?(\w+)>?', line)
            if m:
                func = m.group(1)
                if func in _HEAP_ALLOC_FUNCS:
                    ir_lines.append(f'call {func}();')
                elif func in _HEAP_WRITE_FUNCS:
                    ir_lines.append(f'call {func}();')
    return ir_lines

def get_ir_lines(binary_or_source_path: str,
                 source_dir: str = None) -> List[str]:
    """统一入口: 获取可用于增强检测器的IR行。

    优先级:
      1. 若路径指向 .c 文件 → extract_from_file
      2. 若路径指向二进制 → extract_from_binary (查源码或objdump)
      3. 若有 .decomp.txt 缓存 → 直接读取
    """
    cache_path = binary_or_source_path + '.decomp.txt'
    if os.path.isfile(cache_path):
        with open(cache_path) as f:
            return f.read().splitlines()

    if binary_or_source_path.endswith('.c'):
        lines = extract_from_file(binary_or_source_path)
    else:
        lines = extract_from_binary(binary_or_source_path, source_dir)

    if lines:
        with open(cache_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

    return lines

__all__ = ['extract_from_binary', 'get_ir_lines']
