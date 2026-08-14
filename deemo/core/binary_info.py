"""
二进制文件检测与信息提取, 支持 ELF、PE、Mach-O。
"""

import os
import struct
import subprocess
from typing import Dict, Optional

from utils.elf import is_elf, get_elf_class, elf_arch_name, ELFCLASS64, read_elf_sections
from utils.pe import is_pe, pe_arch_name, read_pe_sections
from utils.macho import is_macho, macho_arch_name


# 缓存最近结果, 避免同一管线运行内重复读取同一二进制
_last_path: Optional[str] = None
_last_info: Optional[Dict] = None


def detect_format(path: str) -> str:
    """返回 'ELF'、'PE'、'Mach-O' 或 'unknown'。"""
    if is_elf(path):
        return 'ELF'
    if is_pe(path):
        return 'PE'
    if is_macho(path):
        return 'Mach-O'
    return 'unknown'


def _r2_info(path: str) -> Dict:
    """通过 radare2 收集二进制元数据。"""
    try:
        result = subprocess.run(
            ['r2', '-q', '-e', 'io.color=false', '-c', 'iI', path],
            capture_output=True, text=True, timeout=30
        )
        info = {}
        for line in result.stdout.splitlines():
            if ' ' in line:
                k, _, v = line.partition(' ')
                info[k.strip()] = v.strip()
        return info
    except Exception:
        return {}


def get_binary_info(path: str) -> Dict:
    """提取核心元数据: 架构、位宽、段、导入、字符串。"""
    global _last_path, _last_info

    path = os.path.abspath(path)
    if path == _last_path and _last_info is not None:
        return _last_info

    if not os.path.isfile(path):
        return {'error': f'file not found: {path}', 'path': path}

    fmt = detect_format(path)
    info = {
        'path': path,
        'filename': os.path.basename(path),
        'size': os.path.getsize(path),
        'format': fmt,
        'arch': 'unknown',
        'bits': 64,
        'sections': [],
    }

    if fmt == 'ELF':
        cls = get_elf_class(path)
        info['bits'] = 64 if cls == ELFCLASS64 else 32
        info['arch'] = elf_arch_name(path)
        info['sections'] = read_elf_sections(path)
    elif fmt == 'PE':
        info['arch'] = pe_arch_name(path)
        info['bits'] = 64 if '64' in info['arch'] else 32
        info['sections'] = read_pe_sections(path)
    elif fmt == 'Mach-O':
        info['arch'] = macho_arch_name(path)
        info['bits'] = 64

    r2 = _r2_info(path)
    info['r2'] = r2
    if 'arch' in r2 and info['arch'] == 'unknown':
        info['arch'] = r2['arch']
    if 'bintype' in r2:
        info['bintype'] = r2['bintype']

    _last_path = path
    _last_info = info
    return info


def validate_binary(path: str) -> bool:
    """若文件存在且格式受支持, 返回 True。"""
    return os.path.isfile(path) and detect_format(path) != 'unknown'
