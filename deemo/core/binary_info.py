"""
二进制文件检测与信息提取, 支持 ELF、PE、Mach-O。
"""

import json
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


_DANGEROUS_IMPORTS = frozenset({
    'gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf',
    'scanf', 'sscanf', 'fscanf', 'vscanf',
    'system', 'execve', 'execl', 'execle', 'execlp', 'execv', 'execvp',
    'popen', 'unlink', 'remove', 'malloc', 'free', 'realloc', 'calloc',
    'memcpy', 'memmove', 'memset',
})


def _r2_imports(path: str) -> Dict:
    """通过 radare2 iij 提取结构化导入及危险函数名。"""
    try:
        result = subprocess.run(
            ['r2', '-q', '-e', 'io.color=false', '-c', 'iij', path],
            capture_output=True, text=True, timeout=30
        )
        rows = json.loads(result.stdout or '[]')
    except Exception:
        rows = []

    all_imports = {}
    dangerous = set()
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        raw_name = str(row.get('name') or row.get('realname') or '')
        name = raw_name.rsplit('.', 1)[-1].split('@', 1)[0]
        if not name:
            continue
        library = str(row.get('libname') or row.get('library') or 'unknown')
        all_imports.setdefault(library, []).append(name)
        if name in _DANGEROUS_IMPORTS:
            dangerous.add(name)
    return {
        'all_imports': all_imports,
        'dangerous_functions': sorted(dangerous),
    }


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
        'imports': {'all_imports': {}, 'dangerous_functions': []},
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
    info['imports'] = _r2_imports(path)
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
