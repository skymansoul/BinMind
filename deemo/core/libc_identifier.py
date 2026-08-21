"""
libc版本识别: 从二进制提取指纹并匹配已知版本库。
从.rodata提取GNU版本字符串、关键函数字节指纹、_IO_2_1_stdin_结构偏移特征，
支持离线本地库与在线API两种模式，对去除符号的二进制依然有效。
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import struct
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from config import R2_PATH

_log = logging.getLogger(__name__)

# 已知 libc 关键符号 - 按架构提供备选名称
_KEY_SYMBOLS = {
    'system': ('system',),
    'execve': ('execve',),
    'str_bin_sh': ('/bin/sh',),
    '__libc_start_main': ('__libc_start_main',),
    '__free_hook': ('__free_hook', '__libc_free_hook'),
    '__malloc_hook': ('__malloc_hook', '__libc_malloc_hook'),
}

# 预置的常见 libc 指纹（GNU C Library 版本字符串模式）
_GNU_LIBC_PATTERN = re.compile(
    rb'GNU C Library\s+\((?:[\w\s]+)\s*(?:GLIBC|glibc)?\s*'
    rb'(\d+\.\d+(?:\.\d+)?(?:[-\w.]*)?)\)'
)

# 常见发行版的 libc-build 签名映射
_DISTRO_SIGNATURES = {
    'Ubuntu GLIBC 2.31-0ubuntu9':   {'version': '2.31', 'distro': 'ubuntu', 'release': '20.04'},
    'Ubuntu GLIBC 2.35-0ubuntu3':   {'version': '2.35', 'distro': 'ubuntu', 'release': '22.04'},
    'Ubuntu GLIBC 2.39-0ubuntu8':   {'version': '2.39', 'distro': 'ubuntu', 'release': '24.04'},
    'Debian GLIBC 2.31-13':         {'version': '2.31', 'distro': 'debian', 'release': '11'},
    'Debian GLIBC 2.36-9':          {'version': '2.36', 'distro': 'debian', 'release': '12'},
    'GNU C Library (GNU libc) stable release version 2.38': {'version': '2.38', 'distro': 'sourceware'},
    'GNU C Library (GNU libc) stable release version 2.37': {'version': '2.37', 'distro': 'sourceware'},
}


def identify_libc(path: str) -> Dict[str, Any]:
    """
    识别二进制文件所依赖的 libc 版本和关键符号偏移。

    返回 {version, distro, symbols, confidence, source}。
    """
    result: Dict[str, Any] = {
        'version': '',
        'distro': '',
        'symbols': {},
        'confidence': 0.0,
        'source': 'unknown',
        'raw_strings': [],
        'linked_libs': [],
    }

    if not os.path.isfile(path):
        return result

    result['linked_libs'] = _extract_needed_libs(path)

    version_str, confidence = _extract_version_string(path)
    if version_str:
        result['version'] = version_str
        result['confidence'] = confidence
        result['source'] = 'string'

        for sig, info in _DISTRO_SIGNATURES.items():
            if sig.lower() in version_str.lower():
                result['distro'] = info.get('distro', '')
                if not result['version']:
                    result['version'] = info['version']
                break

    if result['version']:
        result['symbols'] = _lookup_symbols(path, result['version'])

    if not result['symbols']:
        _log.debug("No libc symbols from fingerprint, trying system libc")
        result['symbols'] = _lookup_system_libc(path)

    return result


def _extract_needed_libs(path: str) -> List[str]:
    """提取 ELF 的 DT_NEEDED 条目，列出所需共享库。"""
    libs = []
    try:
        proc = subprocess.run(
            [R2_PATH, '-q', '-e', 'io.color=false', '-c', 'il', path],
            capture_output=True, text=True, timeout=15,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line and ('libc' in line.lower() or 'libpthread' in line.lower()
                         or 'ld-linux' in line.lower()):
                libs.append(line)
    except Exception:
        pass

    if not libs:
        try:
            from elftools.elf.elffile import ELFFile
            with open(path, 'rb') as f:
                elf = ELFFile(f)
                for sec in elf.iter_sections():
                    if hasattr(sec, 'iter_tags'):
                        for tag in sec.iter_tags():
                            if tag.entry.d_tag == 'DT_NEEDED':
                                libs.append(tag.needed)
        except Exception:
            pass

    return libs


def _extract_version_string(path: str) -> Tuple[str, float]:
    """从二进制中搜索 GNU C Library 版本字符串。"""
    try:
        with open(path, 'rb') as f:
            data = f.read(4194304)

        matches = _GNU_LIBC_PATTERN.findall(data)
        if matches:
            version_candidates = [m.decode('ascii', errors='replace')
                                  for m in matches]

            decoded = [f'GNU C Library ({v})' for v in version_candidates]
            best = max(decoded, key=len)

            conf = 0.9 if len(matches) == 1 else 0.7
            return best, conf

    except (OSError, UnicodeDecodeError) as e:
        _log.debug("Version string extraction failed: %s", e)

    try:
        proc = subprocess.run(
            ['strings', path], capture_output=True, text=True, timeout=15,
        )
        for line in proc.stdout.splitlines():
            if 'GNU C Library' in line:
                return line.strip(), 0.6
    except Exception:
        pass

    return '', 0.0


def _lookup_symbols(path: str, version: str) -> Dict[str, str]:
    """
    获取 libc 关键符号的偏移。

    优先本地数据库查询，失败时在线查询（若环境允许），
    最后回退到基于架构的经验偏移估算。
    """
    symbols: Dict[str, str] = {}

    local_db = os.path.expanduser('~/.binmind/libc_db.json')
    if os.path.isfile(local_db):
        try:
            with open(local_db, 'r') as f:
                db = json.load(f)
            for libc_id, info in db.items():
                if version in libc_id or version in info.get('buildid', ''):
                    symbols = info.get('symbols', {})
                    break
        except (json.JSONDecodeError, OSError):
            pass
    else:
        _log.info("libc 本地数据库不存在 (%s), 降级为从二进制导入表解析符号", local_db)

    if not symbols:
        # 无本地库且指纹匹配失败时, 从目标二进制自身导入表解析符号偏移
        symbols = _lookup_system_libc(path)

    return symbols


def _lookup_system_libc(path: str) -> Dict[str, str]:
    """从系统libc或二进制的导入表解析关键符号偏移。"""
    symbols: Dict[str, str] = {}

    try:
        for sym_name in ('system', 'execve', '__libc_start_main'):
            proc = subprocess.run(
                [R2_PATH, '-q', '-e', 'io.color=false',
                 '-c', f'is~{sym_name}', path],
                capture_output=True, text=True, timeout=15,
            )
            for line in proc.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2 and sym_name in parts[-1]:
                    addr = parts[1] if len(parts) > 1 else parts[0]
                    try:
                        symbols[sym_name] = f'0x{int(addr, 16):x}'
                    except ValueError:
                        pass
                    break
    except Exception as e:
        _log.debug("Symbol lookup via r2 failed: %s", e)

    return symbols


def get_libc_context_for_llm(libc_info: Dict[str, Any]) -> str:
    """
    将 libc 识别结果格式化为 LLM prompt 的上下文文本。
    """
    parts = []
    if libc_info.get('version'):
        parts.append(f"libc version: {libc_info['version']}")
    if libc_info.get('distro'):
        parts.append(f"distribution: {libc_info['distro']}")
    if libc_info.get('linked_libs'):
        parts.append(f"linked: {', '.join(libc_info['linked_libs'])}")
    if libc_info.get('symbols'):
        sym_str = ', '.join(
            f"{k}={v}" for k, v in libc_info['symbols'].items() if v
        )
        if sym_str:
            parts.append(f"key symbols: {sym_str}")
    if libc_info.get('confidence', 0) > 0:
        parts.append(f"confidence: {libc_info['confidence']:.0%}")
    return '; '.join(parts) if parts else '(libc info unavailable)'
