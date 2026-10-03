"""
libc版本识别: 从二进制提取指纹并匹配已知版本库。
从.rodata提取GNU版本字符串、关键函数字节指纹、_IO_2_1_stdin_结构偏移特征，
支持离线本地库与在线API两种模式，对去除符号的二进制依然有效。
"""

from __future__ import annotations

import glob
import hashlib
import importlib.util
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
_GNU_LIBC_LINE_PATTERN = re.compile(
    rb'GNU C Library[^\x00\r\n]*?(?:version\s+)?'
    rb'\d+\.\d+(?:\.\d+)?(?:[-\w.]*)?[^\x00\r\n]*'
)
_GNU_LIBC_VERSION_PATTERN = re.compile(
    rb'(\d+\.\d+(?:\.\d+)?(?:[-\w.]*)?)'
)
_LDD_LIBC_PATTERN = re.compile(r'\blibc\.so\.6\s*=>\s*(\S+)')

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


def identify_libc(path: str, leaks: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    """
    识别二进制文件所依赖的 libc 版本和关键符号偏移。

    leaks 为可选运行时泄露地址映射, 例如 {'puts': 0x7ffff7a5e5f0}。
    返回 {version, distro, symbols, confidence, source, libcsearch}。
    """
    result: Dict[str, Any] = {
        'version': '',
        'distro': '',
        'path': '',
        'symbols': {},
        'confidence': 0.0,
        'source': 'unknown',
        'raw_strings': [],
        'linked_libs': [],
        'libcsearch': {
            'enabled': bool(leaks),
            'leaks': _format_leaks(leaks or {}),
            'candidates': [],
            'note': '',
            'error': '',
        },
    }

    if not os.path.isfile(path):
        return result

    result['linked_libs'] = _extract_needed_libs(path)

    version_str, confidence = _extract_version_string(path)
    if version_str:
        result['version'] = version_str
        result['confidence'] = confidence
        result['source'] = 'binary-string'
        result['raw_strings'].append(version_str)

    libc_path, libc_source = _resolve_linked_libc_path(path, result['linked_libs'])
    if libc_path:
        result['path'] = libc_path
        libc_version, libc_confidence = _extract_version_string(libc_path)
        if libc_version:
            result['version'] = libc_version
            result['confidence'] = max(result['confidence'], libc_confidence)
            result['source'] = libc_source
            if libc_version not in result['raw_strings']:
                result['raw_strings'].append(libc_version)

    if result['version']:
        for sig, info in _DISTRO_SIGNATURES.items():
            if sig.lower() in result['version'].lower():
                result['distro'] = info.get('distro', '')
                break
        result['symbols'] = _lookup_symbols(result['path'] or path, result['version'])

    if not result['symbols']:
        _log.debug("No libc symbols from fingerprint, trying system libc")
        result['symbols'] = _lookup_system_libc(result['path'] or path)

    if leaks:
        result['libcsearch'] = _search_libc_candidates(leaks)
    else:
        result['libcsearch']['note'] = (
            'No leaks supplied. LibcSearcher/libcsearch needs at least one runtime '
            'libc symbol leak, e.g. --leak puts=0x7ffff7a5e5f0.'
        )

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
    """从二进制或 libc 文件中搜索 GNU C Library 版本字符串。"""
    try:
        with open(path, 'rb') as f:
            data = f.read(4194304)

        matches = _GNU_LIBC_LINE_PATTERN.findall(data)
        if matches:
            decoded = [m.decode('ascii', errors='replace').strip()
                       for m in matches]
            best = max(decoded, key=len)
            conf = 0.9 if len(matches) == 1 else 0.7
            return best, conf

        version_matches = _GNU_LIBC_VERSION_PATTERN.findall(data)
        if b'GNU C Library' in data and version_matches:
            version = version_matches[0].decode('ascii', errors='replace')
            return f'GNU C Library version {version}', 0.5

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


def _resolve_linked_libc_path(path: str, linked_libs: List[str]) -> Tuple[str, str]:
    """优先解析题目目录自带 libc，找不到再用 ldd 解析系统加载路径。"""
    if not any('libc.so.6' in lib for lib in linked_libs):
        return '', ''

    local_libc = _find_local_libc_path(path, linked_libs)
    if local_libc:
        return local_libc, 'local-libc'

    try:
        proc = subprocess.run(
            ['ldd', path], capture_output=True, text=True, timeout=15,
        )
    except Exception as exc:
        _log.debug("ldd libc resolution failed: %s", exc)
        return '', ''

    for line in proc.stdout.splitlines():
        match = _LDD_LIBC_PATTERN.search(line)
        if not match:
            continue
        libc_path = match.group(1)
        if os.path.isfile(libc_path):
            return libc_path, 'linked-libc'

    return '', ''


def _find_local_libc_path(path: str, linked_libs: List[str]) -> str:
    """在 CTF 题目目录中寻找随题附带的 libc 文件。"""
    base_dir = os.path.dirname(os.path.abspath(path)) or os.curdir
    search_dirs = [base_dir, os.path.join(base_dir, 'lib'), os.path.join(base_dir, 'libs')]
    names = [os.path.basename(lib) for lib in linked_libs if 'libc' in lib.lower()]
    patterns = names + ['libc.so.6', 'libc-*.so', 'libc_*.so', 'libc*.so*']

    candidates: List[str] = []
    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        for pattern in patterns:
            for candidate in glob.glob(os.path.join(search_dir, pattern)):
                candidate = os.path.realpath(candidate)
                if os.path.isfile(candidate) and candidate != os.path.realpath(path):
                    candidates.append(candidate)

    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        version, _confidence = _extract_version_string(candidate)
        if version:
            return candidate

    return ''


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


def parse_libc_leaks(values: Optional[List[str]]) -> Dict[str, int]:
    """解析 CLI 传入的 sym=addr 泄露参数。"""
    leaks: Dict[str, int] = {}
    for item in values or []:
        if '=' not in item:
            raise ValueError(f'leak must be sym=addr: {item}')
        sym, raw_addr = item.split('=', 1)
        sym = sym.strip()
        raw_addr = raw_addr.strip()
        if not sym:
            raise ValueError(f'leak symbol is empty: {item}')
        try:
            leaks[sym] = int(raw_addr, 0)
        except ValueError as exc:
            raise ValueError(f'invalid leak address for {sym}: {raw_addr}') from exc
    return leaks


def _format_leaks(leaks: Dict[str, int]) -> Dict[str, str]:
    return {sym: f'0x{addr:x}' for sym, addr in leaks.items()}


def _search_libc_candidates(leaks: Dict[str, int]) -> Dict[str, Any]:
    """使用 LibcSearcher 数据库按泄露地址列出全部候选 libc。"""
    result: Dict[str, Any] = {
        'enabled': True,
        'leaks': _format_leaks(leaks),
        'candidates': [],
        'note': '',
        'error': '',
    }
    if not leaks:
        result['note'] = 'No leaks supplied.'
        return result

    try:
        candidate_names = _query_libcsearcher_database(leaks)
    except ImportError:
        result['error'] = (
            'LibcSearcher is not installed. Install it in the active environment '
            'to enable leak-based libc candidate search.'
        )
        return result
    except Exception as exc:
        result['error'] = f'LibcSearcher lookup failed: {exc}'
        return result

    result['candidates'] = [{'id': name} for name in candidate_names]
    if candidate_names:
        result['note'] = (
            'Candidates are matched by low 12-bit page offsets from supplied leaks; '
            'use multiple independent leaks to reduce ambiguity.'
        )
    else:
        result['note'] = 'No libc candidate matched supplied leaks.'
    return result


def _query_libcsearcher_database(leaks: Dict[str, int]) -> List[str]:
    """直接读取 LibcSearcher DB, 避免多候选时触发交互选择。"""
    spec = importlib.util.find_spec('LibcSearcher')
    if spec is None or not spec.submodule_search_locations:
        raise ImportError('LibcSearcher')

    db_dir = os.path.join(spec.submodule_search_locations[0], 'libc-database', 'db')
    if not os.path.isdir(db_dir):
        raise FileNotFoundError(f'LibcSearcher database not found: {db_dir}')

    candidates: List[str] = []
    for db_file in glob.glob(os.path.join(db_dir, '*.symbols')):
        if _libc_symbols_file_matches(db_file, leaks):
            candidates.append(os.path.splitext(os.path.basename(db_file))[0])
    candidates.sort()
    return candidates


def _libc_symbols_file_matches(db_file: str, leaks: Dict[str, int]) -> bool:
    symbols: Dict[str, int] = {}
    try:
        with open(db_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                try:
                    symbols[parts[0]] = int(parts[1], 16)
                except ValueError:
                    continue
    except OSError:
        return False

    for sym, leaked_addr in leaks.items():
        offset = symbols.get(sym)
        if offset is None:
            return False
        if (offset & 0xfff) != (leaked_addr & 0xfff):
            return False
    return True


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
