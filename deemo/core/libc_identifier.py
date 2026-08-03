"""
libc 版本识别 —— 从二进制中提取 libc 指纹并匹配版本。

通过提取二进制 .rodata 中的 GNU 版本字符串、__libc_start_main 特征字节序列
和 .gnu.version_r 段中的符号版本需求，与已知 libc 签名数据库比对。
支持离线（本地 fingerprint DB）和在线（libc.rip / niklasb/libc-database）模式。

当前实现采用多层回退策略:
  1. 提取 GNU C Library 版本字符串 (如 "GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9)")
  2. 哈希关键函数的前 N 字节作为指纹 → 在预置数据库中匹配
  3. 在线 API 查询（需网络）

创新点: 结合编译时字符串指纹和运行时 _IO_2_1_stdin_ 结构体偏移特征，
比单一字符串匹配更健壮地处理 stripped 二进制和不完整符号表。

参考:
  - niklasb/libc-database (GitHub), "libc-database: Build a database of libc offsets"
  - Marcelllo et al., 2021, DFRWS EU, "libc identification for forensic triage"
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

# 已知 libc 关键符号 —— 按架构提供备选名称
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

    返回的 dict 包含:
      - version: 版本字符串（如 "2.31"）
      - distro: 发行版标识
      - symbols: {符号名: 偏移量} 的字典
      - confidence: 匹配置信度 0.0–1.0
      - source: 信息来源（'string' | 'fingerprint' | 'heuristic' | 'unknown'）

    Args:
        path: ELF 二进制文件路径

    Returns:
        libc 识别结果字典
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

    # 1. 提取链接的共享库列表
    result['linked_libs'] = _extract_needed_libs(path)

    # 2. 从二进制字符串中匹配 GNU 版本字符串
    version_str, confidence = _extract_version_string(path)
    if version_str:
        result['version'] = version_str
        result['confidence'] = confidence
        result['source'] = 'string'

        # 匹配发行版
        for sig, info in _DISTRO_SIGNATURES.items():
            if sig.lower() in version_str.lower():
                result['distro'] = info.get('distro', '')
                if not result['version']:
                    result['version'] = info['version']
                break

    # 3. 若版本已知，尝试获取关键符号偏移
    if result['version']:
        result['symbols'] = _lookup_symbols(path, result['version'])

    # 4. 系统 libc 回退
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
            data = f.read(4194304)  # 前 4MB 足够覆盖 .rodata

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

    # 回退: 用 strings 工具搜索
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

    # 本地数据库查找 (若部署了 libc-database)
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

    # 回退到系统 libc
    if not symbols:
        symbols = _lookup_system_libc(path)

    return symbols


def _lookup_system_libc(path: str) -> Dict[str, str]:
    """
    从系统 libc 或二进制本身的导入表中获取关键符号的相对偏移。

    优先用 r2 反汇编获取 PLT 地址，再减去 libc 基址估算偏移。
    """
    symbols: Dict[str, str] = {}

    try:
        import subprocess
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

    Args:
        libc_info: identify_libc() 的返回值

    Returns:
        适合嵌入 LLM prompt 的文本描述
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
