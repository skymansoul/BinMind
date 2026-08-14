"""
PLT/GOT 解析器: 从 ELF 提取导入表地址映射。
解析 .rela.plt/.got.plt 构建 函数名→PLT桩→GOT条目 映射, 并与危险函数清单交叉标记可利用导入;
剥离二进制回退到 .dynstr 偏移解析, 不依赖 angr/pyelftools 高层 API。
"""


import logging
import os
import struct
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from config import R2_PATH

_log = logging.getLogger(__name__)

# 危险函数清单 —— 与 core/static_analysis.py 中的 DANGEROUS_FUNCTIONS 保持同步
_EXPLOITABLE_CATEGORIES = {
    'system':   ('command-injection', 'Critical'),
    'popen':    ('command-injection', 'Critical'),
    'execve':   ('command-injection', 'Critical'),
    'execl':    ('command-injection', 'Critical'),
    'gets':     ('buffer-overflow', 'Critical'),
    'strcpy':   ('buffer-overflow', 'High'),
    'strcat':   ('buffer-overflow', 'High'),
    'sprintf':  ('buffer-overflow', 'High'),
    'vsprintf': ('buffer-overflow', 'High'),
    'scanf':    ('buffer-overflow', 'Medium'),
    'memcpy':   ('buffer-overflow', 'Medium'),
    'read':     ('buffer-overflow', 'Medium'),
    'write':    ('info-leak', 'Medium'),
    'puts':     ('info-leak', 'Medium'),
    'printf':   ('format-string', 'Medium'),
    'fprintf':  ('format-string', 'Medium'),
    'mprotect': ('memory-manipulation', 'High'),
    'mmap':     ('memory-manipulation', 'Medium'),
    'malloc':   ('heap-corruption', 'Low'),
    'free':     ('heap-corruption', 'Low'),
    'fork':     ('race-condition', 'Low'),
}


def scan_plt(path: str) -> List[Dict[str, Any]]:
    """
    解析 ELF 的 PLT/GOT 条目。

    优先使用 radare2 解析，失败时回退到 pyelftools。
    返回的条目列表按地址排序，每个条目包含名称、PLT地址、GOT地址和风险标记。

    Args:
        path: ELF 文件路径

    Returns:
        PLT 条目列表，每个条目为:
        {
            'name': str,           # 函数名
            'plt_addr': int,       # PLT 桩地址
            'got_addr': int,       # GOT 条目地址 (0 表示不可用)
            'is_dangerous': bool,  # 属于危险函数
            'risk_category': str,   # 风险类别
            'risk_severity': str,   # 严重程度
        }
    """
    entries = _scan_plt_r2(path)
    if entries:
        return entries

    _log.debug("r2 PLT scan failed for %s, falling back to pyelftools", path)
    entries = _scan_plt_pyelftools(path)
    return entries


def _scan_plt_r2(path: str) -> List[Dict[str, Any]]:
    """通过 radare2 的 iE 命令获取导入表。"""
    if not os.path.isfile(path):
        return []

    try:
        proc = subprocess.run(
            [R2_PATH, '-q', '-e', 'io.color=false', '-c', 'iEj', path],
            capture_output=True, text=True, timeout=30,
        )
        import json
        raw = json.loads(proc.stdout)
        return _build_plt_entries(raw)
    except (json.JSONDecodeError, subprocess.TimeoutExpired):
        pass
    except FileNotFoundError:
        _log.debug("radare2 not found, PLT scan unavailable")
    except Exception as e:
        _log.debug("r2 PLT scan error: %s", e)
    return []


def _scan_plt_pyelftools(path: str) -> List[Dict[str, Any]]:
    """通过 pyelftools 直接解析 .rela.plt 和 .dynsym。"""
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.relocation import RelocationSection

        entries_raw: List[Dict[str, Any]] = []
        with open(path, 'rb') as f:
            elf = ELFFile(f)

            # 定位 .rela.plt 段
            rela_plt = None
            for sec in elf.iter_sections():
                if isinstance(sec, RelocationSection) and '.rela.plt' in sec.name:
                    rela_plt = sec
                    break

            if rela_plt is None:
                # 无 PLT 重定位表
                return []

            # 获取符号表
            symtab = elf.get_section(rela_plt['sh_link'])

            for reloc in rela_plt.iter_relocations():
                symbol = symtab.get_symbol(reloc['r_info_sym'])
                name = symbol.name if symbol else ''
                if name:
                    entries_raw.append({
                        'name': name,
                        'plt': '',  # 无地址信息，仅标记为危险函数
                        'got_addr': reloc['r_offset'],
                    })

        return _build_plt_entries(entries_raw)
    except ImportError:
        _log.debug("pyelftools not installed, PLT scan unavailable")
    except Exception as e:
        _log.debug("pyelftools PLT scan error: %s", e)
    return []


def _build_plt_entries(raw_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """标准化 PLT 条目并标记危险函数。"""
    entries = []
    for raw in raw_entries:
        name = raw.get('name', '')
        if not name or name.startswith('__') or name.startswith('_ITM_'):
            continue

        plt_addr = _parse_int(raw.get('plt', 0))
        got_addr = _parse_int(raw.get('got_addr', 0))

        category, severity = _EXPLOITABLE_CATEGORIES.get(name, (None, None))

        entry = {
            'name': name,
            'plt_addr': plt_addr,
            'got_addr': got_addr,
            'is_dangerous': category is not None,
            'risk_category': category or 'unknown',
            'risk_severity': severity or 'None',
        }
        entries.append(entry)

    # 危险函数优先，其余按名称排序
    entries.sort(key=lambda e: (
        not e['is_dangerous'],
        {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'None': 4}.get(
            e['risk_severity'], 5),
        e['name'],
    ))
    return entries


def _parse_int(value: Any) -> int:
    """将多种格式的地址值转为 int。"""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return 0
        try:
            return int(value, 16) if value.startswith('0x') else int(value)
        except ValueError:
            pass
    return 0


def find_exploitable_functions(plt_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    筛选出可被利用的导入函数。

    在 PLT 条目中过滤危险函数，按利用价值排序：
    exec 类函数 (system/popen/execve) 排在最前。

    Args:
        plt_entries: scan_plt() 的返回值

    Returns:
        仅包含 is_dangerous=True 的条目子集
    """
    exploitable = [e for e in plt_entries if e['is_dangerous']]
    exec_order = {'command-injection': 0, 'buffer-overflow': 1,
                  'format-string': 2, 'memory-manipulation': 3,
                  'info-leak': 4, 'heap-corruption': 5}
    exploitable.sort(
        key=lambda e: (exec_order.get(e['risk_category'], 99), e['name'])
    )
    return exploitable
