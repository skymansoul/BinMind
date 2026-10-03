"""
PLT/GOT 解析器: 从 ELF 提取导入表地址映射。
解析 .rela.plt/.got.plt 构建 函数名-PLT桩-GOT条目 映射, 并与危险函数清单交叉标记可利用导入;
剥离二进制回退到 .dynstr 偏移解析, 不依赖 angr/pyelftools 高层 API。
"""


import json
import logging
import os
import struct
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from config import R2_PATH
from core.detection_shared import DANGEROUS_FUNCTIONS, normalize_import_name

_log = logging.getLogger(__name__)

# 兼容旧测试/调用方: 从统一危险函数表派生 PLT 分类。
_EXPLOITABLE_CATEGORIES = {
    name: (meta[0], meta[1]) for name, meta in DANGEROUS_FUNCTIONS.items()
}


def scan_plt(path: str) -> List[Dict[str, Any]]:
    """
    解析 ELF 的 PLT/GOT 条目。

    优先 radare2, 失败回退 pyelftools。每项含名称/PLT地址/
    GOT地址/危险标记/风险类别/严重度。
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
        raw_name = raw.get('name', '')
        name = normalize_import_name(raw_name)
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

    在 PLT 条目中过滤危险函数, 按利用价值排序:
    exec 类函数 (system/popen/execve) 排在最前。
    返回仅含 is_dangerous=True 的条目子集。
    """
    exploitable = [e for e in plt_entries if e['is_dangerous']]
    exec_order = {'command-injection': 0, 'buffer-overflow': 1,
                  'format-string': 2, 'memory-manipulation': 3,
                  'info-leak': 4, 'heap-corruption': 5}
    exploitable.sort(
        key=lambda e: (exec_order.get(e['risk_category'], 99), e['name'])
    )
    return exploitable
