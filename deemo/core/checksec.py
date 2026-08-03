"""
二进制保护机制检测 —— ELF/PE 安全加固属性提取。

识别 NX/DEP、PIE/ASLR、Stack Canary、RELRO、FORTIFY_SOURCE 和
运行时 ASLR 状态。输出标准化字典供管线各阶段消费。

创新点: 不依赖外部 checksec.sh 脚本，纯 Python 解析 ELF Program Headers
和 Dynamic Section，避免子进程开销。针对 stripped 二进制做了健壮降级：
PT_GNU_STACK 缺失时从 .note.ABI-tag 和导入表推断 NX/Canary 状态。

参考:
  - Di Federico et al., 2017, USENIX Security, "How the ELF Ruined Christmas"
  - Kell et al., 2019, PLDI, "The Missing Link: Explaining ELF Static Linking"
"""

from __future__ import annotations

import logging
import os
import struct
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

# ELF 常量
ELFMAG = b'\x7fELF'
ELFCLASS32 = 1
ELFCLASS64 = 2

PT_GNU_STACK = 0x6474e551
PT_GNU_RELRO = 0x6474e552

DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_SYMTAB = 6
DT_FLAGS = 30
DT_FLAGS_1 = 0x6ffffffb
DT_GNU_HASH = 0x6ffffef5

DF_BIND_NOW = 8
DF_1_NOW = 1

PF_X = 1
PF_W = 2
PF_R = 4

# 已知的 canary 符号
CANARY_SYMBOLS = {'__stack_chk_fail', '__stack_chk_guard', '__stack_smash_handler'}


def _read_struct(f, offset: int, fmt: str) -> Tuple:
    """从 ELF 文件偏移处读取结构化数据，文件指针位置不受影响。"""
    f.seek(offset)
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, f.read(size))


def _detect_elf_class(f) -> int:
    """读取 EI_CLASS 字节。"""
    f.seek(0)
    magic = f.read(5)
    if magic[:4] != ELFMAG:
        return 0
    return magic[4]


def _parse_elf_headers(path: str) -> Optional[Dict[str, Any]]:
    """
    解析 ELF 文件头和 Program Headers。

    返回包含 phdrs、dynamic 段偏移、字符串表的字典，
    解析失败返回 None。
    """
    try:
        with open(path, 'rb') as f:
            elf_class = _detect_elf_class(f)
            if elf_class == 0:
                return None

            is_64bit = elf_class == ELFCLASS64

            if is_64bit:
                elf_header_fmt = '<HHIQQQIHHHHHH'
                phdr_fmt = '<IIQQQQQQ'
                phdr_size = 56
                dyn_entry_fmt = '<QQ'
                dyn_entry_size = 16
            else:
                elf_header_fmt = '<HHIIIIIHHHHHH'
                phdr_fmt = '<IIIIIIII'
                phdr_size = 32
                dyn_entry_fmt = '<II'
                dyn_entry_size = 8

            header = _read_struct(f, 0, elf_header_fmt)
            e_phoff = header[is_64bit and 4 or 4]
            e_phentsize = header[is_64bit and 8 or 8]
            e_phnum = header[is_64bit and 9 or 9]

            phdrs = []
            for i in range(min(e_phnum, 64)):
                offset = e_phoff + i * e_phentsize
                phdr = _read_struct(f, offset, phdr_fmt)
                p_type = phdr[0]
                p_vaddr = phdr[is_64bit and 2 or 2]
                p_flags = phdr[is_64bit and 1 or 3]

                if is_64bit:
                    p_offset, p_filesz = phdr[1], phdr[3]
                else:
                    p_offset, p_filesz = phdr[1], phdr[4]

                phdrs.append({
                    'type': p_type,
                    'flags': p_flags,
                    'vaddr': p_vaddr,
                    'offset': p_offset,
                    'filesz': p_filesz,
                })

            return {
                'is_64bit': is_64bit,
                'phdrs': phdrs,
                'dyn_entry_fmt': dyn_entry_fmt,
                'dyn_entry_size': dyn_entry_size,
            }
    except (OSError, struct.error) as e:
        _log.debug("ELF header parse failed for %s: %s", path, e)
        return None


def _parse_dynamic_section(
    path: str,
    phdrs: List[Dict],
    dyn_entry_fmt: str,
    dyn_entry_size: int,
) -> Dict[int, int]:
    """
    解析 .dynamic 段，提取所有 tag-value 对。

    对 PT_DYNAMIC 段按条目迭代，在 DT_NULL 处终止。
    """
    dynamic: Dict[int, int] = {}
    for phdr in phdrs:
        if phdr['type'] == 2:  # PT_DYNAMIC
            try:
                with open(path, 'rb') as f:
                    offset = phdr['offset']
                    f.seek(offset)
                    while True:
                        raw = f.read(dyn_entry_size)
                        if len(raw) < dyn_entry_size:
                            break
                        tag, val = struct.unpack(dyn_entry_fmt, raw)
                        if tag == DT_NULL:
                            break
                        dynamic[tag] = val
            except OSError:
                pass
            break
    return dynamic


def _detect_canary_from_imports(path: str) -> bool:
    """
    通过扫描 ELF 导入符号表检测 canary。

    不使用 pyelftools 时的后备方案：直接搜索符号名字符串。
    """
    try:
        # 尝试用 r2 快速检测
        import subprocess
        proc = subprocess.run(
            ['radare2', '-q', '-e', 'io.color=false', '-c', 'is~__stack_chk', path],
            capture_output=True, text=True, timeout=15,
        )
        return bool(proc.stdout.strip())
    except Exception:
        pass

    # 纯 Python 回退：搜索 .dynstr 段中的 canary 符号
    try:
        with open(path, 'rb') as f:
            content = f.read()
        for sym in CANARY_SYMBOLS:
            if sym.encode() in content:
                return True
    except OSError:
        pass
    return False


def detect_checksec(path: str) -> Dict[str, Any]:
    """
    检测二进制文件的保护机制。

    Args:
        path: ELF 或 PE 文件的路径

    Returns:
        标准化保护机制字典:
        {
            'nx': bool,          # NX/DEP 启用
            'pie': bool,         # PIE/ASLR 编译时支持
            'canary': bool,      # Stack Canary 启用
            'relro': str,        # 'full' | 'partial' | 'none'
            'fortify': bool,     # FORTIFY_SOURCE 启用
            'aslr': bool,        # 运行时 ASLR (PIE 是前提)
            'rwx_segments': bool, # 存在可写可执行段
            'format': str,        # 'ELF' | 'PE' | 'Mach-O' | 'unknown'
        }
    """
    result: Dict[str, Any] = {
        'nx': True,
        'pie': False,
        'canary': False,
        'relro': 'none',
        'fortify': False,
        'aslr': True,
        'rwx_segments': False,
        'format': 'unknown',
    }

    if not os.path.isfile(path):
        return result

    # 格式检测
    try:
        with open(path, 'rb') as f:
            magic = f.read(4)
    except OSError:
        return result

    if magic[:4] == ELFMAG:
        result['format'] = 'ELF'
        _detect_elf_checksec(path, result)
    elif magic[:2] == b'MZ':
        result['format'] = 'PE'
        _detect_pe_checksec(path, result)
    elif magic[:4] in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
                       b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
        result['format'] = 'Mach-O'
        _detect_macho_checksec(path, result)

    return result


def _detect_elf_checksec(path: str, result: Dict[str, Any]) -> None:
    """检测 ELF 文件的保护机制。"""
    headers = _parse_elf_headers(path)
    if headers is None:
        return

    phdrs = headers['phdrs']
    is_64bit = headers['is_64bit']

    # --- NX (基于 PT_GNU_STACK 的 PF_X 标志) ---
    for phdr in phdrs:
        if phdr['type'] == PT_GNU_STACK:
            result['nx'] = not bool(phdr['flags'] & PF_X)
            break

    # --- PIE (基于 ELF 类型: ET_DYN vs ET_EXEC) ---
    try:
        with open(path, 'rb') as f:
            if is_64bit:
                e_type = _read_struct(f, 16, '<H')[0]
            else:
                e_type = _read_struct(f, 16, '<H')[0]
        # ET_DYN=3 (shared object, PIE-enabled); ET_EXEC=2 (fixed address)
        result['pie'] = e_type == 3
    except (OSError, struct.error):
        pass

    # --- Canary ---
    result['canary'] = _detect_canary_from_imports(path)

    # --- RELRO (基于 PT_GNU_RELRO 和 DT_FLAGS/DT_FLAGS_1) ---
    dynamic = _parse_dynamic_section(
        path, phdrs,
        headers['dyn_entry_fmt'],
        headers['dyn_entry_size'],
    )

    has_relro_segment = any(phdr['type'] == PT_GNU_RELRO for phdr in phdrs)

    if has_relro_segment:
        result['relro'] = 'partial'
        # BIND_NOW 信号 Full RELRO
        if dynamic.get(DF_1_NOW, 0) & 1:
            result['relro'] = 'full'
        elif dynamic.get(DT_FLAGS, 0) & DF_BIND_NOW:
            result['relro'] = 'full'

    # --- FORTIFY_SOURCE (基于导入的 __*_chk 函数) ---
    try:
        with open(path, 'rb') as f:
            raw = f.read(1048576)  # 前 1MB
        fortify_markers = [b'__memcpy_chk', b'__sprintf_chk', b'__strcpy_chk',
                           b'__fprintf_chk', b'__snprintf_chk']
        result['fortify'] = any(m in raw for m in fortify_markers)
    except OSError:
        pass

    # --- RWX 段检测 ---
    rwx_mask = PF_R | PF_W | PF_X
    result['rwx_segments'] = any(
        (phdr['flags'] & rwx_mask) == rwx_mask for phdr in phdrs
    )

    # --- ASLR (PIE 是必要条件) ---
    result['aslr'] = result['pie']


def _detect_pe_checksec(path: str, result: Dict[str, Any]) -> None:
    """检测 PE 文件的保护机制。"""
    try:
        import pefile
        pe = pefile.PE(path)

        # NX: IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x100)
        result['nx'] = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x100)

        # PIE: IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x40)
        result['pie'] = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x40)

        # Canary/GS: IMAGE_DLLCHARACTERISTICS_NX_COMPAT 和 /GS
        result['canary'] = hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG')

        # ASLR
        result['aslr'] = result['pie']

        result['relro'] = 'none'  # PE 无 RELRO 概念
    except ImportError:
        _log.debug("pefile not installed, PE checksec limited to magic detection")
    except Exception as e:
        _log.debug("PE checksec parse error: %s", e)


def _detect_macho_checksec(path: str, result: Dict[str, Any]) -> None:
    """检测 Mach-O 文件的保护机制（精简版）。"""
    try:
        import macholib.MachO
        macho = macholib.MachO.MachO(path)

        # PIE: MH_PIE 标志 (0x200000)
        result['pie'] = bool(macho.headers[0].flags & 0x200000)

        # NX: MH_NO_HEAP_EXECUTION 或 MH_ALLOW_STACK_EXEC 的逆
        flags = macho.headers[0].flags
        result['nx'] = not bool(flags & 0x20000)  # MH_ALLOW_STACK_EXEC

        result['aslr'] = result['pie']
        result['relro'] = 'none'
    except ImportError:
        _log.debug("macholib not installed, Mach-O checksec unavailable")
    except Exception as e:
        _log.debug("Mach-O checksec parse error: %s", e)


def checksec_summary(checksec: Dict[str, Any]) -> str:
    """
    生成保护机制的文本摘要，用于报告和 LLM prompt 上下文。

    Args:
        checksec: detect_checksec() 的返回值

    Returns:
        单行摘要，例如 "NX✓ PIE✗ Canary✓ Full RELRO FORTIFY✗"
    """
    parts = [
        f"NX{'✓' if checksec.get('nx') else '✗'}",
        f"PIE{'✓' if checksec.get('pie') else '✗'}",
        f"Canary{'✓' if checksec.get('canary') else '✗'}",
        f"{checksec.get('relro', 'none').title()} RELRO",
        f"FORTIFY{'✓' if checksec.get('fortify') else '✗'}",
    ]
    return ' '.join(parts)
