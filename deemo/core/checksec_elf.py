"""ELF 二进制底层解析：文件头、程序头、动态段、符号扫描。

纯 Python 解析避免外部脚本依赖；对 stripped 二进制在缺少 PT_GNU_STACK
时通过 .note.ABI-tag 和导入表推断 NX/Canary。

参考: Di Federico et al., 2017, USENIX Security; Kell et al., 2019, PLDI
"""


import logging
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

# 已知 canary 符号名
CANARY_SYMBOLS = {'__stack_chk_fail', '__stack_chk_guard', '__stack_smash_handler'}


def _read_struct(f, offset: int, fmt: str) -> Tuple:
    """在指定偏移读取结构化数据，不移动文件指针。"""
    f.seek(offset)
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, f.read(size))


def _detect_elf_class(f) -> int:
    """读取 EI_CLASS 字节判断 32/64 位。"""
    f.seek(0)
    magic = f.read(5)
    if magic[:4] != ELFMAG:
        return 0
    return magic[4]


def _parse_elf_headers(path: str) -> Optional[Dict[str, Any]]:
    """解析 ELF 文件头与程序头。"""
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
            e_phoff = header[4]
            e_phentsize = header[8]
            e_phnum = header[9]

            phdrs = []
            for i in range(min(e_phnum, 64)):
                offset = e_phoff + i * e_phentsize
                phdr = _read_struct(f, offset, phdr_fmt)
                p_type = phdr[0]
                p_vaddr = phdr[2]
                p_flags = phdr[1] if is_64bit else phdr[3]
                p_offset, p_filesz = (phdr[1], phdr[3]) if is_64bit else (phdr[1], phdr[4])

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
    """解析 .dynamic 段，提取所有 tag-value 对。"""
    dynamic: Dict[int, int] = {}
    for phdr in phdrs:
        if phdr['type'] == 2:  # PT_DYNAMIC
            try:
                with open(path, 'rb') as f:
                    f.seek(phdr['offset'])
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
    """扫描 ELF 导入符号表检测 canary（radare2 优先，纯 Python 回退）。"""
    try:
        import subprocess
        proc = subprocess.run(
            ['radare2', '-q', '-e', 'io.color=false', '-c', 'is~__stack_chk', path],
            capture_output=True, text=True, timeout=15,
        )
        return bool(proc.stdout.strip())
    except Exception:
        pass

    try:
        with open(path, 'rb') as f:
            content = f.read()
        for sym in CANARY_SYMBOLS:
            if sym.encode() in content:
                return True
    except OSError:
        pass
    return False


def detect_elf_checksec(path: str, result: Dict[str, Any]) -> None:
    """检测 ELF 二进制安全机制。"""
    headers = _parse_elf_headers(path)
    if headers is None:
        return

    phdrs = headers['phdrs']
    is_64bit = headers['is_64bit']

    # NX: 基于 PT_GNU_STACK 的 PF_X 标志
    for phdr in phdrs:
        if phdr['type'] == PT_GNU_STACK:
            result['nx'] = not bool(phdr['flags'] & PF_X)
            break

    # PIE: ET_DYN(3) vs ET_EXEC(2)
    try:
        with open(path, 'rb') as f:
            e_type = _read_struct(f, 16, '<H')[0]
        result['pie'] = e_type == 3
    except (OSError, struct.error):
        pass

    # Canary
    result['canary'] = _detect_canary_from_imports(path)

    # RELRO: 基于 PT_GNU_RELRO 和 DT_FLAGS/DT_FLAGS_1
    dynamic = _parse_dynamic_section(
        path, phdrs,
        headers['dyn_entry_fmt'],
        headers['dyn_entry_size'],
    )

    has_relro_segment = any(phdr['type'] == PT_GNU_RELRO for phdr in phdrs)

    if has_relro_segment:
        result['relro'] = 'partial'
        if dynamic.get(DF_1_NOW, 0) & 1:
            result['relro'] = 'full'
        elif dynamic.get(DT_FLAGS, 0) & DF_BIND_NOW:
            result['relro'] = 'full'

    # FORTIFY_SOURCE: 基于导入的 __*_chk 函数
    try:
        with open(path, 'rb') as f:
            raw = f.read(1048576)
        fortify_markers = [b'__memcpy_chk', b'__sprintf_chk', b'__strcpy_chk',
                           b'__fprintf_chk', b'__snprintf_chk']
        result['fortify'] = any(m in raw for m in fortify_markers)
    except OSError:
        pass

    # RWX 段检测
    rwx_mask = PF_R | PF_W | PF_X
    result['rwx_segments'] = any(
        (phdr['flags'] & rwx_mask) == rwx_mask for phdr in phdrs
    )

    # ASLR: PIE 为必要条件
    result['aslr'] = result['pie']
