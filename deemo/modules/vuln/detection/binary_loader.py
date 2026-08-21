"""
二进制加载器 - 解析ELF/PE头部, 提取.text段用于capstone反汇编。

设计决策:
  capstone从固定偏移0x1000反汇编PE文件只能得到6条指令(PE头数据被误解析为代码)。
  本模块正确解析ELF program headers和PE section headers,
  定位.text段的确切文件偏移和虚拟地址, 使capstone能反汇编全部代码。

支持: ELF (x86-64), PE (x86-64)
不依赖: pyelftools, pefile — 纯二进制头部解析

修改记录:
  创建 2025-04-17
"""
import struct
from typing import Optional, Tuple


def _parse_elf_text_section(data: bytes) -> Optional[Tuple[int, int, int]]:
    """解析ELF64 .text段。返回 (file_offset, vaddr, size) 或 None。"""
    if len(data) < 64 or data[:4] != b'\x7fELF':
        return None
    is_64bit = data[4] == 2
    if not is_64bit: return None

    # ELF64 header
    e_phoff = struct.unpack_from('<Q', data, 32)[0]
    e_phentsize = struct.unpack_from('<H', data, 54)[0]
    e_phnum = struct.unpack_from('<H', data, 56)[0]

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        if p_type != 1: continue  # PT_LOAD
        p_offset = struct.unpack_from('<Q', data, off + 8)[0]
        p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
        p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
        p_flags = struct.unpack_from('<I', data, off + 4)[0]
        if p_flags & 5:  # PF_X | PF_R = executable+readable - .text
            return int(p_offset), int(p_vaddr), int(p_filesz)
    return None


def _parse_pe_text_section(data: bytes) -> Optional[Tuple[int, int, int]]:
    """解析PE32+ .text段。返回 (file_offset, vaddr, size)。"""
    if len(data) < 512 or data[:2] != b'MZ': return None
    pe_offset = struct.unpack_from('<I', data, 60)[0]
    if pe_offset + 24 > len(data): return None

    # NumberOfSections is in COFF FileHeader (offset +6 from PE sig), NOT in OptionalHeader
    nsections = struct.unpack_from('<H', data, pe_offset + 6)[0]
    opt_hdr_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
    sec_offset = pe_offset + 24 + opt_hdr_size

    for i in range(min(nsections, 50)):
        off = sec_offset + i * 40
        name = data[off:off+8].rstrip(b'\x00').decode('ascii','ignore')
        if name == '.text':
            raw_size = struct.unpack_from('<I', data, off + 16)[0]
            raw_ptr = struct.unpack_from('<I', data, off + 20)[0]
            vaddr = struct.unpack_from('<I', data, off + 12)[0]
            return int(raw_ptr), int(vaddr), int(raw_size)
    return None


def load_text_section(filepath: str) -> Optional[Tuple[bytes, int]]:
    """
    加载二进制的.text段。返回 (code_bytes, base_vaddr) 或 None。

    优先尝试ELF解析, 回退PE解析, 再回退原始读取。
    """
    with open(filepath, 'rb') as f:
        data = f.read()

    # ELF
    elf_result = _parse_elf_text_section(data)
    if elf_result:
        offset, vaddr, size = elf_result
        if offset + size <= len(data):
            return data[offset:offset+size], vaddr

    # PE
    pe_result = _parse_pe_text_section(data)
    if pe_result:
        offset, vaddr, size = pe_result
        if offset + size <= len(data):
            return data[offset:offset+size], vaddr

    # Raw fallback: 尝试从0x1000开始
    if len(data) > 0x1000:
        return data[0x1000:0x10000], 0x1000

    return None
