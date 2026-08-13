"""
PLT/导入表解析器 — 从PE提取导入函数名, 用于解析call目标。

方法:
  1. 解析PE section headers, 定位 .idata 和 .text 段
  2. 从 .idata 段的导入描述符表中提取 DLL名+函数名
  3. 建立 {IAT虚拟地址 → 函数名} 映射

RVA→文件偏移使用 section header 映射表。
若导入解析失败, 回退到直接从 .idata 段扫描可打印字符串作为候选函数名。

修改记录:
  创建 2025-05-12
"""
import struct, re
from typing import Dict, List, Optional


def _pe_sections(data: bytes) -> List[dict]:
    """解析PE section headers → [{name, va, size, raw_ptr, raw_size}]。"""
    if len(data) < 512 or data[:2] != b'MZ':
        return []
    pe_off = struct.unpack_from('<I', data, 60)[0]
    nsections = struct.unpack_from('<H', data, pe_off + 6)[0]
    opt_hdr_size = struct.unpack_from('<H', data, pe_off + 20)[0]
    sec_off = pe_off + 24 + opt_hdr_size
    sections = []
    for i in range(nsections):
        so = sec_off + i * 40
        name = data[so:so+8].rstrip(b'\x00').decode('ascii', 'ignore')
        sections.append({
            'name': name,
            'va': struct.unpack_from('<I', data, so + 12)[0],
            'size': struct.unpack_from('<I', data, so + 8)[0],
            'raw_ptr': struct.unpack_from('<I', data, so + 20)[0],
            'raw_size': struct.unpack_from('<I', data, so + 16)[0],
        })
    return sections


def _rva_to_offset(sections: List[dict], rva: int) -> Optional[int]:
    for s in sections:
        if s['va'] <= rva < s['va'] + max(s['size'], s['raw_size']):
            return s['raw_ptr'] + (rva - s['va'])
    return None


def _parse_pe_imports(data: bytes) -> Dict[int, str]:
    result: Dict[int, str] = {}
    if len(data) < 512 or data[:2] != b'MZ':
        return result

    pe_off = struct.unpack_from('<I', data, 60)[0]
    opt_hdr_size = struct.unpack_from('<H', data, pe_off + 20)[0]
    magic = struct.unpack_from('<H', data, pe_off + 24)[0]
    sections = _pe_sections(data)
    if not sections:
        return result

    # DataDirectory[1] = Import Table
    dd_start = pe_off + 24 + (112 if magic == 0x20b else 96)
    import_rva = struct.unpack_from('<I', data, dd_start + 8)[0]   # DD[1].RVA
    if import_rva == 0:
        return result

    imp_off = _rva_to_offset(sections, import_rva)
    if imp_off is None:
        return result

    # 遍历 IMAGE_IMPORT_DESCRIPTOR 数组
    while imp_off + 20 <= len(data):
        orig_thunk_rva = struct.unpack_from('<I', data, imp_off)[0]     # OriginalFirstThunk
        name_rva = struct.unpack_from('<I', data, imp_off + 12)[0]       # Name RVA
        iat_rva = struct.unpack_from('<I', data, imp_off + 16)[0]        # FirstThunk

        if name_rva == 0 and orig_thunk_rva == 0:
            break

        # IAT地址对应导入函数→这是我们的映射键
        if iat_rva:
            thunk_off = _rva_to_offset(sections, orig_thunk_rva or iat_rva)
            if thunk_off:
                iat_base = iat_rva
                while thunk_off + 8 <= len(data):
                    if magic == 0x20b:
                        thunk_val = struct.unpack_from('<Q', data, thunk_off)[0]
                        thunk_off += 8
                        iat_rva_inc = 8
                    else:
                        thunk_val = struct.unpack_from('<I', data, thunk_off)[0]
                        thunk_off += 4
                        iat_rva_inc = 4

                    if thunk_val == 0:
                        break
                    if thunk_val & (1 << 63 if magic == 0x20b else 31):
                        iat_base += iat_rva_inc
                        continue

                    name_entry_rva = thunk_val & 0x7fffffff
                    name_off = _rva_to_offset(sections, name_entry_rva)
                    if name_off:
                        hint = struct.unpack_from('<H', data, name_off)[0]
                        fname = data[name_off+2:].split(b'\x00')[0]
                        try:
                            fname_str = fname.decode('ascii')
                            result[iat_base] = fname_str
                        except UnicodeDecodeError:
                            pass
                    iat_base += iat_rva_inc

        imp_off += 20

    return result


def _fallback_string_scan(data: bytes, sections: List[dict]) -> Dict[int, str]:
    """
    回退方案: 扫描 .idata 段中的可打印字符串作为候选函数名。
    无法建立精确的地址→函数名映射, 但提供候选集供模式匹配。
    """
    result: Dict[int, str] = {}
    for s in sections:
        if '.idata' in s['name'] or '.rdata' in s['name']:
            start = s['raw_ptr']
            end = start + min(s['raw_size'], 4096)
            chunk = data[start:end]
            for m in re.finditer(rb'[a-zA-Z_][a-zA-Z0-9_]{2,31}', chunk):
                try:
                    fname = m.group().decode('ascii')
                    if fname not in ('Name', 'Characteristics', 'VirtualAddress', '__NULL_IMPORT_DESCRIPTOR'):
                        result[m.start() + start] = fname
                except UnicodeDecodeError:
                    pass
    return result


def resolve_imports(filepath: str) -> Dict[int, str]:
    with open(filepath, 'rb') as f:
        data = f.read()
    pe_imports = _parse_pe_imports(data)
    if pe_imports:
        return pe_imports
    sections = _pe_sections(data)
    return _fallback_string_scan(data, sections)
