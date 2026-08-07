# Created: 2026-06-01 08:06:15
#
# pe_elf_analysis — PE/ELF 深度结构解析
# 出的 PE/ELF 特定分析函数
# binary_scanner.py 原从 ..info_collect 导入但函数未定义
# 提供: analyze_pe_sections, parse_pe_rich_header, check_pe_signature,
#       detect_pe_overlay, enumerate_pe_resources, analyze_pe_exports,
#       parse_pe_debug_directory, analyze_pe_relocations, analyze_elf_segments

import struct
from typing import Dict, List, Optional


def analyze_pe_sections(raw: bytes) -> Dict:
    """PE 节表分析：节数量、WX/E 冲突计数、每节属性列表。"""
    if len(raw) < 64 or raw[0:2] != b'MZ':
        return {"section_count": 0, "wxe_violations": 0, "sections": []}
    try:
        pe_off = struct.unpack_from('<I', raw, 0x3C)[0]
        if pe_off + 4 > len(raw): return {"section_count": 0, "wxe_violations": 0, "sections": []}
        num_sections = struct.unpack_from('<H', raw, pe_off + 6)[0]
        opt_size = struct.unpack_from('<H', raw, pe_off + 20)[0]
        sec_off = pe_off + 24 + opt_size
        sections, wxe_count = [], 0
        for i in range(min(num_sections, 96)):
            so = sec_off + i * 40
            if so + 40 > len(raw): break
            name = raw[so:so + 8].rstrip(b'\x00').decode('ascii', errors='replace')
            vsize = struct.unpack_from('<I', raw, so + 8)[0]
            chars = struct.unpack_from('<I', raw, so + 36)[0]
            is_exec, is_write = bool(chars & 0x20000000), bool(chars & 0x80000000)
            if is_exec and is_write: wxe_count += 1
            sections.append({"name": name, "virtual_size": vsize,
                            "is_executable": is_exec, "is_writable": is_write})
        return {"section_count": len(sections), "wxe_violations": wxe_count, "sections": sections}
    except Exception:
        return {"section_count": 0, "wxe_violations": 0, "sections": []}


def parse_pe_rich_header(raw: bytes) -> Optional[Dict]:
    """PE Rich Header 解析：编译工具链标识提取。"""
    try:
        rich_off = raw.find(b'Rich')
        if rich_off == -1 or rich_off < 0x80: return None
        xor_key = struct.unpack_from('<I', raw, rich_off + 4)[0]
        entries, pos = [], rich_off - 8
        while pos > 0x80:
            entry = struct.unpack_from('<II', raw, pos)
            if entry[0] == 0 and entry[1] == 0: break
            comp_id = (entry[0] >> 16) ^ xor_key
            count = (entry[0] & 0xFFFF) ^ xor_key
            entries.append({"comp_id": comp_id, "count": count})
            pos -= 8
        return {"xor_key": xor_key, "entries": entries[::-1]} if entries else None
    except Exception:
        return None


def check_pe_signature(raw: bytes) -> Dict:
    """PE 数字签名检测：检查 CERTIFICATE 目录条目非零。"""
    try:
        if len(raw) < 64 or raw[0:2] != b'MZ':
            return {"signed": False, "certificate_rva": 0, "certificate_size": 0}
        pe_off = struct.unpack_from('<I', raw, 0x3C)[0]
        opt_magic = struct.unpack_from('<H', raw, pe_off + 24)[0]
        data_dir_off = pe_off + 24 + (112 if opt_magic == 0x020B else 96)
        cert_rva, cert_size = struct.unpack_from('<II', raw, data_dir_off + 32)
        return {"signed": cert_rva != 0 and cert_size > 0,
                "certificate_rva": cert_rva, "certificate_size": cert_size}
    except Exception:
        return {"signed": False, "certificate_rva": 0, "certificate_size": 0}


def detect_pe_overlay(raw: bytes) -> Dict:
    """PE 覆层检测：文件实际大小 > 节表声明范围 → 附加数据。"""
    try:
        if len(raw) < 64 or raw[0:2] != b'MZ':
            return {"has_overlay": False, "overlay_size": 0}
        pe_off = struct.unpack_from('<I', raw, 0x3C)[0]
        num_sec = struct.unpack_from('<H', raw, pe_off + 6)[0]
        opt_size = struct.unpack_from('<H', raw, pe_off + 20)[0]
        sec_off = pe_off + 24 + opt_size
        max_end = 0
        for i in range(min(num_sec, 96)):
            so = sec_off + i * 40
            if so + 40 > len(raw): break
            max_end = max(max_end, struct.unpack_from('<I', raw, so + 20)[0] + struct.unpack_from('<I', raw, so + 16)[0])
        overlay_sz = len(raw) - max_end if max_end < len(raw) else 0
        return {"has_overlay": overlay_sz > 64, "overlay_size": overlay_sz,
                "overlay_ratio": round(overlay_sz / len(raw), 4)}
    except Exception:
        return {"has_overlay": False, "overlay_size": 0}


def enumerate_pe_resources(raw: bytes) -> Dict:
    """PE 资源表枚举：检测嵌入 PE (MZ+PE签名)。"""
    result = {"total_resources": 0, "embedded_pe": []}
    mz_positions, off = [], 0
    while True:
        pos = raw.find(b'MZ', off)
        if pos == -1 or pos == 0: break
        if pos + 64 < len(raw):
            sig_off = struct.unpack_from('<I', raw, pos + 0x3C)[0]
            if pos + sig_off + 4 < len(raw) and struct.unpack_from('<I', raw, pos + sig_off)[0] == 0x00004550:
                mz_positions.append(pos)
        off = pos + 1
        if len(mz_positions) > 20: break
    if len(mz_positions) > 1:
        result["embedded_pe"] = [{"offset": p, "offset_hex": f"0x{p:x}"} for p in mz_positions[1:]]
    result["total_resources"] = len(mz_positions)
    return result


def analyze_pe_exports(raw: bytes) -> Dict:
    """PE 导出表：函数数量、可疑模式（导出多但具名少）。"""
    try:
        if len(raw) < 64 or raw[0:2] != b'MZ':
            return {"export_count": 0, "suspicious_patterns": False}
        pe_off = struct.unpack_from('<I', raw, 0x3C)[0]
        is_64 = struct.unpack_from('<H', raw, pe_off + 24)[0] == 0x020B
        data_dir = pe_off + 24 + (112 if is_64 else 96)
        exp_rva, exp_size = struct.unpack_from('<II', raw, data_dir)
        if exp_rva == 0 or exp_size == 0 or exp_rva >= len(raw):
            return {"export_count": 0, "suspicious_patterns": False}
        num_funcs = struct.unpack_from('<I', raw, exp_rva + 20)[0]
        num_names = struct.unpack_from('<I', raw, exp_rva + 24)[0]
        return {"export_count": num_funcs, "named_exports": num_names,
                "suspicious_patterns": num_funcs > 100 and num_names < num_funcs * 0.3}
    except Exception:
        return {"export_count": 0, "suspicious_patterns": False}


def parse_pe_debug_directory(raw: bytes) -> Dict:
    """PE 调试目录：检测 PDB 路径泄露风险。"""
    try:
        if len(raw) < 64 or raw[0:2] != b'MZ':
            return {"has_debug": False, "info_leak_risk": False}
        pe_off = struct.unpack_from('<I', raw, 0x3C)[0]
        is_64 = struct.unpack_from('<H', raw, pe_off + 24)[0] == 0x020B
        data_dir = pe_off + 24 + (112 if is_64 else 96)
        dbg_rva, dbg_size = struct.unpack_from('<II', raw, data_dir + 48)
        if dbg_rva == 0 or dbg_size == 0:
            return {"has_debug": False, "info_leak_risk": False}
        return {"has_debug": True, "debug_rva": dbg_rva, "debug_size": dbg_size,
                "info_leak_risk": b'.pdb' in raw or b'PDB' in raw}
    except Exception:
        return {"has_debug": False, "info_leak_risk": False}


def analyze_pe_relocations(raw: bytes) -> Dict:
    """PE 重定位表：ASLR 兼容检测。"""
    try:
        if len(raw) < 64 or raw[0:2] != b'MZ':
            return {"aslr_compatible": False, "suspicious_large_relocs": False}
        pe_off = struct.unpack_from('<I', raw, 0x3C)[0]
        dll_chars = struct.unpack_from('<H', raw, pe_off + 94)[0]
        is_64 = struct.unpack_from('<H', raw, pe_off + 24)[0] == 0x020B
        data_dir = pe_off + 24 + (112 if is_64 else 96)
        _, reloc_size = struct.unpack_from('<II', raw, data_dir + 40)
        return {"aslr_compatible": bool(dll_chars & 0x0040),
                "relocation_size": reloc_size,
                "suspicious_large_relocs": reloc_size > 1_000_000}
    except Exception:
        return {"aslr_compatible": False, "suspicious_large_relocs": False}


def analyze_elf_segments(raw: bytes) -> Dict:
    """ELF Program Header 解析：段类型/WX属性/INTERP/NOTE。"""
    result = {"segments": [], "needed": [], "interp": None,
              "has_gnu_stack": False, "gnu_stack_exec": False}
    if len(raw) < 52 or raw[0:4] != b'\x7fELF': return result
    is_64, is_le = raw[4] == 2, raw[5] == 1
    e = '<' if is_le else '>'
    if is_64:
        phoff = struct.unpack_from(f'{e}Q', raw, 32)[0]
        phnum, phentsize = struct.unpack_from(f'{e}H', raw, 56)[0], struct.unpack_from(f'{e}H', raw, 54)[0]
        phdr_fmt = f'{e}IIQQQQ'; phdr_sz = 56
    else:
        phoff = struct.unpack_from(f'{e}IIII', raw, 28)[0]
        phnum = struct.unpack_from(f'{e}H', raw, 44)[0]
        phentsize = struct.unpack_from(f'{e}H', raw, 42)[0]
        phdr_fmt = f'{e}IIIIIIII'; phdr_sz = 32
    for i in range(min(phnum, 256)):
        po = phoff + i * phentsize
        if po + phdr_sz > len(raw): break
        if is_64:
            ptype, pflags, _, pvaddr, _, pfilesz = struct.unpack_from(phdr_fmt, raw, po)
        else:
            vals = struct.unpack_from(phdr_fmt, raw, po)
            ptype, pvaddr, pfilesz, pflags = vals[0], vals[2], vals[4], vals[7]
        result["segments"].append({
            "type": ptype, "vaddr": pvaddr, "filesz": pfilesz,
            "flags": pflags, "is_wxe": bool(pflags & 0x1) and bool(pflags & 0x2),
            "is_exec": bool(pflags & 0x1),
        })
        if ptype == 0x6474E551:
            result["has_gnu_stack"] = True; result["gnu_stack_exec"] = bool(pflags & 0x1)
    return result
