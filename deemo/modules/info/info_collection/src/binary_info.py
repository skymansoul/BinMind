# binary_info — PE/ELF/Mach-O 元数据解析，纯 struct 零外部依赖
# 目标环境可能无 pip，因此不依赖 pefile/elftools
# 仅提取分析所需的核心字段，不追求全格式覆盖

import os
import struct
import hashlib
from datetime import datetime
from typing import Dict, List, Optional
from itertools import islice

# PE 常量表
_IMAGE_DOS_SIGNATURE = 0x5A4D
_IMAGE_NT_SIGNATURE = 0x00004550
_IMAGE_FILE_MACHINE_I386 = 0x014C
_IMAGE_FILE_MACHINE_AMD64 = 0x8664
_IMAGE_FILE_MACHINE_ARM = 0x01C0
_IMAGE_FILE_MACHINE_ARM64 = 0xAA64
_IMAGE_FILE_MACHINE_ARMNT = 0x01C4

_PE_MACHINE_MAP = {
    0x014C: "I386", 0x8664: "AMD64", 0x01C0: "ARM",
    0xAA64: "ARM64", 0x01C4: "ARMNT", 0x0200: "IA64",
    0x01A2: "MIPS16", 0x01A4: "MIPSFPU", 0x01A6: "MIPSFPU16",
    0x01F0: "POWERPC", 0x01F1: "POWERPCFP",
    0x0284: "ALPHA", 0x0290: "ALPHA64",
    0x01D3: "M68K", 0x0268: "M32R",
    0x9041: "RISCV32", 0x5064: "RISCV64", 0x5128: "RISCV128",
    0x01C2: "THUMB", 0x0EB1: "EBC",
}

_IMAGE_SUBSYSTEM_MAP = {
    0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI",
    5: "OS2_CUI", 7: "POSIX_CUI", 9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM",
    14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION",
}

# PE 节区属性位掩码
_SECTION_CHAR_MAP = {
    0x00000020: "CNT_CODE", 0x00000040: "CNT_INITIALIZED_DATA",
    0x00000080: "CNT_UNINITIALIZED_DATA", 0x02000000: "MEM_DISCARDABLE",
    0x04000000: "MEM_NOT_CACHED", 0x08000000: "MEM_NOT_PAGED",
    0x10000000: "MEM_SHARED", 0x20000000: "MEM_EXECUTE",
    0x40000000: "MEM_READ", 0x80000000: "MEM_WRITE",
}

# ELF 常量表
_ELF_MAGIC = b'\x7fELF'
_ELF_CLASS_32 = 1
_ELF_CLASS_64 = 2
_ELF_DATA_LSB = 1
_ELF_DATA_MSB = 2

_ELF_MACHINE_MAP = {
    0: "EM_NONE", 3: "EM_386", 8: "EM_MIPS", 20: "EM_PPC",
    21: "EM_PPC64", 40: "EM_ARM", 43: "EM_SPARCV9",
    50: "EM_IA_64", 62: "EM_X86_64", 83: "EM_AVR",
    92: "EM_OPENRISC", 183: "EM_AARCH64", 243: "EM_RISCV",
    247: "EM_BPF", 0x9026: "EM_ALPHA",
}

_ELF_SHT_STRTAB = 3
_ELF_SHT_SYMTAB = 2
_ELF_SHT_DYNSYM = 11
_ELF_SHT_DYNAMIC = 6
_ELF_SHT_NOTE = 7
_ELF_SHT_RELA = 4
_ELF_SHT_HASH = 5

_PT_LOAD = 1
_PT_DYNAMIC = 2
_PT_INTERP = 3
_PT_NOTE = 4
_PT_GNU_RELRO = 0x6474E552
_PT_GNU_STACK = 0x6474E551

# Mach-O 常量表
_MACHO_MAGIC_32 = 0xFEEDFACE
_MACHO_MAGIC_64 = 0xFEEDFACF
_MACHO_CIGAM_32 = 0xCEFAEDFE
_MACHO_CIGAM_64 = 0xCFFAEDFE

_MACHO_CPUTYPE = {
    7: "I386", 12: "ARM", 0x01000007: "X86_64",
    0x0100000C: "ARM64", 18: "PPC", 0x01000012: "PPC64",
    2: "M68K", 0x0000000A: "MC98000",
}
_MACHO_FILETYPE = {
    1: "OBJECT", 2: "EXECUTE", 3: "FVMLIB", 4: "CORE",
    5: "PRELOAD", 6: "DYLIB", 7: "DYLINKER", 8: "BUNDLE",
    9: "DYLIB_STUB", 10: "DSYM", 11: "KEXT_BUNDLE",
}


def detect_format(data: bytes) -> str:
    """魔数检测：MZ→PE, \\x7fELF→ELF, FEEDFACx→MACHO，其余 UNKNOWN。"""
    if len(data) < 4:
        return "UNKNOWN"
    if data[0:2] == b'MZ':
        return "PE"
    if data[0:4] == _ELF_MAGIC:
        return "ELF"
    _magic = struct.unpack_from('<I', data, 0)[0]
    if _magic in (_MACHO_MAGIC_32, _MACHO_MAGIC_64, _MACHO_CIGAM_32, _MACHO_CIGAM_64):
        return "MACHO"
    return "UNKNOWN"


def _pe_machine_to_arch(machine: int) -> str:
    return _PE_MACHINE_MAP.get(machine, f"UNKNOWN_{machine:#06x}")


def _elf_machine_to_arch(machine: int) -> str:
    return _ELF_MACHINE_MAP.get(machine, f"EM_UNKNOWN_{machine}")


def _decode_section_flags(characteristics: int) -> list:
    _flags = []
    for _mask, _name in _SECTION_CHAR_MAP.items():
        if characteristics & _mask:
            _flags.append(_name)
    return _flags


def parse_pe(data: bytes) -> dict:
    """解析 PE 头：架构、区段、导入/导出表、入口点。省略资源表与重定位表。"""
    _info: dict = {"format": "PE", "sections": [], "imports": {}, "exports": []}
    if len(data) < 64:
        return _info

    _e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if len(data) <= _e_lfanew + 4:
        return _info

    _nt_sig = struct.unpack_from('<I', data, _e_lfanew)[0]
    if _nt_sig != _IMAGE_NT_SIGNATURE:
        return _info

    _file_header_offset = _e_lfanew + 4
    if len(data) < _file_header_offset + 20:
        return _info

    _machine, _num_sections, _timestamp, _ = struct.unpack_from(
        '<HHII', data, _file_header_offset
    )
    _info["machine"] = _pe_machine_to_arch(_machine)
    _info["timestamp"] = _timestamp
    _info["timestamp_utc"] = datetime.utcfromtimestamp(_timestamp).isoformat() if _timestamp else "N/A"

    _opt_header_offset = _file_header_offset + 20
    if len(data) < _opt_header_offset + 2:
        return _info

    _opt_magic = struct.unpack_from('<H', data, _opt_header_offset)[0]
    _is_pe64 = (_opt_magic == 0x020B)
    _opt_size = struct.unpack_from('<H', data, _file_header_offset + 16)[0]

    if _is_pe64:
        _fmt = '<HQIIIIIHHHHHHHHHI'
        _opt_fields = struct.unpack_from(_fmt, data, _opt_header_offset)
        _info["image_base"] = _opt_fields[1]
        _info["entry_point"] = _opt_fields[4]
        _info["subsystem"] = _IMAGE_SUBSYSTEM_MAP.get(_opt_fields[13], f"UNKNOWN_{_opt_fields[13]}")
        _info["image_size"] = _opt_fields[15]
        _data_dir_start = _opt_header_offset + 112
    else:
        _fmt = '<IIIIIIHHHHHHHHHHI'
        _opt_fields = struct.unpack_from(_fmt, data, _opt_header_offset)
        _info["image_base"] = _opt_fields[2]
        _info["entry_point"] = _opt_fields[4]
        _info["subsystem"] = _IMAGE_SUBSYSTEM_MAP.get(_opt_fields[13], f"UNKNOWN_{_opt_fields[13]}")
        _info["image_size"] = _opt_fields[14]
        _data_dir_start = _opt_header_offset + 96

    _export_rva, _export_size = struct.unpack_from('<II', data, _data_dir_start)
    _import_rva, _import_size = struct.unpack_from('<II', data, _data_dir_start + 8)

    _section_offset = _file_header_offset + 20 + _opt_size
    _section_size = 40
    for _i in range(min(_num_sections, 96)):
        _so = _section_offset + _i * _section_size
        if len(data) < _so + 40:
            break
        _raw_name = data[_so:_so + 8]
        _name = _raw_name.rstrip(b'\x00').decode('ascii', errors='replace')
        _va, _raw_size, _raw_ptr, _, _, _, _chars = struct.unpack_from(
            '<IIIIIIHHI', data, _so + 12
        )
        _info["sections"].append({
            "name": _name, "va": _va, "raw_size": _raw_size,
            "raw_ptr": _raw_ptr, "characteristics": _decode_section_flags(_chars),
        })

    _info["imports"] = _parse_pe_imports(data, _import_rva, _import_size)

    if _export_rva and _export_size:
        _info["exports"] = _parse_pe_exports(data, _export_rva, _export_size)

    return _info


def _rva_to_offset(data: bytes, rva: int, sections: list = None) -> Optional[int]:
    """RVA→文件偏移。小型 PE 通常区段对齐等于文件对齐，直接当偏移用。"""
    return rva if rva < len(data) else None


def _parse_pe_imports(data: bytes, import_rva: int, import_size: int) -> dict:
    _imports = {}
    if import_rva == 0 or import_size == 0 or import_rva >= len(data):
        return _imports
    _offset = import_rva
    _descriptor_size = 20
    for _i in range(256):
        if _offset + _descriptor_size > len(data):
            break
        _fields = struct.unpack_from('<IIIII', data, _offset)
        _name_rva = _fields[3]
        if _name_rva == 0:
            break
        if _name_rva >= len(data):
            _offset += _descriptor_size
            continue
        _dll_end = data.find(b'\x00', _name_rva)
        _dll_name = data[_name_rva:_dll_end].decode('ascii', errors='replace')
        _funcs = []
        _thunk_rva = _fields[0] if _fields[0] else _fields[4]
        if _thunk_rva and _thunk_rva < len(data):
            _thunk_off = _thunk_rva
            for _j in range(2048):
                if _thunk_off + 8 > len(data):
                    break
                _hint_name_rva = struct.unpack_from('<Q' if False else '<I', data, _thunk_off)[0] if False else struct.unpack_from('<I', data, _thunk_off)[0]
                _hint_name_rva = struct.unpack_from('<I', data, _thunk_off)[0]
                if _hint_name_rva == 0:
                    break
                if _hint_name_rva & 0x80000000:
                    _funcs.append(f"ordinal_{_hint_name_rva & 0xFFFF}")
                elif _hint_name_rva < len(data):
                    _fn_end = data.find(b'\x00', _hint_name_rva + 2)
                    _fn = data[_hint_name_rva + 2:_fn_end].decode('ascii', errors='replace')
                    _funcs.append(_fn)
                _thunk_off += 4
        _imports[_dll_name] = _funcs
        _offset += _descriptor_size
    return _imports


def _parse_pe_exports(data: bytes, export_rva: int, export_size: int) -> list:
    _exports = []
    if export_rva >= len(data) or export_size == 0:
        return _exports
    _off = export_rva
    _, _, _, _name_rva, _base, _num_funcs, _num_names = struct.unpack_from('<IIIIIII', data, _off)
    if _name_rva and _name_rva < len(data):
        _dll_end = data.find(b'\x00', _name_rva)
        _exports.append(f"module:{data[_name_rva:_dll_end].decode('ascii', errors='replace')}")
    _names_rva = struct.unpack_from('<I', data, _off + 32)[0]
    _funcs_rva = struct.unpack_from('<I', data, _off + 28)[0]
    for _i in range(min(_num_names, 512)):
        if _names_rva + _i * 4 + 4 > len(data):
            break
        _name_ptr = struct.unpack_from('<I', data, _names_rva + _i * 4)[0]
        if _name_ptr and _name_ptr < len(data):
            _end = data.find(b'\x00', _name_ptr)
            _exports.append(data[_name_ptr:_end].decode('ascii', errors='replace'))
    return _exports


def parse_elf(data: bytes) -> dict:
    """解析 ELF 头：class、字节序、架构、节/段/符号表。"""
    _info: dict = {"format": "ELF", "sections": [], "imports": {}, "exports": []}
    if len(data) < 52 or data[0:4] != _ELF_MAGIC:
        return _info
    _ei_class = data[4]
    _ei_data = data[5]
    _is_64 = (_ei_class == _ELF_CLASS_64)
    _is_le = (_ei_data == _ELF_DATA_LSB)
    _endian = '<' if _is_le else '>'
    _info["class"] = "ELF64" if _is_64 else "ELF32"
    _info["endian"] = "little" if _is_le else "big"

    if _is_64:
        _hdr = struct.unpack_from(f'{_endian}HHIQQQIHHHHHH', data, 16)
        _info["machine"] = _elf_machine_to_arch(_hdr[1])
        _info["entry"] = _hdr[4]
        _phoff, _shoff, _flags, _ehsize = _hdr[5], _hdr[6], _hdr[7], _hdr[8]
        _phentsize, _phnum, _shentsize, _shnum, _shstrndx = _hdr[9], _hdr[10], _hdr[11], _hdr[12], _hdr[13]
    else:
        _hdr = struct.unpack_from(f'{_endian}HHIIIIIHHHHHH', data, 16)
        _info["machine"] = _elf_machine_to_arch(_hdr[1])
        _info["entry"] = _hdr[4]
        _phoff, _shoff, _flags, _ehsize = _hdr[5], _hdr[6], _hdr[7], _hdr[8]
        _phentsize, _phnum, _shentsize, _shnum, _shstrndx = _hdr[9], _hdr[10], _hdr[11], _hdr[12], _hdr[13]

    _info["program_headers"] = []
    for _i in range(min(_phnum, 256)):
        _po = _phoff + _i * _phentsize
        if _po + _phentsize > len(data):
            break
        if _is_64:
            _p_type, _p_flags, _p_offset, _p_vaddr, _, _p_filesz = struct.unpack_from(
                f'{_endian}IIQQQQ', data, _po
            )
        else:
            _p_type, _p_offset, _p_vaddr, _, _p_filesz, _, _p_flags, _ = struct.unpack_from(
                f'{_endian}IIIIIIII', data, _po
            )
        _info["program_headers"].append({
            "type": _p_type, "vaddr": _p_vaddr, "filesz": _p_filesz,
            "flags": _p_flags,
        })

    _info["sections"] = []
    if _shstrndx > 0 and _shoff > 0:
        for _i in range(min(_shnum, 1024)):
            _so = _shoff + _i * _shentsize
            if _so + _shentsize > len(data):
                break
            if _is_64:
                _s_name_idx, _s_type, _s_flags, _s_addr, _s_offset, _s_size = struct.unpack_from(
                    f'{_endian}IIQQQQ', data, _so
                )
            else:
                _s_name_idx, _s_type, _s_flags, _s_addr, _s_offset, _s_size, _, _, _, _ = struct.unpack_from(
                    f'{_endian}IIIIIIIIII', data, _so
                )
            _info["sections"].append({
                "name_idx": _s_name_idx, "type": _s_type,
                "addr": _s_addr, "offset": _s_offset, "size": _s_size,
                "flags": _s_flags,
            })

        _shstr_section = _info["sections"][_shstrndx] if _shstrndx < len(_info["sections"]) else None
        if _shstr_section:
            _strtab_off = _shstr_section["offset"]
            for _sec in _info["sections"]:
                _nm_off = _strtab_off + _sec["name_idx"]
                if _nm_off < len(data):
                    _end = data.find(b'\x00', _nm_off)
                    _sec["name"] = data[_nm_off:_end].decode('ascii', errors='replace')

    _symtab_off = None
    _symtab_size = 0
    _strtab_off = None
    for _sec in _info["sections"]:
        if _sec.get("type") == _ELF_SHT_SYMTAB or _sec.get("type") == _ELF_SHT_DYNSYM:
            _symtab_off = _sec["offset"]
            _symtab_size = _sec["size"]
    for _sec in _info["sections"]:
        if _sec.get("type") == _ELF_SHT_STRTAB and _sec["offset"] != _shstr_section["offset"]:
            _strtab_off = _sec["offset"]
            break

    if _symtab_off and _strtab_off:
        _entsize = 24 if _is_64 else 16
        _num_ents = _symtab_size // _entsize if _symtab_size > 0 else 0
        for _i in range(min(_num_ents, 2048)):
            _eo = _symtab_off + _i * _entsize
            if _eo + _entsize > len(data):
                break
            if _is_64:
                _st_name, _st_info = struct.unpack_from(f'{_endian}IB', data, _eo)
                _st_offset = struct.unpack_from(f'{_endian}I', data, _eo)[0]
                _st_info = data[_eo + 4]
            else:
                _st_offset = struct.unpack_from(f'{_endian}I', data, _eo)[0]
                _st_info = data[_eo + 12]
            if _st_offset and _strtab_off + _st_offset < len(data):
                _end = data.find(b'\x00', _strtab_off + _st_offset)
                _sym_name = data[_strtab_off + _st_offset:_end].decode('ascii', errors='replace')
                if _sym_name:
                    if data[_eo + (_entsize - 2)] & 0x0F == 0:
                        pass
                    else:
                        _info.setdefault("exports", []).append(_sym_name)

    return _info


def parse_macho(data: bytes) -> dict:
    _info: dict = {"format": "MACHO", "sections": [], "imports": {}}
    if len(data) < 28:
        return _info
    _magic = struct.unpack_from('<I', data, 0)[0]
    _is_64 = _magic in (_MACHO_MAGIC_64, _MACHO_CIGAM_64)
    _is_swap = _magic in (_MACHO_CIGAM_32, _MACHO_CIGAM_64)
    _e = '>' if _is_swap else '<'

    _cputype, _cpusubtype, _filetype, _ncmds, _sizeofcmds = struct.unpack_from(
        f'{_e}IIIII', data, 4
    )
    _info["cputype"] = _MACHO_CPUTYPE.get(_cputype, f"CPU_{_cputype:#x}")
    _info["filetype"] = _MACHO_FILETYPE.get(_filetype, f"TYPE_{_filetype}")
    _info["ncmds"] = _ncmds

    _cmd_offset = 32 if _is_64 else 28
    _dylibs = []
    for _c in range(min(_ncmds, 256)):
        if _cmd_offset + 8 > len(data):
            break
        _cmd, _cmdsize = struct.unpack_from(f'{_e}II', data, _cmd_offset)
        if _cmdsize < 8:
            break

        if _cmd == 0x19:
            _segname = data[_cmd_offset + 8:_cmd_offset + 24].rstrip(b'\x00').decode('ascii', errors='replace')
            _vmaddr, _vmsize, _fileoff, _filesize = struct.unpack_from(
                f'{_e}QQQQ', data, _cmd_offset + 24
            )
            _nsects = struct.unpack_from(f'{_e}I', data, _cmd_offset + 64)[0]
            _info["sections"].append({
                "segment": _segname, "vmaddr": _vmaddr, "vmsize": _vmsize,
                "fileoff": _fileoff, "filesize": _filesize,
            })
            _sect_off = _cmd_offset + 72
            for _s in range(min(_nsects, 128)):
                if _sect_off + 80 > len(data):
                    break
                _sname = data[_sect_off:_sect_off + 16].rstrip(b'\x00').decode('ascii', errors='replace')
                _addr, _size, _off_s = struct.unpack_from(f'{_e}QQI', data, _sect_off + 32)
                _info["sections"].append({
                    "segment": _segname, "section": _sname,
                    "addr": _addr, "size": _size, "offset": _off_s,
                })
                _sect_off += 80

        elif _cmd == 0x01:
            _segname = data[_cmd_offset + 8:_cmd_offset + 24].rstrip(b'\x00').decode('ascii', errors='replace')
            _vmaddr, _vmsize, _fileoff, _filesize = struct.unpack_from(
                f'{_e}IIII', data, _cmd_offset + 24
            )
            _nsects = struct.unpack_from(f'{_e}I', data, _cmd_offset + 48)[0]
            _info["sections"].append({
                "segment": _segname, "vmaddr": _vmaddr, "vmsize": _vmsize,
                "fileoff": _fileoff, "filesize": _filesize,
            })

        elif _cmd == 0x0C or _cmd == 0x8000000C:
            _name_off = _cmd_offset + struct.calcsize(f'{_e}III')
            _dylib_end = data.find(b'\x00', _name_off)
            _dylib_name = data[_name_off:_dylib_end].decode('ascii', errors='replace')
            _dylibs.append(_dylib_name)

        elif _cmd == 0x05:
            _info["entry_point"] = "via_thread_command"

        _cmd_offset += _cmdsize

    if _dylibs:
        _info["dylibs"] = _dylibs
    return _info


def get_binary_info(filepath: str) -> dict:
    """读取文件，识别格式并解析，返回统一二进制信息字典。
    对外唯一入口。返回结构：
    { "file", "sha256", "format", "size", "machine", "entry_point",
      "sections", "imports", "exports" }
    """
    _r: dict = {"file": filepath, "format": "UNKNOWN"}
    if not os.path.isfile(filepath):
        _r["error"] = "file_not_found"
        return _r
    _r["size"] = os.path.getsize(filepath)
    with open(filepath, 'rb') as _fh:
        _data = _fh.read()
    _r["sha256"] = hashlib.sha256(_data).hexdigest()
    _fmt = detect_format(_data)
    _r["format"] = _fmt

    _parsed = {}
    if _fmt == "PE":
        _parsed = parse_pe(_data)
    elif _fmt == "ELF":
        _parsed = parse_elf(_data)
    elif _fmt == "MACHO":
        _parsed = parse_macho(_data)

    _r.update({k: v for k, v in _parsed.items() if k != "format"})
    _r.setdefault("machine", "UNKNOWN")
    _r.setdefault("sections", [])
    _r.setdefault("imports", {})
    _r.setdefault("exports", [])
    return _r
