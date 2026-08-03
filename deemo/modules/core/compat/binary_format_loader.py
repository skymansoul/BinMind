# 零拷贝快速判别 + 深度头解析 + LIEF 可选回退

import struct, os, hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
from enum import Enum, auto


# ===== 枚举 =====
class BinaryFormat(Enum):
    ELF = "elf"
    PE = "pe"
    MACH_O = "mach_o"
    RAW = "raw"
    UNIVERSAL = "universal"
    UNKNOWN = "unknown"


class Arch(Enum):
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    MIPS64 = "mips64"
    PPC = "ppc"
    PPC64 = "ppc64"
    IA64 = "ia64"
    UNKNOWN = "unknown"


# ===== 数据结构 =====
@dataclass
class ImportEntry:
    dll_name: str = ""
    function_name: str = ""
    ordinal: int = 0
    hint: int = 0


@dataclass
class ExportEntry:
    name: str = ""
    ordinal: int = 0
    address: int = 0
    forwarder: str = ""


@dataclass
class SectionInfo:
    name: str = ""
    virtual_address: int = 0
    virtual_size: int = 0
    raw_offset: int = 0
    raw_size: int = 0
    characteristics: int = 0
    entropy: float = 0.0


@dataclass
class PESection(SectionInfo):
    pass


@dataclass
class ELFSection(SectionInfo):
    section_type: int = 0
    flags: int = 0
    link: int = 0
    info: int = 0
    addr_align: int = 0
    entry_size: int = 0


@dataclass
class SegmentInfo:
    segment_type: int = 0
    offset: int = 0
    vaddr: int = 0
    paddr: int = 0
    filesz: int = 0
    memsz: int = 0
    flags: int = 0
    align: int = 0


@dataclass
class SymbolEntry:
    name: str = ""
    value: int = 0
    size: int = 0
    symbol_type: str = ""
    binding: str = ""


@dataclass
class PEParsedInfo:
    machine: int = 0
    num_sections: int = 0
    timestamp: int = 0
    entry_point: int = 0
    image_base: int = 0
    is_64bit: bool = False
    sections: List[PESection] = field(default_factory=list)
    imports: List[ImportEntry] = field(default_factory=list)
    exports: List[ExportEntry] = field(default_factory=list)
    dll_characteristics: int = 0


@dataclass
class ELFParsedInfo:
    elf_type: int = 0
    machine: int = 0
    version: int = 0
    entry: int = 0
    phoff: int = 0
    shoff: int = 0
    flags: int = 0
    is_64bit: bool = False
    sections: List[ELFSection] = field(default_factory=list)
    segments: List[SegmentInfo] = field(default_factory=list)
    symbols: List[SymbolEntry] = field(default_factory=list)
    dyn_symbols: List[SymbolEntry] = field(default_factory=list)


@dataclass
class MachOParsedInfo:
    cputype: int = 0
    cpusubtype: int = 0
    filetype: int = 0
    is_fat: bool = False
    arch_slices: List[Dict[str, int]] = field(default_factory=list)
    segments: List[Dict[str, Any]] = field(default_factory=list)
    symbols: List[SymbolEntry] = field(default_factory=list)
    entry_point: int = 0


@dataclass
class ParsedBinary:
    format: BinaryFormat = BinaryFormat.UNKNOWN
    arch: Arch = Arch.UNKNOWN
    bits: int = 64
    filepath: str = ""
    pe_info: Optional[PEParsedInfo] = None
    elf_info: Optional[ELFParsedInfo] = None
    macho_info: Optional[MachOParsedInfo] = None
    sections: List[SectionInfo] = field(default_factory=list)
    imports: List[ImportEntry] = field(default_factory=list)
    exports: List[ExportEntry] = field(default_factory=list)


# ---- Magic 签名表 ----
_MAGIC_DB = {
    b'\x7fELF': ('ELF', None),
    b'MZ': ('PE', None),
    b'\xfe\xed\xfa\xce': ('MACH-O', '32-bit'),
    b'\xfe\xed\xfa\xcf': ('MACH-O', '64-bit'),
    b'\xce\xfa\xed\xfe': ('MACH-O', '32-bit-le'),
    b'\xcf\xfa\xed\xfe': ('MACH-O', '64-bit-le'),
    b'\xca\xfe\xba\xbe': ('UNIVERSAL', 'fat'),
    b'\xbe\xba\xfe\xca': ('UNIVERSAL', 'fat-le'),
}

# PE machine → Arch
_PE_ARCH_MAP = {
    0x014c: (Arch.X86, 32), 0x8664: (Arch.X64, 64), 0x0200: (Arch.IA64, 64),
    0x01c4: (Arch.ARM, 32), 0xaa64: (Arch.ARM64, 64), 0x01f0: (Arch.PPC, 32),
    0x0166: (Arch.MIPS, 32), 0x01c2: (Arch.MIPS, 32),
}

# ELF machine → Arch
_ELF_ARCH_MAP = {
    0x03: (Arch.X86, 32), 0x3e: (Arch.X64, 64), 0x28: (Arch.ARM, 32),
    0xb7: (Arch.ARM64, 64), 0x32: (Arch.IA64, 64), 0x14: (Arch.PPC, 32),
    0x15: (Arch.PPC64, 64), 0x08: (Arch.MIPS, 32), 0x3b: (Arch.MIPS64, 64),
    0x2a: (Arch.MIPS, 32),  # SuperH — mapped to MIPS for compat
}

_format_cache: Dict[str, dict] = {}


# //// 快速格式检测 ////
def _quick_sniff(path: str) -> dict | None:
    if path in _format_cache:
        return _format_cache[path]
    if not path or not os.path.isfile(path):
        return None
    try:
        sz = os.path.getsize(path)
        if sz < 64:
            return None
        with open(path, 'rb') as fh:
            head = fh.read(64)
    except OSError:
        return None

    fmt_name = 'unknown'; arch = 'unknown'; bits = 32
    for magic, (name, variant) in _MAGIC_DB.items():
        if head.startswith(magic):
            fmt_name = name
            break

    if fmt_name == 'PE' and len(head) >= 64:
        pe_offset = struct.unpack_from('<I', head, 0x3c)[0]
        if pe_offset + 4 <= len(head):
            machine = struct.unpack_from('<H', head, pe_offset + 4)[0]
            arch_info = _PE_ARCH_MAP.get(machine)
            if arch_info:
                arch, bits = arch_info[0].value, arch_info[1]
    elif fmt_name == 'ELF':
        ei_class = head[4]
        bits = 64 if ei_class == 2 else 32
        machine = struct.unpack_from('<H', head, 18)[0]
        arch_info = _ELF_ARCH_MAP.get(machine)
        if arch_info:
            arch = arch_info[0].value

    result = {'format': fmt_name, 'arch': arch, 'bits': bits}
    _format_cache[path] = result
    return result


def detect_format_from_magic(filepath: str) -> BinaryFormat:
    """读取前 64 字节匹配 magic 签名"""
    if not filepath or not os.path.isfile(filepath):
        return BinaryFormat.UNKNOWN
    try:
        with open(filepath, 'rb') as fh:
            head = fh.read(64)
    except OSError:
        return BinaryFormat.UNKNOWN

    # Mach-O fat binary 优先检测
    if head[:4] in (b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
        return BinaryFormat.UNIVERSAL
    if head[:4] == b'\x7fELF':
        return BinaryFormat.ELF
    if head[:2] == b'MZ':
        pe_offset = struct.unpack_from('<I', head, 0x3c)[0]
        if pe_offset + 4 <= len(head) and head[pe_offset:pe_offset + 4] == b'PE\x00\x00':
            return BinaryFormat.PE
    if head[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                     b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
        return BinaryFormat.MACH_O
    return BinaryFormat.RAW


# ===== PE 解析器 =====
class PEParser:
    def parse(self, filepath: str) -> PEParsedInfo:
        info = PEParsedInfo()
        if not filepath or not os.path.isfile(filepath):
            return info
        try:
            with open(filepath, 'rb') as fh:
                data = fh.read()
        except OSError:
            return info
        if len(data) < 128 or data[:2] != b'MZ':
            return info

        pe_offset = struct.unpack_from('<I', data, 0x3c)[0]
        if pe_offset + 4 > len(data) or data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
            return info

        coff_start = pe_offset + 4
        info.machine = struct.unpack_from('<H', data, coff_start)[0]
        info.num_sections = struct.unpack_from('<H', data, coff_start + 2)[0]
        info.timestamp = struct.unpack_from('<I', data, coff_start + 4)[0]

        opt_header_start = coff_start + 20
        opt_magic = struct.unpack_from('<H', data, opt_header_start)[0]
        info.is_64bit = (opt_magic == 0x20b)

        if info.is_64bit:
            info.entry_point = struct.unpack_from('<I', data, opt_header_start + 16)[0]
            info.image_base = struct.unpack_from('<Q', data, opt_header_start + 24)[0]
            info.dll_characteristics = struct.unpack_from('<H', data, opt_header_start + 70)[0]
            section_start = opt_header_start + 112 + struct.unpack_from('<I', data, opt_header_start + 108)[0]
        else:
            info.entry_point = struct.unpack_from('<I', data, opt_header_start + 16)[0]
            info.image_base = struct.unpack_from('<I', data, opt_header_start + 28)[0]
            info.dll_characteristics = struct.unpack_from('<H', data, opt_header_start + 68)[0]
            section_start = opt_header_start + 96 + struct.unpack_from('<I', data, opt_header_start + 92)[0]

        info.sections = self._parse_sections(data, section_start, info.num_sections)
        info.imports = self._parse_imports(data, info.sections)
        info.exports = self._parse_exports(data, info.sections)
        return info

    # ----
    def _parse_sections(self, data: bytes, start: int, count: int) -> List[PESection]:
        sections: List[PESection] = []
        for i in range(count):
            off = start + i * 40
            if off + 40 > len(data):
                break
            name_raw = data[off:off + 8].rstrip(b'\x00')
            name = name_raw.decode('ascii', errors='replace').strip('\x00')
            vsize = struct.unpack_from('<I', data, off + 8)[0]
            vaddr = struct.unpack_from('<I', data, off + 12)[0]
            rsize = struct.unpack_from('<I', data, off + 16)[0]
            roff = struct.unpack_from('<I', data, off + 20)[0]
            chars = struct.unpack_from('<I', data, off + 36)[0]

            # 熵计算 (简易)
            if rsize > 0 and roff > 0 and roff + rsize <= len(data):
                section_data = data[roff:roff + min(rsize, 65536)]
                entropy = self._calc_entropy(section_data)
            else:
                entropy = 0.0

            sections.append(PESection(
                name=name, virtual_address=vaddr, virtual_size=vsize,
                raw_offset=roff, raw_size=rsize, characteristics=chars,
                entropy=round(entropy, 2),
            ))
        return sections

    # ----
    def _parse_imports(self, data: bytes, sections: List[PESection]) -> List[ImportEntry]:
        imports: List[ImportEntry] = []
        # 在 .idata / .rdata 段中查找导入表
        for sec in sections:
            if sec.raw_size == 0 or sec.raw_offset == 0:
                continue
            if sec.raw_offset + sec.raw_size > len(data):
                continue
            sec_data = data[sec.raw_offset:sec.raw_offset + sec.raw_size]
            # 扫描 DLL 名称模式 (ASCII 字符串后跟 IAT 结构)
            i = 0
            while i < len(sec_data) - 12:
                # heuristic: 查找以 .dll 结尾的字符串
                if sec_data[i:i + 4] == b'.dll':
                    end = i
                    while end > 0 and sec_data[end - 1] > 32:
                        end -= 1
                    dll_name = sec_data[end:i + 4].decode('ascii', errors='replace')
                    if len(dll_name) > 3 and len(dll_name) < 50:
                        imports.append(ImportEntry(dll_name=dll_name))
                    i += 4
                else:
                    i += 1
        return imports

    # ----
    def _parse_exports(self, data: bytes, sections: List[PESection]) -> List[ExportEntry]:
        exports: List[ExportEntry] = []
        for sec in sections:
            if sec.raw_size == 0 or sec.name not in ('.edata', '.rdata', 'EXPORT'):
                continue
            if sec.raw_offset + sec.raw_size > len(data):
                continue
            sec_data = data[sec.raw_offset:sec.raw_offset + min(sec.raw_size, 65536)]
            # 扫描 ASCII 函数名 (常见导出命名模式)
            i = 0
            while i < len(sec_data) - 4:
                if sec_data[i] > 32 and sec_data[i] < 127:
                    end = i
                    while end < len(sec_data) and sec_data[end] > 32 and sec_data[end] < 127:
                        end += 1
                    if end - i > 3 and end - i < 120:
                        name = sec_data[i:end].decode('ascii', errors='replace')
                        if name not in [e.name for e in exports[-50:]]:
                            exports.append(ExportEntry(name=name))
                    i = end
                else:
                    i += 1
        return exports

    @staticmethod
    def _calc_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        ent = 0.0
        length = len(data)
        for f in freq:
            if f > 0:
                p = f / length
                ent -= p * __import__('math').log2(p)
        return ent

    @staticmethod
    def get_arch(machine: int) -> Tuple[Arch, int]:
        result = _PE_ARCH_MAP.get(machine)
        return result if result else (Arch.UNKNOWN, 32)


# ===== ELF 解析器 =====
class ELFParser:
    def parse(self, filepath: str) -> ELFParsedInfo:
        info = ELFParsedInfo()
        if not filepath or not os.path.isfile(filepath):
            return info
        try:
            with open(filepath, 'rb') as fh:
                data = fh.read()
        except OSError:
            return info
        if len(data) < 64 or data[:4] != b'\x7fELF':
            return info

        is_64bit = (data[4] == 2)
        info.is_64bit = is_64bit
        is_le = (data[5] == 1)
        endian = '<' if is_le else '>'
        word = 'Q' if is_64bit else 'I'
        half = 'H'

        info.elf_type = struct.unpack_from(endian + half, data, 16)[0]
        info.machine = struct.unpack_from(endian + half, data, 18)[0]
        info.version = struct.unpack_from(endian + 'I', data, 20)[0]
        info.entry = struct.unpack_from(endian + word, data, 24)[0]
        info.phoff = struct.unpack_from(endian + word, data, 32 if is_64bit else 28)[0]
        info.shoff = struct.unpack_from(endian + word, data, 40 if is_64bit else 32)[0]
        info.flags = struct.unpack_from(endian + 'I', data, 48 if is_64bit else 36)[0]

        sh_entsize_off = 58 if is_64bit else 46
        sh_num_off = 60 if is_64bit else 48
        sh_strndx_off = 62 if is_64bit else 50

        e_shentsize = struct.unpack_from(endian + half, data, sh_entsize_off)[0]
        e_shnum = struct.unpack_from(endian + half, data, sh_num_off)[0]
        e_shstrndx = struct.unpack_from(endian + half, data, sh_strndx_off)[0]

        info.sections = self._parse_sections(data, info.shoff, e_shnum, e_shentsize,
                                              e_shstrndx, endian, is_64bit)
        info.segments = self._parse_segments(data, info.phoff,
                                              struct.unpack_from(endian + half, data, 56 if is_64bit else 44)[0],
                                              struct.unpack_from(endian + half, data, 58 if is_64bit else 42)[0],
                                              endian, is_64bit)
        info.symbols = self._parse_symbols(data, info.sections, endian, is_64bit, '.symtab')
        info.dyn_symbols = self._parse_symbols(data, info.sections, endian, is_64bit, '.dynsym')
        return info

    # ----
    def _parse_sections(self, data, shoff, shnum, shentsize, shstrndx, endian, is_64bit):
        sections: List[ELFSection] = []
        if shnum == 0 or shentsize == 0:
            return sections
        word = 'Q' if is_64bit else 'I'

        # 读取 section name string table
        shstrtab_off = 0; shstrtab_size = 0
        strndx_offset = shoff + shstrndx * shentsize
        if strndx_offset + shentsize <= len(data):
            shstrtab_off = struct.unpack_from(endian + word, data, strndx_offset + 24)[0]
            shstrtab_size = struct.unpack_from(endian + word, data, strndx_offset + 32)[0]

        for i in range(shnum):
            off = shoff + i * shentsize
            if off + shentsize > len(data):
                break
            name_idx = struct.unpack_from(endian + 'I', data, off)[0]
            s_type = struct.unpack_from(endian + 'I', data, off + 4)[0]
            s_flags = struct.unpack_from(endian + word, data, off + 8)[0]
            s_addr = struct.unpack_from(endian + word, data, off + 16)[0]
            s_offset = struct.unpack_from(endian + word, data, off + 24)[0]
            s_size = struct.unpack_from(endian + word, data, off + 32)[0]
            s_link = struct.unpack_from(endian + 'I', data, off + 40)[0]
            s_info = struct.unpack_from(endian + 'I', data, off + 44)[0]
            s_align = struct.unpack_from(endian + word, data, off + 48)[0]
            s_entsize = struct.unpack_from(endian + word, data, off + 56)[0]

            name = ''
            if shstrtab_off > 0 and name_idx > 0 and shstrtab_off + name_idx < len(data):
                name_end = data.index(0, shstrtab_off + name_idx) if 0 in data[shstrtab_off + name_idx:] else len(data)
                name = data[shstrtab_off + name_idx:name_end].decode('ascii', errors='replace')

            sections.append(ELFSection(
                name=name, section_type=s_type, flags=s_flags,
                virtual_address=s_addr, virtual_size=s_size,
                raw_offset=s_offset, raw_size=s_size,
                link=s_link, info=s_info,
                addr_align=s_align, entry_size=s_entsize,
            ))
        return sections

    # ----
    def _parse_segments(self, data, phoff, phnum, phentsize, endian, is_64bit):
        segments: List[SegmentInfo] = []
        word = 'Q' if is_64bit else 'I'
        for i in range(phnum):
            off = phoff + i * phentsize
            if off + phentsize > len(data):
                break
            p_type = struct.unpack_from(endian + 'I', data, off)[0]
            # 64-bit: flags at offset 4; 32-bit: offset at 4
            if is_64bit:
                p_flags = struct.unpack_from(endian + 'I', data, off + 4)[0]
                p_offset = struct.unpack_from(endian + word, data, off + 8)[0]
                p_vaddr = struct.unpack_from(endian + word, data, off + 16)[0]
                p_paddr = struct.unpack_from(endian + word, data, off + 24)[0]
                p_filesz = struct.unpack_from(endian + word, data, off + 32)[0]
                p_memsz = struct.unpack_from(endian + word, data, off + 40)[0]
                p_align = struct.unpack_from(endian + word, data, off + 48)[0]
            else:
                p_offset = struct.unpack_from(endian + word, data, off + 4)[0]
                p_vaddr = struct.unpack_from(endian + word, data, off + 8)[0]
                p_paddr = struct.unpack_from(endian + word, data, off + 12)[0]
                p_filesz = struct.unpack_from(endian + word, data, off + 16)[0]
                p_memsz = struct.unpack_from(endian + word, data, off + 20)[0]
                p_flags = struct.unpack_from(endian + word, data, off + 24)[0]
                p_align = struct.unpack_from(endian + word, data, off + 28)[0]
            segments.append(SegmentInfo(
                segment_type=p_type, offset=p_offset, vaddr=p_vaddr,
                paddr=p_paddr, filesz=p_filesz, memsz=p_memsz,
                flags=p_flags, align=p_align,
            ))
        return segments

    # ----
    def _parse_symbols(self, data, sections, endian, is_64bit, sec_name):
        symbols: List[SymbolEntry] = []
        target_sec = None
        for s in sections:
            if s.name == sec_name:
                target_sec = s
                break
        if not target_sec or target_sec.entry_size == 0:
            return symbols

        # 查找对应的 string table
        str_sec = None
        for s in sections:
            if s.name in ('.strtab', '.dynstr'):
                str_sec = s
                break
        if not str_sec or str_sec.raw_offset == 0:
            return symbols

        sym_size = 24 if is_64bit else 16
        count = min(target_sec.raw_size // sym_size, 5000)
        for i in range(count):
            off = target_sec.raw_offset + i * sym_size
            if off + sym_size > len(data):
                break
            st_name = struct.unpack_from(endian + 'I', data, off)[0]
            st_value = struct.unpack_from(endian + 'Q' if is_64bit else 'I', data, off + 8)[0]
            st_size = struct.unpack_from(endian + 'Q' if is_64bit else 'I', data, off + 16)[0]
            st_info = struct.unpack_from('B', data, off + (4 if is_64bit else 12))[0]
            st_other = struct.unpack_from('B', data, off + (5 if is_64bit else 13))[0]

            name = ''
            if st_name > 0 and str_sec.raw_offset + st_name < len(data):
                name_end = data.index(0, str_sec.raw_offset + st_name) if 0 in data[str_sec.raw_offset + st_name:] else len(data)
                name = data[str_sec.raw_offset + st_name:name_end].decode('ascii', errors='replace')

            if name:
                sym_type_map = {0: 'NOTYPE', 1: 'OBJECT', 2: 'FUNC', 3: 'SECTION', 4: 'FILE'}
                bind_map = {0: 'LOCAL', 1: 'GLOBAL', 2: 'WEAK'}
                symbols.append(SymbolEntry(
                    name=name, value=st_value, size=st_size,
                    symbol_type=sym_type_map.get(st_info & 0xf, 'UNKNOWN'),
                    binding=bind_map.get(st_info >> 4, 'UNKNOWN'),
                ))
        return symbols


# ===== Mach-O 解析器 =====
class MachOParser:
    _MAGICS = {0xFEEDFACE: (32, True), 0xCEFAEDFE: (32, False),
               0xFEEDFACF: (64, True), 0xCFFAEDFE: (64, False)}

    def parse(self, filepath: str) -> MachOParsedInfo:
        info = MachOParsedInfo()
        if not filepath or not os.path.isfile(filepath):
            return info
        try:
            with open(filepath, 'rb') as fh:
                data = fh.read()
        except OSError:
            return info
        if len(data) < 28:
            return info

        magic = struct.unpack_from('<I', data, 0)[0]
        if magic in (0xCAFEBABE, 0xBEBAFECA):
            return self._parse_fat(data)
        if magic not in self._MAGICS:
            return info

        bits, is_be = self._MAGICS.get(magic, (32, False))
        endian = '>' if is_be else '<'
        word = 'Q' if bits == 64 else 'I'

        info.cputype = struct.unpack_from(endian + 'I', data, 4)[0]
        info.cpusubtype = struct.unpack_from(endian + 'I', data, 8)[0]
        info.filetype = struct.unpack_from(endian + 'I', data, 12)[0]
        ncmds = struct.unpack_from(endian + 'I', data, 16)[0]
        sizeofcmds = struct.unpack_from(endian + 'I', data, 20)[0]

        offset = 28 if bits == 64 else 28
        for _ in range(ncmds):
            if offset + 8 > len(data):
                break
            cmd = struct.unpack_from(endian + 'I', data, offset)[0]
            cmdsize = struct.unpack_from(endian + 'I', data, offset + 4)[0]
            if cmdsize == 0:
                break

            if cmd in (0x01, 0x19):  # LC_SEGMENT / LC_SEGMENT_64
                seg_name = data[offset + 8:offset + 24].rstrip(b'\x00').decode('ascii', errors='replace')
                if bits == 64:
                    seg_vmaddr = struct.unpack_from(endian + 'Q', data, offset + 24)[0]
                    seg_vmsize = struct.unpack_from(endian + 'Q', data, offset + 32)[0]
                    seg_fileoff = struct.unpack_from(endian + 'Q', data, offset + 40)[0]
                    seg_filesize = struct.unpack_from(endian + 'Q', data, offset + 48)[0]
                else:
                    seg_vmaddr = struct.unpack_from(endian + 'I', data, offset + 24)[0]
                    seg_vmsize = struct.unpack_from(endian + 'I', data, offset + 28)[0]
                    seg_fileoff = struct.unpack_from(endian + 'I', data, offset + 32)[0]
                    seg_filesize = struct.unpack_from(endian + 'I', data, offset + 36)[0]
                info.segments.append({
                    'name': seg_name,
                    'vmaddr': seg_vmaddr, 'vmsize': seg_vmsize,
                    'fileoff': seg_fileoff, 'filesize': seg_filesize,
                })
            elif cmd == 0x02:  # LC_SYMTAB
                symoff = struct.unpack_from(endian + 'I', data, offset + 8)[0]
                nsyms = struct.unpack_from(endian + 'I', data, offset + 12)[0]
                stroff = struct.unpack_from(endian + 'I', data, offset + 16)[0]
                strsize = struct.unpack_from(endian + 'I', data, offset + 20)[0]
                info.symbols = self._parse_macho_symbols(data, symoff, nsyms, stroff, endian, bits)
            elif cmd == 0x11:  # LC_DYSYMTAB
                pass

            offset += cmdsize

        return info

    # ----
    def _parse_fat(self, data) -> MachOParsedInfo:
        info = MachOParsedInfo(is_fat=True)
        narch = struct.unpack_from('>I', data, 4)[0]
        for i in range(min(narch, 10)):
            off = 8 + i * 20
            if off + 20 > len(data):
                break
            cpu = struct.unpack_from('>I', data, off)[0]
            subc = struct.unpack_from('>I', data, off + 4)[0]
            arch_off = struct.unpack_from('>I', data, off + 8)[0]
            arch_size = struct.unpack_from('>I', data, off + 12)[0]
            info.arch_slices.append({
                'cputype': cpu, 'cpusubtype': subc,
                'offset': arch_off, 'size': arch_size,
            })
        return info

    # ----
    def _parse_macho_symbols(self, data, symoff, nsyms, stroff, endian, bits):
        symbols: List[SymbolEntry] = []
        entry_size = 16 if bits == 32 else 16
        for i in range(min(nsyms, 5000)):
            off = symoff + i * entry_size
            if off + entry_size > len(data):
                break
            stridx = struct.unpack_from(endian + 'I', data, off)[0]
            sym_type = struct.unpack_from('B', data, off + 4)[0]
            name = ''
            if stroff + stridx < len(data) and stridx > 0:
                name_end = data.index(0, stroff + stridx) if 0 in data[stroff + stridx:] else len(data)
                name = data[stroff + stridx:name_end].decode('ascii', errors='replace')
            if name:
                symbols.append(SymbolEntry(name=name, symbol_type=str(sym_type & 0x0e)))
        return symbols


# ---- LIEF 可选回退 ----
def _try_lief_parse(filepath: str) -> Optional[ParsedBinary]:
    try:
        import lief
        binary = lief.parse(filepath)
        if binary is None:
            return None
        result = ParsedBinary(filepath=filepath)
        fmt = binary.format
        if fmt == lief.Binary.FORMATS.ELF:
            result.format = BinaryFormat.ELF
        elif fmt == lief.Binary.FORMATS.PE:
            result.format = BinaryFormat.PE
        elif fmt == lief.Binary.FORMATS.MACHO:
            result.format = BinaryFormat.MACH_O
        else:
            return None
        if result.format == BinaryFormat.ELF:
            result.bits = 64 if binary.header.identity_class == lief.ELF.ELF_CLASS.ELF64 else 32
        elif result.format == BinaryFormat.PE:
            result.bits = 64 if hasattr(binary.optional_header, 'magic') and 'PE64' in str(type(binary.optional_header)) else 32
        for s in binary.sections:
            result.sections.append(SectionInfo(name=s.name, virtual_address=s.virtual_address,
                                                virtual_size=s.virtual_size, raw_size=s.size))
        for imp in binary.imported_functions:
            result.imports.append(ImportEntry(dll_name=imp.library if hasattr(imp, 'library') else '',
                                               function_name=imp.name))
        return result
    except Exception:
        return None


# ===== 统一接口 =====
def load_binary(filepath: str) -> ParsedBinary:
    """主入口 — 统一的二进制加载接口"""
    fmt = detect_format_from_magic(filepath)
    result = ParsedBinary(filepath=filepath, format=fmt)

    if fmt == BinaryFormat.PE:
        parser = PEParser()
        pe_info = parser.parse(filepath)
        result.pe_info = pe_info
        result.imports = pe_info.imports
        result.exports = pe_info.exports
        result.sections = pe_info.sections  # type: ignore[assignment]
        if pe_info.machine in _PE_ARCH_MAP:
            result.arch, result.bits = _PE_ARCH_MAP[pe_info.machine]
    elif fmt == BinaryFormat.ELF:
        parser = ELFParser()
        elf_info = parser.parse(filepath)
        result.elf_info = elf_info
        result.sections = elf_info.sections  # type: ignore[assignment]
        if elf_info.machine in _ELF_ARCH_MAP:
            result.arch, result.bits = _ELF_ARCH_MAP[elf_info.machine]
    elif fmt == BinaryFormat.MACH_O or fmt == BinaryFormat.UNIVERSAL:
        lief_result = _try_lief_parse(filepath)
        if lief_result:
            result = lief_result
        else:
            parser = MachOParser()
            result.macho_info = parser.parse(filepath)

    return result


# 兼容旧接口 — 与 core.binary_info 互通
def detect_format(filepath: str):
    return _quick_sniff(filepath)


def get_binary_info(filepath: str) -> dict:
    sniff = _quick_sniff(filepath)
    if sniff:
        return {
            'format': sniff['format'],
            'arch': sniff['arch'],
            'bits': sniff['bits'],
            'sections': [],
            'symbols': [],
            'imports': [],
        }
    return {'format': 'unknown', 'arch': 'unknown', 'bits': 64}


def validate_binary(filepath: str) -> bool:
    return bool(filepath and os.path.isfile(filepath) and _quick_sniff(filepath) is not None)


# ---- BinaryFormatLoader 兼容 ----
class BinaryFormatLoader:
    def __init__(self, path: str = ''):
        self.path = path
        self._info = _quick_sniff(path) if path else None

    def load(self):
        if self._info:
            return dict(self._info)
        try:
            upstream = detect_format(self.path)
            if upstream:
                _format_cache[self.path] = upstream
                return dict(upstream)
        except Exception:
            pass
        return {'format': 'unknown', 'arch': 'unknown', 'bits': 64}

    def get_sections(self):
        try:
            info = get_binary_info(self.path)
            return info.get('sections', []) if isinstance(info, dict) else []
        except Exception:
            return []

    def get_symbols(self):
        try:
            info = get_binary_info(self.path)
            return info.get('symbols', []) if isinstance(info, dict) else []
        except Exception:
            return []

    def get_imports(self):
        try:
            info = get_binary_info(self.path)
            return info.get('imports', []) if isinstance(info, dict) else []
        except Exception:
            return []
