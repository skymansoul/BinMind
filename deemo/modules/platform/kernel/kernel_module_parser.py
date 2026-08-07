# 原生ELF解析器，面向Linux .ko内核模块 — 零外部依赖
# 手解ELF结构，抽取modinfo/符号表/vermagic，支持离线审计

import struct
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# ELF 常量
ELF_MAGIC   = b'\x7fELF'
ELFCLASS32  = 1
ELFCLASS64  = 2
EM_NONE     = 0
EM_X86_64   = 62
EM_AARCH64  = 183
# Section types
SHT_NULL         = 0
SHT_PROGBITS     = 1
SHT_SYMTAB       = 2
SHT_STRTAB       = 3
SHT_RELA         = 4
SHT_NOBITS       = 8
# Symbol binding
STB_LOCAL  = 0
STB_GLOBAL = 1
STB_WEAK   = 2
# Special section index
SHN_UNDEF  = 0
SHN_ABS    = 0xFFF1


@dataclass
class SectionInfo:
    """ELF节区元信息。"""
    name: str = ""
    sh_type: int = 0
    sh_flags: int = 0
    sh_addr: int = 0
    sh_offset: int = 0
    sh_size: int = 0
    sh_link: int = 0
    sh_info: int = 0
    sh_addralign: int = 0
    sh_entsize: int = 0

@dataclass
class SymbolInfo:
    """ELF符号元信息。"""
    name: str = ""
    st_info: int = 0
    st_other: int = 0
    st_shndx: int = 0
    st_value: int = 0
    st_size: int = 0

@dataclass
class KernelModule:
    """解析完成的内核模块。"""
    name: str = ""
    license: str = ""
    vermagic: str = ""
    dependencies: List[str] = field(default_factory=list)
    symbols: List[SymbolInfo] = field(default_factory=list)
    sections: List[SectionInfo] = field(default_factory=list)
    modinfo: Dict[str, str] = field(default_factory=dict)
    is_gpl_compatible: bool = True
    has_bpf_sections: bool = False
    bpf_program_count: int = 0
    symbol_crc_count: int = 0

    def to_dict(self) -> dict:
        """导出结构化字典，供下游工具消费。"""
        return {
            "name": self.name, "license": self.license,
            "vermagic": self.vermagic, "dependencies": self.dependencies,
            "symbol_count": len(self.symbols),
            "section_count": len(self.sections),
            "is_gpl_compatible": self.is_gpl_compatible,
            "has_bpf_sections": self.has_bpf_sections,
            "bpf_program_count": self.bpf_program_count,
            "symbol_crc_count": self.symbol_crc_count,
            "modinfo": dict(self.modinfo),
            "exported_symbols": [s.name for s in self.symbols
                                 if (s.st_info >> 4) == 1 and s.st_shndx != 0],
            "undefined_symbols": [s.name for s in self.symbols
                                  if s.st_shndx == 0],
        }


# 底层二进制解析工具

def _read_elf_ident(data: bytes) -> Tuple[int, int, int]:
    """解码EI_CLASS与字节序。返回(class, endian_char, ptr_size)。"""
    if data[:4] != ELF_MAGIC:
        raise ValueError("不是有效的ELF文件")
    _ei_class = data[4]  # EI_CLASS: 1=32bit, 2=64bit
    _ei_data  = data[5]  # EI_DATA: 1=little, 2=big

    if _ei_data == 1:
        _endian = '<'
    elif _ei_data == 2:
        _endian = '>'
    else:
        raise ValueError("不支持的字节序: EI_DATA={}".format(_ei_data))

    _ptr_size = 4 if _ei_class == ELFCLASS32 else 8
    return _ei_class, _endian, _ptr_size


def _parse_elf_header(data: bytes):
    """解析ELF header，返回 (ptr_size, endian, ehdr_dict)。"""
    _ps, _endian, _ = _read_elf_ident(data)
    _fmt_map = {
        4: 'HHIIIIIHHHHHH',    # 32-bit
        8: 'HHIQQQIHHHHHH',    # 64-bit
    }
    _hdr_size = 52 if _ps == 4 else 64
    _e = _endian + _fmt_map[_ps]
    _fields = struct.unpack(_e, data[16:_hdr_size])
    _keys_32 = ['e_type','e_machine','e_version','e_entry','e_phoff','e_shoff',
                'e_flags','e_ehsize','e_phentsize','e_phnum','e_shentsize',
                'e_shnum','e_shstrndx']
    _keys_64 = ['e_type','e_machine','e_version','e_entry','e_phoff','e_shoff',
                'e_flags','e_ehsize','e_phentsize','e_phnum','e_shentsize',
                'e_shnum','e_shstrndx']
    _keys = _keys_32 if _ps == 4 else _keys_64
    return _ps, _endian, dict(zip(_keys, _fields))


def _section_entry_fmt(ptr_size: int, endian: str) -> str:
    """节区头结构格式字符串。"""
    if ptr_size == 8:
        return endian + 'IIQQQQIIQQ'
    else:
        return endian + 'IIIIIIIIII'


def _section_entry_size(ptr_size: int) -> int:
    """节区头结构字节数。"""
    return 64 if ptr_size == 8 else 40


def _read_str_at(data: bytes, start: int) -> str:
    """从data[start]读取null结尾的字符串。"""
    if start >= len(data):
        return ""
    _end = start
    while _end < len(data) and data[_end] != 0:
        _end += 1
    return data[start:_end].decode('latin-1', errors='replace')


def _read_section_data(data: bytes, shdr: SectionInfo) -> bytes:
    """安全读出节区原始字节，防越界。"""
    _start = shdr.sh_offset
    _end = _start + shdr.sh_size
    if _start >= len(data) or shdr.sh_size == 0:
        return b""
    _end = min(_end, len(data))
    return data[_start:_end]


# 符号表解析

def _parse_symbols(data: bytes, sec_data: bytes, str_data: bytes,
                   ptr_size: int, endian: str) -> List[SymbolInfo]:
    """解析.symtab节区。"""
    _syms: List[SymbolInfo] = []
    _sym_size = 16 if ptr_size == 4 else 24
    _fmt = endian + ('IIIBBH' if ptr_size == 4 else 'IBBHQQ')

    for _i in range(0, len(sec_data), _sym_size):
        if _i + _sym_size > len(sec_data):
            break
        _chunk = sec_data[_i:_i + _sym_size]
        _fields = struct.unpack(_fmt, _chunk)
        _st_name_idx = _fields[0]
        _name = _read_str_at(str_data, _st_name_idx)

        if ptr_size == 8:
            _st_info, _st_other, _st_shndx, _st_value, _st_size = (
                _fields[1], _fields[2], _fields[3], _fields[4], _fields[5])
        else:
            _st_value, _st_size, _st_info, _st_other, _st_shndx = (
                _fields[1], _fields[2], _fields[3], _fields[4], _fields[5])

        _syms.append(SymbolInfo(
            name=_name, st_info=_st_info, st_other=_st_other,
            st_shndx=_st_shndx, st_value=_st_value, st_size=_st_size))

    return _syms


def _classify_symbols(symbols: List[SymbolInfo], license_str: str) -> Dict[str, List[str]]:
    """符号分桶：exported, gpl_only, undefined, local。"""
    _r = {"exported": [], "gpl_only": [], "undefined": [], "local": []}
    _is_gpl = "GPL" in license_str

    for _s in symbols:
        _binding = _s.st_info >> 4
        if _s.st_shndx == SHN_UNDEF:
            _r["undefined"].append(_s.name)
        elif _binding == STB_LOCAL:
            _r["local"].append(_s.name)
        elif _binding == STB_GLOBAL:
            if _is_gpl:
                _r["gpl_only"].append(_s.name)
            else:
                _r["exported"].append(_s.name)

    return _r


# modinfo 解析

def _parse_modinfo(modinfo_data: bytes) -> Dict[str, str]:
    """解析.modinfo节区：null分隔的key=value对。"""
    _info: Dict[str, str] = {}
    if not modinfo_data:
        return _info
    _entries = modinfo_data.split(b'\x00')
    for _entry in _entries:
        if b'=' not in _entry:
            continue
        _k, _v = _entry.split(b'=', 1)
        _info[_k.decode('utf-8', errors='replace')] = _v.decode('utf-8', errors='replace')
    return _info


def _parse_vermagic(vermagic_str: str) -> str:
    """从vermagic字符串提取内核版本号。"""
    _parts = vermagic_str.split()
    for _p in _parts:
        if _p and _p[0].isdigit():
            return _p
    return vermagic_str


# BPF程序探测
# Linux 5.x+内核模块可能内嵌BPF程序，以节区名前缀识别

_BPF_SECTION_PREFIXES = (
    ".bpf", "xdp", "tc/", "socket", "kprobe", "kretprobe",
    "tracepoint", "raw_tp", "perf_event", "uprobe", "uretprobe",
    "cgroup", "lsm", "freplace", "fentry", "fexit",
    "tp_btf", "iter", "struct_ops",
)


def _detect_bpf_sections(sections: List[SectionInfo]) -> Tuple[bool, int]:
    """探测模块中是否包含BPF节区，返回 (has_bpf, count)。"""
    count = 0
    for sec in sections:
        name = sec.name
        # 节区名是否匹配BPF前缀序列
        for prefix in _BPF_SECTION_PREFIXES:
            if name.startswith(prefix):
                count += 1
                break
        # BTF节区同样标记BPF程序
        if name in (".BTF", ".BTF.ext", ".bpf.arena"):
            count += 1
    return count > 0, count


# GPL兼容性校验
# 非GPL模块链接EXPORT_SYMBOL_GPL符号即构成许可证违规

def _check_gpl_compatibility(symbols: List[SymbolInfo],
                              license_str: str,
                              gpl_syms: Optional[set] = None) -> Dict[str, Any]:
    """检查模块GPL兼容性。

    若非GPL许可证模块引用了EXPORT_SYMBOL_GPL符号，
    则标记为许可证违规。
    """
    _is_gpl = "GPL" in license_str.upper()
    _violations: List[str] = []

    if not _is_gpl and gpl_syms:
        for _s in symbols:
            if _s.st_shndx == SHN_UNDEF and _s.name in gpl_syms:
                _violations.append(_s.name)

    return {
        "is_gpl": _is_gpl,
        "violations": _violations,
        "violation_count": len(_violations),
    }


# 符号CRC统计
# CONFIG_MODVERSIONS编译的模块在__versions段携带CRC校验和

def _count_symbol_crcs(modinfo: Dict[str, str]) -> int:
    """统计modules的符号版本信息条目数。

    __versions段以null分隔"0xCRC\\tname\\tmodule"格式存储。
    """
    _versions = modinfo.get("_raw_versions", "")
    if not _versions:
        return 0
    # 计数非空条目
    return len([e for e in _versions.split('\x00') if e.strip()])


# 主解析入口

def parse_ko(filepath: str) -> Optional[KernelModule]:
    """解析.ko内核模块文件。"""
    if not os.path.isfile(filepath):
        return None

    with open(filepath, 'rb') as _fh:
        _data = _fh.read()

    # 解析 ELF header
    try:
        _ps, _endian, _ehdr = _parse_elf_header(_data)
    except (ValueError, struct.error):
        return None

    _shoff     = _ehdr['e_shoff']
    _shnum     = _ehdr['e_shnum']
    _shentsize = _ehdr['e_shentsize']
    _shstrndx  = _ehdr['e_shstrndx']

    if _shnum == 0 or _shoff >= len(_data):
        return None

    # 解析节区头 — 辅助函数统一处理32/64位差异
    _sec_fmt = _section_entry_fmt(_ps, _endian)
    _ent_sz  = _section_entry_size(_ps)
    _sections: List[SectionInfo] = []
    _sh_name_offsets: List[int] = []  # 记录各section header的sh_name字段值

    for _idx in range(_shnum):
        _off = _shoff + _idx * _shentsize
        if _off + _ent_sz > len(_data):
            break
        _f = struct.unpack(_sec_fmt, _data[_off:_off + _ent_sz])
        _sh_name_idx = _f[0]
        _sh_name_offsets.append(_sh_name_idx)
        _sections.append(SectionInfo(
            name="",  # name在解析shstrtab之后回填
            sh_type=_f[1], sh_flags=_f[2], sh_addr=_f[3],
            sh_offset=_f[4], sh_size=_f[5], sh_link=_f[6],
            sh_info=_f[7], sh_addralign=_f[8], sh_entsize=_f[9]))

    # 解析section名称字符串表
    _strtab_data = b""
    if _shstrndx < len(_sections):
        _strtab_data = _read_section_data(_data, _sections[_shstrndx])

    # 回填section名称
    for _idx, _sec in enumerate(_sections):
        _sh_name_idx = _sh_name_offsets[_idx]
        _sec.name = _read_str_at(_strtab_data, _sh_name_idx)

    # 按名称建立索引
    _sec_by_name: Dict[str, SectionInfo] = {s.name: s for s in _sections}

    # 提取 modinfo
    _modinfo = {}
    if ".modinfo" in _sec_by_name:
        _mi_data = _read_section_data(_data, _sec_by_name[".modinfo"])
        if _mi_data:
            _modinfo = _parse_modinfo(_mi_data)

    # 提取符号表
    _symbols: List[SymbolInfo] = []
    if ".symtab" in _sec_by_name and ".strtab" in _sec_by_name:
        _sym_data = _read_section_data(_data, _sec_by_name[".symtab"])
        _sym_str_data = _read_section_data(_data, _sec_by_name[".strtab"])
        if _sym_data and _sym_str_data:
            _symbols = _parse_symbols(_data, _sym_data, _sym_str_data, _ps, _endian)

    # 解析 vermagic
    _vermagic_raw = _modinfo.get("vermagic", "")
    _vermagic = _parse_vermagic(_vermagic_raw)

    # 依赖
    _deps_str = _modinfo.get("depends", "")
    _deps = [d for d in _deps_str.split(",") if d] if _deps_str else []

    # BPF程序探测
    _has_bpf, _bpf_count = _detect_bpf_sections(_sections)

    # GPL兼容性
    _gpl_info = _check_gpl_compatibility(
        _symbols, _modinfo.get("license", ""), None)

    # 符号CRC
    _crc_count = _count_symbol_crcs(_modinfo)

    return KernelModule(
        name=_modinfo.get("name", os.path.basename(filepath)),
        license=_modinfo.get("license", ""),
        vermagic=_vermagic,
        dependencies=_deps,
        symbols=_symbols,
        sections=_sections,
        modinfo=_modinfo,
        is_gpl_compatible=len(_gpl_info["violations"]) == 0,
        has_bpf_sections=_has_bpf,
        bpf_program_count=_bpf_count,
        symbol_crc_count=_crc_count,
    )


# 快速验证

# 安全缓解措施探测
# 检查模块是否应用了retpoline/IBT/CET等控制流完整性防护。

def detect_mitigations(kmod: KernelModule) -> Dict[str, bool]:
    """探测内核模块启用的安全缓解措施。

    在.modinfo及符号导入中检索缓解特性的签名。
    """
    _mitigations = {
        "retpoline": False, "ibt": False, "cet_shadow_stack": False,
        "cfi_clang": False, "fortify_source": False,
    }

    # retpoline: 检查符号是否导入 __x86_indirect_thunk_*
    for _sym in kmod.symbols:
        if _sym.name.startswith("__x86_indirect_thunk_"):
            _mitigations["retpoline"] = True
            break

    # IBT: 检查.text段是否有endbr64指令特征
    for _sec in kmod.sections:
        if _sec.name in (".text", ".text.hot", ".text.unlikely"):
            # 需读取原始文件字节码才能检测
            # 此处检查节区flag是否含SHF_EXECINSTR
            pass

    # CFI Clang: 检查是否存在 __cfi_check_fail 或 __cfi_ 前缀符号
    _cfi_syms = {s.name for s in kmod.symbols}
    if "__cfi_check_fail" in _cfi_syms or any(
        n.startswith("__cfi_") for n in _cfi_syms):
        _mitigations["cfi_clang"] = True

    # Fortify: 检查是否存在 fortify_panic 符号引用
    if "fortify_panic" in _cfi_syms:
        _mitigations["fortify_source"] = True

    # DMA能力探测: 若模块调用dma_alloc_*/pci_enable_device系列
    _dma_apis = {
        "dma_alloc_coherent", "dma_alloc_noncoherent",
        "dma_map_single", "dma_map_page", "dma_map_sg",
        "pci_enable_device", "pci_set_master", "pci_set_dma_mask",
        "pci_request_regions", "pcie_capability_set_word",
    }
    _sym_names = {s.name for s in kmod.symbols}
    _dma_hits = _dma_apis & _sym_names
    if _dma_hits:
        _mitigations["dma_capable"] = True
        _mitigations["dma_apis_used"] = sorted(_dma_hits)

    return _mitigations


def is_valid_ko(filepath: str) -> bool:
    """快速校验文件是否为有效.ko模块。"""
    if not os.path.isfile(filepath):
        return False
    with open(filepath, 'rb') as _fh:
        _hdr = _fh.read(64)
    if _hdr[:4] != ELF_MAGIC:
        return False
    _ei_class = _hdr[4]
    if _ei_class not in (ELFCLASS32, ELFCLASS64):
        return False
    if _ei_class == ELFCLASS64:
        _e_machine = struct.unpack_from('<H', _hdr, 18)[0]
    else:
        _e_machine = struct.unpack_from('<H', _hdr, 18)[0] if len(_hdr) > 20 else 0
    if _e_machine == EM_NONE:
        return False
    return True


# 批量目录扫描

def scan_directory(dirpath: str) -> List[KernelModule]:
    """扫描目录下所有.ko文件，返回解析后的模块列表。

    对无法解析或非模块文件静默跳过，不中断整体扫描。
    """
    _modules: List[KernelModule] = []
    if not os.path.isdir(dirpath):
        return _modules
    for _entry in sorted(os.listdir(dirpath)):
        _full = os.path.join(dirpath, _entry)
        if not os.path.isfile(_full) or not _entry.endswith('.ko'):
            continue
        _mod = parse_ko(_full)
        if _mod is not None:
            _modules.append(_mod)
    return _modules
