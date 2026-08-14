# 二进制硬化检测入口: 实现按职责分散到 checksec_elf_parser/checksec_detectors/checksec_api, 本文件仅做再导出以保持 API 兼容。

from .checksec_constants import (
    ELFMAG, ELFCLASS32, ELFCLASS64,
    PT_GNU_STACK, PT_GNU_RELRO,
    DT_NULL, DT_NEEDED, DT_STRTAB, DT_SYMTAB,
    DT_FLAGS, DT_FLAGS_1, DT_GNU_HASH,
    DF_BIND_NOW, DF_1_NOW, PF_X, PF_W, PF_R,
    CANARY_SYMBOLS,
)
from .checksec_elf_parser import (
    _read_struct, _detect_elf_class, _parse_elf_headers,
    _parse_dynamic_section,
)
from .checksec_detectors import (
    _detect_canary_from_imports,
    _detect_elf_checksec, _detect_pe_checksec, _detect_macho_checksec,
)
from .checksec_api import detect_checksec, checksec_summary

__all__ = [
    "detect_checksec", "checksec_summary",
    "ELFMAG", "ELFCLASS32", "ELFCLASS64",
    "PT_GNU_STACK", "PT_GNU_RELRO",
    "CANARY_SYMBOLS",
    "_read_struct", "_detect_elf_class", "_parse_elf_headers",
    "_parse_dynamic_section", "_detect_canary_from_imports",
    "_detect_elf_checksec", "_detect_pe_checksec", "_detect_macho_checksec",
]
