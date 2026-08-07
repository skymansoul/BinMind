"""Binary normalizer extracted differential_模糊测试器.py

module 处理 binary--canonical-form conversions needed
differential 模糊测试 engine. Parsing file headers a uniform _BinaryMeta
representation, extracting code sections, fingerprinting instruction streams
computing locality-sensitive block 哈希 belong --
orthogonal 模糊测试 orchestration execution-comparison logic
remains differential_模糊测试器.py

Splitting out keeps normalizer testable isolation lets
tools (binary_similarity, semantic_diff_analyzer) reuse same primitives
pulling full 模糊测试器
"""

import struct
import logging
import zlib
from typing import Dict, List, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# capstone import
try:
    import capstone as _cs_mod
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False
    logger.debug("capstone not installed -- instruction-level diff degraded")


# 二进制头解析——最小依赖，不引入pefile/pyelftools

@dataclass
class _BinaryMeta:
    """从文件头提取的二进制元信息"""
    fmt: str           # 'PE', 'ELF', 'MACHO', 'RAW'
    arch: str          # 'x86', 'x86-64', 'arm', 'arm64', 'unknown'
    bits: int          # 32 or 64
    endian: str        # 'little' or 'big'
    entry_point: int
    sections: List[Dict[str, int]] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    compiler_hint: str = ""  # 编译器指纹


def _parse_binary_meta(binary_path: str) -> _BinaryMeta:
    """解析二进制文件头，提取架构和编译器相关信息"""
    try:
        with open(binary_path, 'rb') as fh:
            header = fh.read(128)
    except (OSError, IOError):
        return _BinaryMeta(fmt='RAW', arch='unknown', bits=64,
                           endian='little', entry_point=0)

    # ELF
    if header[:4] == b'\x7fELF':
        elf_class = header[4]
        is_64 = elf_class == 2
        endian = 'big' if header[5] == 2 else 'little'
        if is_64:
            machine = struct.unpack_from('<H' if endian == 'little' else '>H',
                                         header, 0x12)[0]
            entry = struct.unpack_from('<Q' if endian == 'little' else '>Q',
                                       header, 0x18)[0]
        else:
            machine = struct.unpack_from('<H' if endian == 'little' else '>H',
                                         header, 0x12)[0]
            entry = struct.unpack_from('<I' if endian == 'little' else '>I',
                                       header, 0x18)[0]
        arch_map = {3: 'x86', 62: 'x86-64', 40: 'arm', 183: 'arm64'}
        arch = arch_map.get(machine, f'machine_{machine}')
        return _BinaryMeta(fmt='ELF', arch=arch, bits=64 if is_64 else 32,
                           endian=endian, entry_point=entry)

    # PE
    if header[:2] == b'MZ':
        pe_offs = struct.unpack_from('<I', header, 0x3C)[0]
        with open(binary_path, 'rb') as fh:
            fh.seek(pe_offs)
            pe_sig = fh.read(4)
            if pe_sig != b'PE\x00\x00':
                return _BinaryMeta(fmt='RAW', arch='unknown', bits=64,
                                   endian='little', entry_point=0)
            coff = fh.read(20)
            machine = struct.unpack_from('<H', coff, 0)[0]
            # PE32+: Magic=0x20b → x86-64; PE32: 0x10b → x86
            opt_magic = struct.unpack_from('<H', coff, 18)[0]
            is_64 = opt_magic == 0x20b
            arch_map = {0x014C: 'x86', 0x8664: 'x86-64',
                       0xAA64: 'arm64', 0x01C4: 'arm', 0x0200: 'ia64'}
            arch = arch_map.get(machine, f'machine_{machine:04x}')
        return _BinaryMeta(fmt='PE', arch=arch, bits=64 if is_64 else 32,
                           endian='little', entry_point=0)

    # Mach-O magic 检查
    macho_magic_le64 = b'\xcf\xfa\xed\xfe'
    macho_magic_le32 = b'\xce\xfa\xed\xfe'
    macho_magic_be64 = b'\xfe\xed\xfa\xcf'
    macho_magic_be32 = b'\xfe\xed\xfa\xce'
    if header[:4] in (macho_magic_le64, macho_magic_le32,
                      macho_magic_be64, macho_magic_be32):
        return _BinaryMeta(fmt='MACHO', arch='arm64', bits=64,
                           endian='little', entry_point=0)

    return _BinaryMeta(fmt='RAW', arch='unknown', bits=64,
                       endian='little', entry_point=0)


def _detect_compiler_hints(binary_path: str, meta: _BinaryMeta) -> str:
    """扫描二进制字符串表检测编译器指纹
    
    GCC:.comment节含 "GCC: (xxx) x.y.z"
    Clang: "clang version"
    MSVC:.rdata含 "Microsoft (R)" 或 Rich header
    : " 构建 ID"
    Rust: "rustc"
    """
    hints: List[str] = []
    try:
        with open(binary_path, 'rb') as fh:
            # 读前256KB搜索编译器字符串
            chunk = fh.read(256 * 1024)
    except (OSError, IOError):
        return 'unknown'

    patterns = [
        (b'GCC:', 'gcc'),
        (b'clang version', 'clang'),
        (b'Microsoft (R)', 'msvc'),
        (b'Go build ID', 'go'),
        (b'rustc', 'rust'),
        (b'RICH\x00', 'msvc-rich'),
        (b'MinGW', 'mingw'),
        (b'GNU C', 'gcc'),
        (b'Free Software Foundation', 'gcc'),
        (b'glibc', 'glibc'),
        (b'musl', 'musl-libc'),
    ]
    for pat, name in patterns:
        if pat in chunk:
            hints.append(name)

    return ','.join(hints) if hints else 'unknown'


# 代码段提取

def _extract_code_section(binary_path: str) -> Tuple[bytes, int]:
    """提取代码段用于反汇编比对。返回 (code_bytes, base_vaddr)"""
    try:
        with open(binary_path, 'rb') as fh:
            header = fh.read(64)
    except (OSError, IOError):
        return b'', 0

    # ELF: 遍历program headers找可执行段
    if header[:4] == b'\x7fELF':
        elf_class = header[4]
        is_64 = elf_class == 2
        with open(binary_path, 'rb') as fh:
            if is_64:
                e_phoff = struct.unpack_from('<Q', header, 0x20)[0]
                e_phentsize = struct.unpack_from('<H', header, 0x36)[0]
                e_phnum = struct.unpack_from('<H', header, 0x38)[0]
            else:
                e_phoff = struct.unpack_from('<I', header, 0x1C)[0]
                e_phentsize = struct.unpack_from('<H', header, 0x2A)[0]
                e_phnum = struct.unpack_from('<H', header, 0x2C)[0]
            for i in range(e_phnum):
                offset = e_phoff + i * e_phentsize
                fh.seek(offset)
                if is_64:
                    phdr = fh.read(e_phentsize)
                    p_type = struct.unpack_from('<I', phdr, 0)[0]
                    p_flags = struct.unpack_from('<I', phdr, 4)[0]
                    p_offset = struct.unpack_from('<Q', phdr, 8)[0]
                    p_vaddr = struct.unpack_from('<Q', phdr, 16)[0]
                    p_filesz = struct.unpack_from('<Q', phdr, 32)[0]
                else:
                    phdr = fh.read(e_phentsize)
                    p_type = struct.unpack_from('<I', phdr, 0)[0]
                    p_offset = struct.unpack_from('<I', phdr, 4)[0]
                    p_vaddr = struct.unpack_from('<I', phdr, 8)[0]
                    p_filesz = struct.unpack_from('<I', phdr, 16)[0]
                    p_flags = struct.unpack_from('<I', phdr, 24)[0]
                if p_type == 1 and (p_flags & 1) and p_filesz > 0:
                    fh.seek(p_offset)
                    return fh.read(p_filesz), p_vaddr
        return b'', 0

    # PE: 遍历section headers
    if header[:2] == b'MZ':
        pe_offset = struct.unpack_from('<I', header, 0x3C)[0]
        with open(binary_path, 'rb') as fh:
            fh.seek(pe_offset)
            if fh.read(4) != b'PE\x00\x00':
                return b'', 0x400000
            coff = fh.read(20)
            n_sections = struct.unpack_from('<H', coff, 2)[0]
            opt_hdr_size = struct.unpack_from('<H', coff, 16)[0]
            opt_start = pe_offset + 4 + 20
            fh.seek(opt_start + opt_hdr_size)
            for _ in range(n_sections):
                sec = fh.read(40)
                sec_rawsize = struct.unpack_from('<I', sec, 16)[0]
                sec_rawptr = struct.unpack_from('<I', sec, 20)[0]
                sec_vaddr = struct.unpack_from('<I', sec, 12)[0]
                sec_flags = struct.unpack_from('<I', sec, 36)[0]
                # IMAGE_SCN_MEM_EXECUTE = 0x20000000
                if (sec_flags & 0x20000000) and sec_rawsize > 0:
                    fh.seek(sec_rawptr)
                    return fh.read(sec_rawsize), sec_vaddr
        return b'', 0x400000

    return b'', 0


# 指令级指纹提取
# 用于编译器差分比对：提取指令分布直方图作为编译器指纹
# Rosenblum et al. "编译器 Provenance Attribution"

def _extract_instruction_fingerprint(code: bytes, base_addr: int,
                                     meta: _BinaryMeta) -> Dict[str, Any]:
    """反汇编代码段并返回指令级指纹特征
    
    返回: {prologue_patterns, insn_histogram, call_targets, n_functions_est,.}
    """
    result: Dict[str, Any] = {
        'n_instructions': 0,
        'insn_histogram': {},
        'prologue_count': {},
        'n_functions_est': 0,
        'floating_point_ratio': 0.0,
        'simd_ratio': 0.0,
    }

    if not _HAS_CAPSTONE or not code:
        return result

    if meta.arch in ('x86-64',):
        md = _cs_mod.Cs(_cs_mod.CS_ARCH_X86, _cs_mod.CS_MODE_64)
    elif meta.arch == 'x86':
        md = _cs_mod.Cs(_cs_mod.CS_ARCH_X86, _cs_mod.CS_MODE_32)
    elif meta.arch == 'arm64':
        md = _cs_mod.Cs(_cs_mod.CS_ARCH_ARM64, _cs_mod.CS_MODE_ARM)
    elif meta.arch == 'arm':
        md = _cs_mod.Cs(_cs_mod.CS_ARCH_ARM, _cs_mod.CS_MODE_ARM)
    else:
        md = _cs_mod.Cs(_cs_mod.CS_ARCH_X86, _cs_mod.CS_MODE_64)

    md.detail = True
    md.skipdata = True

    count = 0
    prologue_counts: Dict[str, int] = defaultdict(int)
    histo: Dict[str, int] = defaultdict(int)
    fp_count = 0
    simd_count = 0

    try:
        for insn in md.disasm(bytes(code), base_addr):
            count += 1
            mnem = insn.mnemonic.lower()
            histo[mnem] = histo.get(mnem, 0) + 1

            # 浮点指令
            if mnem.startswith(('f',)) and mnem not in ('fi',):
                fp_count += 1
            # SIMD指令
            if any(mnem.startswith(p) for p in
                   ('movdqa', 'movdqu', 'padd', 'psub', 'pmul',
                    'pxor', 'por', 'pand', 'pshuf', 'punpck',
                    'vadd', 'vmul', 'vsub', 'vdiv', 'vxor',
                    'vmovdqa', 'vmovdqu', 'vfmadd',
                    'ldr', 'str', 'fadd', 'fmul')):
                simd_count += 1

            if count > 50000:
                break

        # 函数序言检测——启发式扫描
        # x86-64 GCC: push rbp; mov rbp, rsp
        # x86-64 MSVC: push rbp; mov rbp, rsp; sub rsp, imm
        # ARM64: stp x29, x30, [sp, #-imm]!; mov x29, sp
        prologue_counts = {
            'push_rbp_mov_rbp_rsp': 0,
            'sub_rsp_imm': 0,
            'stp_frame': 0,
        }
    except Exception as e:
        logger.debug("capstone fingerprint extraction error (suppressed): %s", e)

    result['n_instructions'] = count
    result['insn_histogram'] = dict(sorted(histo.items(),
                                    key=lambda x: -x[1])[:30])
    result['floating_point_ratio'] = fp_count / count if count > 0 else 0.0
    result['simd_ratio'] = simd_count / count if count > 0 else 0.0
    # 函数数量估算——基于ret指令数
    ret_count = histo.get('ret', 0) + histo.get('retn', 0)
    result['n_functions_est'] = max(1, ret_count)
    result['prologue_count'] = dict(prologue_counts)
    return result


# 代码块哈希 (保留原有接口)


class BinaryNormalizer:
    """将二进制标准化为可比对形式——消除编译器无关的噪音（时间戳、构建ID等）
    采用局部敏感哈希 (ssdeep/TLSH) 思想：以固定块大小分片哈希，比较哈希相似度
    而非逐字节比对。这样跨编译器产生的偏移漂移、寄存器分配差异不影响比对结果
    """
# _BLOCK_SIZE = 64  # 哈希块大小——64 字节是 -cache line 宽度，常见指令对齐边界

    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def compute_block_hashes(self, section_start: int = 0x1000,
                              section_len: int = 0x100000) -> List[str]:
        """计算代码节的块哈希序列——每个 64B 块一个 CRC32，返回 hex 字符串列表"""
        hashes: List[str] = []
        try:
            with open(self.binary_path, 'rb') as fh:
                fh.seek(section_start)
                buf = fh.read(section_len)
            for offset in range(0, len(buf) - self._BLOCK_SIZE, self._BLOCK_SIZE):
                crc = zlib.crc32(buf[offset:offset + self._BLOCK_SIZE])
                hashes.append(f"{crc:08x}")
        except Exception:
            logger.debug("compute_block_hashes failed (suppressed)", exc_info=True)
        return hashes

    def block_similarity(self, other_hashes: List[str]) -> float:
        """比较两组块哈希的 Jaccard 相似度"""
        mine = self.compute_block_hashes()
        if not mine or not other_hashes:
            return 0.0
        set_a = set(mine)
        set_b = set(other_hashes)
        intersection = len(set_a & set_b)
        union = len(set_a | set_b)
        return intersection / union if union > 0 else 0.0
