"""FMT-SPEC .rdata 提取器 — 从PE二进制提取格式字符串并分析printf调用.

核心流程:
  1. objdump反汇编 → 找所有 lea reg, [rip+off] → 计算目标VA
  2. PE header解析: VA → 文件偏移
  3. 读取.rdata中的null-terminated格式字符串
  4. MOV链追踪: 确定格式串参数通过哪些寄存器传递到printf
  5. 对每个printf调用点, 提取格式串+解析说明符

与BinaryFmtScanner的区别: 本模块不仅区分.rdata vs 栈来源,
还提取实际的格式字符串内容, 解析说明符, 计数参数.

创建: 2025-02-06
"""
import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .fmt_spec_parser import (
    parse_format_specs, count_consumed_args,
    detect_format_danger, FmtSpecifier)

# PE 文件格式

def va_to_offset_pe(binary_path: str, va: int) -> Optional[int]:
    """PE: 虚拟地址→文件偏移 (手动解析PE header, 无依赖)."""
    with open(binary_path, 'rb') as f:
        f.seek(0x3C)
        pe_offset = struct.unpack('<I', f.read(4))[0]
        f.seek(pe_offset)
        if f.read(4) != b'PE\x00\x00':
            return None
        # COFF(20): Machine+NumSections+...+SizeOfOptionalHeader
        f.seek(pe_offset + 4 + 16)
        size_opt = struct.unpack('<H', f.read(2))[0]
        # Optional Header: Magic(2) → PE32=0x10b, PE32+=0x20b
        opt_start = pe_offset + 4 + 20
        f.seek(opt_start)
        magic = struct.unpack('<H', f.read(2))[0]
        # ImageBase: PE32 at +0x1C (4 bytes), PE32+ at +0x18 (8 bytes)
        if magic == 0x20b:  # PE32+
            f.seek(opt_start + 24)
            image_base = struct.unpack('<Q', f.read(8))[0]
        else:
            f.seek(opt_start + 28)
            image_base = struct.unpack('<I', f.read(4))[0]
        # Convert absolute VA to RVA
        rva = va - image_base
        section_start = opt_start + size_opt
        for i in range(32):
            f.seek(section_start + i * 40)
            name_raw = f.read(8)
            if name_raw[0] == 0:
                break
            vsize = struct.unpack('<I', f.read(4))[0]
            va_base = struct.unpack('<I', f.read(4))[0]
            raw_size = struct.unpack('<I', f.read(4))[0]
            raw_offset = struct.unpack('<I', f.read(4))[0]
            if va_base <= rva < va_base + max(vsize, raw_size):
                return raw_offset + (rva - va_base)
    return None


def extract_string_at_va(binary_path: str, va: int,
                         max_len: int = 512) -> Optional[str]:
    """从二进制文件指定VA读取null-terminated C字符串."""
    off = va_to_offset_pe(binary_path, va)
    if off is None:
        return None
    try:
        with open(binary_path, 'rb') as f:
            f.seek(off)
            data = f.read(max_len)
            null_idx = data.find(b'\x00')
            if null_idx >= 0:
                data = data[:null_idx]
            try:
                return data.decode('ascii')
            except UnicodeDecodeError:
                return data.decode('latin-1', errors='replace')
    except Exception:
        return None


# objdump LEA追踪

_LEA_RIP_RE = re.compile(
    r'\blea\s+(\w+),\s*\[rip\s*([+\-])\s*(0x[0-9a-f]+)\]', re.I)
_PRINTF_CALL_RE = re.compile(
    r'\bcall\s+(?:[0-9a-f]+\s+<)?(printf|fprintf|sprintf|snprintf|'
    r'dprintf|vsprintf|vsnprintf|vfprintf|vprintf|syslog|'
    r'__mingw_printf|__mingw_fprintf|__mingw_sprintf|__mingw_snprintf|'
    r'__mingw_vprintf|__mingw_vfprintf|__mingw_vsprintf|__mingw_vsnprintf|'
    r'__mingw_dprintf)(?:@plt)?>?\b', re.I)
_ADDR_RE = re.compile(r'\s*([0-9a-f]+):\s+')

# Windows x64 calling convention: 格式串参数位置
_FMT_POS = {
    'printf': 'rcx', 'fprintf': 'rdx', 'sprintf': 'rdx',
    'snprintf': 'r8', 'dprintf': 'rdx', 'vsprintf': 'rdx',
    'vsnprintf': 'r8', 'vfprintf': 'rdx', 'vprintf': 'rcx',
    'syslog': 'rdx', '__mingw_printf': 'rcx',
    # MinGW variants
    '__mingw_fprintf': 'rdx', '__mingw_sprintf': 'rdx',
    '__mingw_snprintf': 'r8', '__mingw_vfprintf': 'rdx',
    '__mingw_vsprintf': 'rdx', '__mingw_vsnprintf': 'r8',
    '__mingw_vprintf': 'rcx', '__mingw_dprintf': 'rdx',
}


def _canon(r: str) -> str:
    """32→64位寄存器规范化."""
    m = {'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
         'esi': 'rsi', 'edi': 'rdi', 'r8d': 'r8', 'r9d': 'r9'}
    return m.get(r.lower(), r.lower())


@dataclass
class FmtCallSite:
    """一个printf族调用点的完整分析."""
    call_addr: int
    func: str
    fmt_reg: str = ""
    fmt_from_rdata: bool = False
    fmt_va: int = 0
    fmt_string: str = ""
    specs: List[FmtSpecifier] = field(default_factory=list)
    args_passed: int = 0
    args_expected: int = 0
    risk: str = "UNKNOWN"
    confidence: float = 0.0


def extract_fmt_calls(objdump_lines: List[str],
                      binary_path: str) -> List[FmtCallSite]:
    """从objdump提取所有printf调用并分析格式串.

    单遍扫描算法:
      1. lea reg,[rip+off] → 计算VA → 记录{reg: VA}
      2. mov dst,src → 追踪寄存器传播链 (格式串参数传递)
      3. call printf → 解析格式串参数寄存器 → 提取.rdata字符串 → 解析说明符

    返回: FmtCallSite列表, 每个包含格式串内容和风险等级.
    """
    reg_to_rdata: Dict[str, int] = {}   # reg → .rdata VA
    reg_alias: Dict[str, str] = {}       # dst → src (MOV链)
    calls: List[FmtCallSite] = []

    def _resolve(r: str) -> int:
        """沿MOV链解析寄存器→.rdata VA."""
        seen = set()
        cur = _canon(r)
        while cur in reg_alias and cur not in seen:
            seen.add(cur)
            nxt = reg_alias[cur]
            if nxt in reg_to_rdata:
                return reg_to_rdata[nxt]
            cur = _canon(nxt)
        return reg_to_rdata.get(cur, 0)

    for line in objdump_lines:
        il = line.strip()
        if not il:
            continue

        addr_m = _ADDR_RE.match(il)
        insn_addr = int(addr_m.group(1), 16) if addr_m else 0
        il_lower = il.lower()

        # Phase 1: LEA rip-relative
        lea_m = _LEA_RIP_RE.search(il_lower)
        if lea_m:
            dst = _canon(lea_m.group(1))
            sign = -1 if lea_m.group(2) == '-' else 1
            off = int(lea_m.group(3), 16) * sign
            target_va = insn_addr + 7 + off
            reg_to_rdata[dst] = target_va
            # LEA创建新别名, 清除旧alias (新值覆盖旧引用)
            reg_alias.pop(dst, None)
            continue

        # Phase 1.5: 寄存器覆写检测 — 非LEA写入则清除.rdata映射
        # mov reg, [mem] / mov reg, imm / xor reg,reg → kill rdata mapping
        mov_mem = re.search(
            r'\bmov\s+(\w+),\s*(?:qword|dword|word|byte)\s+ptr\s+\[', il_lower)
        mov_imm = re.search(
            r'\bmov\s+(\w+),\s*(0x[0-9a-f]+|\d+)\s*$', il_lower)
        xor_zero = re.search(r'\bxor\s+(\w+),\s*\1\b', il_lower)
        kill_dst = None
        if mov_mem:
            kill_dst = _canon(mov_mem.group(1))
        elif mov_imm:
            kill_dst = _canon(mov_imm.group(1))
        elif xor_zero:
            kill_dst = _canon(xor_zero.group(1))
        if kill_dst and kill_dst not in ('rbp', 'rsp', 'rip'):
            reg_to_rdata.pop(kill_dst, None)
            reg_alias.pop(kill_dst, None)
            # 清除所有指向被kill寄存器的别名链
            for alias_dst, alias_src in list(reg_alias.items()):
                if _canon(alias_src) == kill_dst:
                    reg_alias.pop(alias_dst, None)

        # Phase 2: MOV reg→reg
        mov_rr = re.search(r'\bmov\s+(\w+),\s*(\w+)\s*$', il_lower)
        if mov_rr:
            dst = _canon(mov_rr.group(1))
            src = _canon(mov_rr.group(2))
            if dst not in ('rbp', 'rsp', 'rip'):
                reg_alias[dst] = src
            continue

        # Phase 3: printf-family call
        call_m = _PRINTF_CALL_RE.search(il_lower)
        if call_m:
            func = call_m.group(1).lower()
            fmt_reg = _FMT_POS.get(func, 'rcx')
            fmt_va = _resolve(fmt_reg)

            site = FmtCallSite(
                call_addr=insn_addr, func=func, fmt_reg=fmt_reg,
                fmt_from_rdata=(fmt_va > 0), fmt_va=fmt_va)

            if site.fmt_from_rdata:
                fmt_str = extract_string_at_va(binary_path, fmt_va)
                if fmt_str:
                    site.fmt_string = fmt_str
                    site.specs = parse_format_specs(fmt_str)
                    site.args_expected = count_consumed_args(site.specs)
                    danger = detect_format_danger(fmt_str, site.specs)
                    site.risk = danger['risk_level']

            calls.append(site)

    return calls
