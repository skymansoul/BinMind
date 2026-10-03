# 堆写入点扫描 — 识别malloc后的memcpy/strcpy等危险写入
"""堆写入点扫描器 — 从汇编中提取memcpy-like调用的写入大小。

ABI兼容: System V x86_64 和 Microsoft x64。
  memcpy(dst, src, size):
    SysV:  rdi=dst, rsi=src, rdx=size
    MS x64: rcx=dst, rdx=src, r8=size

strcpy/strcat无显式size参数, 通过源字符串推断最小写入量:
  - lea src_reg, [rip+offset] → 从数据段提取字符串长度
  - 寄存器来源 → 保守返回1 (至少null terminator)
gets无大小限制, 保守标记为MAX_INT。
"""

import re
import subprocess
import os
from typing import List, Dict, Tuple, Optional

_WRITE_FUNCS = re.compile(
    r'\bcall\s+(?:[0-9a-f]+\s+<)?(memcpy|memmove|strcpy|strcat|strncpy|strncat|'
    r'bcopy|sprintf|snprintf|gets|read|__mingw_memcpy|__mingw_memmove)(?:@plt)?>?\b', re.I)

_SRC_REGS = ('rdx', 'rsi', 'edx', 'esi')
_SIZE_REGS = ('rdx', 'edx', 'r8', 'r8d')
# 寄存器间接追踪: mov r8, rcx → 找mov rcx/ecx, IMM
_REG_ALIASES = {
    'rcx': ('rcx', 'ecx', 'cx', 'cl'),
    'rdx': ('rdx', 'edx', 'dx', 'dl'),
    'r8': ('r8', 'r8d', 'r8w', 'r8b'),
    'rax': ('rax', 'eax', 'ax', 'al'),
}
# data_cache: 按binary_path缓存的数据段内容
_data_cache = {}


def find_write_sites(asm_lines: List[str],
                     binary_path: str = '') -> List[Dict]:
    """扫描所有危险写入调用点，提取函数名和写入大小。"""
    global _data_cache
    sites = []
    for i, line in enumerate(asm_lines):
        m = _WRITE_FUNCS.search(line)
        if not m:
            continue
        func = m.group(1).lower()
        size_val, is_const = _extract_write_size(asm_lines, i, func, binary_path)
        sites.append({
            'line': i, 'func': func,
            'write_size': size_val, 'size_is_constant': is_const,
        })
    return sites


def _extract_write_size(asm: List[str], call_idx: int,
                        func: str, binary_path: str = '') -> Tuple[int, bool]:
    """提取写操作的字节数。"""
    func = func.lower()

    if func == 'gets':
        return 2**31 - 1, False

    if func in ('strcpy', 'strcat'):
        src_len = _infer_strcpy_size(asm, call_idx, binary_path)
        return (src_len, False) if src_len > 0 else (1, False)

    # memcpy类 → 第3参数: 先查立即数, 再查寄存器间接, 再查lea size
    for j in range(call_idx - 1, max(call_idx - 6, -1), -1):
        line = asm[j].strip().lower().replace(',', ' ')
        for reg in _SIZE_REGS:
            m = re.search(r'\bmov\s+' + reg + r',?\s*(0x[0-9a-f]+|\d+)', line)
            if m:
                v = m.group(1)
                return (int(v, 16) if v.lower().startswith('0x')
                        else int(v)), True
        # 寄存器间接: mov r8, rcx → 跟踪rcx的来源
        for reg in _SIZE_REGS:
            m = re.search(r'\bmov\s+' + reg + r',?\s*(\w{2,3})', line)
            if m:
                src_reg = m.group(1)
                indirect = _track_reg_immediate(asm, j, src_reg)
                if indirect:
                    return indirect
        # lea size_reg, [src+imm] (O2优化: strlen+1等)
        for reg in _SIZE_REGS:
            m = re.search(r'\blea\s+' + reg + r',?\s*\[(\w+)\s*([+\-])\s*'
                          r'(0x[0-9a-f]+|\d+)\]', line)
            if m:
                # 非立即数src → 标记未知(不判常量), 交给表达式层
                return 0, False
    return 0, False


def _track_reg_immediate(asm: List[str], from_line: int,
                         target_reg: str) -> Optional[Tuple[int, bool]]:
    """追踪寄存器的立即数来源 (一级间接)。

    mov r8, rcx 在from_line处 → 向前找mov rcx/ecx, IMM。
    若发现立即数前有jmp指令 (jmp-over-constant模式),
    则标记为非const, 让表达式追踪器处理。
    """
    aliases = _REG_ALIASES.get(target_reg, (target_reg,))
    for j in range(from_line - 1, max(from_line - 5, -1), -1):
        line = asm[j].strip().lower().replace(',', ' ')
        for alias in aliases:
            m = re.search(r'\bmov\s+' + alias + r',?\s*(0x[0-9a-f]+|\d+)', line)
            if m:
                v = m.group(1)
                val = (int(v, 16) if v.lower().startswith('0x')
                       else int(v))
                # jmp-over-constant检测: 前一行=jmp → 此常量为fallback, 非真实值
                if j > 0 and re.search(r'\bjmp\b', asm[j - 1].strip().lower()):
                    return None  # 拒绝fallback常量, 让上层标记w_size=0
                return val, True
    return None


def _infer_strcpy_size(asm: List[str], call_idx: int,
                       binary_path: str = '') -> int:
    """推断strcpy/strcat的源字符串最小长度。

    策略:
      1. lea src_reg, [rip+offset] → 用objdump -s读数据段字符串
      2. 字符串常量 → 返回strlen+1 (含null)
      3. 寄存器来源 → 返回0 (让调用方用默认值)
    """
    for j in range(call_idx - 1, max(call_idx - 8, -1), -1):
        line = asm[j].strip().lower().replace(',', ' ')
        for reg in _SRC_REGS:
            m = re.search(r'\blea\s+' + reg + r',?\s*\[rip\s*([+\-])\s*'
                          r'(0x[0-9a-f]+)\]', line)
            if m:
                sign, offset = m.group(1), m.group(2)
                rip_offset = int(offset, 16)
                if sign == '-':
                    rip_offset = -rip_offset
                str_addr = _approx_rip_target(asm, j) + rip_offset
                s = _read_string_from_data_section(binary_path, str_addr)
                if s:
                    return len(s) + 1
    return 0


def _approx_rip_target(asm: List[str], instr_line: int) -> int:
    """近似计算rip-relative引用的基地址 (下一条指令地址)。"""
    for k in range(instr_line, min(instr_line + 3, len(asm))):
        m = re.match(r'\s*([0-9a-f]+):', asm[k].strip())
        if m:
            return int(m.group(1), 16) + 7  # lea指令常见7字节
    return 0


def _read_string_from_data_section(binary_path: str, addr: int) -> Optional[str]:
    """从objdump -s输出中读取指定地址的C字符串。"""
    global _data_cache
    if not binary_path or not os.path.isfile(binary_path):
        return None
    if binary_path not in _data_cache:
        _data_cache[binary_path] = _dump_data_section(binary_path)
    hexdump = _data_cache[binary_path]
    if not hexdump:
        return None

    # 在hexdump中搜索地址
    addr_str = f'{addr:x}'
    pattern = re.compile(
        r'\s*([0-9a-f]+)\s+((?:[0-9a-f]{2}\s+)+)\s*\|([^|]*)\|')
    for m in pattern.finditer(hexdump):
        line_addr = int(m.group(1), 16)
        hex_bytes = m.group(2).strip().split()
        ascii_part = m.group(3)
        # 计算地址偏移
        if line_addr <= addr < line_addr + len(hex_bytes):
            offset = addr - line_addr
            # 从ascii列提取字符串 (更可靠)
            result = []
            for i in range(offset, len(ascii_part)):
                ch = ascii_part[i]
                if ch == '.' and hex_bytes[i] != '2e':  # '.'但不是0x2e → 不可打印
                    # 检查是否为null终止符
                    if i < len(hex_bytes) and hex_bytes[i] == '00':
                        break
                result.append(ch)
            return ''.join(result)
    return None


def _dump_data_section(binary_path: str) -> str:
    """objdump -s 转储完整数据段内容。"""
    try:
        r = subprocess.run(
            ['objdump', '-s', binary_path],
            capture_output=True, text=True, timeout=15)
        return r.stdout if r.returncode == 0 else ''
    except Exception:
        return ''
