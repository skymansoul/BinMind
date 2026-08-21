# 格式串来源深化追踪-溯源fmt寄存器至最终来源, 区分常量与用户输入
# 误报根源: 栈驻留常量格式串被分类为STACK→DANGEROUS
#   例: char fmt[]="%s"; printf(fmt,x) —— fmt在栈上但内容是编译期常量
#   例: char *fmt="hello"; printf(fmt) —— rdi←rbx, rbx来自.rodata
#   现有format_string_deep只查rdi的直接装载, 遇栈槽/callee-saved即判STACK
# 方法: 沿寄存器链+栈槽写回溯源:
#   (1) lea/mov [rip+X] → CONST_RODATA
#   (2) 栈槽写入立即数 → CONST(内容可静态解析)
#   (3) 栈槽由call(如strcpy)写入 → 保持原来源分类
#   (4) 参数寄存器/alloc → ARG/HEAP
# 安全性: 仅将可证为常量的fmt降为SAFE, 用户输入fmt不受影响——只压误报

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Tuple

# 来源常量-与format_string_deep.FmtSource.value对应, 避免循环导入
CONST_RODATA = 'const_rodata'
ARG = 'arg'
HEAP = 'heap'
UNKNOWN = 'unknown'

logger = logging.getLogger(__name__)

_NON_REG = {'qword', 'dword', 'word', 'byte', 'ptr', 'xmmword'}
_ARG_REGS = {'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9',
             'edi', 'esi', 'edx', 'ecx', 'r8d', 'r9d'}
_STACK_SLOT_RE = re.compile(
    r'\[(rbp|rsp)([+\-]0x[0-9a-f]+)\]')
_SLOT_LOAD_RE = re.compile(
    r'(?:mov|movsxd|movzx|movsx)\s+%?(\w+),\s*(?:\w+\s+ptr\s+)?'
    r'\[(rbp|rsp)([+\-]0x[0-9a-f]+)\]')
_SLOT_STORE_IMM = re.compile(
    r'mov\s+(?:\w+\s+ptr\s+)?\[(rbp|rsp)([+\-]0x[0-9a-f]+)\]\s*,\s*'
    r'\$?(0x[0-9a-f]+|\d+)')
_SLOT_STORE_REG = re.compile(
    r'mov\s+(?:\w+\s+ptr\s+)?\[(rbp|rsp)([+\-]0x[0-9a-f]+)\]\s*,\s*%?(\w+)')
_RIP_LEA = re.compile(
    r'lea\s+(?:0x[0-9a-f]+|%?\w+)?\s*\(\s*%?rip\s*\)\s*,\s*%?(\w+)')
_RIP_LEA_INTEL = re.compile(
    r'lea\s+%?(\w+)\s*,\s*\[rip([+\-]0x[0-9a-f]+)\]')
_RIP_LOAD = re.compile(
    r'(?:mov|lea)\s+%?(\w+)\s*,\s*(?:qword\s+ptr\s+)?\[rip([+\-]0x[0-9a-f]+)\]')
_IMM_MOV = re.compile(
    r'(?:mov|movabs)\s+\$?(0x[0-9a-f]+|\d+),\s*%?(\w+)')
_IMM_MOV_INTEL = re.compile(
    r'(?:mov|movabs)\s+%?(\w+),\s*(0x[0-9a-f]+|\d+)')
_REG_MOV = re.compile(
    r'(?:mov|movabs|movsxd|movzx|movsx)\s+%?(\w+),\s*%?(\w+)')
_SLOT_LEA = re.compile(
    r'lea\s+%?(\w+)\s*,\s*\[(rbp|rsp)([+\-]0x[0-9a-f]+)\]')


class FmtProvenance:
    """格式串来源深化追踪器-溯源fmt寄存器到常量/参数/堆最终来源"""

    def __init__(self, max_depth: int = 12):
        self._max_depth = max_depth

    def resolve(self, instructions: List[str], call_idx: int,
                fmt_reg: str = 'rdi',
                rodata_refs: Optional[Dict[int, str]] = None
                ) -> Tuple[FmtSource, str]:
        """解析fmt来源→(FmtSource, 内容片段)。返回CONST_*即安全"""
        rodata_refs = rodata_refs or {}
        src, content = self._trace_reg(instructions, call_idx - 1, fmt_reg,
                                       rodata_refs, depth=0)
        return src, content

    def _trace_reg(self, instructions, from_idx, reg,
                   rodata_refs, depth: int) -> Tuple[str, str]:
        """沿寄存器链+栈槽回溯-终止于.rodata/立即数/参数/call"""
        if from_idx < 0 and reg.lower().lstrip('%') in _ARG_REGS:
            return ARG, ""
        if depth > self._max_depth or from_idx < 0:
            return UNKNOWN, ""
        cur = reg.lower().lstrip('%')
        for j in range(from_idx, max(-1, from_idx - 14), -1):
            if j < 0:
                break
            il = instructions[j].strip().lower()
            if not il or il.startswith((';', '.')):
                continue

            # RIP加载/lea → .rodata
            m = _RIP_LEA_INTEL.match(il)
            if m and m.group(1) == cur:
                return CONST_RODATA, self._rodata_content(
                    m.group(2), rodata_refs)
            m = _RIP_LOAD.match(il)
            if m and m.group(1) == cur:
                return CONST_RODATA, self._rodata_content(
                    m.group(2), rodata_refs)
            if 'rip' in il and re.search(rf'\b{cur}\s*$', il):
                return CONST_RODATA, ""

            # 立即数mov → 常量地址/内容
            m = _IMM_MOV.match(il)
            if m and m.group(2) == cur:
                return self._imm_source(m.group(1), rodata_refs)
            m = _IMM_MOV_INTEL.match(il)
            if m and m.group(1) == cur:
                return self._imm_source(m.group(2), rodata_refs)

            # 栈槽加载 → 追栈槽写回
            m = _SLOT_LOAD_RE.match(il)
            if m and m.group(1) == cur:
                slot = f"[{m.group(2)}{m.group(3)}]"
                return self._trace_slot(instructions, j, slot,
                                        rodata_refs, depth)

            # lea reg,[rbp/rsp+off] → reg指向栈槽, 追槽内容
            m = _SLOT_LEA.match(il)
            if m and m.group(1) == cur:
                slot = f"[{m.group(2)}{m.group(3)}]"
                return self._trace_slot(instructions, j, slot,
                                        rodata_refs, depth)

            # 寄存器间mov → 继续
            m = _REG_MOV.match(il)
            if m:
                r1, r2 = m.group(1), m.group(2)
                src = r1 if '%' in il else r2   # AT&T src第一, Intel src第二
                if src == cur:
                    dst = r2 if '%' in il else r1
                    if dst in _ARG_REGS:
                        return ARG, ""
                    return self._trace_reg(instructions, j - 1, dst,
                                           rodata_refs, depth + 1)
                if r2 == cur and '%' in il:     # AT&T: cur是目标
                    return self._trace_reg(instructions, j - 1, r1,
                                           rodata_refs, depth + 1)
                if r1 == cur and '%' not in il:  # Intel: cur是目标
                    return self._trace_reg(instructions, j - 1, r2,
                                           rodata_refs, depth + 1)

            # 调用截断-fmt来自函数返回值
            if 'call' in il:
                return UNKNOWN, ""
        # 循环结束: 参数寄存器
        if cur in _ARG_REGS:
            return ARG, ""
        return UNKNOWN, ""

    def _trace_slot(self, instructions, from_idx, slot,
                    rodata_refs, depth) -> Tuple[str, str]:
        """栈槽写回溯源-立即数→常量; call写入→保持分类; 寄存器→继续。
        槽写可发生在lea之后call之前(lea rcx,[rsp+X]; mov [rsp+X],rax), 需前向扫描
        """
        # 前向: lea之后到call之前
        end = min(len(instructions), from_idx + 14)
        for j in range(from_idx + 1, end):
            if j >= len(instructions):
                break
            il = instructions[j].strip().lower()
            if not il or il.startswith((';', '.')):
                continue
            if 'call' in il:
                break
            m = _SLOT_STORE_IMM.match(il)
            if m and f"[{m.group(1)}{m.group(2)}]" == slot:
                return CONST_RODATA, self._imm_content(m.group(3))
            m = _SLOT_STORE_REG.match(il)
            if m and f"[{m.group(1)}{m.group(2)}]" == slot:
                return self._trace_reg(instructions, j - 1, m.group(3),
                                       rodata_refs, depth + 1)
        # 后向兜底
        for j in range(from_idx - 1, max(-1, from_idx - 20), -1):
            if j < 0:
                break
            il = instructions[j].strip().lower()
            if not il or il.startswith((';', '.')):
                continue
            m = _SLOT_STORE_IMM.match(il)
            if m and f"[{m.group(1)}{m.group(2)}]" == slot:
                return CONST_RODATA, self._imm_content(m.group(3))
            m = _SLOT_STORE_REG.match(il)
            if m and f"[{m.group(1)}{m.group(2)}]" == slot:
                return self._trace_reg(instructions, j - 1, m.group(3),
                                       rodata_refs, depth + 1)
            if 'call' in il:
                break
        return UNKNOWN, ""

    @staticmethod
    def _imm_source(imm: str, rodata_refs) -> Tuple[FmtSource, str]:
        try:
            addr = int(imm, 16) if '0x' in imm else int(imm)
        except ValueError:
            return UNKNOWN, ""
        if addr in rodata_refs:
            return CONST_RODATA, rodata_refs[addr][:80]
        if addr > 0x400000:
            return CONST_RODATA, ""   # 高地址→通常.rodata
        return HEAP, ""

    @staticmethod
    def _rodata_content(offset: str, rodata_refs) -> str:
        try:
            off = int(offset, 16)
        except ValueError:
            return ""
        for addr, content in rodata_refs.items():
            if abs(addr - off) < 0x10000:
                return content[:80]
        return ""

    @staticmethod
    def _imm_content(imm: str) -> str:
        """立即数(小端字节)转ASCII内容片段-用于短字符串常量"""
        try:
            v = int(imm, 16) if '0x' in imm else int(imm)
        except ValueError:
            return ""
        out = []
        for _ in range(8):
            byte = v & 0xFF
            if byte == 0:
                break
            if 0x20 <= byte <= 0x7E:
                out.append(chr(byte))
            else:
                return ""
            v >>= 8
        return ''.join(out)
