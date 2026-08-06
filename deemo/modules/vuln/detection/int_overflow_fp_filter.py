# -*- coding: utf-8 -*-
# 整数溢出误报过滤——验证溢出结果是否流向malloc/memcpy等危险操作
import re, logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
_log = logging.getLogger(__name__)

@dataclass
class IntOverflowFpResult:
    confirmed: List = field(default_factory=list)
    filtered: List = field(default_factory=list)
    fp_reduction_pct: float = 0.0

class IntOverflowFpFilter:
    """整数溢出误报过滤器——仅保留溢出结果流向危险操作的候选。

    逻辑: 整数溢出本身不构成漏洞——只有当溢出结果被用作
    malloc参数或memcpy的size参数时才形成可利用漏洞。
    若溢出指令的目标寄存器在后续未被用于危险操作→滤除。

    危险操作: malloc(size)/calloc(n,size)/memcpy(,,size)/realloc(,size)
    追踪: 溢出指令的目标寄存器→后续mov传递→危险操作的参数寄存器
    """
    _DANGER_SINKS = {'malloc', 'calloc', 'realloc', 'memcpy', 'memmove', 'alloca'}

    # 32位→64位寄存器映射
    _R32_TO_64 = {'eax':'rax','ebx':'rbx','ecx':'rcx','edx':'rdx','esi':'rsi','edi':'rdi'}

    def filter(self, instructions, io_candidates):
        result = IntOverflowFpResult()
        if not io_candidates: return result

        for cand in io_candidates:
            overflow_reg = self._extract_dst_reg(cand)
            if not overflow_reg:
                result.filtered.append((cand.location, '无法提取目标寄存器'))
                continue

            # 溢出寄存器的所有可能名称 (32位+64位变体)
            reg64 = self._R32_TO_64.get(overflow_reg, overflow_reg)
            reg_variants = {overflow_reg, reg64}

            reaches_sink = False; sink_info = ''
            for i, insn in enumerate(instructions):
                mnem, ops = self._parse(insn)
                if mnem != 'call': continue
                callee = self._callee(insn)
                if not callee: continue
                matched = None
                for ds in self._DANGER_SINKS:
                    if ds in callee: matched = ds; break
                if not matched: continue

                arg_regs = ['rdi', 'rsi', 'rdx', 'rcx']
                arg_regs32 = ['edi', 'esi', 'edx', 'ecx']
                for arg_idx, (arg64, arg32) in enumerate(zip(arg_regs, arg_regs32)):
                    linked = False
                    for j in range(i - 1, max(-1, i - 10), -1):
                        insn2 = instructions[j].lower().strip()
                        if ':' in insn2[:20]: insn2 = insn2.split(':', 1)[1].strip()
                        for reg_v in reg_variants:
                            for arg_v in (arg64, arg32):
                                if f'mov {arg_v}, {reg_v}' in insn2:
                                    linked = True; break
                            if linked: break
                        if linked: break
                    if linked:
                        reaches_sink = True
                        sink_info = f'{matched}(arg{arg_idx})'
                        break
                if reaches_sink: break

            if reaches_sink:
                result.confirmed.append((cand.location, sink_info))
            else:
                result.filtered.append((cand.location, f'溢出寄存器{overflow_reg}未流向危险操作'))

        t = len(result.confirmed) + len(result.filtered)
        result.fp_reduction_pct = round(len(result.filtered) / max(t, 1) * 100, 1)
        return result

    def _extract_dst_reg(self, cand):
        # 优先使用显式dst_reg字段
        dr = getattr(cand, 'dst_reg', '')
        if dr: return dr
        # 回退——从operation字符串解析
        op = getattr(cand, 'operation', '')
        m = re.match(r'(add|mul|shl)\s+(\w+)', op)
        if m: return m.group(2)
        return ''

    def _parse(self, insn):
        s = insn.strip()
        if ':' in s[:20]: s = s.split(':', 1)[1].strip()
        p = s.split(None, 1)
        return (p[0].lower(), []) if len(p) < 2 else (p[0].lower(), [o.strip() for o in p[1].split(',')])

    def _callee(self, insn):
        s = insn.strip()
        if ':' in s[:20]: s = s.split(':', 1)[1].strip()
        p = s.split()
        return p[1].lower().split('@')[0] if len(p) >= 2 and p[0].lower() == 'call' else ''

__all__ = ['IntOverflowFpResult', 'IntOverflowFpFilter']
