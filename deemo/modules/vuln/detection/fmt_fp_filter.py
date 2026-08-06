# -*- coding: utf-8 -*-
# 格式字符串误报过滤——验证污点路径的实际可达性
import re, logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
_log = logging.getLogger(__name__)

@dataclass
class FmtFilterResult:
    confirmed: List = field(default_factory=list)
    filtered: List = field(default_factory=list)
    fp_reduction_pct: float = 0.0

class FormatStringFpFilter:
    """格式字符串误报过滤器——双重验证污点路径。

    Layer 1: .rodata地址检测——若格式参数地址在只读段, 安全。
    Layer 2: 指令间寄存器清除检测——若污点寄存器在printf之前被xor清零, 污点不可达。
    Layer 3: 安全包装检测——若格式串经过snprintf/asprintf限制大小, 风险降低。

    与constraint_filter的关系: constraint_filter做数值约束过滤, 本模块做格式特定的逻辑过滤。
    """

    def filter(self, instructions, fmt_candidates, rodata_ranges=None):
        if rodata_ranges is None:
            rodata_ranges = [(0x400000, 0x4FFFFF)]
        result = FmtFilterResult()
        if not fmt_candidates: return result

        for cand in fmt_candidates:
            call_idx = getattr(cand, 'call_idx', -1)
            call_addr = getattr(cand, 'call_address', 0)
            is_vuln = getattr(cand, 'is_vulnerable', True)
            conf = getattr(cand, 'confidence', 0.5)
            fmt_arg = getattr(cand, 'fmt_arg', '')

            if call_idx < 0:
                # 尝试通过地址定位
                call_idx = self._find_call_idx(instructions, call_addr)

            reasons = []

            # Layer 1: .rodata检测
            if self._is_rodata(fmt_arg, rodata_ranges):
                result.filtered.append((call_idx, '格式串在.rodata段, 安全'))
                continue

            # Layer 2: 寄存器清除检测
            if call_idx >= 0 and self._is_taint_cleared(instructions, call_idx):
                result.filtered.append((call_idx, '污点寄存器在printf前被清除'))
                continue

            # Layer 3: 安全包装
            if call_idx >= 0 and self._has_safe_wrapper(instructions, call_idx):
                result.filtered.append((call_idx, '经过snprintf安全包装'))
                continue

            result.confirmed.append(call_idx)

        t = len(result.confirmed) + len(result.filtered)
        result.fp_reduction_pct = round(len(result.filtered) / max(t, 1) * 100, 1)
        return result

    def _is_rodata(self, fmt_arg, ranges):
        if not fmt_arg: return False
        try:
            addr = int(fmt_arg, 16) if fmt_arg.startswith('0x') else None
        except (ValueError, TypeError): addr = None
        if addr is None: return False
        for lo, hi in ranges: 
            if lo <= addr <= hi: return True
        return False

    def _is_taint_cleared(self, insns, call_idx):
        for j in range(call_idx - 1, max(-1, call_idx - 10), -1):
            insn = insns[j].lower().strip()
            if ':' in insn[:20]: insn = insn.split(':', 1)[1].strip()
            if 'xor rdi, rdi' in insn or 'xor rdi,rdi' in insn:
                return True
            if 'mov rdi, 0' in insn or 'xor edi, edi' in insn:
                return True
        return False

    def _has_safe_wrapper(self, insns, call_idx):
        for j in range(call_idx - 1, max(-1, call_idx - 5), -1):
            insn = insns[j].lower().strip()
            if ':' in insn[:20]: insn = insn.split(':', 1)[1].strip()
            if 'snprintf' in insn or 'asprintf' in insn or 'vsnprintf' in insn:
                return True
        return False

    def _find_call_idx(self, insns, addr):
        if not addr: return -1
        for i, insn in enumerate(insns):
            s = insn.strip()
            if ':' in s[:20]:
                try:
                    if int(s.split(':')[0], 16) == addr: return i
                except ValueError: pass
        return -1

__all__ = ['FmtFilterResult', 'FormatStringFpFilter']
