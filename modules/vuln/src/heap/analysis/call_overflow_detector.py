"""函数调用型堆溢出检测器 — memcpy/memset/strcpy 等隐式内存写入.

创建: 2025-05-12
修改: 2025-05-12 (dest偏移追踪: memset(p+60,32) 类偏移溢出)

检测策略:
  1. 追踪 malloc 返回值 (rax) 的去向 — 记录到栈槽或寄存器
  2. 遇到 mem_write call 时, 反向追踪 dest 参数是否来自 malloc
  3. 追踪 dest 偏移量 (add reg, imm) + size, 若 offset+size > usable → 溢出

调用约定: MS x64 (rcx=arg0) 和 System V (rdi=arg0) 双支持.
"""
from __future__ import annotations

import re as _re
from typing import Dict, List, Optional, Tuple

from .interval_domain import SInterval, AllocatorModel, DEFAULT_ALLOCATOR
from .malloc_size_inferrer import MallocSite, MallocSizeInferrer
from .access_parser import (
    identify_mem_write_calls, trace_call_arg_value,
    get_call_arg_reg, _MEM_WRITE_FUNCS, _canon_reg)
from .semantic_fp_filter import SemanticFalsePositiveFilter, SemanticFeatures


class CallOverflowDetector:
    """函数调用型堆溢出检测 — memcpy/memset/strcpy 等隐式写入."""

    def __init__(self, size_inferrer: MallocSizeInferrer,
                 fp_filter: SemanticFalsePositiveFilter):
        self._size_inferrer = size_inferrer
        self._fp_filter = fp_filter

    def scan(self, instructions: List[str],
             malloc_sites: Dict[int, MallocSite],
             function_name: str,
             guards: Optional[List] = None) -> List:
        """扫描函数调用型溢出, 返回 HeapOverflowFinding 列表."""
        from .heap_overflow_detector import HeapOverflowFinding

        findings = []
        alloc_rax_track = self._track_malloc_returns(
            instructions, malloc_sites)
        if not alloc_rax_track:
            return findings

        mem_call_sites = identify_mem_write_calls(instructions)
        if not mem_call_sites:
            return findings

        for call_idx, func_name in mem_call_sites:
            func_info = _MEM_WRITE_FUNCS.get(func_name, {})
            dest_idx = func_info.get('dest_idx', 0)
            size_idx = func_info.get('size_idx', 2)
            if size_idx < 0:
                continue  # strcpy/strcat: 无显式 size

            dest_trace = self._trace_dest_to_malloc(
                instructions, call_idx, dest_idx, alloc_rax_track)
            if dest_trace is None:
                continue
            dest_site, dest_offset = dest_trace

            copy_size, size_desc = self._trace_size(
                instructions, call_idx, func_name, size_idx)
            if copy_size <= 0:
                continue

            # 关键: offset+size vs usable — memset(p+60,32) 有效范围[60,92)
            usable_lo, _ = self._size_inferrer.usable_range(dest_site)
            effective_end = dest_offset + copy_size
            if effective_end <= usable_lo:
                continue

            overflow = effective_end - usable_lo
            ctx = self._build_call_context(
                instructions, call_idx, dest_site,
                guards=guards, function_name=function_name)
            features = self._fp_filter.extract_features(
                dest_site, dest_offset, copy_size, ctx)
            sem_score = self._fp_filter.score(features)
            is_fp = self._fp_filter.is_likely_fp(features)

            offset_desc = (f' dest_offset={dest_offset}'
                           if dest_offset > 0 else '')
            finding = HeapOverflowFinding(
                insn_addr=call_idx, function_name=function_name,
                description=(
                    f'heap overflow via {func_name}:{offset_desc}'
                    f' copy_size={copy_size} '
                    f'effective={dest_offset}+{copy_size}={effective_end}'
                    f' exceeds alloc={usable_lo} '
                    f'at {function_name}:0x{call_idx:x}'),
                alloc_site=dest_site.insn_addr,
                alloc_size_requested=dest_site.size_interval.min_possible(),
                alloc_size_usable=usable_lo,
                access_offset=dest_offset,
                access_size=copy_size,
                overflow_bytes=overflow,
                semantic_score=sem_score,
                is_likely_fp=is_fp,
                fp_reason=(self._fp_filter._explain(features, sem_score)
                           if is_fp else ""),
                confidence=sem_score,
                size_source=(
                    f'mem_write:{func_name}(size={copy_size},'
                    f'alloc={dest_site.size_interval.lo},{size_desc})'),
            )
            findings.append(finding)

        return findings

# malloc 返回值追踪

    def _track_malloc_returns(self, instructions: List[str],
                               malloc_sites: Dict[int, MallocSite]
                               ) -> Dict[str, MallocSite]:
        """追踪 malloc 返回值 (rax) 的去向.

        扫描每个 call malloc 之后 15 条指令, 记录:
          stack:{slot} ← mov [rbp±N], rax
          reg:{reg}   ← mov reg, rax
        """
        track: Dict[str, MallocSite] = {}
        for call_idx, site in malloc_sites.items():
            if call_idx < 0:       # 合成 MallocSite (跨函数) — 无对应 call 指令
                continue
            for j in range(call_idx + 1,
                           min(call_idx + 15, len(instructions))):
                il = instructions[j].strip().lower()
                if not il or il.startswith(';'):
                    continue
                if 'call' in il:
                    break

                m = _re.match(
                    r'mov\s+(?:qword\s+ptr\s+)?\[rbp\s*([+\-])\s*'
                    r'(0x[0-9a-f]+|\d+)\],\s*rax\s*$', il, _re.I)
                if m:
                    sign = 1 if m.group(1) == '+' else -1
                    slot = sign * int(m.group(2), 16
                                      if '0x' in m.group(2) else 10)
                    track[f'stack:{slot}'] = site
                    continue

                m = _re.match(r'mov\s+(\w+),\s*rax\s*$', il, _re.I)
                if m:
                    dst = _canon_reg(m.group(1))
                    if dst not in ('rbp', 'rsp', 'rip'):
                        track[f'reg:{dst}'] = site
        return track

# dest 参数追踪 (含偏移量)

    def _trace_dest_to_malloc(self, instructions: List[str],
                               call_idx: int, dest_arg_idx: int,
                               alloc_rax_track: Dict[str, MallocSite]
                               ) -> Optional[Tuple[MallocSite, int]]:
        """追踪 dest 参数 → malloc 缓冲区, 返回 (site, offset) 或 None.

        增强: 追踪 dest = malloc_ptr + K 中的偏移 K.
        对 memset(p+60, 32) 至关重要 — 偏移+大小联合判断越界.
        """
        for convention, regs in [('ms64', ['rcx', 'ecx']),
                                  ('sysv', ['rdi', 'edi'])]:
            dest_reg = regs[0] if dest_arg_idx < len(regs) else regs[0]
            canon_dest = _canon_reg(dest_reg)

            for i in range(call_idx - 1, max(-1, call_idx - 10), -1):
                il = instructions[i].strip().lower()
                if not il or il.startswith(';'):
                    continue
                if 'call' in il:
                    break

                # 模式A: mov dest_reg, rax → 检查前序 add rax, imm
                if _re.match(r'mov\s+' + _re.escape(canon_dest) +
                            r'\s*,\s*rax\s*$', il, _re.I):
                    offset = self._trace_offset(
                        instructions, i, 'rax', backward=True)
                    for _k, site in alloc_rax_track.items():
                        return (site, offset)

                # 模式B: mov dest_reg, [rbp±N] → 查栈槽 + 前向偏移
                m = _re.match(
                    r'mov\s+' + _re.escape(canon_dest) +
                    r'\s*,\s*(?:qword\s+ptr\s+)?\[rbp\s*([+\-])\s*'
                    r'(0x[0-9a-f]+|\d+)\]', il, _re.I)
                if m:
                    sign = 1 if m.group(1) == '+' else -1
                    slot = sign * int(m.group(2), 16
                                      if '0x' in m.group(2) else 10)
                    slot_key = f'stack:{slot}'
                    if slot_key in alloc_rax_track:
                        offset = self._trace_offset(
                            instructions, i, canon_dest, backward=False)
                        return (alloc_rax_track[slot_key], offset)

                # 模式C: movsxd dest_reg, eax
                if _re.match(r'movsxd\s+' + _re.escape(canon_dest) +
                            r'\s*,\s*eax\s*$', il, _re.I):
                    offset = self._trace_offset(
                        instructions, i, 'rax', backward=True)
                    for _k, site in alloc_rax_track.items():
                        return (site, offset)

        return None

    def _trace_offset(self, instructions: List[str], start_idx: int,
                      target_reg: str, backward: bool = True) -> int:
        """追踪 target_reg 的 add/sub 常量偏移.

        backward=True: 从 start_idx 往前找 (mov rcx, rax 前有 add rax, K).
        backward=False: 从 start_idx 往后找 (mov rcx, [rbp-N] 后有 add rcx, K).
        """
        canon = _canon_reg(target_reg)
        step, end = (-1, max(-1, start_idx - 5)) if backward else (
            1, min(len(instructions), start_idx + 6))
        rng = range(start_idx + step, end, step)

        for j in rng:
            il = instructions[j].strip().lower()
            if not il or il.startswith(';') or 'call' in il:
                break
            m = _re.match(r'(add|sub)\s+' + _re.escape(canon) +
                         r'\s*,\s*(0x[0-9a-f]+|\d+)\s*$', il, _re.I)
            if m:
                v = int(m.group(2), 16 if '0x' in m.group(2) else 10)
                return -v if m.group(1) == 'sub' else v
            m = _re.match(r'lea\s+' + _re.escape(canon) +
                         r'\s*,\s*\[\w+\s*\+\s*(0x[0-9a-f]+|\d+)\]',
                         il, _re.I)
            if m:
                return int(m.group(1), 16 if '0x' in m.group(1) else 10)
        return 0

# size 参数追踪

    def _trace_size(self, instructions: List[str], call_idx: int,
                    func_name: str, size_idx: int) -> Tuple[int, str]:
        """追踪 mem_write 函数的 size 参数值.

        同时尝试 MS x64 和 System V 调用约定, 选已知的那个.
        """
        size_reg_ms = get_call_arg_reg(func_name, size_idx, 'ms64')
        size_reg_sv = get_call_arg_reg(func_name, size_idx, 'sysv')
        known_ms = known_sv = False
        val_ms = val_sv = 0
        desc_ms = desc_sv = ''

        if size_reg_ms:
            known_ms, val_ms, desc_ms = trace_call_arg_value(
                instructions, call_idx, size_reg_ms)
        if size_reg_sv:
            known_sv, val_sv, desc_sv = trace_call_arg_value(
                instructions, call_idx, size_reg_sv)

        if known_ms and known_sv:
            return val_ms, desc_ms  # PE 优先 MS64
        elif known_ms:
            return val_ms, desc_ms
        elif known_sv:
            return val_sv, desc_sv
        return 0, 'unknown'

    def _build_call_context(self, instructions: List[str],
                             call_idx: int,
                             site: MallocSite,
                             guards: Optional[List] = None,
                             function_name: str = '') -> dict:
        """为函数调用型溢出构建语义上下文.

        委托 detector_context.build_context 进行动态特征提取,
        传入 instructions/guards/function_name 以替代静态硬编码.
        """
        from .detector_context import build_context
        return build_context(
            instructions, call_idx, site, offset=0,
            guards=guards, function_name=function_name)
