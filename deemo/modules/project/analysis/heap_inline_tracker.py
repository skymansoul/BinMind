# 堆溢出检测 — 内联写入追踪 + 跨函数溯源修正
# 铁律
# 职责: _track_inline_write (Pass 1内存写入记录),
#   _postprocess_call_provenance (跨函数调用边溯源修正),
#   _find_param_slot + _trace_reg_to_param_slot (参数栈槽位解析),
#   _find_early_return_guard (提前返回保护模式识别)
from __future__ import annotations
import re
from typing import Dict, List, Optional, Tuple

from .value_range import ValueRange
from .instruction_parser import InstructionParser


class InlineTrackerMixin:
    """堆溢出检测 — 内联写入与跨函数溯源层.

    以mixin形式注入 HeapOverflowDetector, 保持self._xxx访问.
    """

    def _track_inline_write(self, dst: str, src: str, idx: int, ctx: str,
                            raw_line: str = "", simd: bool = False):
        """在Pass 1中追踪内存写入, 记录当前存活的堆指针写入.

        仅在写入发生时检查指针溯源 (provenance), 避免Pass 2.5
        查询时provenance已被后续指令清除的问题.
        raw_line: 原始指令行 (parse_line 已剥除大小前缀, 立即数源
          的写入宽度只能从原始行获取).
        simd: SIMD 向量存储 (movups 等), 默认 16B 写入.
        """
        if not ('[' in dst or 'PTR' in dst.upper()):
            return
        write_size = 16 if simd else 1
        dst_clean = dst.strip()
        size_m = re.match(r'(BYTE|WORD|DWORD|QWORD)\s+PTR',
                          dst_clean, re.I)
        if not size_m and raw_line:
            # 原始行以 mov 等操作码开头, 须用 search 而非 match
            size_m = re.search(r'(BYTE|WORD|DWORD|QWORD)\s+PTR',
                               raw_line, re.I)
        if size_m:
            write_size = {'BYTE': 1, 'WORD': 2, 'DWORD': 4, 'QWORD': 8}.get(
                size_m.group(1).upper(), 1)
        else:
            src_clean = InstructionParser.clean_reg(src)
            if len(src_clean) <= 2:
                write_size = 1
            elif src_clean.endswith('l') and len(src_clean) == 3:
                write_size = 1
            elif src_clean.startswith('e'):
                write_size = 4
            else:
                write_size = 8

        clean = InstructionParser._SIZE_PREFIX_RE.sub('', dst_clean)
        if clean.startswith('[') and ']' in clean:
            inner = clean[1:clean.index(']')]
            if '+' in inner or '-' in inner:
                parts = re.split(r'([+\-])', inner)
                if parts:
                    m = re.match(r'(\w+)', parts[0].strip())
                    if m:
                        base_reg = m.group(1)
                    else:
                        return
            else:
                m = re.match(r'(\w+)', inner.strip())
                if m:
                    base_reg = m.group(1)
                else:
                    return
        else:
            return

        base_reg = InstructionParser.normalize_reg64(base_reg)
        if base_reg in ('rbp', 'rsp', 'ebp', 'esp'):
            return

        origin = self._prov.get_origin(base_reg)
        alloc_site_id = (origin.alloc_site_id
                         if (origin and origin.alloc_site_id != 'unknown')
                         else '')

        self._inline_writes.append({
            'idx': idx,
            'base_reg': base_reg,
            'write_size': write_size,
            'alloc_site_id': alloc_site_id,
            'offset_in_alloc': origin.offset_in_alloc if origin else 0,
            'function_name': self._current_func,
        })

    def _postprocess_call_provenance(self,
                                      instructions: List[str],
                                      func_map: Dict[str, Tuple[int, int]]):
        """修正跨函数调用边的inline write溯源.

        当callee在二进制中物理位置早于caller时, 线性扫描Pass 1会先处理
        callee再处理caller, 导致callee内部的堆指针写入无法获取caller
        传参 (rcx) 的溯源信息.

        利用Pass 1期间记录的_call_provenance_edges反向推导callee中
        依赖rcx参数的inline write并修正其alloc_site_id.
        """
        if not self._call_provenance_edges:
            return

        callee_edges: Dict[str, List[Dict]] = {}
        for edge in self._call_provenance_edges:
            callee_edges.setdefault(edge['target'], []).append(edge)

        for callee_name, edges in callee_edges.items():
            callee_range = func_map.get(callee_name)
            if not callee_range:
                continue
            callee_start, callee_end = callee_range

            param_slot = self._find_param_slot(
                instructions, callee_start, callee_end, 'rcx')
            edx_slot = self._find_param_slot(
                instructions, callee_start, callee_end, 'edx')
            if edx_slot is None:
                edx_slot = self._find_param_slot(
                    instructions, callee_start, callee_end, 'rdx')

            for edge in edges:
                edx_vr = edge.get('edx_value_range')
                if edx_vr is not None and edx_slot is not None and self._vd:
                    existing = self._vd.get_mem(edx_slot)
                    if existing.is_top:
                        self._vd.set_mem(edx_slot, edx_vr)

            caller_alloc_site = edges[0].get('alloc_site_id', '')
            if caller_alloc_site:
                for iw in self._inline_writes:
                    if not (callee_start <= iw['idx'] <= callee_end):
                        continue
                    existing = iw.get('alloc_site_id', '')
                    if existing and existing != 'unknown':
                        continue

                    if self._trace_reg_to_param_slot(
                        instructions, iw['idx'], iw['base_reg'],
                        callee_start, param_slot):
                        iw['alloc_site_id'] = caller_alloc_site
                        iw['provenance_resolved_by'] = \
                            'call_edge_postprocess'

    def _find_param_slot(self, instructions: List[str],
                          start: int, end: int, param_reg: str
                          ) -> Optional[int]:
        """在函数开头N条指令内查找参数寄存器的栈槽位.

        搜索模式: mov [rbp+offset], param_reg.
        返回 offset 值, 若未找到返回 None.
        """
        search_end = min(start + 10, end + 1)
        for i in range(start, search_end):
            line = instructions[i]
            m = re.search(
                r'mov\s+(?:QWORD|DWORD|WORD|BYTE)?\s*(?:PTR\s+)?'
                r'\[rbp([+\-]0x[0-9a-fA-F]+)\],\s*' + param_reg + r'\b',
                line, re.IGNORECASE)
            if m:
                sign = 1 if m.group(1)[0] == '+' else -1
                return sign * int(m.group(1)[1:], 16)
        return None

    def _trace_reg_to_param_slot(self, instructions: List[str],
                                   write_idx: int, base_reg: str,
                                   func_start: int,
                                   param_slot: Optional[int]
                                   ) -> bool:
        """反向追踪: 检查base_reg是否从param_slot加载.

        在write_idx向前搜索 (不超过func_start), 查找:
          mov base_reg, [rbp+param_slot]
        允许中间经过 add/sub 等指针算术.
        """
        if param_slot is None:
            return False
        base64 = InstructionParser.normalize_reg64(base_reg)
        current_reg = base64
        for i in range(write_idx - 1,
                       max(func_start, write_idx - 20) - 1, -1):
            line = instructions[i]
            parsed = self._parser.parse_line(line)
            if parsed is None:
                continue
            op, ops = parsed

            if op in ('mov', 'movsxd') and len(ops) >= 2:
                dst = ops[0].strip()
                src = ops[1].strip()
                dst64 = InstructionParser.normalize_reg64(
                    InstructionParser.clean_reg(dst))
                if dst64 == current_reg:
                    offset_str = f'{param_slot:+#x}'
                    offset_pattern = re.escape(offset_str)
                    if re.search(r'\[rbp' + offset_pattern + r'\]', src):
                        return True
                    if InstructionParser.is_reg(src):
                        src64 = InstructionParser.normalize_reg64(
                            InstructionParser.clean_reg(src))
                        current_reg = src64
                        continue
                    return False

            if op in ('add', 'sub') and len(ops) >= 2:
                dst = ops[0].strip()
                dst64 = InstructionParser.normalize_reg64(
                    InstructionParser.clean_reg(dst))
                if dst64 == current_reg:
                    continue

        return False

    @staticmethod
    def _find_early_return_guard(write_idx: int,
                                  instructions: List[str],
                                  size_reg: str) -> Optional[int]:
        """向后扫描写入点前N条指令, 寻找提前返回/终止的边界保护.

        模式: cmp X, imm; jcc — 若jcc指示X>imm则跳走,
        fallthrough路径上X≤imm, imm即为写入大小的实际上界.

        匹配 (二者任一):
        1. cmp的源寄存器 == size_reg (如cmp r8d, imm)
        2. cmp的源操作数 [rbp±X] 与 size_reg追溯的栈槽位相同
           (编译器将guard比较放在内存而memset参数放在寄存器中)

        规则2解决cmp [rbp-0xc],0x80与mov r8,[rbp-0xc]→call memset
        的寄存器间接匹配问题, 同时排除argc等无关变量的guard误关联.
        """
        scan_start = max(0, write_idx - 40)
        size_base = InstructionParser.normalize_reg64(
            InstructionParser.clean_reg(size_reg))
        traced_slot = InstructionParser.trace_reg_to_source_slot(
            write_idx, instructions, size_base)

        for i in range(write_idx - 1, scan_start, -1):
            line = instructions[i].strip()
            if not line:
                continue
            cleaned = InstructionParser._SIZE_PREFIX_RE.sub('', line)
            parts = cleaned.replace(',', ' ').split()
            if not parts:
                continue
            op = parts[0]

            if op in ('ja', 'jg', 'jae', 'jge', 'jbe', 'jle', 'jb', 'jl'):
                if i <= scan_start:
                    continue
                prev_line = instructions[i - 1].strip()
                prev_cleaned = InstructionParser._SIZE_PREFIX_RE.sub(
                    '', prev_line)
                prev_parts = prev_cleaned.replace(',', ' ').split()
                if not prev_parts or prev_parts[0] != 'cmp':
                    continue
                if len(prev_parts) < 3:
                    continue
                cmp_src = prev_parts[1]

                # 检查1: 寄存器直接匹配
                cmp_src_clean = InstructionParser.clean_reg(cmp_src)
                cmp_src64 = InstructionParser.normalize_reg64(cmp_src_clean)
                reg_match = (cmp_src64 == size_base)

                # 检查2: 内存槽位匹配
                cmp_slot = InstructionParser.parse_mem_slot(cmp_src)
                slot_match = (cmp_slot is not None
                              and cmp_slot == traced_slot)

                if not reg_match and not slot_match:
                    continue

                imm_val = InstructionParser.parse_immediate(prev_parts[-1])
                if imm_val is None:
                    continue
                if 0 < imm_val <= 0x10000:
                    return imm_val

        return None
