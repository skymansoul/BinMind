# 跨函数内存值映射追踪 — 从cross_fn_analyzer.py拆分.
# 包含全局变量/结构体字段/栈槽的值传播辅助方法.
# 创建: 2026-06-20

import re
from typing import Dict, Optional


class CrossFnMemMixin:
    """内存值追踪辅助方法, 由CrossFnAnalyzer继承."""

    @staticmethod
    def _stack_offset(operand: str) -> Optional[str]:
        """提取栈偏移量规范表示. 'qword ptr [rbp-0x20]' → 'rbp-0x20'."""
        m = re.search(r'\[(rbp[+-]0x[0-9a-fA-F]+)\]', operand)
        return m.group(1) if m else None

    @staticmethod
    def _is_heap_ptr(v) -> bool:
        """检查值是否表示堆分配 (malloc@/calloc@/realloc@/strdup@)."""
        if not isinstance(v, str):
            return False
        return any(kw in v for kw in ('malloc', 'calloc', 'realloc', 'strdup'))

    @staticmethod
    def _rip_offset(operand: str) -> Optional[str]:
        """提取RIP相对偏移. '[rip+0xNNNN]' → 'rip+0xNNNN'."""
        m = re.search(r'\[rip\s*([+-]\s*0x[0-9a-fA-F]+)\]', operand)
        return m.group(0) if m else None

    @staticmethod
    def _comment_addr(insn) -> Optional[str]:
        """从 objdump 注释提取绝对地址."""
        m = re.search(r'#\s*([0-9a-fA-F]+)\b', insn.raw)
        return m.group(1).lower() if m else None

    @staticmethod
    def _mem_base_offset(operand: str):
        """从内存操作数提取 (base_reg, offset).
        '[rax+0x10]' → ('rax', 16), '[rdx]' → ('rdx', 0)."""
        m = re.search(
            r'\[([a-z][a-z0-9]*)\s*(?:([+-])\s*(0x[0-9a-fA-F]+|\d+))?\]',
            operand)
        if not m:
            return None, None
        base = m.group(1).lower()
        _ALIASES = {'eax': 'rax', 'ecx': 'rcx', 'edx': 'rdx', 'ebx': 'rbx',
                    'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
                    'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10', 'r11d': 'r11'}
        base = _ALIASES.get(base, base)
        try:
            off_str = (m.group(2) or '') + (m.group(3) or '')
            offset = int(off_str, 0) if off_str else 0
        except ValueError:
            offset = 0
        return base, offset

    def _track_global_store(self, dst: str, src_reg,
                            reg_val: dict, insn) -> None:
        """mov [rip+0xNNNN], reg → 若 reg 有 malloc 值, 记录到全局映射."""
        rip = self._rip_offset(dst)
        if not rip or not src_reg or src_reg not in reg_val:
            return
        v = reg_val[src_reg]
        if self._is_heap_ptr(v):
            key = self._comment_addr(insn) or rip
            self._global_map[key] = v

    def _track_global_load(self, src: str, dst_reg,
                           reg_val: dict, insn) -> None:
        """mov reg, [rip+0xNNNN] → 若全局映射中有值, 恢复到 reg_val."""
        rip = self._rip_offset(src)
        if not rip or not dst_reg:
            return
        key = self._comment_addr(insn) or rip
        if key in self._global_map:
            reg_val[dst_reg] = self._global_map[key]

    def _track_field_store(self, dst: str, src_reg, reg_val: dict) -> None:
        """mov [base_reg+NN], src_reg → 记录 (base_val, offset) → src_val."""
        base, off = self._mem_base_offset(dst)
        if not base or not src_reg or src_reg not in reg_val:
            return
        base_val = reg_val.get(base)
        src_val = reg_val[src_reg]
        if (self._is_heap_ptr(base_val) and self._is_heap_ptr(src_val)):
            self._field_map[(base_val, off)] = src_val

    def _track_field_load(self, src: str, dst_reg, reg_val: dict) -> None:
        """mov dst_reg, [base_reg+NN] → 若字段映射中有值, 恢复到 reg_val."""
        base, off = self._mem_base_offset(src)
        if not base or not dst_reg:
            return
        base_val = reg_val.get(base)
        if not base_val:
            return
        key = (str(base_val), off)
        if key in self._field_map:
            reg_val[dst_reg] = self._field_map[key]

    def _capture_write_resolution(self, dst: str, fn_name: str,
                                   insn, reg_val: dict) -> None:
        """若内存写 [base_reg+off] 的 base_reg 持有 malloc 值, 记录解析."""
        base, _ = self._mem_base_offset(dst)
        if not base or base not in reg_val:
            return
        bv = reg_val[base]
        if self._is_heap_ptr(bv):
            self._resolved_write_vals[(fn_name, insn.addr)] = bv
