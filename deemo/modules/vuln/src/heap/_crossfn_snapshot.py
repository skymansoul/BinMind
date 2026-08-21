# 跨函数call site快照追踪 — 从cross_fn_analyzer.py拆分.
# 轻量寄存器+栈追踪, 提取每个call点的寄存器快照.

import re
from typing import Dict, List, Optional

from .insn_parser import Instruction, extract_register

_ARG_REGS = ['rcx', 'rdx', 'r8', 'r9']


class CrossFnSnapshotMixin:
    """call site寄存器快照追踪, 由CrossFnAnalyzer继承."""

    def _snapshot_call_sites(self, fn_name: str,
                              insns: List[Instruction],
                              entry_bindings: Optional[Dict[str, object]] = None
                              ) -> List[dict]:
        """轻量寄存器+栈追踪, 提取每个call点的寄存器快照."""
        reg_val: Dict[str, object] = {}
        stack_map: Dict[str, object] = {}
        for i, reg in enumerate(_ARG_REGS, 1):
            arg_key = f"arg{i}"
            if entry_bindings and arg_key in entry_bindings:
                reg_val[reg] = entry_bindings[arg_key]
            else:
                reg_val[reg] = arg_key

        for insn in insns[:12]:
            if insn.mnemonic not in ('mov', 'movsxd'):
                continue
            parts = insn.operands.split(',')
            dst, src = parts[0].strip(), parts[-1].strip()
            src_r = extract_register(src)
            off = self._stack_offset(dst)
            if off and src_r and src_r in reg_val:
                stack_map[off] = reg_val[src_r]

        def _parse_int(s: str):
            try: return int(s, 0)
            except ValueError: return None

        rax_pending = None
        snapshots = []
        for insn in insns:
            mn = insn.mnemonic
            op = insn.operands
            dst = op.split(',')[0].strip() if ',' in op else ''
            src = op.split(',')[-1].strip() if ',' in op else ''
            dst_reg = extract_register(dst)
            src_reg = extract_register(src)

            if mn == 'call':
                if rax_pending is not None:
                    reg_val['rax'] = rax_pending
                    rax_pending = None
                target = op.strip()
                m = re.search(r'<([^+>]+)', target)
                callee = m.group(1) if m else target
                bindings = {}
                for i, reg in enumerate(_ARG_REGS, 1):
                    if reg_val.get(reg) is not None:
                        bindings[f"arg{i}"] = reg_val[reg]
                snapshots.append({
                    'addr': insn.addr, 'callee': callee,
                    'arg_bindings': bindings})
                alloc_name = None
                for kw in ('malloc', 'calloc', 'realloc', 'strdup'):
                    if callee == kw:
                        alloc_name = kw
                        break
                if alloc_name:
                    rax_pending = f"{alloc_name}@{insn.addr:x}"
                elif callee in self._fn_return_vals:
                    rax_pending = self._fn_return_vals[callee]
                if callee == 'free':
                    free_v = reg_val.get('rcx')
                    if self._is_heap_ptr(free_v):
                        self._resolved_free_vals[(fn_name, insn.addr)] = free_v
                for r in ('rcx','rdx','r8','r9','r10','r11'):
                    reg_val.pop(r, None)
                continue

            if rax_pending is not None:
                reg_val['rax'] = rax_pending
                rax_pending = None

            if mn in ('mov','movsxd','movzx','movsx'):
                if '[' in dst:
                    off = self._stack_offset(dst)
                    if off and src_reg and src_reg in reg_val:
                        stack_map[off] = reg_val[src_reg]
                    self._track_global_store(dst, src_reg, reg_val, insn)
                    self._track_field_store(dst, src_reg, reg_val)
                    self._capture_write_resolution(dst, fn_name, insn, reg_val)
                    continue
                if '[' in src:
                    off = self._stack_offset(src)
                    if off and off in stack_map:
                        if dst_reg:
                            reg_val[dst_reg] = stack_map[off]
                    self._track_global_load(src, dst_reg, reg_val, insn)
                    self._track_field_load(src, dst_reg, reg_val)
                    continue
                if dst_reg and src_reg and src_reg in reg_val:
                    reg_val[dst_reg] = reg_val[src_reg]
                elif dst_reg and not src_reg:
                    reg_val.pop(dst_reg, None)
            elif mn in ('add','sub'):
                sv = _parse_int(src)
                if dst_reg and sv is not None:
                    cur = reg_val.get(dst_reg)
                    if isinstance(cur, int):
                        reg_val[dst_reg] = cur + sv if mn == 'add' else max(0, cur - sv)
                    elif isinstance(cur, str) and 'malloc' in str(cur) and mn == 'add':
                        reg_val[dst_reg] = f"{cur}+{sv}"
            elif mn in ('xor','pxor'):
                if dst_reg and src_reg and dst_reg == src_reg:
                    reg_val[dst_reg] = 0
            elif mn == 'lea' and dst_reg:
                reg_val.pop(dst_reg, None)

        final_rax = reg_val.get('rax')
        if self._is_heap_ptr(final_rax):
            self._fn_return_vals[fn_name] = final_rax
        return snapshots
