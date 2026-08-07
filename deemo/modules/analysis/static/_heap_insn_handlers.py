# 堆溢出检测器指令处理器.
# 包含mov/rep_movs/inline_sse/direct_write的指令级分析.
# 创建: 2026-05-11

import re
from typing import List, Optional, Tuple

from .disasm_util import norm_reg, extract_stack_slot, is_32bit_reg
from .heap_constraint import Interval


class HeapInsnHandlerMixin:
    """mov/rep_movs/sse/direct_write指令处理, 由HeapOverflowDetector继承."""

    def _handle_rep_movs(self, ins: dict, ops: List[str], addr: int):
        """检测rep movs系列指令作为内联memcpy."""
        if not self._is_user_code(addr):
            return
        first_op = ops[0].lower()
        elem_size = 4
        if "byte" in first_op or first_op == "movsb":
            elem_size = 1
        elif "dword" in first_op or first_op == "movsd":
            elem_size = 4
        elif "qword" in first_op or first_op == "movsq":
            elem_size = 8
        elif "word" in first_op or first_op == "movsw":
            elem_size = 2

        dst_reg = "rdi"
        ecx_vr = self._get_precise_range(addr, "ecx")
        if ecx_vr and not ecx_vr.is_bottom and ecx_vr.hi < 2**31:
            total_bytes = ecx_vr.hi * elem_size
            size_iv = Interval(total_bytes, total_bytes)
        elif ecx_vr and not ecx_vr.is_bottom:
            size_iv = Interval(
                max(0, ecx_vr.lo * elem_size),
                min(ecx_vr.hi * elem_size, 2**31 - 1))
        else:
            size_iv = Interval(0, 2**31 - 1)

        result = self._alloc_tracker.track_write(addr, size_iv, dst_reg)
        if result:
            result["size_operand"] = "ecx"
            result["ptr_operand"] = dst_reg
            result["dangerous_func"] = "inline_memcpy"
            alloc_entry = self._alloc_tracker._ptr_to_alloc.get(dst_reg)
            if alloc_entry is not None:
                result["_snapshot_alloc_addr"] = alloc_entry
                alloc = self._alloc_tracker._allocations.get(alloc_entry)
                if alloc:
                    raw_size = getattr(alloc, 'raw_alloc_size',
                                       alloc.alloc_size)
                    result["alloc_size"] = raw_size.hi
            if result.get("alloc_size", 0) > 0:
                ok, reason = self._alloc_model.is_overflow(
                    result["alloc_size"],
                    result.get("write_size", size_iv.hi))
                if not ok:
                    result["alloc_model_safe"] = True
                    result["alloc_model_reason"] = reason
            if alloc_entry and not self._is_user_code(alloc_entry):
                return
            self._raw_findings.append(result)

    def _handle_inline_sse_store(self, ins: dict, ops: List[str],
                                  addr: int):
        """检测内联SSE存储 — 若目标为堆指针则检查溢出."""
        if len(ops) < 2 or not self._is_user_code(addr):
            return
        dst_op = ops[0].strip()
        base_reg, offset = self._parse_mem_base_offset(dst_op)
        if base_reg is None:
            return
        alloc_addr = self._alloc_tracker._ptr_to_alloc.get(base_reg)
        if alloc_addr is None:
            return
        alloc = self._alloc_tracker._allocations.get(alloc_addr)
        if alloc is None:
            return
        raw_size = getattr(alloc, 'raw_alloc_size', alloc.alloc_size)
        write_end = offset + 16
        if write_end <= raw_size.lo:
            return
        alloc.write_sites.append((addr, Interval(offset, write_end)))
        overflow = write_end - raw_size.hi
        result = {
            "type": "heap_overflow",
            "alloc_addr": alloc.alloc_site,
            "alloc_size": raw_size.hi,
            "write_addr": addr,
            "write_size": write_end,
            "overflow_bytes": overflow,
            "severity": "critical" if overflow > 64 else "high",
            "size_operand": "xmm",
            "ptr_operand": base_reg,
            "dangerous_func": "inline_sse_memcpy",
            "_snapshot_alloc_addr": alloc_addr,
            "alloc_size_interval": f"[{raw_size.lo},{raw_size.hi}]",
        }
        if alloc_addr and not self._is_user_code(alloc_addr):
            return
        self._raw_findings.append(result)

    @staticmethod
    def _parse_mem_base_offset(op: str) -> Tuple[Optional[str], int]:
        """解析内存操作数, 返回(基址寄存器, 偏移量)."""
        op_clean = op.lower().replace(' ', '')
        m = re.search(r'\[([a-z][a-z0-9]*)([+-]0x[0-9a-f]+)?\]', op_clean)
        if not m:
            return None, 0
        base_reg = m.group(1)
        offset_str = m.group(2)
        offset = 0
        if offset_str:
            sign = -1 if offset_str.startswith('-') else 1
            offset = sign * int(offset_str.lstrip('+-'), 16)
        return base_reg, offset

    def _handle_lea(self, ins: dict, ops: List[str], addr: int):
        """lea dst, [base+offset] — 指针算术, 传播堆溯源.

        lea rcx, [rax+0x20] 表示 rcx = 堆指针 + 0x20, 指向同一
        分配的字段/元素. ptr_map 保持同一 alloc, 偏移由后续
        write 检查与 alloc_size 比较时统一处理.
        """
        if len(ops) < 2:
            return
        dst_reg = norm_reg(ops[0])
        base_reg, offset = self._parse_mem_base_offset(ops[1])
        if base_reg is None:
            return
        ptr_map = self._alloc_tracker._ptr_to_alloc
        if base_reg in ptr_map:
            ptr_map[dst_reg] = ptr_map[base_reg]
        else:
            ptr_map.pop(dst_reg, None)
        self._struct_infer.feed_memory_access(ins, dst_reg)

    def _handle_shift_const(self, ins: dict, ops: List[str], addr: int):
        """shl/sal/shr/sar dst, imm — 常量表更新 (移位乘法/除法).

        shl eax, 2 = eax * 4. 常量传播对分配大小解析至关重要:
        size = n*4 的模式经 shl 实现, 若不传播则分配大小未知.
        """
        if len(ops) < 2:
            return
        dst_raw = ops[0].strip()
        dst_reg = norm_reg(dst_raw)
        shift_src = ops[1].strip().lstrip("$").split("#")[0].strip()
        try:
            shift = int(shift_src, 16) if shift_src.startswith("0x") \
                else int(shift_src)
        except ValueError:
            return
        cur = self._known_constants.get(dst_reg)
        if cur is not None:
            if self._is_shift_left(ins):
                self._known_constants[dst_reg] = cur << shift
            else:
                self._known_constants[dst_reg] = cur >> shift
            # 32位回绕
            if is_32bit_reg(dst_raw):
                self._known_constants[dst_reg] &= 0xFFFFFFFF

    def _handle_arith_const(self, ins: dict, ops: List[str], addr: int):
        """add/sub dst, imm — 常量表更新."""
        if len(ops) < 2:
            return
        dst_raw = ops[0].strip()
        dst_reg = norm_reg(dst_raw)
        src = ops[1].strip().lstrip("$").split("#")[0].strip()
        val = None
        if src.startswith("0x"):
            val = int(src, 16)
        elif src.isdigit():
            val = int(src)
        elif src.startswith("-") and src[1:].isdigit():
            val = int(src)
        if val is None:
            return
        mnem = ins.get("mnemonic", "").lower()
        if mnem == "add":
            self._known_constants[dst_reg] = \
                self._known_constants.get(dst_reg, 0) + val
        else:
            self._known_constants[dst_reg] = \
                self._known_constants.get(dst_reg, 0) - val
        if is_32bit_reg(dst_raw):
            self._known_constants[dst_reg] &= 0xFFFFFFFF

    @staticmethod
    def _is_shift_left(ins: dict) -> bool:
        mnem = ins.get("mnemonic", "").lower()
        return mnem in ("shl", "sal")

    def _handle_mov(self, ins: dict, ops: List[str], addr: int):
        src = ops[1].strip().lstrip("$").split("#")[0].strip()
        dst_raw = ops[0].strip(); dst_reg = norm_reg(dst_raw)
        ptr_map = self._alloc_tracker._ptr_to_alloc

        if src.startswith("0x") or src.isdigit() or \
           (src.startswith("-") and src[1:].isdigit()):
            val = int(src, 16) if src.startswith("0x") else int(src)
            if is_32bit_reg(dst_raw) and val >= 0x80000000:
                val -= 0x100000000
            self._known_constants[dst_reg] = val
            ptr_map.pop(dst_reg, None)
            if "[" in dst_raw.lower() and "rbp" in dst_raw.lower():
                slot = extract_stack_slot(dst_raw)
                if slot: self._stack_constants[slot] = val
        else:
            src_reg = norm_reg(src)
            if "[" in dst_raw.lower() and "rbp" in dst_raw.lower():
                slot = extract_stack_slot(dst_raw)
                if slot:
                    if src_reg in self._known_constants:
                        self._stack_constants[slot] = \
                            self._known_constants[src_reg]
                    if src_reg in ptr_map:
                        ptr_map[f"stack:{slot}"] = ptr_map[src_reg]
            elif "[" in src.lower() and "rbp" in src.lower():
                slot = extract_stack_slot(src); sk = f"stack:{slot}"
                if slot and sk in ptr_map:
                    ptr_map[dst_reg] = ptr_map[sk]
                elif slot and slot in self._stack_constants:
                    self._known_constants[dst_reg] = \
                        self._stack_constants[slot]
                elif slot:
                    ptr_map.pop(dst_reg, None)
                    self._known_constants.pop(dst_reg, None)
            else:
                if src_reg in ptr_map:
                    ptr_map[dst_reg] = ptr_map[src_reg]
                else:
                    ptr_map.pop(dst_reg, None)
                if src_reg in self._known_constants:
                    self._known_constants[dst_reg] = \
                        self._known_constants[src_reg]
                else:
                    self._known_constants.pop(dst_reg, None)
        if "[" in dst_raw.lower() or "[" in src.lower():
            self._struct_infer.feed_memory_access(ins, dst_reg)
        if "[" in dst_raw.lower():
            self._check_direct_write(dst_raw, addr)

    def _check_direct_write(self, dst_op: str, addr: int):
        """检测直接内存写入指令 mov [reg], imm 是否写入堆缓冲区."""
        if not self._is_user_code(addr):
            return
        base_reg, offset = self._parse_mem_base_offset(dst_op)
        if base_reg is None:
            return
        alloc_addr = self._alloc_tracker._ptr_to_alloc.get(base_reg)
        if alloc_addr is None:
            return
        alloc = self._alloc_tracker._allocations.get(alloc_addr)
        if alloc is None:
            return
        op_lower = dst_op.lower()
        if "qword" in op_lower:
            write_size = 8
        elif "dword" in op_lower:
            write_size = 4
        elif "word" in op_lower:
            write_size = 2
        elif "byte" in op_lower:
            write_size = 1
        else:
            write_size = 1
        write_end = offset + write_size
        raw_size = getattr(alloc, 'raw_alloc_size', alloc.alloc_size)
        if write_end <= raw_size.lo:
            return
        overflow = max(0, write_end - raw_size.hi)
        result = {
            "type": "heap_overflow_possible",
            "alloc_addr": alloc.alloc_site,
            "alloc_size": raw_size.hi,
            "alloc_size_range": f"[{raw_size.lo},{raw_size.hi}]",
            "write_addr": addr,
            "write_size": write_end,
            "write_size_range": f"[{write_end},{write_end}]",
            "overflow_bytes": overflow,
            "severity": "high" if overflow > 0 else "medium",
            "note": "direct_store_to_heap",
            "size_operand": base_reg,
            "ptr_operand": base_reg,
            "wb_numeric": write_end,
            "_snapshot_alloc_addr": alloc_addr,
            "alloc_size_interval": f"[{raw_size.lo},{raw_size.hi}]",
        }
        result["_write_sym_expr"] = self._sym_propagator.get_size_expr(
            base_reg)
        if alloc_addr and not self._is_user_code(alloc_addr):
            return
        self._raw_findings.append(result)
