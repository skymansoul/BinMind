# 堆溢出检测器call指令处理器.
# 包含alloc/write/free调用路径的指令级分析.
# 创建: 2026-05-19

from typing import List

from .disasm_util import extract_func_name
from .heap_constraint import Interval
from .value_range import ValueRange


class HeapCallHandlerMixin:
    """call指令处理, 由HeapOverflowDetector继承."""

    def _handle_call(self, ins: dict, ops: List[str], addr: int):
        func = extract_func_name(ops[0])

        if func in self.ALLOC_FUNCS:
            self._handle_alloc_call(func, ins, ops, addr)
        elif func in self.FREE_FUNCS:
            ptr_reg = self._get_arg_reg(ops, 0, self._args[0])
            alloc_addr = self._alloc_tracker._ptr_to_alloc.get(ptr_reg)
            if alloc_addr and alloc_addr in self._alloc_tracker._allocations:
                self._alloc_tracker._allocations[alloc_addr].free_site = addr
        elif func in self.WRITE_FUNCS:
            self._handle_write_call(func, ins, ops, addr)

    def _handle_alloc_call(self, func: str, ins: dict,
                           ops: List[str], addr: int):
        if func == "realloc":
            size_reg = self._get_arg_reg(ops, 1,
                self._args[1] if len(self._args) > 1 else self._args[0])
            old_ptr_reg = self._get_arg_reg(ops, 0, self._args[0])
        elif func == "calloc":
            self._handle_calloc(func, ins, ops, addr)
            return
        else:
            size_reg = self._get_arg_reg(ops, 0, self._args[0])
            old_ptr_reg = None

        size_iv = self._narrow_size(addr, size_reg)

        if func == "realloc" and old_ptr_reg:
            old_alloc_addr = self._alloc_tracker._ptr_to_alloc.get(
                old_ptr_reg)
            if old_alloc_addr is not None:
                old_alloc = self._alloc_tracker._allocations.get(
                    old_alloc_addr)
                if old_alloc:
                    old_alloc.alloc_size = size_iv
        self._alloc_tracker.track_alloc(addr, size_iv, "rax")
        alloc_sym = self._sym_propagator.get_alloc_size_expr(addr, size_reg)
        self._sym_snapshots[addr] = {"alloc_expr": alloc_sym}
        if func == "realloc" and old_ptr_reg:
            if "rax" in self._alloc_tracker._ptr_to_alloc:
                self._alloc_tracker._ptr_to_alloc[old_ptr_reg] = \
                    self._alloc_tracker._ptr_to_alloc["rax"]
        self._struct_infer.feed_allocation(addr, "rax")

    def _handle_calloc(self, func: str, ins: dict,
                        ops: List[str], addr: int):
        count_reg = self._get_arg_reg(ops, 0, self._args[0])
        elem_reg = self._get_arg_reg(ops, 1,
            self._args[1] if len(self._args) > 1 else self._args[0])
        count_vr = self._get_precise_range(addr, count_reg)
        elem_vr = self._get_precise_range(addr, elem_reg)
        count_val = self._known_constants.get(count_reg)
        elem_val = self._known_constants.get(elem_reg)
        if count_val is not None and elem_val is not None:
            product = count_val * elem_val
            size_iv = Interval(product, product)
        elif count_vr and elem_vr and not count_vr.is_bottom \
                and not elem_vr.is_bottom:
            lo = count_vr.lo * elem_vr.lo
            hi = min(count_vr.hi * elem_vr.hi, 2**31 - 1)
            size_iv = Interval(lo, hi)
        else:
            size_iv = Interval(0, 2**31 - 1)
        self._alloc_tracker.track_alloc(addr, size_iv, "rax")
        alloc_sym = self._sym_propagator.get_alloc_size_expr(
            addr, count_reg)
        self._sym_snapshots[addr] = {"alloc_expr": alloc_sym}
        self._struct_infer.feed_allocation(addr, "rax")

    def _handle_write_call(self, func: str, ins: dict,
                            ops: List[str], addr: int):
        if func in self._UNSIZED_WRITES:
            return
        dst_reg = self._get_arg_reg(ops, 0, self._args[0])
        size_reg = self._get_arg_reg(ops, 2,
            self._args[2] if len(self._args) > 2 else self._args[1])
        size_iv = self._narrow_size(addr, size_reg)
        result = self._alloc_tracker.track_write(addr, size_iv, dst_reg)
        if result:
            result["size_operand"] = size_reg
            result["ptr_operand"] = dst_reg
            alloc_entry = self._alloc_tracker._ptr_to_alloc.get(dst_reg)
            if alloc_entry is not None:
                result["_snapshot_alloc_addr"] = alloc_entry
                alloc = self._alloc_tracker._allocations.get(alloc_entry)
                if alloc:
                    raw_size = getattr(alloc, 'raw_alloc_size',
                                       alloc.alloc_size)
                    result["alloc_size"] = raw_size.hi
                    result["alloc_size_interval"] = (
                        f"[{raw_size.lo},{raw_size.hi}]")
            if result.get("alloc_size", 0) > 0:
                ok, reason = self._alloc_model.is_overflow(
                    result["alloc_size"],
                    result.get("write_size", size_iv.hi))
                if not ok:
                    result["alloc_model_safe"] = True
                    result["alloc_model_reason"] = reason
            if alloc_entry and not self._is_user_code(alloc_entry):
                return
            write_expr = self._sym_propagator.get_size_expr(size_reg)
            result["_write_sym_expr"] = write_expr
            self._raw_findings.append(result)

    def _narrow_size(self, addr: int, size_reg: str) -> Interval:
        """路径敏感bounds check窄化, 回退到区间分析或常量."""
        vr_narrowed = self._ps_vra.narrow_for_bounds_check(
            self._instructions, addr, size_reg)
        if vr_narrowed:
            return Interval(vr_narrowed.lo, vr_narrowed.hi)
        vr = self._get_precise_range(addr, size_reg)
        if vr and not vr.is_bottom and vr.hi < 2**31:
            return Interval(vr.lo, vr.hi)
        return self._alloc_tracker.get_or_create_size_interval(
            size_reg, self._known_constants)
