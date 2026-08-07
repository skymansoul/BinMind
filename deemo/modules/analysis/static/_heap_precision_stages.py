# 堆溢出精度增强阶段 (Heap Precision Stages Mixin)
#
# 核心决策:
#   在既有DDSSC/SAWCE/octagon过滤之上, 修正三个系统性精度缺陷:
#     A. PCST: 按调用点参数语义表提取size/dst, 修复snprintf/fread/read
#        等函数参数索引错误导致的错误数据流.
#     B. BWR: 对无界写入(strcpy/strcat/sprintf/gets)恢复有界写尺寸,
#        安全即抑制(降误报), 确定溢出即报(保召回).
#     C. 栈槽/32位寄存器符号解析: 分配与写入同栈槽时符号关联可用,
#        消除区间重叠类误报.
#   既有所有阶段原样保留, 本阶段仅插入与追加.
#
# 创建: 2026-05-06

from typing import Dict, List, Optional

from .heap_write_semantics import (
    write_dst_index, write_size_index, is_sized_write,
    is_unsized_write, is_write_func,
)
from .bounded_write_recovery import BoundedWriteRecovery
from .heap_alloc_model import AllocatorFamily
from .heap_constraint import Interval
from .disasm_util import extract_stack_slot


class HeapPrecisionStagesMixin:
    """PCST+BWR+栈槽符号解析, 由HeapOverflowDetector最先继承."""

    # 扩展写入函数全集: 覆盖PCST支持的sized/unsized写.
    WRITE_FUNCS = {
        "memcpy", "memmove", "strcpy", "strncpy", "strcat",
        "sprintf", "snprintf", "read", "fread", "recv",
        "memset", "stpcpy", "strncat", "vsprintf", "memccpy",
        "mempcpy", "bzero", "explicit_bzero", "bcopy",
    }

    def __init__(self, allocator=None,
                 allocator_family: AllocatorFamily = AllocatorFamily.GLIBC,
                 use_win64_abi: bool = False,
                 enable_bwr: bool = True, enable_pcst: bool = True):
        family = allocator if allocator is not None else allocator_family
        super().__init__(allocator_family=family,
                         use_win64_abi=use_win64_abi)
        self._enable_pcst = enable_pcst
        self._bwr_enabled = enable_bwr and enable_pcst
        self._bwr = BoundedWriteRecovery(self._alloc_model)
        self._bwr_safe_suppressed = 0
        self._bwr_unknown_skipped = 0
        self._addr_to_idx: Dict[int, int] = {}

    def _handle_alloc_call(self, func: str, ins: dict,
                           ops: List[str], addr: int):
        super()._handle_alloc_call(func, ins, ops, addr)
        # 重写符号快照: 分配尺寸若源自栈槽/32位寄存器, 解析为符号表达式,
        # 使DDSSC符号关联能够匹配分配与写入的等价性.
        size_reg = self._get_arg_reg(
            ops, 1, self._args[1] if len(self._args) > 1 else self._args[0]) \
            if func == "realloc" else self._get_arg_reg(ops, 0, self._args[0])
        resolved = self._resolved_sym_expr(size_reg)
        if resolved is not None:
            self._sym_snapshots[addr] = {"alloc_expr": resolved}

    def _handle_write_call(self, func: str, ins: dict,
                           ops: List[str], addr: int):
        if is_unsized_write(func):
            if self._bwr_enabled:
                self._handle_bwr_write(func, ins, ops, addr)
            return
        if not is_sized_write(func):
            return
        if not self._enable_pcst:
            self._legacy_write_call(func, ins, ops, addr)
            return
        dst_idx = write_dst_index(func)
        size_spec = write_size_index(func)
        dst_reg = self._get_arg_reg(ops, dst_idx, self._args[0])
        size_reg = ""
        if isinstance(size_spec, tuple):
            regs = [self._get_arg_reg(ops, i, self._args[min(i, len(self._args) - 1)])
                    for i in size_spec]
            ivs = [self._narrow_size(addr, r) for r in regs]
            size_iv = Interval(ivs[0].lo * ivs[1].lo,
                               min(ivs[0].hi * ivs[1].hi, 2**31 - 1))
        else:
            size_idx = int(size_spec)
            size_reg = self._get_arg_reg(
                ops, size_idx,
                self._args[min(size_idx, len(self._args) - 1)])
            size_iv = self._narrow_size(addr, size_reg)

        result = self._alloc_tracker.track_write(addr, size_iv, dst_reg)
        if not result:
            return
        if not self._is_user_code(addr):
            return
        if result.get("write_size") is None:
            result["write_size"] = size_iv.hi
        result["size_operand"] = size_reg
        result["ptr_operand"] = dst_reg
        alloc_entry = self._alloc_tracker._ptr_to_alloc.get(dst_reg)
        if alloc_entry is not None:
            result["_snapshot_alloc_addr"] = alloc_entry
            alloc = self._alloc_tracker._allocations.get(alloc_entry)
            if alloc:
                raw_size = getattr(alloc, "raw_alloc_size", alloc.alloc_size)
                result["alloc_size"] = raw_size.hi
                result["alloc_size_interval"] = f"[{raw_size.lo},{raw_size.hi}]"
        if result.get("alloc_size", 0) > 0:
            ok, reason = self._alloc_model.is_overflow(
                result["alloc_size"], result.get("write_size", size_iv.hi))
            if not ok:
                result["alloc_model_safe"] = True
                result["alloc_model_reason"] = reason
        if alloc_entry and not self._is_user_code(alloc_entry):
            return
        write_expr = self._resolved_sym_expr(size_reg) if size_reg else None
        result["_write_sym_expr"] = write_expr
        self._raw_findings.append(result)

    def _legacy_write_call(self, func: str, ins: dict,
                           ops: List[str], addr: int):
        """旧语义: 统一 size=index2, dst=index0, 无界写跳过 (基线)."""
        if func in self._UNSIZED_WRITES:
            return
        dst_reg = self._get_arg_reg(ops, 0, self._args[0])
        size_reg = self._get_arg_reg(
            ops, 2, self._args[2] if len(self._args) > 2 else self._args[1])
        size_iv = self._narrow_size(addr, size_reg)
        result = self._alloc_tracker.track_write(addr, size_iv, dst_reg)
        if not result:
            return
        if not self._is_user_code(addr):
            return
        if result.get("write_size") is None:
            result["write_size"] = size_iv.hi
        result["size_operand"] = size_reg
        result["ptr_operand"] = dst_reg
        alloc_entry = self._alloc_tracker._ptr_to_alloc.get(dst_reg)
        if alloc_entry is not None:
            result["_snapshot_alloc_addr"] = alloc_entry
            alloc = self._alloc_tracker._allocations.get(alloc_entry)
            if alloc:
                raw_size = getattr(alloc, "raw_alloc_size", alloc.alloc_size)
                result["alloc_size"] = raw_size.hi
                result["alloc_size_interval"] = (
                    f"[{raw_size.lo},{raw_size.hi}]")
        if result.get("alloc_size", 0) > 0:
            ok, reason = self._alloc_model.is_overflow(
                result["alloc_size"], result.get("write_size", size_iv.hi))
            if not ok:
                result["alloc_model_safe"] = True
                result["alloc_model_reason"] = reason
        if alloc_entry and not self._is_user_code(alloc_entry):
            return
        write_expr = self._resolved_sym_expr(size_reg) if size_reg else None
        result["_write_sym_expr"] = write_expr
        self._raw_findings.append(result)

    def _handle_bwr_write(self, func: str, ins: dict,
                          ops: List[str], addr: int):
        dst_idx = write_dst_index(func)
        dst_reg = self._get_arg_reg(ops, dst_idx, self._args[0])
        alloc_addr = self._alloc_tracker._ptr_to_alloc.get(dst_reg)
        if alloc_addr is None:
            return
        alloc_entry = self._alloc_tracker._allocations.get(alloc_addr)
        if alloc_entry is None or not self._is_user_code(alloc_addr):
            return
        call_idx = self._instruction_index(addr)
        if call_idx is None:
            return
        src_idx = 1 if func not in ("gets",) else 0
        src_reg = self._get_arg_reg(
            ops, src_idx, self._args[min(src_idx, len(self._args) - 1)])
        verdict = self._bwr.recover(self._instructions, call_idx, func,
                                    self._alloc_tracker, dst_reg, src_reg)
        if verdict.kind == "overflow":
            raw = getattr(alloc_entry, "raw_alloc_size", alloc_entry.alloc_size)
            usable = self._alloc_model.usable_size(raw.hi)
            overflow = verdict.bound - usable
            self._raw_findings.append({
                "type": "heap_overflow",
                "alloc_addr": alloc_addr,
                "alloc_size": raw.hi,
                "write_addr": addr,
                "write_size": verdict.bound,
                "overflow_bytes": max(overflow, 1),
                "severity": "critical" if overflow > 64 else "high",
                "detection_method": "bwr",
                "ptr_operand": dst_reg,
                "size_operand": "recovered",
                "note": verdict.reason,
                "bwr_bound": verdict.bound,
                "_snapshot_alloc_addr": alloc_addr,
            })
        elif verdict.kind == "safe":
            self._bwr_safe_suppressed += 1
        else:
            # 无界写入且目标来源无法恢复: 若目标是固定小缓冲,
            # 保守报潜在溢出候选 (下界可用量以内不报, 交由后续过滤).
            raw = getattr(alloc_entry, "raw_alloc_size", alloc_entry.alloc_size)
            if raw.is_singleton and 0 < raw.hi < 2**31 - 1:
                usable = self._alloc_model.usable_size(raw.hi)
                self._raw_findings.append({
                    "type": "heap_overflow_possible",
                    "alloc_addr": alloc_addr,
                    "alloc_size": raw.hi,
                    "write_addr": addr,
                    "write_size": usable + 1,
                    "overflow_bytes": 1,
                    "severity": "medium",
                    "detection_method": "bwr_unknown_fixed",
                    "ptr_operand": dst_reg,
                    "size_operand": "unresolved",
                    "note": verdict.reason,
                    "_snapshot_alloc_addr": alloc_addr,
                })
            else:
                self._bwr_unknown_skipped += 1

    def _narrow_size(self, addr: int, size_reg: str) -> Interval:
        """路径敏感窄化 → 栈槽/32位符号常量 → 值域 → 最宽区间."""
        vr_narrowed = self._ps_vra.narrow_for_bounds_check(
            self._instructions, addr, size_reg)
        if vr_narrowed:
            return Interval(vr_narrowed.lo, vr_narrowed.hi)
        expr = self._resolved_sym_expr(size_reg)
        if expr is not None and expr.is_const() and expr.const >= 0:
            return Interval(expr.const, expr.const)
        vr = self._get_precise_range(addr, size_reg)
        if vr and not vr.is_bottom and vr.hi < 2**31:
            return Interval(vr.lo, vr.hi)
        return self._alloc_tracker.get_or_create_size_interval(
            size_reg, self._known_constants)

    def _resolved_sym_expr(self, reg: str):
        """解析size操作数的符号表达式: 栈槽 → 栈表, 寄存器 → 常规表."""
        if not reg:
            return None
        r = reg.strip().lower().lstrip("%").replace("$", "")
        if "[" in r:
            slot = extract_stack_slot(reg)
            if slot:
                return self._sym_propagator._tracker.get_stack_expr(slot)
            return None
        return self._sym_propagator.get_size_expr(r)

    def _instruction_index(self, addr: int) -> Optional[int]:
        if not self._addr_to_idx:
            self._addr_to_idx = {ins.get("address", 0): i
                                 for i, ins in enumerate(self._instructions)}
        return self._addr_to_idx.get(addr)

    @property
    def stats(self) -> dict:
        s = super().stats
        s["bwr"] = {
            "enabled": self._bwr_enabled,
            "safe_suppressed": self._bwr_safe_suppressed,
            "unknown_skipped": self._bwr_unknown_skipped,
            **self._bwr.stats,
        }
        return s


__all__ = ["HeapPrecisionStagesMixin"]
