# 增强型堆溢出检测器 (Enhanced Heap Overflow Detector)
#
# 整合后向值流追踪 + 约束简化 + 多阶段FP过滤,
# 在保留高召回的同时压低误报率.
#

from typing import Dict, List, Optional, Tuple

from .heap_constraint import HeapConstraintTracker, Interval
from .heap_alloc_model import AllocatorFamily, HeapAllocModel
from .heap_fp_filter import HeapFPFilter
from .heap_slice_trace import BackwardSliceTracer
from .heap_struct_infer import HeapStructInference
from .path_sensitive_vra import PathSensitiveVRA
from .value_range_analyzer import ValueRangeAnalyzer
from .value_range import ValueRange
from .sym_propagator import SymbolicPropagator
from .sym_size_correlator import SymbolicSizeTracker as _SymCorrTracker
from .symbolic_size_expr import SymbolicSizeTracker
from .symbolic_correlator import SymbolicCorrelator
from .size_corr_coordinator import DDSSCCoordinator
from .size_corr_fp_filter import DDSSCFPFilter
from .octagon_filter import OctagonFPFilter
from .co_source_filter import AWSCFPFilter
from .loop_write_accumulator import LoopWriteAccumulator
from .octagon_filter import OctagonFPFilter
from .disasm_util import extract_func_name
from .disasm_util import norm_reg, extract_stack_slot, is_32bit_reg
from .bounded_write_recovery import BoundedWriteRecovery
from .provenance_domain import ProvValue
from .provenance_propagator import ProvenancePropagator
from .write_bound_infer import WbVerdict, WriteBoundInferer
from .interproc_summary import InterprocSummaryBuilder
from .heap_write_semantics import (
    write_dst_index, write_size_index, is_sized_write,
    is_unsized_write, is_write_func,
)

import re


# 堆溢出检测器指令处理器.
# 包含mov/rep_movs/inline_sse/direct_write的指令级分析.

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
        # 优先查已知常量表 (mov ecx, 0x64 由 _handle_mov 归一化为 rcx),
        # Os/O2 优化下 VRA 可能未传播到 rep movs 点, 常量表更可靠.
        ecx_const = self._known_constants.get("ecx") \
            or self._known_constants.get("rcx")
        if ecx_const is not None:
            total_bytes = ecx_const * elem_size
            size_iv = Interval(total_bytes, total_bytes)
        else:
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
        """检测内联SSE存储 - 若目标为堆指针则检查溢出."""
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
        """lea dst, [base+offset] - 指针算术, 传播堆溯源.

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
        """shl/sal/shr/sar dst, imm - 常量表更新 (移位乘法/除法).

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
        """add/sub dst, imm - 常量表更新."""
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

# 堆溢出检测器call指令处理器.
# 包含alloc/write/free调用路径的指令级分析.

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
                    # realloc 后请求大小随之更新, raw 字段需同步,
                    # 否则旧分配点 finding 用旧 raw_size 低估写界 → 误报.
                    if hasattr(old_alloc, "raw_alloc_size"):
                        old_alloc.raw_alloc_size = size_iv
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

# 堆溢出检测器finalize阶段.
# 包含多阶段FP过滤管线: 去重→Stage4路径敏感→Stage5结构推断→Stage3.5 Octagon→Stage1-3→按需符号尺寸关联→SAWCE.

# 插入Stage 3.5 Octagon关系型域过滤
class HeapFinalizeMixin:
    """finalize阶段多阶段FP过滤, 由HeapOverflowDetector继承."""

    @staticmethod
    def _dedup_by_alloc(findings: List[dict]) -> List[dict]:
        """按(alloc_addr, write_addr)去重 - 同一分配点的不同写入操作各自独立保留."""
        by_key: Dict[tuple, dict] = {}
        for f in findings:
            alloc_addr = f.get("_snapshot_alloc_addr",
                               f.get("alloc_addr", 0))
            write_addr = f.get("write_addr", 0)
            key = (alloc_addr, write_addr)
            if key in by_key:
                existing = by_key[key]
                if f.get("overflow_bytes", 0) > \
                        existing.get("overflow_bytes", 0):
                    by_key[key] = f
            else:
                by_key[key] = f
        return list(by_key.values())

    def finalize(self, instructions: List[dict]) -> List[dict]:
        """所有指令分析完毕后, 运行多阶段FP过滤."""
        deduped = self._dedup_by_alloc(self._raw_findings)

        stage4_survivors = []
        for f in deduped:
            if not self._stage4_path_sensitive_check(f):
                continue
            stage4_survivors.append(f)

        stage5_survivors = []
        for f in stage4_survivors:
            if not self._stage5_struct_field_check(f):
                continue
            stage5_survivors.append(f)

        # Stage 3.5: Octagon 关系型域过滤
        # 消除区间域无法判定的变量间等价/支配关系类误报
        octagon_builder = self._octagon_filter.build_domain(instructions)
        stage35_survivors = self._octagon_filter.filter(
            stage5_survivors, octagon_builder)

        stage123_survivors = self._fp_filter.filter(
            stage35_survivors, instructions, self._alloc_tracker)

        sym_expr_map = self._build_sym_expr_map(stage123_survivors)
        stage678_survivors = self._ddssc_filter.filter(
            stage123_survivors, instructions, self._alloc_tracker,
            self._known_constants, sym_expr_map)

        self._struct_size_tracker.set_instructions(instructions)
        self._struct_size_tracker.reset()
        for ins in instructions:
            self._struct_size_tracker.process(ins)
        corr_results = self._symbolic_correlator.correlate(
            self._struct_size_tracker, self._alloc_tracker)
        stage9_survivors = []
        for f in stage678_survivors:
            filter_reason = self._symbolic_correlator.filter_finding(
                f, corr_results)
            if filter_reason:
                f["fp_stage"] = "stage9_sawce_correlation"
                f["fp_reason"] = filter_reason
                continue
            stage9_survivors.append(f)

        loop_findings = self._loop_accumulator.analyze(
            instructions, self._alloc_tracker,
            use_win64_abi=self._win64)
        # 去重键含 detection_method: loop off-by-one 是独立证据, 不应
        # 因同 alloc 已有 raw finding 而被跳过 (raw 可能被判 benign).
        existing_keys = {
            (f.get("_snapshot_alloc_addr", f.get("alloc_addr", 0)),
             f.get("detection_method", ""))
            for f in stage9_survivors}
        for lf in loop_findings:
            key = (lf.get("_snapshot_alloc_addr", 0),
                   lf.get("detection_method", "loop_accumulation"))
            if key not in existing_keys:
                stage9_survivors.append(lf)
                existing_keys.add(key)

        # Stage 10: 分配-写关联 同源关联过滤
        # 消除"分配=写入且同根来源"类误报 (区间分析无法识别)
        stage10_survivors = self._awsc_filter.filter(
            stage9_survivors, instructions, self._alloc_tracker,
            self._user_func_ranges)

        # Stage 11: 来源约束写界推断
        # 按写入大小来源将候选分级为 confirmed/suspected/benign,
        # 仅 confirmed 计入最终检出, suspected 归入疑似列表供复核.
        # enable_pcwbi=False 时跳过, 返回 分配-写关联 存活集 (消融基线).
        self._filtered_findings = stage10_survivors
        if getattr(self, "_pcwbi_enabled", True):
            self._filtered_findings = self.prov_run(instructions)
        return self._filtered_findings

    def _build_sym_expr_map(self, findings: List[dict]) -> Dict[int, dict]:
        """从findings和符号快照构建 {alloc_addr: {alloc_expr, write_expr}}."""
        expr_map: Dict[int, dict] = {}
        for f in findings:
            alloc_addr = f.get("_snapshot_alloc_addr",
                               f.get("alloc_addr", 0))
            if alloc_addr not in expr_map:
                snapshot = self._sym_snapshots.get(alloc_addr, {})
                expr_map[alloc_addr] = dict(snapshot)
        return expr_map

    def _stage4_path_sensitive_check(self, f: dict) -> bool:
        """路径敏感bounds check窄化: 若写入大小经约束窄化≤分配大小→过滤."""
        size_op = f.get("size_operand", "")
        alloc_sz = f.get("alloc_size", 0)
        if not size_op or alloc_sz <= 0:
            return True
        if f.get("note", "") == "direct_store_to_heap":
            return True
        if alloc_sz >= 2**31 - 1:
            return True
        narrowed = self._ps_vra.narrow_for_bounds_check(
            self._instructions, f.get("write_addr", 0), size_op)
        if narrowed and narrowed.hi <= alloc_sz:
            f["fp_stage"] = "stage4_path_sensitive"
            return False
        return True

    def _stage5_struct_field_check(self, f: dict) -> bool:
        """堆对象结构推断: 若写入是已知字段访问→过滤.

        守卫: 写量未知(≤0)时不做结构推断, 避免把memcpy类
        整体拷贝误判为字段访问而过滤真实溢出.
        """
        if f.get("note", "") == "direct_store_to_heap":
            return True
        ptr_reg = f.get("ptr_operand", "")
        if not ptr_reg:
            return True
        write_size = f.get("write_size", 0) or 0
        if write_size <= 0:
            return True
        if f.get("detection_method") in ("bwr", "loop_accumulation"):
            return True
        if self._struct_infer.is_field_access(
                ptr_reg, 0, write_size):
            f["fp_stage"] = "stage5_struct_field"
            return False
        return True

# 堆检测器 集成 mixin - 来源约束写界推断作为 finalize Stage 10.
#
# 决策逻辑:
#   Stage 1-9 输出经多阶段过滤的候选告警 (self._filtered_findings).
#   Stage 10 不再新增候选, 而是按"写入大小来源"对候选重新分级:
# CONFIRMED: 可证明存在溢出路径, 计入最终检出.
# BENIGN:    可证明所有路径安全, 从最终检出中剔除 (抑制误报).
#     - SUSPECTED: 信息不足, 不删除, 单独归入 suspected_findings 供人工复核.
#   分级数据写入每条 finding 的 wb_* 字段, 原始候选本身不删除,
#   保证"只增不减"约束下误报率可测量.
#

class HeapProvenanceMixin:
    """来源约束写界推断, 由 HeapOverflowDetector 继承."""

    def _init_provenance(self):
        self._prov_propagator = ProvenancePropagator(
            arg_regs=list(self._args), use_win64_abi=self._win64)
        self._prov_summary_builder = InterprocSummaryBuilder(
            arg_regs=list(self._args))
        self._wb_inferer = WriteBoundInferer(self._alloc_model)
        self._suspected_findings: List[dict] = []
        self._benign_findings: List[dict] = []
        self._pcwbi_enabled: bool = True

    def set_pcwbi_enabled(self, enabled: bool):
        """消融开关: 关闭后 finalize 跳过 Stage 11, 返回基线候选集."""
        self._pcwbi_enabled = enabled

    def prov_build_summary(self, func_name: str,
                           instructions: List[dict]):
        """为单个用户函数构建来源摘要 (供带函数边界的驱动调用)."""
        self._prov_summary_builder.build(func_name, instructions,
                                         is_win64=self._win64)

    def prov_run(self, instructions: List[dict]) -> List[dict]:
        """执行 Stage 10 写界推断.

        输入: Stage 9 输出的候选告警.
        返回: 保留级告警列表.

        决策修正: 只抑制"可证明安全"(BENIGN) 的告警;
        SUSPECTED (信息不足, 未证安全) 必须保留在检出中,
        否则真实溢出因证据不足被丢弃 → 召回崩塌.
        被过滤告警仍以 wb_verdict=benign 标记, 供消融审计.
        """
        self._prov_propagator.reset()
        self._prov_propagator.set_instructions(instructions)
        for ins in instructions:
            self._prov_propagator.handle_instruction(ins)

        # rep movs 内联复制的写界 = ecx * elem_size, 字节数已由
        # _handle_rep_movs 写入 finding.write_size. prov_propagator
        # 只追踪 ecx 元素计数, 交给 CONSTANT 分支会低估写界 (100 vs 400)
        # → 误判 benign. 对该类 finding 直接走 numeric 分支 (write_size).
        rep_write_addrs = {
            f.get("write_addr", 0)
            for f in self._filtered_findings
            if f.get("dangerous_func") == "inline_memcpy"
        }

        def get_write_prov(write_addr, size_op):
            if write_addr in rep_write_addrs:
                return None
            return self._get_write_prov(write_addr, size_op)

        results = self._wb_inferer.infer(
            self._filtered_findings,
            get_write_prov=get_write_prov,
            get_alloc_prov=self._get_alloc_prov)

        confirmed, suspected, benign = [], [], []
        for r in results:
            self._apply_verdict(r.finding, r)
            if r.verdict == WbVerdict.CONFIRMED:
                confirmed.append(r.finding)
            elif r.verdict == WbVerdict.SUSPECTED:
                suspected.append(r.finding)
            else:
                benign.append(r.finding)

        self._suspected_findings = suspected
        self._benign_findings = benign
        return confirmed + suspected

    def _get_write_prov(self, write_addr: int,
                        size_op: str) -> Optional[ProvValue]:
        """查询写入大小操作数在写入点的来源."""
        if not size_op:
            return None
        reg = size_op.strip().lower().lstrip("%")
        return self._prov_propagator.get_at(write_addr, reg)

    def _get_alloc_prov(self, alloc_addr: int) -> Optional[ProvValue]:
        """查询分配点 size 参数的来源."""
        return self._prov_propagator.get_alloc_arg_source(alloc_addr)

    def _apply_verdict(self, finding: dict, result):
        """将分级结果写入 finding 的 wb_* 字段."""
        finding["wb_verdict"] = result.verdict
        finding["wb_reason"] = result.reason
        finding["wb_provenance"] = result.provenance
        finding["wb_filtered"] = result.verdict != WbVerdict.CONFIRMED

    @property
    def suspected_findings(self) -> List[dict]:
        return list(self._suspected_findings)

    @property
    def benign_findings(self) -> List[dict]:
        return list(self._benign_findings)

    def wb_stats(self) -> dict:
        return dict(self._wb_inferer.stats)

# 堆溢出精度增强阶段 (Heap Precision Stages Mixin)
#
# 核心决策:
#   在既有按需符号尺寸关联/SAWCE/octagon过滤之上, 修正三个系统性精度缺陷:
#     A. 路径条件敏感污点: 按调用点参数语义表提取size/dst, 修复snprintf/fread/read
#        等函数参数索引错误导致的错误数据流.
#     B. 有界写恢复: 对无界写入(strcpy/strcat/sprintf/gets)恢复有界写尺寸,
#        安全即抑制(降误报), 确定溢出即报(保召回).
#     C. 栈槽/32位寄存器符号解析: 分配与写入同栈槽时符号关联可用,
#        消除区间重叠类误报.
#   既有所有阶段原样保留, 本阶段仅插入与追加.
#

class HeapPrecisionStagesMixin:
    """路径条件敏感污点+有界写恢复+栈槽符号解析, 由HeapOverflowDetector最先继承."""

    # 扩展写入函数全集: 覆盖路径条件敏感污点支持的sized/unsized写.
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
        # 使按需符号尺寸关联符号关联能够匹配分配与写入的等价性.
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
                result["alloc_request"] = raw_size.lo
                result["alloc_size_interval"] = f"[{raw_size.lo},{raw_size.hi}]"
        if result.get("alloc_size", 0) > 0:
            # is_overflow 以原始请求为输入算 usable, 避免对齐值导致
            # 小请求下 usable 偏高而漏报真实溢出.
            request = result.get("alloc_request", result["alloc_size"])
            ok, reason = self._alloc_model.is_overflow(
                request, result.get("write_size", size_iv.hi))
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
                result["alloc_request"] = raw_size.lo
                result["alloc_size_interval"] = (
                    f"[{raw_size.lo},{raw_size.hi}]")
        if result.get("alloc_size", 0) > 0:
            request = result.get("alloc_request", result["alloc_size"])
            ok, reason = self._alloc_model.is_overflow(
                request, result.get("write_size", size_iv.hi))
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


class HeapOverflowDetector(
    HeapPrecisionStagesMixin,
    HeapInsnHandlerMixin, HeapCallHandlerMixin, HeapFinalizeMixin,
    HeapProvenanceMixin,
):
    """增强型堆溢出检测器.

    输入: 反汇编指令流.
    输出: 过滤后的高置信度堆溢出告警.
    """

    ALLOC_FUNCS = {"malloc", "calloc", "realloc", "_Znwm", "_Znam",
                   "g_malloc", "g_try_malloc", "ExAllocatePoolWithTag"}
    WRITE_FUNCS = {"memcpy", "memmove", "memset", "strcpy", "strncpy",
                   "strcat", "sprintf", "snprintf", "read", "fread", "recv"}
    FREE_FUNCS = {"free", "_ZdlPv", "g_free", "ExFreePool"}

    _UNSIZED_WRITES = {"strcpy", "strcat", "gets", "sprintf"}

    _WIN64_ARGS = ["rcx", "rdx", "r8", "r9"]
    _SYSV_ARGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

    def __init__(
        self,
        allocator: Optional[AllocatorFamily] = None,
        allocator_family: AllocatorFamily = AllocatorFamily.GLIBC,
        use_win64_abi: bool = False,
        enable_bwr: bool = True,
        enable_pcst: bool = True,
    ):
        family = allocator if allocator is not None else allocator_family
        self._alloc_tracker = HeapConstraintTracker()
        self._fp_filter = HeapFPFilter()
        self._tracer = BackwardSliceTracer()
        self._raw_findings: List[dict] = []
        self._filtered_findings: List[dict] = []
        self._known_constants: Dict[str, int] = {}
        self._stack_constants: Dict[str, int] = {}
        self._instructions: List[dict] = []

        self._win64 = use_win64_abi
        self._args = self._WIN64_ARGS if use_win64_abi else self._SYSV_ARGS
        self._alloc_model = HeapAllocModel(family)
        self._sym_tracker = _SymCorrTracker()
        self._sym_propagator = SymbolicPropagator(self._sym_tracker)
        self._sym_snapshots: Dict[int, dict] = {}
        self._struct_infer = HeapStructInference()
        self._ps_vra = PathSensitiveVRA()
        self._vra = ValueRangeAnalyzer()
        self._ddssc_coordinator = DDSSCCoordinator(enable_smt=True)
        self._ddssc_filter = DDSSCFPFilter(self._ddssc_coordinator)
        self._symbolic_correlator = SymbolicCorrelator()
        self._struct_size_tracker = SymbolicSizeTracker(
            arg_regs=tuple(self._args))
        self._loop_accumulator = LoopWriteAccumulator(
            use_win64_abi=use_win64_abi)
        self._init_provenance()
        self._octagon_filter = OctagonFPFilter()
        self._awsc_filter = AWSCFPFilter(
            use_win64_abi=use_win64_abi, alloc_model=self._alloc_model)

        # 路径条件敏感污点+有界写恢复精度阶段
        self._enable_pcst = enable_pcst
        self._bwr_enabled = enable_bwr and enable_pcst
        self._bwr = BoundedWriteRecovery(self._alloc_model)
        self._bwr_safe_suppressed = 0
        self._bwr_unknown_skipped = 0
        self._addr_to_idx: Dict[int, int] = {}

        self._min_user_addr: int = 0
        self._user_func_ranges: List[Tuple[int, int]] = []

    def set_min_user_addr(self, addr: int):
        self._min_user_addr = addr

    def set_rodata_bytes(self, rodata: dict):
        """注入 .rdata/.rodata 节字节映射, 供有界写恢复读取字符串字面量."""
        if rodata:
            self._bwr.set_rodata(rodata)

    def set_user_func_ranges(self, ranges: List[Tuple[int, int]]):
        self._user_func_ranges = ranges

    def pre_analyze(self, instructions: List[dict]):
        """预分析: 值域分析 + 符号传播参数初始化."""
        self._instructions = instructions
        self._vra.analyze(instructions)
        self._sym_propagator.init_function_params(self._args)

    def analyze_instruction(self, ins: dict):
        """逐指令分析: 追踪分配/写入/释放."""
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        addr = ins.get("address", 0)

        self._sym_propagator.handle_instruction(ins, self._known_constants)

        if mnem == "call" and ops:
            self._handle_call(ins, ops, addr)
        elif mnem == "rep" or (mnem.startswith("rep") and ops):
            self._handle_rep_movs(ins, ops, addr)
        elif mnem in ("mov", "movsxd", "movzx", "movsx") and len(ops) >= 2:
            self._handle_mov(ins, ops, addr)
        elif mnem == "lea" and len(ops) >= 2:
            self._handle_lea(ins, ops, addr)
        elif mnem in ("shl", "sal", "shr", "sar") and len(ops) >= 2:
            self._handle_shift_const(ins, ops, addr)
        elif mnem in ("add", "sub") and len(ops) >= 2:
            self._handle_arith_const(ins, ops, addr)
        elif mnem in ("movaps", "movups", "movdqa", "movdqu",
                       "movapd", "movupd") and len(ops) >= 2:
            self._handle_inline_sse_store(ins, ops, addr)

    def _is_user_code(self, addr: int) -> bool:
        """判断地址是否属于用户代码区(非CRT库).

        _user_func_ranges非空时检查地址是否在任一函数范围内;
        _min_user_addr作为辅助过滤, 但不单独拒绝(分配可能在main之前).
        """
        if self._user_func_ranges:
            for lo, hi in self._user_func_ranges:
                if lo <= addr < hi:
                    return True
            if self._min_user_addr and addr < self._min_user_addr:
                return False
            return False
        return True

    def _get_precise_range(self, addr: int, reg: str) -> Optional[ValueRange]:
        """获取寄存器在指定地址的精确值域."""
        return self._vra.get_range_at(addr, reg)

    def _get_arg_reg(self, ops: List[str], idx: int, default: str) -> str:
        if idx + 1 < len(ops):
            return ops[idx + 1].strip().lower().lstrip("%")
        return default

    @property
    def raw_findings(self) -> List[dict]:
        return list(self._raw_findings)

    @property
    def findings(self) -> List[dict]:
        return list(self._filtered_findings)

    @property
    def stats(self) -> dict:
        s = {
            "raw_findings": len(self._raw_findings),
            "filtered_findings": len(self._filtered_findings),
            "alloc_tracker": self._alloc_tracker.stats(),
        }
        if getattr(self, "_bwr", None) is not None:
            s["bwr"] = {
                "enabled": self._bwr_enabled,
                "safe_suppressed": self._bwr_safe_suppressed,
                "unknown_skipped": self._bwr_unknown_skipped,
                **self._bwr.stats,
            }
        return s


__all__ = ["HeapOverflowDetector"]
