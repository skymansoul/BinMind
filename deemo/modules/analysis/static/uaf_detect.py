# Use-After-Free 检测器 v6 — PDL-UAF
# v6: PDL-UAF (Path-Dominance Lifespan) — 分支范围路径互斥判定
#   + 过程间free摘要 + cleanup-pattern误报抑制 + pre_analyze提取到独立模块.
# v4: 路径敏感free-use验证 + 全局变量重赋值检测 + realloc生命周期.
# 创建: 2026-07-31

from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from .disasm_util import (
    norm_reg, extract_stack_slot, resolve_rip_relative, extract_func_name
)
from .uaf_operand_utils import is_indexed_access, parse_immediate
from .uaf_pre_analyzer import UAFPreAnalyzer
from .uaf_path_analyzer import PathAnalyzer
from .uaf_interproc_free import InterprocFreeAnalyzer
from .uaf_deref_checker import DerefChecker
from .uaf_ptr_propagate import PointerPropagator
from .uaf_finalize import UAFFinalizer


class HeapObject:
    """堆对象追踪: 分配点→释放点→使用点."""
    __slots__ = ("obj_id", "alloc_addr", "alloc_size", "freed_at",
                 "use_after_free_at", "nulled_after_free", "nulled_at",
                 "realloc_count")
    def __init__(self, obj_id: int, alloc_addr: int, alloc_size: int = 0):
        self.obj_id = obj_id; self.alloc_addr = alloc_addr
        self.alloc_size = alloc_size; self.freed_at: List[int] = []
        self.use_after_free_at: List[int] = []
        self.nulled_after_free = False; self.nulled_at: Optional[int] = None
        self.realloc_count = 0


class UAFDetector:
    """UAF 生命周期检测器 v6 — PDL-UAF.

    新增能力:
      1. 分支范围路径互斥判定 (PathAnalyzer) — 消除互斥路径上的FP
      2. 过程间free摘要 (InterprocFreeAnalyzer) — 检测间接free的UAF
      3. cleanup-pattern抑制 — free(obj);free(obj->data)语义安全
    """

    ALLOC_FUNCS = {"malloc", "calloc", "_Znwm", "_Znam",
                    "operator_new", "g_malloc", "ExAllocatePoolWithTag"}
    FREE_FUNCS = {"free", "_ZdlPv", "_ZdaPv", "operator_delete", "g_free", "ExFreePool"}
    REALLOC_FUNCS = {"realloc"}
    _SYSV_ARGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
    _WIN64_ARGS = ("rcx", "rdx", "r8", "r9")
    _DANGEROUS_CALLS = {"memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat",
                        "sprintf", "snprintf", "printf", "fprintf", "fwrite",
                        "read", "recv", "fread", "free", "_ZdlPv", "g_free",
                        "strlen", "strcmp", "strncmp"}

    def __init__(self, use_win64_abi: bool = False):
        self._objects: Dict[int, HeapObject] = {}
        self._reg_to_obj: Dict[str, int] = {}
        self._addr_to_obj: Dict[int, int] = {}
        self._stack_to_obj: Dict[str, int] = {}
        self._findings: List[dict] = []
        self._next_obj_id = 1
        self._free_count: Dict[int, int] = defaultdict(int)
        self._arg_regs = self._WIN64_ARGS if use_win64_abi else self._SYSV_ARGS
        self._ins_snapshot: Dict[int, dict] = {}
        self._current_addr: int = 0
        self._reg_to_global: Dict[str, int] = {}
        self._user_func_ranges: List[Tuple[int, int]] = []
        self._pre_analyzer = UAFPreAnalyzer()
        self._path_analyzer = PathAnalyzer()
        self._interproc = InterprocFreeAnalyzer(use_win64_abi=use_win64_abi)
        self._deref_checker = DerefChecker(self)
        self._propagator = PointerPropagator(self)
        self._finalizer = UAFFinalizer(self)
        self._all_instructions: List[dict] = []

    def set_user_func_ranges(self, ranges: List[Tuple[int, int]]):
        self._user_func_ranges = sorted(ranges, key=lambda r: r[0])

    def _is_user_code(self, addr: int) -> bool:
        if not self._user_func_ranges: return True
        for lo, hi in self._user_func_ranges:
            if lo <= addr < hi: return True
        return False

    def _is_crt_code(self, addr: int) -> bool:
        return not self._is_user_code(addr)

    def pre_analyze(self, instructions: List[dict]):
        """Phase 0: 构建函数索引+路径范围图+过程间free摘要."""
        self._all_instructions = instructions
        self._pre_analyzer.analyze_from_instructions(instructions)
        if not self._user_func_ranges:
            self._user_func_ranges = self._pre_analyzer.user_func_ranges
        self._path_analyzer.build_scope_map(instructions, self._user_func_ranges)
        self._interproc.build_summaries(instructions, self._user_func_ranges)

    def analyze_instruction(self, ins: dict):
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        addr = ins.get("address", 0)
        self._current_addr = addr
        self._ins_snapshot[addr] = ins
        if len(self._ins_snapshot) > 200:
            del self._ins_snapshot[min(self._ins_snapshot.keys())]

        if mnem == "call" and ops:
            self._handle_call(ins, ops, addr)
        elif mnem == "jmp" and ops:
            self._handle_jmp_tailcall(ins, ops, addr)
        self._deref_checker.check_deref(ops, addr, mnem)
        if mnem in ("mov", "lea", "movzx", "movsx", "movsxd") and len(ops) >= 2:
            self._propagator.propagate(ins, ops[0], ops[1], addr)
        if mnem == "xor" and len(ops) >= 2:
            dst, src = norm_reg(ops[0]), norm_reg(ops[1])
            if dst == src:
                self._reg_to_obj.pop(dst, None)
                self._reg_to_global.pop(dst, None)
        if mnem == "mov" and len(ops) >= 2:
            dst_op, src_op = ops[0].strip(), ops[1].strip()
            dst_reg = norm_reg(dst_op)
            if parse_immediate(src_op) == 0 and dst_reg:
                self._reg_to_obj.pop(dst_reg, None)
                self._reg_to_global.pop(dst_reg, None)
            if "[" in dst_op.lower():
                self._check_global_reassign(ins, ops, addr)
        if mnem == "ret" and self._is_user_code(addr):
            for reg in ("rax","rcx","rdx","r8","r9","r10","r11",
                        "eax","ecx","edx","r8d","r9d","r10d","r11d"):
                self._reg_to_obj.pop(reg, None)
                self._reg_to_global.pop(reg, None)
            self._stack_to_obj.clear()

    def _handle_jmp_tailcall(self, ins: dict, ops: List[str], addr: int):
        """识别 jmp free 等tail-call模式: Os将call+jmp+ret优化为jmp."""
        func = extract_func_name(ops[0])
        if func in self.FREE_FUNCS:
            freed_oid = self._resolve_free_arg(ins, addr)
            if freed_oid is not None:
                obj = self._objects.get(freed_oid)
                if obj:
                    self._free_count[addr] += 1
                    if len(obj.freed_at) >= 1 and self._is_user_code(addr):
                        first_free = obj.freed_at[-1]
                        if not self._path_analyzer.are_mutually_exclusive(
                                first_free, addr):
                            self._findings.append({"type":"double_free",
                                "address":addr,"obj_id":freed_oid,
                                "severity":"critical",
                                "first_free_at":first_free})
                    obj.freed_at.append(addr)
        elif func in self._DANGEROUS_CALLS or \
                self._interproc.is_free_like(func) or \
                func in self._interproc._summaries:
            self._check_call_args_uaf(ins, func, addr)

    def _handle_call(self, ins: dict, ops: List[str], addr: int):
        func = extract_func_name(ops[0])
        if func in self.ALLOC_FUNCS:
            if not self._is_user_code(addr): return
            self._reg_to_obj.pop("rax", None); self._reg_to_obj.pop("eax", None)
            obj = HeapObject(self._next_obj_id, addr)
            self._objects[self._next_obj_id] = obj
            self._reg_to_obj["rax"] = self._reg_to_obj["eax"] = self._next_obj_id
            self._next_obj_id += 1
        elif func in self.REALLOC_FUNCS:
            if self._is_user_code(addr): self._handle_realloc(ins, ops, addr)
        elif func in self.FREE_FUNCS:
            freed_oid = self._resolve_free_arg(ins, addr)
            if freed_oid is not None:
                obj = self._objects.get(freed_oid)
                if obj:
                    self._free_count[addr] += 1
                    # 基于对象 freed_at 长度判定 double free: 同一对象第二次 free 即 DF
                    if len(obj.freed_at) >= 1 and self._is_user_code(addr):
                        first_free = obj.freed_at[-1]
                        if not self._path_analyzer.are_mutually_exclusive(
                                first_free, addr):
                            self._findings.append({"type":"double_free",
                                "address":addr,"obj_id":freed_oid,
                                "severity":"critical",
                                "first_free_at":first_free})
                    obj.freed_at.append(addr)
            self._reg_to_obj.pop(self._arg_regs[0] if self._arg_regs else "rcx", None)
        else:
            self._check_call_args_uaf(ins, func, addr)
            self._check_interproc_free(ins, func, addr)

    def _check_interproc_free(self, ins: dict, func: str, addr: int):
        """过程间free摘要: callee会释放参数→标记对应对象freed."""
        freed_params = self._interproc.get_freed_params(func)
        if not freed_params: return
        for pidx in freed_params:
            if pidx >= len(self._arg_regs): continue
            oid = self._reg_to_obj.get(self._arg_regs[pidx])
            if oid is not None and oid in self._objects:
                self._objects[oid].freed_at.append(addr)

    def _handle_realloc(self, ins: dict, ops: List[str], addr: int):
        arg0 = self._arg_regs[0] if self._arg_regs else "rdi"
        old_oid = self._reg_to_obj.get(arg0) or self._resolve_free_arg(ins, addr)
        if old_oid is not None and old_oid in self._objects:
            obj = self._objects[old_oid]
            obj.realloc_count += 1; obj.freed_at.append(addr)
            new_obj = HeapObject(self._next_obj_id, addr)
            self._objects[self._next_obj_id] = new_obj
            self._reg_to_obj["rax"] = self._reg_to_obj["eax"] = self._next_obj_id
            self._next_obj_id += 1
        else:
            obj = HeapObject(self._next_obj_id, addr)
            self._objects[self._next_obj_id] = obj
            self._reg_to_obj["rax"] = self._reg_to_obj["eax"] = self._next_obj_id
            self._next_obj_id += 1

    def _check_global_reassign(self, ins: dict, ops: List[str], addr: int):
        op_dst = ops[0].strip(); mem_part = op_dst
        for prefix in ("QWORD PTR ","DWORD PTR ","WORD PTR ","BYTE PTR "):
            if prefix in op_dst.upper():
                mem_part = op_dst.upper().split(prefix,1)[1]; break
        if not mem_part.startswith("["):
            mem_part = op_dst[op_dst.find("["):] if "[" in op_dst else op_dst
        abs_addr = resolve_rip_relative(ins, mem_part, addr)
        if abs_addr is None: return
        old_oid = self._addr_to_obj.get(abs_addr)
        if old_oid is None: return
        src_reg = norm_reg(ops[1].strip()); src_oid = self._reg_to_obj.get(src_reg)
        src_val = parse_immediate(ops[1].strip())
        obj = self._objects.get(old_oid)
        if src_oid is not None and src_oid != old_oid:
            self._addr_to_obj[abs_addr] = src_oid
        elif src_oid is None and src_val is not None and obj and obj.freed_at:
            if src_val == 0:
                obj.nulled_after_free = True
                obj.nulled_at = addr
            else:
                # 非零魔数赋值: 恢复已释放对象的可检测性
                obj.nulled_after_free = False

    def _resolve_free_arg(self, ins: dict, addr: int) -> Optional[int]:
        arg0 = self._arg_regs[0]
        oid = self._reg_to_obj.get(arg0)
        if oid is not None: return oid
        for a in sorted(self._ins_snapshot.keys(), reverse=True):
            if a >= addr: continue
            past = self._ins_snapshot[a]
            pm = past.get("mnemonic","").lower(); po = past.get("operands",[])
            if pm in ("mov","lea","movzx","movsx") and len(po) >= 2:
                if norm_reg(po[0].strip()) == arg0:
                    src_reg = norm_reg(po[1].strip())
                    oid = self._reg_to_obj.get(src_reg)
                    if oid is not None: return oid
                    abs_addr = resolve_rip_relative(past, po[1].strip(), a)
                    if abs_addr is not None:
                        oid = self._addr_to_obj.get(abs_addr)
                        if oid is not None: return oid
                    break
            if pm == "call": break
        return None

    def _check_call_args_uaf(self, ins: dict, func: str, addr: int):
        if not self._is_user_code(addr):
            return
        # 检查两类函数: 危险库函数 + 所有已知用户函数(可能内部解引用参数)
        is_dangerous = func in self._DANGEROUS_CALLS
        is_known_user = self._interproc.is_free_like(func) or \
                        func in self._interproc._summaries
        if not is_dangerous and not is_known_user:
            return
        for ai, ar in enumerate(self._arg_regs):
            if ai >= 4: break
            oid = self._reg_to_obj.get(ar)
            if oid is not None and oid in self._objects:
                obj = self._objects[oid]
                if obj.freed_at and not obj.nulled_after_free:
                    if self._path_analyzer.are_mutually_exclusive(obj.freed_at[-1], addr):
                        return
                    gap = addr - obj.freed_at[-1]
                    obj.use_after_free_at.append(addr)
                    self._findings.append({"type":"use_after_free","address":addr,
                        "obj_id":oid,"freed_at":obj.freed_at[-1],"instr_gap":gap,
                        "function":func,"severity":"critical" if gap>100 else "high"})
                    return

    def _track_pointer_move(self, ins: dict, dst_op: str, src_op: str, addr: int):
        dst_raw, src_raw = dst_op.strip(), src_op.strip()
        dst_reg, src_reg = norm_reg(dst_raw), norm_reg(src_raw)
        if not ("[" in dst_raw.lower() or "[" in src_raw.lower()):
            oid = self._reg_to_obj.get(src_reg)
            if oid is not None: self._reg_to_obj[dst_reg] = oid
            return
        if "[" in dst_raw.lower():
            abs_addr = resolve_rip_relative(ins, dst_raw, addr)
            if abs_addr is not None:
                oid = self._reg_to_obj.get(src_reg)
                if oid is not None: self._addr_to_obj[abs_addr] = oid
                return
            if self._is_user_code(addr):
                slot = extract_stack_slot(dst_raw)
                if slot is not None:
                    oid = self._reg_to_obj.get(src_reg)
                    if oid is not None:
                        self._stack_to_obj[slot] = oid
                    else:
                        # 源为0/常量/未知: 栈槽已不指向任何堆对象,
                        # 必须清除旧映射, 否则置空后误判为UAF.
                        self._stack_to_obj.pop(slot, None)
                    return
                if is_indexed_access(dst_raw) and self._is_user_code(addr):
                    gbase = resolve_global_array_base(dst_raw, self._ins_snapshot, self._current_addr)
                    if gbase is not None:
                        oid = self._reg_to_obj.get(src_reg)
                        if oid is not None: self._addr_to_obj[gbase] = oid
                        return
        if "[" in src_raw.lower():
            abs_addr = resolve_rip_relative(ins, src_raw, addr)
            if abs_addr is not None:
                self._reg_to_global[dst_reg] = abs_addr
                oid = self._addr_to_obj.get(abs_addr)
                if oid is not None:
                    self._reg_to_obj[dst_reg] = oid
                    return
                oid = match_global_array_elem(ins, src_raw, addr, self._addr_to_obj)
                if oid is not None:
                    self._reg_to_obj[dst_reg] = oid
                    return
            if self._is_user_code(addr):
                slot = extract_stack_slot(src_raw)
                if slot is not None:
                    oid = self._stack_to_obj.get(slot)
                    if oid is not None:
                        self._reg_to_obj[dst_reg] = oid
                        return
                base_reg = extract_base_reg(src_raw)
                if base_reg is not None:
                    gbase = self._reg_to_global.get(base_reg)
                    if gbase is not None:
                        oid = self._addr_to_obj.get(gbase)
                        if oid is not None:
                            self._reg_to_obj[dst_reg] = oid
                            return
            if is_indexed_access(src_raw):
                gbase = resolve_global_array_base(src_raw, self._ins_snapshot, self._current_addr)
                if gbase is not None:
                    oid = self._addr_to_obj.get(gbase)
                    if oid is not None:
                        self._reg_to_obj[dst_reg] = oid
                        return
                return
            self._reg_to_obj.pop(dst_reg, None)
            return

    def finalize(self, instructions: List[dict]) -> List[dict]:
        return self._finalizer.finalize(instructions)

    def stats(self) -> dict:
        return self._finalizer.stats()

    @property
    def findings(self) -> List[dict]:
        return list(self._findings)


__all__ = ["UAFDetector", "HeapObject"]
