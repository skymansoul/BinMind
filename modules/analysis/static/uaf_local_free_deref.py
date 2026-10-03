# 同函数内寄存器级 Free→Deref 检测.
#
# 检测同一函数内, free参数通过寄存器/栈传递而非全局变量的UAF:
#   alloc; ...; mov rcx,rax; mov [rsp+x],rax; call free; mov rax,[rsp+x]; deref [rax]
#
# 线性指令流中ret会清空寄存器映射, 导致error path上的free→deref漏检.
# 本模块在finalize阶段做后处理, 通过全指令流回溯重建关联.
#

from typing import Dict, List, Optional, Set, Tuple

from .disasm_util import resolve_rip_relative, extract_func_name, norm_reg
from .uaf_operand_utils import is_indexed_access


class LocalFreeDerefScanner:
    """同函数内寄存器级 free→deref 后处理检测器."""

    _FREE_FUNCS = {"free", "_ZdlPv", "_ZdaPv", "operator_delete",
                   "g_free", "ExFreePool", "__builtin_free"}
    _DEREF_MNEMS = {"mov", "movzx", "movsx", "movsxd", "cmp", "test",
                    "add", "sub", "lea"}

    def __init__(self, detector):
        self._det = detector

    def scan(self, instructions: List[dict]) -> List[dict]:
        """扫描非全局变量路径上的 free→deref 模式."""
        findings: List[dict] = []
        addr_to_idx: Dict[int, int] = {}
        for idx, ins in enumerate(instructions):
            addr_to_idx[ins.get("address", 0)] = idx

        for idx, ins in enumerate(instructions):
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            addr = ins.get("address", 0)
            if mnem not in ("call", "jmp") or not ops:
                continue
            callee = extract_func_name(ops[0])
            if callee not in self._FREE_FUNCS:
                continue
            if not self._det._is_user_code(addr):
                continue

            oid = self._trace_free_to_alloc(instructions, idx, addr)
            if oid is None or oid not in self._det._objects:
                continue
            obj = self._det._objects[oid]
            if addr in obj.freed_at:
                continue
            obj.freed_at.append(addr)
            deref_addr = self._check_deref_after_free(
                instructions, idx, addr, oid)
            if deref_addr is not None:
                gap = deref_addr - addr
                if self._det._path_analyzer.are_mutually_exclusive(
                        addr, deref_addr):
                    continue
                findings.append({
                    "type": "use_after_free",
                    "address": deref_addr,
                    "obj_id": oid,
                    "freed_at": addr,
                    "instr_gap": gap,
                    "deref_reg": "local",
                    "severity": "critical" if gap > 100 else "high",
                })
        return findings

    def _trace_free_to_alloc(self, instructions: List[dict],
                             free_idx: int,
                             free_addr: int) -> Optional[int]:
        """回溯free参数(rcx)到call malloc, 返回obj_id.

        模式: call malloc; ...; mov rcx,rax; call free
        或者: call malloc; ...; mov [rsp+x],rax; ...; mov rcx,[rsp+x]; call free
        """
        arg0 = self._det._arg_regs[0] if self._det._arg_regs else "rcx"
        search_reg = arg0
        for k in range(free_idx - 1, max(-1, free_idx - 40), -1):
            ins = instructions[k]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if mnem == "call" and ops:
                func = extract_func_name(ops[0])
                if func in self._det.ALLOC_FUNCS:
                    alloc_addr = ins.get("address", 0)
                    for oid, obj in self._det._objects.items():
                        if obj.alloc_addr == alloc_addr:
                            return oid
                    break
                if func in self._FREE_FUNCS:
                    continue
            if mnem in ("mov", "movzx", "movsx") and len(ops) >= 2:
                dst = norm_reg(ops[0].strip())
                src = norm_reg(ops[1].strip())
                if dst == search_reg:
                    if src in ("rax", "eax"):
                        search_reg = "rax"
                    elif "[" in ops[1].lower():
                        slot = self._extract_stack_key(ops[1])
                        if slot is not None:
                            search_reg = self._find_stack_to_reg(
                                instructions, k, slot) or search_reg
        return None

    def _check_deref_after_free(self, instructions: List[dict],
                                free_idx: int, free_addr: int,
                                oid: int) -> Optional[int]:
        """检查free后是否有指针解引用.

        通过_identify_freed_ptr_slots精确确定存储了被释放指针的栈slot,
        然后正向扫描检查这些slot是否在free后被加载并解引用.
        """
        arg0 = self._det._arg_regs[0] if self._det._arg_regs else "rcx"
        saved_slots = self._identify_freed_ptr_slots(
            instructions, free_idx, arg0)

        if not saved_slots:
            return None

        loaded_regs: Set[str] = set()
        limit = min(free_idx + 30, len(instructions))
        for k in range(free_idx + 1, limit):
            ins = instructions[k]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            addr = ins.get("address", 0)
            if not self._det._is_user_code(addr):
                continue
            if mnem in ("ret", "jmp"):
                break
            loaded_regs = self._track_load(
                mnem, ops, addr, saved_slots, loaded_regs)
            loaded_regs = self._propagate(mnem, ops, loaded_regs)
            deref = self._check_deref(mnem, ops, addr, loaded_regs)
            if deref is not None:
                return deref
        return None

    @staticmethod
    def _extract_stack_key(operand: str) -> Optional[str]:
        """从 [rsp+0x28] 提取 'rsp+0x28' 作为栈slot标识."""
        op = operand.lower()
        if "[" not in op or "]" not in op:
            return None
        inner = op[op.find("[") + 1:op.rfind("]")]
        parts = inner.replace(" ", "").split("+")
        valid = [p for p in parts
                 if p.startswith("r") or p.startswith("0x") or p.isdigit()]
        if not valid:
            return None
        return "+".join(valid)

    def _identify_freed_ptr_slots(self, instructions: List[dict],
                                  free_idx: int,
                                  free_reg: str) -> Set[str]:
        """回溯free参数, 精确确定存储了被释放指针的栈slot.

        两阶段策略避免单遍反向扫描的顺序敏感问题:
        Pass1扩展别名集: 从free_reg反向扫描, 当遇到mov rcx,rax时
        将rax加入别名集-此时rax在更早的mov [slot],rax中才有效.
        Pass2收集栈slot: 用完整别名集重新反向扫描, 收集所有
        mov [slot], reg(∈别名集) 的slot.
        """
        alias_regs = self._build_alias_set(instructions, free_idx, free_reg)
        return self._collect_slots_with_aliases(
            instructions, free_idx, alias_regs)

    def _build_alias_set(self, instructions: List[dict],
                         free_idx: int, free_reg: str) -> Set[str]:
        """Pass1: 反向扫描构建被释放指针的完整寄存器别名集.

        当遇到mov reg, [slot]时kill reg-此时reg被重新赋值为slot内容,
        不再持有被释放指针. 这防止将更早的同名寄存器存储误纳入别名.
        """
        alias: Set[str] = {free_reg}
        for k in range(free_idx - 1, max(-1, free_idx - 40), -1):
            ins = instructions[k]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if mnem == "call":
                if ops:
                    func = extract_func_name(ops[0])
                    if func in self._FREE_FUNCS:
                        continue
                    if func in self._det.ALLOC_FUNCS:
                        break
                continue
            if mnem not in ("mov", "movzx", "movsx") or len(ops) < 2:
                continue
            dst_raw = ops[0].strip()
            src_raw = ops[1].strip()
            dst_norm = norm_reg(dst_raw)
            src_norm = norm_reg(src_raw)
            if "[" in dst_raw.lower():
                continue
            if "[" in src_raw.lower():
                alias.discard(dst_norm)
                continue
            if dst_norm in alias and src_norm not in ("rsp", "rbp", "rip"):
                alias.add(src_norm)
        return alias

    def _collect_slots_with_aliases(self, instructions: List[dict],
                                    free_idx: int,
                                    alias_regs: Set[str]) -> Set[str]:
        """Pass2: 用完整别名集收集所有存储了被释放指针的栈slot."""
        slots: Set[str] = set()
        for k in range(free_idx - 1, max(-1, free_idx - 40), -1):
            ins = instructions[k]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if mnem == "call":
                if ops:
                    func = extract_func_name(ops[0])
                    if func in self._FREE_FUNCS:
                        continue
                    if func in self._det.ALLOC_FUNCS:
                        break
                continue
            if mnem not in ("mov", "movzx", "movsx") or len(ops) < 2:
                continue
            dst_raw = ops[0].strip()
            if "[" in dst_raw.lower():
                slot = self._extract_stack_key(dst_raw)
                if slot and norm_reg(ops[1].strip()) in alias_regs:
                    slots.add(slot)
        return slots

    @staticmethod
    def _find_stack_to_reg(instructions: List[dict], before_idx: int,
                           slot: str) -> Optional[str]:
        """在before_idx之前找 mov [slot], reg → 返回reg."""
        for k in range(before_idx - 1, max(-1, before_idx - 30), -1):
            ins = instructions[k]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if mnem in ("mov", "movzx", "movsx") and len(ops) >= 2:
                if LocalFreeDerefScanner._extract_stack_key(ops[0]) == slot:
                    return norm_reg(ops[1].strip())
        return None

    @staticmethod
    def _track_load(mnem: str, ops: List[str], addr: int,
                    saved_slots: Set[str], loaded_regs: Set[str]) -> Set[str]:
        if mnem not in ("mov", "movzx", "movsx", "movsxd") or len(ops) < 2:
            return loaded_regs
        dst = norm_reg(ops[0].strip())
        src_slot = LocalFreeDerefScanner._extract_stack_key(ops[1])
        if src_slot is not None and src_slot in saved_slots:
            loaded_regs.add(dst)
        return loaded_regs

    @staticmethod
    def _propagate(mnem: str, ops: List[str],
                   loaded_regs: Set[str]) -> Set[str]:
        if mnem not in ("mov", "movzx", "movsx", "movsxd") or len(ops) < 2:
            return loaded_regs
        dst = norm_reg(ops[0].strip())
        src = norm_reg(ops[1].strip())
        if src in loaded_regs:
            loaded_regs.add(dst)
        elif dst in loaded_regs and "[" not in ops[1].lower():
            loaded_regs.discard(dst)
        return loaded_regs

    @staticmethod
    def _check_deref(mnem: str, ops: List[str], addr: int,
                     loaded_regs: Set[str]) -> Optional[int]:
        if not loaded_regs or mnem not in LocalFreeDerefScanner._DEREF_MNEMS:
            return None
        for op in ops:
            op_s = op.strip().lower()
            for prefix in ("qword ptr ", "dword ptr ", "word ptr ", "byte ptr "):
                if op_s.startswith(prefix):
                    op_s = op_s[len(prefix):]
                    break
            if "[" in op_s and "]" in op_s:
                inner = op_s[op_s.find("[") + 1:op_s.rfind("]")]
                base = inner.split("+")[0].split("-")[0].split("*")[0].strip()
                if base in loaded_regs:
                    return addr
        return None


__all__ = ["LocalFreeDerefScanner"]
