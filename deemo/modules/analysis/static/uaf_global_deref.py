# 全局变量 Free 后解引用检查.
#
# 扫描 free 后指令流: 全局变量被加载到寄存器后解引用即为 UAF.
# 若全局变量在 free 后被新 malloc 赋值, 停止扫描.
#

from typing import List, Optional, Set

from .disasm_util import resolve_rip_relative, extract_func_name, norm_reg


class GlobalDerefChecker:
    """全局变量 free 后解引用检测器."""

    def __init__(self, detector):
        self._det = detector

    def check(self, instructions: List[dict], start_idx: int,
              global_addr: int, free_addr: int, oid: int) -> Optional[int]:
        """检查全局变量在 free 后是否被加载并解引用.

        返回解引用地址, 或None(安全).
        loaded_regs 追踪全局变量值传播到的所有寄存器.
        """
        loaded_regs: Set[str] = set()
        for j in range(start_idx, min(start_idx + 50, len(instructions))):
            ins = instructions[j]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            addr = ins.get("address", 0)
            if not self._det._is_user_code(addr):
                continue

            if self._is_reassign_to_new(instructions, j, ins, ops,
                                         mnem, addr, global_addr,
                                         start_idx, free_addr):
                return None

            loaded_regs = self._track_global_load(
                mnem, ops, addr, global_addr, loaded_regs)
            loaded_regs = self._propagate_regs(mnem, ops, loaded_regs)

            deref = self._check_deref(mnem, ops, addr, loaded_regs)
            if deref is not None:
                return deref

            call_deref = self._check_call_deref(mnem, ops, addr, loaded_regs)
            if call_deref is not None:
                return call_deref

            if mnem == "ret":
                loaded_regs = set()

        return None

    def _is_reassign_to_new(self, instructions: List[dict], j: int,
                            ins: dict, ops: List[str], mnem: str,
                            addr: int, global_addr: int,
                            start_idx: int = 0,
                            free_addr: int = 0) -> bool:
        """全局变量被新malloc返回值覆盖 → 旧UAF不再适用.

        排除跨函数: free到store之间有ret或jmp(tail-call) → 不同函数.
        """
        if mnem != "mov" or len(ops) < 2:
            return False
        dst_raw = ops[0].strip()
        if "rip" not in dst_raw.lower() or "[" not in dst_raw.lower():
            return False
        gaddr = resolve_rip_relative(ins, dst_raw, addr)
        if gaddr != global_addr:
            return False
        src_reg = norm_reg(ops[1].strip())
        if src_reg not in ("rax", "eax") or j == 0:
            return False
        # 确定free指令在指令流中的索引
        free_idx = start_idx
        for k in range(start_idx - 1, max(-1, start_idx - 5), -1):
            if instructions[k].get("address", 0) == free_addr:
                free_idx = k
                break
        if free_idx < start_idx:
            # free指令到start_idx之间有ret/jmp → 跨函数
            for k in range(free_idx, start_idx):
                kmn = instructions[k].get("mnemonic", "").lower()
                if kmn in ("ret", "jmp"):
                    return False
        # start_idx到store之间的函数边界检测
        for k in range(start_idx, j):
            kmn = instructions[k].get("mnemonic", "").lower()
            if kmn in ("ret", "jmp"):
                return False
        prev = instructions[j - 1]
        if prev.get("mnemonic", "").lower() != "call" or not prev.get("operands"):
            return False
        prev_func = extract_func_name(prev["operands"][0])
        return prev_func in self._det.ALLOC_FUNCS

    @staticmethod
    def _track_global_load(mnem: str, ops: List[str], addr: int,
                           global_addr: int,
                           loaded_regs: Set[str]) -> Set[str]:
        """追踪 mov rax,[rip+global] 加载到 loaded_regs 集合."""
        if mnem not in ("mov", "movzx", "movsx", "movsxd", "lea"):
            return loaded_regs
        if len(ops) < 2:
            return loaded_regs
        dst = norm_reg(ops[0].strip())
        src_raw = ops[1].strip()
        if "rip" not in src_raw.lower() or "[" not in src_raw.lower():
            return loaded_regs
        gaddr = resolve_rip_relative(
            {"mnemonic": mnem, "operands": ops}, src_raw, addr)
        if gaddr == global_addr:
            loaded_regs.add(dst)
        return loaded_regs

    @staticmethod
    def _propagate_regs(mnem: str, ops: List[str],
                        loaded_regs: Set[str]) -> Set[str]:
        """追踪 mov dst, src 的寄存器间传播: loaded_regs 中 src 被传播到 dst."""
        if mnem not in ("mov", "movzx", "movsx", "movsxd"):
            return loaded_regs
        if len(ops) < 2:
            return loaded_regs
        dst = norm_reg(ops[0].strip())
        src = norm_reg(ops[1].strip())
        if not dst or not src:
            return loaded_regs
        if src in loaded_regs:
            loaded_regs.add(dst)
        elif dst in loaded_regs:
            if "[" not in ops[1].lower():
                loaded_regs.discard(dst)
        return loaded_regs

    @staticmethod
    def _check_deref(mnem: str, ops: List[str], addr: int,
                     loaded_regs: Set[str]) -> Optional[int]:
        """检查已加载寄存器的内存解引用."""
        if not loaded_regs:
            return None
        if mnem not in ("mov", "movzx", "movsx", "movsxd", "cmp", "test"):
            return None
        for op in ops:
            op_s = op.strip().lower()
            for prefix in ("qword ptr ", "dword ptr ", "word ptr ", "byte ptr "):
                if op_s.startswith(prefix):
                    op_s = op_s[len(prefix):]
                    break
            if "[" in op_s and "]" in op_s:
                inner = op_s[op_s.find("[")+1:op_s.rfind("]")]
                base = inner.split("+")[0].split("-")[0].split("*")[0].strip()
                if base in loaded_regs:
                    return addr
        return None

    def _check_call_deref(self, mnem: str, ops: List[str], addr: int,
                           loaded_regs: Set[str]) -> Optional[int]:
        """检查 call/jmp tail-call 指令参数是否使用了已释放的全局变量.

        jmp tail-call: O2/Os将 call+ret 优化为 jmp,
        参数寄存器中可能携带已释放指针.
        """
        if not loaded_regs:
            return None
        if mnem not in ("call", "jmp") or not ops:
            return None
        func = extract_func_name(ops[0])
        is_dangerous = func in self._det._DANGEROUS_CALLS
        is_known_user = self._det._interproc.is_free_like(func) or \
            func in self._det._interproc._summaries
        if not is_dangerous and not is_known_user:
            return None
        for ar in self._det._arg_regs[:4]:
            if ar in loaded_regs:
                return addr
        return None


__all__ = ["GlobalDerefChecker"]
