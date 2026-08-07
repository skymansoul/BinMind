# UAF 解引用检查器.
# 职责: 检测已释放指针的解引用 + cleanup-pattern 误报抑制
# 创建: 2026-07-12
# 修改: 2026-07-12 — cleanup抑制增加读写区分和同对象校验

from typing import Dict, List, Optional

from .disasm_util import norm_reg, resolve_rip_relative, extract_func_name


class DerefChecker:
    """已释放指针解引用检测器."""

    _PTR_PREFIXES = ("xmmword ptr ", "ymmword ptr ", "qword ptr ",
                     "dword ptr ", "word ptr ", "byte ptr ")

    def __init__(self, detector):
        self._det = detector

    def check_deref(self, ops: List[str], addr: int, mnem: str = ""):
        """检查操作数中是否有已释放指针的解引用.

        mnem用于区分读写: mov [reg], imm 是写入型解引用(不应被cleanup抑制).
        """
        if not self._det._is_user_code(addr):
            return
        is_write = self._is_write_deref(ops, mnem)
        for op in ops:
            op_s = op.strip().lower()
            for prefix in self._PTR_PREFIXES:
                if op_s.startswith(prefix):
                    op_s = op_s[len(prefix):]
                    break
            if not (op_s.startswith("[") and "]" in op_s):
                continue
            inner = op_s[op_s.find("[") + 1:op_s.rfind("]")]
            base = inner.split("+")[0].split("-")[0].split("*")[0].strip()
            oid = self._det._reg_to_obj.get(base)
            if oid is None or oid not in self._det._objects:
                continue
            obj = self._det._objects[oid]
            if obj.freed_at:
                if self._det._path_analyzer.are_mutually_exclusive(
                        obj.freed_at[-1], addr):
                    return
                if not is_write and self._is_cleanup_pattern(oid, addr):
                    return
                gap = addr - obj.freed_at[-1]
                obj.use_after_free_at.append(addr)
                self._det._findings.append({
                    "type": "use_after_free", "address": addr,
                    "obj_id": oid, "freed_at": obj.freed_at[-1],
                    "instr_gap": gap, "deref_reg": op,
                    "severity": "critical" if gap > 100 else "high"})

    @staticmethod
    def _is_write_deref(ops: List[str], mnem: str) -> bool:
        """判定解引用是写入还是读取.

        mov [reg], imm 和 mov [reg], reg 是写入; mov reg, [reg] 是读取.
        dst在内存操作数侧为写入.
        """
        if mnem not in ("mov", "movzx", "movsx"):
            return False
        if len(ops) < 2:
            return False
        dst = ops[0].strip().lower()
        return "[" in dst

    def _is_cleanup_pattern(self, oid: int, addr: int) -> bool:
        """cleanup-pattern抑制: free(obj); free(obj->field) 语义安全.

        释放结构体后读取其字段指针用于二次free — 属于清理代码,
        读取已释放内存虽技术上是UB, 但语义意图是清理而非UAF利用.
        判定条件:
          1. deref为读取型(非写入)
          2. deref后4条指令内有free-call
          3. 后续free的目标与已释放对象关联(同一对象或其字段)
        """
        obj = self._det._objects.get(oid)
        if not obj or not obj.freed_at:
            return False
        gap = addr - obj.freed_at[-1]
        if gap > 50:
            return False
        idx = None
        for i, ins in enumerate(self._det._all_instructions):
            if ins.get("address", 0) == addr:
                idx = i
                break
        if idx is None:
            return False
        for j in range(idx + 1, min(idx + 4, len(self._det._all_instructions))):
            nxt = self._det._all_instructions[j]
            if nxt.get("mnemonic", "").lower() == "call" and nxt.get("operands"):
                callee = extract_func_name(nxt["operands"][0])
                if callee in self._det.FREE_FUNCS:
                    if self._free_targets_same_obj(j, oid):
                        return True
                break
        return False

    def _free_targets_same_obj(self, free_call_idx: int, oid: int) -> bool:
        """判定free-call的参数是否指向同一已释放对象或其字段.

        cross_free模式: free(q) 后续free释放不同对象 → 不抑制.
        cleanup模式: free(obj) 后续free(obj->field) 或 free(obj) → 抑制.
        """
        free_arg = self._det._arg_regs[0] if self._det._arg_regs else "rcx"
        insns = self._det._all_instructions
        start = max(0, free_call_idx - 5)
        for k in range(free_call_idx - 1, start - 1, -1):
            ins = insns[k]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if mnem in ("mov", "movzx") and len(ops) >= 2:
                dst = norm_reg(ops[0])
                if dst == free_arg:
                    src_reg = norm_reg(ops[1].strip())
                    src_oid = self._det._reg_to_obj.get(src_reg)
                    if src_oid == oid:
                        return True
                    src_raw = ops[1].strip().lower()
                    if "[" in src_raw:
                        base = self._extract_base(src_raw)
                        base_oid = self._det._reg_to_obj.get(base)
                        if base_oid == oid:
                            return True
                    return False
            if mnem == "call":
                break
        return False

    @staticmethod
    def _extract_base(operand: str) -> str:
        """从 [rcx+0x8] 提取基址寄存器."""
        o = operand.strip().lower()
        idx = o.find("[")
        if idx < 0:
            return ""
        inner = o[idx + 1:o.find("]", idx)]
        return norm_reg(inner.split("+")[0].split("-")[0].split("*")[0].strip())


__all__ = ["DerefChecker"]
