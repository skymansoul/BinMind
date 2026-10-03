"""溢出后写入验证 - 欠分配后的写入量是否构成利用路径.

误报根源: binary_int_overflow_scanner 只报告 imul→malloc 数据流,
不验证分配后的写入 - 固定小写入的样本 (不可利用) 与
循环大写入的样本 (CWE-680) 被同等对待.
本模块对 malloc 调用点之后的指令窗口 (≤40 条) 检查:
  1. memcpy/memset/memmove 调用: 目标为分配指针, 大小参数
  2. 循环写形态: mov [ptr+idx*scale], val (索引寄存器)
写入总量可静态下界化且超过分配大小 → 高危; 无写入或
固定小量 → 安全.
"""

from typing import Dict, List, Optional, Tuple

from ..heap_analysis.instruction_parser import InstructionParser

_WINDOW = 40
_COPY_FUNCS = {"memcpy", "memmove", "memset", "strcpy", "strncpy",
               "__mingw_memcpy", "__mingw_memset"}


class WriteValidation:
    """分配后写入验证器 - 返回写入形态证据."""

    def __init__(self, insns: list):
        self._insns = insns
        self._addr_to_idx = {ins.address: i for i, ins in enumerate(insns)}

    def validate(self, alloc_addr: int) -> Tuple[str, int]:
        """alloc 调用点后的写入形态.

        返回 (kind, bytes): kind ∈ {"large", "loop", "small", "none"}.
        """
        idx = self._addr_to_idx.get(alloc_addr)
        if idx is None:
            return "none", 0
        # 分配指针在 rax
        ptr_regs = self._track_ptr(idx)
        if not ptr_regs:
            return "none", 0
        largest = 0
        for j in range(idx + 1, min(idx + _WINDOW, len(self._insns))):
            ins = self._insns[j]
            mn = ins.mnemonic
            if mn == "call" and ins.operands:
                callee = InstructionParser.extract_callee(ins)
                if callee in _COPY_FUNCS:
                    # dest=rcx/rdi; size: memcpy/memmove → rdx,
                    # memset → r8 (Win64: val 在 rdx, size 在 r8)
                    if self._reg_holds_ptr(j, "rcx", ptr_regs) or \
                            self._reg_holds_ptr(j, "rdi", ptr_regs):
                        size_regs = ("rdx", "r8") if "memset" not in callee \
                            else ("r8", "rdx")
                        sz = self._imm_at(j, size_regs)
                        if sz is not None:
                            largest = max(largest, sz)
                            if sz >= 0x1000:
                                return "large", sz
            elif mn == "mov" and len(ins.operands) >= 2:
                dst = ins.operands[0].strip()
                if "[" in dst:
                    base, _, scale, _ = \
                        InstructionParser.parse_memory_operand_full(dst)
                    # 写入目标经 mov/lea/add 链解析到分配指针
                    target = self._resolve_to_ptr(j, base or "", ptr_regs)
                    if target:
                        sz = InstructionParser.infer_access_size(ins)
                        largest = max(largest, sz)
                        if scale > 1:
                            return "loop", sz * scale
                        # 扁平化循环写: 写指令后存在回跳 jcc → 循环
                        if self._in_loop_after(j):
                            return "loop", sz
            if ins.address - self._insns[idx].address > 0x200:
                break
        if largest >= 0x1000:
            return "large", largest
        if largest > 8:
            return "small", largest
        return "none", 0

    def _track_ptr(self, alloc_idx: int) -> set:
        """分配后 rax 传播到的寄存器集合 (mov/add 链, ≤6 跳)."""
        ptrs = {"rax"}
        changed = True
        hops = 0
        while changed and hops < 6:
            changed = False
            hops += 1
            for j in range(alloc_idx + 1,
                           min(alloc_idx + _WINDOW, len(self._insns))):
                ins = self._insns[j]
                if len(ins.operands) < 2:
                    continue
                dst = InstructionParser.normalize_reg(ins.operands[0])
                if not dst:
                    continue
                if ins.mnemonic in ("mov", "movabs"):
                    src = InstructionParser.normalize_reg(ins.operands[1])
                    if src in ptrs and dst not in ptrs:
                        ptrs.add(dst)
                        changed = True
                elif ins.mnemonic in ("add", "lea"):
                    # add rdx, rax / lea rdx, [rax*4] - 基址传播
                    ops_text = " ".join(ins.operands)
                    if any(r in ptrs for r in
                           InstructionParser.KNOWN_REGS
                           if r in ops_text) and dst not in ptrs:
                        ptrs.add(dst)
                        changed = True
        return ptrs

    def _in_loop_after(self, idx: int) -> bool:
        """写指令之后 (≤20 条) 是否存在回跳 jcc - 循环写形态."""
        for j in range(idx + 1, min(idx + 20, len(self._insns))):
            ins = self._insns[j]
            if not ins.mnemonic.startswith("j") or not ins.operands:
                continue
            addr_part = ins.operands[0].strip().split()[0]
            try:
                target = int(addr_part, 16)
            except ValueError:
                continue
            if target < ins.address:
                return True
        return False

    def _resolve_to_ptr(self, idx: int, reg: str,
                        ptr_regs: set) -> bool:
        """寄存器链解析: reg 或其 mov/lea/add 来源是否 ∈ ptr_regs."""
        r = reg
        for hop in range(4):
            if r in ptr_regs:
                return True
            found = False
            for j in range(idx - 1, max(0, idx - 8), -1):
                ins = self._insns[j]
                if len(ins.operands) < 2:
                    continue
                dst = InstructionParser.normalize_reg(ins.operands[0])
                if dst != r:
                    continue
                if ins.mnemonic in ("mov", "movabs", "lea", "add"):
                    ops_text = " ".join(ins.operands)
                    hit = None
                    for known in InstructionParser.KNOWN_REGS:
                        if known in ops_text and known in ptr_regs:
                            hit = known
                            break
                    if hit:
                        return True
                    src = InstructionParser.normalize_reg(ins.operands[1])
                    if src:
                        r = src
                        found = True
                break
            if not found:
                return False
        return False

    def _reg_holds_ptr(self, idx: int, reg: str, ptr_regs: set) -> bool:
        """call/写入前 reg 是否持有分配指针 (寄存器链追迹)."""
        r = reg
        for hop in range(4):
            if r in ptr_regs:
                return True
            found = False
            for j in range(idx - 1, max(0, idx - 8), -1):
                ins = self._insns[j]
                if ins.mnemonic not in ("mov", "movabs") or \
                        len(ins.operands) < 2:
                    continue
                if InstructionParser.normalize_reg(ins.operands[0]) != r:
                    continue
                src = InstructionParser.normalize_reg(ins.operands[1])
                if src:
                    r = src
                    found = True
                break
            if not found:
                return False
        return False

    def _imm_at(self, idx: int, regs: Tuple[str, ...]) -> Optional[int]:
        """call 前指定寄存器的立即数 — 按寄存器优先级逐查."""
        for reg in regs:
            for j in range(idx - 1, max(0, idx - 8), -1):
                ins = self._insns[j]
                if ins.mnemonic not in ("mov", "movabs") or \
                        len(ins.operands) < 2:
                    continue
                if InstructionParser.normalize_reg(ins.operands[0]) == reg:
                    return InstructionParser._try_parse_int(
                        ins.operands[1])
        return None


# smoke test
def _check():
    class _I:
        def __init__(self, addr, mn, ops):
            self.address = addr
            self.mnemonic = mn
            self.operands = ops

    # malloc 后 memcpy(dst, src, 0x1000) → large
    insns = [
        _I(0x1000, "call", ["malloc"]),
        _I(0x1005, "mov", ["rcx", "rax"]),
        _I(0x1008, "mov", ["rdx", "0x1000"]),
        _I(0x100d, "call", ["memcpy"]),
    ]
    v = WriteValidation(insns)
    kind, n = v.validate(0x1000)
    assert kind == "large", f"应 large, got {kind}"
    # 无写入 → none
    insns2 = [_I(0x2000, "call", ["malloc"]),
              _I(0x2005, "ret", [])]
    v2 = WriteValidation(insns2)
    k2, _ = v2.validate(0x2000)
    assert k2 == "none", f"应 none, got {k2}"
    print("[OK] alloc_write_validate: 写入形态判定通过")


if __name__ == "__main__":
    _check()
