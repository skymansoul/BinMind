"""溯源门控分配归属 — 以目标寄存器溯源替代空间最近邻分配匹配.

误报根源: absint_adjudicator._find_nearest_alloc 在指针溯源缺失时,
将任意危险调用 (memcpy/strcpy...) 的目标匹配到"最近"的 malloc.
栈/全局目标、错误分配目标均被误报为堆溢出. 本模块沿 def-use 链
逆向分类目标寄存器: 溯源指向堆分配 → 精确归属; 溯源为栈/全局/
立即数 → 非堆目标直接过滤; 溯源无法解析 → 保守保留 (召回保全).

设计决策:
  - 仅处理 prov_alloc 缺失的调用点 (引擎已解析的不重复分析)
  - 寄存器追迹最多 5 跳, 前向窗口 24 条指令
  - 目标未知时保留告警 — 不确定即过滤会损失召回
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from .instruction_parser import InstructionParser, ParsedInstruction

_MAX_HOPS = 5
_WINDOW = 24

# x86_64 SysV/Win64 目标寄存器候选
_DEST_REGS = ("rdi", "rcx")

# 返回值寄存器 (跨函数堆指针)
_RET_REGS = ("rax", "eax")

_ALLOC_FUNCS = {"malloc", "calloc", "realloc", "_Znwm", "_Znam"}


@dataclass
class DestInfo:
    """目标寄存器溯源分类结果."""
    kind: str              # heap / non_heap / unknown
    alloc_addr: Optional[int] = None
    alloc_size: Optional[int] = None
    reg: str = ""
    hops: int = 0
    reason: str = ""


class AllocAttributor:
    """目标溯源分类器 — 对危险调用点的目标寄存器做归属判定.

    输入: prov_alloc 缺失的调用点 (call_idx, dest_reg).
    输出: DestInfo — heap (带分配地址/大小), non_heap, unknown.
    """

    def __init__(self, insns: List[ParsedInstruction],
                 addr_to_idx: Dict[int, int],
                 allocs: Dict[int, Tuple[int, int]]):
        self._insns = insns
        self._addr_to_idx = addr_to_idx
        self._allocs = allocs

    # 公共入口

    def attribute(self, call_idx: int, dest_reg: str,
                  prov_alloc: Optional[int]) -> DestInfo:
        """判定调用点目标的堆归属."""
        if prov_alloc is not None:
            size = self._allocs.get(prov_alloc, (None, None))[0]
            kind = "heap" if size is not None else "heap"
            return DestInfo(kind=kind, alloc_addr=prov_alloc,
                            alloc_size=size, reg=dest_reg,
                            reason="engine provenance")
        reg = InstructionParser.normalize_reg(dest_reg) or "rdi"
        return self._classify(call_idx, reg, _MAX_HOPS)

    # 内部: def-use 链分类

    def _classify(self, call_idx: int, reg: str,
                  hops_left: int) -> DestInfo:
        """沿 def-use 链逆向分类寄存器来源."""
        if hops_left <= 0:
            return DestInfo(kind="unknown", reg=reg,
                            hops=_MAX_HOPS - hops_left,
                            reason="chain depth exceeded")
        start = max(0, call_idx - _WINDOW)
        for j in range(call_idx - 1, start - 1, -1):
            ins = self._insns[j]
            mn = ins.mnemonic
            if len(ins.operands) < 2:
                continue
            dst = InstructionParser.normalize_reg(ins.operands[0])
            if dst != reg:
                continue
            src = ins.operands[1].strip()
            if mn in ("mov", "movabs"):
                return self._classify_mov(ins, j, src, hops_left)
            if mn == "lea":
                base, _, _, _ = InstructionParser.parse_memory_operand_full(src)
                if base in ("rbp", "rsp"):
                    return DestInfo(kind="non_heap", reg=reg,
                                    hops=_MAX_HOPS - hops_left,
                                    reason="stack address (lea)")
                if base == "rip":
                    return DestInfo(kind="non_heap", reg=reg,
                                    hops=_MAX_HOPS - hops_left,
                                    reason="global address (rip lea)")
                if base:
                    return self._classify(j, base, hops_left - 1)
                return DestInfo(kind="unknown", reg=reg,
                                hops=_MAX_HOPS - hops_left,
                                reason="lea without base")
            if mn in ("add", "sub", "xor", "and"):
                src_reg = InstructionParser.normalize_reg(src)
                if src_reg:
                    return self._classify(j, src_reg, hops_left - 1)
                return DestInfo(kind="unknown", reg=reg,
                                hops=_MAX_HOPS - hops_left,
                                reason="arithmetic on imm")
            if mn == "call":
                callee = InstructionParser.extract_callee(ins)
                if callee in _ALLOC_FUNCS:
                    return DestInfo(kind="heap", alloc_addr=ins.address,
                                    alloc_size=self._allocs.get(
                                        ins.address, (None, None))[0],
                                    reg=reg, hops=_MAX_HOPS - hops_left,
                                    reason=f"direct alloc {callee}")
                return DestInfo(kind="unknown", reg=reg,
                                hops=_MAX_HOPS - hops_left,
                                reason=f"call {callee} result")
            break
        return DestInfo(kind="unknown", reg=reg,
                        hops=_MAX_HOPS - hops_left,
                        reason="no def in window")

    def _classify_mov(self, ins: ParsedInstruction, idx: int,
                      src: str, hops_left: int) -> DestInfo:
        """分类 mov 指令的来源."""
        # 立即数 / 内存加载
        imm = InstructionParser._try_parse_int(src)
        if imm is not None:
            return DestInfo(kind="non_heap", reg=ins.operands[0],
                            hops=_MAX_HOPS - hops_left,
                            reason=f"immediate {hex(imm)}")
        mem_base, _, _, _ = InstructionParser.parse_memory_operand_full(src)
        if mem_base == "rip":
            return DestInfo(kind="non_heap", reg=ins.operands[0],
                            hops=_MAX_HOPS - hops_left,
                            reason="global load [rip+off]")
        if mem_base in ("rbp", "rsp"):
            # 栈槽内容未知 — 引擎已解析堆槽则 prov_alloc 非空,
            # 走到此处说明槽内非堆 → 但为召回保全, 保守报告
            return DestInfo(kind="unknown", reg=ins.operands[0],
                            hops=_MAX_HOPS - hops_left,
                            reason="stack slot load, content unknown")
        if mem_base:
            return self._classify(idx, mem_base, hops_left - 1)
        src_reg = InstructionParser.normalize_reg(src)
        if src_reg:
            if src_reg in _RET_REGS:
                return self._classify(idx, src_reg, hops_left - 1)
            return self._classify(idx, src_reg, hops_left - 1)
        return DestInfo(kind="unknown", reg=ins.operands[0],
                        hops=_MAX_HOPS - hops_left,
                        reason="unparsed source")


# smoke test
def _check():
    asm = """
    1000 <caller>:
    1000:       55                      push   rbp
    1001:       48 89 e5                mov    rbp,rsp
    1004:       48 c7 c7 00 04 00 00    mov    rdi,0x400
    100b:       e8 f0 fe ff ff          call   malloc
    1010:       48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax
    1014:       48 8d 45 f0             lea    rax,[rbp-0x10]
    1018:       48 89 c7                mov    rdi,rax
    101b:       be 00 10 40 00          mov    esi,0x401000
    1020:       e8 db fe ff ff          call   strcpy
    1025:       48 8b 7d f8             mov    rdi,QWORD PTR [rbp-0x8]
    1029:       ba 00 01 00 00          mov    edx,0x100
    102e:       e8 cd fe ff ff          call   memcpy
    """
    insns = InstructionParser.parse(asm)
    funcs = InstructionParser.parse_functions(asm)
    addr_to_idx = {i.address: k for k, i in enumerate(insns)}
    allocs = {0x100b: (0x400, 0x400)}
    attr = AllocAttributor(insns, addr_to_idx, allocs)
    strcpy_idx = next(i for i, x in enumerate(insns) if "strcpy" in x.raw_line)
    memcpy_idx = next(i for i, x in enumerate(insns) if "memcpy" in x.raw_line)
    d1 = attr.attribute(strcpy_idx, "rdi", None)
    assert d1.kind == "non_heap", f"strcpy dest should be stack, got {d1.kind}"
    d2 = attr.attribute(memcpy_idx, "rdi", 0x100b)
    assert d2.kind == "heap" and d2.alloc_addr == 0x100b, f"memcpy dest should be heap, got {d2}"
    print(f"[OK] alloc_attribution: strcpy→{d1.kind}, memcpy→{d2.kind}")


if __name__ == "__main__":
    _check()
