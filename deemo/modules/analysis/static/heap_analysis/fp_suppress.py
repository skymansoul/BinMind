"""融合误报抑制判定器 - 汇聚归属/大小界定/循环界/守卫窄化/可控性.

判定分层 (verdict):
  SAFE     - 可证明安全: 非堆目标 / 写入上界 ≤ 可用大小 / 循环界内
  OVERFLOW - 可证明越界: 写入上界 > 可用大小
  RISKY    - 无法证明: 未知大小 + 无守卫 + 未解析目标 → 保守报告

与 absint_adjudicator 的关系: 该判定器消费同一份引擎中间数据,
但以溯源归属 + 界定/守卫证据链替代"空间最近邻 + 未知即报"逻辑.
保持召回: 一切无法证明安全的点仍进入 RISKY 输出.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from .instruction_parser import InstructionParser, ParsedInstruction
from .alloc_attribution import AllocAttributor
from .write_size_bound import WriteSizeBounder
from .loop_bound_analyzer import LoopBoundAnalyzer
from .alloc_controllability import AllocControllability, ControlSource
from .absint_adjudicator import compute_usable
from .backward_constraint import BackwardConstraintNarrower

_SAFE, _OVERFLOW, _RISKY = "safe", "overflow", "risky"

_WINDOW = 24   # def-use 追迹窗口

_SRC_REG_FOR_LEN = {"strcpy": "rsi", "strcat": "rsi",
                    "sprintf": "rsi", "gets": "rdi"}


@dataclass
class Decision:
    """单个调用点/写入点的抑制判定."""
    addr: int
    func: str
    verdict: str
    reason: str
    alloc_size: int = 0
    usable: int = 0
    write_bound: int = 0
    guard_hi: int = 0
    confidence: float = 0.0
    meta: dict = None

    def to_finding(self, filtered: bool) -> dict:
        return {
            "type": "heap_overflow",
            "subtype": "giva",
            "insn_addr": self.addr,
            "function": self.func,
            "write_size": self.write_bound,
            "alloc_size": self.alloc_size,
            "usable_size": self.usable,
            "overflow_by": max(0, self.write_bound - self.usable),
            "reason": self.reason,
            "confidence": round(self.confidence, 2),
            "filtered": filtered,
        }


class FpSuppressor:
    """融合判定器 - 对危险调用与堆写入输出三层 verdict."""

    def __init__(self, insns: List[ParsedInstruction],
                 addr_to_idx: Dict[int, int],
                 allocs: Dict[int, Tuple[int, int]],
                 binary_path: Optional[str] = None):
        self._insns = insns
        self._addr_to_idx = addr_to_idx
        self._allocs = allocs
        self._attributor = AllocAttributor(insns, addr_to_idx, allocs)
        self._bounder = WriteSizeBounder(binary_path)
        self._narrower = BackwardConstraintNarrower()
        self._ctl = AllocControllability()
        self._loops = LoopBoundAnalyzer(insns, addr_to_idx)
        self._loops.analyze()

    # 危险调用判定

    def decide_danger_call(self, addr: int, func: str,
                           size_val: int,
                           prov_alloc: Optional[int]) -> Decision:
        """对 memcpy/strcpy 等危险调用输出判定."""
        call_idx = self._addr_to_idx.get(addr)
        if call_idx is None:
            return Decision(addr, func, _RISKY, "call not in index",
                            confidence=0.4)
        # 目标寄存器: SysV 为 rdi, Win64 为 rcx — 两者都尝试
        attr = self._attributor.attribute(call_idx, "rdi", prov_alloc)
        if attr.kind == "unknown":
            attr = self._attributor.attribute(call_idx, "rcx", prov_alloc)

        # 1) 非堆目标 → 安全
        if attr.kind == "non_heap":
            return Decision(addr, func, _SAFE,
                            f"non-heap destination ({attr.reason})",
                            confidence=0.0)

        # 2) 目标为堆, 归属精确 → 大小比较
        if attr.kind == "heap" and attr.alloc_addr is not None \
                and attr.alloc_addr in self._allocs:
            alloc_size, usable = self._allocs[attr.alloc_addr]
            usable = max(usable, compute_usable(alloc_size))
            if size_val > 0:
                return self._size_verdict(addr, func, size_val,
                                          alloc_size, usable)
            return self._bounded_verdict(call_idx, addr, func,
                                         alloc_size, usable, attr)

        # 3) 堆目标但大小未知 → 有界写入仍可判安全, 否则保守
        if size_val > 0:
            if func in ("gets", "strcpy", "strcat", "sprintf"):
                return Decision(addr, func, _RISKY,
                                "heap target, alloc size unknown, "
                                "unbounded copy family", confidence=0.5)
            return Decision(addr, func, _RISKY,
                            "heap target, alloc size unknown",
                            confidence=0.5)
        return self._bounded_verdict(call_idx, addr, func,
                                     0, 0, attr)

    # 堆写入判定 (循环/偏移)

    def decide_heap_write(self, addr: int, alloc_addr: int,
                          offset: int, access_size: int,
                          operand: str,
                          heap_regs: Dict[str, bool]) -> Decision:
        """对直接写入指令输出判定.

        带索引寄存器的写入 (mov [heap+idx*scale], v) 语义为
        集合偏移 {0, scale, 2*scale, ...} — 不能按单次偏移扁平化:
        循环次数可知 → 字节上界 = trips*scale; 不可知 → 保守报告.
        """
        if alloc_addr not in self._allocs:
            return Decision(addr, "direct_write", _RISKY,
                            "write to untracked alloc", confidence=0.4)
        alloc_size, usable = self._allocs[alloc_addr]
        usable = max(usable, compute_usable(alloc_size))
        base, idx, scale, _ = \
            InstructionParser.parse_memory_operand_full(operand)
        idx_norm = InstructionParser.normalize_reg(idx) if idx else None
        base_norm = InstructionParser.normalize_reg(base) if base else None
        info = self._loops.containing_loop(addr)
        # 1) 显式索引寄存器 → 循环界判定
        if idx_norm and heap_regs.get(idx_norm) is not True:
            if info is not None and info.counter_reg == idx_norm:
                if info.trips is not None:
                    total = info.trips * (scale if scale > 0 else 1)
                    if total <= usable:
                        return Decision(addr, "direct_write", _SAFE,
                                        f"loop bounded: trips({info.trips})"
                                        f"*scale({scale}) <= usable({usable})",
                                        alloc_size, usable, total,
                                        confidence=0.0)
                    return Decision(addr, "direct_write", _OVERFLOW,
                                    f"loop writes {total} > usable({usable})",
                                    alloc_size, usable, total,
                                    confidence=0.85)
                return Decision(addr, "direct_write", _RISKY,
                                "loop write with unbounded trip count",
                                alloc_size, usable, 0, confidence=0.5)
        # 2) 扁平化地址: base 依赖循环计数器 (MinGW -O0 形态)
        chain = self._loops.loop_chain(addr)
        if chain and base_norm is not None:
            if self._depends_on_counter(addr, base_norm, chain[0]):
                total = access_size
                bounded = True
                for info in chain:
                    if info.trips is None:
                        bounded = False
                        break
                    total *= info.trips
                if bounded:
                    if total <= usable:
                        return Decision(addr, "direct_write", _SAFE,
                                        f"loop-indexed: trips-product "
                                        f"({total}) <= usable({usable})",
                                        alloc_size, usable, total,
                                        confidence=0.0)
                    return Decision(addr, "direct_write", _OVERFLOW,
                                    f"loop-indexed writes {total} "
                                    f"> usable({usable})",
                                    alloc_size, usable, total,
                                    confidence=0.85)
                return Decision(addr, "direct_write", _RISKY,
                                "loop-indexed write, unbounded trips",
                                alloc_size, usable, 0, confidence=0.5)
        if offset >= 0:
            if offset + access_size <= usable:
                return Decision(addr, "direct_write", _SAFE,
                                f"offset({offset})+size({access_size}) "
                                f"<= usable({usable})", alloc_size, usable,
                                offset + access_size, confidence=0.0)
            return Decision(addr, "direct_write", _OVERFLOW,
                            f"offset({offset})+size({access_size}) "
                            f"> usable({usable})", alloc_size, usable,
                            offset + access_size,
                            confidence=0.85 if offset >= usable else 0.6)
        # 未知偏移且无索引寄存器 → 仅循环界可证安全
        if idx_norm:
            trips = self._loops.write_bytes_bound(addr, idx_norm)
            if trips is not None:
                total = trips * (scale if scale > 0 else 1)
                if total <= usable:
                    return Decision(addr, "direct_write", _SAFE,
                                    f"loop bounded: trips({trips})*scale "
                                    f"<= usable({usable})",
                                    alloc_size, usable, total,
                                    confidence=0.0)
        return Decision(addr, "direct_write", _RISKY,
                        f"unknown offset, alloc({alloc_size}) "
                        f"usable({usable})", alloc_size, usable,
                        confidence=0.4)

    def _depends_on_counter(self, addr: int, base_reg: str,
                            info) -> bool:
        """判定写地址是否由循环计数器派生 (扁平化地址形态).

        沿 base 寄存器的 def-use 链回溯: add heap, idx 或
        mov reg, [counter_slot] 命中计数器 → True.
        """
        call_idx = self._addr_to_idx.get(addr)
        if call_idx is None:
            return False
        return self._chase_counter(call_idx, base_reg, info, 6, set())

    def _chase_counter(self, idx: int, reg: str, info,
                       hops_left: int, seen: set) -> bool:
        if hops_left <= 0 or (idx, reg) in seen:
            return False
        seen.add((idx, reg))
        start = max(0, idx - _WINDOW)
        for j in range(idx - 1, start - 1, -1):
            ins = self._insns[j]
            mn = ins.mnemonic
            if len(ins.operands) < 2:
                continue
            dst = InstructionParser.normalize_reg(ins.operands[0])
            if dst != reg:
                continue
            src = ins.operands[1].strip()
            if mn in ("mov", "movabs"):
                src_reg = InstructionParser.normalize_reg(src)
                if src_reg:
                    return self._chase_counter(j, src_reg, info,
                                               hops_left - 1, seen)
                base, _, _, off = \
                    InstructionParser.parse_memory_operand_full(src)
                if info.counter_slot and (base, off) == info.counter_slot:
                    return True
                if info.counter_reg and base == info.counter_reg:
                    return True
                return False
            if mn == "lea":
                b, ix, sc, off = \
                    InstructionParser.parse_memory_operand_full(src)
                if ix and sc > 0:
                    return self._chase_counter(j, ix, info,
                                               hops_left - 1, seen)
                if b:
                    return self._chase_counter(j, b, info,
                                               hops_left - 1, seen)
                return False
            if mn == "add":
                imm = InstructionParser._try_parse_int(src)
                if imm is not None:
                    return self._chase_counter(j, reg, info,
                                               hops_left - 1, seen)
                src_reg = InstructionParser.normalize_reg(src)
                if src_reg:
                    # 双操作数: 任一链命中计数器即成立
                    if self._chase_counter(j, src_reg, info,
                                           hops_left - 1, seen):
                        return True
                    return self._chase_counter(j, reg, info,
                                               hops_left - 1, seen)
                return False
            if mn == "imul":
                src_reg = InstructionParser.normalize_reg(src)
                if src_reg:
                    return self._chase_counter(j, src_reg, info,
                                               hops_left - 1, seen)
                if len(ins.operands) >= 3:
                    src_reg = InstructionParser.normalize_reg(
                        ins.operands[2])
                    if src_reg:
                        return self._chase_counter(
                            j, src_reg, info, hops_left - 1, seen)
                return False
            if mn in ("movzx", "movsx", "cdqe", "cdq", "cqo"):
                src_reg = InstructionParser.normalize_reg(src)
                if src_reg:
                    return self._chase_counter(j, src_reg, info,
                                               hops_left - 1, seen)
                return False
            return False
        return False

    # 内部

    @property
    def _SIZE_REGS(self) -> Tuple[str, ...]:
        return ("rdx", "r8")

    def _size_verdict(self, addr: int, func: str, size_val: int,
                      alloc_size: int, usable: int) -> Decision:
        if size_val <= usable:
            return Decision(addr, func, _SAFE,
                            f"write({size_val}) <= usable({usable})",
                            alloc_size, usable, size_val, confidence=0.0)
        return Decision(addr, func, _OVERFLOW,
                        f"write({size_val}) > usable({usable})",
                        alloc_size, usable, size_val,
                        confidence=0.85)

    def _bounded_verdict(self, call_idx: int, addr: int, func: str,
                         alloc_size: int, usable: int,
                         attr) -> Decision:
        """未知大小 → 界定链 / 守卫 / 源长度 逐级取证."""
        # a) def-use 链界定
        res = self._bounder.bound(self._insns, call_idx, func)
        if res.bounded and usable > 0 and res.hi <= usable:
            return Decision(addr, func, _SAFE,
                            f"write bounded by def-use chain "
                            f"(hi={res.hi}) <= usable({usable})",
                            alloc_size, usable, res.hi, confidence=0.0)
        # b) 守卫窄化
        for reg in self._SIZE_REGS:
            lo, hi = self._narrower.narrow(self._insns, call_idx, reg)
            if hi < 2 ** 31 - 1:
                if usable > 0 and hi <= usable:
                    return Decision(addr, func, _SAFE,
                                    f"guarded: {reg} <= {hi} <= usable",
                                    alloc_size, usable, hi, confidence=0.0)
                if usable == 0:
                    return Decision(addr, func, _RISKY,
                                    f"guard {reg}<={hi}, alloc unknown",
                                    alloc_size, 0, hi, confidence=0.45)
                break
        # c) 源长度估计 (strcpy 家族)
        if func in _SRC_REG_FOR_LEN:
            src_len = self._bounder.source_len(
                self._insns, call_idx, _SRC_REG_FOR_LEN[func])
            if src_len is not None and usable > 0 and src_len <= usable:
                return Decision(addr, func, _SAFE,
                                f"rodata source len({src_len}) "
                                f"<= usable({usable})",
                                alloc_size, usable, src_len,
                                confidence=0.0)
        # d) 无法证明 → 保守报告, 置信度按可控性调整
        conf = 0.45
        if attr.alloc_addr is not None and attr.alloc_addr in self._allocs:
            ctl = self._ctl.classify(self._insns, call_idx,
                                     self._alloc_size_regs(call_idx))
            if ctl in (ControlSource.USER, ControlSource.PARAM):
                conf = 0.55
            elif ctl == ControlSource.CONSTANT:
                conf = 0.40
        return Decision(addr, func, _RISKY,
                        "unbounded write size, no guard/bound evidence",
                        alloc_size, usable, 0, confidence=conf)

    def _alloc_size_regs(self, call_idx: int) -> Tuple[str, ...]:
        return ("rdi", "rcx")

    # [DEPRECATED] 以下辅助已被 decide_heap_write 内联逻辑取代,
    # 保留供外部调用方使用, 待确认后移除.
    def _extract_index_reg(self, operand: str) -> Optional[str]:
        base, idx, _, _ = \
            InstructionParser.parse_memory_operand_full(operand)
        return idx or base

    @staticmethod
    def _scale_of(operand: str) -> int:
        _, _, scale, _ = \
            InstructionParser.parse_memory_operand_full(operand)
        return scale if scale > 0 else 1


# smoke test
def _check():
    asm = """
    1400:       48 c7 c7 00 04 00 00    mov    rdi,0x400
    1407:       e8 f4 fe ff ff          call   malloc
    140c:       48 89 c3                mov    rbx,rax
    140f:       ba 00 02 00 00          mov    edx,0x200
    1414:       48 89 df                mov    rdi,rbx
    1417:       e8 e4 fe ff ff          call   memcpy
    141c:       48 8d 45 f0             lea    rax,[rbp-0x10]
    1420:       48 89 c7                mov    rdi,rax
    1423:       be 00 10 40 00          mov    esi,0x401000
    1428:       e8 d3 fe ff ff          call   strcpy
    """
    insns = InstructionParser.parse(asm)
    addr_to_idx = {i.address: k for k, i in enumerate(insns)}
    allocs = {0x1407: (0x400, 0x400)}
    fs = FpSuppressor(insns, addr_to_idx, allocs)
    d1 = fs.decide_danger_call(0x1417, "memcpy", 0x200, 0x1407)
    assert d1.verdict == _SAFE, f"memcpy 0x200<=0x400 should be safe: {d1.verdict}"
    d2 = fs.decide_danger_call(0x1428, "strcpy", 0, None)
    assert d2.verdict == _SAFE, f"strcpy to stack should be safe: {d2.verdict}"
    print(f"[OK] fp_suppress: memcpy→{d1.verdict}, strcpy→{d2.verdict}")


if __name__ == "__main__":
    _check()
