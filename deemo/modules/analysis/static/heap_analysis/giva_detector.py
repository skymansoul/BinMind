"""GIVA 检测器 — 溯源门控写入界验证 (Provenance-Gated Write-Bound Verification).

管线: AbstractInterpreter (既有 absint 引擎, 不改动) →
      FpSuppressor (三层误报抑制: 归属 / 大小界定 / 循环界).
输出: giva_real / giva_filtered, 同时保留 baseline (absint) 结果,
用于对比实验中的误报率消融.

设计决策:
  - 子类化引擎仅为了捕获堆写入的完整操作数 (索引寄存器),
    不覆盖任何既有判定逻辑
  - 整数溢出风险与 UAF/格式化字符串不在此管线 — 由既有检测器承担
"""

from typing import Dict, List, Optional, Set, Tuple

from .instruction_parser import InstructionParser, ParsedInstruction
from .strided_value import StridedValue
from .absint_engine import AbstractInterpreter
from .fp_suppress import FpSuppressor
from .absint_adjudicator import compute_usable


class GivaInterpreter(AbstractInterpreter):
    """捕获堆写入操作数的引擎子类."""

    def __init__(self, binary_path: Optional[str] = None):
        super().__init__()
        self._binary_path = binary_path
        self._write_operands: List[Tuple[int, str]] = []

    def _step_one(self, ins: ParsedInstruction):
        super()._step_one(ins)
        if ins.mnemonic != "mov" or len(ins.operands) < 2:
            return
        base, idx, _, _ = \
            InstructionParser.parse_memory_operand_full(ins.operands[0])
        if base is None and idx is None:
            return
        reg = idx or base
        val = self._state.get(reg)
        if val.is_heap_ptr:
            self._write_operands.append((ins.address, ins.operands[0]))

    def analyze_all(self):
        """运行引擎 + 融合抑制, 返回 (giva_real, giva_filtered)."""
        self._prescan_allocs()
        self._addr_to_idx = {ins.address: i
                             for i, ins in enumerate(self._insns)}
        for ins in self._insns:
            self._step_one(ins)
        # baseline 判定 (既有逻辑, 用于消融对比)
        baseline_real, baseline_filtered = self._adjudicator.adjudicate(
            self._insns, self._addr_to_idx, self._allocs,
            self._danger_calls, self._heap_writes,
            self._int_overflow_risks)
        # giva 判定
        self._fix_realloc_sizes()
        suppressor = FpSuppressor(
            self._insns, self._addr_to_idx, self._allocs,
            binary_path=self._binary_path)
        real, filtered = self._adjudicate_giva(suppressor)
        return (real, filtered, baseline_real, baseline_filtered)

    def _fix_realloc_sizes(self):
        """修正 realloc 分配大小 — 大小参数在 rdx/r8, 非 rdi/rcx.

        引擎的 _prescan_allocs 只查 rdi/rcx, 对 realloc(ptr, size)
        会误取指针寄存器为大小 → 分配记录错误 → 误报. 此处按
        SysV/Win64 调用约定重新解析 rdx/r8 立即数并覆写记录.
        """
        for i, ins in enumerate(self._insns):
            if ins.mnemonic != "call":
                continue
            callee = InstructionParser.extract_callee(ins)
            if callee != "realloc":
                continue
            size = self._prev_imm(i, ("rdx", "edx", "r8", "r8d"))
            if size is not None and size > 0:
                self._allocs[ins.address] = (size, compute_usable(size))

    def _prev_imm(self, idx: int, regs: Tuple[str, ...]) -> Optional[int]:
        """在 call 前找 mov reg, imm (窗口 10 条)."""
        for j in range(idx - 1, max(0, idx - 10), -1):
            p = self._insns[j]
            if p.mnemonic not in ("mov", "movabs") or len(p.operands) < 2:
                continue
            norm = InstructionParser.normalize_reg(p.operands[0])
            if norm in regs:
                try:
                    return int(p.operands[1].strip(), 0)
                except ValueError:
                    return None
        return None

    def _adjudicate_giva(self, suppressor: FpSuppressor):
        real, filtered = [], []
        for addr, func, size_val, prov_alloc in self._danger_calls:
            d = suppressor.decide_danger_call(
                addr, func, size_val, prov_alloc)
            (filtered if d.verdict == "safe" else real).append(
                d.to_finding(d.verdict == "safe"))
        for addr, alloc_addr, woff, asize in self._heap_writes:
            operand = self._operand_for(addr)
            heap_regs = self._heap_regs_at(addr)
            d = suppressor.decide_heap_write(
                addr, alloc_addr, woff, asize, operand, heap_regs)
            (filtered if d.verdict == "safe" else real).append(
                d.to_finding(d.verdict == "safe"))
        for addr, alloc_size, multiplier, reason in self._int_overflow_risks:
            real.append({
                "type": "heap_overflow",
                "subtype": "integer_overflow_alloc",
                "insn_addr": addr, "function": "malloc",
                "write_size": 0, "alloc_size": alloc_size,
                "usable_size": compute_usable(alloc_size),
                "overflow_by": 0, "reason": reason,
                "confidence": 0.65, "filtered": False,
            })
        return real, filtered

    def _operand_for(self, addr: int) -> str:
        for a, op in self._write_operands:
            if a == addr:
                return op
        return ""

    def _heap_regs_at(self, addr: int) -> Dict[str, bool]:
        """写入指令处的堆指针寄存器快照."""
        result = {}
        for reg, val in self._state.regs.items():
            if val.is_heap_ptr:
                result[reg] = True
        return result


class GivaScanner:
    """GIVA 扫描器 — objdump 文本 → 结构化结果."""

    def __init__(self, binary_path: Optional[str] = None,
                 import_map: Optional[Dict[int, str]] = None):
        self._binary_path = binary_path
        self._import_map = import_map

    def scan(self, objdump_output: str,
             sample_name: str = "") -> dict:
        import time
        t0 = time.perf_counter()
        # 导入映射按二进制不同 — 每次扫描显式设置, 避免类级缓存串扰
        if self._import_map is not None:
            InstructionParser.set_import_map(self._import_map)
        elif self._binary_path:
            from .plt_resolver import build_import_map
            InstructionParser.set_import_map(
                build_import_map(self._binary_path))
        insns = InstructionParser.parse(objdump_output)
        if not insns:
            return {"sample": sample_name, "error": "no instructions",
                    "real": [], "filtered": [], "elapsed_ms": 0.0}
        funcs = InstructionParser.parse_functions(objdump_output)
        user_insns = InstructionParser.filter_user_instructions(
            insns, funcs) or insns
        engine = GivaInterpreter(binary_path=self._binary_path)
        engine.feed_instructions(user_insns)
        engine.set_functions(funcs)
        real, filtered, baseline_real, baseline_filtered = \
            engine.analyze_all()
        for f in real + filtered:
            addr = f.get("insn_addr", 0)
            f["func"] = InstructionParser.resolve_function(addr, funcs) or "?"
            f["address"] = hex(addr)
        return {
            "sample": sample_name,
            "real": real,
            "filtered": filtered,
            "baseline_real": baseline_real,
            "baseline_filtered": baseline_filtered,
            "n_real": len(real),
            "n_filtered": len(filtered),
            "n_baseline_real": len(baseline_real),
            "elapsed_ms": (time.perf_counter() - t0) * 1000,
        }


# smoke test
def _check():
    asm = """
    1500:       48 c7 c7 40 00 00 00    mov    rdi,0x40
    1507:       e8 f4 fe ff ff          call   malloc
    150c:       48 89 c3                mov    rbx,rax
    150f:       48 8d 43 50             lea    rax,[rbx+0x50]
    1513:       c7 00 ef be ad de       mov    DWORD PTR [rax],0xdeadbeef
    1519:       b8 00 00 00 00          mov    eax,0
    151e:       c3                      ret
    """
    s = GivaScanner()
    r = s.scan(asm, "smoke")
    assert r["n_real"] >= 1, f"expected real finding, got {r['n_real']}"
    print(f"[OK] giva_detector: real={r['n_real']} filtered={r['n_filtered']} "
          f"baseline_real={r['n_baseline_real']}")


if __name__ == "__main__":
    _check()
