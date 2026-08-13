"""IO-FPMIN 检测器 — BinaryIntOverflowScanner + 乘法域/写入验证抑制.

相对既有 scanner 的增强 (不修改原类):
  1. calloc 双参数补检: 原 scanner 只查 rcx/rdi 单参数,
     calloc(nmemb, size) 的第二个乘法参数 (rsi/rdx) 漏检
  2. add 链回绕补检: add rax, rax (同寄存器加倍) 流入 malloc
  3. IntOverflowSuppressor 后处理: S-I1/S-I2/S-I3 证据过滤
"""

import os
import sys
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from .binary_int_overflow_scanner import BinaryIntOverflowScanner  # noqa: E402
from .io_suppress import IntOverflowSuppressor                      # noqa: E402
from ..heap_analysis.instruction_parser import InstructionParser    # noqa: E402


class IntOverflowFpminScanner(BinaryIntOverflowScanner):
    """误报抑制版整数溢出扫描器 — 补检 + 证据过滤."""

    def scan(self, objdump_output: str, sample_name: str = "",
             user_code_only: bool = True,
             functions: Optional[Dict[int, str]] = None) -> dict:
        import time
        t0 = time.perf_counter()
        raw = super().scan(objdump_output, sample_name,
                           user_code_only=user_code_only,
                           functions=functions)
        insns = InstructionParser.parse(objdump_output)
        if user_code_only:
            if functions is None:
                functions = InstructionParser.parse_functions(objdump_output)
            insns = InstructionParser.filter_user_instructions(
                insns, functions) or insns
        raw = self._supplement_calloc_add(insns, raw)
        suppressor = IntOverflowSuppressor(insns)
        kept = suppressor.suppress(raw)
        suppressed = suppressor.suppressed_evidence()
        for f in kept:
            f["source"] = "io_fpmin"
        return {
            "sample": sample_name,
            "findings": kept,
            "n_findings": len(kept),
            "suppressed": suppressed,
            "n_suppressed": len(suppressed),
            "n_raw": len(raw),
            "elapsed_ms": (time.perf_counter() - t0) * 1000,
        }

    def _supplement_calloc_add(self, insns: list,
                               raw: List[dict]) -> List[dict]:
        """补检分配参数的乘法/加倍来源.

        覆盖: malloc/realloc 第一参数 (rcx/rdi) 与 calloc 第二
        参数 (rsi/rdx) 的 imul/shl/add_double 来源 — 原 scanner
        只跟踪寄存器级 taint, 栈槽暂存 (mov [rbp-0x8], eax 后
        重新加载) 与 add 同寄存器加倍均漏检.
        """
        extra = []
        reported = {f.get("insn_addr") for f in raw}
        for i, ins in enumerate(insns):
            if ins.mnemonic != "call" or not ins.operands:
                continue
            callee = InstructionParser.extract_callee(ins)
            if callee not in self.ALLOC_FUNCS:
                continue
            if ins.address in reported:
                continue
            check_regs = ("rcx", "rdi")
            if "calloc" in callee or "reallocarray" in callee:
                check_regs = ("rcx", "rdi", "rsi", "rdx")
            for reg in check_regs:
                kind = self._check_arg_overflow(insns, i, reg)
                if kind:
                    extra.append({
                        "type": "integer_overflow",
                        "insn_addr": ins.address,
                        "alloc_func": callee,
                        "overflow_kind": kind,
                        "reason": f"{kind} in arg {reg} flows to "
                                  f"{callee}()",
                        "confidence": 0.7,
                    })
                    break
        return raw + extra

    def _check_arg_overflow(self, insns: list, call_idx: int,
                            reg: str) -> Optional[str]:
        """参数寄存器的乘法/加倍来源 (寄存器/栈槽链 ≤4 跳)."""
        r = reg
        seen = set()
        for hop in range(4):
            if (call_idx, r) in seen:
                return None
            seen.add((call_idx, r))
            for j in range(call_idx - 1, max(0, call_idx - 10), -1):
                ins = insns[j]
                if len(ins.operands) < 2:
                    continue
                dst = InstructionParser.normalize_reg(ins.operands[0])
                if dst != r:
                    continue
                if ins.mnemonic in ("imul", "mul"):
                    return "imul_arg"
                if ins.mnemonic == "shl":
                    return "shl_arg"
                if ins.mnemonic == "add":
                    if len(ins.operands) >= 2 and \
                            InstructionParser.normalize_reg(
                                ins.operands[0]) == \
                            InstructionParser.normalize_reg(ins.operands[1]):
                        return "add_double"
                if ins.mnemonic in ("mov", "movabs"):
                    src = ins.operands[1].strip()
                    src_reg = InstructionParser.normalize_reg(src)
                    if src_reg:
                        r = src_reg
                        call_idx = j
                        break
                    # 栈槽加载 → 追槽的写入
                    base, _, _, off = \
                        InstructionParser.parse_memory_operand_full(src)
                    if base in ("rbp", "rsp"):
                        slot_src = self._slot_writer(insns, j, base, off)
                        if slot_src:
                            r = slot_src
                            call_idx = j
                            break
                    return None
                return None
            else:
                return None
        return None

    def _slot_writer(self, insns: list, load_idx: int,
                     base: str, off: int) -> Optional[str]:
        """栈槽最近写入的寄存器来源."""
        for j in range(load_idx - 1, max(0, load_idx - 12), -1):
            ins = insns[j]
            if ins.mnemonic != "mov" or len(ins.operands) < 2:
                continue
            if InstructionParser.normalize_reg(ins.operands[0]):
                continue
            wbase, _, _, woff = \
                InstructionParser.parse_memory_operand_full(ins.operands[0])
            if (wbase, woff) == (base, off):
                return InstructionParser.normalize_reg(ins.operands[1])
        return None


# smoke test
def _check():
    s = IntOverflowFpminScanner()
    # calloc(n, 16) 中第二参数常量 — 无补检 finding
    r = s.scan("1000:       55                      push   rbp\n"
               "1001:       48 89 e5                mov    rbp,rsp\n"
               "1004:       48 8b 4d 10             mov    rcx,QWORD PTR [rbp+0x10]\n"
               "1008:       ba 10 00 00 00          mov    edx,0x10\n"
               "100d:       e8 ee fe ff ff          call   calloc\n",
               user_code_only=False)
    assert r["n_findings"] == 0, f"常量第二参数不应检出, got {r['n_findings']}"
    print("[OK] io_fpmin_scanner: 常量 calloc 第二参数不检")


if __name__ == "__main__":
    _check()
