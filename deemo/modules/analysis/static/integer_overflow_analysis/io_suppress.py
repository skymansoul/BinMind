"""整数溢出误报融合抑制 — 乘法域 + 检查有效性 + 写入验证.

规则:
  S-I1 乘法域证明安全 (常量缩放/掩码约束/窄位扩展) → 滤
  S-I2 有效溢出检查 (cmp 上界 < 2^32 且比较对象与 malloc 参数
       同寄存器链) → 滤 (低危)
  S-I3 写入验证: 分配后无写入或固定小量 → 滤 (不可利用)
保留: RUNTIME 乘法 + 无有效检查 + 大/循环写入 (CWE-680 形态).
"""

from typing import Dict, List, Optional, Tuple

from ..heap_analysis.instruction_parser import InstructionParser
from .mul_domain import MulDomainAnalyzer
from .alloc_write_validate import WriteValidation

_SAFE, _KEEP = "safe", "keep"
_LIMIT = 1 << 32


class IntOverflowSuppressor:
    """整数溢出融合判定器 — 消费原始 findings 做证据过滤."""

    def __init__(self, insns: list):
        self._insns = insns
        self._addr_to_idx = {ins.address: i for i, ins in enumerate(insns)}
        self._mul = MulDomainAnalyzer(insns)
        self._wv = WriteValidation(insns)
        self._suppressed: List[Tuple[dict, str]] = []

    def suppress(self, findings: List[dict]) -> List[dict]:
        kept = []
        for f in findings:
            verdict, reason = self._decide(f)
            if verdict == _KEEP:
                kept.append(f)
            else:
                self._suppressed.append((f, reason))
        return kept

    def suppressed_evidence(self) -> List[dict]:
        return [{"insn_addr": f.get("insn_addr", 0),
                 "reason": r} for f, r in self._suppressed]

    # 判定

    def _decide(self, f: dict) -> Tuple[str, str]:
        reason = f.get("reason", "")
        alloc_addr = f.get("insn_addr", 0)
        idx = self._addr_to_idx.get(alloc_addr)
        if idx is None:
            return _KEEP, ""
        # 定位乘法源地址 (reason 含 "imul@0x.." / "shl@0x.." 形态)
        src = self._overflow_src_addr(reason)
        if src is None:
            return _KEEP, ""
        # S-I1: 乘法域
        s_idx = self._addr_to_idx.get(src)
        if s_idx is not None:
            ins = self._insns[s_idx]
            if ins.mnemonic in ("imul", "mul"):
                r = self._mul.analyze_imul(ins)
            elif ins.mnemonic in ("shl", "sal"):
                r = self._mul.analyze_shl(ins)
            else:
                r = None
            if r is not None and not r.can_overflow:
                return _SAFE, f"S-I1 {r.reason}"
        # S-I2: 有效检查
        if self._valid_check(src, alloc_addr):
            return _SAFE, "S-I2 valid overflow check (bounded, same reg)"
        # S-I3: 写入验证
        kind, nbytes = self._wv.validate(alloc_addr)
        if kind in ("none", "small"):
            return _SAFE, f"S-I3 write {kind} ({nbytes} bytes) — " \
                          f"no exploit path"
        return _KEEP, ""

    # 内部

    def _overflow_src_addr(self, reason: str) -> Optional[int]:
        import re
        # 兼容 imul/imul_chain/shl/add_chain 形态
        for m in re.finditer(r"(?:imul|shl|add_chain)\w*@0x([0-9a-f]+)",
                             reason):
            return int(m.group(1), 16)
        return None

    def _valid_check(self, overflow_addr: int,
                     call_addr: int) -> bool:
        """溢出源与 malloc 之间的 cmp 是否构成有效检查.

        有效: cmp rax, imm (imm < 2^32) 且 rax 与 malloc 参数
        同寄存器链; 检查无关寄存器或上界 ≥ 2^32 → 无效.
        """
        arg_reg = self._alloc_arg_reg(call_addr)
        if arg_reg is None:
            return False
        in_range = False
        for ins in self._insns:
            if ins.address == overflow_addr:
                in_range = True
                continue
            if ins.address == call_addr:
                break
            if not in_range:
                continue
            if ins.mnemonic in ("cmp", "test"):
                ops = ins.operands
                if len(ops) < 2:
                    continue
                cmp_reg = InstructionParser.normalize_reg(ops[0])
                if cmp_reg != arg_reg:
                    continue
                imm = InstructionParser._try_parse_int(ops[1])
                if imm is not None and 0 < imm < _LIMIT:
                    return True
                return False  # 同寄存器但上界无效 → 检查无效
            if ins.mnemonic == "jo":
                return True
        return False

    def _alloc_arg_reg(self, call_addr: int) -> Optional[str]:
        idx = self._addr_to_idx.get(call_addr)
        if idx is None:
            return None
        for j in range(idx - 1, max(0, idx - 8), -1):
            ins = self._insns[j]
            if ins.mnemonic not in ("mov", "movabs") or \
                    len(ins.operands) < 2:
                continue
            dst = InstructionParser.normalize_reg(ins.operands[0])
            if dst in ("rcx", "rdi"):
                return dst
        return None


# smoke test
def _check():
    class _I:
        def __init__(self, addr, mn, ops):
            self.address = addr
            self.mnemonic = mn
            self.operands = ops

    # imul 常量缩放 → malloc → S-I1 滤
    insns = [
        _I(0x1000, "imul", ["rax", "rax", "0x30"]),
        _I(0x1004, "mov", ["rcx", "rax"]),
        _I(0x1008, "call", ["malloc"]),
    ]
    s = IntOverflowSuppressor(insns)
    f = {"insn_addr": 0x1008,
         "reason": "imul@0x1000 flows to malloc() via rcx"}
    v, r = s._decide(f)
    assert v == _SAFE, f"常量缩放应滤, got {v} {r}"
    print("[OK] io_suppress: S-I1 乘法域过滤通过")


if __name__ == "__main__":
    _check()
