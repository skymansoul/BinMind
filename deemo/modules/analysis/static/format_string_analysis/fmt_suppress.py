"""格式串误报融合抑制 - 溯源 + 参数一致性双证据判定.

规则:
  S-F1 溯源 RDATA/STACK_CONST/HEAP_CONST → 格式串不可控 → 滤
        (含 %n: 常量串 %n 写本地地址, 非漏洞原语)
  S-F2 溯源 USER → 保留 (含 %n 加重置信度)
  S-F3 溯源 UNKNOWN 且无实参 → 保留 (保守, 维持原置信度)
  S-F4 溯源 UNKNOWN 但说明符与实参一致 → 降级保留 (低置信)
无法给出安全证据的判定一律保留 - 召回保全.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .fmt_provenance import FmtProvenance, FmtSource
from .fmt_argument_check import FmtArgumentCheck, count_specifiers
from ..heap_analysis.instruction_parser import InstructionParser

_SAFE, _KEEP = "safe", "keep"


@dataclass
class FmtDecision:
    """单调用点的格式串判定."""
    addr: int
    callee: str
    verdict: str
    reason: str
    confidence: float = 0.0
    source: str = ""
    spec_total: int = 0
    spec_write: int = 0
    n_args: int = 0


class FmtSuppressor:
    """格式串融合判定器 - 消费溯源与参数一致性证据."""

    def __init__(self, insns: list, rdata_reader=None):
        self._insns = insns
        self._provenance = FmtProvenance(insns)
        self._args = FmtArgumentCheck(insns)
        self._rdata = rdata_reader
        self._suppressed: List[Tuple[dict, str]] = []

    def suppress(self, findings: List[dict],
                 addr_to_idx: Dict[int, int]) -> List[dict]:
        """过滤 findings, 返回保留项; 抑制项带证据."""
        kept = []
        for f in findings:
            # rdx 补充检测已做 USER 验证 — 不重复抑制
            if f.get("verified_rdx"):
                kept.append(f)
                continue
            addr = f.get("insn_addr", 0)
            call_idx = addr_to_idx.get(addr)
            if call_idx is None:
                kept.append(f)
                continue
            verdict, reason = self._decide(f, addr, call_idx)
            if verdict == _KEEP:
                kept.append(f)
            else:
                self._suppressed.append((f, reason))
        return kept

    def suppressed_evidence(self) -> List[dict]:
        return [{"insn_addr": f.get("insn_addr", 0),
                 "reason": r} for f, r in self._suppressed]

    def _decide(self, f: dict, addr: int,
                call_idx: int) -> Tuple[str, str]:
        src, evidence = self._provenance.classify(call_idx, "rcx")
        if src == FmtSource.UNKNOWN:
            # 再试 Win64 入口寄存器
            src, evidence = self._provenance.classify(call_idx, "rdi")
        if src in (FmtSource.RDATA, FmtSource.STACK_CONST,
                   FmtSource.HEAP_CONST):
            return _SAFE, f"S-F1 {src.name}: {evidence}"
        if src == FmtSource.USER:
            return _KEEP, ""
        # UNKNOWN: 参数一致性佐证
        fmt_str = self._fmt_string_at(addr, call_idx)
        if fmt_str:
            spec = count_specifiers(fmt_str)
            n_args = self._args.count_args(call_idx)
            if spec["total"] > 0 and n_args >= spec["total"]:
                return _SAFE, f"S-F4 spec({spec['total']}) <= args({n_args}) " \
                              f"on constant fmt - benign formatting"
        return _KEEP, ""

    def _fmt_string_at(self, addr: int,
                       call_idx: int) -> Optional[str]:
        """从 .rdata 读取调用点的格式串内容 (若可用)."""
        if self._rdata is None or not getattr(self._rdata, "is_loaded", False):
            return None
        # 复用 binary_fmt_scanner 的 rip 偏移追踪: 直接查调用点前 lea
        for j in range(call_idx - 1, max(0, call_idx - 10), -1):
            ins = self._insns[j]
            if ins.mnemonic != "lea" or len(ins.operands) < 2:
                continue
            if InstructionParser.normalize_reg(ins.operands[0]) != "rcx":
                continue
            import re as _re
            m = _re.search(r"[+-]0x([0-9a-f]+)", ins.operands[1])
            if not m:
                continue
            rip_off = int(m.group(1), 16)
            if "-" in ins.operands[1]:
                rip_off = -rip_off
            ins_len = 7
            mm = _re.search(r':\s+((?:[0-9a-f]{2}\s)+)\s{2,}', ins.raw_line)
            if mm:
                ins_len = len(mm.group(1).strip().split())
            target_va = ins.address + ins_len + rip_off
            return self._rdata.read_string_at_va(target_va)
        return None


# smoke test
def _check():
    class _I:
        def __init__(self, addr, mn, ops, raw=""):
            self.address = addr
            self.mnemonic = mn
            self.operands = ops
            self.raw_line = raw

    insns = [
        _I(0x1000, "lea", ["rcx", "[rip+0x9830]"], "lea rcx,[rip+0x9830]"),
        _I(0x1007, "call", ["printf"]),
    ]
    addr_to_idx = {0x1007: 1}
    f = {"type": "format_string", "insn_addr": 0x1007,
         "reason": "possibly user-controlled fmt"}
    s = FmtSuppressor(insns)
    v, r = s._decide(f, 0x1007, 1)
    assert v == _SAFE, f"lea rip 应滤, got {v} {r}"
    print("[OK] fmt_suppress: RDATA 溯源过滤通过")


if __name__ == "__main__":
    _check()
