"""说明符/实参一致性验证 — 常量格式串的合法性佐证.

用途: 为融合判定器提供第二证据 — 常量格式串的说明符数量
与实际传入参数数量一致时, 该调用是正常格式化 (SAFE 佐证);
数量不匹配 (缺参数) 提示异常, 但不单独构成漏洞判定.

说明符解析: %[flags][width][.prec][length]conv, 跳过 %%.
"""

import re
from typing import Dict, List, Optional, Tuple

from ..heap_analysis.instruction_parser import InstructionParser

_CONV = "diouxXeEfFgGaAcspnm"
_SPEC_RE = re.compile(
    r"%[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|L|z|j|t)?[" + _CONV + r"]")


def count_specifiers(fmt: str) -> Dict[str, int]:
    """统计格式串中的转换说明符 (%% 预处理为占位, 不计入)."""
    stats = {"total": 0, "write": 0, "string": 0, "num": 0}
    body = (fmt or "").replace("%%", "\x00")
    for m in _SPEC_RE.finditer(body):
        stats["total"] += 1
        conv = m.group(0)[-1]
        if conv == "n":
            stats["write"] += 1
        elif conv == "s":
            stats["string"] += 1
        else:
            stats["num"] += 1
    return stats


class FmtArgumentCheck:
    """实参计数 — 统计 call 点被填充的参数寄存器/栈槽."""

    _ARG_REGS = ("rdx", "r8", "r9")   # SysV: rsi/rdx/rcx/r8/r9; Win64: rdx/r8/r9

    def __init__(self, insns: list):
        self._insns = insns
        self._addr_to_idx = {ins.address: i for i, ins in enumerate(insns)}

    def count_args(self, call_idx: int) -> int:
        """统计 call 前被定义的实参寄存器数."""
        n = 0
        for reg in self._ARG_REGS:
            if self._reg_defined(call_idx, reg):
                n += 1
        return n

    def _reg_defined(self, call_idx: int, reg: str) -> bool:
        for j in range(call_idx - 1, max(0, call_idx - 10), -1):
            ins = self._insns[j]
            if ins.mnemonic not in ("mov", "movabs", "lea", "movzx",
                                    "movsx") or len(ins.operands) < 2:
                continue
            if InstructionParser.normalize_reg(ins.operands[0]) == reg:
                src = ins.operands[1].strip()
                # 立即数/寄存器/内存来源都算"已填充"
                return InstructionParser._try_parse_int(src) is not None \
                    or InstructionParser.normalize_reg(src) is not None \
                    or "[" in src
        return False

    def match(self, spec: Dict[str, int], n_args: int) -> bool:
        """说明符数 (不含 %n, %n 消耗指针参数) 与实参数一致."""
        need = spec["total"]
        return need <= n_args and need >= n_args - 1


# smoke test
def _check():
    spec = count_specifiers("user=%s count=%d\n")
    assert spec["total"] == 2 and spec["string"] == 1, spec
    spec2 = count_specifiers("prefix%n-suffix\n")
    assert spec2["total"] == 1 and spec2["write"] == 1, spec2
    spec3 = count_specifiers("100%% done\n")
    assert spec3["total"] == 0, spec3
    print("[OK] fmt_argument_check: 说明符解析通过")


if __name__ == "__main__":
    _check()
