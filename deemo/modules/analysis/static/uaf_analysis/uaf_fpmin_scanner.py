"""UAF-FPMIN 检测器 - BinaryUafScanner + 误报融合抑制封装.

管线: objdump 文本 → BinaryUafScanner (既有, 不改动) →
      UafFpSuppressor (S1-S5 证据过滤) → 最终 findings.
输出: findings (保留项) + suppressed (抑制项及证据), 供消融对比.
"""

import os
import sys
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))

from .binary_uaf_scanner import BinaryUafScanner  # noqa: E402
from .uaf_fp_suppress import UafFpSuppressor      # noqa: E402
from ..heap_analysis.instruction_parser import InstructionParser  # noqa: E402


class UafFpminScanner:
    """误报抑制版 UAF 扫描器 - run_scanner 的 uaf_fpmin 检测器."""

    def __init__(self, binary_path: Optional[str] = None):
        self._binary_path = binary_path
        self._scanner = BinaryUafScanner()

    def scan(self, objdump_output: str, sample_name: str = "",
             user_code_only: bool = True) -> dict:
        import time
        t0 = time.perf_counter()
        raw = self._scanner.scan(objdump_output, sample_name,
                                 user_code_only=user_code_only)
        insns = InstructionParser.parse(objdump_output)
        func_map = InstructionParser.parse_functions(objdump_output)
        if user_code_only:
            insns = InstructionParser.filter_user_instructions(
                insns, func_map) or insns
        suppressor = UafFpSuppressor(insns, self._binary_path, func_map)
        kept = suppressor.suppress(raw)
        suppressed = suppressor.suppressed_evidence()
        for f in kept:
            f["source"] = "uaf_fpmin"
        return {
            "sample": sample_name,
            "findings": kept,
            "n_findings": len(kept),
            "suppressed": suppressed,
            "n_suppressed": len(suppressed),
            "n_raw": len(raw),
            "elapsed_ms": (time.perf_counter() - t0) * 1000,
        }


# smoke test
def _check():
    s = UafFpminScanner()
    r = s.scan("1000: 55 push rbp\n1001: 48 89 e5 mov rbp,rsp\n"
               "1004: 48 8b 4d 10 mov rcx,[rbp+0x10]\n"
               "1008: e8 f3 fe ff ff call free\n"
               "100d: 48 c7 01 00 mov QWORD PTR [rcx],0",
               user_code_only=False)
    assert r["n_findings"] >= 1, f"真 UAF 应保留, got {r['n_findings']}"
    print(f"[OK] uaf_fpmin_scanner: 真 UAF 保留 ({r['n_findings']}), "
          f"抑制 {r['n_suppressed']}")


if __name__ == "__main__":
    _check()
