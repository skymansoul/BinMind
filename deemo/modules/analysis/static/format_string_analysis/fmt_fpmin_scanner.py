"""FMT-FPMIN 检测器 - BinaryFmtScanner + 溯源/参数一致性抑制封装.

相对既有 scanner 的两处增强 (不修改原类):
  1. _FMT_FUNCS 扩展: 补 __mingw_fprintf/__mingw_sprintf 等 MinGW
     包装名 — 原集合缺失导致 fprintf/sprintf 用户格式串漏检
  2. FmtSuppressor 后处理: RDATA/栈槽常量/堆常量溯源 → 滤;
     USER 溯源 → 保留; UNKNOWN + 参数一致 → 滤
"""

import os
import sys
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from .binary_fmt_scanner import BinaryFmtScanner  # noqa: E402
from .fmt_suppress import FmtSuppressor            # noqa: E402
from ..heap_analysis.instruction_parser import InstructionParser  # noqa: E402


class FmtFpminScanner(BinaryFmtScanner):
    """误报抑制版格式串扫描器 - 扩展 callee 集 + 证据过滤."""

    _FMT_FUNCS = {
        "printf", "fprintf", "sprintf", "snprintf",
        "__mingw_printf", "__mingw_fprintf", "__mingw_sprintf",
        "__mingw_snprintf", "__mingw_vfprintf", "__mingw_vsprintf",
        "__mingw_vsnprintf", "__printf_chk", "__fprintf_chk",
        "__sprintf_chk", "__snprintf_chk",
    }

    # sprintf 家族: dst=rcx, fmt=rdx - 原 scanner 只查 rcx/rdi, 漏 rdx
    _SPRINTF_FAMILY = {"sprintf", "snprintf", "__mingw_sprintf",
                       "__mingw_snprintf", "__mingw_vsprintf",
                       "__mingw_vsnprintf", "__sprintf_chk",
                       "__snprintf_chk"}

    def scan(self, objdump_output: str, sample_name: str = "",
             user_code_only: bool = True,
             functions: Optional[Dict[int, str]] = None,
             binary_path: Optional[str] = None) -> dict:
        import time
        t0 = time.perf_counter()
        # 导入映射显式设置 - callee 解析不依赖外部 import 时序
        if binary_path and os.path.isfile(binary_path):
            from ..heap_analysis.plt_resolver import build_import_map
            InstructionParser.set_import_map(build_import_map(binary_path))
        raw = super().scan(objdump_output, sample_name,
                           user_code_only=user_code_only,
                           functions=functions,
                           binary_path=binary_path)
        insns = InstructionParser.parse(objdump_output)
        addr_to_idx = {ins.address: i for i, ins in enumerate(insns)}
        # 补充检测只在用户函数指令内扫描 — 避免 CRT 内部
        # vsnprintf 转发链 (printf 实现) 被误判为用户调用
        user_insns = insns
        if user_code_only:
            funcs = functions or InstructionParser.parse_functions(
                objdump_output)
            user_insns = InstructionParser.filter_user_instructions(
                insns, funcs) or insns
        raw = self._supplement_sprintf_fmt(user_insns, addr_to_idx, raw)
        suppressor = FmtSuppressor(insns, self._rdata_reader)
        kept = suppressor.suppress(raw, addr_to_idx)
        suppressed = suppressor.suppressed_evidence()
        for f in kept:
            f["source"] = "fmt_fpmin"
        return {
            "sample": sample_name,
            "findings": kept,
            "n_findings": len(kept),
            "suppressed": suppressed,
            "n_suppressed": len(suppressed),
            "n_raw": len(raw),
            "elapsed_ms": (time.perf_counter() - t0) * 1000,
        }

    def _supplement_sprintf_fmt(self, insns: list,
                                addr_to_idx: dict,
                                raw: List[dict]) -> List[dict]:
        """fmt 调用点溯源补检 — 覆盖原 scanner 的两类缺陷.

        缺陷1: sprintf 家族 fmt 在 rdx, 原 scanner 只查 rcx/rdi.
        缺陷2: _literal_regs 残留 (寄存器重用后旧标记不清),
               printf(fmt堆指针) 被误判为 .rdata 常量.
        对每个 fmt 调用点按 Win64 约定检查 rcx (printf 家族) 与
        rdx (sprintf 家族) 的溯源, USER → 追加 verified finding.
        """
        from .fmt_provenance import FmtProvenance, FmtSource
        prov = FmtProvenance(insns)
        extra = []
        for i, ins in enumerate(insns):
            if ins.mnemonic != "call":
                continue
            callee = InstructionParser.extract_callee(ins)
            if callee not in self._FMT_FUNCS:
                continue
            check_regs = ("rdx",) if callee in self._SPRINTF_FAMILY \
                else ("rcx",)
            for reg in check_regs:
                src, _ = prov.classify(i, reg)
                if src == FmtSource.USER:
                    extra.append({
                        "type": "format_string",
                        "insn_addr": ins.address,
                        "callee": callee,
                        "reason": f"{callee} user-controlled fmt in {reg} "
                                  f"(loaded from user input)",
                        "confidence": 0.5,
                        "fscs_score": 7.0,
                        "verified_rdx": True,
                    })
                    break
        return raw + extra


# smoke test
def _check():
    s = FmtFpminScanner()
    # 常量格式串 → 滤
    r = s.scan("1000:       55                      push   rbp\n"
               "1001:       48 89 e5                mov    rbp,rsp\n"
               "1004:       48 8d 0d 30 98 00 00    lea    rcx,[rip+0x9830]\n"
               "100b:       e8 f0 fe ff ff          call   1000 <printf>\n",
               user_code_only=False)
    assert r["n_findings"] == 0, f"常量串应滤, got {r['n_findings']}"
    # 用户格式串 → 保留
    r2 = s.scan("2000:       55                      push   rbp\n"
                "2001:       48 89 e5                mov    rbp,rsp\n"
                "2004:       48 8b 4d 18             mov    rcx,QWORD PTR [rbp+0x18]\n"
                "2008:       e8 f3 fe ff ff          call   1000 <printf>\n",
                user_code_only=False)
    assert r2["n_findings"] >= 1, f"用户格式串应保留, got {r2['n_findings']}"
    print(f"[OK] fmt_fpmin_scanner: 滤={r['n_findings']}/保留={r2['n_findings']}")


if __name__ == "__main__":
    _check()
