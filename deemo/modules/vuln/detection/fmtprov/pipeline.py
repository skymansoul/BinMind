# coding: utf-8
# 创建: 2026-05-10  |  格式化字符串验证管线
#
"""
FMTPROV 管线: 扫描格式调用点 → 溯源 fmt 参数 → 判定。

判定语义:
  SAFE        fmt 为编译期常量 (rodata) → 滤除
  VULN        fmt 来自用户输入 → 告警
  SUSPICIOUS 无法归因 → 保守保留

%n 可用性: 输出非 stderr/syslog → 可用 (标记利用深度)。
"""

import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from heapver.insn import Instruction, parse_disasm, callee_name

from .fmt_abi import find_format
from .taint import FmtTaintWalker, CONST, TAINT, UNKNOWN

SAFE = "SAFE"
VULN = "VULN"
SUSPICIOUS = "SUSPICIOUS"

# CRT/导入库函数——不参与用户代码判定 (避免启动代码格式调用噪音)
_LIB_FUNCS = frozenset({
    "malloc", "calloc", "realloc", "free", "_ZdlPv", "_ZdaPv",
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat",
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
    "vsprintf", "vsnprintf", "dprintf", "puts", "putchar",
    "scanf", "gets", "fgets", "fread", "read", "recv", "getenv",
    "strlen", "strchr", "strstr", "strcmp", "strncmp", "atoi",
    "fflush", "fwrite", "fclose", "fopen", "stdin", "stdout",
    "__main", "mainCRTStartup", "WinMainCRTStartup",
    "__tmainCRTStartup", "_setargv", "__mingw_raise_matherr",
    "__report_error", "_amsg_exit", "_fpreset", "_initterm",
    "__getmainargs", "__acrt_iob_func", "__set_app_type",
    "safe_flush", "check_managed_app", "duplicate_ppstrings",
    "mark_section_writable", "restore_modified_sections",
    "do_pseudo_reloc", "__write_memory", "__do_global_dtors",
    "__do_global_ctors", "register_frame_ctor", "atexit",
    "__gcc_register_frame", "__gcc_deregister_frame",
    "_pei386_runtime_relocator", "__mingwthr_run_key_dtors",
    "__mingw_TLScallback", "__tlregdtor", "__dyn_tls_dtor",
    "_initterm_e", "_cexit", "_crt_atexit", "__iob_func",
    "abort", "exit", "_exit",
})

# 子串黑名单——CRT 内部符号
_LIB_SUBSTR = ("mingw", "pseudo_reloc", "section_writable",
               "relocator", "matherr", "_tls", "exception_handler",
               "_initterm", "app_type", "iob_func", "register_frame",
               "frame_info", "ValidateImage", "FindPESection",
               "GetPEImage", "IsNonwritable", "enum_import",
               "chkstk", "getmainargs", "invalid_parameter",
               "configthreadlocale", "specific_handler")


def _is_user_func(name: str) -> bool:
    if name == "main":
        return True
    if name in _LIB_FUNCS or name.startswith("_"):
        return False
    if any(sub in name for sub in _LIB_SUBSTR):
        return False
    return True


@dataclass
class FmtFinding:
    verdict: str = SUSPICIOUS
    rule: str = ""
    func: str = ""
    addr: int = 0
    fmt_func: str = ""
    classification: str = UNKNOWN
    pct_n: bool = False
    evidence: List[str] = field(default_factory=list)

    @property
    def is_finding(self) -> bool:
        return self.verdict in (VULN, SUSPICIOUS)


@dataclass
class FmtReport:
    binary_path: str = ""
    n_functions: int = 0
    n_calls: int = 0
    n_safe: int = 0
    n_vuln: int = 0
    n_suspicious: int = 0
    fp_reduction_pct: float = 0.0
    elapsed_ms: float = 0.0
    findings: List[FmtFinding] = field(default_factory=list)
    per_class: Dict[str, int] = field(default_factory=dict)

    @property
    def detected(self) -> bool:
        return self.n_vuln + self.n_suspicious > 0


class FmtProvenancePipeline:
    """格式化字符串验证管线."""

    def __init__(self):
        self._walker = FmtTaintWalker()

    def analyze(self, text: str, binary_path: str = "") -> FmtReport:
        t0 = time.time()
        rep = FmtReport(binary_path=binary_path)
        functions = parse_disasm(text)
        rep.n_functions = len(functions)

        for fn in functions:
            if not _is_user_func(fn.name):
                continue
            insns = fn.insns
            for i, insn in enumerate(insns):
                if not insn.is_call:
                    continue
                callee = callee_name(insn)
                key, sig = find_format(callee)
                if sig is None:
                    continue
                rep.n_calls += 1
                # ABI 候选: win64 优先, 失败回退 sysv
                cands = sig["win64"] + sig["sysv"]
                cls, ev = self._walker.resolve(insns, i, cands)
                rep.per_class[cls] = rep.per_class.get(cls, 0) + 1
                pct_n = "stderr" not in insn.raw and "syslog" not in insn.raw
                if cls == CONST:
                    v, rule = SAFE, "C_const_fmt"
                    rep.n_safe += 1
                elif cls == TAINT:
                    v, rule = VULN, "T_tainted_fmt"
                    rep.n_vuln += 1
                else:
                    v, rule = SUSPICIOUS, "U_unknown_fmt"
                    rep.n_suspicious += 1
                rep.findings.append(FmtFinding(
                    verdict=v, rule=rule, func=fn.name, addr=insn.addr,
                    fmt_func=callee, classification=cls, pct_n=pct_n,
                    evidence=[ev]))

        total = rep.n_safe + rep.n_vuln + rep.n_suspicious
        rep.fp_reduction_pct = round(rep.n_safe / max(1, total) * 100, 1)
        rep.elapsed_ms = round((time.time() - t0) * 1000, 1)
        return rep

    def analyze_binary(self, binary_path: str) -> FmtReport:
        text = _disassemble(binary_path)
        if not text:
            return FmtReport(binary_path=binary_path)
        return self.analyze(text, binary_path)

    def stats(self) -> dict:
        return {"walker": self._walker.stats()}


def _disassemble(binary_path: str) -> str:
    for tool in ("objdump", "llvm-objdump"):
        try:
            proc = subprocess.run(
                [tool, "-d", "-M", "intel", binary_path],
                capture_output=True, text=True, timeout=30)
            if proc.returncode == 0 and len(proc.stdout) > 100:
                return proc.stdout
        except Exception:
            continue
    return ""


__all__ = ["FmtProvenancePipeline", "FmtReport", "SAFE", "VULN",
           "SUSPICIOUS"]
