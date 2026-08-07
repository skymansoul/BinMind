# Ghidra UAF基线检测器 v1 — 模拟Ghidra decompiler的UAF检测
#
# 策略: 通过函数级xref模式匹配寻找free→deref序列
# 不追踪寄存器值流, 不做路径分析 → 预期高误报
#
# 创建: 2026-08-04

import sys, time, subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

_ALLOC_FUNCS = {"malloc", "calloc", "_Znwm", "_Znam", "operator_new"}
_FREE_FUNCS = {"free", "_ZdlPv", "_ZdaPv", "operator_delete"}
_DANGEROUS_CALLS = {"memcpy", "memmove", "memset", "strcpy", "strncpy",
                    "sprintf", "snprintf", "printf", "fprintf",
                    "strlen", "strcmp", "strncmp"}


def _disassemble(binary_path: str) -> List[dict]:
    try:
        out = subprocess.run(
            ["objdump", "-d", "-M", "intel", binary_path],
            capture_output=True, text=True, timeout=30
        ).stdout
    except Exception:
        return []
    insns = []
    for line in out.split("\n"):
        parts = line.strip().split("\t")
        if len(parts) < 3:
            continue
        try:
            addr = int(parts[0].strip().rstrip(":"), 16)
            mnem_part = parts[2].split()
            mnem = mnem_part[0] if mnem_part else ""
            ops = []
            if len(mnem_part) > 1:
                for o in " ".join(mnem_part[1:]).split(","):
                    ops.append(o.strip())
            insns.append({"address": addr, "mnemonic": mnem, "operands": ops})
        except (ValueError, IndexError):
            continue
    return insns


def _extract_func_name(op: str) -> str:
    if "<" in op and ">" in op:
        name = op.split("<")[-1].split(">")[0].split("+")[0]
        return name.lstrip("_")
    return op.strip()


class GhidraUAFBaseline:
    """Ghidra风格UAF检测: 函数内xref匹配, 无寄存器追踪.

    在每个函数范围内查找 free→dangerous_call 序列,
    若同一函数内出现 free 后紧接危除调用则报告 UAF.
    """

    def __init__(self):
        self._findings: List[dict] = []

    def analyze(self, instructions: List[dict]) -> List[dict]:
        # 按函数分段(以push rbp开头, ret结尾)
        func_ranges: List[tuple] = []
        func_start: Optional[int] = None
        for i, ins in enumerate(instructions):
            mnem = ins.get("mnemonic", "").lower()
            if func_start is None:
                if mnem == "push" and ins.get("operands", [""])[0].lower() == "rbp":
                    func_start = i
            else:
                if mnem == "ret":
                    func_ranges.append((func_start, i))
                    func_start = None

        for lo, hi in func_ranges:
            self._scan_function(instructions, lo, hi)
        return self._findings

    def _scan_function(self, instructions: List[dict], lo: int, hi: int):
        has_free = False
        free_addr = 0
        for j in range(lo, hi + 1):
            ins = instructions[j]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            addr = ins.get("address", 0)

            if mnem == "call" and ops:
                func = _extract_func_name(ops[0])
                if func in _FREE_FUNCS:
                    if has_free:
                        self._findings.append({
                            "type": "double_free",
                            "address": addr, "freed_at": free_addr})
                    has_free = True
                    free_addr = addr
                elif func in _DANGEROUS_CALLS and has_free:
                    self._findings.append({
                        "type": "use_after_free",
                        "address": addr, "freed_at": free_addr})
                elif func in _ALLOC_FUNCS:
                    has_free = False


def analyze_binary(binary_path: str, timeout: int = 60) -> dict:
    t0 = time.perf_counter()
    result = {"tool": "Ghidra-UAF", "binary": binary_path,
              "detected": False, "finding_count": 0,
              "uaf_count": 0, "double_free_count": 0,
              "time_ms": 0, "findings": [], "error": ""}
    try:
        insns = _disassemble(binary_path)
        if not insns:
            result["error"] = "disassembly failed"
            result["time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            return result
        detector = GhidraUAFBaseline()
        findings = detector.analyze(insns)
        uaf = [f for f in findings if f["type"] == "use_after_free"]
        df = [f for f in findings if f["type"] == "double_free"]
        result["findings"] = findings
        result["finding_count"] = len(findings)
        result["uaf_count"] = len(uaf)
        result["double_free_count"] = len(df)
        result["detected"] = len(findings) > 0
    except Exception as e:
        result["error"] = str(e)[:200]
    result["time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return result


__all__ = ["analyze_binary"]
