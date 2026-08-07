# Angr UAF基线检测器 v1 — 模拟符号执行的UAF检测baseline
#
# 策略: 通过CFG分析识别malloc→free→use模式, 但不做路径敏感分析
# → 预期高召回但高误报(无法区分互斥路径/NULL赋值/reassign)
#
# 创建: 2026-07-04

import sys, time, subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

_ALLOC_FUNCS = {"malloc", "calloc", "_Znwm", "_Znam", "operator_new"}
_FREE_FUNCS = {"free", "_ZdlPv", "_ZdaPv", "operator_delete"}
_DANGEROUS_CALLS = {"memcpy", "memmove", "memset", "strcpy", "strncpy",
                    "sprintf", "snprintf", "printf", "fprintf",
                    "strlen", "strcmp", "strncmp"}
_WIN64_ARGS = ("rcx", "rdx", "r8", "r9")
_SYSV_ARGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")


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


def _norm_reg(op: str) -> str:
    r = op.strip().lower()
    for p in ("qword ptr ", "dword ptr ", "word ptr ", "byte ptr "):
        if r.startswith(p):
            r = r[len(p):]
    if r.startswith("[") and r.endswith("]"):
        return ""
    for pre in ("r", "e"):
        if r.startswith(pre) and len(r) == 3:
            return r
    return r


def _extract_func_name(op: str) -> str:
    if "<" in op and ">" in op:
        name = op.split("<")[-1].split(">")[0].split("+")[0]
        return name.lstrip("_")
    return op.replace("rip+", "").strip()


class AngrUAFBaseline:
    """Angr风格UAF检测: 无路径敏感, 无NULL过滤, 无reassign分析."""

    def __init__(self, use_win64: bool = True):
        self._win64 = use_win64
        self._arg_regs = _WIN64_ARGS if use_win64 else _SYSV_ARGS
        self._objects: Dict[int, dict] = {}
        self._reg_to_obj: Dict[str, int] = {}
        self._next_oid = 1
        self._findings: List[dict] = []

    def analyze(self, instructions: List[dict]) -> List[dict]:
        for ins in instructions:
            self._process(ins)
        return self._findings

    def _process(self, ins: dict):
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        addr = ins.get("address", 0)

        if mnem == "call" and ops:
            func = _extract_func_name(ops[0])
            if func in _ALLOC_FUNCS:
                oid = self._next_oid
                self._objects[oid] = {"freed": False, "alloc_at": addr}
                self._reg_to_obj["rax"] = oid
                self._reg_to_obj["eax"] = oid
                self._next_oid += 1
            elif func in _FREE_FUNCS:
                arg0 = self._arg_regs[0]
                oid = self._reg_to_obj.get(arg0)
                if oid is not None and oid in self._objects:
                    if self._objects[oid]["freed"]:
                        self._findings.append({
                            "type": "double_free", "address": addr, "obj_id": oid})
                    self._objects[oid]["freed"] = True
                    self._reg_to_obj.pop(arg0, None)
            elif func in _DANGEROUS_CALLS:
                for ar in self._arg_regs[:4]:
                    oid = self._reg_to_obj.get(ar)
                    if oid and oid in self._objects and self._objects[oid]["freed"]:
                        self._findings.append({
                            "type": "use_after_free", "address": addr,
                            "obj_id": oid})
                        break
            self._reg_to_obj.pop("rax", None)
            self._reg_to_obj.pop("eax", None)

        if mnem == "ret":
            for r in ("rax","rcx","rdx","r8","r9","eax","ecx","edx","r8d","r9d"):
                self._reg_to_obj.pop(r, None)

        if mnem in ("mov", "movzx", "movsx") and len(ops) >= 2:
            dst = _norm_reg(ops[0])
            src = _norm_reg(ops[1])
            if dst and src:
                oid = self._reg_to_obj.get(src)
                if oid is not None:
                    self._reg_to_obj[dst] = oid

        if mnem == "xor" and len(ops) >= 2:
            d, s = _norm_reg(ops[0]), _norm_reg(ops[1])
            if d == s:
                self._reg_to_obj.pop(d, None)


def analyze_binary(binary_path: str, timeout: int = 60) -> dict:
    t0 = time.perf_counter()
    result = {"tool": "Angr-UAF", "binary": binary_path,
              "detected": False, "finding_count": 0,
              "uaf_count": 0, "double_free_count": 0,
              "time_ms": 0, "findings": [], "error": ""}
    try:
        insns = _disassemble(binary_path)
        if not insns:
            result["error"] = "disassembly failed"
            result["time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            return result
        detector = AngrUAFBaseline(use_win64=True)
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
