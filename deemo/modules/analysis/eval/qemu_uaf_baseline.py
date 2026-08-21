# QEMU UAF基线检测器 v1 - 动态执行检测UAF导致的崩溃
#
# 策略: 通过QEMU用户模式执行二进制, 检测SIGSEGV/SIGABRT
# UAF不总是导致崩溃 → 预期低召回但低误报
#

import sys, time, subprocess, os
from pathlib import Path
from typing import Optional


def _detect_qemu() -> Optional[str]:
    for name in ("qemu-x86_64", "qemu-x86_64-static",
                 "qemu-i386", "qemu-i386-static"):
        try:
            r = subprocess.run(["which", name],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()
        except Exception:
            pass
    try:
        where = subprocess.run(["where", "qemu-x86_64"],
                               capture_output=True, text=True, timeout=5)
        if where.returncode == 0 and where.stdout.strip():
            return where.stdout.strip().split("\n")[0]
    except Exception:
        pass
    return None


def trace_binary(binary_path: str, timeout: int = 10) -> dict:
    result = {"crashed": False, "signals": [], "time_ms": 0, "error": ""}
    qemu = _detect_qemu()
    if not qemu:
        result["error"] = "qemu-user not found"
        return result
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            [qemu, "-strace", binary_path],
            capture_output=True, text=True, timeout=timeout
        )
        stderr = proc.stderr
        rc = proc.returncode
        crash_signals = {
            -11: "SIGSEGV", -6: "SIGABRT", -7: "SIGBUS",
            -8: "SIGFPE", -4: "SIGILL"
        }
        if rc in crash_signals:
            result["crashed"] = True
            result["signals"].append({
                "signal": crash_signals[rc], "returncode": rc})
        if "SEGV" in stderr or "Assertion" in stderr:
            if not result["crashed"]:
                result["crashed"] = True
                result["signals"].append({"signal": "SEGV/assert", "returncode": rc})
    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)[:200]
    result["time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return result


def analyze_binary(binary_path: str, timeout: int = 10) -> dict:
    t0 = time.perf_counter()
    result = {"tool": "QEMU-UAF", "binary": binary_path,
              "detected": False, "finding_count": 0,
              "uaf_count": 0, "double_free_count": 0,
              "time_ms": 0, "findings": [], "error": ""}
    trace = trace_binary(binary_path, timeout=timeout)
    result["detected"] = trace.get("crashed", False)
    result["finding_count"] = len(trace.get("signals", []))
    result["uaf_count"] = result["finding_count"]
    result["error"] = trace.get("error", "")
    result["time_ms"] = trace.get("time_ms", 0)
    if result["detected"]:
        result["findings"] = [{"type": "crash", "address": 0,
                               "signal": trace["signals"][0]["signal"]}]
    return result


__all__ = ["analyze_binary"]
