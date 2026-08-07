# QEMU user-mode 追踪器 — 运行时内存操作作为 ground truth.
#
# 决策逻辑:
#   qemu-x86_64 以用户态执行 ELF, 配合自写轻量插桩 (syscall trace +
#   信号捕获) 判定堆溢出是否实际触发:
# 若样本以构造的超限输入运行且产生 SIGSEGV/SIGABRT (malloc
#       检测到越界写后 abort) → 运行时确实溢出.
#   PE 样本无法由 qemu-user 直接执行, 返回 unsupported, 不产生误报.
#   该结果作为"动态 ground truth 对照组", 与静态工具交叉验证.
#
# 创建: 2026-06-25

import json
import os
import shutil
import subprocess
import sys
import time
from typing import Dict


def qemu_available() -> bool:
    return shutil.which("qemu-x86_64") is not None or \
        shutil.which("qemu-x86_64-static") is not None


def _is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except Exception:
        return False


def trace(binary: str, arg: str = "65536") -> Dict:
    """以构造输入运行样本, 追踪运行时崩溃.

    arg: 传给样本的超限长度参数 (argv[1]).
    返回: {detected, signal, elapsed_ms, error, format}
    """
    t0 = time.perf_counter()
    result = {"detected": False, "signal": "", "elapsed_ms": 0.0,
              "error": "", "format": "unknown"}
    if not qemu_available():
        result["error"] = "qemu-x86_64 not found"
        return result
    if not _is_elf(binary):
        result["format"] = "pe"
        result["error"] = "qemu-user requires ELF (PE unsupported)"
        return result
    result["format"] = "elf"

    qemu = shutil.which("qemu-x86_64") or \
        shutil.which("qemu-x86_64-static")
    try:
        # -strace 打印 syscall, 超限输入触发 glibc abort / SEGV
        r = subprocess.run(
            [qemu, "-strace", binary, arg, "A" * 4096],
            capture_output=True, text=True, timeout=15)
        stderr = (r.stderr or "") + (r.stdout or "")
        if "SIGSEGV" in stderr or "SIGABRT" in stderr or \
                "stack smashing" in stderr or "munmap_chunk" in stderr or \
                "free(): invalid" in stderr:
            result["detected"] = True
            result["signal"] = "SIGSEGV/SIGABRT"
    except subprocess.TimeoutExpired:
        result["error"] = "timeout (no crash in 15s)"
    except Exception as e:
        result["error"] = f"qemu run failed: {str(e)[:120]}"

    result["elapsed_ms"] = (time.perf_counter() - t0) * 1000
    return result


def main():
    if len(sys.argv) < 2:
        print("usage: python qemu_tracer.py <binary> [arg] [--json]")
        return
    binary = sys.argv[1]
    arg = sys.argv[2] if len(sys.argv) > 2 and \
        not sys.argv[2].startswith("--") else "65536"
    res = trace(binary, arg)
    if "--json" in sys.argv:
        print(json.dumps(res, indent=2, default=str))
    else:
        print(f"detected={res['detected']} signal={res['signal']} "
              f"time={res['elapsed_ms']:.0f}ms error={res['error']}")


if __name__ == "__main__":
    main()
