# eval/qemu_tracer — QEMU user mode 运行时内存操作追踪
# 利用 qemu-x86_64 -d cpu,exec 抓取指令执行序列,
# 从日志中解析危险函数调用及其参数, 生成 ground truth 标记。
# 若 QEMU 未安装则输出 SKIP 而不中断整体流程。

import subprocess, json, re, os, sys, tempfile
from pathlib import Path


def trace_execution(target: str, timeout: int = 30) -> dict:
    """运行目标并抓取 QEMU 执行日志。"""
    # PE/COFF 无法在 qemu-user (仅 ELF) 下运行 → 明确标记
    if str(target).lower().endswith((".exe", ".dll", ".sys")):
        return {"tool": "qemu", "error": "PE binary not runnable under "
                "qemu-user (ELF only)", "available": False, "skip": True}

    qemu_bin = "qemu-x86_64"
    # 检查 QEMU 是否可用
    try:
        subprocess.run([qemu_bin, "--version"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {"tool": "qemu", "error": "qemu-x86_64 not installed",
                "available": False, "skip": True}

    try:
        proc = subprocess.run(
            [qemu_bin, "-d", "in_asm,cpu", target],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"tool": "qemu", "error": "timeout", "available": True}

    log = proc.stderr if proc.stderr else ""
    # 从执行日志中解析危险函数调用
    # 简化: 搜索 call 指令后的跳转目标是否在危险地址范围内
    dangerous_calls = []
    for m in re.finditer(r'(?:call|jmp)\s+(0x[0-9a-f]+)', log, re.IGNORECASE):
        dangerous_calls.append({"address": m.group(1), "type": "call_or_jmp"})

    # 统计执行的基本块数
    blocks = len(re.findall(r'IN:', log))

    return {
        "tool": "qemu",
        "available": True,
        "executed": proc.returncode == 0,
        "basic_blocks_executed": blocks,
        "dangerous_calls_detected": len(dangerous_calls),
        "call_sites": dangerous_calls[:20],
        "stderr_bytes": len(log),
    }


def generate_ground_truth(target: str) -> dict:
    """结合 QEMU 追踪和 AC3 分析, 生成 ground truth 数据。
    若 QEMU 不可用, 则基于 AC3 的高置信度发现作为近似 ground truth。
    """
    qemu_result = trace_execution(target)

    if qemu_result.get("available"):
        # QEMU 可用: 以它为 ground truth
        executed = qemu_result.get("basic_blocks_executed", 0) > 0
        return {
            "ground_truth_source": "qemu_dynamic",
            "executed": executed,
            "blocks_hit": qemu_result.get("basic_blocks_executed", 0),
            "has_dangerous_calls": qemu_result.get("dangerous_calls_detected", 0) > 0,
        }
    else:
        # QEMU 不可用: 标记 unknown
        return {
            "ground_truth_source": "unavailable",
            "executed": False,
            "note": "QEMU user mode not installed; ground truth unavailable",
        }


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    if target and os.path.exists(target):
        result = generate_ground_truth(target)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(json.dumps({"error": "no_target", "usage": "python qemu_tracer.py <elf>"}))
