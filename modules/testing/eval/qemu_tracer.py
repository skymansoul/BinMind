"""QEMU 用户模式追踪器 — 运行时堆操作 ground truth.

两条路径:
  1. qemu-user 指令追踪 (Linux): qemu-x86_64 -d in_asm 解析
     malloc/memcpy 调用点, 提取大小参数做运行时比较
  2. ASan 插桩 ground truth (跨平台): gcc -fsanitize=address
     编译临时副本, 用触发输入运行, 解析 heap-buffer-overflow
     报告 — 作为标签验证的运行时事实源

qemu-user 不可用 → 仅提供 ASan ground truth, 不阻塞基准流程.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

_RESULTS_CACHE: Dict[str, dict] = {}


def _check_qemu() -> Optional[str]:
    """检查 QEMU user-mode 是否可用."""
    for qemu_bin in ('qemu-x86_64', 'qemu-i386', 'qemu-x86_64-static'):
        try:
            r = subprocess.run([qemu_bin, '--version'],
                               capture_output=True, timeout=5)
            if r.returncode == 0:
                return qemu_bin
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


# 路径1: qemu-user 指令追踪

_CALL_RE = re.compile(r'0x([0-9a-f]+):\s+.*\s+call(q?)\s+')
_MOVIMM_RE = re.compile(r'0x([0-9a-f]+):\s+.*\s+mov[qdl]?\s+\$(0x[0-9a-f]+|\d+),\s*%(rdi|rsi|rdx|rcx|r8)\b')


def _trace_with_qemu(binary_path: str, qemu_bin: str,
                     timeout: int = 20) -> List[dict]:
    """qemu-user -d in_asm 追踪, 统计 malloc/memcpy 大小模式."""
    findings = []
    try:
        result = subprocess.run(
            [qemu_bin, '-d', 'in_asm', '-D', '/dev/stdout', binary_path],
            capture_output=True, text=True, errors="ignore",
            timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return [{"type": "meta", "reason": "qemu trace timed out",
                 "confidence": 0.0}]
    except Exception as e:
        return [{"error": f"qemu trace failed: {e}"}]

    trace = result.stdout
    if not trace.strip():
        return []

    # 解析 call 目标与 mov imm 参数, 构建 malloc size / memcpy size 序列
    alloc_sizes: List[int] = []
    pending = {}          # reg → imm, 在 call 时消费
    overflow_found = False
    for line in trace.split('\n'):
        m = _MOVIMM_RE.search(line)
        if m:
            try:
                pending[m.group(3)] = int(m.group(2), 0)
            except ValueError:
                continue
            continue
        m = _CALL_RE.search(line)
        if not m:
            continue
        # call 目标的符号名不可直接获得 — 用附近 mov 序列粗分类
        rdi = pending.pop('rdi', None)
        rdx = pending.pop('rdx', None)
        r8 = pending.pop('r8', None)
        # 难以可靠区分 malloc/memcpy — 仅记录大小对
        if rdi is not None and (rdx is not None or r8 is not None):
            alloc_sizes.append((rdi, rdx or r8 or 0))
    for alloc, write in alloc_sizes:
        if write > alloc:
            overflow_found = True
            findings.append({
                "type": "heap_overflow", "subtype": "qemu_trace",
                "reason": f"qemu runtime: write({write}) > alloc({alloc})",
                "confidence": 0.7})
            break
    if not overflow_found and alloc_sizes:
        findings.append({"type": "meta",
                         "reason": "qemu trace: no size mismatch observed",
                         "confidence": 0.0})
    return findings


# 路径2: ASan 插桩 ground truth

_ASAN_RE = re.compile(
    r'ERROR: AddressSanitizer: (heap-buffer-overflow|heap-use-after-free'
    r'|double-free|stack-buffer-overflow)')
_ASAN_LOC_RE = re.compile(r'#0\s+0x[0-9a-f]+ in (\w+)')

# Windows NTSTATUS 崩溃分类 (ASan 不可用时的运行时事实源)
_CRASH_CODES = {
    0xC0000374: "heap-corruption",       # STATUS_HEAP_CORRUPTION
    0xC0000005: "access-violation",      # STATUS_ACCESS_VIOLATION
    0xC0000094: "integer-overflow",      # STATUS_INTEGER_OVERFLOW
    0xC00000FD: "stack-overflow",        # STATUS_STACK_OVERFLOW
    0xC0000409: "stack-buffer-overrun",  # STATUS_STACK_BUFFER_OVERRUN
}

_TRIGGER_INPUTS = [
    [],                              # 默认输入
    ["A" * 300],                     # 长字符串触发 strcpy/memcpy
    ["A" * 1500],                    # 超长字符串 (跨 8KB 命令行上限内的最大触发)
    ["65536"],                       # 大数值参数
    ["0x1FFFFFFF"],                  # 整数溢出候选
]


def _classify_crash(rc: int) -> Optional[str]:
    """按退出码分类运行时崩溃."""
    unsigned = rc & 0xFFFFFFFF
    return _CRASH_CODES.get(unsigned)


def asan_ground_truth(binary_path: str, sample_name: str = "") -> dict:
    """ASan 编译副本 + 触发输入 → 运行时堆错误事实源."""
    result = {"tool": "asan_truth", "sample": sample_name,
              "available": False, "findings": [], "elapsed_ms": 0.0,
              "error": ""}
    try:
        gcc = subprocess.run(["gcc", "--version"], capture_output=True,
                             timeout=5)
        if gcc.returncode != 0:
            result["error"] = "gcc unavailable"
            return result
    except (FileNotFoundError, subprocess.TimeoutExpired):
        result["error"] = "gcc unavailable"
        return result

    src = os.path.join(os.path.dirname(binary_path), "src", "vuln.c")
    if not os.path.isfile(src):
        result["error"] = "source not found"
        return result

    t0 = time.perf_counter()
    tmpdir = tempfile.mkdtemp(prefix="asan_truth_")
    asan_exe = os.path.join(tmpdir, "asan_vuln.exe")
    asan_ok = True
    try:
        r = subprocess.run(
            ["gcc", "-fsanitize=address", "-O0", "-g", "-no-pie", "-o",
             asan_exe, src],
            capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            asan_ok = False
    except (FileNotFoundError, subprocess.TimeoutExpired):
        asan_ok = False

    if asan_ok:
        result["available"] = True
        for args in _TRIGGER_INPUTS:
            try:
                run = subprocess.run([asan_exe] + args, capture_output=True,
                                     text=True, errors="ignore", timeout=15)
            except subprocess.TimeoutExpired:
                continue
            except Exception:
                continue
            out = (run.stdout or "") + (run.stderr or "")
            m = _ASAN_RE.search(out)
            if m:
                loc = _ASAN_LOC_RE.search(out)
                result["findings"].append({
                    "type": "runtime_memory_error",
                    "subtype": m.group(1),
                    "func": loc.group(1) if loc else "?",
                    "args": str(args),
                    "confidence": 1.0,
                })
    else:
        # ASan 运行时缺失 (MinGW 无 libasan) → 崩溃分类回退.
        # 确定性崩溃 (堆损坏/访问违规) 是运行时事实的诚实代理.
        # 回退直接运行原始二进制 — ASan 副本编译失败不可用.
        result["error"] = "asan unavailable, crash-classification fallback"
        result["available"] = True
        for args in _TRIGGER_INPUTS:
            try:
                run = subprocess.run([binary_path] + args,
                                     capture_output=True, text=True,
                                     errors="ignore", timeout=15)
            except subprocess.TimeoutExpired:
                continue
            except Exception:
                continue
            crash = _classify_crash(run.returncode)
            if crash:
                result["findings"].append({
                    "type": "runtime_memory_error",
                    "subtype": crash,
                    "args": str(args),
                    "confidence": 1.0,
                })
    result["elapsed_ms"] = (time.perf_counter() - t0) * 1000
    shutil.rmtree(tmpdir, ignore_errors=True)
    return result


def run_qemu_scan(binary_path: str, sample_name: str = "",
                  cache: bool = True) -> dict:
    """对单个二进制运行 QEMU 追踪分析."""
    if cache and binary_path in _RESULTS_CACHE:
        return _RESULTS_CACHE[binary_path]
    qemu_bin = _check_qemu()
    result = {"tool": "qemu", "sample": sample_name,
              "available": qemu_bin is not None, "findings": [],
              "elapsed_ms": 0.0, "error": ""}
    if not qemu_bin:
        result["error"] = "qemu-user not found"
        if cache:
            _RESULTS_CACHE[binary_path] = result
        return result
    t0 = time.perf_counter()
    try:
        result["findings"] = _trace_with_qemu(binary_path, qemu_bin)
    except Exception as e:
        result["error"] = str(e)
    result["elapsed_ms"] = (time.perf_counter() - t0) * 1000
    if cache:
        _RESULTS_CACHE[binary_path] = result
    return result


def main():
    import argparse
    ap = argparse.ArgumentParser(description="QEMU heap tracer + ASan truth")
    ap.add_argument("binary", help="Path to binary")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--asan", action="store_true", help="仅 ASan ground truth")
    args = ap.parse_args()

    if args.asan:
        result = asan_ground_truth(args.binary, Path(args.binary).stem)
    else:
        result = run_qemu_scan(args.binary, Path(args.binary).stem)
        truth = asan_ground_truth(args.binary, Path(args.binary).stem)
        result["asan_truth"] = truth
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"QEMU Tracer — {args.binary}")
        print(f"  Available: {result['available']}")
        print(f"  Findings:  {len(result['findings'])}")
        print(f"  Time:      {result['elapsed_ms']:.1f}ms")
        if args.asan:
            print(f"  ASan truth: "
                  f"{len(result.get('findings', []))} runtime error(s)")


if __name__ == "__main__":
    main()
