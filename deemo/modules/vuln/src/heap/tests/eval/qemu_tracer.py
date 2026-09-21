"""堆区间证据消歧对比实验 — QEMU user-mode 动态追踪.

用 qemu-x86_64 -trace 追踪 heap 操作 (malloc/free/memcpy),
收集运行时分配大小和访问大小, 对比静态分析结果.

依赖: qemu-x86_64 (MSYS2: pacman -S qemu)

用法:
  python qemu_tracer.py --sample cve_2021_3156

创建: 2024-09-27
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional


BUILD_ROOT = Path(__file__).resolve().parent.parent / "build"
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
QEMU = "qemu-x86_64"


def trace_with_qemu(exe_path: Path, timeout: int = 10) -> dict:
    """用 qemu-x86_64 -strace 追踪样本执行."""
    t0 = time.perf_counter()

    try:
# strace 输出所有系统调用, 包括 brk/mmap (malloc 底层)
        result = subprocess.run(
            [QEMU, "-strace", str(exe_path)],
            capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return {'error': 'qemu-x86_64 not found. Install: pacman -S qemu', 'time_ms': 0}
    except subprocess.TimeoutExpired:
        return {'error': 'timeout', 'time_ms': timeout * 1000, 'findings': 0}

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
    output = result.stderr  # strace 输出到 stderr

    # 解析 brk 调用: brk(NULL) 获取当前 break, brk(new) 扩展/收缩堆
    brk_pattern = re.compile(r'(\d+)\s+brk\(([^)]+)\)\s*=\s*([^\s]+)')
    mmap_pattern = re.compile(r'(\d+)\s+mmap\([^)]+\)\s*=\s*(0x[0-9a-f]+)')

    brk_calls = brk_pattern.findall(output)
    mmap_calls = mmap_pattern.findall(output)

    # 从 brk 调用估算堆大小 — 简化版
    heap_extensions = []
    prev_brk = 0
    for _, brk_arg_str, ret_str in brk_calls:
        try:
            if brk_arg_str.strip() == 'NULL' or brk_arg_str.strip() == '0':
                prev_brk = int(ret_str, 16) if '0x' in ret_str else int(ret_str)
            else:
                new_brk = int(ret_str, 16) if '0x' in ret_str else int(ret_str)
                brk_val = int(brk_arg_str, 16) if '0x' in brk_arg_str else int(brk_arg_str)
                if new_brk > prev_brk:
                    heap_extensions.append(new_brk - prev_brk)
                prev_brk = new_brk
        except (ValueError, IndexError):
            continue

    # 简化判断: 若 brk 扩展超过某阈值 → 可疑
    total_heap = sum(heap_extensions)
    suspicious = any(ext > 0x100000 for ext in heap_extensions)  # > 1MB

    return {
        'brk_calls': len(brk_calls),
        'mmap_calls': len(mmap_calls),
        'heap_extensions': heap_extensions[:20],
        'total_heap_bytes': total_heap,
        'suspicious_large_heap': suspicious,
        'findings': 1 if suspicious else 0,
        'time_ms': elapsed_ms,
        'error': '',
    }


def main():
    parser = argparse.ArgumentParser(description="QEMU 动态追踪")
    parser.add_argument("--sample", type=str, default="", help="单样本名称")
    parser.add_argument("--all", action="store_true", help="全量")
    args = parser.parse_args()

    opt_dir = BUILD_ROOT / "gcc" / "O0"
    if not opt_dir.exists():
        print(f"  [ERROR] Build dir not found: {opt_dir}")
        print(f"  Run 'python compile_samples.py' first.")
        sys.exit(1)

    exes = sorted(opt_dir.glob("*.exe"))
    if args.sample:
        exes = [e for e in exes if args.sample in e.stem]
    elif not args.all:
        print("  Usage: python qemu_tracer.py --sample cve_2021_3156")
        print("  NOTE: QEMU user-mode required. Install: pacman -S qemu")
        return

    results = []
    for exe in exes:
        print(f"  QEMU tracing: {exe.stem} ...")
        r = trace_with_qemu(exe)
        r['sample'] = exe.stem
        results.append(r)
        if r.get('error'):
            print(f"    Error: {r['error']}")
        else:
            print(f"    Heap ext: {len(r['heap_extensions'])}, "
                  f"Total: {r['total_heap_bytes']} bytes, "
                  f"Time: {r['time_ms']}ms")

    out_path = RESULTS_DIR / "qemu_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n  Results: {out_path}")


if __name__ == "__main__":
    main()
