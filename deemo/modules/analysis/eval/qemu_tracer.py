# QEMU user mode tracer — 抓取运行时内存操作作为 ground truth
# 用于统计对比工具的误报/漏报

import subprocess
import sys
import time
import json
import shutil
import tempfile
import os

_SHIM_SOURCE = r"""
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define _GNU_SOURCE
#include <dlfcn.h>

static void (*real_malloc)(size_t);
static void (*real_free)(void *);

void *malloc(size_t sz) {
    static int once = 0;
    if (!once) { real_malloc = dlsym(RTLD_NEXT, "malloc"); once = 1; }
    void *p = real_malloc(sz);
    fprintf(stderr, "HOOK alloc %p %zu\n", p, sz);
    return p;
}
void free(void *p) {
    static int once = 0;
    if (!once) { real_free = dlsym(RTLD_NEXT, "free"); once = 1; }
    if (p) fprintf(stderr, "HOOK free %p\n", p);
    real_free(p);
}
void *memcpy(void *d, const void *s, size_t n) {
    static void *(*r)(void*,const void*,size_t);
    if (!r) r = dlsym(RTLD_NEXT, "memcpy");
    fprintf(stderr, "HOOK write %p %zu\n", d, n);
    return r(d, s, n);
}
void *memset(void *d, int c, size_t n) {
    static void *(*r)(void*,int,size_t);
    if (!r) r = dlsym(RTLD_NEXT, "memset");
    fprintf(stderr, "HOOK write %p %zu\n", d, n);
    return r(d, c, n);
}
"""


def _build_shim(shim_path: str) -> bool:
    """编译 LD_PRELOAD shim 为 .so."""
    cc = shutil.which("gcc")
    if not cc:
        return False
    r = subprocess.run(
        [cc, "-shared", "-fPIC", "-ldl", "-o", shim_path, "-x", "c", "-"],
        input=_SHIM_SOURCE, capture_output=True, text=True, timeout=30)
    return r.returncode == 0 and os.path.exists(shim_path)


def trace_binary(binary_path: str, input_data: str = "") -> dict:
    """QEMU user mode 追踪二进制运行时内存操作.

    返回: {crashed, allocations, writes, oob_writes, time_ms, error}
    oob_writes: 检测到写入超过分配大小的次数 (ground truth).
    """
    t0 = time.perf_counter()
    result = {"tool": "QEMU", "binary": binary_path, "crashed": False,
              "allocations": [], "writes": [], "oob_writes": 0,
              "signals": [], "time_ms": 0, "error": ""}
    qemu = shutil.which("qemu-x86_64") or shutil.which("qemu-x86_64-static")
    if not qemu:
        result["error"] = "qemu-x86_64 not found in PATH"
        result["time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        return result

    # 优先插桩模式; 编译失败则退回 strace
    shim_dir = tempfile.mkdtemp(prefix="qemu_shim_")
    shim_path = os.path.join(shim_dir, "hook.so")
    use_shim = _build_shim(shim_path)

    try:
        if use_shim:
            cmd = [qemu, "-E", "LD_PRELOAD=" + shim_path,
                   "-E", "LD_LIBRARY_PATH=/usr/lib", binary_path]
        else:
            cmd = [qemu, "-strace", "-E", "LD_LIBRARY_PATH=/usr/lib",
                   binary_path]
        r = subprocess.run(cmd, input=input_data, capture_output=True,
                           text=True, timeout=15)
        stderr = r.stderr or ""
        result["crashed"] = any(s in stderr for s in
                                ("SIGSEGV", "SIGABRT", "SIGILL", "SIGBUS"))
        for sig in ("SIGSEGV", "SIGABRT", "SIGILL", "SIGBUS", "SIGFPE"):
            if sig in stderr:
                result["signals"].append(sig)

        if use_shim:
            _parse_hooks(stderr, result)
        else:
            result["syscalls"] = len([l for l in stderr.split("\n") if "=" in l])
    except subprocess.TimeoutExpired:
        result["error"] = "timeout (15s)"
    except Exception as e:
        result["error"] = str(e)[:200]
    finally:
        shutil.rmtree(shim_dir, ignore_errors=True)

    result["time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return result


def _parse_hooks(stderr: str, result: dict):
    """解析 shim 输出, 统计分配/写入/越界."""
    allocs = {}  # ptr -> size
    writes = []
    for line in stderr.split("\n"):
        parts = line.split()
        if len(parts) < 3 or parts[0] != "HOOK":
            continue
        kind = parts[1]
        if kind == "alloc" and len(parts) >= 4:
            try:
                ptr = int(parts[2], 16)
                size = int(parts[3])
                allocs[ptr] = size
                result["allocations"].append({"ptr": ptr, "size": size})
            except ValueError:
                pass
        elif kind == "free" and len(parts) >= 3:
            try:
                ptr = int(parts[2], 16)
                allocs.pop(ptr, None)
            except ValueError:
                pass
        elif kind == "write" and len(parts) >= 4:
            try:
                ptr = int(parts[2], 16)
                size = int(parts[3])
                writes.append({"ptr": ptr, "size": size})
            except ValueError:
                pass

    # 越界判定: 写入地址落在某分配范围内但 size 超出该块
    result["writes"] = writes
    for w in writes:
        for aptr, asz in allocs.items():
            if aptr <= w["ptr"] < aptr + asz and w["ptr"] + w["size"] > aptr + asz:
                result["oob_writes"] += 1
                break


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("binary")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()
    r = trace_binary(args.binary)
    if args.json:
        print(json.dumps(r, indent=2, default=str))
    else:
        print(f"QEMU: crashed={r['crashed']} "
              f"allocs={len(r['allocations'])} "
              f"oob_writes={r['oob_writes']} "
              f"{r.get('time_ms', 0)}ms {r.get('error', '')}")
