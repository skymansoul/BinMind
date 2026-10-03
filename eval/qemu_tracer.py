#!/usr/bin/env python3
"""
QEMU user-mode tracer — 堆操作动态追踪 + objdump回退.

三种模式:
1. QEMU user-mode: 通过 -d in_asm 追踪指令, 检测危险函数调用
2. LD_PRELOAD hook: 注入malloc/free/realloc拦截库, 记录分配大小与写入偏移
3. objdump回退: 无QEMU时解析反汇编, 统计危险函数调用频次
"""
from __future__ import annotations
import json, os, subprocess, sys, time
from pathlib import Path
from typing import Dict, List, Optional

DANGER_FUNCS = frozenset([
    'malloc', 'calloc', 'realloc', 'free',
    'memcpy', 'memmove', 'memset',
    'strcpy', 'strcat', 'sprintf', 'gets', 'scanf', 'printf',
])

# LD_PRELOAD拦截库源码（编译后注入）
_HOOK_C = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static FILE*_log;
static void _open_log(void){
    const char*p=getenv("HOOK_LOG");
    if(p)_log=fopen(p,"w");
    if(!_log)_log=stderr;
}
__attribute__((constructor))static void _init(void){_open_log();}
void*malloc(size_t s){void*(*r)(size_t)=dlsym(RTLD_NEXT,"malloc");void*p=r(s);
    if(_log)fprintf(_log,"MALLOC %p %zu\n",p,s);return p;}
void free(void*p){void(*r)(void*)=dlsym(RTLD_NEXT,"free");
    if(_log)fprintf(_log,"FREE %p\n",p);r(p);}
void*realloc(void*p,size_t s){void*(*r)(void*,size_t)=dlsym(RTLD_NEXT,"realloc");
    void*q=r(p,s);if(_log)fprintf(_log,"REALLOC %p->%p %zu\n",p,q,s);return q;}
"""

def trace_qemu(binary_path: str, sample_name: str,
               timeout: int = 10) -> Dict:
    """QEMU user-mode追踪: -d in_asm统计危险函数调用."""
    try:
        t0 = time.perf_counter()
        r = subprocess.run(
            ["qemu-x86_64", "-d", "in_asm", binary_path],
            capture_output=True, text=True, timeout=timeout)
        dt = round(time.perf_counter() - t0, 3)
        calls = r.stdout.count("call") + r.stdout.count("callq")
        return {"tool": "QEMU-user", "sample": sample_name,
                "calls": calls, "duration_s": dt, "error": ""}
    except FileNotFoundError:
        return {"tool": "QEMU-user", "sample": sample_name,
                "calls": 0, "duration_s": 0,
                "error": "qemu-x86_64 not found"}
    except subprocess.TimeoutExpired:
        return {"tool": "QEMU-user", "sample": sample_name,
                "calls": 0, "duration_s": timeout, "error": "timeout"}


def trace_hook(binary_path: str, sample_name: str,
               timeout: int = 10) -> Dict:
    """LD_PRELOAD hook追踪: 编译拦截库并注入, 记录alloc/free序列."""
    hook_so = _compile_hook()
    if hook_so is None:
        return {"tool": "QEMU-hook", "sample": sample_name,
                "calls": 0, "duration_s": 0, "error": "hook compile failed"}
    log_path = os.path.join(
        os.path.dirname(binary_path), "hook_log.txt")
    env = os.environ.copy()
    env["LD_PRELOAD"] = hook_so
    env["HOOK_LOG"] = log_path
    try:
        t0 = time.perf_counter()
        subprocess.run([binary_path], capture_output=True, text=True,
                       timeout=timeout, env=env)
        dt = round(time.perf_counter() - t0, 3)
        allocs, frees = _parse_hook_log(log_path)
        return {"tool": "QEMU-hook", "sample": sample_name,
                "allocs": allocs, "frees": frees,
                "duration_s": dt, "error": ""}
    except FileNotFoundError:
        return {"tool": "QEMU-hook", "sample": sample_name,
                "allocs": 0, "frees": 0, "duration_s": 0,
                "error": "binary not found"}
    except subprocess.TimeoutExpired:
        return {"tool": "QEMU-hook", "sample": sample_name,
                "allocs": 0, "frees": 0, "duration_s": timeout,
                "error": "timeout"}
    finally:
        if os.path.isfile(log_path):
            os.remove(log_path)


def trace_objdump(binary_path: str, sample_name: str) -> Dict:
    """objdump回退: 解析反汇编统计危险函数调用频次."""
    t0 = time.perf_counter()
    try:
        r = subprocess.run(
            ["objdump", "-d", binary_path],
            capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return {"tool": "objdump", "sample": sample_name,
                    "calls": 0, "duration_s": 0,
                    "error": f"objdump exit {r.returncode}"}
    except FileNotFoundError:
        return {"tool": "objdump", "sample": sample_name,
                "calls": 0, "duration_s": 0,
                "error": "objdump not found"}
    except subprocess.TimeoutExpired:
        return {"tool": "objdump", "sample": sample_name,
                "calls": 0, "duration_s": 30, "error": "timeout"}
    calls = 0
    for line in r.stdout.splitlines():
        for fn in DANGER_FUNCS:
            if fn in line and "call" in line:
                calls += 1
                break
    dt = round(time.perf_counter() - t0, 3)
    return {"tool": "objdump", "sample": sample_name,
            "calls": calls, "duration_s": dt, "error": ""}


def trace_auto(binary_path: str, sample_name: str,
               timeout: int = 10) -> Dict:
    """自动选择可用模式: QEMU → LD_PRELOAD → objdump."""
    r = trace_qemu(binary_path, sample_name, timeout)
    if not r["error"]:
        return r
    r = trace_hook(binary_path, sample_name, timeout)
    if not r["error"]:
        return r
    return trace_objdump(binary_path, sample_name)


def trace_batch(binary_paths: List[str],
                timeout: int = 10) -> List[Dict]:
    """批量追踪多个二进制文件."""
    results = []
    for bp in binary_paths:
        name = os.path.basename(bp)
        results.append(trace_auto(bp, name, timeout))
    return results


def _compile_hook() -> Optional[str]:
    """编译LD_PRELOAD拦截库, 返回.so路径; 失败返回None."""
    out_dir = os.path.join(os.path.dirname(__file__), ".cache")
    os.makedirs(out_dir, exist_ok=True)
    so_path = os.path.join(out_dir, "heap_hook.so")
    c_path = os.path.join(out_dir, "heap_hook.c")
    if os.path.isfile(so_path):
        return so_path
    with open(c_path, "w", encoding="utf-8") as f:
        f.write(_HOOK_C)
    try:
        gcc = os.environ.get("GCC", "gcc")
        r = subprocess.run(
            [gcc, "-shared", "-fPIC", "-o", so_path, c_path, "-ldl"],
            capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return so_path
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _parse_hook_log(log_path: str) -> tuple:
    """解析hook日志, 返回(alloc次数, free次数)."""
    allocs, frees = 0, 0
    try:
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                if line.startswith("MALLOC") or line.startswith("REALLOC"):
                    allocs += 1
                elif line.startswith("FREE"):
                    frees += 1
    except (FileNotFoundError, OSError):
        pass
    return allocs, frees


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: qemu_tracer.py <binary> [--batch f1 f2 ...]")
        sys.exit(1)
    if "--batch" in sys.argv:
        idx = sys.argv.index("--batch")
        paths = sys.argv[idx + 1:]
        out = trace_batch(paths)
    else:
        out = trace_auto(sys.argv[1], os.path.basename(sys.argv[1]))
    print(json.dumps(out, indent=2))
