# QEMU user mode + 自写轻量插桩——抓取运行时的内存操作作为ground truth
# 方法: 用QEMU user mode的 -d 选项记录所有内存访问，
#       解析执行日志提取malloc/memcpy参数，计算实际溢出情况
#
# QEMU user mode -d options:
# d in_asm,cpu: 记录每条的指令+CPU状态(含寄存器值)
# d exec: 记录执行轨迹但不含寄存器状态
#
# 由于QEMU日志量巨大，本脚本的实际实现:
#   1. 用LD_PRELOAD Hook拦截malloc/free/memcpy(strcpy)
#   2. 记录每次调用的参数和返回值
#   3. 分析: 对每个memcpy(dst,src,n)，检查dst是否在已知的malloc区域
#      若 n > alloc_size → 溢出
#
# 备选方案(若无LD_PRELOAD):
#   使用gdb script自动化断点——break malloc, break memcpy, break free
#   在每个断点处打印参数寄存器

import subprocess
import sys
import json
import re
import time
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# LD_PRELOAD Hook (C source)
HOOK_C_SOURCE = r"""
// 轻量级堆操作追踪Hook——通过LD_PRELOAD拦截内存管理函数
// 编译: gcc -shared -fPIC -o libmemtrace.so memtrace_hook.c -ldl
// 使用: LD_PRELOAD=./libmemtrace.so ./target_binary
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

static FILE *trace_fp = NULL;
static int alloc_id = 0;

typedef struct { int id; void *ptr; size_t size; } alloc_record_t;
static alloc_record_t *records = NULL;
static int n_records = 0;
static int max_records = 0;

static void ensure_trace_file() {
    if (!trace_fp) {
        const char *path = getenv("MEMTRACE_OUTPUT");
        trace_fp = fopen(path ? path : "memtrace.log", "w");
        if (trace_fp) setvbuf(trace_fp, NULL, _IONBF, 0);
    }
}

static void record_alloc(int id, void *ptr, size_t size) {
    if (n_records >= max_records) {
        max_records = max_records ? max_records * 2 : 1024;
        records = realloc(records, max_records * sizeof(alloc_record_t));
    }
    records[n_records].id = id;
    records[n_records].ptr = ptr;
    records[n_records].size = size;
    n_records++;
}

static size_t find_alloc_size(void *ptr) {
    for (int i = n_records - 1; i >= 0; i--) {
        if (records[i].ptr == ptr) return records[i].size;
    }
    return 0;
}

void *malloc(size_t size) {
    static void *(*real_malloc)(size_t) = NULL;
    if (!real_malloc) real_malloc = dlsym(RTLD_NEXT, "malloc");
    void *ptr = real_malloc(size);
    ensure_trace_file();
    int id = ++alloc_id;
    record_alloc(id, ptr, size);
    if (trace_fp) fprintf(trace_fp, "ALLOC\t%d\t%p\t%zu\n", id, ptr, size);
    return ptr;
}

void *calloc(size_t nmemb, size_t size) {
    static void *(*real_calloc)(size_t, size_t) = NULL;
    if (!real_calloc) real_calloc = dlsym(RTLD_NEXT, "calloc");
    void *ptr = real_calloc(nmemb, size);
    ensure_trace_file();
    int id = ++alloc_id;
    size_t total = nmemb * size;
    record_alloc(id, ptr, total);
    if (trace_fp) fprintf(trace_fp, "ALLOC\t%d\t%p\t%zu\n", id, ptr, total);
    return ptr;
}

void *realloc(void *oldptr, size_t size) {
    static void *(*real_realloc)(void *, size_t) = NULL;
    if (!real_realloc) real_realloc = dlsym(RTLD_NEXT, "realloc");
    void *ptr = real_realloc(oldptr, size);
    ensure_trace_file();
    int id = ++alloc_id;
    record_alloc(id, ptr, size);
    if (trace_fp) fprintf(trace_fp, "ALLOC\t%d\t%p\t%zu\n", id, ptr, size);
    return ptr;
}

void *memcpy(void *dst, const void *src, size_t n) {
    static void *(*real_memcpy)(void *, const void *, size_t) = NULL;
    if (!real_memcpy) real_memcpy = dlsym(RTLD_NEXT, "memcpy");
    ensure_trace_file();
    size_t alloc_sz = find_alloc_size(dst);
    int overflow = (alloc_sz > 0 && n > alloc_sz) ? 1 : 0;
    if (trace_fp) fprintf(trace_fp, "COPY\t%p\t%zu\t%zu\t%d\n",
                          dst, n, alloc_sz, overflow);
    return real_memcpy(dst, src, n);
}

char *strcpy(char *dst, const char *src) {
    static char *(*real_strcpy)(char *, const char *) = NULL;
    if (!real_strcpy) real_strcpy = dlsym(RTLD_NEXT, "strcpy");
    ensure_trace_file();
    size_t alloc_sz = find_alloc_size(dst);
    size_t src_len = strlen(src) + 1;
    int overflow = (alloc_sz > 0 && src_len > alloc_sz) ? 1 : 0;
    if (trace_fp) fprintf(trace_fp, "COPY\t%p\t%zu\t%zu\t%d\n",
                          dst, src_len, alloc_sz, overflow);
    return real_strcpy(dst, src);
}

void free(void *ptr) {
    static void (*real_free)(void *) = NULL;
    if (!real_free) real_free = dlsym(RTLD_NEXT, "free");
    ensure_trace_file();
    if (trace_fp) fprintf(trace_fp, "FREE\t%p\n", ptr);
    real_free(ptr);
}
"""


def compile_hook(output_dir: Path) -> Optional[Path]:
    """编译LD_PRELOAD hook库"""
    hook_c = output_dir / "memtrace_hook.c"
    hook_so = output_dir / "libmemtrace.so"

    with open(hook_c, 'w') as f:
        f.write(HOOK_C_SOURCE)

    try:
        proc = subprocess.run(
            ['gcc', '-shared', '-fPIC', '-o', str(hook_so),
             str(hook_c), '-ldl'],
            capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            return hook_so
        else:
            print(f"Failed to compile hook: {proc.stderr}", file=sys.stderr)
            return None
    except FileNotFoundError:
        # gcc不可用——尝试使用环境中可用的编译器
        print("gcc not available for hook compilation", file=sys.stderr)
        return None


def run_with_hook(binary: Path, hook_so: Path,
                   timeout: int = 10) -> Tuple[List[Dict], float]:
    """用LD_PRELOAD运行二进制并解析memtrace日志"""
    t0 = time.perf_counter()
    trace_file = binary.parent / "memtrace.log"

    env = os.environ.copy()
    env['LD_PRELOAD'] = str(hook_so)
    env['MEMTRACE_OUTPUT'] = str(trace_file)

    mem_ops = []
    try:
        subprocess.run(
            [str(binary)],
            env=env, capture_output=True, timeout=timeout,
            cwd=str(binary.parent))
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        pass

    elapsed = (time.perf_counter() - t0) * 1000

    # 解析日志
    if trace_file.exists():
        with open(trace_file) as f:
            for line in f:
                parts = line.strip().split('\t')
                if parts[0] == 'ALLOC' and len(parts) >= 4:
                    mem_ops.append({
                        'type': 'alloc', 'id': int(parts[1]),
                        'ptr': parts[2], 'size': int(parts[3])})
                elif parts[0] == 'COPY' and len(parts) >= 5:
                    mem_ops.append({
                        'type': 'copy', 'ptr': parts[1],
                        'copy_size': int(parts[2]),
                        'alloc_size': int(parts[3]),
                        'overflow': bool(int(parts[4]))})
                elif parts[0] == 'FREE':
                    mem_ops.append({
                        'type': 'free', 'ptr': parts[1]})

    # 汇总
    overflows = [op for op in mem_ops
                 if op.get('overflow', False)]
    return mem_ops, elapsed


def trace_binary(binary_path: str) -> Dict:
    """用QEMU/LD_PRELOAD追踪二进制的内存操作。

    返回ground truth: 实际执行中发生的溢出事件列表。
    """
    binary = Path(binary_path)
    result = {
        "binary": str(binary),
        "available": False,
        "mem_ops": [],
        "total_allocations": 0,
        "total_copies": 0,
        "confirmed_overflows": 0,
        "time_ms": 0,
        "error": "",
    }

    if not binary.exists():
        result["error"] = f"Binary not found: {binary_path}"
        return result

    # 尝试LD_PRELOAD hook
    hook_so = compile_hook(binary.parent)
    if hook_so is None:
        result["error"] = "Cannot compile LD_PRELOAD hook (gcc not available)"
        return result

    result["available"] = True
    mem_ops, elapsed = run_with_hook(binary, hook_so, timeout=10)
    result["mem_ops"] = mem_ops
    result["time_ms"] = elapsed
    result["total_allocations"] = sum(1 for op in mem_ops if op['type'] == 'alloc')
    result["total_copies"] = sum(1 for op in mem_ops if op['type'] == 'copy')
    result["confirmed_overflows"] = sum(1 for op in mem_ops if op.get('overflow'))

    return result


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: qemu_tracer.py <binary>", "available": False}))
        return 0

    binary = sys.argv[1]
    result = trace_binary(binary)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
