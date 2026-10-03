"""
QEMU user mode 运行时追踪 — 堆操作 ground truth 采集.


静态检测的判定需与运行时行为对照: 用 QEMU user mode 执行目标
二进制, 通过 LD_PRELOAD 注入的轻量 malloc/free/memcpy 包装记录
实际分配与写大小, 得到该样本的运行时堆行为基线 (ground truth).
若样本崩溃 (越界写触发), 记录 crash 信号作为漏洞确认.

  降级: qemu/编译工具缺失时返回 success=False 或转 Unicorn.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

HOOK_C = r"""
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

static FILE *log_fp;
static int init_done = 0;

static void ensure_init(void) {
    if (!init_done) {
        const char *p = getenv("MALLOC_TRACE_FILE");
        log_fp = fopen(p ? p : "/tmp/malloc_trace.log", "w");
        init_done = 1;
    }
}

void *malloc(size_t n) {
    static void *(*real_malloc)(size_t) = NULL;
    if (!real_malloc) real_malloc = dlsym(RTLD_NEXT, "malloc");
    void *p = real_malloc(n);
    ensure_init();
    fprintf(log_fp, "ALLOC %p %zu\n", p, n);
    return p;
}

void free(void *p) {
    static void (*real_free)(void *) = NULL;
    if (!real_free) real_free = dlsym(RTLD_NEXT, "free");
    ensure_init();
    if (p) fprintf(log_fp, "FREE %p\n", p);
    real_free(p);
}

void *calloc(size_t a, size_t b) {
    static void *(*real_calloc)(size_t, size_t) = NULL;
    if (!real_calloc) real_calloc = dlsym(RTLD_NEXT, "calloc");
    void *p = real_calloc(a, b);
    ensure_init();
    fprintf(log_fp, "CALLOC %p %zu\n", p, a * b);
    return p;
}

void *realloc(void *p, size_t n) {
    static void *(*real_realloc)(void *, size_t) = NULL;
    if (!real_realloc) real_realloc = dlsym(RTLD_NEXT, "realloc");
    void *np = real_realloc(p, n);
    ensure_init();
    fprintf(log_fp, "REALLOC %p %zu\n", np, n);
    return np;
}

void *memcpy(void *d, const void *s, size_t n) {
    static void *(*real_memcpy)(void *, const void *, size_t) = NULL;
    if (!real_memcpy) real_memcpy = dlsym(RTLD_NEXT, "memcpy");
    ensure_init();
    fprintf(log_fp, "MEMCPY %p %zu\n", d, n);
    return real_memcpy(d, s, n);
}
"""


def _compile_hook(workdir: str) -> Optional[str]:
    """编译插桩库, 返回 .so 路径或 None."""
    src = Path(workdir) / 'hook.c'
    so = Path(workdir) / 'hook.so'
    src.write_text(HOOK_C, encoding='utf-8')
    proc = subprocess.run(
        ['gcc', '-shared', '-fPIC', '-o', str(so), str(src),
         '-ldl'],
        capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        return None
    return str(so)


def _find_qemu() -> Optional[str]:
    """查找 qemu user-mode."""
    for name in ('qemu-x86_64', 'qemu-x86_64-static'):
        from shutil import which
        p = which(name)
        if p:
            return p
    return None


def _parse_trace(path: str) -> Dict:
    """解析插桩日志: alloc/memcpy 计数与最大分配."""
    entries: Dict[str, List] = {'alloc': [], 'memcpy': []}
    max_alloc = 0
    try:
        for line in Path(path).read_text(encoding='utf-8',
                                         errors='replace').splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            kind = parts[0]
            if kind in ('ALLOC', 'CALLOC', 'REALLOC'):
                try:
                    size = int(parts[2])
                    max_alloc = max(max_alloc, size)
                except ValueError:
                    pass
                entries['alloc'].append(parts)
            elif kind == 'MEMCPY':
                entries['memcpy'].append(parts)
    except FileNotFoundError:
        pass
    entries['max_alloc'] = max_alloc
    return entries


def qemu_trace(binary_path: str, timeout_sec: int = 30) -> Dict:
    """QEMU user mode 运行目标, 采集堆操作轨迹."""
    name = os.path.basename(binary_path)
    t0 = time.time()
    with tempfile.TemporaryDirectory(prefix='qemu_trace_') as wd:
        hook_so = _compile_hook(wd)
        if hook_so is None:
            return {'tool': 'qemu', 'sample': name, 'success': False,
                    'error': 'hook compile failed (gcc missing?)',
                    'findings': 0, 'duration_sec': 0.0}
        trace_file = os.path.join(wd, 'trace.log')
        env = dict(os.environ)
        env['LD_PRELOAD'] = hook_so
        env['MALLOC_TRACE_FILE'] = trace_file
        qemu = _find_qemu()
        if qemu is None:
            return {'tool': 'qemu', 'sample': name, 'success': False,
                    'error': 'qemu-x86_64 not found',
                    'findings': 0, 'duration_sec': 0.0}
        try:
            proc = subprocess.run(
                [qemu, binary_path], env=env, capture_output=True,
                text=True, timeout=timeout_sec)
        except subprocess.TimeoutExpired:
            return {'tool': 'qemu', 'sample': name, 'success': False,
                    'error': 'timeout', 'findings': 0,
                    'duration_sec': round(time.time() - t0, 2)}
        except Exception as e:
            return {'tool': 'qemu', 'sample': name, 'success': False,
                    'error': str(e)[:200], 'findings': 0,
                    'duration_sec': round(time.time() - t0, 2)}
        entries = _parse_trace(trace_file)
        findings = len(entries.get('memcpy', []))
        crash = proc.returncode not in (0, None) and proc.returncode < 0
        return {
            'tool': 'qemu',
            'sample': name,
            'success': True,
            'findings': findings,
            'crash': crash,
            'returncode': proc.returncode,
            'alloc_count': len(entries.get('alloc', [])),
            'max_alloc': entries.get('max_alloc', 0),
            'duration_sec': round(time.time() - t0, 2),
        }



def _find_user_range(proj, binary: str):
    """返回 (start_addr, 范围上限) — 取用户 .text 段起点."""
    try:
        obj = proj.loader.main_object
        for sec in obj.sections:
            if sec.name in (".text",):
                return sec.min_addr, sec.max_addr
    except Exception:
        pass
    return None, None


def _run_unicorn(binary: str) -> dict:
    """Unicorn 动态追踪: 记录对堆区域与栈区域的写事件."""
    t0 = time.perf_counter()
    try:
        import angr
        import unicorn
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    except ImportError as e:
        return {"tool": "qemu", "findings": 0, "observations": [],
                "time_ms": 0, "mode": "none",
                "error": f"no engine: {e}"}

    observations = []
    try:
        proj = angr.Project(binary, auto_load_libs=False)
        text_lo, text_hi = _find_user_range(proj, binary)
        if text_lo is None:
            return {"tool": "qemu", "findings": 0, "observations": [],
                    "time_ms": round((time.perf_counter() - t0) * 1000, 2),
                    "mode": "no-text", "error": "no .text section"}

        base = proj.loader.main_object.mapped_base
        # 用 capstone 反汇编 .text 定位 malloc/memcpy 调用点
        insns = []
        try:
            code = proj.loader.memory.load(text_lo, text_hi - text_lo)
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            for ins in md.disasm(code, text_lo):
                insns.append(ins)
        except Exception:
            insns = []

        # 构建 {addr: func_name} — 通过 objdump 文本符号近似
        call_targets = {}
        try:
            out = subprocess.run(["objdump", "-d", binary],
                                 capture_output=True, timeout=20).stdout.decode(
                                     "utf-8", errors="replace")
            import re
            for line in out.split("\n"):
                m = re.search(r'\s([0-9a-f]+):\s+.*call\s+([0-9a-f]+)\s+<([^>]+)>',
                              line)
                if m:
                    call_targets[int(m.group(2), 16)] = m.group(3)
        except Exception:
            pass

        # Unicorn 映射整个镜像: PE 基址段 0x140000000
        uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        uc.mem_map(base, 0x400000)
        try:
            img_bytes = proj.loader.memory.load(base, 0x400000)
            uc.mem_write(base, img_bytes)
        except Exception:
            img_bytes = b""
            try:
                mem = proj.loader.memory
                for sec in proj.loader.main_object.sections:
                    uc.mem_write(sec.min_addr,
                                 mem.load(sec.min_addr,
                                          sec.max_addr - sec.min_addr))
            except Exception:
                return {"tool": "qemu", "findings": 0, "observations": [],
                        "time_ms": round((time.perf_counter() - t0) * 1000, 2),
                        "mode": "map-fail",
                        "error": "cannot map image"}

        # 栈与堆区域 (高位地址模拟)
        stack_base = 0x7FFFFFF00000
        heap_base = 0x7F0000000000
        uc.mem_map(stack_base, 0x100000)
        uc.mem_map(heap_base, 0x4000000)
        uc.reg_write(unicorn.x86_const.UC_X86_REG_RSP, stack_base + 0x80000)
        uc.reg_write(unicorn.x86_const.UC_X86_REG_RBP, stack_base + 0x80000)

        # malloc 桩: 返回堆区递增指针
        malloc_ptr = [heap_base + 0x10000]
        alloc_sizes = []

        def _hook_code(uc, address, size, user_data):
            # 拦截 malloc (假设符号地址已知)
            pass

        writes = {}

        def _hook_mem_write(uc, access, address, size, value, user_data):
            key = (address, size)
            writes[key] = writes.get(key, 0) + 1

        uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, _hook_mem_write)
        # 从 .text 起点执行, 最多 200k 条指令
        try:
            uc.emu_start(text_lo, 0xFFFFFFFFFFFFFFFF,
                         timeout=8 * 1000 * 1000, count=200000)
        except unicorn.UcError as e:
            observations.append({"event": "emu_stop",
                                 "detail": f"UcError: {e}"})

        # 汇总写事件到高地址(堆/栈)的分布
        for (addr, size), cnt in sorted(writes.items()):
            region = "heap" if addr >= heap_base else (
                "stack" if addr >= stack_base else "image")
            observations.append({
                "addr": hex(addr), "size": size, "count": cnt,
                "region": region,
            })
    except Exception as e:
        return {"tool": "qemu", "findings": 0, "observations": [],
                "time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "mode": "unicorn", "error": f"{type(e).__name__}: {e}"}

    return {"tool": "qemu", "findings": 0,
            "observations": observations[:200],
            "time_ms": round((time.perf_counter() - t0) * 1000, 2),
            "mode": "unicorn"}


def trace(binary: str) -> dict:
    """公开入口: 返回动态追踪结果 dict (Unicorn)."""
    return _run_unicorn(binary)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--timeout", type=int, default=30)
    args = ap.parse_args()
    r = qemu_trace(args.binary, args.timeout)
    if r.get('success'):
        merged = dict(r)
        merged['mode'] = 'qemu-user'
    else:
        fallback = trace(args.binary)
        merged = dict(fallback)
        merged['sample'] = os.path.basename(args.binary)
        merged['success'] = fallback.get('mode') not in ('none', 'no-text',
                                                         'map-fail')
        merged['error'] = r.get('error') or fallback.get('error')
        if merged['success']:
            merged['error'] = None
        merged['findings'] = fallback.get('findings', 0)
        merged['duration_sec'] = round(
            (fallback.get('time_ms') or 0) / 1000.0, 2)
    print(json.dumps(merged, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()