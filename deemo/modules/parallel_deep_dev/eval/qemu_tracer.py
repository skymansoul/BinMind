"""QEMU user-mode 追踪器 — 运行时内存操作作为 ground truth。

插桩方式: LD_PRELOAD 注入拦截库(自写 C), 记录 MALLOC/FREE/
MEMCPY 等事件; 解析日志把 memcpy 长度与对应分配容量比对,
得到"运行时确实发生写越界"的判定。优先经 qemu-user 运行
(支持无宿主 ABI 交叉执行), 失败则回退到原生 LD_PRELOAD 运行,
再回退到 qemu -d in_asm 调用统计。

仅支持 ELF 目标; 无 qemu/gcc 时返回 skipped。
"""

# FIXME: Windows 下 hook 需交叉编译或原生 DLL 注入, 当前仅 Linux 生效

import os
import re
import subprocess
import time
from pathlib import Path

_HOOK_C = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static FILE *g_log;
static void open_log(void){
    const char *p = getenv("HOOK_LOG");
    if (p) g_log = fopen(p, "w");
    if (!g_log) g_log = stderr;
}
__attribute__((constructor)) static void init_hook(void){ open_log(); }
void *malloc(size_t s){ void *(*r)(size_t)=dlsym(RTLD_NEXT,"malloc");
    void *p = r(s); if(g_log) fprintf(g_log,"MALLOC %p %zu\n",p,s); return p; }
void *calloc(size_t n,size_t s){ void *(*r)(size_t,size_t)=dlsym(RTLD_NEXT,"calloc");
    void *p = r(n,s); if(g_log) fprintf(g_log,"MALLOC %p %zu\n",p,n*s); return p; }
void *realloc(void *p,size_t s){ void *(*r)(void*,size_t)=dlsym(RTLD_NEXT,"realloc");
    void *q = r(p,s); if(g_log) fprintf(g_log,"REALLOC %p %p %zu\n",p,q,s); return q; }
void free(void *p){ void (*r)(void*)=dlsym(RTLD_NEXT,"free");
    if(g_log) fprintf(g_log,"FREE %p\n",p); r(p); }
void *memcpy(void *d,const void *s,size_t n){
    void *(*r)(void*,const void*,size_t)=dlsym(RTLD_NEXT,"memcpy");
    void *q = r(d,s,n); if(g_log) fprintf(g_log,"MEMCPY %p %zu\n",d,n); return q; }
void *memmove(void *d,const void *s,size_t n){
    void *(*r)(void*,const void*,size_t)=dlsym(RTLD_NEXT,"memmove");
    void *q = r(d,s,n); if(g_log) fprintf(g_log,"MEMCPY %p %zu\n",d,n); return q; }
void *memset(void *d,int c,size_t n){
    void *(*r)(void*,int,size_t)=dlsym(RTLD_NEXT,"memset");
    void *q = r(d,c,n); if(g_log) fprintf(g_log,"MEMCPY %p %zu\n",d,n); return q; }
char *strcpy(char *d,const char *s){
    char *(*r)(char*,const char*)=dlsym(RTLD_NEXT,"strcpy");
    char *q = r(d,s); if(g_log) fprintf(g_log,"MEMCPY %p %zu\n",d,strlen(s)+1); return q; }
char *strncpy(char *d,const char *s,size_t n){
    char *(*r)(char*,const char*,size_t)=dlsym(RTLD_NEXT,"strncpy");
    char *q = r(d,s,n); if(g_log) fprintf(g_log,"MEMCPY %p %zu\n",d,n); return q; }
"""


def _compile_hook(cache_dir: Path):
    so = cache_dir / 'heap_hook.so'
    if so.exists():
        return str(so)
    c = cache_dir / 'heap_hook.c'
    c.write_text(_HOOK_C, encoding='utf-8')
    for cc in ('gcc', 'cc'):
        try:
            r = subprocess.run([cc, '-shared', '-fPIC', '-o', str(so),
                                str(c), '-ldl'],
                               capture_output=True, timeout=30)
            if r.returncode == 0 and so.exists():
                return str(so)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def _run_with_hook(binary: str, hook_so: str, timeout: int) -> str:
    log = f'{binary}.hook.log'
    if os.path.exists(log):
        os.remove(log)
    env = dict(os.environ)
    env['LD_PRELOAD'] = hook_so
    env['HOOK_LOG'] = log
    subprocess.run([binary], capture_output=True, timeout=timeout, env=env)
    if os.path.exists(log):
        return open(log, encoding='utf-8', errors='replace').read()
    return ''


def _run_qemu(binary: str, hook_so: str, timeout: int) -> str:
    log = f'{binary}.qemu.log'
    if os.path.exists(log):
        os.remove(log)
    env = dict(os.environ)
    env['LD_PRELOAD'] = hook_so
    env['HOOK_LOG'] = log
    subprocess.run(['qemu-x86_64', binary], capture_output=True,
                   timeout=timeout, env=env)
    if os.path.exists(log):
        return open(log, encoding='utf-8', errors='replace').read()
    return ''


def _analyze_log(text: str) -> dict:
    """解析插桩日志, 返回 (overflow_events, allocs, copies)。"""
    allocs = {}
    live = {}
    copies = 0
    overflow = 0
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        kind = parts[0]
        try:
            if kind == 'MALLOC':
                allocs[parts[1]] = int(parts[2])
                live[parts[1]] = int(parts[2])
            elif kind == 'REALLOC':
                if parts[1] in live:
                    del live[parts[1]]
                live[parts[2]] = int(parts[3])
            elif kind == 'FREE':
                live.pop(parts[1], None)
            elif kind == 'MEMCPY':
                copies += 1
                dst = int(parts[1], 16) if parts[1].startswith('0x') \
                    else int(parts[1])
                size = int(parts[2])
                if _writes_out_of_bounds(dst, size, live):
                    overflow += 1
        except (ValueError, IndexError, KeyError):
            continue
    return {'overflow_events': overflow, 'allocs': len(allocs),
            'copies': copies}


def _writes_out_of_bounds(dst: int, size: int, live: dict) -> bool:
    for base_s, cap in live.items():
        base = int(base_s, 16) if base_s.startswith('0x') else int(base_s)
        if base <= dst < base + cap:
            return dst + size > base + cap
    return False


def trace_gt(binary: str, timeout: int = 10) -> dict:
    """运行时 ground truth 判定。返回统一结果字典。"""
    base = {'tool': 'QEMU-GT', 'sample': os.path.basename(binary)}
    if not Path(binary).exists():
        return {**base, 'success': False, 'overflow_events': 0,
                'duration_sec': 0.0, 'error': 'binary missing'}
    cache = Path(__file__).resolve().parent / '.cache'
    cache.mkdir(exist_ok=True)
    hook = _compile_hook(cache)
    if hook is None:
        return {**base, 'success': False, 'overflow_events': 0,
                'duration_sec': 0.0, 'error': 'hook compile failed (gcc?)'}
    t0 = time.time()
    text = ''
    err = ''
    try:
        text = _run_qemu(binary, hook, timeout)
        if not text:
            text = _run_with_hook(binary, hook, timeout)
        if not text:
            err = 'no log produced'
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        err = str(e)[:120]
    dt = round(time.time() - t0, 3)
    if not text and not err:
        err = 'empty trace'
    if text:
        info = _analyze_log(text)
        return {**base, 'success': True,
                'overflow_events': info['overflow_events'],
                'allocs': info['allocs'], 'copies': info['copies'],
                'duration_sec': dt, 'error': ''}
    return {**base, 'success': False, 'overflow_events': 0,
            'duration_sec': dt, 'error': err or 'trace failed'}


def qemu_inasm(binary: str, timeout: int = 10) -> dict:
    """回退模式: qemu -d in_asm 统计危险调用次数。"""
    base = {'tool': 'QEMU-inasm', 'sample': os.path.basename(binary)}
    try:
        r = subprocess.run(['qemu-x86_64', '-d', 'in_asm', binary],
                           capture_output=True, timeout=timeout)
        calls = len(re.findall(r'callq?', r.stdout.decode('utf-8',
                                                          errors='replace')))
        return {**base, 'success': True, 'calls': calls,
                'duration_sec': round(r.elapsed, 3) if hasattr(r, 'elapsed') else 0,
                'error': ''}
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {**base, 'success': False, 'calls': 0, 'duration_sec': 0,
                'error': 'qemu-x86_64 not found'}


if __name__ == '__main__':
    import sys as _sys
    import json
    if len(_sys.argv) < 2:
        print('usage: qemu_tracer.py <binary>')
        _sys.exit(1)
    print(json.dumps(trace_gt(_sys.argv[1]), indent=2))
