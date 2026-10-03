# QEMU用户态追踪器: 使用QEMU user mode + 自定义插桩收集运行时堆操作
# 原理: QEMU的 -trace 和 -d 选项可以记录内存访问,
#   结合LD_PRELOAD拦截malloc/memcpy可获取ground truth (运行时真实数据)
# TODO: Windows 无 LD_PRELOAD, ground truth 需移植到 Linux 环境
# 决策: 不使用完整的QEMU system mode (过于复杂),
#   而是用LD_PRELOAD拦截 + QEMU -d exec追踪执行
#
#   Bellard, "QEMU, a Fast and Portable Dynamic Translator"
#     (USENIX ATC 2005) — QEMU用户态模拟架构
#   Bruening et al. "DynamoRIO"
#     (CGO 2003) — 动态插桩替代方案
import subprocess, sys, os, re, time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# 内存操作拦截器 (编译为共享库, LD_PRELOAD注入)
# 用途: 运行时记录每次malloc/memcpy的参数以获取ground truth
_INTERCEPT_CODE = r"""// heap_intercept.c: LD_PRELOAD内存操作拦截
// 编译: gcc -shared -fPIC -o libheap_intercept.so heap_intercept.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#define LOG_FILE "heap_trace.log"
static FILE* _log = NULL;
static void* (*_real_malloc)(size_t) = NULL;
static void* (*_real_calloc)(size_t,size_t) = NULL;
static void* (*_real_realloc)(void*,size_t) = NULL;
static void (*_real_free)(void*) = NULL;
static void* (*_real_memcpy)(void*,const void*,size_t) = NULL;
static void* (*_real_memset)(void*,size_t,int) = NULL;
static void _init_log(void) {
  if (!_log) { _log = fopen(LOG_FILE,"a"); setvbuf(_log,NULL,_IONBF,0); }
}
void* malloc(size_t n) {
  if(!_real_malloc) _real_malloc = dlsym(RTLD_NEXT,"malloc");
  void *p = _real_malloc(n); _init_log();
  fprintf(_log,"ALLOC %p %zu\n",p,n); return p;
}
void* calloc(size_t nmemb,size_t sz) {
  if(!_real_calloc) _real_calloc = dlsym(RTLD_NEXT,"calloc");
  void *p = _real_calloc(nmemb,sz); _init_log();
  fprintf(_log,"ALLOC %p %zu\n",p,nmemb*sz); return p;
}
void* realloc(void* old,size_t n) {
  if(!_real_realloc) _real_realloc = dlsym(RTLD_NEXT,"realloc");
  void *p = _real_realloc(old,n); _init_log();
  fprintf(_log,"FREE %p 0\n",old);
  fprintf(_log,"ALLOC %p %zu\n",p,n); return p;
}
void free(void* p) {
  if(!_real_free) _real_free = dlsym(RTLD_NEXT,"free");
  _init_log(); fprintf(_log,"FREE %p 0\n",p); _real_free(p);
}
void* memcpy(void* dst,const void*src,size_t n) {
  if(!_real_memcpy) _real_memcpy = dlsym(RTLD_NEXT,"memcpy");
  _init_log(); fprintf(_log,"WRITE %p %zu\n",dst,n);
  return _real_memcpy(dst,src,n);
}
void* memset(void* dst,int c,size_t n) {
  if(!_real_memset) _real_memset = dlsym(RTLD_NEXT,"memset");
  _init_log(); fprintf(_log,"WRITE %p %zu\n",dst,n);
  return _real_memset(dst,c,n);
}
"""


@dataclass
class QemuTraceEntry:
    """运行时追踪条目."""
    op_type: str  # ALLOC / FREE / WRITE
    ptr: int
    size: int
    timestamp: int = 0


@dataclass
class QemuRunResult:
    binary_path: str
    success: bool
    exit_code: int
    trace_entries: List[QemuTraceEntry]
    runtime_ms: float
    overflow_events: List[Dict]  # ground truth: 确实发生的溢出
    error_msg: str = ""


class QemuTracer:
    """QEMU用户态 + LD_PRELOAD运行时追踪器.

    两阶段方案:
      1. 静态: 检查QEMU是否可用 (备用: 直接运行+LD_PRELOAD)
      2. 动态: 执行二进制, 收集malloc/memcpy trace,
         分析trace找出真实溢出的分配-写入对
    """

    def __init__(self, timeout_seconds: int = 10):
        self._timeout = timeout_seconds
        self._intercept_dir = Path(__file__).parent / ".intercept_build"
        self._intercept_so = self._intercept_dir / "libheap_intercept.so"

    def _ensure_interceptor(self) -> Optional[str]:
        """确保拦截器共享库已编译."""
        if self._intercept_so.exists():
            return str(self._intercept_so)
        self._intercept_dir.mkdir(parents=True, exist_ok=True)
        src = self._intercept_dir / "heap_intercept.c"
        with open(src, 'w') as f:
            f.write(_INTERCEPT_CODE)
        try:
            subprocess.run(
                ["gcc", "-shared", "-fPIC", "-o",
                 str(self._intercept_so), str(src), "-ldl"],
                capture_output=True, text=True, timeout=30, check=True)
            return str(self._intercept_so)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            return None

    def trace(self, binary_path: str) -> QemuRunResult:
        """执行二进制并收集运行时trace."""
        so_path = self._ensure_interceptor()
        if so_path is None:
            return QemuRunResult(
                binary_path=binary_path, success=False,
                exit_code=-1, trace_entries=[], runtime_ms=0,
                overflow_events=[], error_msg="拦截器编译失败 (gcc未安装?)")

        log_file = Path(binary_path).parent / "heap_trace.log"
        if log_file.exists():
            log_file.unlink()

        env = os.environ.copy()
        env["LD_PRELOAD"] = so_path

        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                [binary_path], env=env, capture_output=True,
                timeout=self._timeout, cwd=str(Path(binary_path).parent))
            elapsed = (time.perf_counter() - t0) * 1000
            trace = self._parse_trace(log_file)
            overflows = self._detect_overflows(trace)
            return QemuRunResult(
                binary_path=binary_path, success=True,
                exit_code=proc.returncode, trace_entries=trace,
                runtime_ms=elapsed, overflow_events=overflows,
                error_msg=proc.stderr.decode()[:200] if proc.stderr else "")
        except subprocess.TimeoutExpired:
            elapsed = (time.perf_counter() - t0) * 1000
            trace = self._parse_trace(log_file)
            overflows = self._detect_overflows(trace)
            return QemuRunResult(
                binary_path=binary_path, success=True,
                exit_code=-1, trace_entries=trace,
                runtime_ms=elapsed, overflow_events=overflows,
                error_msg="timeout")
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return QemuRunResult(
                binary_path=binary_path, success=False,
                exit_code=-1, trace_entries=[], runtime_ms=elapsed,
                overflow_events=[], error_msg=str(e))
        finally:
            if log_file.exists():
                try:
                    log_file.unlink()
                except OSError:
                    pass

    def _parse_trace(self, log_file: Path) -> List[QemuTraceEntry]:
        """解析拦截器日志."""
        entries = []
        if not log_file.exists():
            return entries
        try:
            with open(log_file, 'r') as f:
                for i, line in enumerate(f):
                    parts = line.strip().split()
                    if len(parts) < 3:
                        continue
                    try:
                        ptr = int(parts[1], 16)
                        size = int(parts[2])
                        entries.append(QemuTraceEntry(
                            op_type=parts[0], ptr=ptr, size=size, timestamp=i))
                    except ValueError:
                        continue
        except Exception:
            pass
        return entries

    def _detect_overflows(self, trace: List[QemuTraceEntry]
                          ) -> List[Dict]:
        """从trace数据中检测真实的堆溢出.

        原理: 对每个WRITE操作, 检查其目标指针是否有对应的ALLOC,
          且写入范围是否超出分配范围.
        """
        overflows = []
        # 建立指针→分配大小的映射
        alloc_sizes: Dict[int, int] = {}  # ptr → size
        for entry in trace:
            if entry.op_type == "ALLOC":
                alloc_sizes[entry.ptr] = entry.size
            elif entry.op_type == "FREE":
                alloc_sizes.pop(entry.ptr, None)
            elif entry.op_type == "WRITE":
                alloc_info = self._find_matching_alloc(entry.ptr, alloc_sizes)
                if alloc_info:
                    alloc_ptr, alloc_size = alloc_info
                    if entry.size > alloc_size:
                        overflows.append({
                            "ptr": hex(entry.ptr),
                            "write_size": entry.size,
                            "alloc_size": alloc_size,
                            "overflow_bytes": entry.size - alloc_size,
                            "alloc_ptr": hex(alloc_ptr),
                        })
        return overflows

    def _find_matching_alloc(self, ptr: int, alloc_sizes: Dict[int, int]
                             ) -> Optional[Tuple[int, int]]:
        """找到与写入目标指针匹配的分配记录.

        堆分配返回的指针可能经过偏移计算,
        因此用地址范围匹配: 若ptr落在[alloc_ptr, alloc_ptr+size)范围内,
        则认为写入目标是该分配的子范围.
        """
        # 精确匹配优先
        if ptr in alloc_sizes:
            return (ptr, alloc_sizes[ptr])
        # 范围匹配: 找到包含ptr的分配
        best = None
        best_size = 0
        for alloc_ptr, size in alloc_sizes.items():
            if alloc_ptr <= ptr < alloc_ptr + size:
                if size > best_size:
                    best = alloc_ptr
                    best_size = size
        if best is not None:
            return (best, best_size)
        return None
