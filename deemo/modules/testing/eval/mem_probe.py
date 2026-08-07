"""跨平台峰值内存测量.

Windows: ctypes GetProcessMemoryInfo (本进程/子进程句柄)
Unix:    resource.getrusage
测量粒度: 运行工具期间的进程工作集采样, 取最大值为峰值近似.
"""

import os
import sys
import threading
import time

_running = {"pid": os.getpid()}


def rss_kb() -> float:
    """当前进程工作集大小 (KB)."""
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes
            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            k32.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
                wintypes.DWORD]
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
            handle = k32.GetCurrentProcess()
            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters),
                                          counters.cb):
                return counters.WorkingSetSize / 1024.0
        except Exception:
            pass
    else:
        try:
            import resource
            return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
        except (ImportError, AttributeError):
            pass
    return 0.0


def measure_peak(run_fn, interval: float = 0.05) -> tuple:
    """执行 run_fn 并采样峰值内存.

    返回 (result, peak_kb, elapsed_ms). run_fn 同步执行于本线程.
    """
    peak = [rss_kb()]
    stop = [False]

    def sampler():
        while not stop[0]:
            v = rss_kb()
            if v > peak[0]:
                peak[0] = v
            time.sleep(interval)

    t0 = time.perf_counter()
    th = threading.Thread(target=sampler, daemon=True)
    th.start()
    try:
        result = run_fn()
    finally:
        stop[0] = True
        th.join(timeout=0.5)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    return result, round(peak[0], 1), round(elapsed_ms, 1)
