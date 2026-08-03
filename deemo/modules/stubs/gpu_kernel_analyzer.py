# compat/ 子模块代理 — GPU 内核安全分析，sys.path 方式加载上游模块。
# 参考: NeuroScope (USENIX Security 2025) 基于 DNN 的二进制逆向与 GPU 内存安全。
import os as _os, sys as _sys

_upstream_dir = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat')
if _upstream_dir not in _sys.path:
    _sys.path.insert(0, _upstream_dir)
import gpu_kernel_analyzer as _src_mod
_sys.path.remove(_upstream_dir)

globals().update({_k: getattr(_src_mod, _k) for _k in dir(_src_mod) if not _k.startswith('_')})

# PTX/SASS 指令级模式匹配
# NeuroScope 使用动态分析逆向 DNN 二进制；此处补充低层级 GPU 指令模式匹配，
# 覆盖 CUDA 内核常见的内存访问模式与同步原语。
import re as _regex

# PTX 同步与内存屏障指令模式
_BARRIER_PATTERNS = [
    _regex.compile(r'bar\.sync\s+\d+'),
    _regex.compile(r'bar\.arrive\s+\d+'),
    _regex.compile(r'membar\.(cta|gl|sys)'),
    _regex.compile(r'__syncthreads\(\)'),
]

# 共享内存 bank 冲突检测 — 按访问步幅推算 bank 占用分布。
_BANK_COUNT = 32
_BANK_WIDTH = 4  # bytes per bank

def detect_bank_conflicts(shared_accesses: list[tuple[int, int]]) -> list[dict]:
    """检测共享内存 bank conflict — 按 warp 分组统计 bank 占用度。
    输入: [(thread_id, byte_offset), ...]
    输出: [{'warp_idx': int, 'conflict_degree': int, 'conflicting_addrs': [...]}]
    参数: warp_size=32 (NVIDIA), bank_count=32, bank_width=4 bytes。"""
    conflicts = []
    warp_size = 32
    for warp_start in range(0, len(shared_accesses), warp_size):
        warp = shared_accesses[warp_start:warp_start + warp_size]
        bank_usage = {}
        for tid, offset in warp:
            bank_id = (offset // _BANK_WIDTH) % _BANK_COUNT
            bank_usage.setdefault(bank_id, []).append(offset)
        max_conflict = max((len(v) for v in bank_usage.values()), default=1)
        if max_conflict > 1:
            conflicts.append({
                'warp_idx': warp_start // warp_size,
                'conflict_degree': max_conflict,
                'conflicting_addrs': [
                    v for v in bank_usage.values() if len(v) > 1
                ]
            })
    return conflicts
