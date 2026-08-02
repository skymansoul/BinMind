# re-export from compat/ — GPU 内核分析桩
# pkg_resources 风格路径解析，与 vm_unvirtualizer 的上游模块加载方式保持一致
# 参考: NeuroScope (USENIX Security 2025) DNN 二进制逆向 & GPU 内存安全分析
import os as _os, sys as _sys

_upstream_dir = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat')
if _upstream_dir not in _sys.path:
    _sys.path.insert(0, _upstream_dir)
import gpu_kernel_analyzer as _src_mod
_sys.path.remove(_upstream_dir)

globals().update({_k: getattr(_src_mod, _k) for _k in dir(_src_mod) if not _k.startswith('_')})

# --- GPU 内核模式补充: PTX/SASS 指令级分类 ---
# NeuroScope 使用动态分析 + ML 逆向 DNN 二进制；此处扩展低层级 GPU 指令
# 模式匹配，覆盖 CUDA 内核中常见的内存访问模式与同步原语。
import re as _regex

# PTX 同步原语模式
_BARRIER_PATTERNS = [
    _regex.compile(r'bar\.sync\s+\d+'),
    _regex.compile(r'bar\.arrive\s+\d+'),
    _regex.compile(r'membar\.(cta|gl|sys)'),
    _regex.compile(r'__syncthreads\(\)'),
]

# 共享内存 bank conflict 检测 — 基于访问步幅分析
_BANK_COUNT = 32
_BANK_WIDTH = 4  # bytes per bank

def detect_bank_conflicts(shared_accesses: list[tuple[int, int]]) -> list[dict]:
    """从共享内存访问序列检测 bank conflict。
    输入: [(thread_id, byte_offset), ...]
    返回: [{'warp_idx': int, 'conflict_degree': int, 'conflicting_addrs': [...]}]
    warp_size=32 (NVIDIA), bank_count=32, bank_width=4 bytes."""
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
