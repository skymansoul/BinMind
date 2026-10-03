# compat 重导出 — 混合执行引擎桩
# 具体执行 + 符号执行路径优先队列
# CO3/SHACO 硬件在环 concolic co-execution &
#        ADFEmu DMA 仿真引导 + DSE 路径探索
import os as _os

_up = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'concolic_execution.py')
try:
    with open(_up, 'r', encoding='utf-8') as _fh:
        _src = _fh.read()
    exec(compile(_src, _up, 'exec'), globals())
except OSError:
    # 上游链缺失时降级为空重导出, 保持模块可导入
    pass

# 路径搜索策略扩展
# CO3 三数量级加速依赖高效路径选择；
# 提供启发式评分备选方案，按新基本块覆盖与路径深度加权排序。
# "Driller" — 选择性符号执行

import heapq as _heapq
from collections import defaultdict as _defdict

def _hash_path_constraints(constraints: list) -> str:
    import hashlib as _hl
    h = _hl.sha256()
    for c in sorted(str(c) for c in constraints):
        h.update(c.encode())
    return h.hexdigest()[:16]

def select_high_value_paths(path_candidates: list[dict],
                             seen_hashes: set[str],
                             top_k: int = 5) -> list[dict]:
    """从候选路径中选择 top-k 个高价值路径。
    价值评分: 新基本块数 * 2 + 深度 * 1 - 分支复杂度 * 0.5。
    seen_hashes 用于去重（已探索过的约束组合跳过）。"""
    scored = []
    for p in path_candidates:
        h = _hash_path_constraints(p.get('constraints', []))
        if h in seen_hashes:
            continue
        new_blocks = len(p.get('reachable_blocks', []))
        depth = p.get('depth', 0)
        complexity = p.get('branch_count', 0)
        value = new_blocks * 2.0 + depth * 1.0 - complexity * 0.5
        scored.append((value, h, p))

    scored.sort(key=lambda x: -x[0])
    selected = []
    for _, h, p in scored[:top_k]:
        seen_hashes.add(h)
        selected.append(p)
    return selected
