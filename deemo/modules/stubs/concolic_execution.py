# re-export from compat/ — 混合执行桩
# 编译-执行策略 + 符号执行路径优先队列补丁
# 参考: CO3/SHACO (USENIX Security 2024) 硬件在环 concolic co-execution &
#        ADFEmu (2025) LLM 引导的 DMA 仿真 + DSE 路径探索
import os as _os

_up = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'concolic_execution.py')
with open(_up, 'r', encoding='utf-8') as _fh:
    _src = _fh.read()
exec(compile(_src, _up, 'exec'), globals())

# --- 路径搜索策略扩展 ---
# CO3 的 "3 个数量级加速" 依赖于高效的路径选择；
# ADFEmu 引入 LLM 指导路径探索方向——此处提供启发式评分备选方案。
# 参考: "Driller" (Stephens et al., NDSS 2016) — 选择性符号执行

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
