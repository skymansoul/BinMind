"""
补丁分析辅助函数 — 基本块签名、可达性估算、入口候选推断。

以控制单文件行数。包含
  - bb_signature: 指令助记符序列→SHA-256 前 16 位 hex
  - _estimate_reachable: BFS 可达性 (邻接表/启发式回退)
  - _entry_candidates: 导入调用点→入口基本块反推
  - BlockMatch: 单基本块匹配结果的数据类

修改记录:
创建 2026-06-10
"""

import hashlib
from typing import Dict, List, Optional, Set
from dataclasses import dataclass


@dataclass
class BlockMatch:
    old_index: int
    new_index: Optional[int]
    signature: str
    matched: bool
    reachability_preserved: Optional[bool]


def bb_signature(instructions: List[str]) -> str:
    """
    基本块签名: 指令助记符序列→SHA-256 前 16 位 hex。
    操作数剥离 → 对寄存器重命名和地址重定位鲁棒。
    对指令重排和语义等价变换敏感 — 补丁通常修改指令流而非仅重排。
    """
    mnemonics = []
    for ins in instructions:
        stripped = ins.strip()
        if not stripped or stripped.startswith(';') or stripped.startswith('#'):
            continue
        parts = stripped.split(None, 1)
        mnem = parts[0].lower() if parts else ''
        if mnem:
            mnemonics.append(mnem)
    return hashlib.sha256(','.join(mnemonics).encode()).hexdigest()[:16]


def _estimate_reachable(bb_index: int, total_blocks: int,
                        entry_indices: Set[int],
                        adjacency: Dict[int, List[int]],
                        max_depth: int = 50) -> bool:
    """BFS从入口出发检查目标基本块可达性。无邻接表时用启发式回退。"""
    if not adjacency:
        return bb_index <= max(total_blocks // 3, 3)
    visited = set()
    queue = list(entry_indices)
    for idx in queue:
        visited.add(idx)
    depth = 0
    while queue and depth < max_depth:
        current = queue.pop(0)
        if current == bb_index:
            return True
        for n in adjacency.get(current, []):
            if n not in visited:
                visited.add(n)
                queue.append(n)
        depth += 1
    return False


def _entry_candidates(function_name: str,
                      import_calls: Dict[str, List[int]]) -> Set[int]:
    """导入调用点→入口基本块反推。无匹配时回退 {0}。"""
    normalized = function_name.lower().lstrip('_')
    for imp_name, indices in import_calls.items():
        if normalized in imp_name.lower():
            return set(indices)
    return {0}
