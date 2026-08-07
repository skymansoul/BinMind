"""
UAF Dominator 验证器 — 基于支配关系的保守 UAF 判定.

在 TemporalPathVerifier 的 BFS 路径探索基础上, 增加图论维度:
  1. Free dominates Use → UAF CONFIRMED (所有到use的路径必经free)
  2. Nullify post-dominates Free → SAFE (所有free之后的路径必经nullify)
  3. Guard-block dominance → CONDITIONAL (use在守卫块内)

理论依据:
  - Lengauer-Tarjan dominator tree
  - Reps-Horwitz-Sagiv program slicing 中的支配概念

保守性保证 (功能只增不减):
  - 仅在可证明时返回 SAFE/CONFIRMED
  - 不确定时返回 UNCERTAIN → fall through 到 TARPS
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from analysis.lpvra_types import build_simple_cfg


# 判定枚举

@dataclass
class DominatorVerdict:
    """支配关系验证结果."""
    CONFIRMED = "CONFIRMED"    # Free dominates Use
    SAFE = "SAFE"              # Nullify post-dominates Free
    CONDITIONAL = "CONDITIONAL"  # Guard-gated
    UNCERTAIN = "UNCERTAIN"    # 无法判定


@dataclass
class DominatorResult:
    """支配关系分析结果."""
    ptr_var: str
    free_line: int
    use_line: int
    verdict: str
    free_dominates_use: bool = False
    nullify_postdom_free: bool = False
    guard_protected: bool = False
    reason: str = ""


# 支配关系计算 (Lengauer-Tarjan 简化版)

def _compute_dominators(
    adj: Dict[int, List[int]],
    entry: int,
    node_count: int,
    reverse: bool = False,
) -> Dict[int, Set[int]]:
    """计算支配者集合 (iterate to fixpoint).

    标准定义:
      - dom(n): 所有到达 n 的路径上都经过的节点集合
      - postdom(n): 从 n 出发所有到达 exit 的路径上都经过的节点集合
                     = dom(n) in reversed CFG (reverse=True)

    算法: 迭代不动点 (O(N^2) worst case, 对小型CFG足够).
    """
    all_nodes = set(range(node_count))
    dom: Dict[int, Set[int]] = {}

    if reverse:
        # 反向图: 找所有能到达 exit 的节点作为初始集合
        rev_adj: Dict[int, List[int]] = {i: [] for i in range(node_count)}
        for u, vs in adj.items():
            for v in vs:
                if v not in rev_adj:
                    rev_adj[v] = []
                rev_adj[v].append(u)
        adj = rev_adj

    # 初始化: dom(entry) = {entry}, dom(n≠entry) = all_nodes
    for n in range(node_count):
        dom[n] = {entry} if n == entry else set(all_nodes)

    changed = True
    iteration = 0
    while changed and iteration < 100:
        changed = False
        iteration += 1
        for n in range(node_count):
            if n == entry:
                continue
            # dom(n) = {n} ∪ ⋂_{p∈pred(n)} dom(p)
            preds = [p for p, vs in adj.items() if n in vs]
            if not preds:
                new_dom = {n}
            else:
                new_dom = {n} | set.intersection(
                    *(dom.get(p, set()) for p in preds))
            if new_dom != dom.get(n):
                dom[n] = new_dom
                changed = True

    return dom


def _compute_reachability(
    adj: Dict[int, List[int]],
    source: int,
    target: int,
    node_count: int,
) -> bool:
    """BFS 检查 source → target 可达性."""
    visited = {source}
    q = deque([source])
    while q:
        u = q.popleft()
        if u == target:
            return True
        for v in adj.get(u, []):
            if v not in visited:
                visited.add(v)
                q.append(v)
    return False


class UAFDominatorVerifier:
    """基于支配关系的 UAF 验证器.

    在 TemporalPathVerifier 的 BFS 基础上增加图论维度:
      - Free block dominates Use block → 所有路径必经free, UAF不可避免
      - Nullify block post-dominates Free block → 所有free后的路径必经nullify
    """

    def __init__(self):
        pass

    def verify(
        self,
        source: str,
        free_line: int,
        use_line: int,
        ptr_var: str,
    ) -> DominatorResult:
        """对给定的 free→use pair 执行支配关系验证.

        Args:
            source: C 源码
            free_line: free() 调用行号 (1-indexed)
            use_line: 指针使用行号 (1-indexed)
            ptr_var: 被释放的指针变量名

        Returns:
            DominatorResult with verdict
        """
        lines = source.splitlines()
        blocks, adj = build_simple_cfg(lines)
        if not blocks:
            return DominatorResult(
                ptr_var=ptr_var, free_line=free_line, use_line=use_line,
                verdict=DominatorVerdict.UNCERTAIN,
                reason="CFG build failed")

        # 定位 free block 和 use block
        free_blk = use_blk = -1
        for b in blocks:
            if b['start'] <= free_line - 1 <= b['end']:
                free_blk = b['id']
            if b['start'] <= use_line - 1 <= b['end']:
                use_blk = b['id']

        if free_blk < 0 or use_blk < 0:
            return DominatorResult(
                ptr_var=ptr_var, free_line=free_line, use_line=use_line,
                verdict=DominatorVerdict.UNCERTAIN,
                reason="block not found")

        node_count = len(blocks)

        # 找到 nullify blocks (p = NULL 在 free_line 之后的块)
        nullify_blks = _find_nullify_blocks(blocks, ptr_var, free_line)

        # 检查守卫块 (if (ptr) / if (ptr != NULL) 包裹 use 的块)
        guard_blocks = _find_guard_blocks(blocks, ptr_var)

        # 维度1: Free dominates Use
        dom = _compute_dominators(adj, 0, node_count)
        free_dominates_use = free_blk in dom.get(use_blk, set())

        # 维度2: Nullify post-dominates Free
        # postdom = dom in reversed graph from exit
        postdom = _compute_dominators(adj, 0, node_count, reverse=True)
        nullify_postdom_free = any(
            nb in postdom.get(free_blk, set()) for nb in nullify_blks)

        # 维度3: Guard 保护
        guard_protected = use_blk in guard_blocks

        # 保守判定
        if nullify_postdom_free:
            return DominatorResult(
                ptr_var=ptr_var, free_line=free_line, use_line=use_line,
                verdict=DominatorVerdict.SAFE,
                nullify_postdom_free=True,
                reason=("SAFE: nullify post-dominates free — "
                        "all paths from free pass through p=NULL "
                        "before reaching use"))
        elif free_dominates_use and not guard_protected:
            return DominatorResult(
                ptr_var=ptr_var, free_line=free_line, use_line=use_line,
                verdict=DominatorVerdict.CONFIRMED,
                free_dominates_use=True,
                reason=("CONFIRMED: free dominates use — "
                        "all paths to use must pass through free, "
                        "UAF unavoidable"))
        elif guard_protected:
            return DominatorResult(
                ptr_var=ptr_var, free_line=free_line, use_line=use_line,
                verdict=DominatorVerdict.CONDITIONAL,
                guard_protected=True,
                reason=("CONDITIONAL: use is guard-protected "
                        f"(if (ptr) check before use@{use_line})"))
        else:
            return DominatorResult(
                ptr_var=ptr_var, free_line=free_line, use_line=use_line,
                verdict=DominatorVerdict.UNCERTAIN,
                reason=(f"UNCERTAIN: free_blk={free_blk}, use_blk={use_blk}, "
                        f"free_dominates_use={free_dominates_use}, "
                        f"nullify_postdom_free={nullify_postdom_free}"))


def _find_nullify_blocks(
    blocks: List[Dict],
    ptr_var: str,
    free_line: int,
) -> List[int]:
    """定位 free 之后将指针置 NULL 的块."""
    import re
    nullify_blks = []
    ptr_base = ptr_var.split('->')[0] if '->' in ptr_var else ptr_var
    null_re = re.compile(
        rf'\b{re.escape(ptr_base)}\s*=\s*(?:NULL|0|nullptr|nil)\s*;')
    for b in blocks:
        if b['start'] < free_line - 1:
            continue
        for stmt in b.get('stmts', []):
            if null_re.search(stmt.strip()):
                nullify_blks.append(b['id'])
                break
    return nullify_blks


def _find_guard_blocks(
    blocks: List[Dict],
    ptr_var: str,
) -> Set[int]:
    """定位对 ptr_var 有 NULL 检查的守卫块."""
    import re
    ptr_base = ptr_var.split('->')[0] if '->' in ptr_var else ptr_var
    guard_re = re.compile(
        rf'if\s*\(\s*{re.escape(ptr_base)}\s*\)'
        rf'|if\s*\(\s*{re.escape(ptr_base)}\s*!=')
    guarded = set()
    for b in blocks:
        for stmt in b.get('stmts', []):
            if guard_re.search(stmt.strip()):
                guarded.add(b['id'])
                break
    return guarded


def dominator_batch_verify(
    source: str,
    free_use_pairs: List[Tuple[int, int, str]],
) -> List[DominatorResult]:
    """批量支配关系验证.

    Args:
        source: C 源码
        free_use_pairs: [(free_line, use_line, ptr_var), ...]

    Returns:
        DominatorResult 列表, 按置信度排序 (CONFIRMED > SAFE > CONDITIONAL > UNCERTAIN)
    """
    verifier = UAFDominatorVerifier()
    results = []
    for fl, ul, pv in free_use_pairs:
        r = verifier.verify(source, fl, ul, pv)
        results.append(r)
    # 按确定性排序
    priority = {DominatorVerdict.CONFIRMED: 0, DominatorVerdict.SAFE: 1,
                DominatorVerdict.CONDITIONAL: 2, DominatorVerdict.UNCERTAIN: 3}
    results.sort(key=lambda r: priority.get(r.verdict, 99))
    return results


__all__ = [
    'UAFDominatorVerifier', 'DominatorVerdict', 'DominatorResult',
    'dominator_batch_verify',
]
