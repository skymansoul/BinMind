"""
UAF路径可达性验证器 —— 基于简化CFG的 free→use 时序判定。

核心问题: 在反编译伪代码中, free(p) 和 *p (use) 的文本先后 ≠ 运行时先后.
例: if(cond) free(p);  else *p = x; — free 和 use 在互斥分支, 不会同时执行.

CFG构建委托给 uaf_cfg_builder.py, 本模块专注于路径可达性分析.

  - Undangle §4.3 — 时序一致性检查
  - GUEB — CFG-based alloc/free pairing
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from analysis.uaf_cfg_builder import UafBasicBlock, UafCFGBuilder

class UafPathVerdict(Enum):
    SAME_PATH = "SAME_PATH"            # free和use在可行路径上可相遇
    MUTUAL_EXCLUSIVE = "MUTUAL_EXCLUSIVE"  # 互斥分支, 不可能同时执行
    DOMINATED = "DOMINATED"            # free dominates use (确定UAF)
    UNCERTAIN = "UNCERTAIN"

@dataclass
class UafPathResult:
    """UAF路径可达性验证结果."""
    ptr_name: str = ""
    free_block: int = -1
    use_block: int = -1
    verdict: UafPathVerdict = UafPathVerdict.UNCERTAIN
    reachable: bool = False
    reason: str = ""
    confidence_delta: float = 0.0

class UafPathVerifier:
    """UAF路径可达性验证器 — 可达性分析。

    工作流程:
      1. 从伪代码行构建简化CFG (委托给 UafCFGBuilder)
      2. 标记每个基本块中的 free/use 操作
      3. BFS从free块出发, 检查是否能到达use块
      4. 若能到达 → SAME_PATH (可能真UAF); 否则 → MUTUAL_EXCLUSIVE (误报)
    """

    def __init__(self):
        self._blocks: List[UafBasicBlock] = []
        self._adj: Dict[int, List[int]] = {}
        self._builder = UafCFGBuilder()

    def build_cfg(self, pseudocode_lines: List[str]) -> List[UafBasicBlock]:
        """从伪代码行列表构建简化CFG —— 委托给 UafCFGBuilder。"""
        self._blocks = self._builder.build(pseudocode_lines)
        self._adj = dict(self._builder.adjacency)
        return self._blocks

    def check_reachability(self, ptr_name: str) -> UafPathResult:
        """检查 free(ptr) → use(*ptr) 的路径可达性。

        对每个 free块, BFS查找能到达的 use块。
        若 free块可到达 use块 → SAME_PATH (可能真UAF)
        若不可达 → MUTUAL_EXCLUSIVE (误报)
        """
        if not self._blocks:
            return UafPathResult(
                ptr_name=ptr_name, free_block=-1, use_block=-1,
                verdict=UafPathVerdict.UNCERTAIN, reachable=False,
                reason="empty CFG", confidence_delta=0.0,
            )

        free_blocks = [i for i, bb in enumerate(self._blocks)
                       if ptr_name in bb.free_vars]
        use_blocks = [i for i, bb in enumerate(self._blocks)
                      if ptr_name in bb.use_vars]

        if not free_blocks:
            return UafPathResult(
                ptr_name=ptr_name, free_block=-1, use_block=-1,
                verdict=UafPathVerdict.UNCERTAIN, reachable=False,
                reason=f"no free({ptr_name}) found in CFG",
                confidence_delta=0.0,
            )
        if not use_blocks:
            return UafPathResult(
                ptr_name=ptr_name, free_block=free_blocks[0], use_block=-1,
                verdict=UafPathVerdict.UNCERTAIN, reachable=False,
                reason=f"no use of {ptr_name} found after free",
                confidence_delta=-0.20,
            )

        fb = free_blocks[0]
        ub = use_blocks[0]

        # BFS 从 free块 出发
        reachable = self._bfs_reachable(fb, ub)

        if reachable:
            # 进一步检查: free块是否 dominates use块
            if self._block_dominates(fb, ub):
                return UafPathResult(
                    ptr_name=ptr_name, free_block=fb, use_block=ub,
                    verdict=UafPathVerdict.DOMINATED,
                    reachable=True,
                    reason=(f"free({ptr_name}) in block {fb} dominates "
                           f"use in block {ub} — confirmed UAF path"),
                    confidence_delta=+0.15,
                )
            return UafPathResult(
                ptr_name=ptr_name, free_block=fb, use_block=ub,
                verdict=UafPathVerdict.SAME_PATH,
                reachable=True,
                reason=(f"free({ptr_name}) in block {fb} can reach "
                       f"use in block {ub}"),
                confidence_delta=+0.05,
            )
        else:
            return UafPathResult(
                ptr_name=ptr_name, free_block=fb, use_block=ub,
                verdict=UafPathVerdict.MUTUAL_EXCLUSIVE,
                reachable=False,
                reason=(f"free({ptr_name}) in block {fb} cannot reach "
                       f"use in block {ub} — likely FP from branch analysis"),
                confidence_delta=-0.35,
            )

    def _bfs_reachable(self, src: int, dst: int) -> bool:
        """BFS检查 src块 是否能到达 dst块。"""
        if src == dst:
            return True
        if src not in self._adj:
            return False
        visited = {src}
        queue = [src]
        while queue:
            cur = queue.pop(0)
            if cur == dst:
                return True
            for succ in self._adj.get(cur, []):
                if succ not in visited:
                    visited.add(succ)
                    queue.append(succ)
        return False

    def _block_dominates(self, a: int, b: int) -> bool:
        """简化: 检查块a是否dominates块b。

        在简化CFG中, 如果从入口到块b的每条路径都经过块a,
        则块a dominates块b。这里使用近似判定:
          从a出发BFS可达b, 且从入口出发的每条到b的路径都经过a。
        简化为: a到b有路径, 且a的ID < b的ID, 且两者间无汇合。
        """
        if not self._bfs_reachable(a, b):
            return False
        # 近似: 检查入口到b的必经路径
        # 简化实现: 从入口BFS, 看是否存在绕过a到达b的路径
        for start in self._entry_blocks():
            if start == a:
                continue
            if self._bfs_reachable(start, b) and not self._bfs_reachable(start, a):
                # 存在不经过a的路径到达b
                return False
        return True

    def _entry_blocks(self) -> List[int]:
        """返回CFG入口块 (没有被其他块指向的块)。"""
        all_succs = set()
        for succs in self._adj.values():
            all_succs.update(succs)
        entries = [i for i in range(len(self._blocks)) if i not in all_succs]
        return entries if entries else [0]

    @staticmethod
    def from_pseudocode(pseudocode: str) -> 'UafPathVerifier':
        """工厂方法: 从反编译伪代码字符串创建验证器。"""
        lines = pseudocode.splitlines()
        verifier = UafPathVerifier()
        verifier.build_cfg(lines)
        return verifier

def verify_uaf_paths(candidates: List[dict],
                     pseudocode: str = '') -> Tuple[List[dict], List[UafPathResult]]:
    """便捷函数: 对 UAF 候选列表执行路径可达性验证。

    返回 (filtered_candidates, path_results)。
    """
    if not pseudocode or not candidates:
        return list(candidates), []

    verifier = UafPathVerifier.from_pseudocode(pseudocode)
    results = []
    kept = []

    for c in candidates:
        ptr = (c.get('freed_variable') or c.get('pointer_name')
               or c.get('alloc_var') or c.get('variable', ''))

        if not ptr:
            results.append(UafPathResult(
                ptr_name='', free_block=-1, use_block=-1,
                verdict=UafPathVerdict.UNCERTAIN, reachable=False,
                reason='no pointer name in candidate', confidence_delta=0.0,
            ))
            kept.append(c)
            continue

        pr = verifier.check_reachability(ptr)
        results.append(pr)

        if pr.verdict == UafPathVerdict.MUTUAL_EXCLUSIVE:
            # 互斥分支: 强FP信号, 过滤
            continue
        elif pr.confidence_delta != 0.0 and isinstance(c, dict):
            c['confidence'] = min(0.98, max(0.05,
                c.get('confidence', 0.5) + pr.confidence_delta))
        kept.append(c)

    return kept, results

__all__ = [
    'UafPathVerdict', 'UafPathResult',
    'UafPathVerifier', 'verify_uaf_paths',
]
