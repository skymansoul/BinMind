"""UAF 分配生命周期分析 — malloc-free 配对 + 逃逸窗口检测.

创建: 2025-08-05
目的: uaf_candidate_scorer.py 的生命期间距评分仅用指令数/基本块计数做归一化，
      未考虑指针在 free 后到函数返回之间的"危险窗口"。本模块精确计算
      free(p) 到 p 的最后一次可达引用之间的指令数，若此窗口 > 阈值 → 高风险。

方法依据: UAFL (USENIX Security 2024) 的 typestate 分析追踪对象状态转移,
          本模块在二进制 IR 层面做简化: 不构建完整 typestate, 仅追踪
          malloc→free→use 的时序关系。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class AllocationLifetime:
    """一次分配的生命周期."""
    ptr_name: str
    alloc_addr: int            # malloc 指令地址
    alloc_size: int            # 分配大小
    free_addr: int             # free 指令地址 (0=未释放)
    last_use_addr: int         # 最后一次使用的指令地址
    danger_window: int         # free 后到 last_use 之间的指令数
    uaf_risk: float            # 0-1


class UAFAllocationLifetime:
    """UAF 分配生命周期分析器.

    追踪每个 malloc 返回的指针从分配到释放到后续使用的完整生命周期。
    danger_window = (last_use_addr - free_addr) — 越大越危险。

    使用方式:
      lifetime = UAFAllocationLifetime()
      lifetime.add_malloc('p', 0x401000, 64)
      lifetime.add_free('p', 0x401050)
      lifetime.add_use('p', 0x401080)
      result = lifetime.analyze('p')
      print(f'UAF risk: {result.uaf_risk:.2f}, danger window: {result.danger_window}')
    """

    def __init__(self):
        # 分配记录: ptr → [(insn, size)]
        self._allocs: Dict[str, List[Tuple[int, int]]] = {}
        # 使用记录: ptr → [insn_addr] (解引用或作为函数参数传递)
        self._uses: Dict[str, List[int]] = {}
        # 释放记录 (继承自 UAFUseChainTracker 或独立维护)
        self._frees: Dict[str, int] = {}

    def add_malloc(self, ptr: str, insn: int, size: int) -> None:
        self._allocs.setdefault(ptr, []).append((insn, size))

    def add_use(self, ptr: str, insn: int) -> None:
        self._uses.setdefault(ptr, []).append(insn)

    def add_free(self, ptr: str, insn: int) -> None:
        # 保留最后一个 free (多次 free 取最后)
        if ptr not in self._frees or insn > self._frees[ptr]:
            self._frees[ptr] = insn

    def analyze(self, ptr: str) -> Optional[AllocationLifetime]:
        """分析指针的完整生命周期."""
        allocs = self._allocs.get(ptr, [])
        if not allocs:
            return None

        last_alloc = max(allocs, key=lambda x: x[0])
        alloc_addr, alloc_size = last_alloc
        free_addr = self._frees.get(ptr, 0)

        # 最后一次使用 (free 之后)
        uses = self._uses.get(ptr, [])
        post_free_uses = [u for u in uses if u > free_addr] if free_addr > 0 else []

        last_use = max(post_free_uses) if post_free_uses else 0
        danger = (last_use - free_addr) if (free_addr > 0 and last_use > 0) else 0

        # 风险评分: danger_window 越大 + alloc_size 越小 → 风险越高
        # 小分配被快速重用, UAF 触发概率更高
        risk = 0.0
        if danger > 0:
            risk += 0.50 * min(1.0, danger / 200.0)
        if alloc_size < 256:
            risk += 0.30  # 小分配 → 更可能被堆分配器重用
        if len(post_free_uses) > 1:
            risk += 0.20  # 多次 free 后使用 → 高风险

        return AllocationLifetime(
            ptr_name=ptr, alloc_addr=alloc_addr,
            alloc_size=alloc_size, free_addr=free_addr,
            last_use_addr=last_use, danger_window=danger,
            uaf_risk=min(1.0, risk))

    def analyze_all(self) -> List[AllocationLifetime]:
        """分析所有已注册指针."""
        results = []
        for ptr in self._allocs:
            r = self.analyze(ptr)
            if r and r.uaf_risk > 0.1:
                results.append(r)
        results.sort(key=lambda x: x.uaf_risk, reverse=True)
        return results

    def stats(self) -> dict:
        all_results = self.analyze_all()
        high_risk = [r for r in all_results if r.uaf_risk > 0.5]
        return {
            'pointers_analyzed': len(self._allocs),
            'total_frees': len(self._frees),
            'uaf_candidates': len(all_results),
            'high_risk_uaf': len(high_risk),
            'mean_danger_window': (
                sum(r.danger_window for r in all_results)
                / max(1, len(all_results)) if all_results else 0),
        }

    def clear(self) -> None:
        self._allocs.clear()
        self._uses.clear()
        self._frees.clear()
