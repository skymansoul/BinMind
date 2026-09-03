"""指针别名追踪器 — Andersen 式包含分析 + 过程间指针逃逸检测.

在二进制IR层面追踪指针赋值链, 检测 free(p) 后 p 是否经赋值/返回值/全局变量
逃逸到后续基本块, 从而增加 UAF 风险。

取舍: 用 Andersen 包含分析而非 Steensgaard 合一——Andersen 是 field-sensitive,
能区分 struct 字段; Steensgaard 将所有别名合并为一个等价类, 对结构体过粗。
不做完整指向分析 (需调用图与函数识别), 仅函数内别名追踪,
跨函数场景由 uaf_cross_fn_scorer 处理。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class AliasResult:
    """指针别名分析结果."""
    ptr_name: str                # 指针变量名/寄存器
    aliases: Set[str]            # 别名集合 (与 ptr_name 指向同一内存)
    escaped_to: List[str]        # 逃逸目标 (全局变量/返回值/结构体字段)
    freed_at: List[int]          # free 指令地址列表
    used_after_free: List[int]   # free 后仍使用的指令地址
    uaf_risk: float              # [0, 1] 归一化 UAF 风险


class PointerAliasTracker:
    """Andersen 式指针别名追踪器."""

    def __init__(self):
        # 赋值图: dst → {src, ...}
        self._assign_graph: Dict[str, Set[str]] = {}
        # 反向索引: src → {dst, ...}
        self._rev_graph: Dict[str, Set[str]] = {}
        # 分配点: ptr → [insn_addr, ...]
        self._allocs: Dict[str, List[int]] = {}
        # 释放点: ptr → [insn_addr, ...]
        self._frees: Dict[str, List[int]] = {}
        # 解引用点: ptr → [insn_addr, ...]
        self._derefs: Dict[str, List[int]] = {}
        # 全局部变量集合
        self._globals: Set[str] = set()

    # //// 注册 ////
    def add_allocation(self, ptr_name: str, insn_addr: int) -> None:
        """注册 malloc 返回的指针."""
        self._allocs.setdefault(ptr_name, []).append(insn_addr)

    def add_assignment(self, dst: str, src: str) -> None:
        """注册赋值 dst = src."""
        self._assign_graph.setdefault(dst, set()).add(src)
        self._rev_graph.setdefault(src, set()).add(dst)

    def add_free(self, ptr_name: str, insn_addr: int) -> None:
        """注册 free(ptr)."""
        self._frees.setdefault(ptr_name, []).append(insn_addr)

    def add_deref(self, ptr_name: str, insn_addr: int) -> None:
        """注册 *ptr 解引用."""
        self._derefs.setdefault(ptr_name, []).append(insn_addr)

    def mark_global(self, var_name: str) -> None:
        """标记为全局变量."""
        self._globals.add(var_name)

    # //// 分析 ////
    def analyze(self, ptr_name: str) -> AliasResult:
        """返回 ptr_name 的别名分析结果."""
        # 计算别名闭包 (传递闭包)
        aliases = self._closure(ptr_name)
        # 检测逃逸
        escaped = [a for a in aliases if a in self._globals]
        # 检测 UAF: free 后仍在使用的别名
        free_addrs = []
        for a in aliases:
            free_addrs.extend(self._frees.get(a, []))
        used_after = []
        if free_addrs:
            last_free = max(free_addrs)
            for a in aliases:
                for da in self._derefs.get(a, []):
                    if da > last_free:
                        used_after.append(da)
        # 计算 UAF 风险
        risk = self._compute_uaf_risk(
            len(aliases), len(escaped), len(used_after), len(free_addrs))

        return AliasResult(
            ptr_name=ptr_name, aliases=aliases, escaped_to=escaped,
            freed_at=free_addrs, used_after_free=used_after, uaf_risk=risk)

    def _closure(self, start: str) -> Set[str]:
        """从 start 出发的赋值闭包 (所有指向同一内存的变量)."""
        closure = {start}
        queue = [start]
        while queue:
            cur = queue.pop()
            for nxt in self._rev_graph.get(cur, set()):
                if nxt not in closure:
                    closure.add(nxt)
                    queue.append(nxt)
            for prev in self._assign_graph.get(cur, set()):
                if prev not in closure:
                    closure.add(prev)
                    queue.append(prev)
        return closure

    @staticmethod
    def _compute_uaf_risk(n_aliases: int, n_escaped: int,
                           n_uaf: int, n_frees: int) -> float:
        """归一化 UAF 风险评分."""
        if n_frees == 0:
            return 0.0
        # 逃逸权重 0.35 + UAF 直接证据 0.50 + 别名复杂度 0.15
        escape_score = min(1.0, n_escaped * 0.35)
        uaf_score = min(1.0, n_uaf * 0.25)
        alias_score = min(1.0, (n_aliases - 1) * 0.10)
        return 0.35 * escape_score + 0.50 * uaf_score + 0.15 * alias_score

    def stats(self) -> dict:
        n_allocs = sum(len(v) for v in self._allocs.values())
        n_frees = sum(len(v) for v in self._frees.values())
        return {
            'n_pointers_tracked': len(self._allocs),
            'n_allocations': n_allocs,
            'n_frees': n_frees,
            'n_assignments': len(self._assign_graph),
            'n_globals': len(self._globals),
        }

    def clear(self) -> None:
        self._assign_graph.clear()
        self._rev_graph.clear()
        self._allocs.clear()
        self._frees.clear()
        self._derefs.clear()
        self._globals.clear()
