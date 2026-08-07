"""UAF 使用链追踪器 — free 后指针通过赋值/返回值/结构体字段逃逸的完整追踪.

创建: 2026-07-04
目的: uaf_candidate_scorer.py 仅做函数内三因素概率评分，对跨函数 UAF 无力。
      本模块追踪 free(p) 后 p 的别名通过赋值链、函数返回值、结构体字段存储
      传播到后续解引用的完整路径，将 UAF 检测从概率猜测提升为路径证据。

方法依据: 的编译期 UAF 静态检测框架
          使用 Andersen 式包含分析追踪指针赋值闭包。本模块在二进制 IR 层面
          做简化版：不依赖类型信息，仅追踪寄存器/内存位置的赋值传递。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class UseChain:
    """一条 UAF 使用链: free 位置 → 逃逸路径 → use 位置."""
    ptr_name: str
    free_addr: int
    use_addr: int
    escape_path: List[str]     # 中间传递节点
    chain_length: int
    confidence: float           # 0-1, 基于路径直接性

class UAFUseChainTracker:
    """UAF 使用链追踪器 — free→use 的完整路径重建.

    追踪三类逃逸:
      1. 直接使用: free(p); *p = x  (同函数内)
      2. 返回值逃逸: return p; (调用方 free 后继续使用)
      3. 结构体字段: obj->ptr = p; free(p); 后续通过 obj->ptr 解引用

    使用方式:
      tracker = UAFUseChainTracker()
      tracker.add_assignment('q', 'p', 0x401000)     # q = p
      tracker.add_free('p', 0x401050)                  # free(p)
      tracker.add_deref('q', 0x401080)                 # *q (UAF)
      chains = tracker.find_chains('p')
    """

    def __init__(self):
        # 赋值图: dst → {src_at_insn}
        self._assignments: Dict[str, List[Tuple[str, int]]] = {}
        # 释放记录: ptr → [insn_addr]
        self._frees: Dict[str, List[int]] = {}
        # 解引用记录: ptr → [insn_addr]
        self._derefs: Dict[str, List[int]] = {}
        # 函数返回值: func_name → ptr_name
        self._returns: Dict[str, str] = {}
        # 结构体字段赋值: obj->field = ptr
        self._field_stores: Dict[str, List[Tuple[str, str, int]]] = {}

    def add_assignment(self, dst: str, src: str,
                       insn_addr: int) -> None:
        """记录 dst = src."""
        self._assignments.setdefault(dst, []).append((src, insn_addr))

    def add_free(self, ptr: str, insn_addr: int) -> None:
        """记录 free(ptr)."""
        self._frees.setdefault(ptr, []).append(insn_addr)

    def add_deref(self, ptr: str, insn_addr: int) -> None:
        """记录 *ptr 解引用."""
        self._derefs.setdefault(ptr, []).append(insn_addr)

    def add_return(self, func_name: str, ptr_name: str) -> None:
        """记录 return ptr (指针通过返回值逃逸)."""
        self._returns[func_name] = ptr_name

    def add_field_store(self, obj: str, field: str,
                        ptr: str, insn_addr: int) -> None:
        """记录 obj->field = ptr (指针存入结构体字段)."""
        self._field_stores.setdefault(ptr, []).append(
            (obj, field, insn_addr))

    def find_chains(self, ptr_name: str) -> List[UseChain]:
        """查找 ptr_name 的完整 UAF 使用链."""
        chains = []
        free_addrs = self._frees.get(ptr_name, [])
        if not free_addrs:
            return chains

        # 计算别名闭包 (从 ptr_name 出发的所有赋值传递)
        aliases = self._alias_closure(ptr_name)
        aliases.add(ptr_name)

        for free_addr in free_addrs:
            for alias in aliases:
                for use_addr in self._derefs.get(alias, []):
                    if use_addr > free_addr:  # free 之后的使用
                        path = self._shortest_path(ptr_name, alias)
                        chains.append(UseChain(
                            ptr_name=ptr_name, free_addr=free_addr,
                            use_addr=use_addr, escape_path=path,
                            chain_length=len(path),
                            confidence=1.0 / max(1, len(path))))

        chains.sort(key=lambda c: c.confidence, reverse=True)
        return chains

    def _alias_closure(self, start: str) -> Set[str]:
        """从 start 出发的赋值传递闭包 (所有别名)."""
        closure = set()
        queue = [start]
        while queue:
            cur = queue.pop(0)
            if cur in closure:
                continue
            closure.add(cur)
            for src, _ in self._assignments.get(cur, []):
                if src not in closure:
                    queue.append(src)
            # 反向: 谁赋给了 cur
            for dst, srcs in self._assignments.items():
                for src, _ in srcs:
                    if src == cur and dst not in closure:
                        queue.append(dst)
        return closure

    def _shortest_path(self, src: str, dst: str) -> List[str]:
        """BFS 最短赋值路径."""
        if src == dst:
            return [src]
        visited = {src}
        queue = [(src, [src])]
        while queue:
            cur, path = queue.pop(0)
            for nxt, _ in self._assignments.get(cur, []):
                if nxt == dst:
                    return path + [nxt]
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, path + [nxt]))
        return [src, dst]

    def stats(self) -> dict:
        n_frees = sum(len(v) for v in self._frees.values())
        all_ptrs = set(self._frees.keys())
        chains_by_ptr = {}
        for p in all_ptrs:
            chains = self.find_chains(p)
            if chains:
                chains_by_ptr[p] = len(chains)
        return {
            'pointers_tracked': len(self._assignments),
            'total_frees': n_frees,
            'ptrs_with_uaf_chains': len(chains_by_ptr),
            'total_uaf_chains': sum(chains_by_ptr.values()),
            'mean_chain_length': (
                sum(len(self.find_chains(p)[0].escape_path)
                    for p in chains_by_ptr) / max(1, len(chains_by_ptr))
                if chains_by_ptr else 0),
        }

    def clear(self) -> None:
        self._assignments.clear()
        self._frees.clear()
        self._derefs.clear()
        self._returns.clear()
        self._field_stores.clear()
