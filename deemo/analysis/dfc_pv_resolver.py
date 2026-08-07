"""DFC-PV 别名解析器 — 多跳别名链可达性 + AOI (Allocation Object Identity) 追踪.

核心区别于旧 DFSV: 以分配对象而非变量名为身份判定基础.
当变量被重新分配 (malloc/calloc/realloc) 时, 旧 AOI 消亡, 新 AOI 诞生,
同一变量名的两次 free 若指向不同 AOI 则非 double-free.
"""

from typing import Dict, List, Set, Tuple, Optional

from analysis.dfc_pv_types import (
    AllocSite, FreeSite, AliasEdge, NullAssign, ReallocSite)


class AOINode:
    """分配对象身份节点."""

    _counter = 0

    def __init__(self, alloc_line: int, var: str):
        self.id = AOINode._counter
        AOINode._counter += 1
        self.alloc_line = alloc_line
        self.alloc_var = var
        self.freed = False
        self.freed_line = 0
        self.nulled_vars: Set[str] = set()
        self.aliases: Set[str] = {var}

    def __repr__(self):
        return f'AOI(#{self.id} L{self.alloc_line} var={self.alloc_var})'


class AliasResolver:
    """别名图构建与可达性查询."""

    def __init__(self, aliases: List[AliasEdge]):
        self.edges: Dict[str, List[AliasEdge]] = {}
        for a in aliases:
            self.edges.setdefault(a.target, []).append(a)

    def reachable(self, src: str, dst: str,
                  visited: Optional[Set[str]] = None) -> bool:
        """src 的别名链上是否能到达 dst."""
        if src == dst:
            return True
        if visited is None:
            visited = set()
        if src in visited:
            return False
        visited.add(src)
        for edge in self.edges.get(src, []):
            if edge.source == dst:
                return True
            if self.reachable(edge.source, dst, visited):
                return True
        return False

    def resolve_chain(self, var: str, visited: Optional[Set[str]] = None,
                      depth: int = 0) -> List[str]:
        """返回 var 能到达的所有原始变量名."""
        if depth > 20:
            return [var]
        if visited is None:
            visited = set()
        if var in visited:
            return []
        visited.add(var)
        chain = [var]
        for edge in self.edges.get(var, []):
            chain.extend(self.resolve_chain(edge.source, visited, depth + 1))
        return chain

    def bidirectional_alias(self, a: str, b: str) -> bool:
        """双向检查 a 和 b 是否互为别名."""
        return self.reachable(a, b) or self.reachable(b, a)


class AOITracker:
    """AOI 生命周期追踪器: 关联 free/realloc/NULL 到具体分配对象."""

    def __init__(self, allocs: List[AllocSite], reallocs: List[ReallocSite],
                 nulls: List[NullAssign], aliases: List[AliasEdge]):
        self.allocs = allocs
        self.reallocs = reallocs
        self.nulls = nulls
        self.resolver = AliasResolver(aliases)
        self.nodes: List[AOINode] = []
        self._build()

    def _build(self):
        """构建 AOI 节点: 每个分配点创建一个节点."""
        for alloc in self.allocs:
            node = AOINode(alloc.line, alloc.var)
            # 传播别名: 如果 alloc.var 有别名, 同时关联
            chain = self.resolver.resolve_chain(alloc.var)
            for alias_var in chain:
                node.aliases.add(alias_var)
            self.nodes.append(node)

    def get_aoi_for_free(self, free_site: FreeSite) -> List[AOINode]:
        """返回 free_site 可能指向的 AOI 节点列表."""
        result = []
        free_chain = self.resolver.resolve_chain(free_site.base_var) + \
                     self.resolver.resolve_chain(free_site.var_expr)
        free_set = set(free_chain)
        # 数组别名: arr[i] 的 free 需匹配 arr 的 AOI
        arr_base = free_site.base_var
        free_set.add(arr_base)

        for node in self.nodes:
            if free_set & node.aliases:
                result.append(node)
        return result

    def has_realloc_between(self, var: str, line_a: int,
                             line_b: int) -> bool:
        """line_a 和 line_b 之间是否有对 var 的重新分配.

        支持 *ptr 形式: var=pp, r.var=*pp 时通过去星号匹配.
        """
        chain = set(self.resolver.resolve_chain(var))
        var_stripped = var.lstrip('*').strip()
        chain.add(var_stripped)
        for r in self.reallocs:
            if line_a < r.line < line_b:
                r_stripped = r.var.lstrip('*').strip()
                if r.var in chain or r.var == var or \
                   r_stripped in chain or r_stripped == var_stripped:
                    return True
        return False

    def has_null_between(self, var: str, line_a: int,
                          line_b: int) -> bool:
        """line_a 和 line_b 之间是否有对 var 的 NULL 赋值."""
        chain = set(self.resolver.resolve_chain(var))
        for n in self.nulls:
            if line_a < n.line < line_b:
                if n.var in chain or n.var == var:
                    return True
        return False

    def has_unconditional_null_between(self, var: str, line_a: int,
                                        line_b: int) -> bool:
        """line_a 和 line_b 之间是否有对 var 的无条件 NULL 赋值.

        包含 line_a 同行 (宏展开后 free 和 NULL 在同一行).
        """
        chain = set(self.resolver.resolve_chain(var))
        for n in self.nulls:
            if line_a <= n.line < line_b and not n.conditional:
                if n.var in chain or n.var == var:
                    return True
        return False

    def is_reallocated_after(self, var: str, line: int) -> bool:
        """line 之后 var 是否被重新分配 (新的 malloc 赋值)."""
        chain = set(self.resolver.resolve_chain(var))
        for r in self.reallocs:
            if r.line > line and (r.var in chain or r.var == var):
                return True
        return False

    def is_null_before_free(self, var: str, free_line: int) -> bool:
        """free_line 之前 var 是否被无条件置 NULL (使 free 成为 no-op).

        同行 realloc (语句序优先) 使 NULL 失效.
        """
        chain = set(self.resolver.resolve_chain(var))
        for n in self.nulls:
            if n.line < free_line and not n.conditional:
                if n.var in chain or n.var == var:
                    has_realloc = False
                    for r in self.reallocs:
                        if n.line < r.line <= free_line and \
                           (r.var in chain or r.var == var):
                            has_realloc = True
                            break
                    if not has_realloc:
                        return True
        return False

    def get_aoi_at_line(self, var: str, line: int) -> List['AOINode']:
        """返回 line 时刻有效的 AOI 节点 (在 line 之前分配且未被 free)."""
        chain = set(self.resolver.resolve_chain(var))
        result = []
        for node in self.nodes:
            if node.alloc_line < line and node.alloc_var in chain:
                result.append(node)
        return result
