"""
乘积链图传播 — 构建变量间乘法依赖图, worklist传播溢出约束.


理论支撑:
  - Kildall: def-use lattice → worklist fixpoint
  - Cousot & Cousot: widening/narrowing 保证终止

架构:
  ProductChainGraph: 构建乘法依赖图 (Node=变量, Edge=乘法关系)
  ProductChainPropagator: Worklist传播范围约束 → fixpoint
  analyze_product_chain_deep: 深度乘积链分析主入口
"""


import re
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from analysis.int_overflow_helpers import (
    _SIZEOF_MAP,
    find_overflow_guards,
    infer_var_range,
    assess_overflow,
)

# 平台相关的 SIZE_MAX
_SIZEMAX = {
    'x86': 0xFFFFFFFF,
    'x86_64': 0xFFFFFFFFFFFFFFFF,
    'arm32': 0xFFFFFFFF,
    'aarch64': 0xFFFFFFFFFFFFFFFF,
    'mips32': 0xFFFFFFFF,
    'default': 0xFFFFFFFFFFFFFFFF,
}


@dataclass
class ProductEdge:
    """乘积图中的边: var = other * const (或 other = var * const)."""
    src: str          # 源变量
    dst: str          # 目标变量
    multiplier: int   # 乘数因子
    line_no: int = 0


class ProductChainGraph:
    """构建变量间的乘法依赖图.

    Node = 变量名, Edge = 乘法关系.
    用于 worklist 传播溢出约束: 若 a = b * k 且 b ∈ [0, N],
    则 a ∈ [0, k*N], 沿图传播到所有下游变量.

    Complexity: O(|V| + |E|) per propagation pass, bounded by |V| fixpoint iterations.
    """

    def __init__(self):
        self._adj: Dict[str, List[ProductEdge]] = {}  # 邻接表 (出边)
        self._rev: Dict[str, List[ProductEdge]] = {}  # 逆邻接表 (入边)
        self._nodes: Set[str] = set()

    def add_edge(self, src: str, dst: str, multiplier: int, line: int = 0):
        """添加乘积边: dst = src * multiplier."""
        e = ProductEdge(src=src, dst=dst, multiplier=multiplier, line_no=line)
        self._adj.setdefault(src, []).append(e)
        self._rev.setdefault(dst, []).append(e)
        self._nodes.add(src); self._nodes.add(dst)

    def build_from_source(self, source: str) -> 'ProductChainGraph':
        """从源码构建乘积链图 (识别 a = b * k 模式)."""
        lines = source.splitlines()
        # 乘法赋值: a = b * const
        mul_re = re.compile(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\d+)\s*;?')
        # sizeof 乘法: a = b * sizeof(T)
        sz_re = re.compile(
            r'(\w+)\s*=\s*(\w+)\s*\*\s*sizeof\s*\(\s*(\w+(?:\s*\*)?)\s*\)',
            re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            for m in mul_re.finditer(line):
                dst, src, k = m.group(1), m.group(2), int(m.group(3))
                self.add_edge(src, dst, k, i)
            for m in sz_re.finditer(line):
                dst, src, tp = m.group(1), m.group(2), m.group(3).strip()
                k = _SIZEOF_MAP.get(tp.lower(), 0)
                if k > 0:
                    self.add_edge(src, dst, k, i)
        return self

    def sources(self) -> Set[str]:
        """入度为0的源变量 (外部输入)."""
        return {n for n in self._nodes
                if n not in self._rev or len(self._rev.get(n, [])) == 0}

    def sinks(self) -> Set[str]:
        """出度为0的汇变量 (最终分配)."""
        return {n for n in self._nodes
                if n not in self._adj or len(self._adj.get(n, [])) == 0}

    def predecessors(self, var: str) -> List[ProductEdge]:
        return self._rev.get(var, [])

    def successors(self, var: str) -> List[ProductEdge]:
        return self._adj.get(var, [])

    def __contains__(self, var: str) -> bool:
        return var in self._nodes

    def __len__(self) -> int:
        return len(self._nodes)


class ProductChainPropagator:
    """Worklist-based constraint propagation over ProductChainGraph.

    Lattice: each variable → range [lo, hi].
    ⊥ (bottom) = unknown range
    ⊤ (top)    = [0, SIZE_MAX]

    Propagation: if a ∈ [lo_a, hi_a] and b = a * k,
    then b ∈ [lo_a * k, hi_a * k] (monitor for wrap-around).

    Fixpoint: iterate until no range changes or max_iter reached.
    """

    def __init__(self, graph: ProductChainGraph, size_max: int = 0xFFFFFFFFFFFFFFFF):
        self._g = graph
        self._smax = size_max
        self._ranges: Dict[str, Tuple[int, int]] = {}

    def propagate(self,
                  seeds: Dict[str, Tuple[int, int]],
                  max_iter: int = 50) -> Dict[str, Tuple[int, int]]:
        """从种子变量出发, worklist 传播范围约束.

        Args:
            seeds: {var: (lo, hi)} — 已知范围的变量
            max_iter: 最大迭代次数

        Returns:
            {var: (lo, hi)} — 所有可推断范围
        """
        self._ranges = dict(seeds)
        worklist = deque(seeds.keys())
        iters = 0

        while worklist and iters < max_iter:
            var = worklist.popleft()
            iters += 1
            if var not in self._ranges:
                continue
            lo, hi = self._ranges[var]

            for edge in self._g.successors(var):
                dst_lo = lo * edge.multiplier
                dst_hi = min(hi * edge.multiplier, self._smax)
                # 溢出检测: 乘法回绕 → 置顶
                if dst_lo > dst_hi:
                    dst_hi = self._smax

                old = self._ranges.get(edge.dst)
                if old is None:
                    self._ranges[edge.dst] = (dst_lo, dst_hi)
                    worklist.append(edge.dst)
                else:
                    # Lattice join ⊔: 取最宽区间
                    new_lo = min(old[0], dst_lo)
                    new_hi = max(old[1], dst_hi)
                    if (new_lo, new_hi) != old:
                        self._ranges[edge.dst] = (new_lo, new_hi)
                        worklist.append(edge.dst)

        return dict(self._ranges)

    def get_range(self, var: str) -> Optional[Tuple[int, int]]:
        return self._ranges.get(var)


def _collect_path_multipliers(graph: ProductChainGraph,
                              sink: str) -> Dict[str, int]:
    """回溯乘积链, 计算每个源变量到 sink 的累积乘数.

    使用 BFS 从 sink 反向遍历, 路径乘数 = ∏(边乘数).
    """
    multipliers: Dict[str, int] = {sink: 1}
    worklist = deque([sink])

    while worklist:
        cur = worklist.popleft()
        cur_mult = multipliers[cur]
        for edge in graph.predecessors(cur):
            new_mult = cur_mult * edge.multiplier
            if edge.src not in multipliers:
                multipliers[edge.src] = new_mult
                worklist.append(edge.src)
            else:
                # ⊔: take the larger multiplier (worst case)
                multipliers[edge.src] = max(multipliers[edge.src], new_mult)

    # 只返回源变量 (入度为0)
    sources = graph.sources()
    return {k: v for k, v in multipliers.items() if k in sources}


def analyze_product_chain_deep(source: str,
                               platform: str = "x86_64") -> List:
    """深度乘积链分析: 构建乘积图 → worklist传播 → 阈值判定.

    这是 I-GUARD 加深后的主入口, 替代简单的 regex→除法 流水线.
    """
    from analysis.int_overflow_symbolic import (
        IntOverflowSymbolicAnalyzer, SymbolicProduct, OverflowThreshold,
    )

    sizemax = _SIZEMAX.get(platform, _SIZEMAX['default'])
    graph = ProductChainGraph().build_from_source(source)

    results = []
    analyzer = IntOverflowSymbolicAnalyzer(platform)

    # 对每个 sink 变量 (最终分配), 沿乘积链回溯计算溢出风险
    for sink in graph.sinks():
        # 找到所有到达 sink 的乘积路径
        path_multipliers = _collect_path_multipliers(graph, sink)
        if not path_multipliers:
            continue

        # 对每个到达 sink 的源变量计算溢出阈值
        for src_var, path_mult in path_multipliers.items():
            if path_mult == 0:
                continue
            threshold = sizemax // path_mult
            guards = find_overflow_guards(source, src_var, threshold)
            var_lo, var_hi = infer_var_range(source, src_var, platform)
            verdict, confidence = assess_overflow(
                src_var, threshold, guards, var_lo, var_hi, source)

            sp = SymbolicProduct(
                result_var=sink, operand_var=src_var,
                constant=path_mult, line_no=0)
            results.append(OverflowThreshold(
                product=sp, threshold=threshold, size_max=sizemax,
                var_range_lo=var_lo, var_range_hi=var_hi,
                is_guarded=len(guards) > 0,
                guard_condition="; ".join(guards) if guards else "",
                verdict=verdict, confidence=confidence,
            ))

    return results


def combine_with_value_range(
    symbolic_results: List,
    verifier_results: List[dict],
    code: str = "",
) -> Tuple[List[dict], Dict[str, int]]:
    """融合符号化分析和值范围分析的判定结果.

    策略: 符号化分析作为前置过滤, 值范围分析作为精化.
      - 符号化判定 SAFE → 过滤 (高置信度)
      - 符号化判定 OVERFLOW → 保留
      - 符号化 UNCERTAIN → 委托给值范围分析
    """
    stats = {'symbolic_safe': 0, 'symbolic_overflow': 0,
             'vr_safe': 0, 'vr_confirmed': 0, 'total': len(verifier_results)}

    safe_vars = {r.product.result_var for r in symbolic_results if r.verdict == "SAFE"}
    overflow_vars = {r.product.result_var for r in symbolic_results if r.verdict == "OVERFLOW"}

    refined = []
    for f in verifier_results:
        expr = f.get('expr', f.get('expression', ''))
        var_match = re.match(r'(\w+)\s*=', expr) if expr else None
        var = var_match.group(1) if var_match else ""

        if var in safe_vars:
            f['severity'] = 'Info'
            f['confidence'] = 0.10
            f['iof_verdict'] = 'symbolic_safe'
            stats['symbolic_safe'] += 1
        elif var in overflow_vars:
            f['severity'] = 'Critical'
            f['confidence'] = max(f.get('confidence', 0.5), 0.80)
            f['iof_verdict'] = 'symbolic_overflow'
            stats['symbolic_overflow'] += 1
        refined.append(f)

    return refined, stats


__all__ = [
    'ProductEdge', 'ProductChainGraph', 'ProductChainPropagator',
    'analyze_product_chain_deep', '_collect_path_multipliers',
    'combine_with_value_range',
]
