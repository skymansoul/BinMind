"""
堆布局推断 — 依据分配序列建模 ptmalloc2 分配行为。
连续相似大小的分配相邻概率高, 前者溢出可破坏后者的头部/数据;
仅基于分配大小与顺序做静态推断, 无需运行时 chunk 地址。
"""
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class HeapAllocSite:
    """堆分配点描述。"""
    site_id: str            # 唯一标识, 如 "line_12_malloc"
    alloc_func: str         # malloc / calloc / realloc
    size_arg: Optional[int] # 分配大小参数 (可静态推断时)
    order: int              # 函数内分配顺序
    var_name: str = ""      # 接收返回值的变量名


@dataclass
class AdjacencyInference:
    """两个堆对象之间的相邻推断。"""
    obj_a: str              # 先分配对象的变量名
    obj_b: str              # 后分配对象的变量名
    is_adjacent: bool       # 是否可能相邻
    confidence: float       # 置信度 0-1
    reasoning: str = ""     # 推断依据


@dataclass
class OverflowImpact:
    """溢出影响: 对象溢出时可覆盖的数据。"""
    source_var: str          # 溢出源变量名
    source_size: int         # 源对象分配大小
    write_size_estimate: int # 估算写入大小
    reachable_targets: List[str] = field(default_factory=list)
    # 高价值目标类型
    can_reach_function_ptr: bool = False
    can_reach_vtable: bool = False
    can_reach_size_field: bool = False
    exploitability_score: float = 0.0


class HeapLayoutInferrer:
    """堆布局推断器 — 静态估计堆对象间的相邻关系。

    用法: extract_alloc_sites → infer_adjacency → assess_overflow_impact。
    """

    _FASTBIN_MAX = 0x80      # 128 bytes (x86_64 fastbin default)
    _TCACHE_MAX = 0x410      # 1040 bytes (glibc 2.31+ default)

    _FUNC_PTR_KEYWORDS = {'callback', 'handler', 'fn', 'func', 'function_ptr'}
    _VTABLE_KEYWORDS = {'vtable', 'vptr', 'virtual', 'class', 'object'}

    def extract_alloc_sites(self, code: str) -> List[HeapAllocSite]:
        """从反编译代码中提取全部堆分配点。"""
        import re
        sites = []
        call_pat = re.compile(r'(\b[a-zA-Z_]\w{0,31}\b)\s*\(([^)]*)\)')
        assign_pat = re.compile(r'(\b[a-zA-Z_]\w{0,31}\b)\s*=\s*(.+)')
        alloc_funcs = frozenset({'malloc', 'calloc', 'realloc', 'aligned_alloc'})

        for order, line in enumerate(code.split('\n')):
            m = call_pat.search(line)
            if not m or m.group(1).strip() not in alloc_funcs:
                continue
            func = m.group(1).strip()
            args = self._split_args(m.group(2))
            size = None
            if func == 'calloc' and len(args) >= 2:
                try:
                    size = int(args[0].strip()) * int(args[1].strip())
                except ValueError:
                    pass
            elif args:
                try:
                    size = int(args[0].strip())
                except ValueError:
                    pass
            var_name = ""
            am = assign_pat.search(line)
            if am:
                var_name = am.group(1).strip()
            sites.append(HeapAllocSite(
                site_id=f'line_{order}_{func}',
                alloc_func=func, size_arg=size,
                order=order, var_name=var_name,
            ))
        return sites

    def infer_adjacency(self, sites: List[HeapAllocSite]) -> List[AdjacencyInference]:
        """推断分配点之间的对象相邻关系。"""
        sorted_sites = sorted(sites, key=lambda s: s.order)
        inferences = []
        for i in range(len(sorted_sites)):
            for j in range(i + 1, min(i + 4, len(sorted_sites))):
                a, b = sorted_sites[i], sorted_sites[j]
                confidence = self._adjacency_confidence(a, b)
                if confidence < 0.3:
                    continue
                reasoning = self._adjacency_reasoning(a, b)
                inferences.append(AdjacencyInference(
                    obj_a=a.var_name or a.site_id,
                    obj_b=b.var_name or b.site_id,
                    is_adjacent=confidence >= 0.5,
                    confidence=round(confidence, 3),
                    reasoning=reasoning,
                ))
        return inferences

    def _adjacency_confidence(self, a: HeapAllocSite, b: HeapAllocSite) -> float:
        """a 与 b 可能相邻的置信度。"""
        if a.size_arg is None or b.size_arg is None:
            return 0.3
        # 同大小同bin → 相邻概率高 (LIFO)
        if abs(a.size_arg - b.size_arg) <= 8:
            return 0.85
        # 同bin类别 (均在 fastbin/tcache) → 中等概率
        both_fastbin = (a.size_arg <= self._FASTBIN_MAX and
                        b.size_arg <= self._FASTBIN_MAX)
        both_tcache = (a.size_arg <= self._TCACHE_MAX and
                       b.size_arg <= self._TCACHE_MAX)
        if both_fastbin:
            return 0.70
        if both_tcache:
            return 0.55
        # 大分配 → 低概率 (直接mmap)
        if a.size_arg > self._TCACHE_MAX or b.size_arg > self._TCACHE_MAX:
            return 0.15
        return 0.35

    def _adjacency_reasoning(self, a: HeapAllocSite, b: HeapAllocSite) -> str:
        conf = self._adjacency_confidence(a, b)
        if conf >= 0.80:
            return f'same size ({a.size_arg}B) consecutive allocs, likely adjacent'
        if conf >= 0.55:
            return f'both in tcache range ({a.size_arg}B vs {b.size_arg}B), medium probability'
        return f'size mismatch ({a.size_arg}B vs {b.size_arg}B), low probability'

    def assess_overflow_impact(
        self, sites: List[HeapAllocSite],
        adjacencies: List[AdjacencyInference],
        overflow_var: str,
        source_size: int,
        write_amount: int,
    ) -> OverflowImpact:
        """评估堆溢出的影响范围。"""
        source_site = None
        for s in sites:
            if s.var_name == overflow_var:
                source_site = s
                break
        adj_map: Dict[str, List[str]] = defaultdict(list)
        for adj in adjacencies:
            adj_map[adj.obj_a].append(adj.obj_b)

        impact = OverflowImpact(
            source_var=overflow_var,
            source_size=source_size or (source_site.size_arg if source_site else 0),
            write_size_estimate=write_amount,
        )

        overflow_bytes = write_amount - (source_site.size_arg if source_site else 0)
        if overflow_bytes <= 0:
            impact.exploitability_score = 0.0
            return impact

        targets = adj_map.get(overflow_var, [])
        impact.reachable_targets = targets

        for tgt_name in targets:
            tgt_lower = tgt_name.lower()
            if any(kw in tgt_lower for kw in self._FUNC_PTR_KEYWORDS):
                impact.can_reach_function_ptr = True
            if any(kw in tgt_lower for kw in self._VTABLE_KEYWORDS):
                impact.can_reach_vtable = True
            if 'size' in tgt_lower or 'len' in tgt_lower:
                impact.can_reach_size_field = True

        score = 0.0
        if impact.can_reach_function_ptr:
            score += 0.5
        if impact.can_reach_vtable:
            score += 0.4
        if impact.can_reach_size_field:
            score += 0.3
        if overflow_bytes >= 8:
            score += 0.2  # 至少足以覆盖一个指针
        score = min(1.0, score * (1.0 if impact.reachable_targets else 0.3))
        impact.exploitability_score = round(score, 3)
        return impact

    @staticmethod
    def _split_args(args_str: str) -> List[str]:
        parts = []; depth = 0; current = []
        for ch in args_str:
            if ch == '(': depth += 1
            elif ch == ')': depth -= 1
            if ch == ',' and depth == 0:
                parts.append(''.join(current).strip()); current = []
            else:
                current.append(ch)
        if current: parts.append(''.join(current).strip())
        return parts
