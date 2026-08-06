"""
Heap layout inference from allocation sequences.

Models ptmalloc2 allocation behavior:
  - Small allocations come from fastbin/tcache in LIFO order
  - Large allocations come from unsorted bin (non-deterministic order)
  - Consecutive small allocations are likely adjacent in memory

If A is allocated before B and they have similar sizes, A and B are likely
adjacent. If A overflows, it can corrupt B's header/data.

Unlike ptmalloc2_state_machine (which needs runtime chunk addresses), this
module uses static inference based only on allocation sizes and ordering.
"""
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class HeapAllocSite:
    """Heap allocation site descriptor."""
    site_id: str            # unique id, e.g. "line_12_malloc"
    alloc_func: str         # malloc / calloc / realloc
    size_arg: Optional[int] # allocation size argument (if statically inferrable)
    order: int              # allocation order within function
    var_name: str = ""      # variable receiving return value


@dataclass
class AdjacencyInference:
    """Adjacency inference between two heap objects."""
    obj_a: str              # first allocated object variable name
    obj_b: str              # later allocated object variable name
    is_adjacent: bool       # likely adjacent
    confidence: float       # 0-1 confidence
    reasoning: str = ""     # reasoning basis


@dataclass
class OverflowImpact:
    """Overflow impact: what data can be overwritten if an object overflows."""
    source_var: str          # overflow source variable name
    source_size: int         # source object allocation size
    write_size_estimate: int # estimated write size
    reachable_targets: List[str] = field(default_factory=list)
    # high-value target types
    can_reach_function_ptr: bool = False
    can_reach_vtable: bool = False
    can_reach_size_field: bool = False
    exploitability_score: float = 0.0


class HeapLayoutInferrer:
    """Heap layout inferrer. Statically estimates adjacency relationships between heap objects.

    Usage:
      hli = HeapLayoutInferrer()
      sites = hli.extract_alloc_sites(decompiled_code)
      adjacencies = hli.infer_adjacency(sites)
      impact = hli.assess_overflow_impact(sites, adjacencies, 'buf', 64, 128)
    """

    _FASTBIN_MAX = 0x80      # 128 bytes (x86_64 fastbin default)
    _TCACHE_MAX = 0x410      # 1040 bytes (glibc 2.31+ default)

    _FUNC_PTR_KEYWORDS = {'callback', 'handler', 'fn', 'func', 'function_ptr'}
    _VTABLE_KEYWORDS = {'vtable', 'vptr', 'virtual', 'class', 'object'}

    def extract_alloc_sites(self, code: str) -> List[HeapAllocSite]:
        """Extract all heap allocation sites from decompiled code."""
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
        """Infer object adjacency relationships between allocation sites."""
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
        """Confidence that a and b are likely adjacent."""
        if a.size_arg is None or b.size_arg is None:
            return 0.3
        # Same size + same bin -> high probability of adjacency (LIFO)
        if abs(a.size_arg - b.size_arg) <= 8:
            return 0.85
        # Same bin class (both in fastbin/tcache) -> medium probability
        both_fastbin = (a.size_arg <= self._FASTBIN_MAX and
                        b.size_arg <= self._FASTBIN_MAX)
        both_tcache = (a.size_arg <= self._TCACHE_MAX and
                       b.size_arg <= self._TCACHE_MAX)
        if both_fastbin:
            return 0.70
        if both_tcache:
            return 0.55
        # Large allocation -> low probability (direct mmap)
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
        """Assess the impact range of a heap overflow."""
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
            score += 0.2  # at least enough to overwrite one pointer
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
