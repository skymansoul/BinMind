# coding: utf-8
"""堆溢出误报过滤器 — 三阶段裁剪管线.

阶段 1: 值区间分析 — alloc_size 与 write_size 的区间比较, 可证明安全则过滤
阶段 2: 分配器约束 — 考虑 glibc/ptmalloc 的对齐/最小块, 调整溢出阈值
阶段 3: 污点-汇点距离 — 外部输入到溢出点的 def-use 链长度 > 阈值 → 降权

设计依据: 堆溢出误报的三类根因:
  (a) 分析器无法证明 alloc 和 write 使用同一个 size (→ 值区间)
  (b) 分析器忽略分配器内部分配大于请求 (→ 约束模型)
  (c) 复杂的数据流中, 外部输入经过多层变换后不再具有溢出威胁 (→ 距离裁剪)
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from modules.core.compat.value_range import (
    Interval, alloc_write_size_compare, infer_interval)
from modules.core.compat.alloc_constraints import (
    get_constraints, is_overflow_infeasible)


@dataclass
class FilterResult:
    """单个堆溢出候选的过滤结果."""
    candidate: Dict[str, Any]        # 原始候选
    passed: bool                     # True = 保留 (无法证明安全), False = 过滤
    stage: str                       # 在哪个阶段被过滤
    reason: str = ''
    alloc_interval: str = ''
    write_interval: str = ''
    taint_distance: int = 0


class FalsePositiveFilter:
    """三阶段误报过滤器.

    用法:
      fpf = FalsePositiveFilter(allocator='glibc_ptmalloc', arch='x86_64')
      filtered = fpf.filter_candidates(heap_candidates, def_use_chains, ir_ops)
      # filtered 中 passed=True 的是保留的高置信度候选
    """

    def __init__(self, allocator_type: str = 'glibc_ptmalloc',
                 arch: str = 'x86_64',
                 taint_distance_threshold: int = 8,
                 value_range_enabled: bool = True,
                 alloc_constraints_enabled: bool = True,
                 taint_distance_enabled: bool = True):
        self._allocator = allocator_type
        self._arch = arch
        self._constraints = get_constraints(allocator_type, arch)
        self._taint_threshold = taint_distance_threshold
        self._enable_vr = value_range_enabled
        self._enable_ac = alloc_constraints_enabled
        self._enable_td = taint_distance_enabled
        self._stats = {'stage1_vr': 0, 'stage2_ac': 0, 'stage3_td': 0,
                       'passed': 0, 'total': 0}

    def filter_candidates(
        self, candidates: List[Dict],
        def_use_chains: Optional[Dict[int, List[int]]] = None,
        ir_ops: Optional[Dict[int, Dict]] = None,
    ) -> List[FilterResult]:
        def_use = def_use_chains or {}
        ir = ir_ops or {}
        results = []
        self._stats = {'stage1_vr': 0, 'stage2_ac': 0, 'stage3_td': 0,
                       'passed': 0, 'total': len(candidates)}

        for c in candidates:
            self._stats['total'] = len(candidates)
            fr = FilterResult(candidate=c, passed=True, stage='none')

            # 阶段 1: 值区间分析
            if self._enable_vr and self._can_do_value_range(c, def_use, ir):
                alloc_site = self._addr(c.get('alloc_site', c.get('overflow_site', 0)))
                write_site = self._addr(c.get('write_site', c.get('overflow_site', 0)))
                vr = alloc_write_size_compare(
                    alloc_site, write_site,
                    c.get('alloc_size_var', 'size'),
                    c.get('write_size_var', 'size'),
                    def_use, ir)
                fr.alloc_interval = vr['alloc_interval']
                fr.write_interval = vr['write_interval']
                if vr['provably_safe']:
                    fr.passed = False; fr.stage = 'value_range'
                    fr.reason = vr['reason']
                    self._stats['stage1_vr'] += 1
                    results.append(fr); continue

            # 阶段 2: 分配器约束
            if self._enable_ac:
                req_alloc = c.get('alloc_size', c.get('size', 0))
                write_sz = c.get('write_size', c.get('overflow_bytes', 0))
                if req_alloc > 0 and write_sz > 0:
                    if is_overflow_infeasible(req_alloc, write_sz,
                                              self._allocator, self._arch):
                        fr.passed = False; fr.stage = 'alloc_constraints'
                        usable = self._constraints.usable_size(req_alloc)
                        fr.reason = (f'malloc({req_alloc}) 实际可用 {usable}B, '
                                    f'写入 {write_sz}B 不越界')
                        self._stats['stage2_ac'] += 1
                        results.append(fr); continue

            # 阶段 3: 污点距离裁剪
            if self._enable_td:
                wsite = self._addr(c.get('write_site', c.get('overflow_site', 0)))
                taint_dist = self._compute_taint_distance(wsite, def_use, ir)
                fr.taint_distance = taint_dist
                if taint_dist > self._taint_threshold:
                    # 不直接过滤, 而是标记并降置信度
                    fr.reason = (f'外部输入到溢出点 {taint_dist} 跳 '
                                f'(>阈值 {self._taint_threshold}), 降为低置信度')
                    self._stats['stage3_td'] += 1

            if fr.passed:
                self._stats['passed'] += 1
            results.append(fr)

        return results

    def _can_do_value_range(self, c: Dict, du, ir) -> bool:
        return (c.get('alloc_size_var') or c.get('write_size_var')) and du and ir

    @staticmethod
    def _addr(v: Any) -> int:
        if isinstance(v, int): return v
        if isinstance(v, str) and v.startswith('0x'):
            try: return int(v, 16)
            except ValueError: return 0
        return 0

    def _compute_taint_distance(self, site: int,
                                 du: Dict[int, List[int]],
                                 ir: Dict[int, Dict],
                                 max_depth: int = 20) -> int:
        """BFS 计算从给定 site 到外部输入函数的 def-use 链距离."""
        visited: Set[int] = set()
        from collections import deque
        q = deque([(site, 0)])
        while q:
            addr, dist = q.popleft()
            if dist > max_depth or addr in visited: continue
            visited.add(addr)
            op = ir.get(addr, {})
            callee = op.get('callee', '').lower()
            # 检查是否命中外部输入
            if any(f in callee for f in ('read', 'recv', 'fgets', 'scanf', 'getc')):
                return dist + 1
            for src in du.get(addr, []):
                q.append((src, dist + 1))
        return max_depth + 1  # 未找到 → 返回超过上限

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    def reduction_rate(self) -> float:
        total = self._stats['total']
        if total == 0: return 0.0
        filtered = self._stats['stage1_vr'] + self._stats['stage2_ac']
        return filtered / total


def batch_filter_and_report(
    candidates: List[Dict],
    def_use: Optional[Dict[int, List[int]]] = None,
    ir: Optional[Dict[int, Dict]] = None,
    **kw,
) -> Tuple[List[Dict], Dict[str, Any]]:
    """便捷函数: 过滤并产出报告."""
    fpf = FalsePositiveFilter(**kw)
    results = fpf.filter_candidates(candidates, def_use, ir)
    retained = [r.candidate for r in results if r.passed]
    filtered_out = [r for r in results if not r.passed]
    report = {
        'total_candidates': len(candidates),
        'retained': len(retained),
        'filtered_out': len(filtered_out),
        'reduction_rate': f'{fpf.reduction_rate():.1%}',
        'by_stage': fpf.stats,
        'filtered_details': [
            {'stage': r.stage, 'reason': r.reason, 'taint_dist': r.taint_distance}
            for r in filtered_out
        ],
    }
    return retained, report
