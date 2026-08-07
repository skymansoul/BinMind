"""累积写入溢出检测 — 多个SafeWrite在循环内累加后溢出分配边界.

现有检测器逐条检查 memcpy(buf+off,src,n) 是否 off+n>alloc_sz.
若每次拷贝64B到256B缓冲区,循环5次,每次单独安全但累积320>256溢出.
方法: 聚合同一分配的写入偏移+大小, 乘循环上界, 检查累积覆盖范围.
"""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from core.heap_overflow_detector import HeapAllocSite, HeapStore, HeapOverflowCandidate


@dataclass
class CumulativeWriteGroup:
    """同一分配目标的写入聚合."""
    alloc: HeapAllocSite
    writes: List[HeapStore] = field(default_factory=list)
    loop_bound: int = 0          # 0=不在循环中, >0=循环上界
    loop_var: str = ""


def detect_cumulative_overflow(
    ir_lines: list[str],
    allocs: list[HeapAllocSite],
    stores: list[HeapStore],
) -> list[HeapOverflowCandidate]:
    """检测累积写入溢出: 多个小写入在循环/顺序中覆盖超出缓冲区.

    返回: 按置信度降序排列的候选列表.
    """
    if not allocs or not stores:
        return []

    candidates: list[HeapOverflowCandidate] = []
    # 按分配变量分组写入
    groups = _group_writes_by_alloc(allocs, stores, ir_lines)

    for group in groups.values():
        if len(group.writes) < 1:
            continue
        result = _check_cumulative_group(group, ir_lines)
        if result:
            candidates.append(result)

    candidates.sort(key=lambda c: -c.confidence)
    return candidates


def _group_writes_by_alloc(
    allocs: list[HeapAllocSite],
    stores: list[HeapStore],
    ir_lines: list[str],
) -> Dict[str, CumulativeWriteGroup]:
    """将写入按分配变量分组, 并推断循环上下文."""
    groups: Dict[str, CumulativeWriteGroup] = {}
    for a in allocs:
        if a.result_var:
            groups[a.result_var] = CumulativeWriteGroup(alloc=a)

    for s in stores:
        base = s.base_var
        if base not in groups:
            continue
        groups[base].writes.append(s)
        # 推断循环上界: 检查写入点前方30行内的循环头
        lb, lv = _infer_context_loop(ir_lines, s.pc)
        if lb > 0:
            if groups[base].loop_bound == 0 or lb < groups[base].loop_bound:
                groups[base].loop_bound = lb
                groups[base].loop_var = lv

    return groups


def _infer_context_loop(
    ir_lines: list[str], write_pc: int,
) -> Tuple[int, str]:
    """在 write_pc 的上下文推断循环上界."""
    for i in range(max(0, write_pc - 30), min(len(ir_lines), write_pc)):
        line = ir_lines[i]
        # for (i=0; i<N; i++) 模式 — 支持 &&/|| 复合条件
        fm = re.search(
            r'for\s*\([^;]*;\s*(\w+)\s*(<=|<|!=)\s*(\w+|\d+)[^;]*;', line)
        if fm:
            bv = fm.group(3)
            try:
                return int(bv, 0), fm.group(1)
            except ValueError:
                t = _trace_constant(ir_lines, bv, i)
                if t > 0:
                    return t, fm.group(1)
        # while (i < N) 模式 — 支持 &&/|| 复合条件
        wm = re.search(
            r'while\s*\(\s*(\w+)\s*(<=|<)\s*(\w+|\d+)[^)]*\)', line)
        if wm:
            bv = wm.group(3)
            try:
                return int(bv, 0), wm.group(1)
            except ValueError:
                t = _trace_constant(ir_lines, bv, i)
                if t > 0:
                    return t, wm.group(1)
    return 0, ""


def _trace_constant(ir_lines: list[str], var: str, max_pc: int) -> int:
    """追踪变量赋值获取常量."""
    pat = re.compile(rf'\b{re.escape(var)}\s*=\s*(\d+|0x[0-9a-fA-F]+)')
    for i in range(max_pc, -1, -1):
        m = pat.search(ir_lines[i])
        if m:
            try: return int(m.group(1), 0)
            except ValueError: pass
    for i in range(max_pc + 1, len(ir_lines)):
        m = pat.search(ir_lines[i])
        if m:
            try: return int(m.group(1), 0)
            except ValueError: pass
    return -1


def _check_cumulative_group(
    group: CumulativeWriteGroup, ir_lines: list[str],
) -> Optional[HeapOverflowCandidate]:
    """检查累积写入组是否溢出."""
    alloc_sz = group.alloc.size_arg
    if alloc_sz <= 0: return None
    lb = group.loop_bound
    if lb > 0 and len(group.writes) >= 1:
        return _check_loop_cumulative(group, alloc_sz, lb, ir_lines)
    if len(group.writes) >= 2:
        return _check_sequential_cumulative(group, alloc_sz)
    return None


def _check_loop_cumulative(
    group: CumulativeWriteGroup, alloc_sz: int, loop_bound: int,
    ir_lines: list[str],
) -> Optional[HeapOverflowCandidate]:
    """循环累积: N次迭代 × 写入大小 → 累积偏移溢出."""
    writes = sorted(group.writes, key=lambda w: w.offset)
    max_off, tw = 0, 0
    for w in writes:
        max_off = max(max_off, w.offset)
        tw += w.store_size if w.store_size > 0 else 0
    # 模式1: 总和 × 循环次数
    if tw > 0:
        cum = tw * loop_bound
        if cum > alloc_sz:
            return HeapOverflowCandidate(
                alloc_site=group.alloc, overflow_store=writes[-1],
                overflow_bytes=cum - alloc_sz, confidence=0.72,
                description=(f'{group.alloc.alloc_func}({alloc_sz}) '
                    f'循环{loop_bound}轮×{tw}B={cum}B > {alloc_sz}B → 累积溢出{cum - alloc_sz}B'))
    # 模式2: 偏移递增
    fo, lo = (writes[0].offset if writes else 0), max_off
    ws = writes[0].store_size if writes else 0
    if lo > fo and ws > 0:
        step = ((lo - fo) / (len(writes) - 1)) if len(writes) > 1 else ws
        tr = int(fo + step * loop_bound + ws)
        if tr > alloc_sz:
            return HeapOverflowCandidate(
                alloc_site=group.alloc, overflow_store=writes[-1],
                overflow_bytes=tr - alloc_sz, confidence=0.68,
                description=(f'{group.alloc.alloc_func}({alloc_sz}) '
                    f'循环{loop_bound}轮,步长{int(step)}B:累积范围{tr}B>{alloc_sz}B → 溢出'))
    # 模式3: 同偏移重复写 memcpy(buf,src,64) 循环5次→320
    if lo == fo and ws > 0 and ws * loop_bound > alloc_sz:
        total = ws * loop_bound
        return HeapOverflowCandidate(
            alloc_site=group.alloc, overflow_store=writes[-1],
            overflow_bytes=total - alloc_sz, confidence=0.70,
            description=(f'{group.alloc.alloc_func}({alloc_sz}) '
                f'同偏移{fo}处循环{loop_bound}轮×{ws}B={total}B > {alloc_sz}B → 溢出'))
    return None


def _check_sequential_cumulative(
    group: CumulativeWriteGroup, alloc_sz: int,
) -> Optional[HeapOverflowCandidate]:
    """顺序非循环累积: 多个memcpy到同一缓冲区,不同偏移, 每次单独安全但累积溢出.

    仅当每次写入单独安全 (offset+size <= alloc_sz) 时才报告 —
    若某个写入自身已溢出, 基础检测器已捕获, 无需累积二次报告.
    """
    writes = sorted(group.writes, key=lambda w: w.offset)
    # 若任一次写入自身已溢出, 跳过 (基础检测器已覆盖)
    for w in writes:
        if w.offset >= 0 and w.store_size > 0:
            if w.offset + w.store_size > alloc_sz:
                return None  # 单次溢出, 非累积场景
        if w.offset >= alloc_sz:
            return None  # 单次偏移溢出, 非累积场景
    min_off = min(w.offset for w in writes)
    max_off = max(w.offset + max(w.store_size, 1) for w in writes)
    cov = max_off - min_off
    if cov > alloc_sz:
        return HeapOverflowCandidate(
            alloc_site=group.alloc, overflow_store=writes[-1],
            overflow_bytes=cov - alloc_sz, confidence=0.55,
            description=(f'{group.alloc.alloc_func}({alloc_sz}) '
                f'{len(writes)}个写入覆盖{cov}B > {alloc_sz}B → 累积溢出{cov - alloc_sz}B'))
    total_sz = sum(w.store_size for w in writes if w.store_size > 0)
    if total_sz > alloc_sz and len(writes) >= 2:
        return HeapOverflowCandidate(
            alloc_site=group.alloc, overflow_store=writes[-1],
            overflow_bytes=total_sz - alloc_sz,
            confidence=0.50 if all(w.offset == writes[0].offset for w in writes) else 0.62,
            description=(f'{group.alloc.alloc_func}({alloc_sz}) '
                f'{len(writes)}个写入总计{total_sz}B > {alloc_sz}B → 同偏移重复写入溢出'))
    return None


def integrate_cumulative_check(
    candidates: list[HeapOverflowCandidate],
    allocs: list[HeapAllocSite], ir_lines: list[str],
) -> list[HeapOverflowCandidate]:
    """在现有候选列表基础上追加累积溢出检测. 返回更新后的候选列表(去重)."""
    from core.heap_store_extractor import track_heap_stores
    covered: Set[Tuple[int, str]] = {(c.alloc_site.pc, c.overflow_store.base_var)
                                       for c in candidates}
    for a in allocs:
        if not a.result_var:
            continue
        stores = track_heap_stores(ir_lines, a)
        remaining = [s for s in stores if (a.pc, s.base_var) not in covered]
        if remaining:
            for nc in detect_cumulative_overflow(ir_lines, [a], remaining):
                dup = next((i for i, ec in enumerate(candidates)
                           if ec.alloc_site.pc == nc.alloc_site.pc
                           and ec.overflow_store.pc == nc.overflow_store.pc), None)
                if dup is not None:
                    if nc.confidence > candidates[dup].confidence:
                        candidates[dup] = nc
                else:
                    candidates.append(nc)
    candidates.sort(key=lambda c: -c.confidence)
    return candidates


__all__ = [
    'CumulativeWriteGroup',
    'detect_cumulative_overflow',
    'integrate_cumulative_check',
    '_infer_context_loop',
    '_check_loop_cumulative',
    '_check_sequential_cumulative',
]
