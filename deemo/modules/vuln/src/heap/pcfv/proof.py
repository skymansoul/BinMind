"""安全证明策略 — 仅接受有充分证据的安全判定.

创建: 2026-04-22
设计决策:
  - 过滤安全的证据等级必须不低于"常量偏移+可用范围"或"支配守卫上界",
    禁止在 offset 未知时仅凭"未检出污点"过滤 — 该模式是基线 Phase1
    在无数据流边注册时误杀真阳性的根因.
  - 分配器舍入padding: offset ∈ [requested, usable) 且 offset 为常量
    或上界被支配守卫限制 → 编译器合法访问.
"""
from typing import List, Optional, Tuple

from .types import (Verdict, ProofRule, Evidence, ValueInfo,
                    FindingVerdict, GuardConstraint, Provenance)


class SafetyProver:
    """安全判定: 返回可证明安全的规则列表(空=无法证明)."""

    def __init__(self):
        self._stats = {r: 0 for r in ProofRule}

    def prove(self, fv: FindingVerdict,
              guards: List[GuardConstraint],
              related_regs: Tuple[str, ...]) -> List[Evidence]:
        evs: List[Evidence] = []
        alloc = fv.alloc_size
        usable = fv.usable_size
        offset = fv.offset_info
        size = fv.copy_size_info

        off_lo = offset.interval_lo if offset is not None else None
        off_hi = offset.interval_hi if offset is not None else None
        size_hi = size.interval_hi if size is not None else None

# 规则1: 常量偏移+确定大小 ≤ 可用范围
        if alloc is not None and usable is not None:
            if (offset is not None and offset.is_constant
                    and offset.constant_value is not None):
                c = offset.constant_value
                if size_hi is not None and size_hi >= 0 and c + size_hi <= usable:
                    if c >= alloc:
                        evs.append(Evidence(
                            rule=ProofRule.ALLOC_PADDING,
                            detail=(f'const offset {c} in padding '
                                    f'[{alloc},{usable}) size≤{size_hi}'),
                            confidence=0.93))
                    else:
                        evs.append(Evidence(
                            rule=ProofRule.CONSTANT_BOUNDED,
                            detail=(f'const offset {c}+{size_hi}≤usable '
                                    f'{usable}'),
                            confidence=0.97))
                elif c < 0:
                    evs.append(Evidence(
                        rule=ProofRule.CONSTANT_BOUNDED,
                        detail=f'negative const offset {c} (backward write)',
                        confidence=0.85))

# 规则2: 支配守卫窄化 → 上界有界且安全
        # 守卫本身提供上界, 不要求 off_hi 已解析
        if alloc is not None and usable is not None:
            for g in guards:
                if not g.dominates or g.bound_value is None:
                    continue
                if g.op in ('lt', 'le', 'eq'):
                    ub = g.bound_value - 1 if g.op == 'lt' else g.bound_value
                    s_hi = size_hi if size_hi is not None else 0
                    if ub >= 0 and ub + s_hi <= usable:
                        evs.append(Evidence(
                            rule=ProofRule.GUARD_DOMINANCE,
                            detail=(f'guard@{g.branch_addr:#x}: {g.reg} '
                                    f'{g.op} {g.bound_value} → ub={ub} '
                                    f'+size {s_hi} ≤ usable {usable}'),
                            confidence=0.90,
                            extra={'branch_addr': g.branch_addr}))

# 规则3: 有界区间证明: off_hi + size_hi ≤ 请求分配大小
        # 修正: 必须使用区间上界, 仅 off_lo 有界会误过滤累积溢出.
        if (alloc is not None and off_hi is not None and off_lo is not None
                and size_hi is not None and off_lo >= 0
                and off_hi + size_hi <= alloc):
            evs.append(Evidence(
                rule=ProofRule.MIN_CAP,
                detail=(f'off_hi {off_hi} + size {size_hi} ≤ alloc '
                        f'{alloc}'),
                confidence=0.75))

# 规则4: realloc 缩小后的旧指针语义
        if fv.access_kind == 'memcpy' and getattr(fv, 'realloc_shrunk', False):
            evs.append(Evidence(
                rule=ProofRule.REALLOC_SHRINK,
                detail='post-realloc-shrink access bounded by new size',
                confidence=0.75))

# 规则5: 最小块安全: alloc 未知但访问 ≤ 最小块可用 16B
        # ptmalloc2 x86-64: 任意 malloc 请求的 usable ≥ 16, 因此
        # 偏移上界 + size ≤ 16 的访问无条件安全 (无需解析分配大小).
        if (alloc is None and off_hi is not None and off_lo is not None
                and size_hi is not None and off_lo >= 0
                and off_hi + size_hi <= 16):
            evs.append(Evidence(
                rule=ProofRule.MIN_CAP,
                detail=(f'min-chunk: off_hi {off_hi} + size {size_hi} '
                        f'≤ 16B usable regardless of alloc size'),
                confidence=0.85))

# 规则6: 循环界内安全: 最后一次迭代偏移 + size ≤ usable
        if (fv.access_kind == 'loop_store'
                and alloc is not None and usable is not None):
            iters = getattr(fv, 'loop_iters', None)
            stride = getattr(fv, 'loop_stride', 1)
            if iters is not None and stride > 0:
                base = (offset.constant_value if
                        (offset is not None and offset.is_constant
                         and offset.constant_value is not None) else 0)
                last_offset = base + (iters - 1) * stride
                if last_offset >= 0 and last_offset + 1 <= usable:
                    evs.append(Evidence(
                        rule=ProofRule.GUARD_DOMINANCE,
                        detail=(f'loop {iters} iters × stride {stride} '
                                f'+base {base} → last offset {last_offset} '
                                f'≤ usable {usable}'),
                        confidence=0.85,
                        extra={'iters': iters, 'last_offset': last_offset}))

        for ev in evs:
            self._stats[ev.rule] += 1
        return evs

    def stats(self) -> dict:
        return {r.name: v for r, v in self._stats.items()}


class OverflowProver:
    """溢出判定: 返回可确认溢出的证据列表(空=无法确认)."""

    def __init__(self):
        self._stats = {r: 0 for r in ProofRule}

    def prove(self, fv: FindingVerdict) -> List[Evidence]:
        evs: List[Evidence] = []
        alloc = fv.alloc_size
        usable = fv.usable_size
        offset = fv.offset_info
        size = fv.copy_size_info
        off_lo = offset.interval_lo if offset is not None else None
        off_hi = offset.interval_hi if offset is not None else None
        size_hi = size.interval_hi if size is not None else None
        size_lo = size.interval_lo if size is not None else None

# 规则1: 常量偏移+确定大小超出可用范围
        if usable is not None and (offset is not None
                                   and offset.is_constant
                                   and offset.constant_value is not None):
            c = offset.constant_value
            s_lo = size_lo if size_lo is not None else (
                size_hi if size_hi is not None else 0)
            if s_lo is not None and c + s_lo > usable:
                evs.append(Evidence(
                    rule=ProofRule.CONSTANT_OVERFLOW,
                    detail=(f'const offset {c}+size {s_lo} > usable '
                            f'{usable} (alloc {alloc})'),
                    confidence=0.95))

# 规则2: 无界复制(strcpy类) → 确定性溢出风险
        if fv.access_kind == 'strcpy':
            evs.append(Evidence(
                rule=ProofRule.UNBOUNDED_COPY,
                detail='strcpy-like unbounded copy into heap buffer',
                confidence=0.85))

# 规则2b: alloc 未知但复制/写入大小 > 最小块可用 16B
        # ptmalloc2 最小 usable=16, 超出该上界的复制必然可能溢出
        if (alloc is None and size_lo is not None and size_lo > 16
                and fv.access_kind in ('memcpy', 'strcpy')):
            evs.append(Evidence(
                rule=ProofRule.UNBOUNDED_COPY,
                detail=(f'copy size ≥ {size_lo} exceeds guaranteed '
                        f'min usable 16B'),
                confidence=0.70))

# 规则3: 循环累积
        if fv.access_kind == 'loop_store' and usable is not None:
            iters = getattr(fv, 'loop_iters', None)
            stride = getattr(fv, 'loop_stride', 1)
            if iters is not None and stride > 0:
                base = (offset.constant_value if
                        (offset is not None and offset.is_constant
                         and offset.constant_value is not None) else 0)
                # 最后一次迭代的偏移 = base + (iters-1)*stride
                last_offset = base + (iters - 1) * stride
                if last_offset + 1 > usable:
                    evs.append(Evidence(
                        rule=ProofRule.LOOP_ACCUMULATE,
                        detail=(f'loop {iters} iters × stride {stride} '
                                f'+base {base} → last offset '
                                f'{last_offset} > usable {usable}'),
                        confidence=0.80,
                        extra={'iters': iters, 'stride': stride,
                               'last_offset': last_offset}))

        for ev in evs:
            self._stats[ev.rule] += 1
        return evs

    def stats(self) -> dict:
        return {r.name: v for r, v in self._stats.items()}
