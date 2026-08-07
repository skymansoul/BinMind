# coding: utf-8
"""
分配器感知约束编码器 — 将 glibc/ptmalloc 的对齐/最小块/元数据约束
编码为可求解的不等式系统, 供 ConstraintSystem 使用.

与 alloc_constraints.py 的区别:
  - alloc_constraints.py: 提供 usable_size/effective_size 的数值计算
  - 本模块: 将这些计算编码为符号约束, 允许在未知变量上做推理

例如 malloc(N) 实际可用 usable_size(N) = effective(N) - overhead,
其中 effective(N) = max(MINSIZE, align_up(N + overhead, ALIGN)).
将这种分段函数编码为线性不等式系统, 允许在 N 未知时做约束传播.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from compat.constraint_solver import (
    Constraint, ConstraintOp, ConstraintSystem,
)
from compat.alloc_constraints import (
    AllocConstraints, get_constraints,
)


@dataclass
class AllocatorAwareSystem:
    """将分配器约束与溢出条件联合编码的约束系统."""
    cs: ConstraintSystem
    alloc_var: str = 'alloc_req'
    write_var: str = 'write_sz'
    eff_var: str = 'alloc_eff'     # effective size (含元数据+对齐)
    usable_var: str = 'alloc_usable'  # 用户实际可用


def encode_allocator_constraints(
    ac: AllocConstraints,
    alloc_var: str = 'alloc_req',
    eff_var: str = 'alloc_eff',
    usable_var: str = 'alloc_usable',
) -> Tuple[ConstraintSystem, AllocatorAwareSystem]:
    """将分配器的内部约束编码为不等式系统.

    编码规则:
      1. eff >= alloc_req + metadata_overhead
      2. eff >= min_chunk_size
      3. eff % alignment == 0  (编码为: eff = k * alignment, k 整数)
      4. usable = eff - metadata_overhead
      5. eff <= alloc_req + metadata_overhead + alignment - 1  (对齐上界)

    约束 3 是等式约束, 在区间传播中难以精确处理.
    改用宽松化: eff ∈ [align_down(...), align_up(...)].
    """
    cs = ConstraintSystem()
    aas = AllocatorAwareSystem(cs, alloc_var, 'write_sz', eff_var, usable_var)

    # 域初始化
    cs.set_domain(alloc_var, 0, 2**24)
    cs.set_domain(eff_var, ac.min_chunk_size, 2**24)
    cs.set_domain(usable_var, 0, 2**24)

    # C1: eff >= alloc_req + metadata_overhead
    cs.add_constraint(Constraint(
        eff_var, ConstraintOp.GE, right_var=alloc_var,
        constant=ac.metadata_overhead, origin='eff>=req+meta'))

    # C2: eff >= min_chunk_size
    cs.add_constraint(Constraint(
        eff_var, ConstraintOp.GE, constant=ac.min_chunk_size,
        origin='eff>=min_chunk'))

    # C3: eff 的上界 — 不会比最小对齐块更大
    cs.add_constraint(Constraint(
        eff_var, ConstraintOp.LE, right_var=alloc_var,
        constant=ac.metadata_overhead + ac.alignment - 1,
        origin='eff<=req+meta+align-1'))

    # C4: usable = eff - metadata_overhead (用 LE+GE 编码 EQ)
    cs.add_constraint(Constraint(
        usable_var, ConstraintOp.LE, right_var=eff_var,
        constant=-ac.metadata_overhead, origin='usable<=eff-meta'))
    cs.add_constraint(Constraint(
        eff_var, ConstraintOp.LE, right_var=usable_var,
        constant=ac.metadata_overhead, origin='eff<=usable+meta'))

    return cs, aas


def prove_safe_with_allocator(
    alloc_request: int,
    write_size: int,
    allocator_type: str = 'glibc_ptmalloc',
    arch: str = 'x86_64',
) -> Tuple[bool, str]:
    """分配器感知约束判定 — 结合区间传播与同余精化.

    两阶段: (1) 同余精化快速路径 (O(1)) (2) 约束系统区间传播 (fallback).
    返回: (溢出不可行 → True, 证明理由).
    """
    from compat.congruence_domain import prove_with_congruence

    ac = get_constraints(allocator_type, arch)

    # 阶段1: 同余精化 — 快速精确路径
    safe_c, reason_c = prove_with_congruence(
        alloc_request, write_size,
        alignment=ac.alignment, min_chunk=ac.min_chunk_size,
        metadata=ac.metadata_overhead,
    )
    if safe_c:
        return True, f'[同余精化] {reason_c}'

    # 阶段2: 约束系统区间传播 (处理更复杂的约束组合)
    cs, aas = encode_allocator_constraints(ac)
    cs.set_domain(aas.alloc_var, alloc_request, alloc_request)
    cs.set_domain(aas.write_var, write_size, write_size)

    cs.add_constraint(Constraint(
        aas.write_var, ConstraintOp.GT,
        right_var=aas.usable_var,
        origin='overflow: write>usable'))

    result = cs.solve()
    if not result.satisfiable:
        usable = ac.usable_size(alloc_request)
        if write_size <= usable:
            return True, (
                f'分配器约束保证安全: malloc({alloc_request}) '
                f'usable={usable} >= write({write_size}), '
                f'(eff={ac.effective_size(alloc_request)}, '
                f'align={ac.alignment}, min={ac.min_chunk_size})')
        return True, f'约束系统证明不可满足: {result.safety_proof}'

    return False, (
        f'可能存在溢出: write({write_size}) > usable({ac.usable_size(alloc_request)})')


def batch_allocator_aware_filter(
    candidates: List[Dict],
    allocator_type: str = 'glibc_ptmalloc',
    arch: str = 'x86_64',
) -> Tuple[List[Dict], Dict[str, int]]:
    """批量分配器感知过滤 — 比纯约束求解更精确的版本."""
    retained = []
    filtered = 0
    details = []

    for c in candidates:
        alloc_sz = c.get('alloc_size', c.get('size', 0))
        write_sz = c.get('write_size', c.get('overflow_bytes', 0))

        if alloc_sz <= 0 or write_sz <= 0:
            retained.append(c)
            continue

        safe, reason = prove_safe_with_allocator(
            alloc_sz, write_sz, allocator_type, arch)

        if safe:
            filtered += 1
            details.append({
                'site': c.get('overflow_site', ''),
                'alloc': alloc_sz, 'write': write_sz, 'reason': reason,
            })
        else:
            retained.append(c)

    stats = {
        'total': len(candidates), 'retained': len(retained),
        'filtered': filtered,
        'reduction': f'{filtered/max(1,len(candidates)):.1%}',
    }
    return retained, stats
