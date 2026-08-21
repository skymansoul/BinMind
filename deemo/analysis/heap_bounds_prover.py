"""
堆边界安全证明器 — Z3约束证明: 路径约束 + strided interval + 分配器模型.

静态堆溢出误报三大根因: 路径不敏感/分配器不感知/区间不精确.
本模块通过Z3将三者结合编码为断言, 查询 write_offset > effective_alloc 的可满足性.
unsat → 安全(过滤). sat → 溢出可能(保留).
timeout=5s per query; Z3不可用时回退到纯区间推理.
"""


import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from analysis.strided_interval import StridedInterval


@dataclass
class ProofResult:
    """一次堆边界安全证明的结果."""
    is_safe: bool                      # 是否可证明 write 不会溢出
    proof_type: str                    # 'z3_unsat' | 'z3_sat' | 'interval' | 'trivial' | 'timeout'
    overflow_possible: bool            # 是否存在可触发溢出的输入
    min_overflow_bytes: int            # Z3 求得的最小溢出字节数 (0=无法溢出)
    proof_time_ms: float = 0.0
    details: str = ""


class HeapBoundsProver:
    """堆边界安全证明器.

    输入: 分配大小, 写入偏移, 路径约束, strided interval (可选)
    输出: ProofResult — 安全/可能的溢出/不确定
    """

    _TIMEOUT_MS = 5000
    _Z3_AVAILABLE = False

    def __init__(self):
        try:
            import z3  # noqa: F401
            self._Z3_AVAILABLE = True
        except ImportError:
            self._Z3_AVAILABLE = False

    def prove_safety(
        self,
        alloc_size: int,
        write_offset: int,
        write_size: int = 1,
        path_constraints: Optional[List[Any]] = None,
        si_alloc: Optional[StridedInterval] = None,
        si_offset: Optional[StridedInterval] = None,
        alloc_func: str = "malloc",
        platform: str = "x86_64",
    ) -> ProofResult:
        """证明给定堆写是否安全。

        path_constraints 来自 path_constraint_collector;
        si_alloc/si_offset 为 size 表达式的 strided interval。
        返回 ProofResult, is_safe=True 表示可安全过滤此告警。
        """
        t0 = time.time()

        # 快速路径: 平凡安全
        if write_offset + write_size <= alloc_size:
            dt = (time.time() - t0) * 1000
            return ProofResult(
                is_safe=True, proof_type='trivial',
                overflow_possible=False, min_overflow_bytes=0,
                proof_time_ms=dt,
                details=f'offset {write_offset}+{write_size} <= alloc {alloc_size}',
            )

        # 快速路径: 分配器语义 — 实际可用空间包含对齐填充
        effective_alloc = self._effective_alloc_size(alloc_size, alloc_func, platform)
        if write_offset + write_size <= effective_alloc:
            dt = (time.time() - t0) * 1000
            return ProofResult(
                is_safe=True, proof_type='allocator_semantics',
                overflow_possible=False, min_overflow_bytes=0,
                proof_time_ms=dt,
                details=(
                    f'effective alloc={effective_alloc}B (requested={alloc_size}) '
                    f'covers offset={write_offset}+{write_size}'
                ),
            )

        # 检查 strided interval: 若 offset 的 stride 不会取到溢出值
        if si_offset is not None and si_alloc is not None:
            if not si_offset.may_exceed(effective_alloc):
                dt = (time.time() - t0) * 1000
                return ProofResult(
                    is_safe=True, proof_type='stride_safe',
                    overflow_possible=False, min_overflow_bytes=0,
                    proof_time_ms=dt,
                    details=f'strided interval {si_offset} cannot exceed {effective_alloc}',
                )

        # Z3 证明
        if self._Z3_AVAILABLE and path_constraints:
            return self._z3_prove(
                alloc_size, write_offset, write_size,
                path_constraints, si_alloc, si_offset,
                effective_alloc, t0,
            )

        # 回退: 区间推理
        return self._interval_prove(
            alloc_size, write_offset, write_size,
            path_constraints, effective_alloc, t0,
        )

    def _z3_prove(
        self, alloc_size: int, write_offset: int, write_size: int,
        path_constraints: list, si_alloc, si_offset,
        effective_alloc: int, t0: float,
    ) -> ProofResult:
        """使用 Z3 进行可满足性证明."""
        import z3

        solver = z3.Solver()
        solver.set("timeout", self._TIMEOUT_MS)

        sym_alloc = z3.Int('alloc')
        sym_offset = z3.Int('offset')
        sym_write = z3.Int('write_sz')

        # 分配大小约束
        solver.add(sym_alloc >= alloc_size)
        solver.add(sym_alloc <= effective_alloc)

        # 写入偏移约束
        solver.add(sym_offset >= write_offset)
        solver.add(sym_write >= write_size)

        # 注入路径约束: 每个 BranchConstraint → Z3 assertion
        for c in path_constraints:
            sym_var = z3.Int(c.var)
            op_map = {
                '<': z3.Int.__lt__,
                '>': z3.Int.__gt__,
                '<=': z3.Int.__le__,
                '>=': z3.Int.__ge__,
                '==': z3.Int.__eq__,
                '!=': lambda a, b: a != b,
            }
            op_fn = op_map.get(c.op)
            if op_fn:
                solver.add(op_fn(sym_var, c.value))

        # strided interval 约束
        if si_alloc is not None and si_alloc.stride > 1:
            solver.add((sym_alloc - si_alloc.lo) % si_alloc.stride == 0)
        if si_offset is not None and si_offset.stride > 1:
            solver.add((sym_offset - si_offset.lo) % si_offset.stride == 0)

        # 溢出条件: offset + write_size > alloc
        solver.add(sym_offset + sym_write > sym_alloc)

        result = solver.check()
        dt = (time.time() - t0) * 1000

        if result == z3.unsat:
            return ProofResult(
                is_safe=True, proof_type='z3_unsat',
                overflow_possible=False, min_overflow_bytes=0,
                proof_time_ms=dt,
                details=f'Z3 proven safe: {len(path_constraints)} constraints, {dt:.1f}ms',
            )
        elif result == z3.sat:
            model = solver.model()
            try:
                min_overflow = (
                    model.evaluate(sym_offset + sym_write - sym_alloc).as_long()
                )
            except Exception:
                min_overflow = 1
            return ProofResult(
                is_safe=False, proof_type='z3_sat',
                overflow_possible=True,
                min_overflow_bytes=max(0, min_overflow),
                proof_time_ms=dt,
                details=f'Z3 counterexample: overflow by {min_overflow}B',
            )
        else:
            return ProofResult(
                is_safe=False, proof_type='z3_unknown',
                overflow_possible=True, min_overflow_bytes=0,
                proof_time_ms=dt,
                details=f'Z3 result={result}: timeout or unknown',
            )

    def _interval_prove(
        self, alloc_size: int, write_offset: int, write_size: int,
        path_constraints, effective_alloc: int, t0: float,
    ) -> ProofResult:
        """区间推理证明 (Z3 不可用时的回退)."""
        dt = (time.time() - t0) * 1000

        if not path_constraints:
            return ProofResult(
                is_safe=False, proof_type='interval_inconclusive',
                overflow_possible=True, min_overflow_bytes=0,
                proof_time_ms=dt,
                details='no constraints, cannot prove safety',
            )

        # 从约束推导变量上界
        lo, hi = 0, 2**63 - 1
        from analysis.path_constraint_collector import PathConstraintCollector
        for c in path_constraints:
            lo, hi = PathConstraintCollector._refine_bounds(lo, hi, c)

        # 若约束确保 hi <= effective_alloc, 则写入安全
        if hi <= effective_alloc:
            return ProofResult(
                is_safe=True, proof_type='interval_proven',
                overflow_possible=False, min_overflow_bytes=0,
                proof_time_ms=dt,
                details=f'interval: hi={hi} <= effective_alloc={effective_alloc}',
            )

        # 若约束确保 lo > effective_alloc, 则必然溢出
        if lo > effective_alloc:
            return ProofResult(
                is_safe=False, proof_type='interval_overflow',
                overflow_possible=True,
                min_overflow_bytes=lo - effective_alloc,
                proof_time_ms=dt,
                details=f'interval: lo={lo} > effective_alloc={effective_alloc}',
            )

        return ProofResult(
            is_safe=False, proof_type='interval_inconclusive',
            overflow_possible=True, min_overflow_bytes=0,
            proof_time_ms=dt,
            details=f'interval [{lo},{hi}] crosses effective_alloc={effective_alloc}',
        )

    @staticmethod
    def _effective_alloc_size(
        requested: int, alloc_func: str, platform: str,
    ) -> int:
        """分配器实际提供的可用字节数.

        参考 glibc checked_request2size → chunk_size → usable_size.
        简化模型: 对齐到 16, 最小 32, 减 header 得到 usable.
        """
        if requested <= 0:
            return 0
        align = 16
        min_chunk = 32
        header = 16 if platform in ("x86_64", "arm64", "aarch64") else 8

        if alloc_func == "calloc":
            # calloc 比 malloc 多一次零初始化, 但大小语义相同
            pass

        aligned = ((requested + header + align - 1) // align) * align
        return max(min_chunk, aligned) - header


def prove_store_safety(
    alloc_size: int,
    store_offset: int,
    store_size: int = 1,
    constraints: Optional[List[Any]] = None,
    alloc_si: Optional[StridedInterval] = None,
    offset_si: Optional[StridedInterval] = None,
) -> Tuple[bool, str]:
    """便捷接口: 证明单次 store 是否安全, 返回 (safe_to_filter, reason)。"""
    prover = HeapBoundsProver()
    result = prover.prove_safety(
        alloc_size=alloc_size,
        write_offset=store_offset,
        write_size=store_size,
        path_constraints=constraints,
        si_alloc=alloc_si,
        si_offset=offset_si,
    )
    return result.is_safe, result.details


__all__ = ['ProofResult', 'HeapBoundsProver', 'prove_store_safety']
