# 偏移值域追踪器 — 从堆分配到访问的偏移值流分析, 用路径约束窄化区间.
# 数据类型已提取到 _offset_types.py, 后向追踪和工具方法已提取到 _offset_trace_mixin.py.
# 本文件保留核心追踪逻辑: track/_parse_offset_reg/_apply_branch_narrowing/_try_prove.
# 创建: 2025-06-09 | 拆分: 2025-06-09

import re
from typing import List, Optional, Tuple

try:
    from ._offset_types import (
        OffsetRange, OffsetProvenance, AllocToAccessPath)
    from ._offset_trace_mixin import OffsetTraceMixin
except ImportError:
    from _offset_types import (  # type: ignore[no-redef]
        OffsetRange, OffsetProvenance, AllocToAccessPath)
    from _offset_trace_mixin import (  # type: ignore[no-redef]
        OffsetTraceMixin)


class OffsetRangeTracker(OffsetTraceMixin):
    """从 alloc 到 access 的偏移值域追踪器.

    核心算法:
      1. 定位 access 处的偏移来源寄存器
      2. 后向追踪 ≤N 条指令, 收集对该寄存器的赋值链 (OffsetTraceMixin._backward_trace)
      3. 扫描 malloc→access 路径上的分支条件, 应用到区间的窄化
      4. 输出窄化后的区间 + 安全证明
    """

    MAX_BACKWARD = 20
    MAX_FORWARD = 50

    def track(self, malloc_addr: int, alloc_size: int,
              access_addr: int, access_size: int,
              insns: list,
              branch_constraints: Optional[List] = None,
              ) -> AllocToAccessPath:
        """对一条 heap access 做完整的偏移追踪."""
        path = AllocToAccessPath(
            malloc_addr=malloc_addr, alloc_size=alloc_size,
            access_addr=access_addr, access_size=access_size)

        if not insns:
            return path

        acc_idx = next((i for i, insn in enumerate(insns)
                        if insn.addr == access_addr), None)
        if acc_idx is None:
            return path

        acc_insn = insns[acc_idx]

        offset_reg, base_reg, const_off = self._parse_offset_reg(acc_insn)
        path.base_reg = base_reg
        path.offset_reg = offset_reg
        if const_off is not None:
            path.offset_range = OffsetRange(
                lo=const_off, hi=const_off,
                provenance=OffsetProvenance.CONSTANT)
            self._try_prove(path, alloc_size, access_size)
            return path

        if not offset_reg:
            return path

        origin = self._backward_trace(offset_reg, acc_idx, insns)
        if origin is not None:
            path.offset_range = origin

        if branch_constraints:
            self._apply_branch_narrowing(path, branch_constraints, alloc_size)

        self._try_prove(path, alloc_size, access_size)
        return path

    def _parse_offset_reg(self, insn) -> Tuple[str, str, Optional[int]]:
        """从内存访问指令提取 (offset_reg, base_reg, const_offset).

        'mov [rax+rdx*4+0x10], ecx' → ('rdx', 'rax', 16)
        'mov [rax+0x20], ecx' → ('', 'rax', 32)
        """
        op = insn.operands
        if ',' not in op:
            return '', '', None
        dst = op.split(',')[0].strip()
        if '[' not in dst:
            return '', '', None

        m = re.search(r'\[(\w+)', dst)
        base = m.group(1).lower() if m else ''

        parts = dst.strip('[]').split('+')
        offset_reg = ''
        const = None

        for p in parts:
            p = p.strip()
            if '*' in p:
                offset_reg = p.split('*')[0].strip()
            elif re.match(r'^0x[0-9a-fA-F]+$', p):
                const = int(p, 16)
            elif p.isdigit() or (p.startswith('-') and p[1:].isdigit()):
                const = int(p)
            elif re.match(r'^[er]?[a-d]x$|^r\d', p) and p != base:
                offset_reg = p

        return offset_reg, base, const

    def _apply_branch_narrowing(self, path: AllocToAccessPath,
                                 constraints: list, alloc_size: int) -> None:
        """用 malloc→access 路径上的分支条件窄化偏移区间."""
        orng = path.offset_range
        for bc in constraints:
            if bc.register != path.offset_reg:
                continue
            if not (path.malloc_addr < bc.insn_addr < path.access_addr):
                continue

            new_lo, new_hi = orng.lo, orng.hi

            if bc.op.value in ('lt', 'le'):
                bound = bc.bound_value + (0 if bc.op.value == 'le' else -1)
                new_hi = min(new_hi, bound)
            elif bc.op.value in ('gt', 'ge'):
                bound = bc.bound_value + (0 if bc.op.value == 'ge' else 1)
                new_lo = max(new_lo, bound)
            elif bc.op.value == 'eq':
                new_lo = max(new_lo, bc.bound_value)
                new_hi = min(new_hi, bc.bound_value)

            if new_lo != orng.lo or new_hi != orng.hi:
                orng = OffsetRange(
                    lo=new_lo, hi=new_hi,
                    provenance=OffsetProvenance.BRANCH_GUARDED,
                    narrow_steps=orng.narrow_steps + [
                        f"branch {bc.op.value} {bc.bound_value} @{bc.insn_addr:x}"])
                path.offset_range = orng

    def _try_prove(self, path: AllocToAccessPath,
                   alloc_size: int, access_size: int) -> None:
        """尝试证明此访问安全或越界."""
        off = path.offset_range

        if off.is_precise():
            if off.lo + access_size <= alloc_size:
                path.can_prove_safe = True
                path.proof_reason = (
                    f'常量偏移 {off.lo}+{access_size} ≤ alloc {alloc_size}')
            elif off.lo >= alloc_size:
                path.can_prove_overflow = True
                path.proof_reason = (
                    f'常量偏移 {off.lo} ≥ alloc {alloc_size}')
            return

        if off.hi != 0xFFFFFFFF and off.hi + access_size <= alloc_size:
            if off.provenance in (OffsetProvenance.BRANCH_GUARDED,
                                  OffsetProvenance.REGISTER_CHAIN):
                path.can_prove_safe = True
                path.proof_reason = (
                    f'窄化区间 [{off.lo},{off.hi}]+{access_size} ≤ alloc {alloc_size}')
                return

        if off.lo > alloc_size:
            if off.provenance != OffsetProvenance.UNKNOWN:
                path.can_prove_overflow = True
                path.proof_reason = (
                    f'偏移下界 {off.lo} > alloc {alloc_size}')
                return

    def stats(self) -> dict:
        return {'max_backward': self.MAX_BACKWARD,
                'max_forward': self.MAX_FORWARD}
