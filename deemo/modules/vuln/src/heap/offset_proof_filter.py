"""偏移证明过滤器 — 将 CAORN 偏移值域追踪接入 DP-TVRA 过滤管线.

创建: 2026-07-13
用途: 在 semantic_fp_filter 的统计评分之前, 先用路径约束做可证明的安全/溢出判定.
      若 CAORN 能证明安全 → 直接过滤 (不进入统计评分阶段).
      若 CAORN 能证明溢出 → 直接确认漏洞.
      若无法证明 → 降级到原有 semantic_fp_filter 评分管线.

管线更新:
  原: BOUND_CHECK → semantic_fp_filter → 最终判定
  新: BOUND_CHECK → CAORN proof → semantic_fp_filter → 最终判定
                     ↑ 可证明时直接决断

与现有模块的关系:
  - offset_range_tracker: 提供 OffsetRangeTracker 引擎
  - heap_bound_infer: 提供 HeapAccess + alloc 信息
  - filter_types: 提供 FilterDecision/FilterPhase 枚举
  - semantic_fp_filter: 无法证明时的降级路径
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum, auto
import re

try:
    from .offset_range_tracker import (
        OffsetRangeTracker, AllocToAccessPath, OffsetRange, OffsetProvenance)
    from .filter_types import FilterPhase, FilterDecision, FilterResult
    from ..insn_parser import extract_register
except ImportError:
    import os as _os, sys as _sys
    _d = _os.path.dirname(_os.path.abspath(__file__))
    if _d not in _sys.path:
        _sys.path.insert(0, _d)
    from offset_range_tracker import (  # type: ignore[no-redef]
        OffsetRangeTracker, AllocToAccessPath, OffsetRange, OffsetProvenance)
    from filter_types import (  # type: ignore[no-redef]
        FilterPhase, FilterDecision, FilterResult)
    from insn_parser import extract_register  # type: ignore[no-redef]


class ProofResult(Enum):
    """CAORN 证明结果."""
    PROVED_SAFE = "proved_safe"         # 约束证明安全 → 过滤
    PROVED_OVERFLOW = "proved_overflow"  # 约束证明溢出 → 确认
    INCONCLUSIVE = "inconclusive"        # 无法证明 → 降级评分


@dataclass
class OffsetProofResult:
    """一次偏移证明的完整结果, 含证据链."""
    proof: ProofResult
    offset_range: Optional[OffsetRange] = None
    reason: str = ""
    constraint_count: int = 0
    proven_safe_count: int = 0
    proven_vuln_count: int = 0


class OffsetProofFilter:
    """偏移证明过滤器 — CAORN 证明优先, 统计评分降级.

    使用方式:
      pf = OffsetProofFilter()
      for access in heap_accesses:
          result = pf.prove(access, alloc_info, instructions, constraints)
          if result.proof == ProofResult.PROVED_SAFE:
              continue   # 过滤
          if result.proof == ProofResult.PROVED_OVERFLOW:
              confirmed.append(access)  # 确认
          else:
              uncertain.append(access)  # 降级评分
    """

    def __init__(self):
        self._tracker = OffsetRangeTracker()
        self._stats = {
            'total_checked': 0, 'proved_safe': 0,
            'proved_overflow': 0, 'inconclusive': 0}

    def prove(self, malloc_addr: int, alloc_size: int,
              access_addr: int, access_size: int,
              insns: list,
              branch_constraints: Optional[List] = None,
              offset_value: int = 0, func_name: str = ''
              ) -> OffsetProofResult:
        """对一条堆访问执行 CAORN 证明."""
        self._stats['total_checked'] += 1

        # 快速路径: 常量偏移 + 已知 alloc → 直接判定
        if (offset_value > 0 and alloc_size > 0
                and offset_value + access_size <= alloc_size):
            self._stats['proved_safe'] += 1
            return OffsetProofResult(
                proof=ProofResult.PROVED_SAFE,
                reason=f'常量偏移 {offset_value}+{access_size} ≤ alloc {alloc_size}',
                proven_safe_count=1)

        # 主路径: 值流追踪 + 约束窄化
        path = self._tracker.track(
            malloc_addr, alloc_size, access_addr, access_size,
            insns, branch_constraints)

        min_offset = max(offset_value, path.offset_range.lo)

        if path.can_prove_safe:
            self._stats['proved_safe'] += 1
            return OffsetProofResult(
                proof=ProofResult.PROVED_SAFE,
                offset_range=path.offset_range,
                reason=path.proof_reason,
                constraint_count=len(path.offset_range.narrow_steps),
                proven_safe_count=1)

        if path.can_prove_overflow:
            self._stats['proved_overflow'] += 1
            return OffsetProofResult(
                proof=ProofResult.PROVED_OVERFLOW,
                offset_range=path.offset_range,
                reason=path.proof_reason,
                constraint_count=len(path.offset_range.narrow_steps),
                proven_vuln_count=1)

        # 启发式: 窄化区间上界落入安全范围
        if (path.offset_range.hi != 0xFFFFFFFF
                and path.offset_range.hi + access_size <= alloc_size):
            self._stats['proved_safe'] += 1
            return OffsetProofResult(
                proof=ProofResult.PROVED_SAFE,
                offset_range=path.offset_range,
                reason=(f'窄化上界 {path.offset_range.hi}+{access_size} '
                       f'≤ alloc {alloc_size}'),
                constraint_count=len(path.offset_range.narrow_steps),
                proven_safe_count=1)

        self._stats['inconclusive'] += 1
        return OffsetProofResult(
            proof=ProofResult.INCONCLUSIVE,
            offset_range=path.offset_range,
            reason=f'无法证明: 偏移[{path.offset_range.lo}, {path.offset_range.hi}]',
            constraint_count=len(path.offset_range.narrow_steps))

# 分支约束提取 (从指令流)

    @staticmethod
    def extract_branch_constraints(insns: list,
                                    malloc_addr: int = 0,
                                    access_addr: int = 0
                                    ) -> List:
        """从指令流提取 cmp+jcc 对作为分支约束.

        在 malloc→access 区间内扫描:
          cmp reg, imm / cmp reg, reg
          jcc target
        → 生成 BranchConstraint, 用于后续窄化.
        """
        from path_value_narrowing import BranchConstraint, ComparisonOp

        constraints = []
        if not insns:
            return constraints

        start_idx = 0
        end_idx = len(insns)

        # 定位 malloc→access 区间
        if malloc_addr:
            start_idx = next((i for i, insn in enumerate(insns)
                             if insn.addr >= malloc_addr), 0)
        if access_addr:
            end_idx = next((i for i, insn in enumerate(insns)
                           if insn.addr >= access_addr), len(insns))

        # cmp → op 映射
        _OP_MAP = {
            'jbe': ('le', True), 'ja': ('gt', True),
            'jae': ('ge', True), 'jb': ('lt', True),
            'jle': ('le', True), 'jg': ('gt', True),
            'jge': ('ge', True), 'jl': ('lt', True),
            'je': ('eq', True), 'jne': ('ne', True),
            'jz': ('eq', True), 'jnz': ('ne', True),
        }

        i = start_idx
        while i < end_idx:
            insn = insns[i]
            if insn.mnemonic == 'cmp' and ',' in insn.operands:
                parts = [x.strip() for x in insn.operands.split(',')]
                reg = extract_register(parts[0])
                if reg and parts[1]:
                    val_str = parts[1]
                    # 尝试解析为立即数
                    m = re.search(r'(0x[0-9a-fA-F]+)', val_str)
                    if m:
                        bound = int(m.group(1), 16)
                    elif val_str.isdigit() or (val_str.startswith('-')
                                                and val_str[1:].isdigit()):
                        bound = int(val_str)
                    else:
                        i += 1; continue

                    # 扫描后续 4 条指令, 找匹配的 jcc
                    for k in range(i + 1, min(i + 5, end_idx)):
                        jcc_name = insns[k].mnemonic
                        if jcc_name in _OP_MAP:
                            op_name, taken = _OP_MAP[jcc_name]
                            op = ComparisonOp(op_name)
                            constraints.append(BranchConstraint(
                                insn_addr=insn.addr, register=reg,
                                op=op, bound_value=bound, is_taken=taken))
                            break
            i += 1

        return constraints

    def stats(self) -> dict:
        total = max(1, self._stats['total_checked'])
        return {
            **self._stats,
            'prove_rate': round(self._stats['proved_safe'] / total, 3),
            'proved_safe_pct': round(
                self._stats['proved_safe'] / total * 100, 1),
            'proved_overflow_pct': round(
                self._stats['proved_overflow'] / total * 100, 1),
        }
