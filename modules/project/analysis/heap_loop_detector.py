# 堆溢出检测 — 循环检测与循环写入验证 (Pass 2.5)
# 职责: _detect_loops (回跳指令循环识别), _check_loop_writes (循环内堆写入验证),
#   _estimate_loop_iterations (迭代次数推断), _recommend_loop
from __future__ import annotations
import re
from typing import Dict, List, Optional, Tuple

from .value_range import ValueRange
from .allocation_tracker import _ALLOC_FUNCTIONS, _REALLOC_FUNCTIONS
from .constraint_simplifier import OverflowVerdict
from .instruction_parser import InstructionParser


# 回跳指令集合: 所有可能形成循环的条件/无条件跳转
_JUMP_INSTRS = {
    'je', 'jne', 'jl', 'jle', 'jg', 'jge',
    'ja', 'jae', 'jb', 'jbe', 'jns', 'js',
    'jno', 'jo', 'jnz', 'jz', 'jmp', 'jnp',
    'jp', 'jcxz', 'jecxz',
}


class LoopDetectorMixin:
    """堆溢出检测 — 循环分析层 (Pass 2.5).

    以mixin形式注入 HeapOverflowDetector, 保持self._xxx访问.
    """

    def _detect_loops(self, instructions: List[str],
                       addrs: List[int],
                       func_map: Dict[str, Tuple[int, int]]
                       ) -> Dict[int, List[int]]:
        """检测循环体: 通过回跳指令识别循环.

        返回 {loop_start_idx: [body_instruction_indices]}.
        循环起点是回跳目标, 循环体包含目标到回跳指令间的所有指令.
        """
        loops: Dict[int, List[int]] = {}
        if not addrs or len(addrs) != len(instructions):
            return loops

        for fname, (f_start, f_end) in func_map.items():
            if (fname.startswith('__') or fname.startswith('_.')
                    or fname.startswith('<')):
                continue
            for i in range(f_start, min(f_end + 1, len(instructions))):
                line = instructions[i]
                stripped = line.strip()
                j_op = stripped.split()[0] if stripped else ''
                if j_op not in _JUMP_INSTRS:
                    continue
                parts = stripped.split()
                target_str = None
                for p in parts[1:]:
                    p_clean = p.split('<')[0].strip()
                    try:
                        int(p_clean, 16)
                        target_str = p_clean
                        break
                    except ValueError:
                        continue
                if target_str is None:
                    continue
                try:
                    target_addr = int(target_str, 16)
                except ValueError:
                    continue
                if target_addr < addrs[i]:
                    target_idx = None
                    for j in range(f_start, i):
                        if addrs[j] == target_addr:
                            target_idx = j
                            break
                    if target_idx is not None:
                        body = list(range(target_idx, i + 1))
                        if target_idx not in loops:
                            loops[target_idx] = body
                        elif len(body) > len(loops[target_idx]):
                            loops[target_idx] = body
        return loops

    def _check_loop_writes(self,
                            loops: Dict[int, List[int]],
                            instructions: List[str],
                            func_map: Dict[str, Tuple[int, int]]
                            ) -> List['OverflowFinding']:
        """Pass 2.5: 检测循环体内的逐字节堆写入.

        使用Pass 1期间记录的 _inline_writes (指令执行时捕获的活跃
        provenance) 而非查询最终provenance状态.
        """
        from .heap_overflow_detector import OverflowFinding, OverflowSeverity
        from .false_positive_filter import FilterVerdict

        findings = []
        if not loops:
            return findings

        iw_by_idx: Dict[int, Dict] = {}
        for iw in self._inline_writes:
            iw_by_idx[iw['idx']] = iw

        for loop_start, body_indices in loops.items():
            matching_writes = []
            for idx in body_indices:
                if idx in iw_by_idx:
                    matching_writes.append(iw_by_idx[idx])

            if not matching_writes:
                continue

            iter_range = self._loop_iteration_range(
                body_indices, instructions, loop_start)

            # 多写入聚合: 循环体含多个写入指令时, 每轮总写入 =
            # Σ 各写入宽度. 逐写入独立检查会低估总量 (heap02 回归根因).
            if len(matching_writes) > 1:
                agg_finding = self._check_aggregate_write(
                    matching_writes, iter_range, loop_start, site=None)
                if agg_finding is not None:
                    findings.append(agg_finding)
                continue

            for iw in matching_writes:
                w_idx = iw['idx']
                write_size = iw['write_size']
                offset_in_alloc = iw['offset_in_alloc']
                func_name = iw['function_name']

                site = self._alloc._alloc_sites.get(iw['alloc_site_id'])
                if not site:
                    continue

                # L6: 循环耦合 — 边界与分配同源且逐字节写入 → 撤销
                if self._loop_coupling_safe(
                        loop_start, site, body_indices,
                        instructions, write_size):
                    continue

                per_write_vr = ValueRange.constant(write_size)
                total_write = iter_range.mul(per_write_vr)
                # 步进循环的字节写入: 以偏移扩展代替迭代总数模型
                extent = self._loop_write_extent(iter_range, write_size)
                if extent is not None:
                    total_write = extent

                a_min = site.min_allocation()
                actual_usable = self._heap_model.get_usable_size(a_min)
                if actual_usable > a_min:
                    corrected_alloc_range = ValueRange.unsigned_range(
                        actual_usable, site.max_allocation())
                else:
                    corrected_alloc_range = site.alloc_size_range

                off_vr = ValueRange.constant(offset_in_alloc)
                result = self._constraint.check_heap_write(
                    total_write, off_vr, corrected_alloc_range,
                    is_str_copy=False)

                if result.verdict == OverflowVerdict.DEFINITE_SAFE:
                    continue

                is_crt = (func_name.startswith('__')
                          or func_name.startswith('_.'))
                fp_check = self._fp_filter.check(
                    write_size=total_write,
                    write_offset=off_vr,
                    alloc_size=corrected_alloc_range,
                    function_name=func_name,
                    sink_func=f"loop_write({write_size}B/iter)",
                    alloc_func=site.alloc_func,
                    is_crt_context=is_crt)
                if fp_check.verdict in (FilterVerdict.FILTER_SAFE,
                                         FilterVerdict.FILTER_NOISE):
                    continue

                sev = self._severity(result, False)
                if fp_check.verdict == FilterVerdict.DEMOTE:
                    if sev == OverflowSeverity.HIGH:
                        sev = OverflowSeverity.MEDIUM
                    elif sev == OverflowSeverity.CRITICAL:
                        sev = OverflowSeverity.HIGH
                findings.append(OverflowFinding(
                    finding_id=f"HEAP-LOOP-{w_idx}",
                    function_name=func_name,
                    sink_func=f"loop_write({write_size}B/iter)",
                    severity=sev,
                    confidence=result.overflow_confidence,
                    alloc_site_info=(
                        f"{site.alloc_func}@{site.call_address:#x}, "
                        f"size∈[{site.min_allocation()},{site.max_allocation()}]"),
                    overflow_detail=(
                        f"循环写入: {write_size}B/iter × "
                        f"[{iter_range.umin},{iter_range.umax}] iter = "
                        f"[{total_write.umin},{total_write.umax}]B, "
                        f"偏移={offset_in_alloc}, "
                        f"分配=[{site.min_allocation()},{site.max_allocation()}]B, "
                        f"判定={result.verdict.name}"),
                    write_size_min=total_write.umin,
                    write_size_max=total_write.umax,
                    alloc_size_min=site.min_allocation(),
                    alloc_size_max=site.max_allocation(),
                    input_controlled=False,
                    evidence=result.evidence,
                    recommendation=self._recommend_loop(
                        result, site, total_write, write_size)))

        return findings

    def _estimate_loop_iterations(self, body_indices: List[int],
                                   instructions: List[str],
                                   loop_start_idx: int
                                   ) -> 'ValueRange':
        """估算循环迭代次数.

        策略:
        1. 找到循环条件比较指令 (cmp reg, imm/mem/reg 或 test reg, reg)
        2. 找到循环计数器自增指令 (add reg, 1 / inc reg)
        3. 从值域推断迭代次数
        4. 若test al,al; jne → 字符串循环, 无固定边界
        """
        cmp_target = None
        cmp_bound = None
        is_test_loop = False

        for idx in body_indices:
            line = instructions[idx]
            stripped = line.strip()
            if stripped.startswith('test '):
                is_test_loop = True
                continue
            if not stripped.startswith('cmp '):
                continue
            clean_cmp = InstructionParser._SIZE_PREFIX_RE.sub('', stripped)
            parts = clean_cmp.replace(',', ' ').split()
            if len(parts) < 3:
                continue
            left = parts[1]
            right = parts[2]
            if '[' in left:
                base, mem_off = InstructionParser.parse_mem(left)
                cmp_target = (InstructionParser.normalize_reg64(base)
                              if base else '')
            else:
                cmp_target = InstructionParser.clean_reg(left)

            imm = InstructionParser.parse_immediate(right)
            if imm is not None:
                cmp_bound = ValueRange.constant(imm)
                continue

            right_clean = InstructionParser.clean_reg(right)
            if InstructionParser.is_reg(right_clean):
                right64 = InstructionParser.normalize_reg64(right_clean)
                cmp_bound = self._vd.get(right64)
                continue

            if '[' in right:
                base, off = InstructionParser.parse_mem(right)
                if base:
                    cmp_bound = self._vd.get_mem(off)
                    if cmp_bound.is_top:
                        cmp_bound = self._vd.get(
                            InstructionParser.normalize_reg64(base))
                continue

        if is_test_loop:
            return ValueRange.unsigned_range(0, 0x100000)

        if cmp_bound is None or cmp_bound.is_top:
            return ValueRange.unsigned_range(0, 0x100000)

        last_idx = body_indices[-1]
        last_line = (instructions[last_idx].strip()
                     if last_idx < len(instructions) else "")
        cond = last_line.split()[0] if last_line else ""

        if cond in ('jle', 'jbe'):
            if cmp_bound.umin >= 0:
                return ValueRange.unsigned_range(
                    cmp_bound.umin + 1,
                    min(cmp_bound.umax + 1, 0x100000))
        elif cond in ('jl', 'jb'):
            if cmp_bound.umin >= 0:
                return ValueRange.unsigned_range(
                    cmp_bound.umin,
                    min(cmp_bound.umax, 0x100000))
        elif cond in ('jne', 'jnz', 'jz', 'je'):
            return ValueRange.unsigned_range(0, 0x100000)

        return (ValueRange.unsigned_range(0, 0x100000)
                if cmp_bound.is_top
                else ValueRange.unsigned_range(cmp_bound.umin, cmp_bound.umax))
    def _check_aggregate_write(self, matching_writes: List[Dict],
                               iter_range: 'ValueRange', loop_start: int,
                               site=None) -> Optional['OverflowFinding']:
        """聚合检查: 循环体内多个写入的总量 vs 分配量.

        返回单个聚合发现或 None (可证明安全时).
        """
        from .heap_overflow_detector import OverflowFinding
        from .constraint_simplifier import OverflowVerdict

        agg_size = sum(iw['write_size'] for iw in matching_writes)
        site = None
        func_name = ""
        for iw in matching_writes:
            s = self._alloc._alloc_sites.get(iw['alloc_site_id'])
            if s:
                site = s
                func_name = iw['function_name']
                break
        if site is None:
            return None

        total_write = iter_range.mul(ValueRange.constant(agg_size))
        a_min = site.min_allocation()
        actual_usable = self._heap_model.get_usable_size(a_min)
        if actual_usable > a_min:
            alloc_range = ValueRange.unsigned_range(
                actual_usable, site.max_allocation())
        else:
            alloc_range = site.alloc_size_range

        result = self._constraint.check_heap_write(
            total_write, ValueRange.constant(0), alloc_range,
            is_str_copy=False)
        if result.verdict == OverflowVerdict.DEFINITE_SAFE:
            return None
        sev = self._severity(result, False)
        return OverflowFinding(
            finding_id=f"HEAP-LOOP-AGG-{loop_start}",
            function_name=func_name,
            sink_func=f"loop_write({agg_size}B/iter)",
            severity=sev,
            confidence=result.overflow_confidence,
            alloc_site_info=(
                f"{site.alloc_func}@{site.call_address:#x}, "
                f"size∈[{site.min_allocation()},{site.max_allocation()}]"),
            overflow_detail=(
                f"循环聚合写入: {agg_size}B/iter × "
                f"[{iter_range.umin},{iter_range.umax}] iter = "
                f"[{total_write.umin},{total_write.umax}]B, "
                f"分配=[{site.min_allocation()},{site.max_allocation()}]B, "
                f"判定={result.verdict.name}"),
            write_size_min=total_write.umin,
            write_size_max=total_write.umax,
            alloc_size_min=site.min_allocation(),
            alloc_size_max=site.max_allocation(),
            input_controlled=False,
            evidence=result.evidence,
            recommendation=self._recommend_loop(
                result, site, total_write, agg_size))

    def _recommend_loop(self, result, alloc, total_write,
                        per_write: int) -> str:
        """循环发现修复建议 (供聚合与逐写入路径共用)."""
        from .constraint_simplifier import OverflowVerdict
        parts = []
        if result.verdict == OverflowVerdict.DEFINITE_OVERFLOW:
            parts.append(
                f"循环写入确认溢出: "
                f"限制迭代次数使总写入≤{alloc.min_allocation()}B")
        elif result.verdict == OverflowVerdict.POSSIBLE_OVERFLOW:
            parts.append(
                f"添加循环边界检查: malloc({alloc.min_allocation()}) "
                f"< 总写入量(≤{total_write.umax}B)")
        parts.append(f"(每轮{per_write}B)")
        return "; ".join(parts)
