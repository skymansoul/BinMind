# 堆溢出静态检测器 — 核心引擎
# 三阶段分析管道:
#   Pass 1 — 分配建模: 识别heap alloc调用, 推导大小值域
#   Pass 2 — 指针溯源+约束验证: 追踪指针→验证写入vs分配
#   Pass 3 — 保守回退: 无溯源信息时的模式匹配补漏
# 核心创新: 阶段2中, 可证明安全的写入 (w_hi+o ≤ a_lo) 不报告,
#   这是与模式匹配方案的根本差异 — 也是误报率大幅降低的关键
# 模块拆分 : heap_call_handler/heap_loop_detector/
#   heap_inline_tracker/loop_aggregate/fp_reduction_mixin 等
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

from .value_range import ValueRange
from .value_range import ValueRangeDomain
from .allocation_tracker import AllocationTracker
from .pointer_provenance import PointerOrigin, PointerProvenanceTracker
from .constraint_simplifier import (ConstraintSimplifier, ConstraintResult,
                                     OverflowVerdict)
from .taint_propagation import TaintTag, TaintTracker
from .instruction_parser import InstructionParser, PropagationCoordinator
from .heap_allocator_model import HeapAllocatorModel, AllocatorFamily
from .false_positive_filter import FalsePositiveFilter, FilterVerdict
from .heap_call_handler import CallHandlerMixin
from .heap_loop_detector import LoopDetectorMixin
from .heap_inline_tracker import InlineTrackerMixin
from .fp_reduction_mixin import FpReductionMixin

log = logging.getLogger(__name__)

import platform as _platform
if _platform.system() == 'Windows':
    _ARG_REGS = ["rcx", "rdx", "r8", "r9"]
else:
    _ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
_WRITE_SINKS = {"memcpy", "memmove", "memset", "__memcpy_chk", "__memmove_chk",
    "strcpy", "strncpy", "strcat", "strncat", "stpcpy",
    "sprintf", "snprintf", "bcopy", "memccpy", "wmemcpy", "wmemmove"}
_STR_SINKS = {"strcpy", "strcat", "stpcpy", "sprintf", "vsprintf"}


class OverflowSeverity(Enum):
    CRITICAL = auto(); HIGH = auto(); MEDIUM = auto()
    LOW = auto(); INFO = auto()


@dataclass
class HeapAccessCheck:
    access_id: str; sink_func: str
    dst_reg: str = ""; src_reg: str = ""; size_reg: str = ""
    size_range: ValueRange = field(default_factory=ValueRange.top)
    alloc_site: Optional['AllocationSite'] = None
    pointer_origin: Optional[PointerOrigin] = None
    constraint_result: Optional[ConstraintResult] = None
    taint_tag: Optional[TaintTag] = None
    instruction_address: int = 0
    function_name: str = ""


@dataclass
class OverflowFinding:
    finding_id: str; function_name: str; sink_func: str
    severity: OverflowSeverity; confidence: float
    alloc_site_info: str; overflow_detail: str
    is_false_positive: bool = False
    false_positive_reason: str = ""
    evidence: List[str] = field(default_factory=list)
    recommendation: str = ""
    alloc_size_min: int = 0; alloc_size_max: int = 0
    write_size_min: int = 0; write_size_max: int = 0
    input_controlled: bool = False
    instruction_address: int = 0   # 写入指令索引 (后处理增强层定位用)
    size_reg: str = ""             # 写入大小寄存器 (路径守卫匹配用)


class HeapOverflowDetector(FpReductionMixin, CallHandlerMixin,
                           LoopDetectorMixin, InlineTrackerMixin):
    """堆溢出静态检测器.

    使用分配点感知的指针溯源+值域约束验证来检测堆溢出,
    同时通过证明"写入量在分配范围内"来消除误报.
    Mixin拆分: CallHandlerMixin (调用处理), LoopDetectorMixin (循环分析),
    InlineTrackerMixin (内联写入+跨函数溯源).
    """

    def __init__(self):
        self._alloc = AllocationTracker()
        self._prov = PointerProvenanceTracker()
        self._constraint = ConstraintSimplifier(assume_glibc_heap=True)
        self._taint = TaintTracker()
        self._vd = ValueRangeDomain()
        self._coord = PropagationCoordinator(self._prov, self._taint, self._vd)
        self._parser = InstructionParser()
        self._current_func = "_entry_"
        self._call_ctr = 0
        self._heap_model = HeapAllocatorModel(AllocatorFamily.WINDOWS_HEAP)
        self._fp_filter = FalsePositiveFilter(self._heap_model)

    def analyze(self, instructions: List[str],
                func_map: Optional[Dict[str, Tuple[int, int]]] = None,
                instr_addrs: Optional[List[int]] = None
                ) -> List[OverflowFinding]:
        """执行完整的三阶段检测管道 (+ Pass 2.5: 循环逐字节写入检测)."""
        self._reset(); func_map = func_map or {}
        self._fp_ctx = (instructions, func_map, instr_addrs)
        pending: List[HeapAccessCheck] = []
        self._loop_writes: List[Tuple[int, str]] = []

        loop_bodies: Dict[int, List[int]] = {}
        if instr_addrs and len(instr_addrs) == len(instructions):
            loop_bodies = self._detect_loops(
                instructions, instr_addrs, func_map)

        # Pass 1: 分配建模 + 指针溯源 + 污点传播 + 内存写入追踪
        prev_func = self._current_func
        for i, line in enumerate(instructions):
            parsed = self._parser.parse_line(line)
            if parsed is None:
                continue
            op, ops = parsed
            for fname, (s, e) in func_map.items():
                if s <= i <= e:
                    self._current_func = fname
                    break
            if self._current_func != prev_func:
                fname = self._current_func
                is_crt = (fname.startswith('__') or fname.startswith('_.')
                          or fname.startswith('<') or fname == '_entry_')
                if is_crt:
                    self._prov.clear_all_registers()
                    self._vd.clear_registers()
                    self._vd.clear_memory()
                    self._coord.size_identity.clear_all_registers()
                self._prov.clear_stack_slots()
                self._coord.size_identity.clear_stack_slots()
                prev_func = self._current_func
            if op in ("call",) or op.startswith("call"):
                chk = self._process_call(i, ops, instructions, func_map)
                if chk:
                    pending.append(chk)
            self._dispatch_propagation(op, ops, i, line)

        self._postprocess_call_provenance(instructions, func_map)

        # Pass 2: 约束验证
        findings = []
        for chk in pending:
            f = self._verify(chk)
            if f:
                findings.append(f)

        # Pass 2.5: 循环逐字节写入检测
        loop_findings = self._check_loop_writes(
            loop_bodies, instructions, func_map)
        findings.extend(loop_findings)

        # Pass 3: 保守回退
        findings.extend(self._conservative_scan(instructions, func_map))
        findings.sort(key=lambda f: (f.severity.value, f.confidence))
        return findings

    def _verify(self, chk: HeapAccessCheck) -> Optional[OverflowFinding]:
        """约束验证: 两层递进证明写入是否溢出.

        Layer 1: ConstraintSimplifier值域碰撞检测 (L0-L3)
        Layer 2: FalsePositiveFilter分配器行为修正 + 多重安全证明
        只有两层都无法证明安全时才报告.
        """
        if chk.alloc_site is None or chk.pointer_origin is None:
            return None  # 无完整溯源, 宁可漏报

        alloc = chk.alloc_site; origin = chk.pointer_origin
        off_vr = ValueRange.constant(origin.offset_in_alloc)

        # Layer 1: 分配器行为修正
        a_min = alloc.min_allocation()
        actual_usable = self._heap_model.get_usable_size(a_min)
        if actual_usable > a_min:
            corrected_alloc_range = ValueRange.unsigned_range(
                actual_usable, alloc.max_allocation())
        else:
            corrected_alloc_range = alloc.alloc_size_range

        result = self._constraint.check_heap_write(
            chk.size_range, off_vr, corrected_alloc_range,
            is_str_copy=(chk.sink_func in _STR_SINKS))

        # Layer 2: 误报过滤器
        is_crt = (chk.function_name.startswith('__') or
                  chk.function_name.startswith('_.') or
                  chk.function_name.startswith('<'))
        fp_result = self._fp_filter.check(
            write_size=chk.size_range,
            write_offset=off_vr,
            alloc_size=corrected_alloc_range,
            function_name=chk.function_name,
            sink_func=chk.sink_func,
            alloc_func=alloc.alloc_func,
            is_crt_context=is_crt)

        if fp_result.verdict in (FilterVerdict.FILTER_SAFE,
                                  FilterVerdict.FILTER_NOISE):
            return None

        if result.verdict == OverflowVerdict.DEFINITE_SAFE:
            return None

        input_ctrl = chk.taint_tag is not None
        sev = self._severity(result, input_ctrl)

        if fp_result.verdict == FilterVerdict.DEMOTE:
            if sev == OverflowSeverity.HIGH:
                sev = OverflowSeverity.MEDIUM
            elif sev == OverflowSeverity.CRITICAL:
                sev = OverflowSeverity.HIGH

        finding = OverflowFinding(
            finding_id=f"HEAP-OVF-{chk.access_id}",
            function_name=chk.function_name, sink_func=chk.sink_func,
            severity=sev, confidence=result.overflow_confidence,
            alloc_site_info=(
                f"{alloc.alloc_func}@{alloc.call_address:#x}, "
                f"size∈[{alloc.min_allocation()},{alloc.max_allocation()}]"
                f"{', 实际可用'+str(actual_usable)+'B' if actual_usable > a_min else ''}"),
            overflow_detail=(
                f"写入={chk.size_range.umin}-{chk.size_range.umax}B, "
                f"偏移={origin.offset_in_alloc}, "
                f"分配={alloc.min_allocation()}-{alloc.max_allocation()}B, "
                f"判定={result.verdict.name}"
                f"{', '+fp_result.reason if fp_result.verdict != FilterVerdict.KEEP else ''}"),
            write_size_min=chk.size_range.umin,
            write_size_max=chk.size_range.umax,
            alloc_size_min=alloc.min_allocation(),
            alloc_size_max=alloc.max_allocation(),
            input_controlled=input_ctrl,
            evidence=result.evidence,
            recommendation=self._recommend(result, chk, alloc),
            instruction_address=chk.instruction_address,
            size_reg=chk.size_reg)
        return self._fp_reduction_post(chk, finding)

    def _severity(self, result: ConstraintResult, input_ctrl: bool
                  ) -> OverflowSeverity:
        if result.verdict == OverflowVerdict.DEFINITE_OVERFLOW:
            return OverflowSeverity.CRITICAL if input_ctrl else OverflowSeverity.HIGH
        if result.verdict == OverflowVerdict.POSSIBLE_OVERFLOW:
            if result.overflow_confidence >= 0.7:
                return OverflowSeverity.HIGH if input_ctrl else OverflowSeverity.MEDIUM
            if result.overflow_confidence >= 0.3:
                return OverflowSeverity.MEDIUM
            return OverflowSeverity.LOW
        return OverflowSeverity.INFO

    def _recommend(self, result: ConstraintResult,
                   chk: HeapAccessCheck, alloc: 'AllocationSite') -> str:
        parts = []
        if result.verdict == OverflowVerdict.DEFINITE_OVERFLOW:
            parts.append(f"确认溢出: 限制{chk.sink_func}写入≤{alloc.min_allocation()}B")
        elif result.verdict == OverflowVerdict.POSSIBLE_OVERFLOW:
            parts.append(f"添加边界检查: min(写入,{alloc.min_allocation()})")
        if chk.taint_tag:
            parts.append(f"写入大小受输入控制({chk.taint_tag.source_func})")
        if alloc.in_loop:
            parts.append("注意: 循环内分配, 检查累积效果")
        return "; ".join(parts) if parts else "手动审计"

    def _reset(self):
        self._alloc = AllocationTracker()
        self._prov = PointerProvenanceTracker()
        self._constraint = ConstraintSimplifier(assume_glibc_heap=True)
        self._taint = TaintTracker()
        self._vd = ValueRangeDomain()
        self._coord = PropagationCoordinator(self._prov, self._taint, self._vd)
        self._current_func = "_entry_"; self._call_ctr = 0
        self._loop_writes = []
        self._inline_writes: List[Dict] = []
        self._call_provenance_edges: List[Dict] = []

    @staticmethod
    def _in_same_function(addr_a: int, addr_b: int,
                          func_map: Dict[str, Tuple[int, int]]) -> bool:
        """检查两个指令地址是否属于同一函数.

        避免malloc(CRT)与memcpy(user)跨函数关联导致的误报.
        """
        for fname, (s, e) in func_map.items():
            a_in = s <= addr_a <= e
            b_in = s <= addr_b <= e
            if a_in and b_in:
                return True
            if a_in or b_in:
                return False
        return True

    def summary(self) -> Dict:
        return {
            "alloc": self._alloc.summary(),
            "provenance": self._prov.summary(),
            "taint": self._taint.summary(),
        }
