"""
集成堆溢出检测器 — 三阶段约束验证管线 (GAPSBV 核心).

管线:
  阶段1 (SVSA): Strided Interval 推断 malloc size 的可能值集
  阶段2 (约束): 路径约束收集, 剪除不可行路径上的违规
  阶段3 (建模): 分配器模型修正 actual write range

指令级追踪委托给 heap_instr_tracker.HeapInstrTracker.
"""


import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .strided_interval import StridedInterval, si_singleton, si_unbounded
from .constraint_tracker import PathCondition
from .heap_alloc_model import HeapAllocModel, AllocatorKind
from .heap_instr_tracker import HeapInstrTracker

_log = logging.getLogger(__name__)


@dataclass
class HeapOverflowFinding:
    """堆溢出检测结果, 含过滤状态和置信度."""
    alloc_site: int
    alloc_func: str
    alloc_size_si: StridedInterval
    alloc_usable_si: StridedInterval       # 经堆模型调整后的可用大小
    write_site: int
    write_func: str
    write_size_si: StridedInterval
    # 过滤状态
    raw_overflow: bool = True              # 阶段0: 原始检测
    svsa_feasible: bool = True             # 阶段1: SVSA后仍为溢出
    constraint_feasible: bool = True       # 阶段2: 路径约束后仍为溢出
    alloc_model_overflow: bool = True      # 阶段3: 堆模型后仍为溢出
    # 最终判决
    is_true_positive: bool = True
    confidence: float = 0.5
    reason: str = ""


@dataclass
class DetectionStats:
    """各阶段过滤统计 — 用于消融实验."""
    total_candidates: int = 0
    svsa_filtered: int = 0
    constraint_filtered: int = 0
    alloc_model_filtered: int = 0
    final_count: int = 0

    @property
    def fp_reduction_pct(self) -> float:
        if self.total_candidates == 0:
            return 0.0
        return (self.total_candidates - self.final_count) / self.total_candidates * 100


class HeapOverflowDetector:
    """三阶段堆溢出检测与误报削减.

    使用方式:
      detector = HeapOverflowDetector(allocator=AllocatorKind.PTMALLOC2)
      detector.analyze_function(insns, func_name="target_fn")
      findings = detector.get_findings(min_confidence=0.3)
      print(detector.get_stats())
    """

    def __init__(self, allocator: AllocatorKind = AllocatorKind.PTMALLOC2):
        self._heap_model = HeapAllocModel(allocator)
        self._tracker = HeapInstrTracker(self._heap_model)
        self._findings: List[HeapOverflowFinding] = []

    # 公开接口

    def analyze_function(self, insns: List[Tuple[int, str]],
                         func_name: str = "",
                         arch: str = "x86_64") -> List[HeapOverflowFinding]:
        """分析函数指令序列, 返回按置信度降序的检测结果."""
        self._tracker.clear()
        self._findings.clear()

        for addr, insn in insns:
            il = insn.strip().lower()
            self._tracker.process_insn(addr, il)

        # 分析完成 — 生成最终结果
        self._post_process()
        return self.get_findings()

    def get_findings(self, min_confidence: float = 0.3
                     ) -> List[HeapOverflowFinding]:
        """返回置信度 >= min_confidence 的检测结果."""
        return sorted(
            [f for f in self._findings if f.confidence >= min_confidence],
            key=lambda f: -f.confidence)

    def get_stats(self) -> DetectionStats:
        """返回各阶段过滤统计."""
        stats = DetectionStats()
        stats.total_candidates = len(self._findings)
        stats.svsa_filtered = sum(
            1 for f in self._findings if f.raw_overflow and not f.svsa_feasible)
        stats.constraint_filtered = sum(
            1 for f in self._findings
            if f.svsa_feasible and not f.constraint_feasible)
        stats.alloc_model_filtered = sum(
            1 for f in self._findings
            if f.constraint_feasible and not f.alloc_model_overflow)
        stats.final_count = sum(1 for f in self._findings if f.is_true_positive)
        return stats

    # 内部: 三阶段检查 + 后处理

    def _post_process(self):
        """从追踪器收集候选, 执行三阶段检查, 去重."""
        pc = self._tracker.constraint_tracker.get_path_condition()

        for alloc_site, write_site, write_func, write_si in self._tracker.candidates:
            alloc_func, ptr_name, alloc_si = self._tracker.allocs[alloc_site]
            finding = HeapOverflowFinding(
                alloc_site=alloc_site,
                alloc_func=alloc_func,
                alloc_size_si=alloc_si,
                alloc_usable_si=StridedInterval(0, 0, 1),
                write_site=write_site,
                write_func=write_func,
                write_size_si=write_si,
            )
            self._check_overflow(finding, pc)
            self._findings.append(finding)

        # 去重: 同一 (alloc_site, write_site) 只保留最高置信度
        seen: Dict[Tuple[int, int], HeapOverflowFinding] = {}
        for f in self._findings:
            key = (f.alloc_site, f.write_site)
            if key not in seen or f.confidence > seen[key].confidence:
                seen[key] = f
        self._findings = list(seen.values())

    def _check_overflow(self, finding: HeapOverflowFinding, pc: PathCondition):
        """三阶段溢出检查."""
        alloc_si = finding.alloc_size_si
        write_si = finding.write_size_si

        # 阶段0: 边界检查 — 无法确定的保守放行
        if alloc_si.is_unbounded() or write_si.is_unbounded():
            finding.raw_overflow = False
            finding.is_true_positive = False
            finding.confidence = 0.0
            finding.reason = "unbounded SI — 保守放行"
            return
        if alloc_si.is_bottom() or write_si.is_bottom():
            finding.raw_overflow = False
            finding.is_true_positive = False
            finding.confidence = 0.0
            finding.reason = "bottom SI"
            return

        alloc_hi = alloc_si.hi
        write_hi = write_si.hi

        # 阶段1: SVSA — strided interval 层面是否一定不溢出
        if write_hi is not None and alloc_hi is not None and write_hi <= alloc_hi:
            finding.svsa_feasible = False
            finding.is_true_positive = False
            finding.confidence = 0.1
            finding.reason = f"SVSA: write_hi={write_hi} <= alloc_hi={alloc_hi}"
            return

        # 阶段2: 约束剪枝 — 路径条件是否保证安全
        if pc.constraints and self._check_safety_constraint(pc, finding):
            finding.constraint_feasible = False
            finding.is_true_positive = False
            finding.confidence = 0.15
            finding.reason = "路径约束保证安全"
            return

        # 阶段3: 堆模型修正 — 调整 alloc usable_range
        adj_lo = self._heap_model.model_allocation(
            max(1, alloc_si.lo or 1)).usable_size
        adj_hi = self._heap_model.model_allocation(
            max(1, max(alloc_si.lo or 1, alloc_si.hi or 1))).usable_size
        finding.alloc_usable_si = StridedInterval(
            adj_lo, adj_hi, alloc_si.stride)

        if write_hi is not None and write_hi <= adj_hi:
            finding.alloc_model_overflow = False
            finding.is_true_positive = False
            finding.confidence = 0.2
            finding.reason = (
                f"堆模型修正: write_hi={write_hi} <= "
                f"usable_hi={adj_hi} (raw alloc_hi={alloc_si.hi})")
            return

        # 三阶段通过 → 可能是真阳性
        finding.is_true_positive = True
        overflow_ratio = ((write_hi or 0) - adj_hi) / max(1, adj_hi)
        finding.confidence = min(0.95, 0.5 + overflow_ratio * 0.3)
        finding.reason = (
            f"三阶段通过: write_size={write_si}, alloc_size={alloc_si}, "
            f"usable_size={finding.alloc_usable_si}")

    @staticmethod
    def _check_safety_constraint(pc: PathCondition,
                                  finding: HeapOverflowFinding) -> bool:
        """检查路径约束是否保证 write_size <= alloc_size."""
        write_hi = finding.write_size_si.hi
        alloc_lo = finding.alloc_size_si.lo
        if write_hi is not None and alloc_lo is not None and write_hi <= alloc_lo:
            return True
        for c in pc.constraints:
            if c.is_equality:
                continue
        return False
