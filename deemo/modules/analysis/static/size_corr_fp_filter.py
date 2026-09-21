# 按需符号尺寸关联误报过滤器 - Stage 6/7/8
# Stage6 区间推理终判 / Stage7 符号尺寸关联 / Stage8 按需SMT

from typing import Dict, List, Optional
from .size_corr_coordinator import DDSSCCoordinator, DDSSCResult
from .sym_size_correlator import SymExpr
from .heap_constraint import Interval, HeapConstraintTracker
from .value_range import ValueRange
from .heap_alloc_model import HeapAllocModel


class DDSSCFPFilter:
    """按需符号尺寸关联三层误报过滤器 (Stage 6/7/8)."""

    def __init__(self, coordinator: DDSSCCoordinator,
                 alloc_model: HeapAllocModel = None):
        self._coordinator = coordinator
        self._alloc_model = alloc_model or HeapAllocModel()
        self._stage6_filtered = 0
        self._stage7_filtered = 0
        self._stage8_filtered = 0
        self._padding_filtered = 0
        self._passed = 0

    def filter(self, findings: List[dict],
               instructions: List[dict],
               alloc_tracker: HeapConstraintTracker,
               known_constants: Dict[str, int],
               sym_exprs: Optional[Dict[int, dict]] = None) -> List[dict]:
        """对Stage1-5存活告警执行按需符号尺寸关联三层过滤.

        参数:
          findings: Stage1-5存活告警列表
          instructions: 函数指令序列
          alloc_tracker: 堆约束追踪器
          known_constants: 已知常量表
          sym_exprs: {alloc_addr: {alloc_expr, write_expr, ...}}
                     符号表达式快照, 由检测器在分析过程中收集
        """
        survivors = []
        sym_exprs = sym_exprs or {}

        for finding in findings:
            if "heap" not in finding.get("type", "").lower():
                survivors.append(finding)
                continue

            alloc_addr = finding.get("_snapshot_alloc_addr",
                                     finding.get("alloc_addr", 0))
            write_addr = finding.get("write_addr", 0)

            alloc_info = sym_exprs.get(alloc_addr, {})
            alloc_expr = alloc_info.get("alloc_expr")
            # 优先从finding获取write_expr: 同一alloc_addr可能有多个写入操作
            write_expr = finding.get("_write_sym_expr")
            if write_expr is None:
                write_expr = alloc_info.get("write_expr")

            alloc_constraint = alloc_tracker._allocations.get(alloc_addr)
            if alloc_constraint is None:
                survivors.append(finding)
                continue

            raw_size = getattr(alloc_constraint, "raw_alloc_size",
                               alloc_constraint.alloc_size)
            alloc_iv = raw_size

            # 优先使用符号表达式解析出的精确常量作为写入大小
            write_size_val = 0
            if write_expr is not None and hasattr(write_expr, 'is_const') \
                    and write_expr.is_const():
                write_size_val = write_expr.const
            if write_size_val == 0:
                write_size_val = finding.get("write_size", 0)
            # 若alloc_expr也是常量, 复用其值替代区间上限
            if alloc_expr is not None and hasattr(alloc_expr, 'is_const') \
                    and alloc_expr.is_const():
                raw_size = Interval(alloc_expr.const, alloc_expr.const)

            write_iv = Interval(0, write_size_val) if write_size_val > 0 \
                else Interval(0, 2**31 - 1)

            alloc_vr = ValueRange(raw_size.lo, raw_size.hi)
            write_vr = ValueRange(write_iv.lo, write_iv.hi)

            result = self._coordinator.analyze_finding(
                alloc_addr=alloc_addr,
                alloc_size_interval=alloc_iv,
                write_size_interval=write_iv,
                alloc_size_expr=alloc_expr,
                write_size_expr=write_expr,
                alloc_vr=alloc_vr,
                write_vr=write_vr,
                instructions=instructions,
                write_addr=write_addr,
                known_constants=known_constants,
            )

            if result.verdict == "safe" and "layer1" in result.layer:
                finding["fp_stage"] = "stage6_ddssc_interval"
                finding["ddssc_detail"] = result.detail
                self._stage6_filtered += 1
                continue

            if result.verdict == "safe" and "layer2" in result.layer:
                finding["fp_stage"] = "stage7_ddssc_symbolic"
                finding["ddssc_detail"] = result.detail
                self._stage7_filtered += 1
                continue

            if result.verdict == "safe" and "layer3" in result.layer:
                finding["fp_stage"] = "stage8_ddssc_smt"
                finding["ddssc_detail"] = result.detail
                self._stage8_filtered += 1
                continue

            if result.verdict == "overflow" and "layer2" in result.layer:
                # 分配器padding检查: 若溢出量在padding范围内则安全
                if alloc_expr is not None and hasattr(alloc_expr, 'is_const') \
                        and alloc_expr.is_const() and write_size_val > 0:
                    ok, reason = self._alloc_model.is_overflow(
                        alloc_expr.const, write_size_val)
                    if not ok:
                        finding["fp_stage"] = "stage7_padding_safe"
                        finding["ddssc_detail"] = reason
                        self._padding_filtered += 1
                        continue
                finding["ddssc_verdict"] = "confirmed"
                finding["ddssc_layer"] = result.layer
                finding["ddssc_detail"] = result.detail
                if result.overflow_bytes > 0:
                    finding["overflow_bytes"] = result.overflow_bytes

            self._passed += 1
            finding["ddssc_verified"] = True
            survivors.append(finding)

        return survivors

    @property
    def stats(self) -> dict:
        total = (self._stage6_filtered + self._stage7_filtered +
                 self._stage8_filtered + self._padding_filtered + self._passed)
        return {
            "stage6_interval_filtered": self._stage6_filtered,
            "stage7_symbolic_filtered": self._stage7_filtered,
            "stage8_smt_filtered": self._stage8_filtered,
            "stage7_padding_filtered": self._padding_filtered,
            "passed": self._passed,
            "total_processed": total,
            "filter_rate": round(
                (self._stage6_filtered + self._stage7_filtered +
                 self._stage8_filtered + self._padding_filtered) / max(total, 1), 4),
        }


__all__ = ["DDSSCFPFilter"]
