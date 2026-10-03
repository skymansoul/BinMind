# 堆溢出误报三阶段过滤器
# Stage1 常量传播 / Stage2 边界检查 / Stage3 分配-写入同源关联

from typing import Dict, List, Optional, Tuple
from .heap_slice_trace import BackwardSliceTracer, SourceKind, TaintSource
from .heap_constraint import HeapConstraintTracker, Interval


class HeapFPFilter:
    """三阶段堆溢出误报过滤器."""

    def __init__(self):
        self._stage1_filtered = 0
        self._stage2_filtered = 0
        self._stage3_filtered = 0
        self._passed = 0

    def filter(self, findings: List[dict],
                instructions: List[dict],
                alloc_tracker: HeapConstraintTracker) -> List[dict]:
        """三阶段级联过滤.

        findings: 初始堆溢出告警列表.
        instructions: 当前函数的指令序列.
        alloc_tracker: 堆约束追踪器 (含已记录的分配信息).
        返回: 过滤后的高置信度告警.
        """
        survivors = []
        tracer = BackwardSliceTracer()

        for finding in findings:
            # 仅处理堆相关告警
            if "heap" not in finding.get("type", "").lower():
                survivors.append(finding)
                continue

            # Stage 1: 常量传播
            if self._stage1_constant_prop(finding, instructions, tracer):
                self._stage1_filtered += 1
                continue

            # Stage 2: Bounds Check
            if self._stage2_bounds_check(finding, instructions, tracer,
                                           alloc_tracker):
                self._stage2_filtered += 1
                continue

            # Stage 3: Allocation-Site Correlation
            if self._stage3_alloc_correlation(finding, alloc_tracker):
                self._stage3_filtered += 1
                continue

            self._passed += 1
            finding["fp_filtered"] = False
            survivors.append(finding)

        return survivors

    def _stage1_constant_prop(self, finding: dict,
                               instructions: List[dict],
                               tracer: BackwardSliceTracer) -> bool:
        """Stage 1: 常量传播检查.

        若 size 参数可追踪为常量且 ≤ 分配大小 → 过滤.
        """
        size_op = finding.get("size_operand", "")
        alloc_sz = finding.get("alloc_size", 0)
        # alloc_sz 是对齐后的分配上界; 常量写量须严格落在原始请求
        # 区间内才判安全, 落在 padding 区域的写量交由 allocator 层
        # 精确判定, 避免小请求下真实溢出被常量传播误滤.
        request = finding.get("alloc_request")
        bound = request if request and request < 2**31 - 1 \
            else max(0, alloc_sz - 15)

        if not size_op:
            return False

        src = tracer.trace(instructions, size_op, max_depth=30)
        if src.kind == SourceKind.CONSTANT and src.value <= bound:
            finding["fp_stage"] = "stage1_constant"
            return True
        return False

    def _stage2_bounds_check(self, finding: dict,
                              instructions: List[dict],
                              tracer: BackwardSliceTracer,
                              alloc_tracker) -> bool:
        """Stage 2: Bounds Check 检测.

        若到达危险调用前, size 参数经过与分配大小的比较 → 过滤.
        """
        size_op = finding.get("size_operand", "")
        if not size_op:
            return False

        src = tracer.trace(instructions, size_op, max_depth=40)
        if src.kind == SourceKind.BOUNDS_CHECKED:
            finding["fp_stage"] = "stage2_bounds_checked"
            return True
        return False

    def _stage3_alloc_correlation(self, finding: dict,
                                    alloc_tracker: HeapConstraintTracker
                                    ) -> bool:
        """Stage 3: Allocation-Site Correlation.

        若此写入的指针与之前跟踪的分配一致, 且大小也一致 → 过滤.
        write_size 缺失时跳过, 因为未知大小不应被当作安全.
        """
        write_sz = finding.get("write_size")
        if write_sz is None:
            return False

        # 优先使用 finding 记录的快照地址, 避免 ptr_map 状态飘移
        alloc_addr = finding.get("_snapshot_alloc_addr")
        if alloc_addr is None:
            ptr_reg = finding.get("ptr_operand", "")
            alloc_addr = alloc_tracker._ptr_to_alloc.get(ptr_reg)
        if alloc_addr is None:
            return False

        alloc = alloc_tracker._allocations.get(alloc_addr)
        if alloc is None:
            return False

        # 写入大小须落在原始请求区间内才判同源安全; 落在 padding
        # 区域的写量交由 allocator 层精确判定.
        request = finding.get("alloc_request")
        bound = request if request and request < 2**31 - 1 \
            else max(0, alloc.alloc_size.lo - 15)
        if alloc.alloc_size.is_singleton and write_sz <= bound:
            finding["fp_stage"] = "stage3_alloc_correlation"
            return True
        return False

    @property
    def stats(self) -> dict:
        total = (self._stage1_filtered + self._stage2_filtered +
                 self._stage3_filtered + self._passed)
        return {
            "stage1_constant_filtered": self._stage1_filtered,
            "stage2_bounds_filtered": self._stage2_filtered,
            "stage3_correlation_filtered": self._stage3_filtered,
            "passed": self._passed,
            "total_processed": total,
            "filter_rate": round(
                (self._stage1_filtered + self._stage2_filtered +
                 self._stage3_filtered) / max(total, 1), 4),
        }


__all__ = ["HeapFPFilter"]
