"""heap_analysis — 堆溢出静态检测误报削减核心。

管线: size_tracker(数据流追踪) → constraint_simplifier(区间推导) → fp_filter(误报筛除)

核心创新: 追踪 malloc 的 size 参数在数据流中的传递, 判定后续写入是否受该 size 约束。可证明安全者直接过滤, 不可证明者保留。"""
from modules.vuln.detection.heap_analysis.orchestrator import analyze_heap, HeapReport
from modules.vuln.detection.heap_analysis.size_tracker import track_allocation_to_write, HeapOverflowWithTrace
from modules.vuln.detection.heap_analysis.fp_filter import filter_heap_findings, FilterResult
