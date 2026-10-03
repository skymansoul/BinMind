"""堆溢出检测分析子包 — 值流约束 + 对齐感知的静态检测.

模块:
- interval_domain: 跨步区间 SInterval + AllocatorModel ()
- backward_tracer: 后向值流追踪 ()
- access_parser: 内存访问指令解析 ()
  - malloc_size_inferrer: malloc 参数值流推断 (使用 interval_domain + backward_tracer)
  - heap_overflow_detector: 改进的主检测器 (使用 access_parser)
  - semantic_fp_filter: 语义级误报过滤器
"""
from .interval_domain import SInterval, AllocatorModel, DEFAULT_ALLOCATOR
from .malloc_size_inferrer import MallocSizeInferrer, MallocSite
from .heap_overflow_detector import (
    ImprovedHeapOverflowDetector, HeapOverflowFinding)
from .semantic_fp_filter import (
    SemanticFalsePositiveFilter, SemanticFeatures)

__all__ = [
    'SInterval', 'AllocatorModel', 'DEFAULT_ALLOCATOR',
    'MallocSizeInferrer', 'MallocSite',
    'ImprovedHeapOverflowDetector', 'HeapOverflowFinding',
    'SemanticFalsePositiveFilter', 'SemanticFeatures',
]
