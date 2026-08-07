# 静态堆溢出检测分析引擎
# 核心创新: 分配点感知的值域分析 + 指针溯源
# 方法论基础: 抽象解释 + 值集分析 (Balakrishnan & Reps 2004)
# 创新边界: 通过追踪malloc→指针→写入的完整链路, 在二进制层面消除误报
#   传统方法仅模式匹配危险函数, 不验证分配大小是否确实不足
from __future__ import annotations
from .value_range import ValueRange, ValueRangeDomain
from .allocation_tracker import AllocationSite, AllocationTracker
from .pointer_provenance import PointerOrigin, PointerProvenanceTracker
from .constraint_simplifier import ConstraintSimplifier
from .heap_overflow_detector import (
    HeapAccessCheck, OverflowFinding, HeapOverflowDetector
)
from .taint_propagation import TaintTag, TaintTracker
from .heap_allocator_model import (
    HeapAllocatorModel, AllocatorFamily, ChunkModel
)
from .false_positive_filter import FalsePositiveFilter, FilterVerdict
from .size_identity import SizeIdentity, SizeIdentityTracker
from .path_constraint_applier import PathConstraintApplier
from .loop_bound_analyzer import LoopBoundAnalyzer, LoopInfo
from .loop_bound_analyzer import locate_operand
from .fp_reduction_mixin import FpReductionMixin

__all__ = [
    'ValueRange', 'ValueRangeDomain',
    'AllocationSite', 'AllocationTracker',
    'PointerOrigin', 'PointerProvenanceTracker',
    'ConstraintSimplifier',
    'HeapAccessCheck', 'OverflowFinding', 'HeapOverflowDetector',
    'TaintTag', 'TaintTracker',
    'HeapAllocatorModel', 'AllocatorFamily', 'ChunkModel',
    'FalsePositiveFilter', 'FilterVerdict',
    'SizeIdentity', 'SizeIdentityTracker',
    'PathConstraintApplier', 'LoopBoundAnalyzer', 'LoopInfo',
    'locate_operand', 'FpReductionMixin',
]
