"""DRIFT — Demand-driven Reverse Information Flow Tracking for UAF detection.

对象身份感知的时间分析: 追踪每个堆对象的唯一身份(alloc_site, func),
在free→use路径上验证是否为同一对象, 从根本上消除"不同对象同一寄存器"的误报.

模块:
  - object_identity: 堆对象身份模型 + 寄存器/栈槽→身份映射
  - pointer_kill_set: 指针寄存器的kill/gen数据流分析
  - free_use_validator: free-use对验证 (对象身份一致性 + 时序)
  - drift_orchestrator: 统一管线编排
  - drift_fp_filter: 语义FP削减 (路径可行性 + 循环感知 + realloc检测)
"""
from .drift_orchestrator import DriftReport, analyze_uaf
from .object_identity import HeapObject, ObjectIdentity, ObjIdTracker

__all__ = [
    'DriftReport', 'analyze_uaf',
    'HeapObject', 'ObjectIdentity', 'ObjIdTracker',
]
