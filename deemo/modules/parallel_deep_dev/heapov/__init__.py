"""heapov — 容量感知耦合边界验证 堆溢出检测包。

面向 C 源码的轻量静态分析: 在仿射+区间双域上验证
写范围与分配容量的关系, 用耦合/守卫/对齐消除误报。
"""

from .detector import CACBVDetector, analyze_source
from .baseline_detector import BaselineDetector, analyze_baseline
from . import verdict as V

__all__ = ['CACBVDetector', 'analyze_source',
           'BaselineDetector', 'analyze_baseline', 'V']
