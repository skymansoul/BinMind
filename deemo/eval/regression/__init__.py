"""
回归测试包.

三模块架构:
  - sample_compiler  : 发现 + 编译样本
  - scan_scheduler   : 调度多工具扫描
  - result_collector : 汇总结果 + 计算指标

使用方式:
  python -m eval.regression.run_regression --samples-dir tests/samples/heap_overflow

创建: 2026-07-06
"""
from __future__ import annotations

from eval.regression.sample_compiler import (
    CompileResult,
    SampleCompiler,
    SampleManifest,
    SAMPLE_ROOTS,
)
from eval.regression.scan_scheduler import (
    ScanReport,
    ScanScheduler,
    ToolResult,
    PROJECT_ROOT,
)
from eval.regression.result_collector import (
    ResultCollector,
    SampleResult,
    ToolMetrics,
    OVERFLOW_VERDICTS,
    SAFE_VERDICTS,
)

__all__ = [
    'CompileResult', 'SampleCompiler', 'SampleManifest', 'SAMPLE_ROOTS',
    'ScanReport', 'ScanScheduler', 'ToolResult', 'PROJECT_ROOT',
    'ResultCollector', 'SampleResult', 'ToolMetrics',
    'OVERFLOW_VERDICTS', 'SAFE_VERDICTS',
]
