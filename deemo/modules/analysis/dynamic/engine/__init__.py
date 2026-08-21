# 动态分析包 —— 懒加载入口
# 按需导入子模块，避免一次性加载所有依赖

import importlib
import sys
from typing import Any

__version__ = "0.3.0"

_MODULE_MAP: dict[str, str] = {}

# 现有模块
_existing = [
    "anti_analysis", "auto_input_minimizer", "baremetal_emulator",
    "behavior_tracer", "behavior_tracing", "breakpoint_recovery",
    "deterministic_replayer", "diagnostic_trace_mode", "dynamic_analysis_engine",
    "dynamic_struct_prober", "dynamic_taint", "forensic_path_recorder",
    "forensic_timeline_reconstructor", "hw_breakpoint_detector",
    "hw_breakpoint_monitor", "hw_trace_analyzer", "instrumentation",
    "intel_pt", "memory_forensics", "memory_heap", "memory_malware_detector",
    "memory_manipulation", "memory_object_reconstructor",
    "memory_primitive_extractor", "memory_sensitive_op_detector",
    "memory_visualizer", "mmio_responder", "shadow_stack_detector",
    "smc_dynamic_analyzer", "taint_propagation", "unicorn_hybrid", "vmi_analyzer",
]

# 新增模块
_new = [
    "sandbox_orchestrator", "api_hook_engine", "taint_engine_v2",
    "concolic_assist", "process_dumper", "crash_triage",
]

for m in _existing + _new:
    _MODULE_MAP[m] = "." + m

_CACHED: dict[str, Any] = {}

# 懒加载函数
def __getattr__(name: str) -> Any:
    if name in _CACHED:
        return _CACHED[name]
    if name not in _MODULE_MAP:
        raise AttributeError(f"module 'dynamic_analysis' has no attribute '{name}'")
    mod = importlib.import_module(
        _MODULE_MAP[name],
        __package__ or "modules.dynamic_analysis"
    )
    _CACHED[name] = mod
    return mod

__all__ = sorted(list(_MODULE_MAP.keys()) + ["__version__"])
