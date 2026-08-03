# INTJ策略: 延迟加载所有子模块，避免循环依赖和启动开销
# 首次访问时触发 import，后续调用返回缓存

_MODULES: dict[str, object] = {}

_EXPORTS: dict[str, list[str]] = {
    "binary_formats": ["BinaryFormatParser"],
    "symbolic_analysis": ["_has_z3", "SymbolicAnalysisBridge", "get_bridge"],
    "vuln_management": ["VulnKB", "CVEEntry", "match_vuln_patterns"],
    "ml_features": ["opcode_histogram", "ngram_features", "entropy_features",
                    "extract_feature_vector", "compute_imphash"],
    "function_boundary": ["detect_prologue", "detect_epilogue",
                          "find_function_starts", "align_func_boundary"],
    "pipeline_infra": ["TaskQueue", "BatchRunner", "dispatch_tasks",
                       "StageConfig", "PipelineTemplate"],
    "exploit_primitives": ["ExploitPrimitives"],
    "memory_heap": ["HeapAnalyzer"],
    "kernel_driver": ["KernelDriverAnalyzer"],
    "analysis_depth_estimator": ["estimate_depth"],
    "cross_validation": ["cross_validate"],
    "diff_notification": ["notify_diff"],
    "testing_fuzzing": ["TestFuzzer"],
    "function_inliner": ["analyze_inlining"],
}


def _load(modname: str) -> object:
    """加载单个子模块并缓存。递归安全"""
    if modname in _MODULES:
        return _MODULES[modname]
    mod = __import__(f"modules.analysis.static.binary_analysis.{modname}",
                     fromlist=_EXPORTS.get(modname, []))
    _MODULES[modname] = mod
    return mod


def __getattr__(name: str):
    # 先检查直接导出
    for modname, names in _EXPORTS.items():
        if name in names:
            mod = _load(modname)
            return getattr(mod, name)
    # 再尝试作为子模块名加载
    if name in _EXPORTS:
        return _load(name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def list_modules() -> list[str]:
    """返回所有可用的子模块名称"""
    return sorted(_EXPORTS.keys())


def preload_all() -> None:
    """预加载所有子模块（用于CI/测试环境一次性验证）"""
    for modname in _EXPORTS:
        try:
            _load(modname)
        except Exception:
            pass
