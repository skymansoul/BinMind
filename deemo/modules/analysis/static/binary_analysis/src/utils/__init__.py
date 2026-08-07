# Lazy import pattern: 延迟加载避免循环依赖与启动开销

_MODULES = {
    "helpers": None,
    "constants": None,
    "errors": None,
    "metrics": None,
}

_EXPORTS: dict[str, list[str]] = {
    "helpers": [
        "r2_json", "r2_cmd", "TTLCache", "atomic_write",
        "dig", "retry", "is_valid_hex_str", "chunk_list",
        "sanitize_filename",
    ],
    "constants": [
        "Arch", "IRType", "Severity", "BinaryFormat",
        "PACKER_SECTIONS",
    ],
    "errors": [
        "AnalysisError", "UnsupportedArchError", "R2NotFoundError",
        "DisassemblyError", "BinaryParseError",
        "SymbolicExecutionError", "TimeoutError",
    ],
    "metrics": [
        "MetricsRecorder", "ScopedTimer", "measure_time",
        "format_duration",
    ],
}


def _load(module_name: str):
    if _MODULES.get(module_name) is not None:
        return
    _MODULES[module_name] = __import__(
        f"binary_analysis.src.utils.{module_name}",
        fromlist=["*"],
    )
    for name in _EXPORTS.get(module_name, []):
        globals()[name] = getattr(_MODULES[module_name], name)


# 常用入口在模块级可访问，第一次访问时触发加载


def __getattr__(name: str):
    for mod, names in _EXPORTS.items():
        if name in names:
            _load(mod)
            return globals()[name]
    raise AttributeError(f"module has no attribute {name!r}")
