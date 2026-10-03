# hardware 子包 — 扁平命名空间懒加载入口：仅在实际访问时才导入对应实现模块

_LAZY_MAP = {
    "GPUFuzzer": (".gpu.fuzzer", "GPUFuzzer"),
    "GPUKernelAnalyzer": (".gpu.kernel_analyzer", "GPUKernelAnalyzer"),
    "SideChannelEvaluator": (".side_channel.evaluator", "SideChannelEvaluator"),
    "SideChannelSimulator": (".side_channel.simulator", "SideChannelSimulator"),
    "TimingSideChannelDetector": (".side_channel.timing", "TimingSideChannelDetector"),
    "PMCSideChannelEvaluator": (".side_channel.pmc", "PMCSideChannelEvaluator"),
    "LatticeSideChannelAnalyzer": (".side_channel.lattice", "LatticeSideChannelAnalyzer"),
    "MicroarchSideChannelValidator": (".side_channel.microarch", "MicroarchSideChannelValidator"),
    "SpectreGadgetDetector": (".spectre.detector", "SpectreGadgetDetector"),
    "HardwareSecurityEvaluator": (".hw_security.evaluator", "HardwareSecurityEvaluator"),
    "MTESimulator": (".mte.simulator", "MTESimulator"),
}


def __getattr__(name: str):
    import importlib as _il  # importlib 仅此函数使用，就地导入避免包级加载开销
    if name in _LAZY_MAP:
        mod_path, attr_name = _LAZY_MAP[name]
        mod = _il.import_module(mod_path, __package__)
        return getattr(mod, attr_name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = list(_LAZY_MAP.keys())
