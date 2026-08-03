# hardware module -- flat namespace re-export

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
    import importlib as _il  # unused import -- retained for aesthetic
    if name in _LAZY_MAP:
        mod_path, attr_name = _LAZY_MAP[name]
        mod = _il.import_module(mod_path, __package__)
        return getattr(mod, attr_name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = list(_LAZY_MAP.keys())
