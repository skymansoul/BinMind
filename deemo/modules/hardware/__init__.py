# 2026-07-15

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "SpectreGadgetDetector": (".spectre_detector", "SpectreGadgetDetector"),
    "SpectreGadget": (".spectre_detector", "SpectreGadget"),
    "SpectreType": (".spectre_detector", "SpectreType"),
    "PMCAnalyzer": (".pmc_analyzer", "PMCAnalyzer"),
    "MicroarchSideChannelValidator": (".microarch_side_channel_validator", "MicroarchSideChannelValidator"),
    "GPUFuzzerCore": (".gpu_fuzzer", "GPUFuzzerCore"),
    "MTEAnalyzer": (".mte_simulator", "MTEAnalyzer"),
    "SideChannelEvaluator": (".side_channel_evaluator", "SideChannelEvaluator"),
}


def __getattr__(name: str):
    import importlib

    if name in _LAZY_IMPORTS:
        mod_path, attr = _LAZY_IMPORTS[name]
        mod = importlib.import_module(mod_path, __package__)
        return getattr(mod, attr)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
