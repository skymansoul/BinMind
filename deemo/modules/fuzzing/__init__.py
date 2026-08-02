# 2026-07-15

"""Fuzzing module -- lazy-loads submodules on demand."""

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "Seed": ("fuzzing.src.core", "Seed"),
    "FuzzConfig": ("fuzzing.src.core", "FuzzConfig"),
    "FuzzResult": ("fuzzing.src.core", "FuzzResult"),
    "CorpusStats": ("fuzzing.src.core", "CorpusStats"),
    "CoverageBitmap": ("fuzzing.src.coverage", "CoverageBitmap"),
    "EdgeCoverage": ("fuzzing.src.coverage", "EdgeCoverage"),
    "CoverageTracker": ("fuzzing.src.coverage", "CoverageTracker"),
    "Scheduler": ("fuzzing.src.scheduler", "Scheduler"),
    "CorpusManager": ("fuzzing.src.scheduler", "CorpusManager"),
    "pick_seed": ("fuzzing.src.scheduler", "pick_seed"),
    "cull_queue": ("fuzzing.src.scheduler", "cull_queue"),
    # 延迟加载 -- 仅在显式引用时导入
    "FaultInjectionFuzzer": ("fuzzing.fault_injection_fuzzer", "FaultInjectionFuzzer"),
    "FaultInjectionResult": ("fuzzing.fault_injection_fuzzer", "FaultInjectionResult"),
    "ClusterAutoscaler": ("fuzzing.fuzz_cluster_autoscaler", "ClusterAutoscaler"),
    "TaskQueue": ("fuzzing.fuzz_cluster_autoscaler", "TaskQueue"),
    "NodeRegistry": ("fuzzing.fuzz_cluster_autoscaler", "NodeRegistry"),
    "SeedEvolution": ("fuzzing.fuzz_seed_evolution", "SeedEvolution"),
    "FuzzDictionaryGenerator": ("fuzzing.fuzz_dictionary_generator", "FuzzDictionaryGenerator"),
    "ConstantExtractor": ("fuzzing.fuzz_dictionary_generator", "ConstantExtractor"),
}

_IMPORT_CACHE: dict[str, object] = {}


def __getattr__(name: str) -> object:
    if name in _IMPORT_CACHE:
        return _IMPORT_CACHE[name]
    _entry = _LAZY_IMPORTS.get(name)
    if _entry is None:
        raise AttributeError(f"module 'fuzzing' has no attribute {name!r}")
    _mod_name, _attr_name = _entry
    _mod = __import__(_mod_name, fromlist=[_attr_name])
    _obj = getattr(_mod, _attr_name)
    _IMPORT_CACHE[name] = _obj
    return _obj


__all__ = sorted(_LAZY_IMPORTS.keys())
