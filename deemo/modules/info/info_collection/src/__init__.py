# info_collection/src — 二进制情报提取入口
# 通过 __getattr__ 按需加载子模块，避免全量导入

__version__ = "2.2.0"

_submodules = {
    "config": ".config",
    "utils": ".utils",
    "binary_info": ".binary_info",
    "anonymizer": ".anonymizer",
    "findings": ".findings",
    "injection_detect": ".injection_detect",
    "lateral": ".lateral",
    "persistence": ".persistence",
    "spoofing": ".spoofing",
    "tls_detect": ".tls_detect",
    "leak_analyzer": ".leak_analyzer",
    "pii": ".pii",
    "cli": ".cli",
    "binary_scanner": ".binary_scanner",
    "protection_interaction": ".protection_interaction",
    "segment_risk": ".segment_risk",
    "security_posture": ".security_posture",
    "posture_pipeline": ".posture_pipeline",
    "cfg_entropy_fingerprint": ".cfg_entropy_fingerprint",
    "exploit_chain_inference": ".exploit_chain_inference",
    "posture_regression": ".posture_regression",
    "entropy_gradient_profiler": ".entropy_gradient_profiler",
    "evidence_fusion": ".evidence_fusion",
    "ttp_correlation": ".ttp_correlation",
    "binary_profiling": ".binary_profiling",
    "pe_elf_analysis": ".pe_elf_analysis",
    "supply_chain_risk": ".supply_chain_risk",
    "evasion_susceptibility": ".evasion_susceptibility",
    "binary_cti_bridge": ".binary_cti_bridge",
    "compiler_normalizer": ".compiler_normalizer",
    "mrem_entropy_map": ".mrem_entropy_map",
    "import_reachability": ".import_reachability",
    "unified_risk_synthesis": ".unified_risk_synthesis",
    "mutation_predictor": ".mutation_predictor",
    "binary_phylogeny": ".binary_phylogeny",
    "confidence_calibrator": ".confidence_calibrator",
    "delta_impact_analyzer": ".delta_impact_analyzer",
    "obfuscation_classifier": ".obfuscation_classifier",
    "cross_arch_equivalence": ".cross_arch_equivalence",
    "capability_inference": ".capability_inference",
    "vuln_inheritance": ".vuln_inheritance",
    "fuzz_prioritizer": ".fuzz_prioritizer",
    "security_decision_engine": ".security_decision_engine",
    "bypass_likelihood": ".bypass_likelihood",
    "knowledge_transfer": ".knowledge_transfer",
    "resource_analyzer": ".resource_analyzer",
    "corpus_baseline": ".corpus_baseline",
    "dangerous_arg_annotations": ".dangerous_arg_annotations",
    "safety_witness_searcher": ".safety_witness_searcher",
    "tiered_vuln_detector": ".tiered_vuln_detector",
    "heap_overflow_detector": ".heap_overflow_detector",
    "uaf_causal_analyzer": ".uaf_causal_analyzer",
    "format_string_analyzer": ".format_string_analyzer",
    "stack_overflow_analyzer": ".stack_overflow_analyzer",
    "int_overflow_detector": ".int_overflow_detector",
    "_shared": "._shared",
    "allocation_tracker": ".allocation_tracker",
    "size_arg_classifier": ".size_arg_classifier",
}

def __getattr__(name):
    if name in _submodules:
        import importlib
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError("module {} has no attribute {}".format(__name__, name))

__all__ = list(_submodules.keys()) + ["__version__"]
