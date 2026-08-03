# 2026-08-03
# analysis/static/tools/ -- 静态分析工具集入口：懒加载子模块与结构化 src/ 子包
# Flat namespace 模块由 modules/__init__.py _FlatFinder 解析；
# 此 __init__.py 使 tools 成为可被子包导入的正规 package
# 并提供 modules.analysis.static.tools import X 的直接属性访问

import importlib

_submodules: dict[str, str] = {
    # -- 结构化子包 --
    "src": ".src",

    # -- 常用 flat 模块（按需懒加载，其余由 _FlatFinder 覆盖） --
    "abstract_interpretation": ".abstract_interpretation",
    "address_mapping": ".address_mapping",
    "address_space_simulation": ".address_space_simulation",
    "async_sm_recovery": ".async_sm_recovery",
    "binary_patch_diff": ".binary_patch_diff",
    "binary_similarity": ".binary_similarity",
    "binary_unpacker": ".binary_unpacker",
    "bpu_detector": ".bpu_detector",
    "branch_exploitability": ".branch_exploitability",
    "compiler_opt_analyzer": ".compiler_opt_analyzer",
    "config_extractor": ".config_extractor",
    "cpp_exception_recovery": ".cpp_exception_recovery",
    "cpp_vtbl_recovery": ".cpp_vtbl_recovery",
    "crypto_auditor": ".crypto_auditor",
    "ctf_challenge_engine": ".ctf_challenge_engine",
    "custom_isa_plugin": ".custom_isa_plugin",
    "dfd_generator": ".dfd_generator",
    "differential_fuzzer": ".differential_fuzzer",
    "digital_twin_risk": ".digital_twin_risk",
    "exploit_template_generator": ".exploit_template_generator",
    "federated_learning": ".federated_learning",
    "firmware_analyzer": ".firmware_analyzer",
    "gadget_chain_v2": ".gadget_chain_v2",
    "go_binary_analyzer": ".go_binary_analyzer",
    "heap_exploit_analyzer": ".heap_exploit_analyzer",
    "heap_layout_solver": ".heap_layout_solver",
    "hierarchical_resource_controller": ".hierarchical_resource_controller",
    "information_flow_verifier": ".information_flow_verifier",
    "int_overflow_exploit_gen": ".int_overflow_exploit_gen",
    "ipc_analyzer": ".ipc_analyzer",
    "jit_analyzer": ".jit_analyzer",
    "jit_pattern_extractor": ".jit_pattern_extractor",
    "kerberos_analyzer": ".kerberos_analyzer",
    "kernel_module_analyzer": ".kernel_module_analyzer",
    "license_compliance": ".license_compliance",
    "llvm_ir_analyzer": ".llvm_ir_analyzer",
    "malware_family_classifier": ".malware_family_classifier",
    "memory_forensics_toolkit": ".memory_forensics_toolkit",
    "object_pointer_graph": ".object_pointer_graph",
    "opa_policy_generator": ".opa_policy_generator",
    "ownership_analyzer": ".ownership_analyzer",
    "post_quantum_detector": ".post_quantum_detector",
    "precise_vtable_recovery": ".precise_vtable_recovery",
    "protocol_reverse_engine": ".protocol_reverse_engine",
    "protocol_state_inferrer": ".protocol_state_inferrer",
    "race_condition_detector": ".race_condition_detector",
    "report": ".report",
    "repro_env": ".repro_env",
    "reverse_report": ".reverse_report",
    "rop_chain_synthesizer": ".rop_chain_synthesizer",
    "sandbox_evasion_detector": ".sandbox_evasion_detector",
    "seh_analyzer": ".seh_analyzer",
    "semantic_diff_analyzer": ".semantic_diff_analyzer",
    "semantic_role_labeler": ".semantic_role_labeler",
    "state_fuzzer": ".state_fuzzer",
    "static_analysis": ".static_analysis",
    "streaming_binary_analyzer": ".streaming_binary_analyzer",
    "structured_input_fuzzer": ".structured_input_fuzzer",
    "structured_logging": ".structured_logging",
    "syscall_classifier": ".syscall_classifier",
    "syscall_constraint_inferencer": ".syscall_constraint_inferencer",
    "syscall_dependency_graph": ".syscall_dependency_graph",
    "syscall_pattern_matcher": ".syscall_pattern_matcher",
    "syscall_table_recovery": ".syscall_table_recovery",
    "taint_tracking_engine": ".taint_tracking_engine",
    "trend_tracker": ".trend_tracker",
    "type_confusion": ".type_confusion",
    "vuln_signature_scanner": ".vuln_signature_scanner",
    "yara_rule_generator": ".yara_rule_generator",
}


def __getattr__(name: str):
    if name in _submodules:
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = sorted(_submodules.keys())
