# info_collection/src/ -- 意图推断与采集路由子包入口
# 向上导出 intent_route / llm_intent_infer 中的核心符号

import importlib

_submodules: dict[str, str] = {
    "intent_route": ".intent_route",
    "llm_intent_infer": ".llm_intent_infer",
    "beta_prior": ".beta_prior",  # 共享统计基元
    # 专利级创新模块 — 按需惰性加载, 不影响旧版导入路径
    "entropy_depth": ".entropy_depth",
    "intent_consistency": ".intent_consistency",
    "confidence_calibrate": ".confidence_calibrate",
    "info_gain_cascade": ".info_gain_cascade",
    "semantic_fingerprint": ".semantic_fingerprint",
    "session_context": ".session_context",
    # 第二批创新模块
    "prompt_defense": ".prompt_defense",
    "online_calibrate": ".online_calibrate",
    "causal_chain": ".causal_chain",
    "evidence_fusion": ".evidence_fusion",
    # 第三批创新模块
    "decision_provenance": ".decision_provenance",
    "probing_detection": ".probing_detection",
    "policy_guard": ".policy_guard",
    # 第四批创新模块
    "self_healing": ".self_healing",
    "rule_extractor": ".rule_extractor",
    # 第五批创新模块
    "embed_cache": ".embed_cache",
    "boundary_harden": ".boundary_harden",
    "bandit_router": ".bandit_router",
    "taxonomy_refine": ".taxonomy_refine",
    "param_calibrator": ".param_calibrator",
    "phase_sequence": ".phase_sequence",
    "api_argument_phase": ".api_argument_phase",
}

def __getattr__(name: str):
    if name in _submodules:
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = sorted(_submodules.keys())
