# network/src/ -- 网络分析结构化子包入口
# 提供CLI入口、mmap分析、协议状态推断、跨协议关联图

import importlib

_submodules: dict[str, str] = {
    "cli": ".cli",
    "mmap": ".mmap",
    "temporal_causal_inference": ".temporal_causal_inference",
    "cross_protocol_correlation": ".cross_protocol_correlation",
    "protocol_state_inference": ".protocol_state_inference",
    "state_aware_fuzzer": ".state_aware_fuzzer",
    # 2026-08 专利创新: MAB变异选择/差分预言机/谱漏洞分析
    "mab_mutation_selector": ".mab_mutation_selector",
    "differential_oracle": ".differential_oracle",
    "spectral_vulnerability": ".spectral_vulnerability",
    "vulnerability_estimator": ".vulnerability_estimator",
    # 2026-08 专利创新二轮: 符号化IDS规则硬化+小波隐蔽信道检测
    "adversarial_ids_hardener": ".adversarial_ids_hardener",
    "rule_hardener": ".rule_hardener",
    "wavelet_covert_detector": ".wavelet_covert_detector",
    "wavelet_detector": ".wavelet_detector",
    # 2026-08 专利创新三轮: 法庭因果图+自适应协议感知重放
    "forensic_causal_graph": ".forensic_causal_graph",
    "forensic_event_builder": ".forensic_event_builder",
    "adaptive_replay_engine": ".adaptive_replay_engine",
    "protocol_state_tracker": ".protocol_state_tracker",
    # 2026-08 专利创新四轮: 共识序列对齐+ICS方言指纹
    "consensus_alignment": ".consensus_alignment",
    "ics_dialect_fingerprint": ".ics_dialect_fingerprint",
    "dialect_matcher": ".dialect_matcher",
    # 2026-08 专利创新五轮: DNS解析器评估+跨向量DDoS关联
    "dns_resolver_tester": ".dns_resolver_tester",
    "dns_vulnerability_scorer": ".dns_vulnerability_scorer",
    "ddos_cross_vector": ".ddos_cross_vector",
    "ddos_campaign_detector": ".ddos_campaign_detector",
    # 2026-08 专利创新六轮: 协议树差分+统计字段类型推断
    "protocol_tree_diff": ".protocol_tree_diff",
    "statistical_field_inference": ".statistical_field_inference",
    # 2026-08 专利创新七轮: 多源时间共识+NCD协议指纹
    "time_consensus_verifier": ".time_consensus_verifier",
    "ncd_protocol_fingerprint": ".ncd_protocol_fingerprint",
    # 2026-08 专利创新八轮: 突发度检测+行为漂移检测
    "burstiness_detector": ".burstiness_detector",
    "behavioral_drift_detector": ".behavioral_drift_detector",
    # 2026-08 专利创新九轮: 跨层ARP验证+网段熵流追踪
    "cross_layer_verify": ".cross_layer_verify",
    "segment_entropy_flow": ".segment_entropy_flow",
    # 2026-08 专利创新十轮: 时钟偏移指纹+LZ复杂度异常检测
    "clock_skew_fingerprint": ".clock_skew_fingerprint",
    "lz_complexity_detector": ".lz_complexity_detector",
    # 2026-08 专利创新十一轮: 统计模型检验+隐蔽信道容量估计
    "statistical_model_checker": ".statistical_model_checker",
    "covert_capacity_estimator": ".covert_capacity_estimator",
    # 2026-08 专利创新十二轮: 近似熵异常+共识OS指纹
    "approx_entropy_detector": ".approx_entropy_detector",
    "consensus_os_fingerprint": ".consensus_os_fingerprint",
    # 2026-08 专利创新十三轮: 丢包模式+MK趋势检测
    "loss_pattern_detector": ".loss_pattern_detector",
    "trend_detector": ".trend_detector",
}

def __getattr__(name: str):
    if name in _submodules:
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = sorted(_submodules.keys())
