# 网络流量分析与威胁检测入口
# FIXME: __version__ 应从单一 VERSION 文件读取；
#        当前在 3 个 __init__.py 中重复定义

__version__ = "0.5.0"

_submodules = {
    "automotive_analyzer": ".automotive_analyzer",
    "ble_radio_analyzer": ".ble_radio_analyzer",
    "can_anomaly_injector": ".can_anomaly_injector",
    "container_scanner": ".container_scanner",
    "ics_fuzz_template_generator": ".ics_fuzz_template_generator",
    "ics_protocol_analyzer": ".ics_protocol_analyzer",
    "iot_protocol_analyzer": ".iot_protocol_analyzer",
    "k8s_scanner": ".k8s_scanner",
    "mmap_binary_analyzer": ".mmap_binary_analyzer",
    "mmap_io": ".mmap_io",
    "protocol_infer": ".protocol_infer",
    "protocol_model_checker": ".protocol_model_checker",
    "protocol_reversing": ".protocol_reversing",
    "sdr_binary_analyzer": ".sdr_binary_analyzer",
    "serverless_analyzer": ".serverless_analyzer",
    "traffic_replayer": ".traffic_replayer",
    "wireless_analyzer": ".wireless_analyzer",
    "dns_analyzer": ".dns_analyzer",
    "tls_analyzer": ".tls_analyzer",
    "network_forensics": ".network_forensics",
    "network_ids": ".network_ids",
    "pcap_processor": ".pcap_processor",
    # 2026-07 广度扩展
    "quic_analyzer": ".quic_analyzer",
    "encrypted_traffic_classifier": ".encrypted_traffic_classifier",
    "netflow_analyzer": ".netflow_analyzer",
    "ddos_detector": ".ddos_detector",
    "ntp_analyzer": ".ntp_analyzer",
    "covert_channel_detector": ".covert_channel_detector",
    "arp_spoof_detector": ".arp_spoof_detector",
    "snmp_analyzer": ".snmp_analyzer",
    "voip_analyzer": ".voip_analyzer",
    "topology_mapper": ".topology_mapper",
    # 协议模糊测试编排 + RFC 合规校验
    "protocol_fuzz_orchestrator": ".protocol_fuzz_orchestrator",
    "rfc_compliance_checker": ".rfc_compliance_checker",
}

def __getattr__(name):
    if name in _submodules:
        import importlib
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

# 注册 MH-Flow 多视图异构图加密流量分类 + 环境偏移鲁棒流图
_submodules["mh_flow"] = ".mh_flow"
# 跨协议因果关联 / 对抗鲁棒分类 / 零日协议表征
_submodules["cross_protocol_correlation"] = ".cross_protocol_correlation"
_submodules["adversarial_robust_classifier"] = ".adversarial_robust_classifier"
_submodules["zeroday_protocol_char"] = ".zeroday_protocol_char"

__all__ = list(_submodules.keys()) + ["__version__"]

