# 2026-07-16
# network — network traffic analysis & threat detection

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
    # 2026-07 新增模块 — 广度拓展
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
    # Zotero 文献驱动模块 — 协议模糊测试编排 + RFC合规校验
    "protocol_fuzz_orchestrator": ".protocol_fuzz_orchestrator",
    "rfc_compliance_checker": ".rfc_compliance_checker",
}

def __getattr__(name):
    if name in _submodules:
        import importlib
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = list(_submodules.keys()) + ["__version__"]
