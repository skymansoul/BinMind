"""网络取证——流追踪、信标检测、数据外泄分析。

拆分后各子模块通过相对导入组合，对外接口不变。
"""
from ._nf_types import (
    TCP_IDLE_TIMEOUT,
    UDP_IDLE_TIMEOUT,
    FLOW_HARD_TIMEOUT,
    BEACON_JITTER_RATIO,
    BEACON_MIN_INTERVALS,
    EXFIL_RATIO_WARN,
    EXFIL_RATIO_DEFINITE,
    FlowRecord,
    KNOWN_PORTS,
)
from ._nf_flow_tracker import FlowTracker
from ._nf_community_id import community_id
from ._nf_beacon import beacon_score, check_beacon_timing
from ._nf_exfil import traffic_asymmetry, check_port_protocol_mismatch
from ._nf_analysis import analyze_pcap

__all__ = [
    "TCP_IDLE_TIMEOUT", "UDP_IDLE_TIMEOUT", "FLOW_HARD_TIMEOUT",
    "BEACON_JITTER_RATIO", "BEACON_MIN_INTERVALS",
    "EXFIL_RATIO_WARN", "EXFIL_RATIO_DEFINITE",
    "FlowRecord", "KNOWN_PORTS",
    "FlowTracker",
    "community_id",
    "beacon_score", "check_beacon_timing",
    "traffic_asymmetry", "check_port_protocol_mismatch",
    "analyze_pcap",
]
