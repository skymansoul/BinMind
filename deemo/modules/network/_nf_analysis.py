"""网络取证——PCAP综合分析入口。"""
import logging
from typing import List, Dict, Any
from time import time as _time_now

from ._nf_types import FlowRecord
from ._nf_flow_tracker import FlowTracker
from ._nf_community_id import community_id
from ._nf_beacon import check_beacon_timing
from ._nf_exfil import traffic_asymmetry, check_port_protocol_mismatch

_log = logging.getLogger(__name__)


def analyze_pcap(packets: List[Any]) -> Dict[str, Any]:
    """PCAP流分析。

    对每个包提取五元组、时间戳、载荷长度，送入FlowTracker进行流追踪。
    完成后对所有活跃流执行信标检测和外泄检测，汇总结果。
    """
    _tracker = FlowTracker()
    _ts = _time_now()

    for _i, _pkt in enumerate(packets):
        # 支持字典和对象两种格式
        if isinstance(_pkt, dict):
            _sip = _pkt.get("src_ip", "0.0.0.0")
            _dip = _pkt.get("dst_ip", "0.0.0.0")
            _sp = _pkt.get("src_port", 0)
            _dp = _pkt.get("dst_port", 0)
            _proto = _pkt.get("protocol", 6)
            _plen = _pkt.get("payload_len", len(_pkt.get("payload", b"")))
            _pts = _pkt.get("timestamp", _ts + _i * 0.001)
            _dir = "out"
        else:
            _sip = getattr(_pkt, "src_ip", "0.0.0.0")
            _dip = getattr(_pkt, "dst_ip", "0.0.0.0")
            _sp = getattr(_pkt, "src_port", 0)
            _dp = getattr(_pkt, "dst_port", 0)
            _proto = getattr(_pkt, "protocol", 6)
            _plen = getattr(_pkt, "payload_len", len(getattr(_pkt, "payload", b"")))
            _pts = getattr(_pkt, "timestamp", _ts + _i * 0.001)
            _dir = "out"

        _tracker.update_flow(_sip, _dip, _sp, _dp, _proto, _plen, _pts, _dir)

    # 回收超时流
    _tracker.expire_stale()
    _flows = _tracker.get_active_flows()

    # 为每个流计算Community ID
    for _f in _flows:
        _f.community_id = community_id(_f.protocol, _f.src_ip, _f.dst_ip,
                                        _f.src_port, _f.dst_port)

    # 检测分析
    _beacon_alerts = []
    _exfil_alerts = []
    _mismatch_alerts = []

    for _f in _flows:
        _beacon = check_beacon_timing(_f)
        if _beacon["is_beacon"]:
            _beacon_alerts.append({
                "flow": f"{_f.src_ip}:{_f.src_port}->{_f.dst_ip}:{_f.dst_port}",
                "score": _beacon["score"],
                "community_id": _f.community_id,
            })

        _exfil = traffic_asymmetry(_f)
        if _exfil["severity"] != "normal":
            _exfil_alerts.append({
                "flow": f"{_f.src_ip}:{_f.src_port}->{_f.dst_ip}:{_f.dst_port}",
                "ratio": _exfil["ratio"],
                "severity": _exfil["severity"],
                "community_id": _f.community_id,
            })

        _mm = check_port_protocol_mismatch(_f)
        for _alert in _mm:
            _mismatch_alerts.append({
                "flow": f"{_f.src_ip}:{_f.src_port}->{_f.dst_ip}:{_f.dst_port}",
                "alert": _alert,
                "community_id": _f.community_id,
            })

# 法庭因果图分析
    _causal_report = None
    if _beacon_alerts or _exfil_alerts or _mismatch_alerts:
        try:
            from .forensic_event_builder import analyze_forensic_causality
        except ImportError:
            from .src.forensic_event_builder import analyze_forensic_causality
        _causal_report = analyze_forensic_causality(
            _beacon_alerts, _exfil_alerts, _mismatch_alerts)

    return {
        "total_packets": len(packets),
        "total_flows": len(_flows),
        "expired_flows": _tracker._expired_count,
        "beacon_alerts": _beacon_alerts,
        "exfil_alerts": _exfil_alerts,
        "mismatch_alerts": _mismatch_alerts,
        "flows": _flows,
        # 法庭因果分析结果
        "forensic_causality": {
            "total_events": _causal_report.total_events if _causal_report else 0,
            "total_edges": _causal_report.total_edges if _causal_report else 0,
            "root_causes": (_causal_report.root_cause_ranking[:5]
                           if _causal_report else []),
            "evidence_chains": [
                {"events": ch.events, "strength": ch.total_strength,
                 "root_cause": ch.root_cause_event}
                for ch in (_causal_report.evidence_chains[:5]
                          if _causal_report else [])
            ],
        } if _causal_report else {},
    }
