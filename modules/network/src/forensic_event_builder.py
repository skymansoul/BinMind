# 法庭事件构造器 —— 从flow分析告警构造统一ForensicEvent。

from __future__ import annotations

from typing import Dict, List, Set

from .forensic_causal_graph import ForensicEvent


def build_forensic_events_from_alerts(
    beacon_alerts: List[Dict],
    exfil_alerts: List[Dict],
    mismatch_alerts: List[Dict],
) -> List[ForensicEvent]:
    """从network_forensics.analyze_pcap的输出告警构造事件列表。

    将三种告警统一映射为ForensicEvent, 提取关联资源和时间戳。
    """
    events: List[ForensicEvent] = []
    idx = 0

    for alert in beacon_alerts:
        flow_str = alert.get("flow", f"unknown_{idx}")
        resources = _parse_flow_resources(flow_str)
        events.append(ForensicEvent(
            event_id=f"beacon_{idx}",
            event_type="beacon",
            timestamp=alert.get("timestamp", float(idx)),
            resources=resources,
            severity=alert.get("score", 0.5),
            description=f"C2 beacon: {flow_str}",
            metadata={"community_id": alert.get("community_id", "")},
        ))
        idx += 1

    for alert in exfil_alerts:
        flow_str = alert.get("flow", f"unknown_{idx}")
        resources = _parse_flow_resources(flow_str)
        sev = 0.9 if alert.get("severity") == "definite" else 0.6
        events.append(ForensicEvent(
            event_id=f"exfil_{idx}",
            event_type="exfiltration",
            timestamp=alert.get("timestamp", float(idx)),
            resources=resources,
            severity=sev,
            description=f"Data exfil: {flow_str}",
            metadata={"ratio": alert.get("ratio", 0)},
        ))
        idx += 1

    for alert in mismatch_alerts:
        flow_str = alert.get("flow", f"unknown_{idx}")
        resources = _parse_flow_resources(flow_str)
        events.append(ForensicEvent(
            event_id=f"mismatch_{idx}",
            event_type="port_mismatch",
            timestamp=alert.get("timestamp", float(idx)),
            resources=resources,
            severity=0.4,
            description=f"Protocol mismatch: {alert.get('alert', '')}",
        ))
        idx += 1

    return events


def _parse_flow_resources(flow_str: str) -> Set[str]:
    """从 'src_ip:src_port->dst_ip:dst_port' 提取资源集合"""
    resources: Set[str] = set()
    parts = flow_str.replace("->", " ").replace(":", " ").split()
    for part in parts:
        resources.add(part.strip())
    return resources


def analyze_forensic_causality(beacon_alerts: List[Dict],
                                exfil_alerts: List[Dict],
                                mismatch_alerts: List[Dict]):
    """便捷入口: 告警列表→法庭事件→因果图→证据链。"""
    from .forensic_causal_graph import ForensicCausalGraph
    events = build_forensic_events_from_alerts(
        beacon_alerts, exfil_alerts, mismatch_alerts)
    return ForensicCausalGraph().build(events)


__all__ = [
    "build_forensic_events_from_alerts", "analyze_forensic_causality",
]
