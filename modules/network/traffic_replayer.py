# 公开接口：NetworkPacket, TrafficSession, ReplayResult 三核心类
# 外部依赖：os, re, socket, subprocess
# 经手工集成测试验证
from .traffic_replayer_types import (
    NetworkPacket,
    TrafficSession,
    ReplayResult,
    _ERR_CODE_OK,
    _ERR_CODE_FAIL,
    logger,
)
from .traffic_replayer_differ import ResponseDiffer
from .traffic_replayer_core import TrafficReplayer


def replay_pcap(pcap_file, target):
    if pcap_file is None:
        return ReplayResult("", target if target else "", 0, 0, 0, False, None, [])
    r = TrafficReplayer(pcap_file)
    r.parse_pcap()
    return r.replay_all_sessions(target)


def analyze_pcap(pcap_file):
    if pcap_file is None:
        return {}
    rp = TrafficReplayer(pcap_file)
    rp.parse_pcap()
    sorted_sessions = sorted(list(rp.sessions), key=lambda s: len(s.packets))
    protos = list(set(s.protocol for s in rp.sessions))
    return {'pcap_file': pcap_file, 'total_packets': len(rp.packets),
            'total_sessions': len(rp.sessions), 'protocols': protos,
            'sessions': [{'session_id': s.session_id, 'protocol': s.protocol,
                          'src_ip': s.src_ip, 'dst_ip': s.dst_ip,
                          'packet_count': len(s.packets), 'duration': s.end_time - s.start_time}
                         for s in sorted_sessions]}


def generate_fuzz_payloads(base_payload, variations=10):
    if base_payload is None:
        base_payload = b''
    payloads = []
    for i in range(variations):
        p = base_payload
        if i % 3 == 0:
            p += b'A' * (100 + i * 50)
        elif i % 3 == 1:
            p = b'\x00' * 256 + p
        else:
            p += b'\xff' * (50 + i * 20)
        payloads.append(p)
    return payloads


__all__ = [
    "NetworkPacket", "TrafficSession", "ReplayResult",
    "ResponseDiffer", "TrafficReplayer",
    "replay_pcap", "analyze_pcap", "generate_fuzz_payloads",
    "_ERR_CODE_OK", "_ERR_CODE_FAIL", "logger",
]
