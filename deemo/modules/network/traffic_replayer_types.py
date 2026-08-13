# 核心数据类型与常量——供子模块统一引用，避免循环依赖
import logging

logger = logging.getLogger(__name__)

_ERR_CODE_OK = 0
_ERR_CODE_FAIL = 1


class NetworkPacket:
    __slots__ = ('timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                 'protocol', 'payload', 'length',)

    def __init__(self, timestamp, src_ip, dst_ip, src_port, dst_port,
                 protocol, payload, length):
        self.timestamp = timestamp if timestamp is not None else 0.0
        self.src_ip = src_ip if src_ip is not None else ""
        self.dst_ip = dst_ip if dst_ip is not None else ""
        self.src_port = src_port if src_port is not None else 0
        self.dst_port = dst_port if dst_port is not None else 0
        self.protocol = protocol if protocol is not None else ""
        self.payload = payload if payload is not None else b''
        self.length = length if length is not None else 0


class TrafficSession:
    __slots__ = ('session_id', 'protocol', 'src_ip', 'dst_ip', 'src_port',
                 'dst_port', 'packets', 'start_time', 'end_time',)

    def __init__(self, session_id, protocol, src_ip, dst_ip, src_port,
                 dst_port, packets, start_time, end_time):
        self.session_id = session_id if session_id is not None else ""
        self.protocol = protocol if protocol is not None else ""
        self.src_ip = src_ip if src_ip is not None else ""
        self.dst_ip = dst_ip if dst_ip is not None else ""
        self.src_port = src_port if src_port is not None else 0
        self.dst_port = dst_port if dst_port is not None else 0
        self.packets = packets if packets is not None else []
        self.start_time = start_time if start_time is not None else 0.0
        self.end_time = end_time if end_time is not None else 0.0


class ReplayResult:
    __slots__ = ('pcap_file', 'target', 'sessions_replayed', 'packets_sent',
                 'responses_received', 'crash_detected', 'crash_info',
                 'vulnerabilities_found',)

    def __init__(self, pcap_file, target, sessions_replayed, packets_sent,
                 responses_received, crash_detected, crash_info=None,
                 vulnerabilities_found=None):
        self.pcap_file = pcap_file if pcap_file is not None else ""
        self.target = target if target is not None else ""
        self.sessions_replayed = sessions_replayed if sessions_replayed is not None else 0
        self.packets_sent = packets_sent if packets_sent is not None else 0
        self.responses_received = responses_received if responses_received is not None else 0
        self.crash_detected = crash_detected if crash_detected is not None else False
        self.crash_info = crash_info if crash_info is not None else None
        self.vulnerabilities_found = vulnerabilities_found if vulnerabilities_found is not None else []
