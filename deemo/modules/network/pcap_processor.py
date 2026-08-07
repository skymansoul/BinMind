"""PCAP处理引擎——零拷贝mmap读取、BPF过滤、流式包解析。

拆分后的主入口：从子模块重新导出全部公共接口，并保留完整处理管线。
"""
from collections import Counter
from typing import List, Dict, Optional, Any

from .pcap_constants import (
    PCAP_MAGIC, PCAP_MAGIC_NS, PCAPNG_MAGIC,
    PCAP_SWAPPED_MAGIC, PCAP_SWAPPED_NS, MMAP_THRESHOLD,
    BPF_FILTER_MAP, parse_bpf,
)
from .pcap_packet import PcapPacket
from .pcap_reader import PcapReader

__all__ = [
    "PCAP_MAGIC", "PCAP_MAGIC_NS", "PCAPNG_MAGIC",
    "PCAP_SWAPPED_MAGIC", "PCAP_SWAPPED_NS", "MMAP_THRESHOLD",
    "BPF_FILTER_MAP", "parse_bpf",
    "PcapPacket", "PcapReader",
    "process_pcap",
]


# 完整处理管线
def process_pcap(filepath: str, bpf_filter: Optional[str] = None) -> Dict[str, Any]:
    """PCAP处理管线：读取 → BPF过滤 → 统计。

    BPF表达式支持host/port/net/proto及and/or组合。
    返回统计信息和过滤后的包列表。
    """
    _filter_fn = parse_bpf(bpf_filter) if bpf_filter else None
    _reader = PcapReader()
    _reader.open(filepath)

    _packets: List[PcapPacket] = []
    _filtered_count = 0
    _proto_dist: Counter = Counter()

    try:
        for _pkt in _reader.iter_packets():
            _pkt._ensure_parsed()
            if _filter_fn is None or _filter_fn(_pkt):
                _packets.append(_pkt)
                _proto_dist[_pkt.protocol] += 1
            else:
                _filtered_count += 1
    finally:
        _reader.close()

    _proto_names = {1: "ICMP", 6: "TCP", 17: "UDP"}

    return {
        "file": filepath,
        "total_packets": len(_packets) + _filtered_count,
        "matched_packets": len(_packets),
        "filtered_out": _filtered_count,
        "bpf_filter": bpf_filter,
        "protocol_distribution": {_proto_names.get(k, str(k)): v for k, v in _proto_dist.most_common()},
        "packets": _packets,
    }
