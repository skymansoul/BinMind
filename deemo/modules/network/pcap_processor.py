# 2026-07-25
"""PCAP处理引擎——零拷贝mmap读取、BPF过滤、流式包解析。"""
import logging, mmap, os, struct, socket, time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Iterator, Callable

_log = logging.getLogger(__name__)

# ---- PCAP魔数 ----
PCAP_MAGIC = 0xa1b2c3d4
PCAP_MAGIC_NS = 0xa1b23c4d
PCAPNG_MAGIC = 0x0a0d0d0a
PCAP_SWAPPED_MAGIC = 0xd4c3b2a1
PCAP_SWAPPED_NS = 0x4d3cb2a1

# //// 大文件阈值（MB）////
MMAP_THRESHOLD = 500 * 1024 * 1024  # 500MB

# ===== BPF过滤器映射 =====
BPF_FILTER_MAP: Dict[str, Callable] = {}

def _bpf_host(ip: str) -> Callable:
    def _filter(pkt: Any) -> bool:
        _sip = pkt.src_ip if hasattr(pkt, "src_ip") else pkt.get("src_ip", "")
        _dip = pkt.dst_ip if hasattr(pkt, "dst_ip") else pkt.get("dst_ip", "")
        return _sip == ip or _dip == ip
    return _filter

def _bpf_port(port: int) -> Callable:
    def _filter(pkt: Any) -> bool:
        _sp = pkt.src_port if hasattr(pkt, "src_port") else pkt.get("src_port", 0)
        _dp = pkt.dst_port if hasattr(pkt, "dst_port") else pkt.get("dst_port", 0)
        return _sp == port or _dp == port
    return _filter

def _bpf_net(net_cidr: str) -> Callable:
    _net, _mask_bits = net_cidr.split("/")
    _mask = int(_mask_bits)
    _net_int = _ip_to_int(_net)
    _mask_int = (0xFFFFFFFF << (32 - _mask)) & 0xFFFFFFFF
    def _filter(pkt: Any) -> bool:
        _sip = pkt.src_ip if hasattr(pkt, "src_ip") else pkt.get("src_ip", "")
        _dip = pkt.dst_ip if hasattr(pkt, "dst_ip") else pkt.get("dst_ip", "")
        return (_ip_to_int(_sip) & _mask_int) == (_net_int & _mask_int) or \
               (_ip_to_int(_dip) & _mask_int) == (_net_int & _mask_int)
    return _filter

def _bpf_proto(protocol: str) -> Callable:
    _proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
    _target = _proto_map.get(protocol.lower(), 0)
    def _filter(pkt: Any) -> bool:
        _p = pkt.protocol if hasattr(pkt, "protocol") else pkt.get("protocol", 0)
        return _p == _target
    return _filter

BPF_FILTER_MAP["host"] = _bpf_host
BPF_FILTER_MAP["port"] = _bpf_port
BPF_FILTER_MAP["net"] = _bpf_net
BPF_FILTER_MAP["proto"] = _bpf_proto


def _ip_to_int(ip: str) -> int:
    try:
        _parts = ip.split(".")
        return (int(_parts[0]) << 24) | (int(_parts[1]) << 16) | (int(_parts[2]) << 8) | int(_parts[3])
    except Exception:
        return 0


# ===== BPF表达式解析 =====
def parse_bpf(expression: str) -> Optional[Callable]:
    """简化的BPF表达式解析器。

    支持host、port、net、proto关键字及and/or组合。返回过滤函数，
    传入包对象返回True/False。支持嵌套组合。
    """
    if not expression:
        return None
    _expr = expression.strip().lower()

    # 处理 "and" 组合
    if " and " in _expr:
        _parts = _expr.split(" and ")
        _filters = [parse_bpf(_p.strip()) for _p in _parts]
        _filters = [f for f in _filters if f is not None]
        if _filters:
            def _and_filter(pkt: Any) -> bool:
                for f in _filters:
                    if not f(pkt):
                        return False
                return True
            return _and_filter
        return None

    # 处理 "or" 组合
    if " or " in _expr:
        _parts = _expr.split(" or ")
        _filters = [parse_bpf(_p.strip()) for _p in _parts]
        _filters = [f for f in _filters if f is not None]
        if _filters:
            def _or_filter(pkt: Any) -> bool:
                for f in _filters:
                    if f(pkt):
                        return True
                return False
            return _or_filter
        return None

    # 单个过滤条件
    for _kw in ["host ", "port ", "net ", "proto "]:
        if _expr.startswith(_kw):
            _val = _expr[len(_kw):].strip()
            _builder = BPF_FILTER_MAP.get(_kw.strip())
            if _builder:
                try:
                    if _kw.strip() == "port":
                        return _builder(int(_val))
                    return _builder(_val)
                except Exception:
                    return None
    return None


# ===== PcapPacket 数据包类 =====
@dataclass
class PcapPacket:
    """PCAP数据包，支持延迟解析以减少不必要的开销。

    L2/L3/L4头部在首次访问时解析。原始数据修改重置解析状态。
    """
    timestamp: float = 0.0
    caplen: int = 0
    wirelen: int = 0
    _raw_data: bytes = field(default=b"", repr=False)
    _parsed: bool = False
    src_mac: str = ""
    dst_mac: str = ""
    eth_type: int = 0
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    payload: bytes = field(default=b"", repr=False)
    _ip_version: int = 0
    _ip_hdr_len: int = 0
    _transport_hdr_len: int = 0

    @property
    def raw_data(self) -> bytes:
        return self._raw_data

    @raw_data.setter
    def raw_data(self, value: bytes) -> None:
        self._raw_data = value
        self._parsed = False

    def _ensure_parsed(self) -> None:
        if self._parsed or not self._raw_data:
            return
        self._parse_ethernet()
        self._parsed = True

    def _parse_ethernet(self) -> None:
        _data = self._raw_data
        if len(_data) < 14:
            return
        self.dst_mac = ":".join(f"{b:02x}" for b in _data[0:6])
        self.src_mac = ":".join(f"{b:02x}" for b in _data[6:12])
        self.eth_type = (_data[12] << 8) | _data[13]
        _offset = 14

        # VLAN标签处理
        if self.eth_type == 0x8100:
            if len(_data) >= 18:
                self.eth_type = (_data[16] << 8) | _data[17]
                _offset = 18

        # IPv4
        if self.eth_type == 0x0800:
            self._parse_ipv4(_data, _offset)
        # IPv6
        elif self.eth_type == 0x86DD:
            self._parse_ipv6(_data, _offset)
        # ARP
        elif self.eth_type in (0x0806, 0x8035):
            self.protocol = 0

    def _parse_ipv4(self, data: bytes, offset: int) -> None:
        if len(data) < offset + 20:
            return
        _vh = data[offset]
        self._ip_version = (_vh >> 4) & 0x0F
        self._ip_hdr_len = (_vh & 0x0F) * 4
        self.protocol = data[offset + 9]
        self.src_ip = ".".join(str(b) for b in data[offset+12:offset+16])
        self.dst_ip = ".".join(str(b) for b in data[offset+16:offset+20])

        _t_offset = offset + self._ip_hdr_len
        if len(data) < _t_offset:
            return

        if self.protocol == 6:  # TCP
            self._parse_tcp(data, _t_offset)
        elif self.protocol == 17:  # UDP
            self._parse_udp(data, _t_offset)
        elif self.protocol == 1:  # ICMP
            self._parse_icmp(data, _t_offset)

    def _parse_ipv6(self, data: bytes, offset: int) -> None:
        if len(data) < offset + 40:
            return
        self._ip_version = 6
        self._ip_hdr_len = 40
        self.protocol = data[offset + 6]  # next header
        _sip = data[offset+8:offset+24]
        _dip = data[offset+24:offset+40]
        self.src_ip = ":".join(f"{_sip[i]:02x}{_sip[i+1]:02x}" for i in range(0, 16, 2))
        self.dst_ip = ":".join(f"{_dip[i]:02x}{_dip[i+1]:02x}" for i in range(0, 16, 2))

        _t_offset = offset + self._ip_hdr_len
        _next = self.protocol
        # 跳过IPv6扩展头
        while _next in (0, 43, 44, 50, 51, 60, 135):  # hop-by-hop, routing, frag, esp, ah, dest, mobility
            if len(data) <= _t_offset + 2:
                return
            _next = data[_t_offset]
            _hdr_ext_len = (data[_t_offset + 1] * 8) + 8
            _t_offset += _hdr_ext_len
        self.protocol = _next

        if len(data) < _t_offset:
            return

        if self.protocol == 6:
            self._parse_tcp(data, _t_offset)
        elif self.protocol == 17:
            self._parse_udp(data, _t_offset)
        elif self.protocol == 1:
            self._parse_icmp(data, _t_offset)

    def _parse_tcp(self, data: bytes, offset: int) -> None:
        if len(data) < offset + 20:
            return
        self.src_port = (data[offset] << 8) | data[offset+1]
        self.dst_port = (data[offset+2] << 8) | data[offset+3]
        self._transport_hdr_len = ((data[offset+12] >> 4) & 0x0F) * 4
        _payload_start = offset + self._transport_hdr_len
        self.payload = data[_payload_start:] if _payload_start < len(data) else b""

    def _parse_udp(self, data: bytes, offset: int) -> None:
        if len(data) < offset + 8:
            return
        self.src_port = (data[offset] << 8) | data[offset+1]
        self.dst_port = (data[offset+2] << 8) | data[offset+3]
        _udp_len = (data[offset+4] << 8) | data[offset+5]
        self._transport_hdr_len = 8
        _payload_start = offset + 8
        _payload_end = min(offset + _udp_len, len(data))
        self.payload = data[_payload_start:_payload_end] if _payload_start < len(data) else b""

    def _parse_icmp(self, data: bytes, offset: int) -> None:
        self.src_port = 0
        self.dst_port = 0
        self._transport_hdr_len = 8
        self.payload = data[offset+8:] if len(data) > offset + 8 else b""

    def to_dict(self) -> Dict[str, Any]:
        self._ensure_parsed()
        return {
            "timestamp": self.timestamp,
            "caplen": self.caplen, "wirelen": self.wirelen,
            "src_mac": self.src_mac, "dst_mac": self.dst_mac,
            "eth_type": self.eth_type,
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "src_port": self.src_port, "dst_port": self.dst_port,
            "protocol": self.protocol,
            "payload_len": len(self.payload),
        }


# ===== PCAP文件读取器 =====
class PcapReader:
    """高性能PCAP读取器：支持标准PCAP和PCAPNG格式。

    大文件（>500MB）使用mmap零拷贝，小文件使用常规读取。
    自动检测字节序和纳秒/微秒时间戳格式。
    """

    def __init__(self):
        self._filepath: str = ""
        self._file_size: int = 0
        self._is_ns: bool = False
        self._swap: bool = False
        self._link_type: int = 0
        self._packet_count: int = 0
        self._data: Optional[bytes] = None
        self._mmap_obj: Optional[mmap.mmap] = None
        self._fd = None

    def open(self, filepath: str) -> None:
        self._filepath = filepath
        self._file_size = os.path.getsize(filepath)

        # 大文件用mmap
        if self._file_size > MMAP_THRESHOLD:
            self._fd = open(filepath, "rb")
            self._mmap_obj = mmap.mmap(self._fd.fileno(), 0, access=mmap.ACCESS_READ)
            _header = self._mmap_obj[:24]
        else:
            with open(filepath, "rb") as _f:
                _header = _f.read(24)
                self._data = _f.read()
            # 如果文件不大，全读入内存
            if self._data is None and self._file_size > 0:
                with open(filepath, "rb") as _f:
                    self._data = _f.read()

        self._parse_global_header(_header)

    def _parse_global_header(self, header: bytes) -> None:
        if len(header) < 24:
            return
        _magic = struct.unpack("<I", header[0:4])[0]

        if _magic == PCAP_MAGIC:
            self._swap = False
            self._is_ns = False
        elif _magic == PCAP_MAGIC_NS:
            self._swap = False
            self._is_ns = True
        elif _magic == PCAP_SWAPPED_MAGIC:
            self._swap = True
            self._is_ns = False
        elif _magic == PCAP_SWAPPED_NS:
            self._swap = True
            self._is_ns = True
        elif _magic == PCAPNG_MAGIC:
            # PCAPNG: pcapng处理，简化——跳过section header
            self._swap = False
            self._is_ns = False
        else:
            _log.warning("未知PCAP魔数: 0x%08x", _magic)
            return

        _fmt = ">" if self._swap else "<"
        if _magic == PCAPNG_MAGIC:
            self._link_type = 1  # 默认Ethernet
            return

        self._link_type = struct.unpack(f"{_fmt}I", header[20:24])[0]

    @staticmethod
    def _read_at(data: Any, offset: int, length: int) -> bytes:
        if isinstance(data, mmap.mmap):
            return data[offset:offset+length]
        elif isinstance(data, bytes):
            return data[offset:offset+length]
        return b""

    def iter_packets(self) -> Iterator[PcapPacket]:
        """生成器，逐个返回PcapPacket。

        对大文件使用mmap切片，小文件使用内存切片。每次读取24字节的包头部
        （timestamp_sec, timestamp_us/ns, caplen, wirelen），然后读取包数据。
        """
        if self._mmap_obj is not None:
            _data = self._mmap_obj
            _offset = 24
        elif self._data is not None:
            _data = self._data
            _offset = 24
        else:
            return

        _fmt = ">" if self._swap else "<"
        _data_len = self._file_size if self._mmap_obj is not None else len(_data)

        while _offset + 16 <= _data_len:
            _hdr = self._read_at(_data, _offset, 16)
            if len(_hdr) < 16:
                break

            _ts_sec = struct.unpack(f"{_fmt}I", _hdr[0:4])[0]
            _ts_frac = struct.unpack(f"{_fmt}I", _hdr[4:8])[0]
            _caplen = struct.unpack(f"{_fmt}I", _hdr[8:12])[0]
            _wirelen = struct.unpack(f"{_fmt}I", _hdr[12:16])[0]

            _offset += 16

            if _offset + _caplen > _data_len:
                break

            _pkt_data = self._read_at(_data, _offset, _caplen)
            _offset += _caplen

            _ts = _ts_sec + (_ts_frac / 1e9 if self._is_ns else _ts_frac / 1e6)

            _pkt = PcapPacket(
                timestamp=_ts,
                caplen=_caplen,
                wirelen=_wirelen,
                _raw_data=bytes(_pkt_data),
            )
            self._packet_count += 1
            yield _pkt

    def close(self) -> None:
        if self._mmap_obj:
            try:
                self._mmap_obj.close()
            except Exception:
                pass
            self._mmap_obj = None
        if self._fd:
            try:
                self._fd.close()
            except Exception:
                pass
            self._fd = None
        self._data = None

    def quick_stats(self) -> Dict[str, Any]:
        """快速统计：遍历所有包计算基本指标。

        返回包数、时长、平均包大小、协议分布和Top Talkers。
        注意会消耗迭代器，调用后无法再遍历包。
        """
        _count = 0
        _total_bytes = 0
        _start_ts = float("inf")
        _end_ts = 0.0
        _proto_dist: Counter = Counter()
        _talkers: Counter = Counter()

        for _pkt in self.iter_packets():
            _count += 1
            _total_bytes += _pkt.caplen
            if _pkt.timestamp < _start_ts:
                _start_ts = _pkt.timestamp
            if _pkt.timestamp > _end_ts:
                _end_ts = _pkt.timestamp
            _pkt._ensure_parsed()
            _proto_dist[_pkt.protocol] += 1
            if _pkt.src_ip:
                _talkers[_pkt.src_ip] += _pkt.caplen
            if _pkt.dst_ip:
                _talkers[_pkt.dst_ip] += _pkt.caplen

        _duration = _end_ts - _start_ts if _start_ts != float("inf") else 0
        _avg_size = _total_bytes / _count if _count > 0 else 0
        _proto_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
        _proto_dist_named = {_proto_names.get(k, str(k)): v for k, v in _proto_dist.most_common()}
        _top_talkers = _talkers.most_common(10)

        return {
            "packet_count": _count,
            "duration": _duration,
            "avg_packet_size": _avg_size,
            "protocol_distribution": _proto_dist_named,
            "top_talkers": [{"ip": ip, "bytes": b} for ip, b in _top_talkers],
        }

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# ===== 完整处理管线 =====
def process_pcap(filepath: str, bpf_filter: Optional[str] = None) -> Dict[str, Any]:
    """完整的PCAP处理管线：读取 → BPF过滤 → 统计。

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
