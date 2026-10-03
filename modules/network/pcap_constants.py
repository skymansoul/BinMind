"""PCAP常量、BPF过滤器和表达式解析。"""
import logging
from typing import Dict, Callable, Optional, Any

_log = logging.getLogger(__name__)

# PCAP魔数
PCAP_MAGIC = 0xa1b2c3d4
PCAP_MAGIC_NS = 0xa1b23c4d
PCAPNG_MAGIC = 0x0a0d0d0a
PCAP_SWAPPED_MAGIC = 0xd4c3b2a1
PCAP_SWAPPED_NS = 0x4d3cb2a1

# 大文件阈值（MB）
MMAP_THRESHOLD = 500 * 1024 * 1024  # 500MB

# BPF过滤器映射
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


# BPF表达式解析
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
