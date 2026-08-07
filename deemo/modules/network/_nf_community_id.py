"""网络取证——Community ID生成。"""
import hashlib
import base64

from ._nf_types import FlowRecord


def community_id(protocol: int, src_ip: str, dst_ip: str,
                 src_port: int = 0, dst_port: int = 0) -> str:
    """按Corelight/Zeek规范生成Community ID。

    ICMP(协议号1)用type+code替代端口。IP地址按字节序排序以确保双向
    流量产生相同ID。SHA1(seed+tuple)截断base64输出。
    """
    _ips = sorted([_ip_to_bytes(src_ip), _ip_to_bytes(dst_ip)])
    _ip1, _ip2 = _ips[0], _ips[1]

    _seed = 0
    if protocol == 1:  # ICMP
        _tuple_str = f"{_seed}|{_ip1.hex()}|{_ip2.hex()}|{protocol}|{src_port}|{dst_port}"
    else:
        _sorted_ports = sorted([src_port, dst_port])
        _tuple_str = f"{_seed}|{_ip1.hex()}|{_ip2.hex()}|{protocol}|{_sorted_ports[0]}|{_sorted_ports[1]}"

    _hash = hashlib.sha1(_tuple_str.encode()).digest()
    return base64.b64encode(_hash[:20]).decode("ascii")


def _ip_to_bytes(ip: str) -> bytes:
    parts = ip.split(".")
    if len(parts) == 4:
        return bytes(int(p) for p in parts)
    # IPv6简化处理
    expanded = _expand_ipv6(ip)
    return bytes.fromhex(expanded.replace(":", ""))


def _expand_ipv6(ip: str) -> str:
    if "::" in ip:
        parts = ip.split("::")
        left = parts[0].split(":") if parts[0] else []
        right = parts[1].split(":") if len(parts) > 1 and parts[1] else []
        missing = 8 - len(left) - len(right)
        return ":".join(left + ["0"] * missing + right)
    return ip
