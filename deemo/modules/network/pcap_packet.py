"""PCAP数据包类，支持延迟解析。"""
from dataclasses import dataclass, field
from typing import Dict, Any


@dataclass
class PcapPacket:
    # PCAP数据包，支持延迟解析以减少不必要开销。
    # L2/L3/L4头部在首次访问时解析。原始数据修改重置解析状态。
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
