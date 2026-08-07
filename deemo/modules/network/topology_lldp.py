"""LLDP 帧解析器——从以太网帧提取TLV字段。

LLDP (IEEE 802.1AB) 是厂商中立的二层发现协议。TLV编码：7bit类型+9bit长度+值。
"""
import struct
from typing import Optional

from .topology_types import (
    LldpNeighbor,
    _LLDP_ETHERTYPE,
    _LLDP_TLV_CHASSIS_ID, _LLDP_TLV_PORT_ID, _LLDP_TLV_TTL,
    _LLDP_TLV_SYS_NAME, _LLDP_TLV_SYS_DESC, _LLDP_TLV_SYS_CAP,
    _LLDP_TLV_MGMT_ADDR, _LLDP_TLV_END,
)


class LldpParser:

    @staticmethod
    def parse(raw_frame: bytes) -> Optional[LldpNeighbor]:
        """解析以太网帧中的LLDP负载部分（跳过14字节以太头）"""
        if len(raw_frame) < 14 + 2:  # 以太头 + 最小TLV
            return None

        eth_type = struct.unpack(">H", raw_frame[12:14])[0]
        start = 14
        if eth_type != _LLDP_ETHERTYPE:
            if eth_type <= 1500:  # 802.3 长度字段 → 非LLDP
                if len(raw_frame) < 22:
                    return None
                return None
            return None

        data = raw_frame[start:]
        return LldpParser._parse_tlvs(data)

    @staticmethod
    def _parse_tlvs(data: bytes) -> LldpNeighbor:
        neighbor = LldpNeighbor()
        pos = 0
        while pos + 2 <= len(data):
            tlv_type = data[pos] >> 1
            tlv_len = ((data[pos] & 0x01) << 8) | data[pos + 1]
            pos += 2
            if tlv_len == 0 or pos + tlv_len > len(data):
                break

            tlv_value = data[pos:pos + tlv_len]
            neighbor.raw_tlvs.append((tlv_type, tlv_value))

            if tlv_type == _LLDP_TLV_CHASSIS_ID and len(tlv_value) > 1:
                subtype = tlv_value[0]
                neighbor.chassis_id = LldpParser._decode_subtype(subtype, tlv_value[1:])
            elif tlv_type == _LLDP_TLV_PORT_ID and len(tlv_value) > 1:
                subtype = tlv_value[0]
                neighbor.port_id = LldpParser._decode_subtype(subtype, tlv_value[1:])
            elif tlv_type == _LLDP_TLV_TTL and len(tlv_value) >= 2:
                neighbor.ttl = struct.unpack(">H", tlv_value[:2])[0]
            elif tlv_type == _LLDP_TLV_SYS_NAME:
                neighbor.sys_name = tlv_value.decode("ascii", errors="replace").rstrip("\x00")
            elif tlv_type == _LLDP_TLV_SYS_DESC:
                neighbor.sys_desc = tlv_value.decode("ascii", errors="replace").rstrip("\x00")[:200]
            elif tlv_type == _LLDP_TLV_SYS_CAP and len(tlv_value) >= 4:
                neighbor.capabilities = struct.unpack(">H", tlv_value[:2])[0]
            elif tlv_type == _LLDP_TLV_MGMT_ADDR and len(tlv_value) >= 9:
                addr_len = tlv_value[0] - 1  # 减去subtype字节
                if addr_len == 4:  # IPv4
                    neighbor.mgmt_ip = ".".join(str(b) for b in tlv_value[2:6])
                elif addr_len == 16:  # IPv6
                    neighbor.mgmt_ip = ":".join(
                        f"{tlv_value[i]:02x}{tlv_value[i+1]:02x}"
                        for i in range(2, 18, 2)
                    )
            elif tlv_type == _LLDP_TLV_END:
                break

            pos += tlv_len
        return neighbor

    @staticmethod
    def _decode_subtype(subtype: int, data: bytes) -> str:
        """按IEEE 802.1AB子类型字段解码标识符值"""
        if subtype == 4:  # MAC address
            return ":".join(f"{b:02x}" for b in data[:6])
        elif subtype == 5:  # Network address (IPv4)
            if len(data) >= 4:
                return ".".join(str(b) for b in data[:4])
        elif subtype == 7:  # Locally assigned
            return data.decode("ascii", errors="replace").rstrip("\x00")[:64]
        else:
            return data.hex()[:32]
