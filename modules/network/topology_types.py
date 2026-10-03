"""网络拓扑映射 —— 类型定义与协议常量。

LLDP/CDP 帧解析、被动OS指纹识别、网络层次推断所需的
数据结构与常量集中于此，避免循环依赖。
"""
import struct
from dataclasses import dataclass, field
from typing import List, Tuple

# LLDP EtherType 常量
_LLDP_ETHERTYPE = 0x88CC
_CDP_ETHERTYPE = 0x2000  # Cisco Discovery Protocol (LLC/SNAP封装)

# LLDP TLV 类型码 (IEEE 802.1AB)
_LLDP_TLV_CHASSIS_ID = 1; _LLDP_TLV_PORT_ID = 2
_LLDP_TLV_TTL = 3; _LLDP_TLV_PORT_DESC = 4
_LLDP_TLV_SYS_NAME = 5; _LLDP_TLV_SYS_DESC = 6
_LLDP_TLV_SYS_CAP = 7; _LLDP_TLV_MGMT_ADDR = 8
_LLDP_TLV_END = 0
_LLDP_TLV_ORG_SPECIFIC = 127

_LLDP_TLV_NAMES = {
    0: "END", 1: "CHASSIS_ID", 2: "PORT_ID", 3: "TTL",
    4: "PORT_DESC", 5: "SYS_NAME", 6: "SYS_DESC",
    7: "SYS_CAP", 8: "MGMT_ADDR", 127: "ORG_SPECIFIC",
}

# 系统能力位掩码 (IEEE 802.1AB §8.5.1)
_CAP_OTHER = 0x01; _CAP_REPEATER = 0x02; _CAP_BRIDGE = 0x04
_CAP_WLAN_AP = 0x08; _CAP_ROUTER = 0x10; _CAP_TELEPHONE = 0x20
_CAP_DOCSIS = 0x40; _CAP_STATION = 0x80
_CAP_NAMES = {
    0x01: "Other", 0x02: "Repeater", 0x04: "Bridge",
    0x08: "WLAN-AP", 0x10: "Router", 0x20: "Telephone",
    0x40: "DOCSIS", 0x80: "Station",
}

# TCP/IP 栈指纹特征库 (p0f风格签名简化版)
# 格式: (初始TTL, 窗口大小范围, TCP选项顺序, 推测OS)
_OS_FINGERPRINTS: List[Tuple[int, Tuple[int, int], str, str]] = [
    (64, (5800, 65535), "mss,sok,ts,nop,ws", "Linux 4.x/5.x"),
    (64, (28000, 30000), "mss,sok,ts,nop,ws", "Linux 2.6/3.x"),
    (128, (63000, 65535), "mss,nop,ws,nop,nop,sok", "Windows 10/11"),
    (128, (16000, 18000), "mss,nop,nop,sok", "Windows 7/2008"),
    (64, (65535, 65535), "mss,nop,ws,nop,nop,ts,nop,sok,eol", "macOS 13+"),
    (64, (65535, 65535), "mss,sok,ts,nop,ws", "Android 12+"),
    (255, (4128, 4160), "mss", "Cisco IOS"),
    (64, (5720, 5840), "mss,nop,ws,nop,nop,ts,sok,eol", "iOS 16+"),
    (64, (5840, 65535), "mss,sok,ts", "FreeBSD 13+"),
    (128, (8192, 8192), "mss,nop,nop,sok", "Windows XP/2003"),
]


@dataclass
class LldpNeighbor:
    """LLDP 邻居信息——单条LLDP消息的核心TLV字段"""
    local_port: str = ""
    chassis_id: str = ""
    port_id: str = ""
    sys_name: str = ""
    sys_desc: str = ""
    ttl: int = 120
    capabilities: int = 0
    mgmt_ip: str = ""
    raw_tlvs: List[Tuple[int, bytes]] = field(default_factory=list)


@dataclass
class OsFingerprint:
    ip: str = ""
    guessed_os: str = ""
    initial_ttl: int = 0
    window_size: int = 0
    tcp_options: str = ""
    confidence: float = 0.0
    first_seen: float = 0.0


@dataclass
class NetworkDevice:
    """拓扑中的网络设备节点结构体"""
    identifier: str = ""
    device_type: str = ""    # switch / router / ap / server / unknown
    hostname: str = ""
    mgmt_ip: str = ""
    neighbors: List[str] = field(default_factory=list)
    os_guess: str = ""
    ports: List[str] = field(default_factory=list)
