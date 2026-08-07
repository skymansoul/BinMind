"""网络取证——共享数据结构与常量。"""
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any

# 流超时常量
TCP_IDLE_TIMEOUT = 120
UDP_IDLE_TIMEOUT = 60
FLOW_HARD_TIMEOUT = 3600

# 信标检测阈值
BEACON_JITTER_RATIO = 0.12
BEACON_MIN_INTERVALS = 5

# 外泄检测阈值
EXFIL_RATIO_WARN = 20
EXFIL_RATIO_DEFINITE = 100


@dataclass
class FlowRecord:
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 6  # 默认TCP
    bytes_sum: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    packets: int = 0
    start_ts: float = 0.0
    last_ts: float = 0.0
    community_id: str = ""
    # 时间间隔序列（信标检测用）
    _intervals: List[float] = field(default_factory=list, repr=False)
    _timestamps: List[float] = field(default_factory=list, repr=False)
    _last_direction: Optional[str] = field(default=None, repr=False)


# 常见协议端口映射
KNOWN_PORTS: Dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP-S", 68: "DHCP-C",
    80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "SYSLOG", 587: "SMTP-TLS",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "ORACLE", 3306: "MYSQL",
    3389: "RDP", 5432: "POSTGRES", 5900: "VNC",
    6379: "REDIS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    9200: "ELASTIC", 11211: "MEMCACHED", 27017: "MONGODB",
}
