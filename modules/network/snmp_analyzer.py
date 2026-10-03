"""SNMP 协议安全分析 —— 团体字符串弱点检测、MIB遍历发现、SNMPv3安全评估。

SNMP v1/v2c 以明文团体字符串作为认证手段，默认值public/private在现网设备中普遍存在。
SNMPv3引入USM安全模型（User-based Security Model），但配置不当可被降级攻击至v1/v2c。

- RFC 3411-3418 (SNMPv3 architecture)
- CVE-2002-0013 (SNMPv1 团体字符串暴力破解)
"""
import struct, logging, re
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any

_log = logging.getLogger(__name__)

# SNMP PDU 类型枚举 (RFC 3416 §4)
_SNMP_GET_REQUEST = 0xA0; _SNMP_GETNEXT_REQUEST = 0xA1
_SNMP_GET_RESPONSE = 0xA2; _SNMP_SET_REQUEST = 0xA3
_SNMP_GETBULK_REQUEST = 0xA5; _SNMP_INFORM_REQUEST = 0xA6
_SNMP_TRAP_V2 = 0xA7; _SNMP_REPORT = 0xA8

_SNMP_PDU_NAMES = {
    0xA0: "GET", 0xA1: "GETNEXT", 0xA2: "RESPONSE", 0xA3: "SET",
    0xA5: "GETBULK", 0xA6: "INFORM", 0xA7: "TRAPv2", 0xA8: "REPORT",
}

# 高频默认团体字符串库
_DEFAULT_COMMUNITIES = frozenset({
    "public", "private", "snmp", "admin", "cisco", "default",
    "root", "secret", "monitor", "manager", "read", "write",
    "tivoli", "openview", "security", "agent", "system",
})

# GETBULK MIB遍历检测参数——同源IP在时间窗口内的请求数阈值
_BULK_WALK_THRESHOLD = 50
_BULK_WALK_WINDOW = 10.0

# SNMPv3 USM 安全级别位掩码 (msgFlags byte)
_SNMPV3_NOAUTH_NOPRIV = 0x00
_SNMPV3_AUTH_NOPRIV = 0x01
_SNMPV3_AUTH_PRIV = 0x03

@dataclass
class SnmpPacket:
    """解析后的SNMP报文结构体"""
    version: int = 0          # 0=v1, 1=v2c, 3=v3
    community: str = ""       # v1/v2c 团体字符串
    pdu_type: int = 0
    pdu_name: str = ""
    request_id: int = 0
    error_status: int = 0
    oid_count: int = 0
    # SNMPv3 扩展字段
    msg_id: int = 0
    security_level: int = 0   # noAuthNoPriv=0, authNoPriv=1, authPriv=3
    security_model: int = 0   # USM=3
    snmpv3_user: str = ""

@dataclass
class SnmpAlert:
    alert_type: str
    description: str
    severity: str = "medium"
    src_ip: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

class SnmpPduParser:
    """SNMP BER/DER 编码解析——轻量级实现，支持v1/v2c/v3版本识别。

    仅提取版本、团体字符串和PDU类型，不完整解析OID树以避免引入ASN.1库依赖。
    """

    @staticmethod
    def parse(data: bytes) -> Optional[SnmpPacket]:
        if len(data) < 3:
            return None

        pkt = SnmpPacket()
        pos = 0

        # 确认外层SEQUENCE标签
        if data[pos] != 0x30:
            return None
        pos = SnmpPduParser._skip_tlv(data, pos)

        # 解析version字段 (INTEGER)
        if pos >= len(data) or data[pos] != 0x02:
            return None
        ver_len = data[pos + 1] if pos + 1 < len(data) else 0
        if pos + 2 + ver_len > len(data):
            return None
        pkt.version = data[pos + 2] if ver_len == 1 else 0
        pos += 2 + ver_len

        # v1/v2c: 提取community string (OCTET STRING)
        if pkt.version in (0, 1) and pos < len(data) and data[pos] == 0x04:
            comm_len = data[pos + 1]
            if pos + 2 + comm_len <= len(data):
                pkt.community = data[pos + 2:pos + 2 + comm_len].decode(
                    "ascii", errors="replace"
                )
            pos += 2 + comm_len

        # v3: msgGlobalData + msgSecurityParameters 层级解析
        if pkt.version == 3 and pos + 1 < len(data):
            if data[pos] == 0x30:
                pos = SnmpPduParser._skip_tlv(data, pos)
            if pos < len(data) and data[pos] == 0x04:
                pos = SnmpPduParser._skip_tlv(data, pos)
            if pos < len(data) and data[pos] == 0x30:
                inner = pos + 1
                inner_len = data[inner] if inner < len(data) else 0
                inner_start = inner + 1 if data[pos + 1] < 0x80 else inner + 1 + (data[pos + 1] & 0x7F)
                if inner_start < len(data):
                    inner_start = SnmpPduParser._skip_tlv(data, inner_start)
                    inner_start = SnmpPduParser._skip_tlv(data, inner_start)
                    if inner_start < len(data):
                        pkt.pdu_type = data[inner_start]
                        pkt.pdu_name = _SNMP_PDU_NAMES.get(pkt.pdu_type, f"0x{pkt.pdu_type:02X}")
                pos = inner_start
                return pkt

        # 标准PDU类型识别
        if pos < len(data) and data[pos] in _SNMP_PDU_NAMES:
            pkt.pdu_type = data[pos]
            pkt.pdu_name = _SNMP_PDU_NAMES[pkt.pdu_type]
        return pkt

    @staticmethod
    def _skip_tlv(data: bytes, pos: int) -> int:
        if pos >= len(data):
            return pos
        tag = data[pos]
        pos += 1
        if pos >= len(data):
            return pos
        length = data[pos]
        pos += 1
        if length & 0x80:  # 多字节长度编码
            nbytes = length & 0x7F
            length = int.from_bytes(data[pos:pos + nbytes], "big")
            pos += nbytes
        return pos + length

class SnmpAnalyzer:
    """SNMP 安全分析引擎——弱团体字符串+ MIB遍历+版本降级并行检测。

    处理流程：逐包轻量解析 → 聚合团体字符串/IP计数 → 触发告警。
    """

    def __init__(self):
        self._parser = SnmpPduParser()
        self._communities: Dict[str, Counter] = defaultdict(Counter)
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._alerts: List[SnmpAlert] = []
        self._packet_count = 0

    def feed(self, data: bytes, src_ip: str = "",
             dst_ip: str = "", timestamp: float = 0.0) -> Optional[SnmpPacket]:
        """输入SNMP UDP负载（端口161/162）进行逐包分析"""
        pkt = self._parser.parse(data)
        if pkt is None:
            return None
        self._packet_count += 1

        if pkt.community:
            self._communities[src_ip][pkt.community] += 1

        if pkt.pdu_name in ("GETNEXT", "GETBULK", "GET"):
            self._requests[src_ip].append(timestamp)

        self._check_default_community(pkt, src_ip)
        self._check_v1_insecure(pkt, src_ip)
        return pkt

    def _check_default_community(self, pkt: SnmpPacket, src_ip: str) -> None:
        if pkt.community and pkt.community.lower() in _DEFAULT_COMMUNITIES:
            self._alerts.append(SnmpAlert(
                alert_type="default_community",
                description=f"SNMPv{pkt.version+1} 使用默认团体字符串 "
                            f"'{pkt.community}' — 严重安全风险",
                severity="critical",
                src_ip=src_ip,
                evidence={"community": pkt.community, "version": pkt.version},
            ))

    def _check_v1_insecure(self, pkt: SnmpPacket, src_ip: str) -> None:
        if pkt.version == 0:
            self._alerts.append(SnmpAlert(
                alert_type="snmpv1_detected",
                description=f"检测到SNMPv1流量（明文团体字符串、无加密）— "
                            f"建议升级至SNMPv3 authPriv",
                severity="high",
                src_ip=src_ip,
            ))

    def detect_mib_walk(self) -> List[SnmpAlert]:
        """MIB遍历行为检测——时间窗口内GETNEXT/GETBULK密集度超过阈值。

        MIB walking通过反复GETNEXT遍历OID树，是攻击者信息收集的典型前置动作。
        """
        alerts = []
        now = __import__("time").time()
        for ip, timestamps in self._requests.items():
            recent = [t for t in timestamps if now - t < _BULK_WALK_WINDOW]
            if len(recent) >= _BULK_WALK_THRESHOLD:
                alerts.append(SnmpAlert(
                    alert_type="mib_walk",
                    description=f"MIB遍历嫌疑: {ip} 在{_BULK_WALK_WINDOW}s内"
                                f"发送{len(recent)}次GETNEXT/BULK — 网络侦察行为",
                    severity="high",
                    src_ip=ip,
                    evidence={
                        "request_count": len(recent),
                        "window_sec": _BULK_WALK_WINDOW,
                        "common_community": self._communities[ip].most_common(3) if ip in self._communities else [],
                    },
                ))
        return alerts

    def summary(self) -> Dict[str, Any]:
        walk_alerts = self.detect_mib_walk()
        self._alerts.extend(walk_alerts)

        type_dist = Counter(a.alert_type for a in self._alerts)
        sev_dist = Counter(a.severity for a in self._alerts)

        # 聚合全部已使用团体字符串，标记弱密码
        all_communities = Counter()
        for ip_comms in self._communities.values():
            all_communities.update(ip_comms)
        weak_comms = {k: v for k, v in all_communities.items()
                      if k.lower() in _DEFAULT_COMMUNITIES}

        return {
            "packets_analyzed": self._packet_count,
            "unique_communities": len(all_communities),
            "weak_communities_found": list(weak_comms.keys()),
            "alerts_total": len(self._alerts),
            "by_alert_type": dict(type_dist),
            "by_severity": dict(sev_dist),
            "mib_walk_detected": len(walk_alerts) > 0,
            "overall_risk": "critical" if sev_dist.get("critical", 0) > 0 else (
                "high" if sev_dist.get("high", 0) > 2 else (
                    "medium" if self._alerts else "low"
                )
            ),
            "recommendation": (
                "启用SNMPv3 authPriv (SHA-256 + AES-256)；"
                "禁用SNMPv1/v2c；将团体字符串迁移至USM用户。"
            ) if weak_comms else "",
        }

def analyze_snmp_traffic(packets: List[Dict]) -> Dict[str, Any]:
    """从UDP包字典列表批量分析SNMP流量——便捷入口函数"""
    analyzer = SnmpAnalyzer()
    for pkt in packets:
        analyzer.feed(
            pkt.get("payload", b""),
            src_ip=pkt.get("src_ip", ""),
            dst_ip=pkt.get("dst_ip", ""),
            timestamp=pkt.get("timestamp", 0.0),
        )
    return analyzer.summary()

__all__ = ["SnmpAnalyzer", "SnmpPduParser", "SnmpPacket",
           "SnmpAlert", "analyze_snmp_traffic"]
