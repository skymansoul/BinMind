"""ARP 欺骗检测器 —— MAC-IP绑定追踪、无偿ARP风暴检测、中间人攻击特征识别。

ARP协议根本缺陷：无状态、无认证。任意主机可在任意时刻发送
任意ARP消息而无需向网关或目标证明身份。本模块被动监听ARP
流量建立MAC-IP绑定历史，在检测到绑定变更时告警。

检测目标：
- ARP缓存投毒 (gratuitous ARP with spoofed IP-MAC)
- MAC洪水 (大量随机MAC地址的ARP请求 —— 交换机CAM表溢出前奏)
- ARP请求风暴 (DoS + 扫描)
- 单向ARP（只发请求从不响应 —— 被动嗅探器指纹）
"""
import logging, struct, time
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any

_log = logging.getLogger(__name__)

# ARP 操作码
_ARP_REQUEST = 1; _ARP_REPLY = 2
_ARP_RARP_REQUEST = 3; _ARP_RARP_REPLY = 4

# ARP 头结构 (Ethernet + ARP 固定部分)
_ARP_HDR_OFFSET = 14  # 跳过以太网头 (6+6+2)
_ARP_HTYPE = _ARP_HDR_OFFSET      # 硬件类型 (2B)
_ARP_PTYPE = _ARP_HDR_OFFSET + 2  # 协议类型 (2B)
_ARP_HLEN = _ARP_HDR_OFFSET + 4   # 硬件地址长度 (1B)
_ARP_PLEN = _ARP_HDR_OFFSET + 5   # 协议地址长度 (1B)
_ARP_OPER = _ARP_HDR_OFFSET + 6   # 操作码 (2B)
_ARP_SHA = _ARP_HDR_OFFSET + 8    # 发送方硬件地址 (6B)
_ARP_SPA = _ARP_HDR_OFFSET + 14   # 发送方协议地址 (4B)
_ARP_THA = _ARP_HDR_OFFSET + 18   # 目标硬件地址 (6B)
_ARP_TPA = _ARP_HDR_OFFSET + 24   # 目标协议地址 (4B)
_ARP_MIN_SIZE = _ARP_HDR_OFFSET + 28  # 最小ARP包大小

# 绑定变更窗口（秒）—— 在此窗口内同一IP出现不同MAC视为投毒
_BINDING_WINDOW = 300
# MAC洪水阈值 —— 每秒新MAC地址数
_MAC_FLOOD_RATE = 20
# 无偿ARP风暴 —— 每秒GARP包数
_GARP_STORM_RATE = 10


@dataclass
class ArpBinding:
    ip: str = ""
    mac: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    is_gateway: bool = False


@dataclass
class ArpAlert:
    alert_type: str   # spoof / mac_flood / garp_storm / scan / unidirectional
    description: str
    src_mac: str = ""
    src_ip: str = ""
    target_ip: str = ""
    severity: str = "high"
    timestamp: float = 0.0


class ArpSpoofDetector:
    """ARP 欺骗综合检测器 —— 被动监听、绑定追踪、变更检测。

    检测逻辑：
    - IP→MAC绑定变更：同一IP在窗口内出现不同MAC → 投毒
    - 网关IP的MAC变更：风险最高 —— 中间人攻击直接入口
    - GARP风暴：大量无偿ARP(目标IP=发送方IP) —— CAM表溢出前兆
    - MAC洪水：大量首次出现的MAC → 交换机资源耗尽攻击
    """

    def __init__(self):
        self._bindings: Dict[str, ArpBinding] = {}      # IP → ArpBinding
        self._mac_ips: Dict[str, set] = defaultdict(set) # MAC → {IPs}
        self._alerts: List[ArpAlert] = []
        self._mac_first_seen: Dict[str, float] = {}      # MAC → 首次出现时间
        self._garp_counts: Dict[str, int] = Counter()    # MAC → GARP计数
        self._arp_request_counts: Dict[str, int] = Counter()
        self._arp_reply_counts: Dict[str, int] = Counter()
        # 网关候选（出现频率最高且目标为.1/.254结尾的IP）
        self._gateway_candidates: Dict[str, int] = Counter()
        self._known_gateway_ips: set = set()

    def feed(self, raw_frame: bytes, timestamp: Optional[float] = None) -> Optional[ArpAlert]:
        """输入以太网帧（含14字节以太网头），返回触发的告警（如有）。

        仅处理 ARP (ethertype=0x0806)。其他帧静默忽略。
        """
        if len(raw_frame) < _ARP_MIN_SIZE:
            return None
        ts = timestamp if timestamp is not None else time.time()

        # 以太类型检测
        eth_type = struct.unpack(">H", raw_frame[12:14])[0]
        if eth_type != 0x0806:  # ARP
            return None

        oper = struct.unpack(">H", raw_frame[_ARP_OPER:_ARP_OPER+2])[0]
        sha = ":".join(f"{b:02x}" for b in raw_frame[_ARP_SHA:_ARP_SHA+6])
        spa = ".".join(str(b) for b in raw_frame[_ARP_SPA:_ARP_SPA+4])
        tha = ":".join(f"{b:02x}" for b in raw_frame[_ARP_THA:_ARP_THA+6])
        tpa = ".".join(str(b) for b in raw_frame[_ARP_TPA:_ARP_TPA+4])

        alert = None

        if oper == _ARP_REQUEST:
            self._arp_request_counts[sha] += 1
        elif oper == _ARP_REPLY:
            self._arp_reply_counts[sha] += 1

        # MAC洪水检测 —— 每秒出现的新MAC超过阈值
        if sha not in self._mac_first_seen:
            self._mac_first_seen[sha] = ts
            recent_new = sum(1 for t in self._mac_first_seen.values()
                            if ts - t < 1.0)
            if recent_new > _MAC_FLOOD_RATE:
                alert = ArpAlert(
                    alert_type="mac_flood",
                    description=f"MAC洪水: {recent_new}个新MAC/秒 —— 交换机CAM表溢出攻击",
                    src_mac=sha, severity="high", timestamp=ts,
                )

        # 无偿ARP (GARP) 检测 —— 目标IP=发送方IP
        is_gratuitous = (spa == tpa and oper == _ARP_REPLY and
                        tha == "00:00:00:00:00:00")
        if is_gratuitous:
            self._garp_counts[sha] += 1

        # IP→MAC 绑定追踪
        if spa != "0.0.0.0" and spa != "255.255.255.255":
            existing = self._bindings.get(spa)
            if existing is not None:
                existing.last_seen = ts
                # 绑定变更检测
                if existing.mac != sha and (ts - existing.last_seen) < _BINDING_WINDOW:
                    sev = "critical" if existing.is_gateway else "high"
                    alert = ArpAlert(
                        alert_type="arp_spoof",
                        description=f"ARP投毒: IP {spa} 的MAC从 {existing.mac} 变为 {sha}"
                                    + (" (网关IP)" if existing.is_gateway else ""),
                        src_mac=sha, src_ip=spa, severity=sev, timestamp=ts,
                    )
                self._mac_ips[sha].add(spa)
            else:
                self._bindings[spa] = ArpBinding(
                    ip=spa, mac=sha, first_seen=ts, last_seen=ts,
                )
                self._mac_ips[sha].add(spa)

        # 网关检测 —— 启发式: .1和.254结尾的IP频繁出现
        if spa.split(".")[-1] in ("1", "254"):
            self._gateway_candidates[spa] += 1

        # GARP 风暴 —— 大量GARP/秒
        if is_gratuitous and self._garp_counts[sha] >= _GARP_STORM_RATE:
            alert = ArpAlert(
                alert_type="garp_storm",
                description=f"GARP风暴: {sha}发出{self._garp_counts[sha]}次无偿ARP —— "
                            f"ARP投毒或生成树攻击嫌疑",
                src_mac=sha, src_ip=spa, severity="high", timestamp=ts,
            )

        if alert:
            self._alerts.append(alert)
        return alert

    def finalize_gateways(self) -> None:
        """所有包处理完成后调用 —— 自动识别网关IP"""
        for ip, count in self._gateway_candidates.most_common(5):
            if ip in self._bindings:
                self._bindings[ip].is_gateway = True
                self._known_gateway_ips.add(ip)

    def detect_unidirectional(self) -> List[ArpAlert]:
        """检测单向ARP设备 —— 只发请求不响应（被动嗅探器特征）"""
        alerts = []
        rq_only = set(self._arp_request_counts) - set(self._arp_reply_counts)
        for mac in rq_only:
            if self._arp_request_counts[mac] >= 5:
                alerts.append(ArpAlert(
                    alert_type="unidirectional",
                    description=f"单向ARP设备 {mac}: 发送{self._arp_request_counts[mac]}次请求"
                                f"，从未响应 —— 被动嗅探器",
                    src_mac=mac, severity="medium",
                ))
        return alerts

    def summary(self) -> Dict[str, Any]:
        self.finalize_gateways()
        ud_alerts = self.detect_unidirectional()
        self._alerts.extend(ud_alerts)

        types = Counter(a.alert_type for a in self._alerts)
        sevs = Counter(a.severity for a in self._alerts)
        return {
            "total_bindings": len(self._bindings),
            "total_macs_seen": len(self._mac_first_seen),
            "known_gateways": list(self._known_gateway_ips),
            "alerts_total": len(self._alerts),
            "by_alert_type": dict(types),
            "by_severity": dict(sevs),
            "spoof_events": sum(1 for a in self._alerts if a.alert_type == "arp_spoof"),
            "mac_flood_events": sum(1 for a in self._alerts if a.alert_type == "mac_flood"),
            "garp_storms": sum(1 for a in self._alerts if a.alert_type == "garp_storm"),
            "overall_risk": "critical" if sevs.get("critical", 0) > 0 else (
                "high" if types.get("arp_spoof", 0) > 0 else (
                    "medium" if len(self._alerts) > 0 else "low"
                )
            ),
        }


def detect_arp_spoof(raw_frames: List[bytes]) -> Dict[str, Any]:
    """从以太网帧列表检测ARP欺骗 —— 便捷入口"""
    det = ArpSpoofDetector()
    for frame in raw_frames:
        det.feed(frame)
    return det.summary()


__all__ = ["ArpSpoofDetector", "ArpAlert", "ArpBinding", "detect_arp_spoof"]
