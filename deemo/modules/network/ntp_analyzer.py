"""NTP 协议安全分析 —— 放大攻击检测、Monlist扫描、时间源信任评估。

NTP monlist (MODE_CONTROL+opcode=42)是历史上放大系数最高的反射攻击向量之一
（单请求可达556.9x放大率）。ntp.conf 4.2.7p26+默认禁用monlist，
但全球仍有大量未升级的NTP服务器存在此漏洞。

- SoK Digital Clock Trustworthiness
- CVE-2013-5211 — NTP monlist 反射DDoS
- RFC 8915 (Network Time Security for NTP)
"""
import struct, logging, math, socket
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime

_log = logging.getLogger(__name__)

# NTP 包结构常量（RFC 5905 / legacy RFC 1305）
_NTP_LI_VN_MODE = 0   # 1B: Leap indicator (2bit) + Version (3bit) + Mode (3bit)
_NTP_STRATUM = 1       # 1B: 层次级别
_NTP_POLL = 2          # 1B: 轮询间隔
_NTP_PRECISION = 3     # 1B: 精度
_NTP_ROOT_DELAY = 4    # 4B
_NTP_ROOT_DISP = 8     # 4B
_NTP_REF_ID = 12       # 4B: 参考标识符
_NTP_REF_TS = 16       # 8B: 参考时间戳
_NTP_ORIG_TS = 24      # 8B: 发起时间戳
_NTP_RECV_TS = 32      # 8B: 接收时间戳
_NTP_XMIT_TS = 40      # 8B: 发送时间戳
_NTP_MIN_SIZE = 48     # 标准NTP包大小（不含扩展字段）

# NTP 模式
_NTP_MODE_RESERVED = 0; _NTP_MODE_SYMMETRIC_ACTIVE = 1
_NTP_MODE_SYMMETRIC_PASSIVE = 2; _NTP_MODE_CLIENT = 3
_NTP_MODE_SERVER = 4; _NTP_MODE_BROADCAST = 5
_NTP_MODE_CONTROL = 6  # NTP control messages (monlist, readvar等)
_NTP_MODE_PRIVATE = 7

_NTP_MODE_NAMES = {
    0: "reserved", 1: "symmetric_active", 2: "symmetric_passive",
    3: "client", 4: "server", 5: "broadcast",
    6: "control", 7: "private",
}

# NTP 版本号
_NTP_VERSION_MIN = 1; _NTP_VERSION_MAX = 4

# NTP control opcodes (MODE_CONTROL 下的操作码)
_NTP_CTL_OP_READSTAT = 1; _NTP_CTL_OP_READVAR = 2
_NTP_CTL_OP_MON_GETLIST = 42  # monlist —— 核心漏洞
_NTP_CTL_OP_MON_GETLIST_1 = 42  # alias

# Stratum 值含义
_STRATUM_UNSPEC = 0
_STRATUM_PRIMARY = 1       # 直接连接参考时钟（GPS/原子钟）
_STRATUM_SECONDARY_MIN = 2
_STRATUM_SECONDARY_MAX = 15
_STRATUM_UNSYNC = 16

# 放大因子阈值
_AMPLIFICATION_THRESHOLD = 5.0      # >5x = 警告
_AMPLIFICATION_CRITICAL = 20.0      # >20x = 严重

@dataclass
class NtpPacket:
    """解析后的NTP包"""
    li: int = 0          # leap indicator
    version: int = 0
    mode: int = 0
    mode_name: str = ""
    stratum: int = 0
    poll_interval: int = 0
    precision: int = 0
    root_delay: float = 0.0
    root_dispersion: float = 0.0
    ref_id: str = ""       # stratum 1时=时钟源ID(GPS/DCF等)，其他=参考服务器IP
    ref_ts: float = 0.0
    orig_ts: float = 0.0
    recv_ts: float = 0.0
    xmit_ts: float = 0.0
    raw: bytes = b""

@dataclass
class NtpAnomaly:
    anomaly_type: str
    src_ip: str = ""
    description: str = ""
    severity: str = "medium"
    amplification_factor: float = 0.0

class NtpPacketParser:
    """NTP 二进制包解析器 —— 支持标准48字节和带扩展字段的NTP包。

    解析RFC 5905 NTPv4格式，兼容v1/v2/v3遗留格式。
    """

    @staticmethod
    def parse(data: bytes) -> Optional[NtpPacket]:
        if len(data) < _NTP_MIN_SIZE:
            return None

        pkt = NtpPacket(raw=data[:_NTP_MIN_SIZE])
        b0 = data[_NTP_LI_VN_MODE]
        pkt.li = (b0 >> 6) & 0x03
        pkt.version = (b0 >> 3) & 0x07
        pkt.mode = b0 & 0x07
        pkt.mode_name = _NTP_MODE_NAMES.get(pkt.mode, f"mode_{pkt.mode}")

        pkt.stratum = data[_NTP_STRATUM]
        pkt.poll_interval = data[_NTP_POLL]
        pkt.precision = data[_NTP_PRECISION]
        # 有符号整数 → 实际精度值（2^precision 秒）
        pkt.precision = NtpPacketParser._decode_int8(pkt.precision)

        pkt.root_delay = NtpPacketParser._ntp_short_to_float(data[_NTP_ROOT_DELAY:_NTP_ROOT_DELAY+4])
        pkt.root_dispersion = NtpPacketParser._ntp_short_to_float(data[_NTP_ROOT_DISP:_NTP_ROOT_DISP+4])

        # _id: stratum 1 → ASCII时钟源标识，其他 → IPv4地址
        rid = data[_NTP_REF_ID:_NTP_REF_ID+4]
        if pkt.stratum <= 1:
            pkt.ref_id = rid.decode("ascii", errors="replace").rstrip("\x00")
        else:
            try:
                pkt.ref_id = socket.inet_ntoa(rid)
            except Exception:
                pkt.ref_id = rid.hex()

        pkt.ref_ts = NtpPacketParser._ntp_timestamp(data[_NTP_REF_TS:_NTP_REF_TS+8])
        pkt.orig_ts = NtpPacketParser._ntp_timestamp(data[_NTP_ORIG_TS:_NTP_ORIG_TS+8])
        pkt.recv_ts = NtpPacketParser._ntp_timestamp(data[_NTP_RECV_TS:_NTP_RECV_TS+8])
        pkt.xmit_ts = NtpPacketParser._ntp_timestamp(data[_NTP_XMIT_TS:_NTP_XMIT_TS+8])

        return pkt

    @staticmethod
    def _ntp_short_to_float(data: bytes) -> float:
        """NTP短格式(16.16定点数)→浮点秒数"""
        if len(data) < 4:
            return 0.0
        secs = struct.unpack(">H", data[:2])[0]
        frac = struct.unpack(">H", data[2:4])[0]
        return float(secs) + frac / 65536.0

    @staticmethod
    def _ntp_timestamp(data: bytes) -> float:
        """NTP时间戳(32.32定点数，纪元=1900-01-01)→Unix时间戳"""
        if len(data) < 8:
            return 0.0
        secs = struct.unpack(">I", data[:4])[0]
        frac = struct.unpack(">I", data[4:8])[0]
        ts = float(secs) + frac / 4294967296.0
        # NTP纪元→Unix纪元
        if ts > 2208988800:
            ts -= 2208988800
        return ts

    @staticmethod
    def _decode_int8(val: int) -> int:
        if val & 0x80:
            return val - 256
        return val

class NtpAmplificationDetector:
    """NTP 放大攻击检测器 —— 检测monlist和其他高放大率NTP控制消息。

    分析维度：
    1. 包大小比（请求/响应比值） —— 单次检测
    2. MODE_CONTROL 消息频率 —— 周期性monlist扫描
    3. 非对称流量（出站>>入站的NTP） —— 反射源识别
    """

    def __init__(self):
        self._req_sizes: Dict[str, int] = {}      # (src,dst) → 请求大小
        self._amp_scores: Dict[str, float] = {}   # (src,dst) → 放大因子
        self._monlist_hits: List[NtpAnomaly] = []
        self._control_msg_counts: Counter = Counter()

    def feed(self, src_ip: str, dst_ip: str, src_port: int,
             dst_port: int, data: bytes, timestamp: float = 0.0) -> Optional[NtpAnomaly]:
        """输入一个UDP NTP包（src_port或dst_port至少一个=123）"""
        flow_key = f"{src_ip}:{src_port}>{dst_ip}:{dst_port}"
        pkt = NtpPacketParser.parse(data)
        if pkt is None:
            return None

        anomaly = None

        # MODE_CONTROL 检测 —— 包含monlist (opcode=42)
        if pkt.mode == _NTP_MODE_CONTROL and len(data) >= _NTP_MIN_SIZE:
            self._control_msg_counts[src_ip] += 1
            # 尝试检测opcode（在MODE_CONTROL包中，offset 12+的部分）
            if len(data) >= 49 and data[48] in (_NTP_CTL_OP_MON_GETLIST,):
                anomaly = NtpAnomaly(
                    anomaly_type="ntp_monlist",
                    src_ip=src_ip,
                    description=f"检测到NTP monlist请求 (opcode={data[48]}) —— "
                                f"存在反射放大风险(CVE-2013-5211)",
                    severity="critical",
                )
                self._monlist_hits.append(anomaly)

        # 放大因子计算 —— 请求包vs响应包大小
        if pkt.mode == _NTP_MODE_CLIENT:
            self._req_sizes[flow_key] = len(data)
        elif pkt.mode == _NTP_MODE_SERVER and flow_key in self._req_sizes:
            req_size = max(self._req_sizes[flow_key], 1)
            amp_factor = len(data) / req_size
            self._amp_scores[flow_key] = amp_factor
            if amp_factor > _AMPLIFICATION_THRESHOLD:
                sev = "critical" if amp_factor > _AMPLIFICATION_CRITICAL else "high"
                anomaly = NtpAnomaly(
                    anomaly_type="ntp_amplification",
                    src_ip=src_ip,
                    description=f"NTP放大因子={amp_factor:.1f}x "
                                f"(req={req_size}B, resp={len(data)}B)",
                    severity=sev,
                    amplification_factor=amp_factor,
                )

        # Stratum 异常检测 —— stratum=0 表示未指定/未同步
        if pkt.stratum == _STRATUM_UNSPEC and pkt.mode == _NTP_MODE_SERVER:
            anomaly = NtpAnomaly(
                anomaly_type="ntp_stratum_zero",
                src_ip=src_ip,
                description="NTP服务器Stratum=0 —— 伪造/KoD包嫌疑",
                severity="low",
            )

        return anomaly

    def check_scanner(self) -> List[NtpAnomaly]:
        """检测NTP monlist扫描器 —— 短时间内大量IP发送MODE_CONTROL消息"""
        alerts = []
        for ip, count in self._control_msg_counts.items():
            if count >= 10:
                alerts.append(NtpAnomaly(
                    anomaly_type="ntp_monlist_scanner",
                    src_ip=ip,
                    description=f"NTP monlist扫描器: {count}次MODE_CONTROL——疑似DDoS反射源扫描",
                    severity="high",
                ))
        return alerts

class NtpAnalyzer:
    """NTP 协议安全分析器 —— 整合包解析+放大检测+扫描检测。

    输入：从UDP流量中提取的NTP包（源或目标端口123）。
    输出：安全分析报告，含放大因子分布、monlist告警、stratum异常。
    """

    def __init__(self):
        self._parser = NtpPacketParser()
        self._amp_detector = NtpAmplificationDetector()
        self._alerts: List[NtpAnomaly] = []
        self._packets_parsed = 0

    def feed(self, src_ip: str, dst_ip: str, src_port: int,
             dst_port: int, data: bytes, ts: float = 0.0) -> Optional[NtpPacket]:
        """输入单个NTP包"""
        pkt = self._parser.parse(data)
        if pkt is None:
            return None
        self._packets_parsed += 1

        alert = self._amp_detector.feed(src_ip, dst_ip, src_port, dst_port, data, ts)
        if alert:
            self._alerts.append(alert)
        return pkt

    def summary(self) -> Dict[str, Any]:
        scan_alerts = self._amp_detector.check_scanner()
        self._alerts.extend(scan_alerts)

        sev_dist = Counter(a.severity for a in self._alerts)
        type_dist = Counter(a.anomaly_type for a in self._alerts)
        amp_values = [a.amplification_factor for a in self._alerts
                      if a.amplification_factor > 0]

        return {
            "packets_analyzed": self._packets_parsed,
            "alerts_total": len(self._alerts),
            "monlist_hits": len(self._amp_detector._monlist_hits),
            "severity_distribution": dict(sev_dist),
            "anomaly_types": dict(type_dist),
            "max_amplification": max(amp_values) if amp_values else 0.0,
            "mean_amplification": sum(amp_values) / len(amp_values) if amp_values else 0.0,
            "scanners_detected": len(scan_alerts),
            "overall_risk": "critical" if sev_dist.get("critical", 0) > 0 else (
                "high" if sev_dist.get("high", 0) > 0 else "low"
            ),
            "top_alerts": [
                {"type": a.anomaly_type, "src_ip": a.src_ip,
                 "severity": a.severity, "description": a.description}
                for a in self._alerts[-20:]
            ],
        }

def analyze_ntp_traffic(packets: List[Dict]) -> Dict[str, Any]:
    """便捷入口 —— 从UDP包字典列表分析NTP流量"""
    analyzer = NtpAnalyzer()
    for pkt in packets:
        analyzer.feed(
            pkt.get("src_ip", ""), pkt.get("dst_ip", ""),
            pkt.get("src_port", 0), pkt.get("dst_port", 0),
            pkt.get("payload", b""), pkt.get("timestamp", 0.0),
        )
    return analyzer.summary()

__all__ = ["NtpAnalyzer", "NtpPacketParser", "NtpAmplificationDetector",
           "NtpPacket", "NtpAnomaly", "analyze_ntp_traffic"]
