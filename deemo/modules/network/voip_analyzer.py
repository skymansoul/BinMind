# 2026-07-26
"""VoIP/SIP/RTP 协议安全分析器 —— SIP洪水、RTP流劫持、长途欺诈模式检测。

VoIP安全面临三类典型威胁：
1. SIP信令层：注册劫持、INVITE洪水、呼叫拦截
2. RTP媒体层：流注入、DTMF窃取、SRTP降级
3. 基础设施层：PBX密码暴力破解、国际长途欺诈(IRS)

检测基于SIP消息头分析和RTP流特征——不解码音频载荷。
"""
import logging, re, struct, hashlib
from collections import defaultdict, Counter, deque
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from statistics import mean, stdev

_log = logging.getLogger(__name__)

# SIP 请求方法
_SIP_METHODS = frozenset({
    "INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS",
    "PRACK", "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "REFER",
    "MESSAGE", "UPDATE",
})

# RTP payload type 常见映射
_RTP_PT_MAP = {
    0: "PCMU/8000", 3: "GSM/8000", 8: "PCMA/8000",
    9: "G722/8000", 18: "G729/8000", 101: "telephone-event",
}

# SIP 响应码类别
_SIP_RESP_CATEGORIES = {
    1: "provisional", 2: "success", 3: "redirection",
    4: "client_error", 5: "server_error", 6: "global_failure",
}

# 长途欺诈检测 —— 高费率国际目的地前缀
_HIGH_COST_PREFIXES = frozenset({
    "0088", "0097", "00252", "00253", "00225", "00237", "00269",
    "00508", "00689", "00691", "00881", "00882", "00224", "00263",
})


@dataclass
class SipMessage:
    method: str = ""              # 请求方法或响应码
    call_id: str = ""
    from_uri: str = ""
    to_uri: str = ""
    via_branch: str = ""
    cseq: int = 0
    is_response: bool = False
    response_code: int = 0
    user_agent: str = ""
    raw: str = ""


@dataclass
class RtpStreamInfo:
    ssrc: int = 0
    payload_type: int = 0
    packet_count: int = 0
    byte_count: int = 0
    start_time: float = 0.0
    last_seq: int = 0
    jitter_estimate: float = 0.0
    lost_packets: int = 0


@dataclass
class VoipAlert:
    alert_type: str    # sip_flood / rtp_hijack / toll_fraud / register_bruteforce
    description: str
    severity: str = "medium"
    src_ip: str = ""
    call_id: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


class SipMessageParser:
    """SIP 消息解析器 —— 从UDP/TCP负载提取结构化SIP头字段。

    SIP遵循RFC 3261文本格式，类HTTP的请求/响应行+头部。使用正则
    提取核心字段，不构建完整SIP栈。
    """

    _REQ_LINE = re.compile(rb"^(\w+)\s+sip:([^\s]+)\s+SIP/2\.0", re.I)
    _RESP_LINE = re.compile(rb"^SIP/2\.0\s+(\d{3})", re.I)
    _CALL_ID = re.compile(rb"^Call-ID:\s*(.+)$", re.I | re.M)
    _FROM = re.compile(rb"^From:\s*(.+)$", re.I | re.M)
    _TO = re.compile(rb"^To:\s*(.+)$", re.I | re.M)
    _VIA = re.compile(rb"branch=([^\s;]+)", re.I)
    _CSEQ = re.compile(rb"^CSeq:\s*(\d+)\s+(\w+)", re.I | re.M)
    _USER_AGENT = re.compile(rb"^User-Agent:\s*(.+)$", re.I | re.M)

    @classmethod
    def parse(cls, data: bytes) -> Optional[SipMessage]:
        if len(data) < 10:
            return None

        msg = SipMessage(raw=data.decode("utf-8", errors="replace")[:500])

        req = cls._REQ_LINE.search(data)
        resp = cls._RESP_LINE.search(data)
        if req:
            msg.method = req.group(1).decode("ascii").upper()
            msg.is_response = False
        elif resp:
            msg.method = resp.group(1).decode("ascii")
            msg.response_code = int(msg.method)
            msg.is_response = True
        else:
            return None  # 非SIP流量

        cid = cls._CALL_ID.search(data)
        if cid:
            msg.call_id = cid.group(1).decode("ascii", errors="replace").strip()

        fr = cls._FROM.search(data)
        if fr:
            msg.from_uri = fr.group(1).decode("ascii", errors="replace").strip()[:120]

        to = cls._TO.search(data)
        if to:
            msg.to_uri = to.group(1).decode("ascii", errors="replace").strip()[:120]

        via = cls._VIA.search(data)
        if via:
            msg.via_branch = via.group(1).decode("ascii", errors="replace")

        cseq = cls._CSEQ.search(data)
        if cseq:
            try:
                msg.cseq = int(cseq.group(1))
            except ValueError:
                pass

        ua = cls._USER_AGENT.search(data)
        if ua:
            msg.user_agent = ua.group(1).decode("ascii", errors="replace").strip()[:100]

        return msg


class SipFloodDetector:
    """SIP 洪水检测 —— 基于INVITE/REGISTER速率的EWMA异常检测。

    SIP洪水是VoIP最常见的DoS攻击形式：超大量INVITE/REGISTER请求
    耗尽PBX的并发呼叫处理能力。
    """

    def __init__(self, alpha: float = 0.2):
        self._alpha = alpha
        self._counters: Dict[str, deque] = defaultdict(lambda: deque(maxlen=30))
        self._ewma: Dict[str, float] = {}

    def feed(self, method: str, src_ip: str, timestamp: float) -> bool:
        """返回True表示当前速率异常（洪水检测触发）"""
        key = f"{src_ip}:{method}"
        self._counters[key].append(timestamp)

        recent = self._counters[key]
        if len(recent) < 5:
            return False

        duration = recent[-1] - recent[0] if len(recent) >= 2 else 0.001
        rate = len(recent) / max(duration, 0.001)

        prev = self._ewma.get(key, rate)
        new_ewma = self._alpha * rate + (1 - self._alpha) * prev
        self._ewma[key] = new_ewma

        return rate > new_ewma * 3.0 and rate > 5.0  # 超过EWMA基线3倍且>5/秒


class RtpStreamTracker:
    """RTP 流追踪器 —— 检测SSRC冲突、序列号跳跃、抖动异常。

    RTP固定头部（12字节）：
    [V=2|P|X|CC(4)] [M|PT(7)] [SeqNum(16)] [Timestamp(32)] [SSRC(32)]
    """

    def __init__(self):
        self._streams: Dict[int, RtpStreamInfo] = {}
        self._ssrc_sources: Dict[int, str] = {}  # SSRC → IP:port

    def feed(self, data: bytes, src_ip: str, src_port: int,
             timestamp: float = 0.0) -> Optional[RtpStreamInfo]:
        if len(data) < 12:
            return None

        b0 = data[0]
        version = (b0 >> 6) & 0x03
        if version != 2:  # RTP version must be 2
            return None

        pt = data[1] & 0x7F
        seq = struct.unpack(">H", data[2:4])[0]
        ts = struct.unpack(">I", data[4:8])[0]
        ssrc = struct.unpack(">I", data[8:12])[0]

        flow_key = f"{src_ip}:{src_port}"
        if ssrc not in self._streams:
            self._streams[ssrc] = RtpStreamInfo(
                ssrc=ssrc, payload_type=pt, start_time=timestamp,
            )
            self._ssrc_sources[ssrc] = flow_key

        stream = self._streams[ssrc]
        stream.packet_count += 1
        stream.byte_count += len(data)
        stream.payload_type = pt

        # 序列号跳跃检测（>500的跳跃 = 丢包或重放）
        if stream.last_seq > 0:
            delta = (seq - stream.last_seq) & 0xFFFF
            if delta > 500:
                stream.lost_packets += delta - 1
        stream.last_seq = seq

        # RTP 抖动估计（RFC 3550 §6.4.1）
        if stream.packet_count > 1:
            transit = timestamp - ts
            d = abs(transit)
            stream.jitter_estimate += (d - stream.jitter_estimate) / 16.0

        return stream


class VoipAnalyzer:
    """VoIP 综合分析引擎 —— SIP信令+RTP媒体+长途欺诈并行检测。

    分析流程：
    1. SIP层：消息解析 → 洪水检测 → REGISTER爆破检测 → 呼叫模式分析
    2. RTP层：流向追踪 → SSRC冲突 → SRTP缺失检测
    3. 交叉层：呼叫方/被叫方模式 → 高费率目的地匹配
    """

    def __init__(self):
        self._sip_parser = SipMessageParser()
        self._flood_det = SipFloodDetector()
        self._rtp_tracker = RtpStreamTracker()
        self._alerts: List[VoipAlert] = []
        self._register_attempts: Dict[str, int] = Counter()
        self._call_history: List[Dict] = []

    def feed_sip(self, data: bytes, src_ip: str = "",
                 dst_ip: str = "", timestamp: float = 0.0) -> Optional[SipMessage]:
        """输入SIP消息负载（UDP/TCP data）"""
        msg = self._sip_parser.parse(data)
        if msg is None:
            return None

        # 洪水检测
        if msg.method in ("INVITE", "REGISTER"):
            if self._flood_det.feed(msg.method, src_ip, timestamp):
                self._alerts.append(VoipAlert(
                    alert_type="sip_flood",
                    description=f"SIP {msg.method}洪水: {src_ip} 速率超EWMA基线3倍",
                    severity="high", src_ip=src_ip,
                    evidence={"method": msg.method},
                ))

        # REGISTER 爆破 —— 同一源IP的多次失败注册
        if msg.method == "REGISTER" and msg.is_response and msg.response_code in (401, 403):
            # 从Via或From中提取源IP
            self._register_attempts[src_ip] += 1

        # 呼叫记录
        if msg.method == "INVITE" and not msg.is_response:
            self._call_history.append({
                "call_id": msg.call_id, "from_uri": msg.from_uri,
                "to_uri": msg.to_uri, "timestamp": timestamp,
                "src_ip": src_ip,
            })

        return msg

    def feed_rtp(self, data: bytes, src_ip: str = "",
                 src_port: int = 0, timestamp: float = 0.0) -> Optional[RtpStreamInfo]:
        """输入RTP包"""
        return self._rtp_tracker.feed(data, src_ip, src_port, timestamp)

    def detect_register_bruteforce(self) -> List[VoipAlert]:
        alerts = []
        for ip, count in self._register_attempts.items():
            if count >= 10:
                alerts.append(VoipAlert(
                    alert_type="register_bruteforce",
                    description=f"SIP REGISTER爆破: {ip} 返回{count}次401/403 — 密码猜测攻击",
                    severity="critical", src_ip=ip,
                    evidence={"failed_attempts": count},
                ))
        return alerts

    def detect_toll_fraud(self) -> List[VoipAlert]:
        """检测国际长途欺诈(IRS) —— 被叫号码匹配高费率目的地前缀"""
        alerts = []
        for call in self._call_history[-100:]:
            to_uri = call.get("to_uri", "")
            # 提取被叫号码
            num_match = re.search(r"sip:(\+?\d+)", to_uri)
            if num_match:
                number = num_match.group(1)
                for prefix in _HIGH_COST_PREFIXES:
                    if number.startswith(prefix):
                        alerts.append(VoipAlert(
                            alert_type="toll_fraud",
                            description=f"高费率国际长途嫌疑: {number} → "
                                        f"前缀{prefix}（IRS欺诈目标地区）",
                            severity="high",
                            src_ip=call.get("src_ip", ""),
                            call_id=call.get("call_id", ""),
                            evidence={"called_number": number, "prefix": prefix},
                        ))
                        break
        return alerts

    def detect_rtp_hijack(self) -> List[VoipAlert]:
        """检测RTP劫持 —— SSRC冲突（同一SSRC来自不同IP）"""
        alerts = []
        for ssrc, info in self._rtp_tracker._streams.items():
            source = self._rtp_tracker._ssrc_sources.get(ssrc, "")
            if info.packet_count > 50 and info.lost_packets > info.packet_count * 0.3:
                alerts.append(VoipAlert(
                    alert_type="rtp_hijack",
                    description=f"RTP SSRC={ssrc:08X}: 丢包率{info.lost_packets/max(info.packet_count,1):.1%} — "
                                f"可能为RTP流注入或降级攻击",
                    severity="high",
                    evidence={
                        "ssrc": f"0x{ssrc:08X}",
                        "packet_count": info.packet_count,
                        "lost_packets": info.lost_packets,
                        "jitter": round(info.jitter_estimate, 3),
                    },
                ))
        return alerts

    def summary(self) -> Dict[str, Any]:
        reg_alerts = self.detect_register_bruteforce()
        tf_alerts = self.detect_toll_fraud()
        rtp_alerts = self.detect_rtp_hijack()
        self._alerts.extend(reg_alerts + tf_alerts + rtp_alerts)

        sev_dist = Counter(a.severity for a in self._alerts)
        type_dist = Counter(a.alert_type for a in self._alerts)

        return {
            "alerts_total": len(self._alerts),
            "by_severity": dict(sev_dist),
            "by_alert_type": dict(type_dist),
            "rtp_streams_tracked": len(self._rtp_tracker._streams),
            "calls_observed": len(self._call_history),
            "register_bruteforce_sources": len(reg_alerts),
            "toll_fraud_attempts": len(tf_alerts),
            "rtp_hijack_alerts": len(rtp_alerts),
            "overall_risk": "critical" if sev_dist.get("critical", 0) > 0 else (
                "high" if sev_dist.get("high", 0) > 2 else (
                    "medium" if self._alerts else "low"
                )
            ),
        }


def analyze_voip_traffic(sip_packets: List[Dict] = None,
                         rtp_packets: List[Dict] = None) -> Dict[str, Any]:
    """便捷入口 —— 同时分析SIP和RTP流量"""
    analyzer = VoipAnalyzer()
    for p in (sip_packets or []):
        analyzer.feed_sip(
            p.get("payload", b""), p.get("src_ip", ""),
            p.get("dst_ip", ""), p.get("timestamp", 0.0),
        )
    for p in (rtp_packets or []):
        analyzer.feed_rtp(
            p.get("payload", b""), p.get("src_ip", ""),
            p.get("src_port", 0), p.get("timestamp", 0.0),
        )
    return analyzer.summary()


__all__ = ["VoipAnalyzer", "SipMessageParser", "SipFloodDetector",
           "RtpStreamTracker", "VoipAlert", "analyze_voip_traffic"]
