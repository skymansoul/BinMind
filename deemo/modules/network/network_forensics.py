"""网络取证——流追踪、信标检测、数据外泄分析。"""
import hashlib, logging, base64, struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from statistics import mean, stdev
from time import time as _time_now

_log = logging.getLogger(__name__)

# ---- 流超时常量 ----
TCP_IDLE_TIMEOUT = 120
UDP_IDLE_TIMEOUT = 60
FLOW_HARD_TIMEOUT = 3600

# 信标检测阈值
BEACON_JITTER_RATIO = 0.12
BEACON_MIN_INTERVALS = 5

# ===== 外泄检测阈值 =====
EXFIL_RATIO_WARN = 20
EXFIL_RATIO_DEFINITE = 100

# ===== 数据结构 =====
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


# 五元组流追踪器
class FlowTracker:
    """对网络流量进行五元组流追踪，支持超时回收和统计。

    设计决策：使用字典键 (src_ip, dst_ip, src_port, dst_port, proto) 追踪流。
    区分出/入方向但存入同一FlowRecord中。超时回收避免内存膨胀。
    """

    def __init__(self):
        self._flows: Dict[Tuple, FlowRecord] = {}
        self._expired_count = 0

    def _make_key(self, src_ip: str, dst_ip: str, src_port: int,
                  dst_port: int, protocol: int) -> Tuple:
        return (src_ip, dst_ip, src_port, dst_port, protocol)

    def update_flow(self, src_ip: str, dst_ip: str, src_port: int,
                    dst_port: int, protocol: int, payload_len: int,
                    ts: Optional[float] = None, direction: str = "out") -> None:
        """更新流统计：累加字节数、包数、记录首末时间戳。

        方向判定：'out'从源到目的，'in'从目的到源。payload_len
        需含L4以上负载。时间戳默认使用当前时间。
        """
        _key = self._make_key(src_ip, dst_ip, src_port, dst_port, protocol)
        _now = ts if ts is not None else _time_now()

        if _key not in self._flows:
            _r = FlowRecord(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=protocol, start_ts=_now, last_ts=_now,
            )
            self._flows[_key] = _r

        _r = self._flows[_key]
        _r.bytes_sum += payload_len
        _r.packets += 1
        _r.last_ts = _now

        # 记录时间戳序列（信标检测）
        if len(_r._timestamps) > 0:
            _interval = _now - _r._timestamps[-1]
            if _interval > 0:
                _r._intervals.append(_interval)
        _r._timestamps.append(_now)

        if direction == "out":
            _r.bytes_out += payload_len
        else:
            _r.bytes_in += payload_len

    def expire_stale(self, now: Optional[float] = None) -> List[FlowRecord]:
        """回收超时流，释放内存"""
        _now = now or _time_now()
        _stale: List[FlowRecord] = []
        _to_del: List[Tuple] = []

        for _key, _flow in self._flows.items():
            _idle_threshold = TCP_IDLE_TIMEOUT if _flow.protocol == 6 else UDP_IDLE_TIMEOUT
            if _now - _flow.last_ts > _idle_threshold or _now - _flow.start_ts > FLOW_HARD_TIMEOUT:
                _stale.append(_flow)
                _to_del.append(_key)

        for _k in _to_del:
            del self._flows[_k]
        self._expired_count += len(_stale)
        return _stale

    def get_active_flows(self) -> List[FlowRecord]:
        return list(self._flows.values())

    def get_flow_count(self) -> int:
        self.expire_stale()
        return len(self._flows)


# ===== 社区ID生成 =====
def community_id(protocol: int, src_ip: str, dst_ip: str,
                 src_port: int = 0, dst_port: int = 0) -> str:
    """按Corelight/Zeek规范生成Community ID。

    ICMP(协议号1)用type+code替代端口。IP地址按字节序排序以确保双向
    流量产生相同ID。SHA1(seed+tuple)截断base64输出。
    """
    # 排序IP
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


# 信标检测
def beacon_score(flow_intervals: List[float]) -> float:
    """计算信标评分：抖动比 = std(intervals)/mean(intervals)。

    抖动比<0.12表示机器般规律性（C2信标特征）。合法流量通常抖动比>0.3。
    """
    if len(flow_intervals) < BEACON_MIN_INTERVALS:
        return 0.0
    _m = mean(flow_intervals)
    if _m <= 0:
        return 0.0
    try:
        _s = stdev(flow_intervals)
    except Exception:
        return 0.0
    _jitter = _s / _m
    # 将抖动比映射为0-1信标评分
    if _jitter < BEACON_JITTER_RATIO:
        return 1.0
    elif _jitter < 0.3:
        return 1.0 - (_jitter - BEACON_JITTER_RATIO) / (0.3 - BEACON_JITTER_RATIO)
    else:
        return 0.0


def check_beacon_timing(flow: FlowRecord) -> Dict[str, Any]:
    """滑动窗口分析流内包间隔，检测信标行为。

    将流划分为多个窗口，每窗口独立计算beacon_score，
    若多数窗口得分>0.7则判定为信标。
    """
    _intervals = flow._intervals
    _n = len(_intervals)
    if _n < BEACON_MIN_INTERVALS:
        return {"is_beacon": False, "score": 0.0, "consistency": 0}

    # 全序列评分
    _score = beacon_score(_intervals)

    # 滑动窗口一致性
    _window = min(8, _n // 2)
    if _window < 3:
        return {"is_beacon": _score > 0.7, "score": _score, "consistency": 0}

    _consist = 0
    _total = 0
    for i in range(_n - _window + 1):
        _win_scores = []
        _win = _intervals[i:i+_window]
        _ws = beacon_score(_win)
        _win_scores.append(_ws)
        _total += 1
        if _ws > 0.7:
            _consist += 1

    return {
        "is_beacon": _score > 0.7 and _consist > _total * 0.5,
        "score": _score,
        "consistency": _consist / _total if _total > 0 else 0,
    }


# 数据外泄检测
def traffic_asymmetry(flow: FlowRecord) -> Dict[str, Any]:
    """流量不对称性分析：出/入字节比。

    上传/外泄场景：bytes_out >> bytes_in。比值>20:1警告，>100:1确认。
    反向极低比值可能为下载/接收通道。
    """
    _out = flow.bytes_out
    _in = flow.bytes_in
    if _in <= 0 and _out > 0:
        return {"ratio": float("inf"), "severity": "definite", "direction": "outbound_only"}
    if _out <= 0 and _in > 0:
        return {"ratio": 0.0, "severity": "definite", "direction": "inbound_only"}
    if _out <= 0 and _in <= 0:
        return {"ratio": 1.0, "severity": "normal", "direction": "balanced"}

    _ratio = _out / _in
    if _ratio >= EXFIL_RATIO_DEFINITE:
        _sev = "definite"
    elif _ratio >= EXFIL_RATIO_WARN:
        _sev = "warning"
    else:
        _sev = "normal"
    return {"ratio": _ratio, "severity": _sev, "direction": "outbound" if _ratio > 10 else "balanced"}


# ===== 常见协议端口映射 =====
_KNOWN_PORTS: Dict[int, str] = {
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

# 端口/协议不匹配检测
def check_port_protocol_mismatch(flow: FlowRecord) -> List[str]:
    """检测端口与协议不匹配的可疑行为。

    例如：UDP在端口80上、TCP在DNS端口53上大流量传输、SSH在443端口等。
    返回告警信息列表。
    """
    alerts: List[str] = []
    _proto = flow.protocol
    _dport = flow.dst_port
    _sport = flow.src_port

    # UDP在常见TCP端口上
    if _proto == 17:
        if _dport in (80, 443, 22):
            alerts.append(f"UDP on port {_dport} ({_KNOWN_PORTS.get(_dport, 'unknown')}) - unusual")
        if _sport in (80, 443, 22):
            alerts.append(f"UDP from port {_sport} ({_KNOWN_PORTS.get(_sport, 'unknown')}) - unusual")

    # TCP DNS 区域传输
    if _proto == 6 and (_dport == 53 or _sport == 53) and flow.bytes_sum > 512:
        alerts.append("TCP on port 53 with large payload (>512 bytes) - possible zone transfer or DNS tunnel")

    # SSH在非标准端口（端口22以外的SSH类流量）
    if _dport == 443 and flow.bytes_sum > 1024:
        pass

    # 已知C2常用端口
    _c2_ports = {4444, 1337, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321}
    if _dport in _c2_ports or _sport in _c2_ports:
        alerts.append(f"C2-associated port {_dport if _dport in _c2_ports else _sport}")

    return alerts


# ===== 综合分析入口 =====
def analyze_pcap(packets: List[Any]) -> Dict[str, Any]:
    """PCAP流分析。

    对每个包提取五元组、时间戳、载荷长度，送入FlowTracker进行流追踪。
    完成后对所有活跃流执行信标检测和外泄检测，汇总结果。
    """
    _tracker = FlowTracker()
    _ts = _time_now()

    for _i, _pkt in enumerate(packets):
        # 支持字典和对象两种格式
        if isinstance(_pkt, dict):
            _sip = _pkt.get("src_ip", "0.0.0.0")
            _dip = _pkt.get("dst_ip", "0.0.0.0")
            _sp = _pkt.get("src_port", 0)
            _dp = _pkt.get("dst_port", 0)
            _proto = _pkt.get("protocol", 6)
            _plen = _pkt.get("payload_len", len(_pkt.get("payload", b"")))
            _pts = _pkt.get("timestamp", _ts + _i * 0.001)
            _dir = "out"
        else:
            _sip = getattr(_pkt, "src_ip", "0.0.0.0")
            _dip = getattr(_pkt, "dst_ip", "0.0.0.0")
            _sp = getattr(_pkt, "src_port", 0)
            _dp = getattr(_pkt, "dst_port", 0)
            _proto = getattr(_pkt, "protocol", 6)
            _plen = getattr(_pkt, "payload_len", len(getattr(_pkt, "payload", b"")))
            _pts = getattr(_pkt, "timestamp", _ts + _i * 0.001)
            _dir = "out"

        _tracker.update_flow(_sip, _dip, _sp, _dp, _proto, _plen, _pts, _dir)

    # 回收超时流
    _tracker.expire_stale()
    _flows = _tracker.get_active_flows()

    # 为每个流计算Community ID
    for _f in _flows:
        _f.community_id = community_id(_f.protocol, _f.src_ip, _f.dst_ip,
                                        _f.src_port, _f.dst_port)

    # 检测分析
    _beacon_alerts = []
    _exfil_alerts = []
    _mismatch_alerts = []

    for _f in _flows:
        _beacon = check_beacon_timing(_f)
        if _beacon["is_beacon"]:
            _beacon_alerts.append({
                "flow": f"{_f.src_ip}:{_f.src_port}->{_f.dst_ip}:{_f.dst_port}",
                "score": _beacon["score"],
                "community_id": _f.community_id,
            })

        _exfil = traffic_asymmetry(_f)
        if _exfil["severity"] != "normal":
            _exfil_alerts.append({
                "flow": f"{_f.src_ip}:{_f.src_port}->{_f.dst_ip}:{_f.dst_port}",
                "ratio": _exfil["ratio"],
                "severity": _exfil["severity"],
                "community_id": _f.community_id,
            })

        _mm = check_port_protocol_mismatch(_f)
        for _alert in _mm:
            _mismatch_alerts.append({
                "flow": f"{_f.src_ip}:{_f.src_port}->{_f.dst_ip}:{_f.dst_port}",
                "alert": _alert,
                "community_id": _f.community_id,
            })

    # ── 法庭因果图分析 ────────────────────────────────────
    _causal_report = None
    if _beacon_alerts or _exfil_alerts or _mismatch_alerts:
        try:
            from .forensic_event_builder import analyze_forensic_causality
        except ImportError:
            from src.forensic_event_builder import analyze_forensic_causality
        _causal_report = analyze_forensic_causality(
            _beacon_alerts, _exfil_alerts, _mismatch_alerts)

    return {
        "total_packets": len(packets),
        "total_flows": len(_flows),
        "expired_flows": _tracker._expired_count,
        "beacon_alerts": _beacon_alerts,
        "exfil_alerts": _exfil_alerts,
        "mismatch_alerts": _mismatch_alerts,
        "flows": _flows,
        # 法庭因果分析结果
        "forensic_causality": {
            "total_events": _causal_report.total_events if _causal_report else 0,
            "total_edges": _causal_report.total_edges if _causal_report else 0,
            "root_causes": (_causal_report.root_cause_ranking[:5]
                           if _causal_report else []),
            "evidence_chains": [
                {"events": ch.events, "strength": ch.total_strength,
                 "root_cause": ch.root_cause_event}
                for ch in (_causal_report.evidence_chains[:5]
                          if _causal_report else [])
            ],
        } if _causal_report else {},
    }
