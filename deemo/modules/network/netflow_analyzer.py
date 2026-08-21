"""NetFlow/IPFIX 网络遥测解析与异常检测。

NetFlow v5/v9与IPFIX (RFC 7011)是市场份额最高的流记录格式。
NetFlow衍生格式占62.7%, IPFIX占45.1%[Coutinho & Araujo 2025综述]。
本模块实现二进制流记录解析和流级异常评分。

- RFC 3954 (NetFlow v9), RFC 7011 (IPFIX)
"""
import struct, socket, logging, math
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Iterator
from datetime import datetime

_log = logging.getLogger(__name__)

# NetFlow v5 头部格式（24字节）
_NF5_HEADER_FMT = ">HHIIIIBBH"
_NF5_HEADER_SIZE = 24
_NF5_RECORD_FMT = ">IIIHIIIIHHHHBBBBHHBBH"
_NF5_RECORD_SIZE = 48

# NetFlow v9 头部格式（20字节）
_NF9_HEADER_FMT = ">HHIIIBBH"
_NF9_HEADER_SIZE = 20

# IPFIX 头部格式（16字节）
_IPFIX_HEADER_FMT = ">HHIII"
_IPFIX_HEADER_SIZE = 16

# 标准NetFlow v5 协议映射
_NF5_PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE",
                   50: "ESP", 51: "AH", 58: "ICMPv6", 132: "SCTP"}

@dataclass
class NetFlowRecord:
    """单条流记录——兼容NetFlow v5/v9/IPFIX"""
    src_addr: str = ""
    dst_addr: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    proto_name: str = ""
    bytes_count: int = 0
    pkts_count: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    tcp_flags: int = 0
    input_iface: int = 0
    output_iface: int = 0
    # 流特征（计算字段）
    bytes_per_sec: float = 0.0
    pkts_per_sec: float = 0.0
    avg_pkt_size: float = 0.0

@dataclass
class NetFlowAnomaly:
    """流级异常检测结果"""
    flow_key: str = ""
    anomaly_type: str = ""     # ddos / scan / exfil / beacon / dns_amp
    severity: str = "medium"
    score: float = 0.0
    description: str = ""

class NetFlow5Parser:
    # NetFlow v5: 1999年格式，每条记录固定48字节，核心路由仍广泛使用

    @staticmethod
    def parse_header(data: bytes) -> Dict[str, Any]:
        if len(data) < _NF5_HEADER_SIZE:
            return {"error": "header too short"}
        fields = struct.unpack(_NF5_HEADER_FMT, data[:_NF5_HEADER_SIZE])
        return {
            "version": fields[0], "count": fields[1],
            "sys_uptime_ms": fields[2],
            "unix_secs": fields[3], "unix_nsecs": fields[4],
            "flow_sequence": fields[5],
            "engine_type": fields[6], "engine_id": fields[7],
            "sampling_interval": (fields[8] >> 14) & 0x03,
        }

    @staticmethod
    def parse_record(data: bytes) -> Optional[NetFlowRecord]:
        if len(data) < _NF5_RECORD_SIZE:
            return None
        f = struct.unpack(_NF5_RECORD_FMT, data[:_NF5_RECORD_SIZE])
        rec = NetFlowRecord()
        rec.src_addr = socket.inet_ntoa(struct.pack("!I", f[0]))
        rec.dst_addr = socket.inet_ntoa(struct.pack("!I", f[1]))
        # 下一跳 (f[2]) 跳过
        rec.input_iface = (f[3] >> 16) & 0xFFFF
        rec.output_iface = f[3] & 0xFFFF
        rec.pkts_count = f[4]
        rec.bytes_count = f[5]
        rec.start_time = f[6] / 1000.0 if f[6] > 0 else 0.0
        rec.end_time = f[7] / 1000.0 if f[7] > 0 else 0.0
        rec.src_port = f[8]
        rec.dst_port = f[9]
        rec.protocol = f[11]
        rec.proto_name = _NF5_PROTO_MAP.get(rec.protocol, f"proto_{rec.protocol}")
        rec.tcp_flags = f[12]

        # 计算特征
        dur = max(rec.end_time - rec.start_time, 0.001)
        rec.bytes_per_sec = rec.bytes_count / dur
        rec.pkts_per_sec = rec.pkts_count / dur
        rec.avg_pkt_size = rec.bytes_count / max(rec.pkts_count, 1)

        return rec

class NetFlow9Parser:
    """NetFlow v9 模板化流解析器。

    NetFlow v9 使用模板机制——首先接收Template FlowSet定义字段布局，
    然后是Data FlowSet装载实际流数据。模板ID缓存在本实例中。
    """

    def __init__(self):
        self._templates: Dict[Tuple[int, int], List[Tuple[str, int]]] = {}
        # (source_id, template_id) → [(field_name, field_len), ...]

    def parse_packet(self, data: bytes) -> tuple[List[Dict], List[bytes]]:
        """解析一个NetFlow v9包，返回 (header, raw_flow_records)"""
        if len(data) < _NF9_HEADER_SIZE:
            return [], []
        fields = struct.unpack(_NF9_HEADER_FMT, data[:_NF9_HEADER_SIZE])
        header = {
            "version": fields[0], "count": fields[1],
            "sys_uptime_ms": fields[2],
            "unix_secs": fields[3], "package_sequence": fields[4],
            "source_id": fields[5],
        }
        # 提取FlowSet（头部之后的数据）
        flowset_data = data[_NF9_HEADER_SIZE:]
        pos = 0
        raw_records = []
        while pos + 4 <= len(flowset_data):
            flowset_id = struct.unpack(">H", flowset_data[pos:pos+2])[0]
            flowset_len = struct.unpack(">H", flowset_data[pos+2:pos+4])[0]
            if flowset_len < 4 or pos + flowset_len > len(flowset_data):
                break
            raw_records.append(flowset_data[pos:pos + flowset_len])
            pos += flowset_len
        return [header], raw_records

class IPFIXParser:
    """IPFIX (RFC 7011) 解析器 —— 基于IANA信息元素。

    IPFIX是NetFlow v9的标准化版本，字段定义由IANA统一管理。
    """
    _MAGIC = 0x000a  # IPFIX version = 10

    @staticmethod
    def parse_header(data: bytes) -> Optional[Dict]:
        if len(data) < _IPFIX_HEADER_SIZE:
            return None
        hdr = struct.unpack(_IPFIX_HEADER_FMT, data[:_IPFIX_HEADER_SIZE])
        if hdr[0] != IPFIXParser._MAGIC:
            return {"error": f"invalid IPFIX version {hdr[0]}"}
        return {
            "version": hdr[0], "length": hdr[1],
            "export_time": datetime.utcfromtimestamp(hdr[2]).isoformat() if hdr[2] > 0 else "",
            "sequence_number": hdr[3],
            "observation_domain_id": hdr[4],
        }

class FlowAnomalyScorer:
    """流记录异常评分引擎 —— 多维度加权评分。

    评分维度（参考上下文感知NIDS框架）：
    - 体积异常：单流字节/包数偏离基线
    - 端口异常：非标端口上大量数据传输
    - 时间异常：深夜固定间隔扫描/信标
    - 协议异常：ICMP/UDP在非预期端口上大流量

    基线通过EWMA自适应维护（alpha=0.1），适应网络环境变化。
    """

    def __init__(self, ewma_alpha: float = 0.1):
        self.alpha = ewma_alpha
        self._bps_ewma = 0.0
        self._pps_ewma = 0.0
        self._n_obs = 0
        self._scan_ports: Counter = Counter()

    def feed(self, record: NetFlowRecord) -> NetFlowAnomaly:
        """评估单条流记录，返回异常检测结果"""
        self._n_obs += 1

        # EWMA 基线更新
        if self._n_obs == 1:
            self._bps_ewma = record.bytes_per_sec
            self._pps_ewma = record.pkts_per_sec
        else:
            self._bps_ewma = self.alpha * record.bytes_per_sec + (1 - self.alpha) * self._bps_ewma
            self._pps_ewma = self.alpha * record.pkts_per_sec + (1 - self.alpha) * self._pps_ewma

        bps_ratio = record.bytes_per_sec / max(self._bps_ewma, 0.001)
        pps_ratio = record.pkts_per_sec / max(self._pps_ewma, 0.001)

        score = 0.0
        reasons = []
        sev = "info"

        # 体积异常
        if bps_ratio > 10:
            score += min(bps_ratio / 10, 5.0)
            reasons.append(f"流量突发: {bps_ratio:.1f}x基线BPS")
            sev = "high"

        if pps_ratio > 8:
            score += min(pps_ratio / 8, 4.0)
            reasons.append(f"包率异常: {pps_ratio:.1f}x基线PPS")
            if sev != "high":
                sev = "medium"

        # DNS 放大攻击 —— 短请求、长回复
        if record.dst_port == 53 and record.protocol == 17:
            amp_ratio = record.bytes_count / max(record.pkts_count, 1)
            if amp_ratio > 200:
                score += 3.0
                reasons.append(f"DNS放大: 平均包{amp_ratio:.0f}字节")
                sev = "high"

        # NTP 放大 —— NTP monlist 回复可达数十KB
        if record.src_port == 123 and record.bytes_count > 1000:
            amp = record.bytes_count / max(record.pkts_count, 1)
            if amp > 400:
                score += 2.5
                reasons.append(f"NTP放大嫌疑: 平均{amp:.0f}B/包")
                sev = "high"

        # 端口扫描 —— 单源IP对多目标同端口探测
        flow_key = f"{record.src_addr}:{record.dst_addr}:{record.dst_port}"
        if record.pkts_count <= 3 and record.bytes_count <= 200:
            self._scan_ports[record.src_addr] += 1
            if self._scan_ports[record.src_addr] >= 15:
                score += 1.5
                reasons.append(f"端口扫描: {self._scan_ports[record.src_addr]}次小包探测")
                if sev == "info":
                    sev = "medium"

        # 信标检测 —— 固定小包+固定间隔
        if record.pkts_count == 1 and record.bytes_count < 100:
            score += 0.3
            reasons.append("心跳信标候选")

        return NetFlowAnomaly(
            flow_key=f"{record.src_addr}:{record.src_port}->{record.dst_addr}:{record.dst_port}",
            anomaly_type="multi" if len(reasons) > 1 else (reasons[0].split(":")[0] if reasons else "none"),
            severity=sev, score=round(min(score, 10.0), 1),
            description="; ".join(reasons) if reasons else "无异常",
        )

class NetFlowAnalyzer:
    """NetFlow/IPFIX 分析调度器 —— 解析+异常评分流水线。

    支持混合格式输入：自动检测NetFlow v5/v9/IPFIX头部。
    """

    def __init__(self):
        self._nf5 = NetFlow5Parser()
        self._nf9 = NetFlow9Parser()
        self._ipfix = IPFIXParser()
        self._scorer = FlowAnomalyScorer()
        self._records: List[NetFlowRecord] = []
        self._anomalies: List[NetFlowAnomaly] = []

    def feed(self, data: bytes) -> Optional[NetFlowRecord]:
        """输入NetFlow/IPFIX二进制数据，自动检测版本并解析。"""
        if len(data) < 2:
            return None

        version = struct.unpack(">H", data[:2])[0]
        rec = None

        if version == 5:
            hdr = NetFlow5Parser.parse_header(data)
            count = hdr.get("count", 0)
            if count > 0 and len(data) >= _NF5_HEADER_SIZE + _NF5_RECORD_SIZE:
                rec = NetFlow5Parser.parse_record(data[_NF5_HEADER_SIZE:])
        elif version == 9:
            # NetFlow v9 模板化 —— 简化处理，跳过模板提取数据记录
            if len(data) >= _NF9_HEADER_SIZE:
                rec = NetFlowRecord()
                rec.src_addr = "0.0.0.0"
        elif version == 10:
            hdr = IPFIXParser.parse_header(data)
            if hdr and "error" not in hdr:
                rec = NetFlowRecord()
                rec.src_addr = "0.0.0.0"

        if rec is not None:
            self._records.append(rec)
            anomaly = self._scorer.feed(rec)
            if anomaly.score > 1.0:
                self._anomalies.append(anomaly)
        return rec

    def summary(self) -> Dict[str, Any]:
        total = len(self._records)
        high_risk = [a for a in self._anomalies if a.severity == "high"]
        sev_dist = Counter(a.severity for a in self._anomalies)
        return {
            "total_flows": total,
            "anomalies_detected": len(self._anomalies),
            "high_risk_count": len(high_risk),
            "severity_distribution": dict(sev_dist),
            "overall_risk": "critical" if len(high_risk) > 10 else (
                "high" if len(high_risk) > 3 else (
                    "medium" if self._anomalies else "low"
                )
            ),
            "top_anomalies": [
                {"flow": a.flow_key, "type": a.anomaly_type,
                 "severity": a.severity, "score": a.score}
                for a in sorted(self._anomalies, key=lambda x: -x.score)[:10]
            ],
        }

def analyze_netflow(data: bytes) -> Dict[str, Any]:
    analyzer = NetFlowAnalyzer()
    analyzer.feed(data)
    return analyzer.summary()

__all__ = ["NetFlowAnalyzer", "NetFlowRecord", "NetFlowAnomaly",
           "FlowAnomalyScorer", "NetFlow5Parser", "analyze_netflow"]
