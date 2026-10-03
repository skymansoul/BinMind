# ICS/SCADA 协议分析器 — Modbus, DNP3, IEC 60870-5-104, BACnet, S7comm
# 从网络流量中识别工业协议并提取关键操作
# Wireshark ICS dissectors, NIST SP 800-82 r3, MITRE ATT&CK ICS matrix
import struct, math
import os
from enum import Enum
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict


# ---- 旧版二进制分析 API 的枚举与数据结构 ----
# 面向二进制样本的协议识别：枚举协议族，结果以 ICSAnalysisResult 汇总。

class ICSProtocol(Enum):
    MODBUS_TCP = "modbus_tcp"
    DNP3 = "dnp3"
    IEC_61850 = "iec_61850"
    PROFINET = "profinet"
    ETHERNET_IP = "ethernet_ip"
    S7COMM = "s7comm"
    BACNET = "bacnet"
    IEC_104 = "iec_104"


class VulnerabilityType(Enum):
    LENGTH_NOT_CHECKED = "length_not_checked"
    INDEX_OUT_OF_BOUNDS = "index_out_of_bounds"
    BUFFER_OVERFLOW = "buffer_overflow"
    PACKET_STRUCTURE = "packet_structure"


@dataclass
class ICSFunction:
    name: str
    protocol: ICSProtocol = None
    address: int = 0
    risk_score: int = 0


@dataclass
class MalformedPacket:
    protocol: ICSProtocol
    mutation_type: str = ""
    payload: bytes = b""


@dataclass
class ICSAnalysisResult:
    binary_path: str = ""
    detected_protocols: List[ICSProtocol] = field(default_factory=list)
    identified_functions: List[ICSFunction] = field(default_factory=list)
    detected_vulnerabilities: List[dict] = field(default_factory=list)
    generated_packets: List[MalformedPacket] = field(default_factory=list)
    summary: str = ""
    analysis_time: float = 0.0


@dataclass
class ICSProtocolFeature:
    protocol: ICSProtocol
    default_port: int
    description: str = ""


class ICSProtocolFeatureDatabase:
    """协议特征库 — 协议默认端口与描述。"""

    def __init__(self):
        self.features: Dict[ICSProtocol, ICSProtocolFeature] = {
            ICSProtocol.MODBUS_TCP: ICSProtocolFeature(ICSProtocol.MODBUS_TCP, 502, "Modbus TCP"),
            ICSProtocol.DNP3: ICSProtocolFeature(ICSProtocol.DNP3, 20000, "DNP3"),
            ICSProtocol.IEC_61850: ICSProtocolFeature(ICSProtocol.IEC_61850, 102, "IEC 61850 MMS"),
            ICSProtocol.PROFINET: ICSProtocolFeature(ICSProtocol.PROFINET, 34962, "PROFINET DCP"),
            ICSProtocol.ETHERNET_IP: ICSProtocolFeature(ICSProtocol.ETHERNET_IP, 44818, "EtherNet/IP"),
        }

    def get_feature(self, protocol: ICSProtocol) -> Optional[ICSProtocolFeature]:
        return self.features.get(protocol)

    def get_all_features(self) -> Dict[ICSProtocol, ICSProtocolFeature]:
        return dict(self.features)


@dataclass
class ICSFrame:
    protocol: str            # modbus / dnp3 / iec104 / bacnet / s7comm
    function_code: int = 0
    data_length: int = 0
    src: int = 0
    dst: int = 0
    payload: bytes = b''
    is_write: bool = False   # 写操作（可能改变物理过程）
    risk_score: int = 0      # 0-100，高危操作打分高
    # MITRE 映射与会话跟踪
    mitre_technique: str = ""
    timestamp: float = 0.0


# MITRE ATT&CK for ICS 技术映射
# 映射 (protocol, function_code_range) → technique ID
_MITRE_ICS_MAP = {
    ("modbus", (5,6,15,16)):   "T0836",  # Modify Parameter
    ("modbus", (8,)):           "T0842",  # Network Sniffing via diag
    ("dnp3", (4,5,6)):          "T0836",  # Direct/Select/Operate
    ("iec104", tuple(range(45,65))): "T0836",  # C_xx commands
    ("bacnet", (14,15)):        "T0836",  # WritePropertyMultiple
    ("s7comm", (0xF0,)):        "T0855",  # Unauthorized Command Message
}

def _map_mitre(proto: str, fc: int) -> str:
    for (p, fcs), tid in _MITRE_ICS_MAP.items():
        if p == proto and (fc in fcs if isinstance(fcs, tuple) else False):
            return tid
    return ""


# Modbus
_MODBUS_WRITE_FC = {5, 6, 15, 16}   # write single/multiple coils/registers
_MODBUS_CRITICAL_FC = {5, 6, 8, 15, 16}  # + diagnostics (8)

def _parse_modbus(data: bytes) -> Optional[ICSFrame]:
    """Modbus TCP/RTU 帧解析。"""
    if len(data) < 8:
        return None
    tcp = False
    if len(data) >= 7 and data[2:4] == b'\x00\x00':  # Modbus TCP header
        tcp = True
        tid = struct.unpack(">H", data[:2])[0]
        pid = struct.unpack(">H", data[2:4])[0]
        length = struct.unpack(">H", data[4:6])[0]
        uid = data[6]
        if len(data) < 7 + length:
            return None
        fc = data[7]
        payload = data[8:7 + length]
    else:  # Modbus RTU (简化：假设地址在第一字节)
        uid = data[0]
        fc = data[1]
        payload = data[2:-2]  # 去掉 CRC16
        tid = 0
        length = len(payload) + 2

    risk = 0
    if fc in _MODBUS_WRITE_FC:
        risk = 40
    if fc == 8:  # diagnostics — 可能为侦察
        risk = 25
    if fc in (5, 6, 15, 16):
        risk = 55  # write operations

    return ICSFrame(
        protocol="modbus", function_code=fc,
        data_length=length, src=uid, dst=0,
        payload=payload, is_write=fc in _MODBUS_WRITE_FC,
        risk_score=risk, mitre_technique=_map_mitre("modbus", fc),
    )


# DNP3
_DNP3_START_BYTES = b'\x05\x64'
_DNP3_CONFIRM = 0x00; _DNP3_READ = 0x01; _DNP3_WRITE = 0x02
_DNP3_SELECT = 0x03; _DNP3_OPERATE = 0x04
_DNP3_DIRECT_OPERATE = 0x05; _DNP3_DIRECT_OPERATE_NR = 0x06

_DNP3_FC_RISK = {
    _DNP3_DIRECT_OPERATE: 65, _DNP3_DIRECT_OPERATE_NR: 65,
    _DNP3_OPERATE: 50, _DNP3_SELECT: 15, _DNP3_WRITE: 40,
}

def _parse_dnp3(data: bytes) -> Optional[ICSFrame]:
    """DNP3 帧解析 —— 只处理 link layer + transport 头。"""
    if len(data) < 10 or data[:2] != _DNP3_START_BYTES:
        return None
    length = data[2]
    ctrl = data[3]
    dst = struct.unpack("<H", data[4:6])[0]
    src = struct.unpack("<H", data[6:8])[0]
    # CRC 位于头部与负载之间，此处简化跳过
    # 查找 transport header（TH字节紧随CRC对之后）
    payload_start = 10  # 8 header + 2 CRC

    fc = 0
    if len(data) > payload_start + 1:
        th = data[payload_start]  # transport header
        fc = th & 0x3F           # FIN+FIR+SEQ bits masked → payload follows
        if len(data) > payload_start + 2:
            fc = data[payload_start + 2]  # application function code

    return ICSFrame(
        protocol="dnp3", function_code=fc,
        data_length=length, src=src, dst=dst,
        payload=data[payload_start:],
        is_write=fc in (_DNP3_DIRECT_OPERATE, _DNP3_DIRECT_OPERATE_NR, _DNP3_OPERATE),
        risk_score=_DNP3_FC_RISK.get(fc, 5),
        mitre_technique=_map_mitre("dnp3", fc),
    )


# IEC 60870-5-104
_IEC104_START = 0x68

def _parse_iec104(data: bytes) -> Optional[ICSFrame]:
    """IEC 104 APCI 帧解析。"""
    if len(data) < 6 or data[0] != _IEC104_START:
        return None
    length = data[1]
    if length < 4:
        return None
    ctrl = data[2:6]
    fc = ctrl[0] & 0x03  # I/S/U format type
    tx_num = struct.unpack("<H", ctrl[:2])[0] >> 1
    rx_num = struct.unpack("<H", ctrl[2:4])[0] >> 1

    payload = data[6:6 + length - 4] if len(data) >= 6 + length else b''
    asdu_type = payload[0] if len(payload) > 0 else 0

    risk = 0
    if asdu_type in (45, 46, 47):    # C_SC_NA_1, C_DC_NA_1, C_RC_NA_1
        risk = 60
    elif asdu_type in (48, 49, 50):  # C_SE_NA_1, C_SE_NB_1, C_SE_NC_1 — setpoint
        risk = 65

    return ICSFrame(
        protocol="iec104", function_code=asdu_type,
        data_length=length, src=tx_num, dst=rx_num,
        payload=payload, is_write=asdu_type >= 45 and asdu_type <= 64,
        risk_score=risk, mitre_technique=_map_mitre("iec104", asdu_type),
    )


# BACnet/IP
_BACNET_BVLC = 0x81

def _parse_bacnet(data: bytes) -> Optional[ICSFrame]:
    """BACnet/IP 帧解析。"""
    if len(data) < 8 or data[0] != _BACNET_BVLC:
        return None
    bvlc_func = data[1]
    bvlc_length = struct.unpack(">H", data[2:4])[0]

    # NPDU (Network Protocol Data Unit)
    if len(data) < 7:
        return None
    npci_version = data[4]
    npci_ctrl = data[5]

    # APDU 起始于 NPDU 之后
    apdu_start = 6
    if len(data) >= apdu_start + 2:
        apdu_type = data[apdu_start] >> 4  # PDU type in top 4 bits
        fc = data[apdu_start + 1] if len(data) > apdu_start + 1 else 0
        service_choice = fc
        is_write = apdu_type in (2, 3, 14, 15)  # WriteProperty, WritePropertyMultiple etc.
        risk = 55 if is_write else 10
    else:
        fc = apdu_start; service_choice = 0; is_write = False; risk = 5

    return ICSFrame(
        protocol="bacnet", function_code=service_choice,
        data_length=bvlc_length, src=0, dst=0,
        payload=data[apdu_start:], is_write=is_write,
        risk_score=risk, mitre_technique=_map_mitre("bacnet", fc),
    )


# S7comm (Siemens)
# TPKT header(4) + COTP header(3) + S7 header(4) 至少
_S7COMM_MIN_LEN = 4 + 3 + 4  # 11 bytes minimum
_S7COMM_WRITE_CODES = frozenset({0x05, 0x0F, 0x10})

def _parse_s7comm(data: bytes) -> Optional[ICSFrame]:
    """S7comm/TPKT 帧解析 — 检测 PLC 写入/启停。

    TPKT: [ver=3, rsv=0, len_be16]
    COTP: [len=2, pdu_type=0xF0]
    S7 header follows.
    """
    if len(data) < _S7COMM_MIN_LEN:
        return None
    # TPKT version 必须为 3 (S7comm)
    if data[0] != 3:
        return None
    tpkt_len = struct.unpack(">H", data[2:4])[0]
    if tpkt_len < _S7COMM_MIN_LEN or tpkt_len > len(data):
        return None

    # COTP 检查: data[4] = length, data[5] = PDU type (0xF0=Data Transfer)
    cotp_len = data[4]
    if data[4] < 2 or data[5] != 0xF0:
        return None  # 非有效 S7comm 数据传送 TPDU

    s7_start = 4 + 1 + cotp_len  # TPKT header(4) + COTP len byte + COTP data
    if len(data) < s7_start + 4:
        return None
    # S7 header: proto_id(1) msg_type(1) reserved(2)
    if data[s7_start] != 0x32:  # S7 protocol ID
        return None
    msg_type = data[s7_start + 1]
    fc = data[s7_start + 3] if len(data) > s7_start + 3 else 0
    is_write = fc in _S7COMM_WRITE_CODES

    risk = 0
    if fc == 0x05: risk = 75   # PLC control (stop/start)
    elif fc == 0x0F: risk = 55 # system status block
    elif fc == 0x10: risk = 55 # PLC password
    elif is_write: risk = 40

    return ICSFrame(
        protocol="s7comm", function_code=fc,
        data_length=tpkt_len, src=0, dst=0,
        payload=data[s7_start:tpkt_len], is_write=is_write,
        risk_score=risk, mitre_technique=_map_mitre("s7comm", fc),
    )


# 统一分析器

class ICSProtocolAnalyzer:
    """工业协议分析器 — 自动检测协议类型并提取关键操作。

    binary_path 提供时读取二进制样本，供协议字符串/模式检测使用。
    """

    def __init__(self, binary_path=None):
        self._parsers = [
            _parse_modbus, _parse_dnp3, _parse_iec104, _parse_bacnet,
            _parse_s7comm,
        ]
        self.frames: List[ICSFrame] = []
        self._stats: Dict[str, int] = {}
        # 每协议会话跟踪用于异常检测
        self._proto_risk_sessions: Dict[str, List[float]] = defaultdict(list)
        self.binary_path = binary_path
        self.binary_data = b""
        if binary_path and os.path.isfile(binary_path):
            with open(binary_path, "rb") as _fh:
                self.binary_data = _fh.read()

    # ---- 旧版二进制分析 API ----
    _PROTOCOL_STRINGS = {
        ICSProtocol.MODBUS_TCP: (b"modbus",),
        ICSProtocol.DNP3: (b"dnp3",),
        ICSProtocol.IEC_61850: (b"61850", b"mms"),
        ICSProtocol.PROFINET: (b"profinet", b"pnio"),
        ICSProtocol.ETHERNET_IP: (b"ethernet_ip", b"enip"),
    }

    _PROTOCOL_PATTERNS = {
        ICSProtocol.DNP3: (b"\x05\x64",),
        ICSProtocol.MODBUS_TCP: (b"\x00\x00\x00\x00\x00\x06",),
    }

    def _find_protocol_strings(self) -> List[ICSProtocol]:
        found = []
        data = self.binary_data or b""
        for proto, needles in self._PROTOCOL_STRINGS.items():
            if any(n in data for n in needles):
                found.append(proto)
        return found

    def _find_protocol_patterns(self) -> Dict[ICSProtocol, int]:
        counts: Dict[ICSProtocol, int] = {}
        data = self.binary_data or b""
        for proto, needles in self._PROTOCOL_PATTERNS.items():
            cnt = sum(data.count(n) for n in needles)
            if cnt:
                counts[proto] = cnt
        return counts

    def detect_protocols(self) -> List[ICSProtocol]:
        detected = self._find_protocol_strings()
        detected.extend(self._find_protocol_patterns())
        # 保序去重
        return list(dict.fromkeys(detected))

    def identify_ics_functions(self) -> List[ICSFunction]:
        """在二进制中定位协议处理函数 —— 以协议特征串出现位置为锚点。

        对每个检测到的协议，在当前已识别的协议处理字节窗口内查找
        特征串，并向前回溯常见的函数序言(push rbp; mov rbp,rsp)以
        确定函数真实起始地址；找不到序言则以特征串偏移作为候选。
        """
        funcs: List[ICSFunction] = []
        data = self.binary_data or b""
        _PROLOGUE = b"\x55\x48\x89\xe5"
        seen: set = set()
        for proto, needles in self._PROTOCOL_STRINGS.items():
            for needle in needles:
                start = 0
                while True:
                    idx = data.find(needle, start)
                    if idx < 0:
                        break
                    probe = max(0, idx - 256)
                    func_start = data.rfind(_PROLOGUE, probe, idx)
                    if func_start < 0:
                        func_start = idx
                    if func_start not in seen:
                        seen.add(func_start)
                        funcs.append(ICSFunction(
                            name="%s_handler_0x%x" % (proto.name.lower(), func_start),
                            protocol=proto,
                            address=func_start,
                            risk_score=40 if proto == ICSProtocol.MODBUS_TCP else 25,
                        ))
                    start = idx + 1
        funcs.sort(key=lambda f: f.address)
        return funcs

    def analyze_vulnerabilities(self) -> List[dict]:
        """基于函数锚点做漏洞启发式评估 —— 粗略指令流特征检查。

        轻量级启发式，不依赖完整反汇编：在每个候选函数入口后取一小段
        指令窗口，若出现"长度加载后未做边界比较即调用"的特征(缺少
        cmp/test 类比较指令但存在靠近内存访问的调用)，标记为长度未
        校验/越界风险。
        """
        vulnerabilities: List[dict] = []
        data = self.binary_data or b""
        for func in self.identify_ics_functions():
            end = min(func.address + 128, len(data))
            window = data[func.address:end]
            if not window:
                continue
            # 常见边界比较指令前缀
            has_bound_cmp = any(
                byte in window for byte in (b"\x3b", b"\x39", b"\x83\xf8", b"\x81\xf8")
            )
            has_unsafe_call = b"\xe8" in window  # call rel32
            if not has_bound_cmp and has_unsafe_call:
                vtype = VulnerabilityType.LENGTH_NOT_CHECKED
                vulnerabilities.append({
                    "function_name": func.name,
                    "function_address": hex(func.address),
                    "protocol": func.protocol.value,
                    "vulnerability_type": vtype.value,
                    "description": self._get_vulnerability_description(vtype),
                    "severity": self._get_vulnerability_severity(vtype),
                    "exploit_difficulty": self._get_exploit_difficulty(vtype),
                })
        return vulnerabilities

    def generate_malformed_packets(self, protocol: ICSProtocol,
                                   count: int = 5) -> List[MalformedPacket]:
        _mutation_types = ["length_truncation", "crc_corruption", "function_code_flip"]
        packets = []
        for i in range(count):
            packets.append(MalformedPacket(
                protocol=protocol,
                mutation_type=_mutation_types[i % len(_mutation_types)],
                payload=b"",
            ))
        return packets

    def analyze(self) -> ICSAnalysisResult:
        protocols = self.detect_protocols()
        functions = self.identify_ics_functions()
        vulns = self.analyze_vulnerabilities()
        return ICSAnalysisResult(
            binary_path=self.binary_path or "",
            detected_protocols=protocols,
            identified_functions=functions,
            detected_vulnerabilities=vulns,
            generated_packets=[],
            summary="检测到 %d 种 ICS 协议" % len(protocols),
            analysis_time=0.0,
        )

    def _get_vulnerability_description(self, vuln_type: VulnerabilityType) -> str:
        return {
            VulnerabilityType.LENGTH_NOT_CHECKED: "长度字段未校验，可导致越界读取",
            VulnerabilityType.INDEX_OUT_OF_BOUNDS: "索引越界访问",
            VulnerabilityType.BUFFER_OVERFLOW: "缓冲区溢出",
            VulnerabilityType.PACKET_STRUCTURE: "报文结构异常",
        }.get(vuln_type, "未知漏洞类型")

    def _get_vulnerability_severity(self, vuln_type: VulnerabilityType) -> str:
        return {
            VulnerabilityType.BUFFER_OVERFLOW: "critical",
            VulnerabilityType.INDEX_OUT_OF_BOUNDS: "high",
            VulnerabilityType.LENGTH_NOT_CHECKED: "medium",
        }.get(vuln_type, "medium")

    def _get_exploit_difficulty(self, vuln_type: VulnerabilityType) -> str:
        return {
            VulnerabilityType.BUFFER_OVERFLOW: "low",
            VulnerabilityType.INDEX_OUT_OF_BOUNDS: "medium",
            VulnerabilityType.LENGTH_NOT_CHECKED: "high",
        }.get(vuln_type, "medium")

    def feed(self, data: bytes) -> Optional[ICSFrame]:
        """输入一段原始数据，自动检测并解析。返回解析结果或 None。"""
        for parser in self._parsers:
            frame = parser(data)
            if frame is not None:
                self.frames.append(frame)
                self._stats[frame.protocol] = self._stats.get(frame.protocol, 0) + 1
                # 追踪风险轨迹用于异常检测
                if frame.risk_score > 0:
                    self._proto_risk_sessions[frame.protocol].append(frame.risk_score)
                return frame
        return None

    def analyze_session(self, frames: List[bytes]) -> Dict:
        """批量分析会话，返回风险评估报告。"""
        results = []
        for raw in frames:
            f = self.feed(raw)
            if f:
                results.append(f)

        write_ops = [f for f in results if f.is_write]
        high_risk = [f for f in results if f.risk_score >= 50]

        # 风险升级检测: 近期风险分的指数移动平均
        escalation_warning = self._detect_escalation()

        # MITRE 技术摘要
        mitre_techs = set(f.mitre_technique for f in results if f.mitre_technique)

        return {
            "total_frames": len(results),
            "protocols": dict(self._stats),
            "write_operations": len(write_ops),
            "high_risk_operations": len(high_risk),
            "risk_assessment": "HIGH" if len(high_risk) > 5 else
                               "MEDIUM" if len(write_ops) > 3 else "LOW",
            "top_risks": sorted(high_risk, key=lambda f: -f.risk_score)[:5],
            "mitre_techniques": sorted(mitre_techs) if mitre_techs else [],
            "escalation_detected": escalation_warning,
        }

    def _detect_escalation(self) -> bool:
        """风险评分趋势上升检测——EWMA与阈值比较。

        若最近5帧EMA风险分比前5帧高出2倍，可能表示攻击者逐步提权。
        """
        all_risks = [f.risk_score for f in self.frames[-20:] if f.risk_score > 0]
        if len(all_risks) < 10:
            return False
        alpha = 0.3
        first_half = all_risks[:len(all_risks)//2]
        second_half = all_risks[len(all_risks)//2:]

        def _ewma(seq):
            ema = seq[0]
            for v in seq[1:]:
                ema = alpha * v + (1 - alpha) * ema
            return ema

        return _ewma(second_half) > _ewma(first_half) * 2.0

    def find_critical_commands(self) -> List[ICSFrame]:
        """返回所有风险评分 >= 50 的操作（关闭/重启/写入关键寄存器等）。"""
        return [f for f in self.frames if f.risk_score >= 50]


def analyze_ics_protocols(binary_path: str) -> ICSAnalysisResult:
    """对二进制样本执行 ICS 协议识别，返回分析结果。"""
    analyzer = ICSProtocolAnalyzer(binary_path)
    return analyzer.analyze()


def format_ics_report(result: ICSAnalysisResult) -> str:
    """将 ICS 分析结果格式化为文本报告。"""
    lines = [
        "ICSprotocolanalysis report",
        "binary_path: %s" % result.binary_path,
        "protocols: %s" % ", ".join(p.value for p in result.detected_protocols),
        "summary: %s" % result.summary,
    ]
    return "\n".join(lines)


def export_ics_json(result: ICSAnalysisResult) -> str:
    """将 ICS 分析结果序列化为 JSON 字符串。"""
    import json
    return json.dumps({
        "binary_path": result.binary_path,
        "protocols": [p.value for p in result.detected_protocols],
        "summary": result.summary,
    }, ensure_ascii=False)
