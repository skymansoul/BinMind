# 2026-07-23
# ICS/SCADA protocol analyzer — Modbus, DNP3, IEC 60870-5-104, BACnet, S7comm
# 从网络流量中识别工业协议并提取关键操作
# 参考：Wireshark ICS dissectors, NIST SP 800-82 r3, MITRE ATT&CK ICS matrix
import struct, math
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict


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
    # new fields for MITRE mapping & session tracking
    mitre_technique: str = ""
    timestamp: float = 0.0


# ---- MITRE ATT&CK for ICS technique mapping ----
# maps (protocol, function_code_range) -> technique ID
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


# ---- Modbus ----
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
    if fc == 8:  # diagnostics — could be recon
        risk = 25
    if fc in (5, 6, 15, 16):
        risk = 55  # write operations

    return ICSFrame(
        protocol="modbus", function_code=fc,
        data_length=length, src=uid, dst=0,
        payload=payload, is_write=fc in _MODBUS_WRITE_FC,
        risk_score=risk, mitre_technique=_map_mitre("modbus", fc),
    )


# ---- DNP3 ----
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
    # CRC between header and payload skipped for simplicity
    # Find transport header (starts with TH byte after CRC pair)
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


# ---- IEC 60870-5-104 ----
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


# ---- BACnet/IP ----
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

    # APDU starts after NPDU
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


# ---- S7comm (Siemens) ----
# TPKT header(4) + COTP header(3) + S7 header(4) minimum
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
    # TPKT version must be 3 for S7comm
    if data[0] != 3:
        return None
    tpkt_len = struct.unpack(">H", data[2:4])[0]
    if tpkt_len < _S7COMM_MIN_LEN or tpkt_len > len(data):
        return None

    # COTP check: data[4] = length, data[5] = PDU type (0xF0=Data Transfer)
    cotp_len = data[4]
    if data[4] < 2 or data[5] != 0xF0:
        return None  # not a valid S7comm data transfer TPDU

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


# ---- Unified analyzer ----

class ICSProtocolAnalyzer:
    """工业协议分析器 — 自动检测协议类型并提取关键操作。"""

    def __init__(self):
        self._parsers = [
            _parse_modbus, _parse_dnp3, _parse_iec104, _parse_bacnet,
            _parse_s7comm,
        ]
        self.frames: List[ICSFrame] = []
        self._stats: Dict[str, int] = {}
        # per-protocol session tracking for anomaly detection
        self._proto_risk_sessions: Dict[str, List[float]] = defaultdict(list)

    def feed(self, data: bytes) -> Optional[ICSFrame]:
        """输入一段原始数据，自动检测并解析。返回解析结果或 None。"""
        for parser in self._parsers:
            frame = parser(data)
            if frame is not None:
                self.frames.append(frame)
                self._stats[frame.protocol] = self._stats.get(frame.protocol, 0) + 1
                # track risk trajectory for anomaly detection
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

        # detect risk escalation: exponential moving average of recent risk scores
        escalation_warning = self._detect_escalation()

        # MITRE technique summary
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
        """检测风险评分趋势上升——使用EWMA与简单阈值。

        若最近5帧的EMA风险分比前5帧高出2倍，可能表示攻击者逐步提权。
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
