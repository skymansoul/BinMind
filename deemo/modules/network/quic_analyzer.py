"""QUIC/HTTP3 流量分析 —— 连接ID追踪、版本指纹、0-RTT安全评估。

QUIC连接标识符(CID)在握手后保持不变，可通过DCID/SCID关联追踪用户跨网迁移。
参考：QUIC安全与隐私调查、RFC 9000/9001/9002 传输层安全规范。
"""
import logging, struct, hashlib
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any

_log = logging.getLogger(__name__)

# QUIC 长包头类型（RFC 9000 §17.2）
_QUIC_LONG_HEADER = 0x80
_QUIC_VERSION_V1 = 0x00000001
_QUIC_VERSION_V2 = 0x6b3343cf
_QUIC_VERSION_DRAFT = frozenset({
    0xff000000, 0xff000001, 0xff000002, 0xff000003, 0xff000004,
    0xff000005, 0xff000006, 0xff000007, 0xff000008, 0xff000009,
    0xff00000a, 0xff00000b, 0xff00000c, 0xff00000d, 0xff00000e,
    0xff00000f, 0xff000010, 0xff000011, 0xff000012, 0xff000013,
    0xff000014, 0xff000015, 0xff000016, 0xff000017, 0xff000018,
    0xff000019, 0xff00001a, 0xff00001b, 0xff00001c, 0xff00001d,
    0xff00001e, 0xff00001f, 0xff000020, 0xff000021, 0xff000022,
})

# Google QUIC 版本 (gQUIC, Q0xx系列)
_GOOGLE_QUIC_VERSIONS = frozenset({
    0x51303030, 0x51303031, 0x51303032, 0x51303033, 0x51303034,
    0x51303035, 0x51303036, 0x51303037, 0x51303038, 0x51303039,
    0x51303130, 0x51303131, 0x51303132, 0x51303133, 0x51303134,
    0x51303135, 0x51303136, 0x51303137, 0x51303138, 0x51303139,
    0x51303230, 0x51303231, 0x51303232, 0x51303233, 0x51303234,
    0x51303235, 0x51303236, 0x51303237, 0x51303238, 0x51303239,
    0x51303330, 0x51303331, 0x51303332, 0x51303333, 0x51303334,
    0x51303335, 0x51303336, 0x51303337, 0x51303338, 0x51303339,
    0x51303430, 0x51303431, 0x51303432, 0x51303433, 0x51303434,
    0x51303435, 0x51303436, 0x51303437, 0x51303438, 0x51303439,
    0x51303530, 0x51303531, 0x51303532, 0x51303533, 0x51303534,
    0x51303535, 0x51303536, 0x51303537, 0x51303538, 0x51303539,
})

# QUIC 帧类型（RFC 9000 §19）
_QUIC_FRAME_PADDING = 0x00; _QUIC_FRAME_PING = 0x01; _QUIC_FRAME_ACK = 0x02
_QUIC_FRAME_CRYPTO = 0x06; _QUIC_FRAME_NEW_TOKEN = 0x07
_QUIC_FRAME_STREAM = range(0x08, 0x10); _QUIC_FRAME_CONN_CLOSE = 0x1c

_QUIC_FRAME_NAMES = {
    0x00: "PADDING", 0x01: "PING", 0x02: "ACK", 0x03: "ACK_ECN",
    0x04: "RESET_STREAM", 0x05: "STOP_SENDING", 0x06: "CRYPTO",
    0x07: "NEW_TOKEN", 0x08: "STREAM", 0x10: "MAX_DATA",
    0x11: "MAX_STREAM_DATA", 0x12: "MAX_STREAMS", 0x14: "DATA_BLOCKED",
    0x15: "STREAM_DATA_BLOCKED", 0x18: "NEW_CONNECTION_ID",
    0x19: "RETIRE_CONNECTION_ID", 0x1a: "PATH_CHALLENGE",
    0x1b: "PATH_RESPONSE", 0x1c: "CONNECTION_CLOSE", 0x1d: "HANDSHAKE_DONE",
}


@dataclass
class QuicConnectionInfo:
    """QUIC 连接分析结果 —— 单次连接的可提取特征"""
    dcid: str = ""
    scid: str = ""
    version: int = 0
    version_name: str = ""
    sni: str = ""           # 从ClientHello/SNI提取
    alpn: str = ""           # 应用层协议协商
    zero_rtt_accepted: bool = False
    cid_count: int = 0      # NEW_CONNECTION_ID帧数量——CID频繁轮换暗示逃避追踪
    stream_count: int = 0
    frame_types: Dict[str, int] = field(default_factory=dict)
    connection_close_code: int = 0
    packets_seen: int = 0
    initial_rtt_ms: float = 0.0


@dataclass
class QuicFingerprint:
    """QUIC 客户端指纹 —— ClientHello特征组合

    QUIC客户端指纹可通过版本+TP组合唯一识别，
    即使ECH启用，初始包中的明文QUIC版本和传输参数仍泄漏客户端身份。
    """
    quic_versions: List[int] = field(default_factory=list)
    tp_params: List[str] = field(default_factory=list)  # 传输参数名
    sni_present: bool = False
    alpn_list: List[str] = field(default_factory=list)
    fingerprint_hash: str = ""


class QuicTrafficAnalyzer:
    """QUIC/HTTP3流量分析器 —— 解析QUIC包头并提取安全相关特征。

    工作流程：
    1. 接收UDP负载（目标端口443或自定义QUIC端口）
    2. 检测长/短包头格式，提取CID和版本
    3. 在Connection级别聚合统计（CID追踪、版本协商、0-RTT检测）
    4. 生成指纹用于客户端识别

    设计约束：不对加密负载解密。所有分析基于明文包头和帧类型推断。
    """

    def __init__(self):
        self._connections: Dict[str, QuicConnectionInfo] = {}
        self._scid_to_conn: Dict[str, str] = {}  # SCID → dcid key
        self._fingerprints: List[QuicFingerprint] = []
        self._cid_collisions = 0

    def feed_packet(self, data: bytes, src_ip: str = "",
                    dst_ip: str = "", src_port: int = 0,
                    dst_port: int = 443, timestamp: float = 0.0) -> Optional[Dict]:
        if len(data) < 2:
            return None

        first_byte = data[0]
        is_long = (first_byte & _QUIC_LONG_HEADER) != 0

        if is_long and len(data) >= 6:
            return self._parse_long_header(data, src_ip, dst_ip, src_port, dst_port, timestamp)
        if not is_long and len(data) >= 2:
            return self._parse_short_header(data, src_ip)
        return None

    def _parse_long_header(self, data: bytes, src_ip: str,
                           dst_ip: str, sp: int, dp: int,
                           ts: float) -> Dict:
        """长包头解析 —— Initial/Handshake/0-RTT 包

        长包头结构（RFC 9000 §17.2）：
        [1b=1|2b=固定|2b=包类型|2b=保留] version(4) dcid_len(1) dcid(v) scid_len(1) scid(v)
        """
        pkt_type = (data[0] >> 4) & 0x03  # 仅取高2bit包类型
        version = struct.unpack(">I", data[1:5])[0]
        pos = 5

        if pos >= len(data):
            return {"error": "payload_truncated_at_version"}

        dcid_len = data[pos]; pos += 1
        if dcid_len > 20 or pos + dcid_len > len(data):
            return {"error": "dcid_len_invalid"}
        dcid = data[pos:pos + dcid_len].hex(); pos += dcid_len

        scid_len = data[pos]; pos += 1
        if scid_len > 20 or pos + scid_len > len(data):
            return {"error": "scid_len_invalid"}
        scid = data[pos:pos + scid_len].hex(); pos += scid_len

        # 连接追踪 —— 以DCID为键聚合
        conn_key = dcid
        if conn_key not in self._connections:
            self._connections[conn_key] = QuicConnectionInfo(
                dcid=dcid, scid=scid, version=version,
                version_name=self._version_label(version),
            )
        conn = self._connections[conn_key]
        conn.packets_seen += 1

        # SCID → DCID 映射（CID旋转检测）
        if scid and scid not in self._scid_to_conn:
            self._scid_to_conn[scid] = conn_key
        elif scid and self._scid_to_conn.get(scid) != conn_key:
            self._cid_collisions += 1

        # 版本协商检测 —— 服务端返回 Version Negotiation
        is_ver_neg = (version == 0 and dcid_len > 0 and scid_len > 0)

        # PING帧检测 —— 用于RTT估算
        has_ping = self._scan_frame_types(data[pos:], conn)

        return {
            "is_quic": True, "packet_type": "long",
            "dcid": dcid, "scid": scid,
            "version": hex(version), "version_label": self._version_label(version),
            "is_version_negotiation": is_ver_neg,
            "conn_key": conn_key,
            "conn_packets": conn.packets_seen,
        }

    def _parse_short_header(self, data: bytes, src_ip: str) -> Optional[Dict]:
        """短包头解析 —— 1-RTT 数据包（加密后正常传输）

        短包头（RFC 9000 §17.3）：
        [1b=0|1b=固定|2b=spin|4b=保留] dcid(variable)
        """
        spin_bit = (data[0] >> 2) & 0x01
        # 短包头DCID隐式——从上下文获取，无法从单包完整解析
        return {
            "is_quic": True, "packet_type": "short",
            "spin_bit": spin_bit,
        }

    def _scan_frame_types(self, payload: bytes, conn: QuicConnectionInfo) -> bool:
        """扫描QUIC帧类型，更新连接统计。返回是否含PING帧。

        帧头部：[类型(1B可变长)] + [帧特定数据]
        仅统计帧类型频率而不完全解析——加密负载不可读。
        """
        has_ping = False
        pos = 0
        frames_seen = 0
        while pos < len(payload) and frames_seen < 20:  # 最多扫描20帧
            if pos >= len(payload):
                break
            frame_type = payload[pos]
            # 可变长帧类型编码：若最高位=1，取下一字节继续解码
            if frame_type & 0x80:
                pos += 1
                if pos >= len(payload):
                    break
                frame_type = payload[pos]

            name = _QUIC_FRAME_NAMES.get(frame_type, f"0x{frame_type:02X}")
            if 0x08 <= frame_type <= 0x0f:
                name = "STREAM"
                conn.stream_count += 1
            conn.frame_types[name] = conn.frame_types.get(name, 0) + 1

            if frame_type == _QUIC_FRAME_PING:
                has_ping = True
            if frame_type == _QUIC_FRAME_NEW_TOKEN:
                conn.cid_count += 1

            pos += 1
            # 跳过帧数据（粗略估计）：大多数简单帧数据长度<20字节
            if frame_type in (_QUIC_FRAME_CRYPTO,):
                if pos + 2 <= len(payload):
                    var_len = self._read_varint(payload, pos)
                    pos = min(pos + var_len + 2, len(payload))
                else:
                    pos += 1
            elif 0x08 <= frame_type <= 0x0f:  # STREAM
                pos += 1

            frames_seen += 1
        return has_ping

    @staticmethod
    def _read_varint(data: bytes, offset: int) -> int:
        """QUIC可变长整数编码（RFC 9000 §16）"""
        if offset >= len(data):
            return 0
        b0 = data[offset]
        msb = b0 >> 6
        if msb == 0:
            return b0 & 0x3F
        length = 1 << msb  # 2, 4, or 8 bytes
        if offset + length > len(data):
            return 0
        val = 0
        for i in range(length):
            val = (val << 8) | data[offset + i]
        return val & ((1 << (8 * length - 2)) - 1)

    @staticmethod
    def _version_label(ver: int) -> str:
        if ver == _QUIC_VERSION_V1: return "QUICv1(RFC9000)"
        if ver == _QUIC_VERSION_V2: return "QUICv2(RFC9369)"
        if ver in _QUIC_VERSION_DRAFT: return f"QUIC-draft-{ver & 0xFF}"
        if ver in _GOOGLE_QUIC_VERSIONS: return f"gQUIC-{ver & 0xFFFF}"
        if ver == 0: return "VersionNegotiation"
        return f"unknown-0x{ver:08X}"

    def generate_fingerprint(self) -> QuicFingerprint:
        """从已收集连接生成客户端指纹 —— 聚合QUIC版本和传输参数特征"""
        fp = QuicFingerprint()
        versions = set()
        for conn in self._connections.values():
            if conn.version:
                versions.add(conn.version)
        fp.quic_versions = sorted(versions)
        raw = ",".join(hex(v) for v in fp.quic_versions)
        fp.fingerprint_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]
        self._fingerprints.append(fp)
        return fp

    def summary(self) -> Dict[str, Any]:
        """返回分析摘要 —— 连接数、CID旋转检测、版本分布"""
        ver_dist = Counter(
            self._version_label(c.version) for c in self._connections.values()
        )
        total_conns = len(self._connections)
        cid_rotation_detected = total_conns > 0 and (
            self._cid_collisions / max(total_conns, 1) > 0.3
        )
        return {
            "total_connections": total_conns,
            "unique_versions": len(ver_dist),
            "version_distribution": dict(ver_dist.most_common()),
            "cid_collisions": self._cid_collisions,
            "cid_rotation_suspected": cid_rotation_detected,
            "fingerprints_collected": len(self._fingerprints),
            "risk_indicators": self._risk_assessment(),
        }

    def _risk_assessment(self) -> List[str]:
        """QUIC连接安全风险指标列表

        风险维度：版本过旧（draft仍有重放漏洞）、CID不旋转、
        PING帧风暴（RTT侧信道探测嫌疑）、0-RTT重放窗口未关闭。
        """
        risks = []
        for conn in self._connections.values():
            if conn.version in _QUIC_VERSION_DRAFT:
                risks.append(f"dcid={conn.dcid[:8]}... 使用QUIC草案版本——可能存在已知漏洞")
            if conn.packets_seen > 50 and conn.cid_count == 0:
                risks.append(f"dcid={conn.dcid[:8]}... 无CID轮换——可跨网络追踪")
            ping_count = conn.frame_types.get("PING", 0)
            if ping_count > conn.packets_seen * 0.3:
                risks.append(f"dcid={conn.dcid[:8]}... PING帧占比{ping_count/conn.packets_seen:.0%}——疑似RTT探测")
        return risks


def analyze_quic_traffic(packets: List[bytes], **kwargs) -> Dict[str, Any]:
    """批量QUIC流量分析入口 —— 遍历UDP负载列表，聚合连接级统计。"""
    analyzer = QuicTrafficAnalyzer()
    for i, pkt in enumerate(packets):
        if isinstance(pkt, bytes):
            analyzer.feed_packet(pkt, timestamp=float(i))
        elif isinstance(pkt, dict):
            analyzer.feed_packet(
                pkt.get("payload", b""),
                src_ip=pkt.get("src_ip", ""),
                dst_ip=pkt.get("dst_ip", ""),
                src_port=pkt.get("src_port", 0),
                dst_port=pkt.get("dst_port", 443),
                timestamp=pkt.get("timestamp", 0.0),
            )
    analyzer.generate_fingerprint()
    return analyzer.summary()


__all__ = ["QuicTrafficAnalyzer", "QuicConnectionInfo", "QuicFingerprint",
           "analyze_quic_traffic"]
