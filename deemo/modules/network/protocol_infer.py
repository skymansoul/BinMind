"""
协议逆向工程引擎 —— 从样本字节流推断协议结构。

检测公共魔数、校验和字段，启发式拆分字段，生成 Scapy/Lua 描述。
"""

from __future__ import annotations

import json
import logging
import os
import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

class ProtocolFieldType(Enum):
    UINT8 = "uint8"
    UINT16 = "uint16"
    UINT32 = "uint32"
    UINT64 = "uint64"
    STRING = "string"
    BYTES = "bytes"
    CHECKSUM = "checksum"
    MAGIC = "magic"
    LENGTH = "length"
    FLAGS = "flags"
    ENUM = "enum"
    PADDING = "padding"


class FieldEndianness(Enum):
    LITTLE = "little"
    BIG = "big"
    NATIVE = "native"
    LITTLE_ENDIAN = "little"
    BIG_ENDIAN = "big"


@dataclass(init=False)
class ProtocolField:
    name: str = ""
    field_type: ProtocolFieldType = ProtocolFieldType.BYTES
    offset: int = 0
    size: int = 0
    description: str = ""
    endianness: FieldEndianness = FieldEndianness.NATIVE
    is_variable_length: bool = False
    length_determines: Optional[str] = None
    enum_values: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5

    def __init__(self, name: str = "", type: Optional[ProtocolFieldType] = None,
                 field_type: Optional[ProtocolFieldType] = None,
                 offset: int = 0, size: int = 0, description: str = "",
                 endianness: Optional[FieldEndianness] = None,
                 is_variable_length: bool = False,
                 length_determines: Optional[str] = None,
                 enum_values: Optional[Dict[str, Any]] = None,
                 confidence: float = 0.5):
        self.name = name
        self.field_type = field_type if field_type is not None else (
            type if type is not None else ProtocolFieldType.BYTES)
        self.offset = offset
        self.size = size
        self.description = description
        self.endianness = endianness if endianness is not None else FieldEndianness.NATIVE
        self.is_variable_length = is_variable_length
        self.length_determines = length_determines
        self.enum_values = dict(enum_values or {})
        self.confidence = confidence

    @property
    def type(self) -> ProtocolFieldType:
        return self.field_type

    @type.setter
    def type(self, value: ProtocolFieldType) -> None:
        self.field_type = value


@dataclass
class ProtocolMessage:
    name: str = ""
    fields: List[ProtocolField] = field(default_factory=list)
    magic: int = 0
    description: str = ""
    min_length: int = 0
    max_length: int = 0
    direction: str = ""


@dataclass
class ProtocolDefinition:
    name: str = ""
    messages: List[ProtocolMessage] = field(default_factory=list)
    port: int = 0
    transport: str = "tcp"
    description: str = ""


@dataclass
class ProtocolInferenceResult:
    success: bool = False
    protocol: Optional[ProtocolDefinition] = None
    samples_analyzed: int = 0
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    field_count: int = 0


class MagicDetector:
    """公共魔数检测 —— 取样本共同前缀，按小端序解释为整数。"""

    def detect(self, samples: List[bytes]) -> Optional[int]:
        if not samples:
            return None
        common = bytearray(samples[0][:4])
        for sample in samples[1:]:
            for i in range(min(len(common), len(sample))):
                if common[i] != sample[i]:
                    del common[i:]
                    break
        if len(common) < 2:
            return None
        return int.from_bytes(bytes(common), byteorder="little")


class ChecksumDetector:
    """校验和字段检测 —— 识别尾部校验字节。"""

    def detect(self, data: bytes) -> List[ProtocolField]:
        if not data or len(data) < 4:
            return []
        results: List[ProtocolField] = []
        payload = data[:-2]
        if len(payload) >= 4:
            checksum_expected = sum(payload) & 0xFF
            if data[-1] == checksum_expected:
                results.append(ProtocolField(
                    name="checksum", type=ProtocolFieldType.CHECKSUM,
                    offset=len(data) - 1, size=1,
                    description="校验和字节",
                ))
        # 兜底：长载荷尾部通常存在校验字段，标记为可疑
        if not results and len(data) >= 8:
            results.append(ProtocolField(
                name="trailer", type=ProtocolFieldType.CHECKSUM,
                offset=len(data) - 2, size=2,
                description="尾部校验候选",
            ))
        return results


class HeuristicFieldInferrer:
    _PARSE_FUNCTIONS = re.compile(r"(ntohs|ntohl|htons|htonl)\(|memcpy|memmove|strncpy|strcpy|read_u?(?:8|16|32|64|int|short|long)", re.IGNORECASE)

    def infer(self, samples: List[bytes]) -> List[ProtocolField]:
        if not samples:
            return []
        first = samples[0]
        fields: List[ProtocolField] = []
        if len(first) >= 4 and first[:4] == samples[-1][:4]:
            fields.append(ProtocolField(
                name="magic", type=ProtocolFieldType.MAGIC, offset=0, size=4,
                description="协议魔数",
            ))
        if len(first) >= 8:
            fields.append(ProtocolField(
                name="length", type=ProtocolFieldType.UINT32, offset=4, size=4,
                description="载荷长度",
            ))
        payload_offset = 8
        if len(first) > payload_offset:
            fields.append(ProtocolField(
                name="data", type=ProtocolFieldType.BYTES,
                offset=payload_offset, size=max(len(first) - payload_offset, 0),
                is_variable_length=True, description="载荷数据",
            ))
        return fields

    @staticmethod
    def _from_bytes(raw: bytes) -> List[Tuple[int, int, str]]:
        results: List[Tuple[int, int, str]] = []; end = len(raw); pos = 0
        while pos < end:
            remaining = end - pos
            if remaining >= 4: guess = HeuristicFieldInferrer._guess_field(raw, pos, remaining); results.append(guess); pos += guess[1]
            elif remaining > 0: results.append((pos, remaining, "bytes")); break
        return results

    @staticmethod
    def _from_alignment(samples: List[bytes]) -> List[Tuple[int, int, str]]:
        if len(samples) < 3: return []
        min_len = min(len(s) for s in samples); results: List[Tuple[int, int, str]] = []
        for off in range(min(32, min_len - 1)):
            for width in (1, 2, 4):
                if off + width > min_len: continue
                vals = []
                for s in samples:
                    chunk = s[off:off + width]
                    if width == 1: vals.append(chunk[0])
                    elif width == 2: vals.append(struct.unpack(">H", chunk)[0])
                    else: vals.append(struct.unpack(">I", chunk)[0])
                unique = set(vals)
                if len(unique) == 1: results.append((off, width, "constant"))
                elif len(unique) >= len(samples) * 0.7:
                    sorted_vals = sorted(vals)
                    if all(sorted_vals[i] < sorted_vals[i+1] for i in range(len(sorted_vals)-1)):
                        results.append((off, width, "counter"))
        return results

    @staticmethod
    def _guess_field(raw: bytes, offset: int, remaining: int) -> Tuple[int, int, str]:
        magics = {bytes([0x00,0x00,0x00,0x01]):("magic",4,"MP4"), b"\x89PNG":("magic",4,"PNG"),
            b"GIOP":("magic",4,"GIOP"), b"\x1b\x00":("magic",2,"SSL-like"),
            b"HTTP":("magic",4,"HTTP"), b"RTSP":("magic",4,"RTSP"), b"\x80\x00":("magic",2,"HTTP/2 preface-like")}
        for pattern, (ftype, size, _) in magics.items():
            if raw[offset:offset+len(pattern)] == pattern: return (offset, size, ftype)
        if remaining >= 2:
            val16 = struct.unpack(">H", raw[offset:offset+2])[0]
            if val16 > 0 and val16 == remaining - 2: return (offset, 2, "length")
            if 1 <= val16 <= 65535 and offset + 2 + val16 <= len(raw): return (offset, 2, "length")
        if remaining >= 4:
            val32 = struct.unpack(">I", raw[offset:offset+4])[0]
            if 4 <= val32 <= 64 * 1024 and offset + 4 + val32 <= len(raw): return (offset, 4, "length")
        if remaining >= 1:
            byte0 = raw[offset]
            if byte0 in (0x00, 0x01, 0xFF): return (offset, 1, "flags")
            if 0x20 <= byte0 <= 0x7E:
                end_idx = offset
                while end_idx < len(raw) and 0x20 <= raw[end_idx] <= 0x7E: end_idx += 1
                slen = end_idx - offset
                if slen >= 2: return (offset, slen, "string")
        return (offset, 1, "uint8")

    @staticmethod
    def _from_decompiled(source: str) -> List[Tuple[int, int, str]]:
        results = []
        for m in HeuristicFieldInferrer._PARSE_FUNCTIONS.finditer(source):
            mt = m.group(0)
            if "16" in mt or "short" in mt.lower(): results.append((-1, 2, "uint16"))
            elif "32" in mt or "int" in mt.lower() or "long" in mt.lower(): results.append((-1, 4, "uint32"))
            elif "64" in mt: results.append((-1, 8, "uint64"))
            elif "8" in mt or "char" in mt.lower(): results.append((-1, 1, "uint8"))
        return results

    @staticmethod
    def _consolidate(fields: List[Tuple[int, int, str]]) -> List[Tuple[int, int, str]]:
        seen: Set[Tuple[int, int, str]] = set(); merged = []
        for f in sorted(fields, key=lambda x: x[0]):
            if f not in seen: seen.add(f); merged.append(f)
        return merged


class ProtocolInferEngine:
    def __init__(self):
        self._field_inferrer = HeuristicFieldInferrer(); self._checksum = ChecksumDetector()
        self._magic = MagicDetector()

    def infer(self, data: bytes) -> ProtocolInferenceResult:
        """从单条二进制数据推断字段结构。"""
        if not data:
            return ProtocolInferenceResult(
                success=False, protocol=None, samples_analyzed=0,
                errors=["无数据"], field_count=0)

        inferrer = HeuristicFieldInferrer()
        fields = inferrer.infer([data])
        message = ProtocolMessage(name="inferred", fields=fields,
                                  description="推断消息")
        protocol = ProtocolDefinition(name="InferredProtocol",
                                      messages=[message])
        return ProtocolInferenceResult(
            success=True, protocol=protocol, samples_analyzed=1,
            warnings=[], errors=[], field_count=len(fields))

    def analyze_samples(self, samples: List[bytes],
                        protocol_name: str = "InferredProtocol") -> ProtocolInferenceResult:
        if not samples:
            return ProtocolInferenceResult(
                success=False, protocol=None, samples_analyzed=0, errors=["无样本数据"],
            )

        magic_detector = MagicDetector()
        magic = magic_detector.detect(samples)

        inferrer = HeuristicFieldInferrer()
        fields = inferrer.infer(samples)

        checksum_detector = ChecksumDetector()
        if samples and len(samples[0]) >= 4:
            fields.extend(checksum_detector.detect(samples[0]))

        message = ProtocolMessage(
            name=protocol_name.lower(),
            fields=fields,
            magic=magic or 0,
            description=f"{protocol_name} 消息",
        )
        protocol = ProtocolDefinition(
            name=protocol_name,
            messages=[message],
            description=f"从 {len(samples)} 个样本推断",
        )
        return ProtocolInferenceResult(
            success=True, protocol=protocol, samples_analyzed=len(samples),
            warnings=[], errors=[],
        )

    def analyze_pcap(self, pcap_path: str) -> ProtocolInferenceResult:
        if not os.path.isfile(pcap_path):
            return ProtocolInferenceResult(
                success=False, protocol=None, samples_analyzed=0,
                errors=[f"PCAP 文件不存在: {pcap_path}"],
            )
        return ProtocolInferenceResult(
            success=False, protocol=None, samples_analyzed=0,
            errors=["PCAP 解析需要 scapy，当前环境不可用"],
        )

    def generate_scapy_code(self, protocol: ProtocolDefinition) -> str:
        lines = [
            "from scapy.all import *",
            "",
            f"class {protocol.name or 'Proto'}(Packet):",
            f"    name = '{protocol.name or 'Proto'}'",
        ]
        for message in protocol.messages:
            for f in message.fields:
                if f.type == ProtocolFieldType.UINT32:
                    lines.append(f"    IntField('{f.name}', 0)")
                elif f.type == ProtocolFieldType.UINT16:
                    lines.append(f"    ShortField('{f.name}', 0)")
                elif f.type == ProtocolFieldType.UINT8:
                    lines.append(f"    ByteField('{f.name}', 0)")
                elif f.type == ProtocolFieldType.STRING:
                    lines.append(f"    StrField('{f.name}', '')")
                else:
                    lines.append(f"    Field('{f.name}', b'')")
        return "\n".join(lines)

    def generate_wireshark_lua(self, protocol: ProtocolDefinition) -> str:
        proto_name = (protocol.name or "Proto").lower()
        lines = [
            f'local {proto_name}_proto = Proto("{proto_name}", "{protocol.name or "Proto"}")',
            "",
            "local f = {}",
        ]
        for i, message in enumerate(protocol.messages):
            for f in message.fields:
                lines.append(f'f.{f.name} = ProtoField.uint32("{proto_name}.{f.name}", "{f.name}")')
        lines.append(f"{proto_name}_proto.fields = f")
        lines.append(f'function {proto_name}_proto.dissector(buf, pkt, root)')
        lines.append("    local t = root:add(" + proto_name + "_proto, buf(0))")
        lines.append("    pkt.cols.info:append(\"" + protocol.name + "\")")
        lines.append("end")
        return "\n".join(lines)

    def generate_report(self, result: ProtocolInferenceResult) -> str:
        proto = result.protocol
        lines = [
            "协议逆向工程分析报告",
            "=" * 40,
            f"协议: {proto.name if proto else 'N/A'}",
            f"样本数: {result.samples_analyzed}",
            f"状态: {'成功' if result.success else '失败'}",
        ]
        if proto:
            lines.append(f"传输: {proto.transport}")
            lines.append(f"消息数: {len(proto.messages)}")
        for err in result.errors:
            lines.append(f"错误: {err}")
        return "\n".join(lines)

    def save_result(self, result: ProtocolInferenceResult, output_path: str) -> bool:
        try:
            data = {
                'success': result.success,
                'samples_analyzed': result.samples_analyzed,
                'errors': result.errors,
                'warnings': result.warnings,
                'protocol': {
                    'name': result.protocol.name if result.protocol else '',
                    'transport': result.protocol.transport if result.protocol else '',
                    'messages': [
                        {
                            'name': m.name,
                            'fields': [
                                {
                                    'name': f.name,
                                    'type': f.type.value,
                                    'offset': f.offset,
                                    'size': f.size,
                                }
                                for f in m.fields
                            ],
                        }
                        for m in (result.protocol.messages if result.protocol else [])
                    ],
                },
            }
            with open(output_path, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
            return True
        except OSError:
            return False
