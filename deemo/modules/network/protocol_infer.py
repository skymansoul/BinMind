"""网络协议推断——从二进制流量处理代码中还原协议结构"""
import enum, logging, re, struct
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)

class ProtocolFieldType(enum.Enum):
    UINT8 = "uint8"; UINT16 = "uint16"; UINT32 = "uint32"; UINT64 = "uint64"
    INT8 = "int8"; INT16 = "int16"; INT32 = "int32"; INT64 = "int64"
    FLOAT = "float"; DOUBLE = "double"; BYTES = "bytes"; STRING = "string"
    MAGIC = "magic"; LENGTH = "length"; CHECKSUM = "checksum"; FLAGS = "flags"
    ENUM = "enum"; PADDING = "padding"; COUNTER = "counter"; CONSTANT = "constant"

class FieldEndianness(enum.Enum): LITTLE = "little"; BIG = "big"; UNKNOWN = "unknown"

@dataclass
class ProtocolField:
    name: str; offset: int; size: int; field_type: ProtocolFieldType = ProtocolFieldType.BYTES
    endianness: FieldEndianness = FieldEndianness.UNKNOWN; is_variable_length: bool = False
    length_determines: Optional[str] = None; enum_values: Dict[int, str] = field(default_factory=dict)
    confidence: float = 0.0

@dataclass
class ProtocolMessage:
    name: str; fields: List[ProtocolField] = field(default_factory=list)
    direction: str = "unknown"; total_size_min: int = 0; total_size_max: int = 0

@dataclass
class ProtocolDefinition:
    name: str; messages: List[ProtocolMessage] = field(default_factory=list)
    transport: str = "tcp"; endianness: FieldEndianness = FieldEndianness.UNKNOWN

@dataclass
class ProtocolInferenceResult:
    definition: ProtocolDefinition; confidence: float = 0.0
    sample_count: int = 0; field_count: int = 0

class HeuristicFieldInferrer:
    _PARSE_FUNCTIONS = re.compile(r"(ntohs|ntohl|htons|htonl)\(|memcpy|memmove|strncpy|strcpy|read_u?(?:8|16|32|64|int|short|long)", re.IGNORECASE)

    @staticmethod
    def infer(data: Any) -> List[Tuple[int, int, str]]:
        fields: List[Tuple[int, int, str]] = []
        if isinstance(data, bytes) and len(data) >= 2: fields = HeuristicFieldInferrer._from_bytes(data)
        elif isinstance(data, str): fields = HeuristicFieldInferrer._from_decompiled(data)
        elif isinstance(data, (list, tuple)):
            for sample in data:
                if isinstance(sample, bytes): fields.extend(HeuristicFieldInferrer._from_bytes(sample))
            align_fields = HeuristicFieldInferrer._from_alignment(data); fields.extend(align_fields)
        return HeuristicFieldInferrer._consolidate(fields)

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

class ChecksumDetector:
    @staticmethod
    def detect(data: bytes) -> Optional[Tuple[int, int, str]]:
        if len(data) < 4: return None
        payload = data[:-2]; checksum_expected = struct.unpack("<H", data[-2:])[0]
        for poly in [0x1021, 0x8005]:
            if ChecksumDetector._crc16(payload, poly) == checksum_expected: return (len(data)-2, 2, f"CRC-16-{poly:#06x}")
        return None

    @staticmethod
    def _crc16(data: bytes, poly: int) -> int:
        crc = 0xFFFF
        for byte in data:
            crc ^= byte << 8
            for _ in range(8): crc = (crc << 1) ^ poly if crc & 0x8000 else crc << 1; crc &= 0xFFFF
        return crc

class MagicDetector:
    @staticmethod
    def find_magic(data: bytes, min_len: int = 2, max_len: int = 8) -> List[bytes]:
        candidates = []
        for ln in range(min_len, min(max_len + 1, len(data))):
            prefix = data[:ln]
            if all(0x00 <= b <= 0x7F for b in prefix) and prefix not in candidates: candidates.append(prefix)
        return candidates

class ProtocolInferEngine:
    def __init__(self):
        self._field_inferrer = HeuristicFieldInferrer(); self._checksum = ChecksumDetector()
        self._magic = MagicDetector()

    def infer(self, data: Any) -> ProtocolInferenceResult:
        samples = [data] if isinstance(data, bytes) else (data if isinstance(data, list) else [data])
        all_fields: List[Tuple[int, int, str]] = []
        for s in samples:
            if isinstance(s, bytes): all_fields.extend(self._field_inferrer.infer(s))
        all_fields = HeuristicFieldInferrer._consolidate(all_fields); pfields = []
        for offset, size, ftype in all_fields:
            try: ft = ProtocolFieldType(ftype)
            except ValueError: ft = ProtocolFieldType.BYTES
            pfields.append(ProtocolField(name=f"field_{offset}", offset=offset, size=size, field_type=ft, confidence=0.7))
        msg = ProtocolMessage(name="inferred_message", fields=pfields)
        definition = ProtocolDefinition(name="inferred_protocol", messages=[msg])
        return ProtocolInferenceResult(definition=definition, confidence=0.5, sample_count=len(samples), field_count=len(pfields))
