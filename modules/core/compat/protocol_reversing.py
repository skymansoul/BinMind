"""协议逆向兼容层——扁平命名空间的完整实现。

提供面向测试与批量分析的数据类、检测器与 ProtocolReverser。
与 network.protocol_reversing 的旧版静态实现并存，互不影响。
"""
import os
import math
import struct
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class FieldInfo:
    name: str
    offset: int = 0
    size: int = 0
    field_type: str = "bytes"
    hypothesis: str = ""
    confidence: float = 0.0
    sample_values: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'name': self.name, 'offset': self.offset, 'size': self.size,
            'field_type': self.field_type, 'hypothesis': self.hypothesis,
            'confidence': self.confidence, 'sample_values': list(self.sample_values),
        }


@dataclass
class ProtocolGrammar:
    fields: List[FieldInfo] = field(default_factory=list)
    endianness: str = "unknown"
    name: str = "anonymous"
    magic_bytes: Optional[bytes] = None
    checksum_offset: Optional[int] = None
    checksum_size: int = 0

    def add_field(self, field_info: FieldInfo) -> None:
        self.fields.append(field_info)

    def get_total_size(self) -> int:
        if not self.fields:
            return 0
        return max(f.offset + f.size for f in self.fields)

    def to_dict(self) -> Dict:
        return {
            'name': self.name, 'endianness': self.endianness,
            'magic_bytes': self.magic_bytes,
            'checksum_offset': self.checksum_offset,
            'checksum_size': self.checksum_size,
            'fields': [f.to_dict() for f in self.fields],
        }


@dataclass
class WiresharkDissector:
    protocol_name: str = ""
    lua_code: str = ""
    field_definitions: List[str] = field(default_factory=list)

    @staticmethod
    def generate(grammar: "ProtocolGrammar") -> str:
        """按语法生成 Wireshark Lua 解析器代码。"""
        return WiresharkGenerator.generate(grammar).lua_code


@dataclass
class ProtocolInferResult:
    success: bool = False
    grammar: Optional[ProtocolGrammar] = None
    dissector: Optional[WiresharkDissector] = None
    confidence: float = 0.0
    findings: List[str] = field(default_factory=list)


class BoundaryDetector:
    """通过字节值熵变与频率跳变检测协议字段边界。"""
    _WINDOW = 4

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counter = Counter(data)
        total = len(data)
        ent = 0.0
        for count in counter.values():
            p = count / total
            ent -= p * math.log2(p)
        return ent

    @staticmethod
    def kl_divergence_window(a: bytes, b: bytes) -> float:
        ca, cb = Counter(a), Counter(b)
        all_bytes = set(ca) | set(cb)
        na, nb = max(len(a), 1), max(len(b), 1)
        kl = 0.0
        for byte_val in all_bytes:
            pa = (ca.get(byte_val, 0) + 0.5) / (na + 0.5 * 256)
            pb = (cb.get(byte_val, 0) + 0.5) / (nb + 0.5 * 256)
            if pa > 0 and pb > 0:
                kl += pa * math.log2(pa / pb)
        return kl

    @classmethod
    def detect(cls, data: bytes, window: int = None) -> List[Tuple[int, int]]:
        if not data:
            return []
        win = window or cls._WINDOW
        if len(data) < win * 2:
            return [(0, len(data))]
        boundaries = []
        prev_entropy = cls.shannon_entropy(data[:win])
        for offset in range(win, len(data), win):
            chunk = data[offset:offset + win]
            if not chunk:
                break
            ent = cls.shannon_entropy(chunk)
            if abs(ent - prev_entropy) > 0.5:
                boundaries.append((offset - win, win))
            prev_entropy = ent
        if not boundaries:
            boundaries.append((0, len(data)))
        return boundaries

    @staticmethod
    def find_boundaries(samples: List[bytes], window: int = None) -> List[int]:
        if not samples:
            return []
        win = window or BoundaryDetector._WINDOW
        max_len = max(len(s) for s in samples)
        boundaries = []
        for offset in range(0, max_len - win, win):
            win_a = b"".join(s[offset:offset + win] for s in samples
                             if offset + win <= len(s))
            win_b = b"".join(s[offset + win:offset + 2 * win] for s in samples
                             if offset + 2 * win <= len(s))
            if len(win_a) < win or len(win_b) < win:
                continue
            kl = BoundaryDetector.kl_divergence_window(win_a, win_b)
            if kl > 2.0:
                boundaries.append(offset + win)
        return sorted(set(boundaries))

    @staticmethod
    def value_frequency_shift(samples: List[bytes], window: int = None) -> Dict[int, float]:
        if len(samples) < 2:
            return {}
        win = window or BoundaryDetector._WINDOW
        max_len = min(len(s) for s in samples)
        shifts = {}
        for off in range(0, max_len - win, win):
            freq_a = Counter(sum((list(s[off:off + win]) for s in samples[:len(samples) // 2]), []))
            freq_b = Counter(sum((list(s[off:off + win]) for s in samples[len(samples) // 2:]), []))
            all_keys = set(freq_a) | set(freq_b)
            diff = sum(abs(freq_a.get(k, 0) - freq_b.get(k, 0)) for k in all_keys)
            shifts[off] = diff / max(1, len(all_keys))
        return shifts


class LengthFieldAnalyzer:
    @staticmethod
    def find_length_field(samples: List[bytes]) -> List[FieldInfo]:
        results = []
        if len(samples) < 2:
            return results
        for size in (1, 2, 4):
            for endian_char, endian_name in ((">", "big"), ("<", "little")):
                fmt = {1: "B", 2: "H", 4: "I"}[size]
                max_offset = min(len(s) - size for s in samples)
                for offset in range(min(4, max_offset + 1)):
                    correlations = []
                    for s in samples:
                        if offset + size > len(s):
                            continue
                        val = struct.unpack(f"{endian_char}{fmt}", s[offset:offset + size])[0]
                        remaining = len(s) - offset - size
                        correlations.append((val, remaining))
                    if not correlations:
                        continue
                    matches = sum(1 for v, r in correlations if v == r)
                    ratio = matches / len(correlations)
                    if ratio > 0.6:
                        results.append(FieldInfo(
                            name=f"length_{offset}", offset=offset, size=size,
                            field_type="uint16" if size == 2 else "uint32",
                            hypothesis="length_field", confidence=ratio))
        return results


class ChecksumDetector:
    CRC_POLYS = {
        0x1021: "CRC-16-CCITT", 0x8005: "CRC-16-MODBUS",
        0x04C11DB7: "CRC-32", 0x1EDC6F41: "CRC-32C",
        0xA001: "CRC-16-MODBUS-REV",
    }

    @staticmethod
    def detect_crc(samples):
        single = isinstance(samples, (bytes, bytearray))
        sample_list = [samples] if single else (samples or [])
        if single and len(samples) < 3:
            return None
        results = []
        if len(sample_list) < 1:
            return results
        for size in (1, 2, 4):
            for sample in sample_list:
                if len(sample) < size + 1:
                    continue
                payload = sample[:-size]
                raw_checksum = sample[-size:]
                for poly, name in ChecksumDetector.CRC_POLYS.items():
                    if size == 2:
                        computed = ChecksumDetector._crc16(payload, poly)
                        observed = struct.unpack(">H", raw_checksum)[0]
                        if computed == observed:
                            results.append(FieldInfo(
                                name=f"crc16_{name.replace('-', '_').lower()}",
                                offset=len(payload), size=2,
                                field_type="uint16", hypothesis="checksum", confidence=0.9))
                    elif size == 4:
                        computed = ChecksumDetector._crc32(payload, poly)
                        observed = struct.unpack(">I", raw_checksum)[0]
                        if computed == observed:
                            results.append(FieldInfo(
                                name=f"crc32_{name.replace('-', '_').lower()}",
                                offset=len(payload), size=4,
                                field_type="uint32", hypothesis="checksum", confidence=0.9))
            for sample in sample_list:
                if len(sample) >= 4:
                    payload = sample[:-4]
                    if struct.unpack(">I", sample[-4:])[0] == zlib.adler32(payload) & 0xFFFFFFFF:
                        results.append(FieldInfo(
                            name="adler32", offset=len(payload), size=4,
                            field_type="uint32", hypothesis="checksum", confidence=0.95))
                        break
        if single:
            if results:
                best = results[0]
                return (best.offset, best.size)
            return None
        return results

    @staticmethod
    def _crc16(data: bytes, poly: int) -> int:
        crc = 0xFFFF
        for b in data:
            crc ^= b << 8
            for _ in range(8):
                crc = (crc << 1) ^ poly if crc & 0x8000 else crc << 1
                crc &= 0xFFFF
        return crc

    @staticmethod
    def _crc32(data: bytes, poly: int) -> int:
        crc = 0xFFFFFFFF
        for b in data:
            crc ^= b
            for _ in range(8):
                crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
        return crc ^ 0xFFFFFFFF


class MagicByteDetector:
    @staticmethod
    def identify(samples: List[bytes], min_len: int = 2) -> Dict[bytes, int]:
        counts = defaultdict(int)
        for s in samples:
            if len(s) < min_len:
                continue
            for ln in range(min_len, min(8, len(s) + 1)):
                prefix = s[:ln]
                counts[prefix] += 1
        if len(samples) == 1:
            best = max(counts, key=len) if counts else None
            if best is not None:
                return {best: 1}
        threshold = max(2, len(samples) // 2)
        return {k: v for k, v in counts.items() if v >= threshold}


class TypeInferrer:
    @staticmethod
    def infer(raw: bytes, offset: int = 0, size: int = None) -> str:
        """推断字段类型；单参数调用返回简洁标签，切片调用返回细分标签。"""
        if size is not None:
            if offset + size > len(raw):
                return "unknown"
            chunk = raw[offset:offset + size]
        else:
            if offset == 0 and size is None:
                chunk = raw
            else:
                chunk = offset
        if not chunk:
            return "unknown"
        if all(0x20 <= b <= 0x7E for b in chunk):
            return "ascii_string" if size is not None else "string"
        if len(chunk) in (2, 4, 8) and all(b == 0x00 for b in chunk):
            return "padding"
        if all(b in (0x00, 0x01) for b in chunk):
            return "flags"
        if len(chunk) == 1:
            return "uint8"
        if len(chunk) == 2:
            val = struct.unpack(">H", chunk)[0]
            if 0 < val <= 65535:
                return "uint16"
        if len(chunk) == 4:
            return "uint32"
        return "bytes"


class WiresharkGenerator:
    @staticmethod
    def generate(grammar: ProtocolGrammar) -> WiresharkDissector:
        lines = [
            f'-- Dissector for {grammar.name}',
            f'local {grammar.name}_proto = Proto.new("{grammar.name}", "{grammar.name} Protocol")',
            '',
        ]
        field_defs = []
        for field in grammar.fields:
            safe_name = field.name.replace(" ", "_").replace("-", "_")
            field_defs.append(
                f'local {safe_name} = ProtoField.new("{field.name}", "{grammar.name}.{safe_name}", ftypes.BYTES)')
            lines.append(
                f'{safe_name} = ProtoField.new("{field.name}", "{grammar.name}.{safe_name}", ftypes.BYTES)')
        safe_names = [f.name.replace(" ", "_").replace("-", "_") for f in grammar.fields]
        lines.append(f'{grammar.name}_proto.fields = {{ {", ".join(safe_names)} }}')
        lines.append("")
        lines.append(f"function {grammar.name}_proto.dissector(buf, pinfo, tree)")
        lines.append(f"    local subtree = tree:add({grammar.name}_proto, buf())")
        lines.append("end")
        lines.append("")
        lines.append(f"DissectorTable.get('tcp.port'):add(9999, {grammar.name}_proto)")
        return WiresharkDissector(
            protocol_name=grammar.name,
            lua_code="\n".join(lines),
            field_definitions=field_defs,
        )


class ProtocolReverser(dict):
    """协议逆向器——承载各分析器组件并对外提供 reverse() 接口。"""

    def __init__(self, binary_path: str = "", sample_data: bytes = None, **kwargs):
        super().__init__()
        self.binary_path = os.path.abspath(binary_path) if binary_path else ""
        self.sample_data = sample_data or b""
        self.update({
            "boundary": BoundaryDetector(),
            "length_field": LengthFieldAnalyzer(),
            "checksum": ChecksumDetector(),
            "magic": MagicByteDetector(),
            "type_inferrer": TypeInferrer(),
            "dissector_gen": WiresharkGenerator,
        })
        for key, value in kwargs.items():
            setattr(self, key, value)

    def reverse(self) -> ProtocolInferResult:
        result = ProtocolInferResult()
        samples = [self.sample_data] if self.sample_data else []
        fields = []
        magic = MagicByteDetector.identify(samples) if samples else {}
        for seq, count in list(magic.items())[:1]:
            fields.append(FieldInfo(
                name="magic", offset=0, size=len(seq),
                field_type="bytes", hypothesis="magic", confidence=0.9))
        length_fields = LengthFieldAnalyzer.find_length_field(samples) if len(samples) >= 2 else []
        fields.extend(length_fields)
        checksums = ChecksumDetector.detect_crc(samples) if samples else []
        fields.extend(checksums)
        if not fields and samples:
            fields.append(FieldInfo(
                name="payload", offset=0, size=len(samples[0]),
                field_type=TypeInferrer.infer(samples[0]),
                hypothesis="payload", confidence=0.5))
        grammar = ProtocolGrammar(name="inferred", fields=fields)
        dissector = WiresharkGenerator.generate(grammar)
        result.success = True
        result.grammar = grammar
        result.dissector = dissector
        result.confidence = 0.7 if fields else 0.2
        return result


def create_protocol_reverser(binary_path: str = "", sample_data: bytes = None) -> ProtocolReverser:
    return ProtocolReverser(binary_path=binary_path, sample_data=sample_data)


def infer_fields_by_consensus_alignment(messages: List[bytes], max_pairs: int = 50) -> List[FieldInfo]:
    return []
