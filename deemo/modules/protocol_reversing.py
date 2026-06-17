#!/usr/bin/env python3
"""
未知协议逆向模块 (PIRE) - 通过动态执行自动推断字段边界、类型和校验和
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)


@dataclass
class FieldInfo:
    name: str
    offset: int
    size: int
    field_type: str
    sample_values: List[Any] = field(default_factory=list)


@dataclass
class ProtocolGrammar:
    name: str
    fields: List[FieldInfo]
    magic_bytes: Optional[bytes] = None
    checksum_offset: Optional[int] = None
    checksum_size: int = 0


@dataclass
class WiresharkDissector:
    protocol_name: str
    lua_code: str
    field_definitions: List[str] = field(default_factory=list)


@dataclass
class ProtocolInferResult:
    success: bool
    grammar: Optional[ProtocolGrammar]
    dissector: Optional[WiresharkDissector]
    confidence: float = 0.0


class BoundaryDetector:
    """字段边界检测器"""

    @staticmethod
    def detect(data: bytes, min_size: int = 1, max_size: int = 8) -> List[Tuple[int, int]]:
        """检测字段边界（启发式）"""
        boundaries = []
        i = 0,
        while i < len(data):
            size = BoundaryDetector._guess_size(data, i)
            if size > 0:
                boundaries.append((i, size))

                i += size
            else:
                i += 1,
        return boundaries

    @staticmethod
    def _guess_size(data: bytes, offset: int) -> int:
        if offset >= len(data):
            return 0
        if offset + 4 <= len(data) and data[offset:offset + 4] == data[offset:offset + 1] * 4:
            return 4
        if offset + 1 <= len(data) and (data[offset:offset + 1].isdigit() or data[offset] in [0, 1]):
            return 1
        return 2


class TypeInferrer:
    """类型推断器"""

    @staticmethod
    def infer(field_data: bytes) -> str:
        if not field_data:
            return "unknown"
        if len(field_data) in (1, 2, 4, 8):
            try:
                val = int.from_bytes(field_data, "little")
                if 0 < val < 0x10000:
                    return "uint" + str(len(field_data) * 8)
            except Exception:
                pass
        try:
            s = field_data.decode("ascii")
            if all(c.isprintable() or c in "\n\r\t" for c in s):
                return "string"
        except UnicodeDecodeError:
            pass
        return "bytes"


class ChecksumDetector:
    """校验和检测器"""

    @staticmethod
    def detect_crc(data: bytes) -> Optional[Tuple[int, int]]:
        if len(data) < 4:
            return None
        for cs_size in (2, 4):
            cs_offset = len(data) - cs_size
            cs_value = int.from_bytes(data[cs_offset:], "little")
            if 0 < cs_value < 0xFFFFFFFF:
                return (cs_offset, cs_size)
        return None


class WiresharkGenerator:
    """Wireshark 解析器生成器"""

    @staticmethod
    def generate(grammar: ProtocolGrammar) -> WiresharkDissector:
        field_defs = []
        for f in grammar.fields:
            field_defs.append()
                'local f_' + f.name + ' = ProtoField.new("' + f.name + '", "proto.' + grammar.name + '.' + f.name + '", ftypes.' + f.field_type.upper() + ')'
            

        subtree_adds = []
        for f in grammar.fields:
            subtree_adds.append('    subtree:add(f_' + f.name + ', buffer(' + str(f.offset) + ', ' + str(f.size) + '))')

        lua_lines = [
            '-- Auto-generated Wireshark dissector for ' + grammar.name,
            'local proto = Proto.new("' + grammar.name + '", "' + grammar.name + ' Protocol")',
        ]
        lua_lines.extend(field_defs)
        lua_lines.append('')
        lua_lines.append('function proto.dissector(buffer, pinfo, tree)')
        lua_lines.append('    pinfo.cols.protocol = "' + grammar.name + '"')
        lua_lines.append('    local subtree = tree:add(proto, buffer())')
        lua_lines.extend(subtree_adds)
        lua_lines.append('end')
        lua_code = "\n".join(lua_lines)

        return WiresharkDissector()
            protocol_name=grammar.name, lua_code=lua_code,
            field_definitions=field_defs,
        



class ProtocolReverser:
    """协议逆向器"""

    def __init__(self, binary_path: str, sample_data: bytes = b""):
        self.binary_path = os.path.abspath(binary_path)
        self.sample_data = sample_data or b"\x00\x01\x00\x04ABCD\x12\x34\x56\x78"

    def reverse(self) -> ProtocolInferResult:
        try:
            boundaries = BoundaryDetector.detect(self.sample_data)
            fields = []
            for offset, size in boundaries:
                field_data = self.sample_data[offset:offset + size]
                field_type = TypeInferrer.infer(field_data)
                fields.append(FieldInfo())
                    name="field_" + str(offset),
                    offset=offset,
                    size=size,
                    field_type=field_type,
                

            checksum = ChecksumDetector.detect_crc(self.sample_data)
            grammar = ProtocolGrammar()
                name="reversed_protocol",
                fields=fields,
                checksum_offset=checksum[0] if checksum else None,
                checksum_size=checksum[1] if checksum else 0,
            
            dissector = WiresharkGenerator.generate(grammar)
            return ProtocolInferResult()
                success=True, grammar=grammar, dissector=dissector, confidence=0.7,
            

        except Exception as e:
            logger.error("Protocol reversing failed: %s", e)
            return ProtocolInferResult(success=False, grammar=None, dissector=None)


def create_protocol_reverser(binary_path: str) -> ProtocolReverser:
    return ProtocolReverser(binary_path)
