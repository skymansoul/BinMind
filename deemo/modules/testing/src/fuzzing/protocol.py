# 2026-07-23
# Protocol reverse engineering — 从报文样本推断协议结构
# 方法：多序列对齐 + 熵分析 + 长度字段检测。
# 输出：ProtocolSpec + Kaitai Struct .ksy 文件。
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
import struct
import math
import collections


@dataclass
class FieldSpec:
    name: str
    offset: int
    size: int
    field_type: str  # u1, u2, u4, u8, bytes, string, magic
    endianness: str = "big"
    is_length_field: bool = False
    references_field: str = ""  # which field's length this encodes
    is_const: bool = False
    const_value: bytes = b""


@dataclass
class ProtocolSpec:
    fields: List[FieldSpec] = field(default_factory=list)
    endianness: str = "big"
    alignment: int = 1
    name: str = "unknown_protocol"
    magic_bytes: bytes = b""


# ================================================
class ProtocolAnalyzer:
    """从网络报文样本中推断协议结构。

    算法：
    1. 多序列对齐找固定字节
    2. 按行熵切片找字段边界
    3. 检测长度字段（值与另一个字段长度匹配）
    4. 识别常量（magic bytes）
    """

    def __init__(self, min_field_size: int = 1, max_field_size: int = 64):
        self.min_field_size = min_field_size
        self.max_field_size = max_field_size

    def analyze(self, samples: List[bytes],
                protocol_name: str = "") -> ProtocolSpec:
        """分析报文样本，返回推断的协议结构。"""
        if not samples:
            return ProtocolSpec(name=protocol_name)

        _spec = ProtocolSpec(name=protocol_name)
        _min_len = min(len(_s) for _s in samples)

        # 1. 找到固定字节 (常量字段)
        _const_mask = bytearray([0xFF] * _min_len)
        for _i in range(_min_len):
            _b = samples[0][_i]
            for _s in samples[1:]:
                if _s[_i] != _b:
                    _const_mask[_i] = 0x00
                    break

        # 2. 基于固定/变化边界的字段分块
        _fields = self.detect_field_boundaries(samples, _const_mask)
        _spec.fields = _fields

        # 3. 检测 magic bytes
        _magic = bytearray()
        for _i in range(_min_len):
            if _const_mask[_i] == 0xFF:
                _magic.append(samples[0][_i])
            else:
                break
        _spec.magic_bytes = bytes(_magic)

        # 4. 检测长度字段
        self._detect_length_fields(_spec, samples)

        # 5. 检测字节序
        _spec.endianness = self._detect_endianness(samples)

        return _spec

    def detect_field_boundaries(self, samples: List[bytes],
                                const_mask: bytearray = None) -> List[FieldSpec]:
        """基于每字节的熵变化找字段边界。
        熵突变位置 = 新 field 的开始。
        """
        if not samples:
            return []
        _min_len = min(len(_s) for _s in samples)

        # 逐字节计算熵
        _entropies = []
        for _i in range(_min_len):
            _vals = [_s[_i] for _s in samples]
            _counter = collections.Counter(_vals)
            _ent = 0.0
            for _c in _counter.values():
                _p = _c / len(_vals)
                if _p > 0:
                    _ent -= _p * math.log2(_p)
            _entropies.append(_ent)

        # 分割字段：熵变化 > 阈值 → 新 field
        _fields = []
        _start = 0
        _threshold = 1.5  # entropy change threshold

        for _i in range(1, _min_len):
            _delta = abs(_entropies[_i] - _entropies[_i - 1])
            if _delta > _threshold and _i - _start >= self.min_field_size:
                _fields.append(self._make_field(_start, _i - _start, "bytes"))
                _start = _i
            elif _i - _start >= self.max_field_size:
                _fields.append(self._make_field(_start, _i - _start, "bytes"))
                _start = _i

        # 剩余
        if _start < _min_len:
            _fields.append(self._make_field(_start, _min_len - _start, "bytes"))

        return _fields

    def _make_field(self, offset: int, size: int, ftype: str) -> FieldSpec:
        _name = f"field_{offset}"
        return FieldSpec(name=_name, offset=offset, size=size, field_type=ftype)

    def _detect_length_fields(self, spec: ProtocolSpec, samples: List[bytes]):
        """检测长度字段：字段值 = 另一字段/剩余数据大小。"""
        if not samples:
            return
        _s = samples[0]
        for _f in spec.fields:
            if _f.size <= 4:  # only small fixed fields can be lengths
                _val = int.from_bytes(
                    _s[_f.offset:_f.offset + _f.size], spec.endianness)
                # 检查是否等于后面字段的长度
                _remaining_start = _f.offset + _f.size
                _remaining_len = len(_s) - _remaining_start
                if _val == _remaining_len:
                    _f.is_length_field = True
                    _f.field_type = f"u{_f.size * 8}"
                    _f.references_field = "payload"
                # 检查是否等于后面某个 field 的长度
                for _f2 in spec.fields:
                    if _f2.offset == _f.offset + _f.size and _f2.size == _val:
                        _f.is_length_field = True
                        _f.field_type = f"u{_f.size * 8}"
                        _f.references_field = _f2.name
                        break

    def _detect_endianness(self, samples: List[bytes]) -> str:
        """通过比较小端/大端解析结果与合理的取值范围推断字节序。"""
        if not samples:
            return "big"
        _s = samples[0]
        _big_count = 0
        _little_count = 0
        for _i in range(0, min(len(_s) - 3, 32), 4):
            _chunk = _s[_i:_i + 4]
            _big_val = int.from_bytes(_chunk, 'big')
            _little_val = int.from_bytes(_chunk, 'little')
            # 小端更可能产生较小值（合理范围 0-65535）
            if _little_val < 65536:
                _little_count += 1
            if _big_val < 65536:
                _big_count += 1
            # 极大值不像是合理的字段值
        return "little" if _little_count > _big_count else "big"


# ================================================
class KaitaiStructGenerator:
    """从 ProtocolSpec 生成 Kaitai Struct .ksy 文件。"""

    def generate(self, spec: ProtocolSpec) -> str:
        """生成 .ksy YAML 内容。"""
        _lines = [
            "meta:",
            f"  id: {spec.name}",
            f"  endian: {'le' if spec.endianness == 'little' else 'be'}",
            "  file-extension: bin",
            "seq:",
        ]
        for _f in spec.fields:
            _type = self._map_type(_f)
            if _f.is_length_field:
                _lines.append(f"  - id: {_f.name}")
                _lines.append(f"    type: {_type}")
            else:
                _lines.append(f"  - id: {_f.name}")
                _lines.append(f"    size: {_f.size}" if _type == "bytes" else f"    type: {_type}")

        if spec.magic_bytes:
            _lines.insert(len(_lines), "  - id: magic")
            _lines.insert(len(_lines), "    contents: [{}]".format(
                ", ".join(f"0x{b:02x}" for b in spec.magic_bytes)))

        return "\n".join(_lines)

    def _map_type(self, field: FieldSpec) -> str:
        if field.field_type.startswith("u"):
            _b = int(field.field_type[1:]) // 8
            return f"u{_b}"
        return "bytes"
