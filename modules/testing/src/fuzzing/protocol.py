"""协议逆向工程——多序列对齐 + 熵分析 -> 字段边界 -> ProtocolSpec + Kaitai Struct"""
import os
from dataclasses import dataclass, field
from typing import List, Dict, Any
from collections import Counter, defaultdict
import math


@dataclass
class FieldSpec:
    name: str
    offset: int
    size: int
    field_type: str  # u1, u2, u4, u8, bytes, string, magic
    endianness: str = "big"
    is_length_field: bool = False
    references_field: str = ""
    is_const: bool = False
    const_value: bytes = b""


@dataclass
class ProtocolSpec:
    fields: List[FieldSpec] = field(default_factory=list)
    endianness: str = "big"
    alignment: int = 1
    name: str = "unknown_protocol"
    magic_bytes: bytes = b""


class ProtocolAnalyzer:
    """报文样本协议结构推断——固定字节检测 + 熵切片 + 长度字段关联"""

    def __init__(self, min_field_size: int = 1, max_field_size: int = 64):
        self.min_field_size = min_field_size
        self.max_field_size = max_field_size

    def analyze(self, samples: List[bytes],
                protocol_name: str = "") -> ProtocolSpec:
        """分析报文样本，返回推断的协议结构"""
        if not samples:
            return ProtocolSpec(name=protocol_name)

        _spec = ProtocolSpec(name=protocol_name)
        _min_len = min(len(_s) for _s in samples)

        _const_mask = bytearray([0xFF] * _min_len)
        for _i in range(_min_len):
            _b = samples[0][_i]
            for _s in samples[1:]:
                if _s[_i] != _b:
                    _const_mask[_i] = 0x00
                    break

        _fields = self.detect_field_boundaries(samples, _const_mask)
        _spec.fields = _fields

        _magic = bytearray()
        for _i in range(_min_len):
            if _const_mask[_i] == 0xFF:
                _magic.append(samples[0][_i])
            else:
                break
        _spec.magic_bytes = bytes(_magic)

        self._detect_length_fields(_spec, samples)
        _spec.endianness = self._detect_endianness(samples)

        return _spec

    def detect_field_boundaries(self, samples: List[bytes],
                                const_mask: bytearray = None) -> List[FieldSpec]:
        """逐字节熵变化检测字段边界——熵突变处为新字段起点"""
        if not samples:
            return []
        _min_len = min(len(_s) for _s in samples)

        _entropies = []
        for _i in range(_min_len):
            _vals = [_s[_i] for _s in samples]
            _counter = Counter(_vals)
            _ent = 0.0
            for _c in _counter.values():
                _p = _c / len(_vals)
                if _p > 0:
                    _ent -= _p * math.log2(_p)
            _entropies.append(_ent)

        _fields = []
        _start = 0
        _threshold = 1.5

        for _i in range(1, _min_len):
            _delta = abs(_entropies[_i] - _entropies[_i - 1])
            if _delta > _threshold and _i - _start >= self.min_field_size:
                _fields.append(self._make_field(_start, _i - _start, "bytes"))
                _start = _i
            elif _i - _start >= self.max_field_size:
                _fields.append(self._make_field(_start, _i - _start, "bytes"))
                _start = _i

        if _start < _min_len:
            _fields.append(self._make_field(_start, _min_len - _start, "bytes"))

        return _fields

    def _make_field(self, offset: int, size: int, ftype: str) -> FieldSpec:
        _name = f"field_{offset}"
        return FieldSpec(name=_name, offset=offset, size=size, field_type=ftype)

    def _detect_length_fields(self, spec: ProtocolSpec, samples: List[bytes]):
        """长度字段检测——字段值等于后方字段或剩余数据大小"""
        if not samples:
            return
        _s = samples[0]
        for _f in spec.fields:
            if _f.size <= 4:
                _val = int.from_bytes(
                    _s[_f.offset:_f.offset + _f.size], spec.endianness)
                _remaining_start = _f.offset + _f.size
                _remaining_len = len(_s) - _remaining_start
                if _val == _remaining_len:
                    _f.is_length_field = True
                    _f.field_type = f"u{_f.size * 8}"
                    _f.references_field = "payload"
                for _f2 in spec.fields:
                    if _f2.offset == _f.offset + _f.size and _f2.size == _val:
                        _f.is_length_field = True
                        _f.field_type = f"u{_f.size * 8}"
                        _f.references_field = _f2.name
                        break

    def _detect_endianness(self, samples: List[bytes]) -> str:
        """通过比较大小端解析值与合理范围推断字节序"""
        if not samples:
            return "big"
        _s = samples[0]
        _big_count = 0
        _little_count = 0
        for _i in range(0, min(len(_s) - 3, 32), 4):
            _chunk = _s[_i:_i + 4]
            _big_val = int.from_bytes(_chunk, 'big')
            _little_val = int.from_bytes(_chunk, 'little')
            if _little_val < 65536:
                _little_count += 1
            if _big_val < 65536:
                _big_count += 1
        return "little" if _little_count > _big_count else "big"


class KaitaiStructGenerator:
    """ProtocolSpec 到 Kaitai Struct YAML 导出"""

    def generate(self, spec: ProtocolSpec) -> str:
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


class ProtocolFormatReverseEngineer:
    """协议格式逆向——静态推断 + 动态熵分析双轨策略"""

    def __init__(self):
        self.inferred_fields: List[Dict[str, Any]] = []
        self.protocol_hints: Dict[str, Any] = {}
        self._field_dictionary: Dict[str, List[bytes]] = defaultdict(list)

    def analyze_from_binary(self, binary_path: str) -> Dict[str, Any]:
        """从二进制分析协议格式——解析函数识别 + 字段推断"""
        result = {
            'binary': binary_path,
            'inferred_fields': [],
            'message_types': [],
            'fuzz_harness': ''
        }

        parse_funcs = self._find_parse_functions(binary_path)
        result['message_types'] = parse_funcs
        result['inferred_fields'] = self._infer_fields(binary_path)
        result['fuzz_harness'] = self._generate_fuzz_harness(result)

        self.inferred_fields = result['inferred_fields']
        return result

    def _find_parse_functions(self, binary_path: str) -> List[Dict[str, Any]]:
        funcs = []
        return funcs

    def _infer_fields(self, binary_path: str) -> List[Dict[str, Any]]:
        """常见协议字段推断——魔数/长度/类型/校验和"""
        fields = []

        field_patterns = [
            ('magic', 4, '魔数校验'),
            ('length', 4, '载荷长度字段'),
            ('type', 2, '消息类型判别'),
            ('checksum', 4, '完整性校验和')
        ]

        for name, size, desc in field_patterns:
            fields.append({
                'name': name,
                'size': size,
                'description': desc,
                'offset': 0
            })

        return fields

    def _generate_fuzz_harness(self, protocol_info: Dict[str, Any]) -> str:
        """从协议信息生成模糊测试 harness 骨架"""
        harness = '''
#include <stdint.h>
#include <stdio.h>

struct {{
}} message_t;

int parse_message(const uint8_t *data, size_t len) {{
    if (len < sizeof(message_t)) return -1;
    return 0;
}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    parse_message(data, size);
    return 0;
}}
'''
        return harness

    def infer_by_entropy(self, samples: List[bytes],
                         window: int = 8) -> List[Dict[str, Any]]:
        """滑动窗香农熵分析——低熵固定字段，高熵可变字段"""
        if not samples:
            return []
        max_len = max(len(s) for s in samples)
        aligned = [s.ljust(max_len, b'\x00') for s in samples]
        fields = []
        pos = 0
        while pos < max_len:
            window_bytes = [s[pos:pos + window] for s in aligned]
            counter: Counter = Counter()
            for w in window_bytes:
                counter.update(w)
            total = sum(counter.values())
            entropy = 0.0
            for cnt in counter.values():
                if cnt > 0:
                    p = cnt / total
                    entropy -= p * math.log2(p)
            normalized = entropy / 8.0
            fields.append({
                'offset': pos,
                'size': window,
                'entropy': round(normalized, 3),
                'likely_type': 'variable' if normalized > 0.7 else 'fixed',
            })
            pos += window
        return fields

    def build_token_dictionary(self, messages: List[bytes]) -> Dict[str, int]:
        """提取高频 4-16 字节片段作为变异字典——出现 >=3 次即收录"""
        freq: Dict[str, int] = defaultdict(int)
        for msg in messages:
            for n in (4, 8, 16):
                for i in range(0, len(msg) - n + 1):
                    token = msg[i:i + n]
                    freq[token.hex()] += 1
        filtered = {k: v for k, v in freq.items() if v >= 3}
        for hex_key in filtered:
            self._field_dictionary['tokens'].append(bytes.fromhex(hex_key))
        return filtered

    def generate_seed_corpus(self, samples: List[bytes]) -> str:
        """从样本字节生成种子语料目录"""
        seed_dir = "data/fuzzing/seeds"
        os.makedirs(seed_dir, exist_ok=True)

        for i, sample in enumerate(samples[:10]):
            seed_path = os.path.join(seed_dir, f"seed_{i:03d}.bin")
            with open(seed_path, 'wb') as f:
                f.write(sample)

        return seed_dir
