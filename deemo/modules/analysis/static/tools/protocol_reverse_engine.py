# 2026-07-24
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from collections import Counter
import re


@dataclass
class Message:
    index: int
    direction: str  # '发送' or 'recv'
    data: bytes
    timestamp: float = 0.0
    parsed_fields: List = field(default_factory=list)


@dataclass
class Field:
    name: str = ""
    offset: int = 0
    size: int = 0
    field_type: str = "unknown"  # magic, length, 校验和, data, type, unknown
    value = None


@dataclass
class StateMachine:
    states: List[str] = field(default_factory=list)
    transitions: List[dict] = field(default_factory=list)
    # transition: {'': str, '': str, 'trigger_idx': int}


class ProtocolReverseEngine:
    # ---- 初始化，内置常见协议magic byte ----

    def __init__(self, messages=None):
        self._msgs = messages or []
        self._known_magics = {
            b'\x16\x03\x01': 'TLS ClientHello',
            b'\x16\x03\x03': 'TLS ApplicationData',
            b'\x16\x03\x02': 'TLS ServerHello',
            b'GET ': 'HTTP GET',
            b'POST': 'HTTP POST',
            b'HTTP': 'HTTP Response',
            b'HEAD': 'HTTP HEAD',
            b'\x00\x00\x00': 'SMB Header',
            b'\xff\x53\x4d\x42': 'SMBv1',
            b'SSH-': 'SSH Banner',
            b'\x03\x00\x00': 'RDP TPKT',
            b'\x00\x01\x00': 'ModbusTCP',
            b'GIOP': 'CORBA GIOP',
        }

    # ---- magic byte检测: 已知签名 + 统计高频前缀 ----

    def detect_magic_bytes(self, messages=None) -> List[dict]:
        if messages is None:
            messages = self._msgs
        _r = []
        _done = set()

        for _m in messages:
            _d = _m.data if isinstance(_m, Message) else _m
            if len(_d) < 2:
                continue
            for _prefix_len in [2, 3, 4, 5]:
                if len(_d) < _prefix_len:
                    continue
                _pfx = _d[:_prefix_len]
                if _pfx in _done:
                    continue
                _done.add(_pfx)
                if _pfx in self._known_magics:
                    _r.append({
                        'offset': 0,
                        'bytes_hex': _pfx.hex(),
                        'protocol': self._known_magics[_pfx],
                        'confidence': 0.9,
                        'method': 'known_signature',
                    })
                elif _pfx[:2] in self._known_magics:
                    _r.append({
                        'offset': 0,
                        'bytes_hex': _pfx[:2].hex(),
                        'protocol': self._known_magics[_pfx[:2]],
                        'confidence': 0.7,
                        'method': 'partial_match',
                    })

        # 统计高频前缀: 出现在 >80% 消息中的字节序列
        _total = len(messages)
        if _total >= 5:
            _pfx_count = Counter()
            for _m in messages:
                _d = _m.data if isinstance(_m, Message) else _m
                if len(_d) >= 4:
                    _pfx_count[_d[:2]] += 1
                    _pfx_count[_d[:4]] += 1
            for _pfx, _cnt in _pfx_count.items():
                _freq = _cnt / _total
                if _freq >= 0.8 and _pfx not in _done:
                    _r.append({
                        'offset': 0,
                        'bytes_hex': _pfx.hex(),
                        'protocol': 'unknown',
                        'confidence': _freq,
                        'method': 'statistical_prefix',
                    })

        return _r

    # //// 校验和暴力识别: CRC32, CRC16 variants, XOR, ADD, Fletcher, Adler ////

    def identify_checksum(self, traces=None) -> List[dict]:
        if traces is None:
            traces = self._msgs
        _r = []
        if len(traces) < 2:
            return _r

        _datas = [t.data if isinstance(t, Message) else t for t in traces]
        _min_len = min(len(d) for d in _datas)

        # 检查末尾1/2/4字节作为checksum
        for _cs_len in [1, 2, 4]:
            if _min_len <= _cs_len + 4:
                continue

            # XOR8: 所有字节异或
            _match = 0
            for _d in _datas:
                _payload = _d[:-_cs_len]
                _expected = _d[-_cs_len:]
                _xor_val = 0
                for _b in _payload:
                    _xor_val ^= _b
                if _cs_len == 1 and _xor_val == _expected[0]:
                    _match += 1
                elif _cs_len == 2:
                    if _xor_val == struct.unpack('<H', _expected)[0]:
                        _match += 1
            if _match >= len(_datas) * 0.7:
                _r.append({
                    'position': f'last_{_cs_len}_bytes',
                    'algorithm': f'XOR{8*_cs_len}',
                    'confidence': _match / len(_datas),
                    'match_count': _match,
                })

            # ADD16/ADD32: 求和取模
            if _cs_len >= 2:
                _match = 0
                for _d in _datas:
                    _payload = _d[:-_cs_len]
                    _expected = _d[-_cs_len:]
                    _sm = sum(_payload)
                    if _cs_len == 2:
                        _sm = _sm & 0xFFFF
                        if struct.pack('<H', _sm) == _expected:
                            _match += 1
                    elif _cs_len == 4:
                        _sm = _sm & 0xFFFFFFFF
                        if struct.pack('<I', _sm) == _expected:
                            _match += 1
                if _match >= len(_datas) * 0.7:
                    _r.append({
                        'position': f'last_{_cs_len}_bytes',
                        'algorithm': f'ADD{8*_cs_len}',
                        'confidence': _match / len(_datas),
                        'match_count': _match,
                    })

            # CRC32
            if _cs_len == 4:
                _match = 0
                for _d in _datas:
                    _payload = _d[:-4]
                    _expected = _d[-4:]
                    _crc = self._crc32(_payload)
                    if struct.pack('<I', _crc) == _expected or struct.pack('>I', _crc) == _expected:
                        _match += 1
                if _match >= len(_datas) * 0.7:
                    _r.append({
                        'position': 'last_4_bytes',
                        'algorithm': 'CRC32',
                        'confidence': _match / len(_datas),
                        'match_count': _match,
                    })

            # CRC16-CCITT
            if _cs_len == 2:
                _match = 0
                for _d in _datas:
                    _payload = _d[:-2]
                    _expected = _d[-2:]
                    _crc = self._crc16(_payload)
                    if struct.pack('<H', _crc) == _expected or struct.pack('>H', _crc) == _expected:
                        _match += 1
                if _match >= len(_datas) * 0.7:
                    _r.append({
                        'position': 'last_2_bytes',
                        'algorithm': 'CRC16-CCITT',
                        'confidence': _match / len(_datas),
                        'match_count': _match,
                    })

            # Fletcher-16
            if _cs_len == 2:
                _match = 0
                for _d in _datas:
                    _payload = _d[:-2]
                    _expected = _d[-2:]
                    _fh = self._fletcher16(_payload)
                    if struct.pack('<H', _fh) == _expected:
                        _match += 1
                if _match >= len(_datas) * 0.7:
                    _r.append({
                        'position': 'last_2_bytes',
                        'algorithm': 'Fletcher-16',
                        'confidence': _match / len(_datas),
                        'match_count': _match,
                    })

            # Adler-32
            if _cs_len == 4:
                _match = 0
                for _d in _datas:
                    _payload = _d[:-4]
                    _expected = _d[-4:]
                    _adl = self._adler32(_payload)
                    if struct.pack('>I', _adl) == _expected:
                        _match += 1
                if _match >= len(_datas) * 0.7:
                    _r.append({
                        'position': 'last_4_bytes',
                        'algorithm': 'Adler-32',
                        'confidence': _match / len(_datas),
                        'match_count': _match,
                    })

        return _r

    # ===== 状态机提取: 从send/recv序列聚类消息类型，构建转移矩阵 =====

    def extract_state_machine(self, messages=None) -> StateMachine:
        if messages is None:
            messages = self._msgs
        if not messages:
            return StateMachine()

        _type_ids = []
        _type_map = {}
        # 用direction + 长度取模 + 首字节聚类消息类型
        for _m in messages:
            _d = _m.data if isinstance(_m, Message) else _m
            _dir = _m.direction if isinstance(_m, Message) else 'unknown'
            _sig = (_dir, len(_d) % 4, _d[0] if len(_d) > 0 else 0)
            if _sig not in _type_map:
                _type_map[_sig] = f"state_{len(_type_map)}"
            _type_ids.append(_type_map[_sig])

        _states = list(set(_type_ids))
        _transitions = []
        _trans_set = set()
        for _i in range(len(_type_ids) - 1):
            _pair = (_type_ids[_i], _type_ids[_i + 1], _i + 1)
            if (_pair[0], _pair[1]) not in _trans_set:
                _trans_set.add((_pair[0], _pair[1]))
                _transitions.append({
                    'from': _pair[0],
                    'to': _pair[1],
                    'trigger_idx': _pair[2],
                })

        return StateMachine(states=_states, transitions=_transitions)

    # ---- 编码检测: JSON/Protobuf/XML/binary ----

    def detect_encoding(self, data: bytes) -> str:
        if len(data) == 0:
            return 'empty'

        _first_byte = data[0]

        # JSON
        if _first_byte in (0x7B, 0x5B):  # '{' or '['
            _txt = data[:256]
            if b'"' in _txt and (b':' in _txt or b']' in _txt):
                return 'json'

        # XML
        if _first_byte == 0x3C:  # '<'
            if b'>' in data[:128] and (b'<?xml' in data[:64] or b'</' in data[:256]):
                return 'xml'

        # Protobuf: varint模式 (高位bit=1表示continuation)
        if len(data) >= 2:
            _varint_cnt = 0
            for _i in range(min(16, len(data) - 1)):
                if data[_i] & 0x80:
                    _varint_cnt += 1
            if _varint_cnt >= 3 and _first_byte < 16:
                return 'protobuf'

        # msgpack: fixmap/fixarray range
        if 0x80 <= _first_byte <= 0x9F or 0xA0 <= _first_byte <= 0xBF:
            return 'msgpack'

        return 'binary'

    # //// 字段结构推断: 对齐消息，找constant/variable/length/type字段 ////

    def infer_field_structure(self, messages=None) -> List[Field]:
        if messages is None:
            messages = self._msgs
        if not messages:
            return []

        _datas = [m.data if isinstance(m, Message) else m for m in messages]
        _min_len = min(len(d) for d in _datas)
        if _min_len == 0:
            return []

        _fields = []
        # 逐offset检查所有消息
        for _off in range(min(_min_len, 64)):
            _vals = [_d[_off] for _d in _datas]
            _unique = set(_vals)
            _is_const = len(_unique) == 1
            _is_variable = len(_unique) > 1

            # 检查是否为length字段: 值 == 后续数据长度
            _is_len = False
            if len(_datas) >= 3:
                _l_match = 0
                for _d in _datas:
                    if _off + 1 < len(_d):
                        _val_at_offset = _d[_off]
                        _remaining = len(_d) - _off - 1
                        # 单字节length
                        if _val_at_offset == _remaining:
                            _l_match += 1
                        # 2字节LE length
                        elif _off + 2 < len(_d):
                            _v16 = struct.unpack('<H', _d[_off:_off + 2])[0]
                            if _v16 == len(_d) - _off - 2:
                                _l_match += 1
                if _l_match >= len(_datas) * 0.6:
                    _is_len = True

            _ft = 'constant' if _is_const else ('length' if _is_len else 'variable')
            if _is_const and _off < 4:
                _ft = 'magic'
            elif _is_variable and len(_unique) <= 8 and len(_unique) > 1:
                _ft = 'type'

            _fields.append(Field(
                offset=_off,
                size=1,
                field_type=_ft,
                value=list(_unique)[:8] if _unique else None,
            ))

        return _fields

    # ===== 全流程流水线 =====

    def analyze(self, messages=None) -> dict:
        if messages is not None:
            self._msgs = messages
        _msgs = self._msgs
        if not _msgs:
            return {'error': 'no messages provided'}

        _magics = self.detect_magic_bytes(_msgs)
        _checksums = self.identify_checksum(_msgs)
        _fields = self.infer_field_structure(_msgs)
        _sm = self.extract_state_machine(_msgs)

        # encoding从第一条消息检测
        _first_data = _msgs[0].data if isinstance(_msgs[0], Message) else _msgs[0]
        _enc = self.detect_encoding(_first_data) if isinstance(_first_data, bytes) else 'unknown'

        return {
            'magic_bytes': _magics,
            'encoding': _enc,
            'checksums': _checksums,
            'fields': _fields,
            'state_machine': _sm,
        }

    # ---- 校验和算法实现 ----

    def _crc32(self, data: bytes) -> int:
        _table = self._crc32_table()
        _crc = 0xFFFFFFFF
        for _b in data:
            _idx = (_crc ^ _b) & 0xFF
            _crc = (_crc >> 8) ^ _table[_idx]
        return _crc ^ 0xFFFFFFFF

    def _crc32_table(self) -> List[int]:
        _t = []
        for _i in range(256):
            _v = _i
            for _j in range(8):
                if _v & 1:
                    _v = (_v >> 1) ^ 0xEDB88320
                else:
                    _v >>= 1
            _t.append(_v)
        return _t

    def _crc16(self, data: bytes) -> int:
        _crc = 0xFFFF
        for _b in data:
            _crc ^= _b << 8
            for _ in range(8):
                if _crc & 0x8000:
                    _crc = ((_crc << 1) ^ 0x1021) & 0xFFFF
                else:
                    _crc = (_crc << 1) & 0xFFFF
        return _crc

    def _adler32(self, data: bytes) -> int:
        _mod = 65521
        _a, _b = 1, 0
        for _byte in data:
            _a = (_a + _byte) % _mod
            _b = (_b + _a) % _mod
        return (_b << 16) | _a

    def _fletcher16(self, data: bytes) -> int:
        _s1, _s2 = 0, 0
        for _b in data:
            _s1 = (_s1 + _b) % 255
            _s2 = (_s2 + _s1) % 255
        return (_s2 << 8) | _s1
