# 2026-07-26
# Property-based testing — forall / shrink / 字段类型推断
# 核心：生成大量随机输入→检验不变量→最小化反例。
# shrink 策略：贪心逐字节删除——对每个字节尝试去掉，若属性仍违反则保留。
from dataclasses import dataclass, field
from typing import List, Dict, Any, Callable, Optional, Tuple
from enum import Enum, auto
import math
import collections


class FieldType(Enum):
    UNKNOWN = auto()
    COUNTER = auto()    # incrementing values
    ENUM = auto()       # few unique values
    FLAGS = auto()      # bit-flags pattern
    KEY = auto()        # high entropy random
    HASH = auto()       # fixed-width high entropy
    TIMESTAMP = auto()  # plausible time range
    STRING = auto()     # printable ASCII range
    LENGTH = auto()     # correlates with another field's size
    CHECKSUM = auto()   # appears to validate other data
    NULL = auto()       # always zero


@dataclass
class Counterexample:
    input_data: bytes
    failed_property: str
    shrink_attempts: int = 0
    minimal_input: bytes = b""

@dataclass
class FieldAnalysis:
    offset: int
    size: int
    field_type: FieldType
    entropy: float
    unique_count: int
    confidence: float


# ================================================
class PropertyTester:
    """Property-based 测试引擎。

    典型用法：
        pt = PropertyTester(seed=42)
        def gen(rng): return bytes([rng.randint(0,255) for _ in range(64)])
        def prop(data): return len(data) == 64  # passes
        ce = pt.forall(gen, prop, count=1000)
    """

    def __init__(self, seed: int = None):
        import random
        self._rng = random.Random(seed)

    # ---- forall ----
    def forall(self, generator: Callable[[], bytes],
               property_func: Callable[[bytes], bool],
               count: int = 1000) -> Optional[Counterexample]:
        """生成 count 个输入，测试 property_func。
        若全部通过则返回 None，否则返回第一个 Counterexample。
        """
        for _i in range(count):
            _data = generator()
            try:
                _holds = property_func(_data)
            except Exception:
                _holds = False
            if not _holds:
                _ce = Counterexample(
                    input_data=_data,
                    failed_property=property_func.__name__,
                )
                # 最小化反例
                _min = self.shrink(_data, property_func)
                _ce.minimal_input = _min
                _ce.shrink_attempts = 1  # will be updated inside shrink
                return _ce
        return None

    # ---- shrink ----
    def shrink(self, data: bytes,
               property_func: Callable[[bytes], bool],
               max_iterations: int = 500) -> bytes:
        """贪心字节删除收缩。逐字节尝试移除；
        若移除后属性仍违反，保留移除（= 数据变小）。
        再尝试二分缩短。
        """
        _current = bytearray(data)
        _attempts = 0

        # Phase 1: 逐字节删除
        _i = len(_current) - 1
        while _i >= 0 and _attempts < max_iterations:
            _candidate = bytes(_current[:_i] + _current[_i + 1:])
            _attempts += 1
            try:
                _still_fails = not property_func(_candidate)
            except Exception:
                _still_fails = True
            if _still_fails:
                del _current[_i]
            _i -= 1

        # Phase 2: 长度减半
        _sz = len(_current)
        while _sz > 1 and _attempts < max_iterations:
            _half = _sz // 2
            _candidate = bytes(_current[:_half])
            _attempts += 1
            try:
                _still_fails = not property_func(_candidate)
            except Exception:
                _still_fails = True
            if _still_fails:
                _current = bytearray(_candidate)
                _sz = len(_current)
            else:
                break

        return bytes(_current)

    # ---- field type inference ----
    def infer_field_types(self, data_samples: List[bytes],
                          field_width: int = 4) -> Dict[int, FieldAnalysis]:
        """分析多个样本中的字节序列，推断字段类型。
        按 field_width 分块，逐块分析熵值、唯一值数、模式特征。
        """
        if not data_samples:
            return {}
        _min_len = min(len(_d) for _d in data_samples)
        _fields = {}

        for _offset in range(0, _min_len, field_width):
            _end = min(_offset + field_width, _min_len)
            _width = _end - _offset
            _chunks = []
            for _d in data_samples:
                _chunks.append(_d[_offset:_end])

            _unique = len(set(_chunks))
            _ent = self._entropy([int.from_bytes(_c, 'big') for _c in _chunks])

            _ft = self._classify_field(_chunks, _unique, _ent, len(data_samples))
            _conf = min(1.0, (1.0 - (_ent / 8.0)) + (_unique / max(len(data_samples), 1)) * 0.3)

            _fields[_offset] = FieldAnalysis(
                offset=_offset, size=_width,
                field_type=_ft, entropy=_ent,
                unique_count=_unique, confidence=_conf,
            )
        return _fields

    def _entropy(self, values: List[int]) -> float:
        """Shannon entropy of integer values in bits。"""
        if not values:
            return 0.0
        _counter = collections.Counter(values)
        _total = len(values)
        _ent = 0.0
        for _count in _counter.values():
            _p = _count / _total
            if _p > 0:
                _ent -= _p * math.log2(_p)
        return _ent

    def _classify_field(self, chunks: List[bytes], unique_count: int,
                        entropy: float, total: int) -> FieldType:
        """基于熵 + 唯一值比例分类字段。"""
        _uniq_ratio = unique_count / max(total, 1)

        # All zeros -> NULL
        if all(_c == b'\x00' * len(_c) for _c in chunks):
            return FieldType.NULL

        # Few unique > ENUM
        if unique_count <= 8 and total > 8:
            return FieldType.ENUM

        # Check for counter pattern
        if len(chunks) >= 4:
            _vals = [int.from_bytes(_c, 'big') for _c in chunks]
            _diffs = [_vals[i + 1] - _vals[i] for i in range(len(_vals) - 1)]
            _pos_diffs = [_d for _d in _diffs if 0 < _d <= 10]
            if len(_pos_diffs) > len(_diffs) * 0.6:
                return FieldType.COUNTER

        # High entropy, many unique -> KEY/HASH
        if entropy > 6.0 and _uniq_ratio > 0.8:
            return FieldType.KEY

        # Printable ASCII range
        if all(32 <= _c[0] < 127 for _c in chunks if _c):
            return FieldType.STRING

        # Timestamp range (rough: 1.3e9 to 2.5e9 = 2011-2050)
        if len(chunks[0]) >= 4:
            _vals = [int.from_bytes(_c, 'big') for _c in chunks]
            _in_range = [1_300_000_000 < _v < 2_500_000_000 for _v in _vals]
            if all(_in_range):
                return FieldType.TIMESTAMP

        # Many bit-flag-like values
        if entropy < 3.0 and unique_count <= 32:
            return FieldType.FLAGS

        return FieldType.UNKNOWN

    # ---- property suite ----
    def run_property_suite(self, test_name: str,
                           generators: Dict[str, Callable],
                           properties: Dict[str, Callable]) -> Dict[str, Any]:
        """运行完整的 property test suite。
        对每个 generator x property 组合执行 forall。
        """
        _results = {}
        for _g_name, _gen in generators.items():
            for _p_name, _prop in properties.items():
                _key = f"{test_name}/{_g_name}/{_p_name}"
                _ce = self.forall(_gen, _prop, count=200)
                _results[_key] = {
                    "passed": _ce is None,
                    "counterexample": _ce,
                }
        return _results
