"""类型感知模糊测试结构生成——二进制/PCAP -> C 结构字段布局推断 + Kaitai Struct 导出"""
import math
import random
import os
from typing import List, Dict, Tuple, Optional, Set, Any
from collections import Counter, defaultdict


FIELD_TYPES = {
    'magic': '固定魔数',
    'length': '长度字段',
    'type': '消息类型/命令码',
    'checksum': '校验和/CRC',
    'counter': '递增计数器/序列号',
    'enum_flags': '枚举值/位标志',
    'string': 'ASCII/UTF-8 字符串',
    'raw': '未分类/有效载荷',
    'padding': '零填充',
    'timestamp': 'Unix 时间戳',
}


class TypeAwareField:
    """推断出的单个协议字段——偏移/大小/类型/置信度"""
    __slots__ = ("offset", "size", "field_type", "confidence",
                 "entropy", "sample_values")

    def __init__(self, offset: int, size: int, field_type: str,
                 confidence: float = 0.5):
        self.offset = offset
        self.size = size
        self.field_type = field_type
        self.confidence = confidence
        self.entropy = 0.0
        self.sample_values: List[bytes] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            'offset': self.offset, 'size': self.size,
            'type': self.field_type,
            'confidence': round(self.confidence, 3),
            'entropy': round(self.entropy, 3),
        }


class TypeAwareStructureInferer:
    """类型感知二进制结构推断——两阶段：多序列对齐边界 + 逐字段类型分类"""

    def __init__(self, min_samples: int = 4):
        self._min_samples = min_samples
        self._fields: List[TypeAwareField] = []

    def infer_fields(self, samples: List[bytes]) -> List[TypeAwareField]:
        """从样本集同时推断字段边界和类型"""
        if len(samples) < self._min_samples:
            return []

        max_len = max(len(s) for s in samples)
        aligned = [s.ljust(max_len, b'\x00') for s in samples]

        entropies = self._compute_position_entropies(aligned, max_len)
        segments = self._segment_by_entropy(entropies)

        self._fields = []
        for start, end in segments:
            field_data = [s[start:end] for s in aligned]
            ftype, conf = self._classify_field(field_data, start)
            field = TypeAwareField(start, end - start, ftype, conf)
            field.entropy = sum(entropies[start:end]) / max(1, end - start)
            field.sample_values = field_data[:8]
            self._fields.append(field)

        return self._fields

    def _compute_position_entropies(self, aligned: List[bytes],
                                    max_len: int) -> List[float]:
        ents = []
        for pos in range(max_len):
            counter = Counter(s[pos] for s in aligned)
            total = sum(counter.values())
            ent = 0.0
            for cnt in counter.values():
                if cnt > 0:
                    p = cnt / total
                    ent -= p * math.log2(p)
            ents.append(ent)
        return ents

    def _segment_by_entropy(self, entropies: List[float],
                            threshold: float = 0.5) -> List[Tuple[int, int]]:
        """按熵变化幅度聚类相邻位置——熵差超过阈值则切出新字段"""
        if not entropies:
            return []
        segments = []
        start = 0
        for i in range(1, len(entropies)):
            if abs(entropies[i] - entropies[i - 1]) > threshold:
                segments.append((start, i))
                start = i
        segments.append((start, len(entropies)))
        return self._merge_tiny_segments(segments, min_size=2)

    @staticmethod
    def _merge_tiny_segments(segments: List[Tuple[int, int]],
                             min_size: int = 2) -> List[Tuple[int, int]]:
        """合并过短片段到相邻段——优先左侧"""
        merged = []
        for seg in segments:
            if merged and (seg[1] - seg[0]) < min_size:
                prev = merged.pop()
                merged.append((prev[0], seg[1]))
            else:
                merged.append(seg)
        i = 0
        while i < len(merged):
            if merged[i][1] - merged[i][0] < min_size:
                if i + 1 < len(merged):
                    merged[i] = (merged[i][0], merged[i + 1][1])
                    del merged[i + 1]
                elif i > 0:
                    merged[i - 1] = (merged[i - 1][0], merged[i][1])
                    del merged[i]
                else:
                    i += 1
            else:
                i += 1
        return merged

    def _classify_field(self, values: List[bytes],
                        offset: int) -> Tuple[str, float]:
        """八条启发式规则分类字段类型"""
        unique = set(values)
        n_unique = len(unique)
        n_total = len(values)

        if all(v == b'\x00' * len(v) for v in values):
            return 'padding', 0.95

        if n_unique == 1 and n_total >= self._min_samples:
            return 'magic', 0.85

        if n_unique < max(2, n_total * 0.1):
            return 'enum_flags', 0.70

        if len(values) >= 3 and len(values[0]) <= 4:
            int_vals = [int.from_bytes(v, 'big') for v in values]
            diffs = [int_vals[i + 1] - int_vals[i]
                     for i in range(len(int_vals) - 1)
                     if int_vals[i + 1] > int_vals[i]]
            if diffs and all(0 < d <= 100 for d in diffs):
                return 'counter', 0.65

        if self._correlates_with_length(values, offset):
            return 'length', 0.60

        if len(values[0]) >= 4:
            int_vals = [int.from_bytes(v[:4], 'big') for v in values]
            if all(1_600_000_000 < v < 1_900_000_000 for v in int_vals):
                return 'timestamp', 0.75

        if all(all(0x20 <= b <= 0x7E for b in v) for v in values):
            return 'string', 0.80

        if n_unique == n_total and len(values[0]) in (2, 4):
            return 'checksum', 0.40

        return 'raw', 0.30

    def _correlates_with_length(self, values: List[bytes],
                                offset: int) -> bool:
        """检查字段值是否与后续数据长度相关"""
        if not values or len(values[0]) > 4:
            return False
        for v in values[:min(8, len(values))]:
            if len(v) <= 4:
                try:
                    predicted_len = int.from_bytes(v, 'big')
                    if 1 <= predicted_len <= 65535:
                        return True
                except Exception:
                    pass
        return False

    def generate(self, count: int = 32) -> List[bytes]:
        """基于推断字段类型生成结构保持的测试输入"""
        if not self._fields:
            return []

        results = []
        for _ in range(count):
            buf = bytearray()
            for field in self._fields:
                chunk = self._generate_field_value(field)
                buf.extend(chunk)
            results.append(bytes(buf))
        return results

    def _generate_field_value(self, field: TypeAwareField) -> bytes:
        """按字段类型生成合理的变异值——边界保持低变异概率，raw 高概率"""
        sz = field.size
        ftype = field.field_type

        if ftype == 'magic':
            if field.sample_values and random.random() > 0.05:
                return field.sample_values[0]
            return bytes(random.randint(0, 255) for _ in range(sz))

        if ftype == 'length':
            payload_guess = random.randint(0, 4096)
            return payload_guess.to_bytes(min(sz, 4), 'big')

        if ftype == 'enum_flags':
            if field.sample_values and random.random() > 0.5:
                return random.choice(field.sample_values)
            bitmask = random.randint(0, (1 << min(sz * 8, 32)) - 1)
            return bitmask.to_bytes(sz, 'big')

        if ftype == 'counter':
            base = random.randint(0, 65535)
            return base.to_bytes(min(sz, 4), 'big')

        if ftype == 'padding':
            return b'\x00' * sz

        if ftype in ('string', 'raw'):
            if ftype == 'string' and random.random() > 0.2:
                return bytes(random.randint(0x20, 0x7E) for _ in range(sz))
            return bytes(random.randint(0, 255) for _ in range(sz))

        if field.sample_values:
            return random.choice(field.sample_values)
        return bytes(random.randint(0, 255) for _ in range(sz))

    def mutate_preserve_structure(self, seed: bytes,
                                   rounds: int = 3) -> bytes:
        """结构保持变异——字段内部变异不破坏边界，magic/low 概率变异"""
        if not self._fields:
            return seed

        buf = bytearray(seed)
        for _ in range(rounds):
            field = random.choice(self._fields)
            if field.offset + field.size > len(buf):
                continue

            mutate_prob = {
                'magic': 0.05, 'padding': 0.02, 'length': 0.15,
                'counter': 0.20, 'enum_flags': 0.30,
                'checksum': 0.10, 'string': 0.50, 'raw': 0.60,
            }.get(field.field_type, 0.40)

            if random.random() > mutate_prob:
                continue

            for _2 in range(max(1, field.size // 4)):
                rel_pos = random.randint(0, field.size - 1)
                abs_pos = field.offset + rel_pos
                if random.random() < 0.5:
                    buf[abs_pos] ^= (1 << random.randint(0, 7))
                else:
                    delta = random.choice([-1, 1, -32, 32])
                    buf[abs_pos] = (buf[abs_pos] + delta) & 0xFF

        return bytes(buf)

    def export_kaitai(self, format_name: str = "inferred_format") -> str:
        """导出 Kaitai Struct YAML 定义"""
        lines = [
            'meta:',
            f'  id: {format_name}',
            '  endian: le',
            '',
            'seq:',
        ]
        for field in self._fields:
            kt_type = {
                'magic': 'u4', 'length': 'u4', 'type': 'u1',
                'counter': 'u4', 'enum_flags': 'u2',
                'checksum': 'u4', 'string': 'str',
                'padding': 'u1', 'raw': 'u1', 'timestamp': 'u8',
            }.get(field.field_type, 'u1')

            if field.field_type == 'string':
                lines.append(
                    f'  - id: field_{field.offset}'
                    f'\n    type: str'
                    f'\n    size: {field.size}'
                    f'\n    encoding: ASCII')
            elif field.size == 1:
                lines.append(
                    f'  - id: field_{field.offset}'
                    f'\n    type: u1')
            else:
                lines.append(
                    f'  - id: field_{field.offset}'
                    f'\n    type: {kt_type}')

        return '\n'.join(lines)

    @property
    def field_count(self) -> int:
        return len(self._fields)

    def field_summary(self) -> List[Dict[str, Any]]:
        return [f.to_dict() for f in self._fields]


def _entropy_segment_merge(segments: List[Tuple[int, int]],
                            min_size: int = 2) -> List[Tuple[int, int]]:
    """微小片段合并辅助函数"""
    merged = []
    for seg in segments:
        sz = seg[1] - seg[0]
        if merged and sz < min_size:
            prev = merged.pop()
            merged.append((prev[0], seg[1]))
        else:
            merged.append(seg)
    return merged


def infer_from_samples(samples: List[bytes]) -> TypeAwareStructureInferer:
    """从原始样本字节列表推断结构并返回拟合的推理器"""
    inferer = TypeAwareStructureInferer()
    inferer.infer_fields(samples)
    return inferer


def infer_from_directory(dir_path: str) -> TypeAwareStructureInferer:
    """从目录加载全部文件作为样本，返回拟合的推理器"""
    samples = []
    if os.path.isdir(dir_path):
        for fname in sorted(os.listdir(dir_path)):
            fpath = os.path.join(dir_path, fname)
            try:
                with open(fpath, 'rb') as fh:
                    data = fh.read()
                if data:
                    samples.append(data)
            except OSError:
                pass
    inferer = TypeAwareStructureInferer()
    if samples:
        inferer.infer_fields(samples)
    return inferer
