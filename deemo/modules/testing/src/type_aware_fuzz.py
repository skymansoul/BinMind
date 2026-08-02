# 2026-08-01
# 类型感知的模糊测试结构生成器 — 从二进制/PCAP 推断 C 结构和协议字段布局
# 核心方法:
#   1. 字段边界推断: 基于样本集的多序列比对 + 熵分析
#   2. 类型推断: CNF 风格分类 → SIZE/LENGTH/MAGIC/ENUM/CHECKSUM/RAW
#   3. 结构保持变异: 在推断的字段边界内做类型化变异
#   4. Kaitai Struct 输出: 将推断结果导出为 Kaitai Struct YAML (.ksy)
# 参考:
#   AIFORE (USENIX Security 2023) — type-aware & structure-aware fuzzing
#   NEMESYS (ISSTA 2022) — network message structure inference
#   ChatAFL (NDSS 2024) — LLM-guided protocol fuzzing, grammar extraction
#   Kaitai Struct (https://kaitai.io/) — declarative binary format description
import math
import struct
from typing import List, Dict, Tuple, Optional, Set, Any
from collections import Counter, defaultdict


# 字段类型枚举 — 参考 AIFORE 的 6 分类 + 扩展
FIELD_TYPES = {
    'magic': '固定魔数',
    'length': '长度字段（值关联后续数据长度）',
    'type': '消息类型/命令码',
    'checksum': '校验和/CRC',
    'counter': '递增计数器/序列号',
    'enum_flags': '枚举值或位标志',
    'string': 'ASCII/UTF-8 字符串',
    'raw': '未分类/有效载荷',
    'padding': '零填充',
    'timestamp': 'Unix 时间戳',
}


class TypeAwareField:
    """推断出的单个协议字段。"""
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
    """类型感知的二进制结构推断器。

    工作流:
      infer(samples) → fields[]
      generate(count, fields) → 生成类型感知的有效变异输入
      export_kaitai(fields, name) → 导出 Kaitai Struct 格式定义
    """

    def __init__(self, min_samples: int = 4):
        self._min_samples = min_samples
        self._fields: List[TypeAwareField] = []

    # ---- 字段边界推断 ----
    def infer_fields(self, samples: List[bytes]) -> List[TypeAwareField]:
        """从样本集同时推断字段边界和类型。分两阶段:
        阶段1: 多序列比对 → 识别固定/可变区域边界
        阶段2: 对每个区域做类型分类"""
        if len(samples) < self._min_samples:
            return []

        max_len = max(len(s) for s in samples)
        # 对齐所有样本到相同长度（右填充 \x00）
        aligned = [s.ljust(max_len, b'\x00') for s in samples]

        # 阶段1: 按字节熵聚类确定字段边界
        entropies = self._compute_position_entropies(aligned, max_len)
        segments = self._segment_by_entropy(entropies)

        # 阶段2: 逐字段推断类型
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
        """按熵变化幅度聚类相邻位置。熵差 > threshold → 新字段边界。"""
        if not entropies:
            return []
        segments = []
        start = 0
        for i in range(1, len(entropies)):
            if abs(entropies[i] - entropies[i - 1]) > threshold:
                segments.append((start, i))
                start = i
        segments.append((start, len(entropies)))
        # 合并 < 2 字节的碎片字段到相邻段
        return self._merge_tiny_segments(segments, min_size=2)

    @staticmethod
    def _merge_tiny_segments(segments: List[Tuple[int, int]],
                             min_size: int = 2) -> List[Tuple[int, int]]:
        """合并过短的片段到邻居（优先左侧）"""
        merged = []
        for seg in segments:
            if merged and (seg[1] - seg[0]) < min_size:
                prev = merged.pop()
                merged.append((prev[0], seg[1]))
            else:
                merged.append(seg)
        # 第二遍向前合并
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

    # ---- 字段类型分类 ----
    def _classify_field(self, values: List[bytes],
                        offset: int) -> Tuple[str, float]:
        """基于启发式规则分类单个字段的类型。"""
        unique = set(values)
        n_unique = len(unique)
        n_total = len(values)

        # 规则 1: 全部为零 → padding
        if all(v == b'\x00' * len(v) for v in values):
            return 'padding', 0.95

        # 规则 2: 仅一个唯一值 → 可能是 magic
        if n_unique == 1 and n_total >= self._min_samples:
            return 'magic', 0.85

        # 规则 3: 少量唯一值 (< 10% 样本数) → enum_flags
        if n_unique < max(2, n_total * 0.1):
            return 'enum_flags', 0.70

        # 规则 4: 值单调递增 → counter
        if len(values) >= 3 and len(values[0]) <= 4:
            int_vals = [int.from_bytes(v, 'big') for v in values]
            diffs = [int_vals[i + 1] - int_vals[i]
                     for i in range(len(int_vals) - 1)
                     if int_vals[i + 1] > int_vals[i]]
            if diffs and all(0 < d <= 100 for d in diffs):
                return 'counter', 0.65

        # 规则 5: 值与其他字段长度相关 → length
        if self._correlates_with_length(values, offset):
            return 'length', 0.60

        # 规则 6: Unix 时间戳范围 (2020-2030)
        if len(values[0]) >= 4:
            int_vals = [int.from_bytes(v[:4], 'big') for v in values]
            if all(1_600_000_000 < v < 1_900_000_000 for v in int_vals):
                return 'timestamp', 0.75

        # 规则 7: 全部为可打印 ASCII → string
        if all(all(0x20 <= b <= 0x7E for b in v) for v in values):
            return 'string', 0.80

        # 规则 8: CRC 校验模式（高熵但值相互关联）
        if n_unique == n_total and len(values[0]) in (2, 4):
            return 'checksum', 0.40

        return 'raw', 0.30

    def _correlates_with_length(self, values: List[bytes],
                                offset: int) -> bool:
        """检查此字段的值是否与后续数据的长度相关。
        例如：4 字节 big-endian 整数 == 后续字段的总长度。"""
        if not values or len(values[0]) > 4:
            return False
        # 尝试将前几个值解释为 size，比较是否与样本总长度一致
        for v in values[:min(8, len(values))]:
            if len(v) <= 4:
                try:
                    predicted_len = int.from_bytes(v, 'big')
                    # 弱检查：值在合理范围内 (1~65535)
                    if 1 <= predicted_len <= 65535:
                        return True
                except Exception:
                    pass
        return False

    # ---- 类型感知的生成 ----
    def generate(self, count: int = 32) -> List[bytes]:
        """基于推断的字段类型生成结构保持的测试输入。
        不同类型采用不同的生成/变异策略。"""
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
        """对单个字段按类型生成合理的变异值。"""
        import random as _rnd
        sz = field.size
        ftype = field.field_type

        if ftype == 'magic':
            # 保留原值（魔数不变），偶尔变异为相似值
            if field.sample_values and _rnd.random() > 0.05:
                return field.sample_values[0]
            return bytes(_rnd.randint(0, 255) for _ in range(sz))

        if ftype == 'length':
            # 生成长度值 — 与当前生成的总体大小一致
            payload_guess = _rnd.randint(0, 4096)
            return payload_guess.to_bytes(min(sz, 4), 'big')

        if ftype == 'enum_flags':
            if field.sample_values and _rnd.random() > 0.5:
                return _rnd.choice(field.sample_values)
            bitmask = _rnd.randint(0, (1 << min(sz * 8, 32)) - 1)
            return bitmask.to_bytes(sz, 'big')

        if ftype == 'counter':
            base = _rnd.randint(0, 65535)
            return base.to_bytes(min(sz, 4), 'big')

        if ftype == 'padding':
            return b'\x00' * sz

        if ftype in ('string', 'raw'):
            # 高概率保持可打印，低概率注入二进制噪声
            if ftype == 'string' and _rnd.random() > 0.2:
                return bytes(_rnd.randint(0x20, 0x7E) for _ in range(sz))
            return bytes(_rnd.randint(0, 255) for _ in range(sz))

        # 默认: 从样本值中抽取或随机生成
        if field.sample_values:
            return _rnd.choice(field.sample_values)
        return bytes(_rnd.randint(0, 255) for _ in range(sz))

    def mutate_preserve_structure(self, seed: bytes,
                                   rounds: int = 3) -> bytes:
        """对种子做结构保持的变异：每个字段内部变异，不破坏字段边界。
        边界值字段（magic/length/counter）变异概率低，raw 字段概率高。"""
        if not self._fields:
            return seed

        import random as _rnd
        buf = bytearray(seed)
        for _ in range(rounds):
            field = _rnd.choice(self._fields)
            if field.offset + field.size > len(buf):
                continue

            # 按字段类型调整变异概率
            mutate_prob = {
                'magic': 0.05, 'padding': 0.02, 'length': 0.15,
                'counter': 0.20, 'enum_flags': 0.30,
                'checksum': 0.10, 'string': 0.50, 'raw': 0.60,
            }.get(field.field_type, 0.40)

            if _rnd.random() > mutate_prob:
                continue

            # 对字段内随机字节做位翻转/算术变异
            for _2 in range(max(1, field.size // 4)):
                rel_pos = _rnd.randint(0, field.size - 1)
                abs_pos = field.offset + rel_pos
                if _rnd.random() < 0.5:
                    buf[abs_pos] ^= (1 << _rnd.randint(0, 7))
                else:
                    delta = _rnd.choice([-1, 1, -32, 32])
                    buf[abs_pos] = (buf[abs_pos] + delta) & 0xFF

        return bytes(buf)

    # ---- 导出 ----
    def export_kaitai(self, format_name: str = "inferred_format") -> str:
        """导出 Kaitai Struct YAML 定义。"""
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


# 内部工具：按熵分段时对微小片段的合并启发式
def _entropy_segment_merge(segments: List[Tuple[int, int]],
                            min_size: int = 2) -> List[Tuple[int, int]]:
    merged = []
    for seg in segments:
        sz = seg[1] - seg[0]
        if merged and sz < min_size:
            prev = merged.pop()
            merged.append((prev[0], seg[1]))
        else:
            merged.append(seg)
    return merged


# ---------------------------------------------------------------------------
# 便捷入口: 从 PCAP/样本目录快速推断
# ---------------------------------------------------------------------------
def infer_from_samples(samples: List[bytes]) -> TypeAwareStructureInferer:
    """从原始样本字节列表推断结构并返回已拟合的推理器。"""
    inferer = TypeAwareStructureInferer()
    inferer.infer_fields(samples)
    return inferer


def infer_from_directory(dir_path: str) -> TypeAwareStructureInferer:
    """从目录中加载全部文件作为样本，返回已拟合的推理器。"""
    import os
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
