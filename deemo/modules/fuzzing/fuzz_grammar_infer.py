"""从种子语料库推断输入语法 -- 有限状态机/正则近似的自动学习。

参考:
  STALAGMITE   (FSE 2024, arXiv:2503.08486) -- 从递归下降解析器代码静态挖掘文法
  GrammarForge (SEFM 2024)                   -- 轻量源码分析+成员查询, 无输入样本
  SyzSpec       (ASE 2022, Zotero)           -- 欠约束符号执行生成内核模糊测试规范
  Grammar-based whitebox fuzzing (Zotero)    -- 白盒文法推断
  Parser-directed fuzzing (Zotero)           -- 解析器定向模糊测试

本模块实现一个轻量的输入语法推断器:
  输入: 一组种子文件 (bytes)
  输出: 一个近似的正则文法, 可用于:
    - 生成符合格式的新输入
    - 检测输入的结构异常
    - 指导字典生成和变异策略
"""

import hashlib
import itertools
import json
import logging
import math
import re
import struct
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class GrammarNodeType(str, Enum):
    LITERAL = "literal"         # 固定字节序列
    CHOICE = "choice"           # 多选一
    REPEAT = "repeat"           # 重复 0-N 次
    SEQUENCE = "sequence"       # 有序连接
    RANGE = "range"             # 字节范围 [lo, hi]
    LENGTH_FIELD = "length_field"  # 长度字段
    CHECKSUM_FIELD = "checksum_field"  # 校验和字段
    UNKNOWN = "unknown"         # 自由字节区域


@dataclass
class GrammarNode:
    """文法树节点。"""
    node_type: GrammarNodeType
    literal_value: Optional[bytes] = None
    children: List['GrammarNode'] = field(default_factory=list)
    min_repeat: int = 0
    max_repeat: int = 10
    range_lo: int = 0
    range_hi: int = 255
    weight: float = 1.0       # 生成时被选中的权重
    label: str = ""            # 人类可读的字段标签


@dataclass
class InferredGrammar:
    """推断出的文法结构。"""
    root: Optional[GrammarNode] = None
    field_count: int = 0
    total_seeds_analyzed: int = 0
    entropy_profile: List[float] = field(default_factory=list)
    protocol_hint: str = "unknown"  # http/json/elf/png/...


class GrammarInferrer:
    """从语料库统计推断输入近似文法 -- 多阶段流水线。"""

    def __init__(self, min_seeds: int = 3, entropy_window: int = 8):
        self.min_seeds = min_seeds
        self.entropy_window = entropy_window
        self._known_magics = {
            b'\x7fELF': 'elf', b'MZ': 'pe', b'\x89PNG': 'png',
            b'\xff\xd8': 'jpeg', b'GIF8': 'gif', b'PK\x03\x04': 'zip',
            b'%PDF': 'pdf', b'\x1f\x8b': 'gzip',
        }

    def infer(self, seeds: List[bytes]) -> InferredGrammar:
        """从种子集合推断文法。

        若种子数 < min_seeds, 返回仅含协议提示的最小文法。
        """
        if not seeds:
            return InferredGrammar()

        ig = InferredGrammar(total_seeds_analyzed=len(seeds))
        ig.protocol_hint = self._detect_protocol(seeds[0])

        if len(seeds) < self.min_seeds:
            ig.root = GrammarNode(node_type=GrammarNodeType.UNKNOWN, label="insufficient_data")
            return ig

        # 阶段1: 对齐分析
        aligned = self._align_seeds(seeds[:50])  # 限50个避免 O(n²)

        # 阶段2: 熵分析
        entropy = self._compute_entropy_profile(aligned)
        ig.entropy_profile = entropy

        # 阶段3: 字段划分
        fields = self._partition_by_entropy(aligned, entropy)

        # 阶段4: 类型推断
        typed_fields = []
        for f_start, f_end, f_data_samples in fields:
            ftype = self._infer_field_type(f_data_samples, f_start, aligned)
            typed_fields.append((f_start, f_end, ftype))

        # 阶段5: 文法树构建
        ig.root = self._build_grammar_tree(typed_fields, aligned[0] if aligned else b'')
        ig.field_count = len(typed_fields)

        return ig

    def _detect_protocol(self, data: bytes) -> str:
        if not data:
            return "empty"
        for magic, label in self._known_magics.items():
            if data.startswith(magic):
                return label
        # 文本检测
        try:
            text = data[:128].decode('ascii', errors='strict')
            if text.startswith(('GET ', 'POST ', 'HTTP/')):
                return "http"
            if text.strip().startswith(('{', '[')):
                return "json"
            if text.strip().startswith('<'):
                return "xml"
        except UnicodeDecodeError:
            pass
        return "binary"

    def _align_seeds(self, seeds: List[bytes]) -> List[bytes]:
        """简单的多序列左对齐 -- 以最小长度截断, 不执行 Needleman-Wunsch。

        STALAGMITE 使用符号执行获取精确文法, 此处用统计近似:
        将所有种子截断到最短长度, 用于发现共同前缀/后缀结构。
        """
        if not seeds:
            return [b'']
        min_len = min(len(s) for s in seeds)
        return [s[:min_len] for s in seeds]

    def _compute_entropy_profile(self, aligned: List[bytes]) -> List[float]:
        """对每个字节位置计算跨种子的香农熵。

        低熵 → 固定值 (魔数/版本号/类型码)
        高熵 → 数据/可变字段
        """
        if not aligned:
            return []
        max_len = max(len(s) for s in aligned)
        profile = []
        for pos in range(max_len):
            vals = [s[pos] for s in aligned if pos < len(s)]
            if len(vals) < 2:
                profile.append(0.0)  # 仅一个样本 → 无法计算, 假设为固定
                continue
            counter = Counter(vals)
            total = len(vals)
            ent = 0.0
            for cnt in counter.values():
                p = cnt / total
                ent -= p * math.log2(p)
            profile.append(ent)
        return profile

    def _partition_by_entropy(
        self, aligned: List[bytes], entropy: List[float]
    ) -> List[Tuple[int, int, List[bytes]]]:
        """按熵值将字节序列分割为字段。

        规则:
          - 熵 < 0.5 → 固定字段 (可能魔数/版本)
          - 0.5 ≤ 熵 < 2.0 → 半固定字段 (可能枚举值)
          - 熵 ≥ 2.0 → 可变字段 (数据载荷)
        """
        if not entropy:
            return []

        # 滑动合并相同类别
        fields = []
        prev_cat = self._entropy_category(entropy[0])
        start = 0

        for i in range(1, len(entropy)):
            cat = self._entropy_category(entropy[i])
            if cat != prev_cat:
                samples = [s[start:i] for s in aligned if len(s) >= i]
                fields.append((start, i, samples))
                start = i
                prev_cat = cat

        # 尾部
        samples = [s[start:] for s in aligned if len(s) >= start]
        fields.append((start, len(entropy), samples))
        return fields

    def _entropy_category(self, e: float) -> int:
        if e < 0.5:
            return 0  # fixed
        elif e < 2.0:
            return 1  # semi-fixed
        return 2  # variable

    def _infer_field_type(self, samples: List[bytes],
                          offset: int, aligned: List[bytes]) -> GrammarNodeType:
        """推断字段类型。

        - 所有样本都相同 → LITERAL
        - 2-5 种不同的值, 且 len < 4 → CHOICE (枚举)
        - 值在连续范围内 → RANGE
        - 4 字节字段, 值 ≈ 后续数据长度 → LENGTH_FIELD
        - 字段内容高频变化 → UNKNOWN
        """
        if not samples or all(len(s) == 0 for s in samples):
            return GrammarNodeType.UNKNOWN

        unique = set(samples)
        n_unique = len(unique)

        if n_unique == 1:
            return GrammarNodeType.LITERAL

        field_len = max(len(s) for s in samples)

        # 长度字段检测: 字段值(解释为整数) ≈ 后续数据的长度
        if field_len in (2, 4) and len(aligned) > 0:
            max_offset = max(offset + field_len, 0)
            remaining_len = max(0, len(aligned[0]) - max_offset) if aligned else 0
            for s_val_bytes in samples:
                if len(s_val_bytes) != field_len:
                    continue
                try:
                    if field_len == 2:
                        val = struct.unpack('<H', s_val_bytes)[0]
                    else:
                        val = struct.unpack('<I', s_val_bytes)[0]
                    if abs(val - remaining_len) < 64:
                        return GrammarNodeType.LENGTH_FIELD
                except struct.error:
                    pass

        if 2 <= n_unique <= 5:
            return GrammarNodeType.CHOICE

        # 检查是否在连续范围内
        if all(len(s) == 1 for s in samples):
            byte_vals = [s[0] for s in samples]
            lo, hi = min(byte_vals), max(byte_vals)
            if hi - lo <= 64 and n_unique >= (hi - lo + 1) * 0.7:
                return GrammarNodeType.RANGE

        return GrammarNodeType.UNKNOWN

    def _build_grammar_tree(self, typed_fields: List[Tuple[int, int, GrammarNodeType]],
                            sample_data: bytes) -> GrammarNode:
        """从字段类型列表构建 GrammarNode 序列。"""
        seq = GrammarNode(node_type=GrammarNodeType.SEQUENCE, label="root")
        for f_start, f_end, ftype in typed_fields:
            child = GrammarNode(node_type=ftype)
            if ftype == GrammarNodeType.LITERAL:
                child.literal_value = sample_data[f_start:f_end]
            elif ftype == GrammarNodeType.RANGE:
                if f_start < len(sample_data):
                    child.range_lo = sample_data[f_start]
                    child.range_hi = min(255, sample_data[f_start] + 64)
            elif ftype == GrammarNodeType.LENGTH_FIELD:
                child.label = f"length_at_{f_start}"
            child.label = f"{ftype.value}[{f_start}:{f_end}]"
            seq.children.append(child)
        return seq


# ===== 从文法生成测试输入 =====

def generate_from_grammar(root: GrammarNode, max_length: int = 4096) -> bytes:
    """从推断的文法树采样生成一个新的输入。

    这是一个简单的递归生成器 -- 对重复节点进行展开,
    对选择节点随机选取, 直到达到 max_length 或所有节点展开完毕。
    """
    output = bytearray()
    _generate_rec(root, output, max_length)
    return bytes(output)


def _generate_rec(node: GrammarNode, buf: bytearray, max_len: int) -> None:
    if len(buf) >= max_len:
        return

    if node.node_type == GrammarNodeType.LITERAL and node.literal_value:
        buf.extend(node.literal_value)
    elif node.node_type == GrammarNodeType.CHOICE and node.children:
        child = random.choice(node.children)
        _generate_rec(child, buf, max_len)
    elif node.node_type == GrammarNodeType.REPEAT:
        count = random.randint(node.min_repeat, min(node.max_repeat, 5))
        for _ in range(count):
            if len(buf) >= max_len:
                break
            for child in node.children:
                _generate_rec(child, buf, max_len)
    elif node.node_type == GrammarNodeType.SEQUENCE:
        for child in node.children:
            _generate_rec(child, buf, max_len)
    elif node.node_type == GrammarNodeType.RANGE:
        buf.append(random.randint(node.range_lo, node.range_hi))
    elif node.node_type == GrammarNodeType.UNKNOWN:
        # 生成 1-8 个随机字节
        for _ in range(random.randint(1, min(8, max_len - len(buf)))):
            buf.append(random.randint(0, 255))
    elif node.node_type == GrammarNodeType.LENGTH_FIELD:
        # 暂时写入占位符, 实际长度由外部调用者后续修正
        buf.extend(b'\x00\x00')


# ===== 语法导出 =====

def export_grammar_json(inferred: InferredGrammar, output_path: Optional[str] = None) -> Dict:
    """将推断的文法导出为 JSON (可被其他工具消费)。"""
    if inferred.root is None:
        return {"error": "no grammar inferred"}

    def _node_to_dict(n: GrammarNode) -> Dict:
        d = {"type": n.node_type.value, "label": n.label, "weight": n.weight}
        if n.node_type == GrammarNodeType.LITERAL and n.literal_value:
            d["literal"] = n.literal_value.hex()
        if n.node_type == GrammarNodeType.RANGE:
            d["range"] = [n.range_lo, n.range_hi]
        if n.node_type == GrammarNodeType.REPEAT:
            d["repeat"] = [n.min_repeat, n.max_repeat]
        if n.children:
            d["children"] = [_node_to_dict(c) for c in n.children]
        return d

    data = {
        "protocol_hint": inferred.protocol_hint,
        "field_count": inferred.field_count,
        "seeds_analyzed": inferred.total_seeds_analyzed,
        "grammar": _node_to_dict(inferred.root),
    }
    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    return data


def infer_grammar(seeds: List[bytes]) -> InferredGrammar:
    """模块级便捷入口。"""
    return GrammarInferrer().infer(seeds)
