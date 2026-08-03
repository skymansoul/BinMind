"""结构感知变异引擎 --- 字段边界/块级/协议感知变异操作。

在core.py的havoc/deterministic基础上扩展四个维度:
  - 字段边界感知: 熵变化检测字段边界, 边界内变异更安全
  - 块级操作: 交换/复制/删除/倒转整块数据
  - 协议感知: 识别length/checksum/magic字段并定向处理
  - 自适应算子选择: MOPT风格的变异概率在线更新
G2Fuzz (USENIX Security 2025, arXiv:2501.19282), AFL++ MOPT, 字典变异系统综述 (SAJC 2025)。
"""

import math
import random
import hashlib
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class StructMutOp(str, Enum):
    """结构感知变异操作枚举。"""
    FIELD_SWAP = "field_swap"            # 交换两个字段
    FIELD_DUPLICATE = "field_duplicate"  # 复制字段到其他位置
    FIELD_DELETE = "field_delete"        # 删除整个字段
    FIELD_SHUFFLE = "field_shuffle"      # 随机重排字段顺序
    SPLICE_AT_BOUNDARY = "splice_at_boundary"  # 在边界处拼接
    LENGTH_UPDATE = "length_update"      # 更新长度字段与实际数据对齐
    MAGIC_TAMPER = "magic_tamper"        # 窜改魔数字节
    CHUNK_CROSSOVER = "chunk_crossover"  # chunk级交叉
    CHUNK_REVERSE = "chunk_reverse"      # 反转字节序
    DICT_GUIDED_FIELD = "dict_guided_field"  # 字典token注入字段


# ==== 字段边界检测 ====
# 基于EntropyBoundaryDetector的边界位置将种子切分为字段列表

@dataclass
class DataField:
    """种子数据中的一个逻辑字段区间。"""
    start: int
    end: int                          # 不含end
    data: bytes
    entropy: float = 0.0              # 字段平均字节熵
    is_length_field: bool = False     # 长度字段标记
    is_checksum_field: bool = False   # 校验和字段标记
    is_magic_field: bool = False      # 魔数字段标记


# ==== 字段划分引擎 ====

class FieldPartitioner:
    """熵边界 + 启发式模式匹配的字段划分。

    当LLM生成器不可用时提供离线回退: 熵边界切分 + 已知魔数/长度字段匹配。
    常见长度字段偏移量预置为{0,2,4,8}。
    """

    # 长度字段常见偏移 (2字节/4字节小端)
    _LENGTH_FIELD_OFFSETS = {0, 2, 4, 8}

    def partition(self, data: bytes, boundaries: Optional[List[int]] = None) -> List[DataField]:
        """按边界偏移切分字节数据为字段序列。

        boundaries为None时以固定16字节块切分。
        """
        if not data:
            return []

        if boundaries is None:
            # 回退: 固定16字节块切分
            chunk = 16
            boundaries = list(range(chunk, len(data), chunk))

        # 去重排序
        bset = sorted(set(b for b in boundaries if 0 < b < len(data)))
        if not bset:
            return [DataField(start=0, end=len(data), data=data)]

        # 构造字段
        fields: List[DataField] = []
        prev = 0
        ent_calc = _field_entropy
        for b in bset:
            if b <= prev:
                continue
            chunk_data = data[prev:b]
            entropy = ent_calc(chunk_data)
            fields.append(DataField(
                start=prev, end=b, data=chunk_data, entropy=entropy
            ))
            prev = b

        # 末尾字段
        if prev < len(data):
            chunk_data = data[prev:]
            fields.append(DataField(
                start=prev, end=len(data), data=chunk_data,
                entropy=ent_calc(chunk_data)
            ))

        # 标注特殊字段
        self._mark_special_fields(fields, data)
        return fields

    def _mark_special_fields(self, fields: List[DataField], raw: bytes) -> None:
        """启发式识别: 长度字段、魔数字段与校验和字段。"""
        import struct
        for f in fields:
            fsize = f.end - f.start
            # 长度字段: 前几个偏移中的小整数, 值约等于剩余数据长度
            if f.start in self._LENGTH_FIELD_OFFSETS and fsize in (2, 4):
                try:
                    if fsize == 2:
                        val = struct.unpack_from("<H", raw, f.start)[0]
                    else:
                        val = struct.unpack_from("<I", raw, f.start)[0]
                    remaining = len(raw) - f.end
                    if abs(val - remaining) < 64:
                        f.is_length_field = True
                except struct.error:
                    pass

            # 魔数字段: 已知文件头匹配
            if fsize <= 8:
                known_magics = {
                    b'\x89PNG', b'\xff\xd8\xff', b'GIF8', b'%PDF',
                    b'PK\x03\x04', b'\x7fELF', b'MZ',
                }
                for magic in known_magics:
                    if f.data.startswith(magic):
                        f.is_magic_field = True
                        break

            # 低熵小字段推测为校验和
            if f.entropy < 2.0 and fsize <= 8:
                f.is_checksum_field = True


def _field_entropy(data: bytes) -> float:
    """字节香农熵。空数据返回0.0。"""
    if not data:
        return 0.0
    counter = Counter(data)
    n = len(data)
    ent = 0.0
    for v in counter.values():
        p = v / n
        ent -= p * math.log2(p)
    return ent


# ==== 结构感知变异器 ====

class StructureAwareMutator:
    """对字段结构执行语义保留变异操作。

    与GeneticMutator的关键区别:
    - GeneticMutator在字节级操作, 不感知输入内部结构
    - 本类先划分字段, 再在字段间/字段内执行结构感知操作

    MOPT自适应: 初始等概率, 记录每次变异是否产生新覆盖,
    每50轮按成功率重新分配概率。每个算子下界0.02防归零。
    """

    def __init__(self):
        self._partitioner = FieldPartitioner()
        # 算子概率表, 初始均匀
        self._op_probs: Dict[StructMutOp, float] = {
            op: 1.0 / len(StructMutOp) for op in StructMutOp
        }
        self._op_hits: Dict[StructMutOp, int] = defaultdict(int)
        self._op_tries: Dict[StructMutOp, int] = defaultdict(int)
        self._mopt_round: int = 0

    def mutate(self, data: bytes, boundaries: Optional[List[int]] = None) -> bytes:
        """对种子执行一次结构感知变异, 返回变异后数据。"""
        if not data:
            return data

        fields = self._partitioner.partition(data, boundaries)
        if not fields:
            return data

        # 按当前MOPT概率采样
        op = self._select_operator()
        self._op_tries[op] += 1

        result = self._apply_op(op, data, fields)
        return result if result else data

    def _select_operator(self) -> StructMutOp:
        """MOPT概率轮盘赌选择算子。"""
        ops = list(StructMutOp)
        probs = [self._op_probs[o] for o in ops]
        total = sum(probs)
        r = random.random() * total
        cum = 0.0
        for op, p in zip(ops, probs):
            cum += p
            if r <= cum:
                return op
        return ops[-1]

    def _apply_op(self, op: StructMutOp, data: bytes,
                  fields: List[DataField]) -> Optional[bytes]:
        """算子分派: 按类型调用对应处理函数。"""
        raw = bytearray(data)

        if op == StructMutOp.FIELD_SWAP and len(fields) >= 2:
            return self._do_field_swap(raw, fields)
        elif op == StructMutOp.FIELD_DUPLICATE and len(fields) >= 1:
            return self._do_field_duplicate(raw, fields)
        elif op == StructMutOp.FIELD_DELETE and len(fields) >= 2:
            return self._do_field_delete(raw, fields)
        elif op == StructMutOp.FIELD_SHUFFLE and len(fields) >= 3:
            return self._do_field_shuffle(raw, fields)
        elif op == StructMutOp.CHUNK_REVERSE:
            return self._do_chunk_reverse(raw, fields)
        elif op == StructMutOp.LENGTH_UPDATE:
            return self._do_length_update(raw, fields)
        elif op == StructMutOp.MAGIC_TAMPER:
            return self._do_magic_tamper(raw, fields)
        elif op == StructMutOp.DICT_GUIDED_FIELD:
            return self._do_dict_guided(raw, fields)
        elif op == StructMutOp.CHUNK_CROSSOVER:
            return None  # 需两个输入, 单输入跳过
        else:
            return None

    # -- 具体变异操作 --

    def _do_field_swap(self, raw: bytearray, fields: List[DataField]) -> bytes:
        """随机交换两个字段的内容区段。"""
        i, j = random.sample(range(len(fields)), 2)
        fi, fj = fields[i], fields[j]
        chunk_i = raw[fi.start:fi.end]
        chunk_j = raw[fj.start:fj.end]
        raw[fi.start:fi.start + len(chunk_j)] = chunk_j
        raw[fj.start:fj.start + len(chunk_i)] = chunk_i
        return bytes(raw)

    def _do_field_duplicate(self, raw: bytearray, fields: List[DataField]) -> bytes:
        """复制随机字段内容并追加到数据末端。"""
        idx = random.randrange(len(fields))
        f = fields[idx]
        dup = raw[f.start:f.end]
        raw.extend(dup)
        return bytes(raw)

    def _do_field_delete(self, raw: bytearray, fields: List[DataField]) -> bytes:
        """删除一个随机非魔数字段。无候选时返回原数据。"""
        candidates = [f for f in fields if not f.is_magic_field]
        if not candidates:
            return bytes(raw)
        f = random.choice(candidates)
        del raw[f.start:f.end]
        return bytes(raw)

    def _do_field_shuffle(self, raw: bytearray, fields: List[DataField]) -> bytes:
        """Fisher-Yates随机重排字段顺序。"""
        order = list(range(len(fields)))
        random.shuffle(order)
        chunks = [raw[f.start:f.end] for f in fields]
        new = bytearray()
        for idx in order:
            new.extend(chunks[idx])
        return bytes(new)

    def _do_chunk_reverse(self, raw: bytearray, fields: List[DataField]) -> bytes:
        """反转随机字段的字节序, 模拟大小端错误。"""
        idx = random.randrange(len(fields))
        f = fields[idx]
        reversed_chunk = bytes(reversed(raw[f.start:f.end]))
        raw[f.start:f.end] = reversed_chunk
        return bytes(raw)

    def _do_length_update(self, raw: bytearray, fields: List[DataField]) -> bytes:
        """将标记为长度字段的位置写入正确的剩余数据长度值。

        2字节字段写低16位, 4字节字段写低32位。
        """
        import struct
        for f in fields:
            if not f.is_length_field:
                continue
            remaining = len(raw) - f.end
            if f.end - f.start == 2:
                struct.pack_into("<H", raw, f.start, remaining & 0xFFFF)
            elif f.end - f.start == 4:
                struct.pack_into("<I", raw, f.start, remaining & 0xFFFFFFFF)
        return bytes(raw)

    def _do_magic_tamper(self, raw: bytearray, fields: List[DataField]) -> bytes:
        """窜改魔数字段中一个字节, 模拟格式混淆攻击。"""
        magic_fields = [f for f in fields if f.is_magic_field]
        if not magic_fields:
            return bytes(raw)
        f = random.choice(magic_fields)
        pos = random.randint(f.start, f.end - 1)
        raw[pos] ^= random.randint(1, 255)
        return bytes(raw)

    def _do_dict_guided(self, raw: bytearray, fields: List[DataField]) -> bytes:
        """在随机字段内插入随机字节 -- 缺少字典时的退化行为。"""
        if not fields:
            return bytes(raw)
        f = random.choice(fields)
        ins = random.randint(f.start, f.end)
        raw.insert(ins, random.randint(0, 255))
        return bytes(raw)

    # -- MOPT概率更新 --

    def notify_result(self, op: StructMutOp, produced_new_coverage: bool) -> None:
        """记录一次变异结果, 每50轮触发概率重分配。"""
        if produced_new_coverage:
            self._op_hits[op] += 1
        self._mopt_round += 1

        if self._mopt_round % 50 == 0:
            self._update_probs()

    def _update_probs(self) -> None:
        """按命中率加权更新算子概率, 保留0.02最低地板。"""
        hit_rates = {}
        total_rate = 0.0
        for op in StructMutOp:
            tries = self._op_tries.get(op, 0)
            hits = self._op_hits.get(op, 0)
            rate = hits / max(1, tries)
            hit_rates[op] = rate
            total_rate += rate

        if total_rate <= 0:
            return

        for op in StructMutOp:
            raw_prob = hit_rates[op] / total_rate
            self._op_probs[op] = max(0.02, raw_prob)

    def get_operator_stats(self) -> Dict[str, Dict]:
        """各算子的尝试/命中/命中率与当前概率统计。"""
        stats = {}
        for op in StructMutOp:
            tries = self._op_tries.get(op, 0)
            hits = self._op_hits.get(op, 0)
            stats[op.value] = {
                "tries": tries,
                "hits": hits,
                "hit_rate": hits / max(1, tries),
                "probability": round(self._op_probs[op], 4),
            }
        return stats


# ==== 协议格式检测 ====
# 识别常见格式以启发结构感知变异策略

def detect_protocol_format(data: bytes) -> str:
    """检测数据对应的协议/文件格式, 返回标签字符串。

    返回值如 "http"/"json"/"elf"/"png"/"unknown",
    供FieldPartitioner和StructureAwareMutator选择适配策略。
    """
    if not data:
        return "unknown"

    head = data[:min(len(data), 64)]

    # 文本协议检测
    try:
        text = head.decode('ascii', errors='ignore')
        if text.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
            return "http"
        if text.startswith(('HTTP/', 'HTTP ')):
            return "http"
        if text.strip().startswith(('{', '[')):
            return "json"
        if text.strip().startswith('<'):
            return "xml"
    except UnicodeDecodeError:
        pass

    # 二进制格式检测
    if head.startswith(b'\x7fELF'):
        return "elf"
    if head.startswith(b'MZ'):
        return "pe"
    if head.startswith(b'\x89PNG'):
        return "png"
    if head.startswith(b'\xff\xd8'):
        return "jpeg"
    if head.startswith(b'GIF8'):
        return "gif"
    if head.startswith(b'PK\x03\x04'):
        return "zip"
    if head.startswith(b'%PDF'):
        return "pdf"
    if head.startswith(b'\x1f\x8b'):
        return "gzip"
    if head.startswith(b'RIFF'):
        return "riff"

    return "unknown"


# ==== 便捷入口 ====

def structure_aware_mutate(
    seed_data: bytes,
    boundaries: Optional[List[int]] = None,
    mutator: Optional[StructureAwareMutator] = None,
) -> bytes:
    """对种子执行结构感知变异的一行入口。

    mutator为None时创建默认实例; boundaries可从EntropyBoundaryDetector获取。
    """
    if mutator is None:
        mutator = StructureAwareMutator()
    return mutator.mutate(seed_data, boundaries)

def _debug_print(*a,**kw):
    if __import__("os").environ.get("BINMIND_DEBUG"):print(*a,**kw)
