# 2026-07-26

"""结构感知变异引擎 --- 块/字段边界/协议感知的变异操作。

参考:
  G2Fuzz  (USENIX Security 2025, arXiv:2501.19282) -- LLM合成输入生成器+分块变异
  AFL++ MOPT 调度               -- 变异算子选择概率自适应
  字典变异系统综述 (SAJC 2025)    -- 字典基变异近似语法感知

本模块在 core.py 的 havoc/deterministic 变异基础上扩展:
  - 字段边界感知: 基于熵变化检测字段边界, 边界内的变异更安全
  - 块级操作: 交换/复制/删除/倒转整块数据
  - 协议感知: 识别 length/checksum/magic 字段并特殊处理
  - 自适应算子选择: MOPT 风格的变异算子概率在线更新
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
    """结构感知变异操作类型。"""
    FIELD_SWAP = "field_swap"            # 交换两个字段
    FIELD_DUPLICATE = "field_duplicate"  # 复制某字段到其他位置
    FIELD_DELETE = "field_delete"        # 删除整个字段
    FIELD_SHUFFLE = "field_shuffle"      # 随机重排字段顺序
    SPLICE_AT_BOUNDARY = "splice_at_boundary"  # 在边界处拼接
    LENGTH_UPDATE = "length_update"      # 更新长度字段匹配实际数据
    MAGIC_TAMPER = "magic_tamper"        # 修改魔数字节
    CHUNK_CROSSOVER = "chunk_crossover"  # 以 chunk 为单位的交叉
    CHUNK_REVERSE = "chunk_reverse"      # 反转某段字节序
    DICT_GUIDED_FIELD = "dict_guided_field"  # 字典token注入到字段内


# ===== 字段边界检测 =====
# 基于 EntropyBoundaryDetector (fuzz_dictionary_generator.py) 的边界位置
# 将种子数据划分为字段列表

@dataclass
class DataField:
    """种子数据中的一个逻辑字段。"""
    start: int
    end: int                          # 不包含end
    data: bytes
    entropy: float = 0.0              # 该字段的平均字节熵
    is_length_field: bool = False     # 是否为长度字段
    is_checksum_field: bool = False   # 是否为校验和字段
    is_magic_field: bool = False      # 是否为魔数字段


# ===== 字段划分引擎 =====

class FieldPartitioner:
    """基于熵边界 + 启发式的输入字段划分。

    G2Fuzz 使用 LLM 合成的 Python 生成器以获取精确的结构知识,
    此处提供无 LLM 依赖的回退方案: 熵边界 + 已知模式匹配。
    当 LLM 生成器不可用时 (如离线场景), 这仍能提供合理的结构近似。
    """

    # 常见长度字段的模式 (2字节/4字节小端, 位于数据起始附近)
    _LENGTH_FIELD_OFFSETS = {0, 2, 4, 8}

    def partition(self, data: bytes, boundaries: Optional[List[int]] = None) -> List[DataField]:
        """将字节数据切分为逻辑字段列表。

        boundaries: 外部提供的边界偏移列表 (如来自 EntropyBoundaryDetector)。
        若为 None, 则按固定块大小 16 字节切分。
        """
        if not data:
            return []

        if boundaries is None:
            # 回退: 固定块切分
            chunk = 16
            boundaries = list(range(chunk, len(data), chunk))

        # 合并去重排序
        bset = sorted(set(b for b in boundaries if 0 < b < len(data)))
        if not bset:
            return [DataField(start=0, end=len(data), data=data)]

        # 构建字段列表
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

        # 最后一个字段
        if prev < len(data):
            chunk_data = data[prev:]
            fields.append(DataField(
                start=prev, end=len(data), data=chunk_data,
                entropy=ent_calc(chunk_data)
            ))

        # 标记特殊字段
        self._mark_special_fields(fields, data)
        return fields

    def _mark_special_fields(self, fields: List[DataField], raw: bytes) -> None:
        """标记长度字段、校验和字段、魔数字段。"""
        import struct
        for f in fields:
            fsize = f.end - f.start
            # 长度字段: 前几个字段中的小整数, 值 ≈ 剩余数据长度
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

            # 魔数字段: 常见魔数值
            if fsize <= 8:
                known_magics = {
                    b'\x89PNG', b'\xff\xd8\xff', b'GIF8', b'%PDF',
                    b'PK\x03\x04', b'\x7fELF', b'MZ',
                }
                for magic in known_magics:
                    if f.data.startswith(magic):
                        f.is_magic_field = True
                        break

            # 低熵 (≤2 bits/byte) 可能为校验和 — 启发式
            if f.entropy < 2.0 and fsize <= 8:
                f.is_checksum_field = True


def _field_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    n = len(data)
    ent = 0.0
    for v in counter.values():
        p = v / n
        ent -= p * math.log2(p)
    return ent


# ===== 结构感知变异器 =====

class StructureAwareMutator:
    """在字段结构上执行语义保留的变异操作 [G2Fuzz 2025]。

    与 GeneticMutator (fuzz_seed_evolution.py) 的不同:
    - 后者在字节级操作, 忽略输入的内部结构
    - 此处先划分字段, 再在字段间/字段内进行结构感知操作

    算子选择采用 MOPT 风格的在线概率自适应:
      初始所有算子等概率, 每轮记录每个算子是否产生新覆盖,
      周期性更新概率分布: 成功率高 → 概率↑。
    """

    def __init__(self):
        self._partitioner = FieldPartitioner()
        # MOPT式算子概率 [AFL++ MOPT]
        self._op_probs: Dict[StructMutOp, float] = {
            op: 1.0 / len(StructMutOp) for op in StructMutOp
        }
        self._op_hits: Dict[StructMutOp, int] = defaultdict(int)
        self._op_tries: Dict[StructMutOp, int] = defaultdict(int)
        self._mopt_round: int = 0

    def mutate(self, data: bytes, boundaries: Optional[List[int]] = None) -> bytes:
        """对种子执行一次结构感知变异。

        随机选取一个变异算子, 在字段划分的基础上执行。
        返回变异后的数据 (可能为空)。
        """
        if not data:
            return data

        fields = self._partitioner.partition(data, boundaries)
        if not fields:
            return data

        # MOPT 概率采样选择算子
        op = self._select_operator()
        self._op_tries[op] += 1

        result = self._apply_op(op, data, fields)
        return result if result else data

    def _select_operator(self) -> StructMutOp:
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
        """分发执行具体的变异操作。"""
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
            return None  # 需要两个输入, 单输入模式跳过
        else:
            return None

    # ---- 具体操作实现 ----

    def _do_field_swap(self, raw: bytearray, fields: List[DataField]) -> bytes:
        """交换两个随机字段的内容。"""
        i, j = random.sample(range(len(fields)), 2)
        fi, fj = fields[i], fields[j]
        chunk_i = raw[fi.start:fi.end]
        chunk_j = raw[fj.start:fj.end]
        raw[fi.start:fi.start + len(chunk_j)] = chunk_j
        raw[fj.start:fj.start + len(chunk_i)] = chunk_i
        return bytes(raw)

    def _do_field_duplicate(self, raw: bytearray, fields: List[DataField]) -> bytes:
        """复制随机字段内容到数据末尾。"""
        idx = random.randrange(len(fields))
        f = fields[idx]
        dup = raw[f.start:f.end]
        raw.extend(dup)
        return bytes(raw)

    def _do_field_delete(self, raw: bytearray, fields: List[DataField]) -> bytes:
        """删除一个随机非魔数字段。"""
        candidates = [f for f in fields if not f.is_magic_field]
        if not candidates:
            return bytes(raw)
        f = random.choice(candidates)
        del raw[f.start:f.end]
        return bytes(raw)

    def _do_field_shuffle(self, raw: bytearray, fields: List[DataField]) -> bytes:
        """随机重排字段顺序 (Fisher-Yates)。"""
        order = list(range(len(fields)))
        random.shuffle(order)
        chunks = [raw[f.start:f.end] for f in fields]
        new = bytearray()
        for idx in order:
            new.extend(chunks[idx])
        return bytes(new)

    def _do_chunk_reverse(self, raw: bytearray, fields: List[DataField]) -> bytes:
        """反转某个字段的字节序 (模拟大小端错误)。"""
        idx = random.randrange(len(fields))
        f = fields[idx]
        reversed_chunk = bytes(reversed(raw[f.start:f.end]))
        raw[f.start:f.end] = reversed_chunk
        return bytes(raw)

    def _do_length_update(self, raw: bytearray, fields: List[DataField]) -> bytes:
        """自动修正长度字段以匹配实际数据体长度。

        对每个标记为 is_length_field 的字段, 写入正确的剩余数据长度。
        参考: G2Fuzz 的校验和/长度自动修复策略。
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
        """窜改魔数字段中的一个字节 (模拟格式混淆攻击)。"""
        magic_fields = [f for f in fields if f.is_magic_field]
        if not magic_fields:
            return bytes(raw)
        f = random.choice(magic_fields)
        pos = random.randint(f.start, f.end - 1)
        raw[pos] ^= random.randint(1, 255)
        return bytes(raw)

    def _do_dict_guided(self, raw: bytearray, fields: List[DataField]) -> bytes:
        if not fields:
            return bytes(raw)
        f = random.choice(fields)
        # 在字段内随机位置插入一个任意字节 — 缺少字典时的退化行为
        ins = random.randint(f.start, f.end)
        raw.insert(ins, random.randint(0, 255))
        return bytes(raw)

    # ---- MOPT 概率更新 ----

    def notify_result(self, op: StructMutOp, produced_new_coverage: bool) -> None:
        """记录一次变异结果, 用于 MOPT 概率自适应。"""
        if produced_new_coverage:
            self._op_hits[op] += 1
        self._mopt_round += 1

        # 每 50 轮更新一次概率
        if self._mopt_round % 50 == 0:
            self._update_probs()

    def _update_probs(self) -> None:
        """MOPT 风格的概率更新: 成功率高于均值的算子加权。"""
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

        # 避免某个算子概率归零 (保留最低 0.02 的地板)
        for op in StructMutOp:
            raw_prob = hit_rates[op] / total_rate
            self._op_probs[op] = max(0.02, raw_prob)

    def get_operator_stats(self) -> Dict[str, Dict]:
        """返回各算子的命中率统计。"""
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


# ===== 协议格式检测 =====
# 识别常见协议格式以启发结构感知的变异策略

def detect_protocol_format(data: bytes) -> str:
    """检测数据对应的协议/格式类型。

    返回格式标签, 如 "http", "json", "elf", "png", "unknown"。
    该标签可供 FieldPartitioner 和 StructureAwareMutator 使用
    以选择更适合该格式的变异策略。
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


# ===== 模块级便捷函数 =====

def structure_aware_mutate(
    seed_data: bytes,
    boundaries: Optional[List[int]] = None,
    mutator: Optional[StructureAwareMutator] = None,
) -> bytes:
    """对种子数据执行结构感知变异。

    若未提供 mutator, 创建默认实例。
    boundaries 可从 fuzz_dictionary_generator.EntropyBoundaryDetector 获取。
    """
    if mutator is None:
        mutator = StructureAwareMutator()
    return mutator.mutate(seed_data, boundaries)
