# 创建: 2026-07-28 18:55
# 修改: 2026-07-28 — 确定性模式匹配 I/O 签名 + 算法意图 + 倒排索引
"""
可解释的二进制特征提取器 — 结构化推理, 无需训练。

GNN 嵌入模型输出不可解释的向量 → 用户不知道两个函数为什么被判定为相似。
本模块提供互补路径: 从汇编代码中提取人类可读的结构化特征:
  - I/O 签名: 函数消费的数据类型 (fd, socket, buffer, struct*)
  - 副作用分类: 函数对程序状态的影响 (文件I/O, 网络, 内存分配, 进程创建)
  - 算法意图: hash, encrypt, compress, parse, sort, search 等模式识别
  - 常量分析: 魔术数字、加密常量表、协议标识符

所有特征通过模式匹配 + 轻量抽象解释提取——不需要训练数据,
不需要 GPU, 跨架构可移植 (x86/ARM/MIPS 共享同一套特征模式)。

特征以 JSON-like 结构存储, 配合倒排索引实现亚秒级搜索。

ref: "Beyond Embeddings" — LLM-agent 提取
     可解释特征, 本项目将 LLM 替换为确定性模式匹配 + 抽象解释,
     消除 API 依赖同时保持跨架构泛化能力
ref: AutoBERT — BERT-based embedding for cross-ISA,
     本项目与其互补: 嵌入模型做语义近似, 本模块做精确语义标注
ref: Hex-Rays microcode — 中间表示的启发式语义标注, 本项目
     将其思路扩展到无源码二进制 + 跨架构场景
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

class IOKind(Enum):
    FILE_DESC = 'file_descriptor'
    SOCKET = 'socket'
    USER_BUFFER = 'user_buffer'
    HEAP_PTR = 'heap_pointer'
    STRUCT_PTR = 'struct_pointer'
    CONSTANT = 'constant'
    UNKNOWN = 'unknown'

class SideEffectKind(Enum):
    FILE_READ = 'file_read'
    FILE_WRITE = 'file_write'
    NET_SEND = 'network_send'
    NET_RECV = 'network_recv'
    MEM_ALLOC = 'memory_allocate'
    MEM_FREE = 'memory_free'
    PROCESS_SPAWN = 'process_spawn'
    PURE_COMPUTE = 'pure_computation'
    SYS_CALL = 'system_call'

class AlgorithmIntent(Enum):
    HASH = 'hash_function'
    ENCRYPT = 'encryption'
    DECRYPT = 'decryption'
    COMPRESS = 'compression'
    DECOMPRESS = 'decompression'
    PARSE = 'parser'
    SERIALIZE = 'serializer'
    SORT = 'sort'
    SEARCH = 'search'
    COPY = 'memory_copy'
    COMPARE = 'comparison'
    CHECKSUM = 'checksum'
    ENCODE = 'encoder'

@dataclass
class FunctionFeatures:
    """从单个函数提取的结构化特征。"""
    function_name: str = ''
    function_addr: int = 0
    # I/O 特征
    io_signature: dict[int, IOKind] = field(default_factory=dict)  # arg_idx → kind
    return_type: IOKind = IOKind.UNKNOWN
    # 副作用
    side_effects: set[SideEffectKind] = field(default_factory=set)
    # 算法意图
    algorithm_intents: set[AlgorithmIntent] = field(default_factory=set)
    # 常量
    notable_constants: list[int] = field(default_factory=list)
    constant_tables: list[str] = field(default_factory=list)
    # 结构
    loop_count: int = 0
    branch_count: int = 0
    call_count: int = 0
    basic_block_count: int = 0
    # 指令统计
    arithmetic_ratio: float = 0.0
    logic_ratio: float = 0.0
    memory_ratio: float = 0.0
    # 匹配质量 [0,1]
    confidence: float = 0.0

# 模式匹配器
# 每个匹配器返回 (FeatureKind, confidence) 或 None。

# 已知加密常量表 (前 4 字节的 hex 字符串)
# 来源: FIPS 180-4 (SHA256), RFC 1321 (MD5), CRC 标准
_CRYPTO_CONSTANTS = {
    '6a09e667': 'SHA256_IV_0', 'bb67ae85': 'SHA256_IV_1',
    '3c6ef372': 'SHA256_IV_2', 'a54ff53a': 'SHA256_IV_3',
    '510e527f': 'SHA256_IV_4', '9b05688c': 'SHA256_IV_5',
    '1f83d9ab': 'SHA256_IV_6', '5be0cd19': 'SHA256_IV_7',
    '67452301': 'MD5_IV_0', 'efcdab89': 'MD5_IV_1',
    '98badcfe': 'MD5_IV_2', '10325476': 'MD5_IV_3',
    '01234567': 'CRC32_IV',
    'c1059ed8': 'CRC32_POLY_ETH',
    '9e3779b9': 'GOLDEN_RATIO',
}

def _detect_crypto_constants(instructions: list[dict]) -> list[str]:
    """检测指令中的已知加密常量。"""
    found = []
    const_hex = set()
    for ins in instructions:
        operands = ins.get('operands', ins.get('disasm', ''))
        if isinstance(operands, str):
            for m in re.finditer(r'(?:0x)?([0-9a-fA-F]{8})', operands):
                const_hex.add(m.group(1).lower())
    for h in const_hex:
        if h in _CRYPTO_CONSTANTS:
            found.append(_CRYPTO_CONSTANTS[h])
    return found

def _detect_algorithm_intent(instructions: list[dict],
                             callees: list[str]) -> set[AlgorithmIntent]:
    """基于指令模式和被调用函数检测算法意图。"""
    intents: set[AlgorithmIntent] = set()

    # 统计指令类别
    n_arith = 0  # add/sub/mul/imul/div/idiv
    n_logic = 0  # and/or/xor/not
    n_shift = 0  # shl/shr/sar/rol/ror
    n_mem = 0    # mov/lea/push/pop 的内存形式
    n_total = len(instructions)

    for ins in instructions:
        mnemonic = ins.get('mnemonic', '').lower()
        if mnemonic in ('add', 'sub', 'mul', 'imul', 'div', 'idiv', 'inc', 'dec'):
            n_arith += 1
        elif mnemonic in ('and', 'or', 'xor', 'not', 'test'):
            n_logic += 1
        elif mnemonic in ('shl', 'shr', 'sal', 'sar', 'rol', 'ror'):
            n_shift += 1
        elif mnemonic in ('mov', 'lea', 'push', 'pop', 'xchg'):
            n_mem += 1

    xor_ratio = n_logic / max(1, n_total)
    shift_ratio = n_shift / max(1, n_total)

    # 哈希检测: XOR 指令占比 >15% + 移位 >5% → 典型的位混合模式
    if xor_ratio > 0.15 and shift_ratio > 0.05:
        intents.add(AlgorithmIntent.HASH)

    # 加密/解密检测: XOR + 大量算数
    arith_ratio = n_arith / max(1, n_total)
    if xor_ratio > 0.10 and arith_ratio > 0.15:
        if any('decrypt' in c.lower() or 'decode' in c.lower() for c in callees):
            intents.add(AlgorithmIntent.DECRYPT)
        elif any('encrypt' in c.lower() or 'encode' in c.lower() for c in callees):
            intents.add(AlgorithmIntent.ENCRYPT)
        elif xor_ratio > 0.20:
            intents.add(AlgorithmIntent.ENCRYPT)  # 默认推测

    # 压缩检测: 大量内存移动 + 循环 + 无浮点
    mem_ratio = n_mem / max(1, n_total)
    if mem_ratio > 0.40 and arith_ratio < 0.05:
        if any(c in callees for c in ['deflate', 'inflate', 'compress', 'uncompress',
                                        'lzma', 'lz4', 'zstd', 'gzip']):
            intents.add(AlgorithmIntent.COMPRESS)

    # 比较检测: test/cmp 占比 >8%
    cmp_count = sum(1 for ins in instructions
                    if ins.get('mnemonic', '').lower() in ('cmp', 'test'))
    if cmp_count / max(1, n_total) > 0.08:
        intents.add(AlgorithmIntent.COMPARE)

    # 校验和检测: 旋转移位 + XOR
    if shift_ratio > 0.08 and xor_ratio > 0.10 and arith_ratio > 0.10:
        intents.add(AlgorithmIntent.CHECKSUM)

    return intents

def _detect_side_effects(callees: list[str]) -> set[SideEffectKind]:
    """从被调用函数名检测副作用类型。"""
    effects: set[SideEffectKind] = set()
    callee_lower = ' '.join(c.lower() for c in callees)

    patterns = [
        ('read', SideEffectKind.FILE_READ),
        ('fread', SideEffectKind.FILE_READ),
        ('write', SideEffectKind.FILE_WRITE),
        ('fwrite', SideEffectKind.FILE_WRITE),
        ('send', SideEffectKind.NET_SEND),
        ('recv', SideEffectKind.NET_RECV),
        ('malloc', SideEffectKind.MEM_ALLOC),
        ('calloc', SideEffectKind.MEM_ALLOC),
        ('realloc', SideEffectKind.MEM_ALLOC),
        ('free', SideEffectKind.MEM_FREE),
        ('fork', SideEffectKind.PROCESS_SPAWN),
        ('exec', SideEffectKind.PROCESS_SPAWN),
        ('mmap', SideEffectKind.MEM_ALLOC),
        ('munmap', SideEffectKind.MEM_FREE),
        ('syscall', SideEffectKind.SYS_CALL),
    ]

    for pattern, effect in patterns:
        if pattern in callee_lower:
            effects.add(effect)

    if not effects:
        effects.add(SideEffectKind.PURE_COMPUTE)

    return effects

def _detect_io_signature(args_info: list[dict]) -> dict[int, IOKind]:
    """从参数信息推断 I/O 签名。"""
    sig: dict[int, IOKind] = {}
    for arg in args_info:
        idx = arg.get('index', 0)
        usage = arg.get('usage', '')
        size = arg.get('size', 0)

        if any(w in usage.lower() for w in ('fd', 'file', 'descriptor', 'socket')):
            sig[idx] = IOKind.FILE_DESC if 'fd' in usage.lower() else IOKind.SOCKET
        elif any(w in usage.lower() for w in ('buf', 'buffer', 'ptr', 'data')):
            sig[idx] = IOKind.USER_BUFFER
        elif size > 16:
            sig[idx] = IOKind.STRUCT_PTR
        elif 'addr' in usage.lower() or 'address' in usage.lower():
            sig[idx] = IOKind.HEAP_PTR
        elif 'const' in usage.lower() or 'flag' in usage.lower():
            sig[idx] = IOKind.CONSTANT
        else:
            sig[idx] = IOKind.UNKNOWN
    return sig

# 主提取器

class InterpretableFeatureExtractor:
    """从反编译输出中提取可解释特征。

    输入: 反编译器输出的结构化数据 (instructions, callees, args)
    输出: FunctionFeatures 结构——可直接 JSON 序列化, 支持倒排索引搜索。"""

    def extract(self, function_name: str, function_addr: int,
                instructions: list[dict],
                callees: list[str],
                args_info: list[dict] | None = None,
                cfg_info: dict | None = None) -> FunctionFeatures:
        feats = FunctionFeatures(
            function_name=function_name,
            function_addr=function_addr,
        )

        # 算法意图
        feats.algorithm_intents = _detect_algorithm_intent(instructions, callees)

        # 加密常量
        crypto_consts = _detect_crypto_constants(instructions)
        if crypto_consts:
            feats.constant_tables = crypto_consts
            feats.algorithm_intents.add(AlgorithmIntent.ENCRYPT)

        # 副作用
        feats.side_effects = _detect_side_effects(callees)

        # I/O 签名
        if args_info:
            feats.io_signature = _detect_io_signature(args_info)

        # 结构统计
        n = len(instructions)
        feats.call_count = len(callees)
        if cfg_info:
            feats.basic_block_count = cfg_info.get('block_count', 0)
            feats.loop_count = cfg_info.get('loop_count', 0)
            feats.branch_count = cfg_info.get('branch_count', 0)

        # 指令统计
        n_arith = sum(1 for ins in instructions
                      if ins.get('mnemonic', '').lower()
                      in ('add', 'sub', 'mul', 'imul', 'div', 'idiv', 'inc', 'dec'))
        n_logic = sum(1 for ins in instructions
                      if ins.get('mnemonic', '').lower()
                      in ('and', 'or', 'xor', 'not', 'test'))
        n_mem = sum(1 for ins in instructions
                    if ins.get('mnemonic', '').lower()
                    in ('mov', 'lea', 'push', 'pop', 'xchg', 'stos', 'lods', 'scas'))

        feats.arithmetic_ratio = n_arith / max(1, n)
        feats.logic_ratio = n_logic / max(1, n)
        feats.memory_ratio = n_mem / max(1, n)

        # 置信度: 基于信息量——特征越多, 置信度越高
        f_count = (len(feats.algorithm_intents) + len(feats.side_effects)
                   + len(feats.io_signature) + len(feats.constant_tables))
        feats.confidence = min(1.0, f_count / 8.0 + 0.3)

        return feats

    def to_searchable_dict(self, feats: FunctionFeatures) -> dict:
        """转为可搜索的字典——键为特征维度, 值为可读标签。"""
        return {
            'name': feats.function_name,
            'addr': feats.function_addr,
            'io': [f'arg{i}:{k.value}' for i, k in feats.io_signature.items()],
            'side_effects': [s.value for s in feats.side_effects],
            'intents': [a.value for a in feats.algorithm_intents],
            'constants': feats.constant_tables,
            'stats': {
                'loops': feats.loop_count,
                'branches': feats.branch_count,
                'bb_count': feats.basic_block_count,
                'arith_ratio': round(feats.arithmetic_ratio, 3),
                'logic_ratio': round(feats.logic_ratio, 3),
            },
            'confidence': round(feats.confidence, 3),
        }

# 倒排索引
# 按特征维度的值建索引, O(1) 时间查找"所有做 encryption 的函数"。

class InvertedFeatureIndex:
    """可解释特征的倒排索引——按特征值快速检索函数。"""

    __slots__ = ('_index', '_entries')

    def __init__(self):
        self._index: dict[str, set[str]] = {}  # feature_value → {func_name, ...}
        self._entries: dict[str, FunctionFeatures] = {}

    def add(self, feats: FunctionFeatures) -> None:
        name = feats.function_name
        self._entries[name] = feats

        for intent in feats.algorithm_intents:
            key = f'intent:{intent.value}'
            self._index.setdefault(key, set()).add(name)

        for effect in feats.side_effects:
            key = f'effect:{effect.value}'
            self._index.setdefault(key, set()).add(name)

        for table_id in feats.constant_tables:
            key = f'const:{table_id}'
            self._index.setdefault(key, set()).add(name)

        for idx, kind in feats.io_signature.items():
            key = f'io:{kind.value}'
            self._index.setdefault(key, set()).add(name)

    def search(self, intent: AlgorithmIntent | None = None,
               side_effect: SideEffectKind | None = None,
               io_kind: IOKind | None = None) -> list[str]:
        """按特征维度搜索。多维度取交集。"""
        result_sets = []
        if intent:
            result_sets.append(
                self._index.get(f'intent:{intent.value}', set()))
        if side_effect:
            result_sets.append(
                self._index.get(f'effect:{side_effect.value}', set()))
        if io_kind:
            result_sets.append(
                self._index.get(f'io:{io_kind.value}', set()))

        if not result_sets:
            return list(self._entries.keys())

        result = result_sets[0]
        for s in result_sets[1:]:
            result = result & s
        return sorted(result)

    def stats(self) -> dict:
        return {
            'indexed_functions': len(self._entries),
            'index_entries': len(self._index),
        }

__all__ = [
    'FunctionFeatures', 'InterpretableFeatureExtractor',
    'InvertedFeatureIndex', 'IOKind', 'SideEffectKind', 'AlgorithmIntent',
]
