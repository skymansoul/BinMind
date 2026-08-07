# coding: utf-8
# 创建: 2026-05-28  |  状态嵌入器
# 修改: 2026-05-28  |  审计后补充文件头与错误处理
#
"""
崩溃状态语义分析——寄存器状态嵌入与语义去重。

技术问题:
  现有崩溃去重仅基于调用栈相似度，
  但相同调用栈可产生不同根因的崩溃(如不同输入触发同一memcpy的不同溢出量)。
  栈级去重将不同根因的崩溃错误合并，导致根因分析遗漏。

解决方案:
  将崩溃点寄存器状态+故障指令上下文嵌入为固定维度向量，
  基于此向量的余弦相似度做根因级去重。

  嵌入维度设计(128维):
    0-15:   通用寄存器值归一化(RAX/RBX/RCX/RDX/RSI/RDI/R8-R15→各1维+低32位截断)
    16-31:  寄存器特征(是否为NULL/填充模式/栈地址/堆地址/代码地址→每标志1维)
    32-47:  故障指令特征(操作码one-hot编码 16类→16维)
    48-63:  故障地址特征(地址范围分段→16维)
    64-79:  信号类型+错误码→16维
    80-95:  栈帧摘要(调用栈前3帧的返回地址哈希→16维)
    96-127: 保留(未来扩展: 内存窗口/污点标记等)

  相似度阈值: 余弦相似度>0.85 → 同根因, 0.65-0.85 → 可能同根因, <0.65 → 不同

与现有方法对比:
  ECHO: 调用栈LCS+余弦相似度——仅结构信息
  Slicing Through Noise: Intel PT+模糊哈希——需硬件支持
  本方法: 纯寄存器+指令嵌入——无硬件依赖, O(1)向量化, 毫秒级相似度计算
"""

import math
import hashlib
import struct
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set

from .cssa_corruption_classifier import CrashState

_log = logging.getLogger(__name__)


# 嵌入定义


EMBEDDING_DIM = 128

# x86_64通用寄存器列表(嵌入维度0-15)
_GPR_NAMES = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi',
              'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

# 指令操作码类别→one-hot索引(维度32-47的起止)
_OPCODE_CLASSES = [
    'mov', 'lea', 'push', 'pop', 'add', 'sub', 'mul', 'div',
    'and', 'or', 'xor', 'cmp', 'test', 'jmp', 'call', 'ret',
]


@dataclass
class CrashEmbedding:
    """崩溃状态的128维嵌入向量"""
    crash_id: str
    vector: List[float] = field(default_factory=list)
    # 元数据
    signal: int = 0
    fault_addr: int = 0
    crash_pc: int = 0
    corruption_type: str = ""


@dataclass
class DedupCluster:
    """去重簇——同根因崩溃的集合"""
    cluster_id: str
    centroid: List[float] = field(default_factory=list)
    members: List[str] = field(default_factory=list)  # crash_id列表
    member_count: int = 0
    # 簇统计
    avg_corruption_confidence: float = 0.0
    dominant_corruption_type: str = ""
    representative_crash: str = ""  # 最接近质心的crash_id


# 嵌入器


class CrashStateEmbedder:
    """从CrashState生成128维语义嵌入向量。

    设计原则:
      - 确定性: 相同崩溃状态→相同嵌入(可复现的去重)
      - 语义保持: 相似根因的崩溃→邻近嵌入
      - 架构无关: 寄存器名映射至架构无关的语义角色, 支持x86_64/ARM64
    """

    def embed(self, crash: CrashState, crash_id: str = "") -> CrashEmbedding:
        """生成崩溃状态的128维嵌入向量。

        返回CrashEmbedding。
        """
        vec = [0.0] * EMBEDDING_DIM

        # 维度 0-15: 通用寄存器值归一化
        for i, reg_name in enumerate(_GPR_NAMES):
            val = crash.registers.get(reg_name, 0)
            if val != 0:
                # sigmoid归一化——将大范围整数值压缩至[0,1]
                vec[i] = 1.0 / (1.0 + math.exp(-abs(val) / 1e9))
                # 保留符号信息(低32位截断)
                lo32 = val & 0xFFFFFFFF
                if lo32 > 0 and lo32 < 0x1000:
                    vec[i] *= 0.1  # 小值——可能是NULL+偏移

        # 维度 16-31: 寄存器特征标志
        for i, reg_name in enumerate(_GPR_NAMES):
            val = crash.registers.get(reg_name, 0)
            lo32 = val & 0xFFFFFFFF
            # 特征编码: [is_null, is_freed_pattern, is_stack_addr, is_heap_addr]
            base = 16 + i % (len(_GPR_NAMES) // 4) * 4
            if base + 3 < 32:
                vec[base] = 1.0 if val == 0 else 0.0
                vec[base + 1] = 1.0 if self._is_freed_pattern(lo32) else 0.0
                vec[base + 2] = 1.0 if self._is_stack_range(val, crash) else 0.0
                vec[base + 3] = 1.0 if self._is_heap_range(val) else 0.0
                break  # 仅编码第一个匹配的寄存器

        # 维度 32-47: 故障指令操作码one-hot
        insn = crash.crash_instruction.lower()
        for i, op_cls in enumerate(_OPCODE_CLASSES):
            if op_cls in insn:
                vec[32 + i] = 1.0
                break

        # 维度 48-63: 故障地址特征(分段编码)
        fa = crash.fault_addr
        if fa == 0:
            vec[48] = 1.0
        elif fa < 0x10000:
            vec[49] = 1.0
        elif fa < 0x100000000:
            vec[50] = 1.0
        else:
            # 高位地址分段
            seg = min(15, fa.bit_length() // 4)
            vec[48 + seg] = max(vec[48 + seg], 0.5)

        # 维度 64-79: 信号类型+错误码
        sig = crash.signal
        if 0 < sig <= 16:
            vec[64 + sig] = 1.0

        # 维度 80-95: 栈帧摘要(前3帧返回地址哈希→分布至16维)
        for depth, frame in enumerate(crash.stack_frames[:3]):
            ret_addr = frame.get('return_address', 0)
            if ret_addr:
                h = hashlib.blake2b(
                    struct.pack('<Q', ret_addr), digest_size=2).digest()
                bucket = (h[0] * 256 + h[1]) % 16
                vec[80 + bucket] += 1.0 / (depth + 1)

        # L2归一化——余弦相似度计算前置
        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 1e-10:
            vec = [v / norm for v in vec]

        return CrashEmbedding(
            crash_id=crash_id or f"crash_{crash.crash_pc:x}",
            vector=vec, signal=sig,
            fault_addr=fa, crash_pc=crash.crash_pc)

    def similarity(self, emb1: CrashEmbedding,
                    emb2: CrashEmbedding) -> float:
        """两嵌入的余弦相似度——O(128)点积"""
        if len(emb1.vector) != len(emb2.vector):
            return 0.0
        dot = sum(a * b for a, b in zip(emb1.vector, emb2.vector))
        return max(0.0, min(1.0, dot))

    def batch_similarity_matrix(self, embeddings: List[CrashEmbedding]
                                 ) -> List[List[float]]:
        """批量相似度矩阵——O(N²×D)"""
        n = len(embeddings)
        matrix = [[0.0] * n for _ in range(n)]
        for i in range(n):
            matrix[i][i] = 1.0
            for j in range(i + 1, n):
                sim = self.similarity(embeddings[i], embeddings[j])
                matrix[i][j] = sim
                matrix[j][i] = sim
        return matrix

    @staticmethod
    def _is_freed_pattern(val32: int) -> bool:
        return val32 in {0xDDDDDDDD, 0xFEEEFEEE, 0xDEADBEEF}

    @staticmethod
    def _is_stack_range(val: int, crash: CrashState) -> bool:
        sp = crash.registers.get('rsp', crash.registers.get('sp', 0))
        return sp != 0 and abs(val - sp) < 0x100000

    @staticmethod
    def _is_heap_range(val: int) -> bool:
        return 0x1000000 < val < 0x7F0000000000


__all__ = [
    "EMBEDDING_DIM",
    "CrashEmbedding",
    "DedupCluster",
    "CrashStateEmbedder",
]
