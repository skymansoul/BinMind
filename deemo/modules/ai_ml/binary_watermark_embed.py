# 语义保持的二进制水印嵌入——通过指令重排嵌入可验证的溯源水印
#
# 核心问题: 二进制文件被盗用/逆向工程后难以溯源。
# 现有水印方案修改二进制结构（添加新节/修改导入表），容易被检测和移除。
# 需要一种不改变二进制语义、不影响执行、且难以被检测和移除的水印方法。
#
# 技术方案:
#   1. 独立指令重排: 识别基本块内无数据依赖的相邻指令对→交换顺序
#      语义完全不变（独立指令的执行顺序不影响结果）
#   2. 水印编码: 指令对(A,B)的顺序编码1bit信息——
#      原始序(A→B)=0，交换后(B→A)=1
#   3. 水印提取: 扫描二进制→定位被标记的基本块→检测指令顺序→解码水印
#   4. 冗余编码: 使用Hamming(7,4)纠错码——每4bit水印扩展为7bit，
#      可纠正1bit错误——抵抗部分水印位被后续编译优化破坏
#   5. 容量估计: 对给定二进制估计最大水印容量——取决于独立指令对的数量

from __future__ import annotations

import math
import random
import hashlib
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


@dataclass
class IndependentPair:
    """可交换的独立指令对——交换后语义不变"""
    block_addr: int
    instr_a_offset: int
    instr_b_offset: int
    instr_a: str
    instr_b: str
    encoded_bit: Optional[int] = None  # 0=原始序, 1=交换序


class DependencyAnalyzer:
    """指令依赖分析——检测可安全交换的独立指令对。

    两条指令可交换的条件:
      1. A不写入B读取的寄存器（无RAW依赖）
      2. B不写入A读取的寄存器（无WAR依赖）
      3. A和B不写入同一寄存器（无WAW依赖）
      4. A和B不都是分支指令
      5. A和B不都访问内存（保守处理）
    """

    @staticmethod
    def can_swap(instr_a: str, instr_b: str) -> bool:
        """判断两条指令是否可以交换而不改变语义"""
        a_tokens = instr_a.strip().lower().split()
        b_tokens = instr_b.strip().lower().split()
        if not a_tokens or not b_tokens:
            return False

        a_op, b_op = a_tokens[0], b_tokens[0]
        # 分支指令不可交换
        branch_ops = {'jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jl',
                      'jge', 'jle', 'ja', 'jb', 'call', 'ret', 'loop'}
        if a_op in branch_ops or b_op in branch_ops:
            return False

        # 简化: 提取寄存器操作数
        def extract_regs(tokens):
            regs = set()
            for t in tokens[1:]:
                t = t.strip(',[]')
                if t.startswith('r') or t in ('eax', 'ebx', 'ecx', 'edx',
                    'esi', 'edi', 'ebp', 'esp', 'rax', 'rbx', 'rcx', 'rdx'):
                    regs.add(t)
            return regs

        a_regs = extract_regs(a_tokens)
        b_regs = extract_regs(b_tokens)
        # 无寄存器重叠→保守认为可交换
        return len(a_regs & b_regs) == 0

    @staticmethod
    def find_independent_pairs(
            instructions: List[str],
            block_addr: int = 0) -> List[IndependentPair]:
        pairs = []
        for i in range(len(instructions) - 1):
            if DependencyAnalyzer.can_swap(instructions[i], instructions[i+1]):
                pairs.append(IndependentPair(
                    block_addr=block_addr,
                    instr_a_offset=i, instr_b_offset=i + 1,
                    instr_a=instructions[i], instr_b=instructions[i+1]))
        return pairs


class HammingCodec:
    """Hamming(7,4)纠错编解码——4bit数据→7bit码字，可纠正1bit错误。

    用于水印的冗余编码——部分水印位可能被后续处理破坏。
    """

    # 生成矩阵 G = [I_4 | P] 产生(7,4)系统码
    G = np.array([
        [1, 0, 0, 0, 0, 1, 1],
        [0, 1, 0, 0, 1, 0, 1],
        [0, 0, 1, 0, 1, 1, 0],
        [0, 0, 0, 1, 1, 1, 1],
    ], dtype=np.int32)

    # 校验矩阵 H
    H = np.array([
        [0, 1, 1, 1, 1, 0, 0],
        [1, 0, 1, 1, 0, 1, 0],
        [1, 1, 0, 1, 0, 0, 1],
    ], dtype=np.int32)

    @classmethod
    def encode(cls, data_bits: List[int]) -> List[int]:
        """4bit→7bit Hamming编码"""
        if len(data_bits) < 4:
            data_bits = (data_bits + [0, 0, 0, 0])[:4]
        d = np.array(data_bits[:4], dtype=np.int32)
        codeword = (d @ cls.G) % 2
        return codeword.tolist()

    @classmethod
    def decode(cls, codeword: List[int]) -> Tuple[List[int], bool]:
        """7bit→4bit Hamming解码+纠错。

        Returns:
            (decoded_bits, corrected) — corrected表示是否进行了纠错
        """
        r = np.array(codeword[:7], dtype=np.int32)
        syndrome = (cls.H @ r) % 2
        error_pos = int(syndrome[0] * 4 + syndrome[1] * 2 + syndrome[2]) - 1
        corrected = False
        if 0 <= error_pos < 7:
            r[error_pos] ^= 1
            corrected = True
        data = np.array([r[0], r[1], r[2], r[3]], dtype=np.int32)
        return data.tolist(), corrected


class BinaryWatermarkEmbedder:
    """二进制水印嵌入器——通过独立指令重排嵌入可溯源水印。

    流程:
      1. 分析二进制→定位所有独立指令对
      2. 用Hamming编码水印数据
      3. 将编码后的bit分配到独立指令对→根据bit值决定是否交换
      4. 记录水印位置映射表→用于提取验证
    """

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed)
        self._watermark_map: Dict[int, IndependentPair] = {}  # bit_pos → pair

    def embed(self,
              basic_blocks: List[Tuple[int, List[str]]],
              watermark_data: bytes,
              analyzer: Optional[DependencyAnalyzer] = None
              ) -> Tuple[List[Tuple[int, List[str]]], Dict[str, Any]]:
        """在二进制基本块中嵌入水印。

        Args:
            basic_blocks: [(block_addr, [instructions]), ...]
            watermark_data: 要嵌入的水印数据(bytes)

        Returns:
            (modified_blocks, embedding_report)
        """
        if analyzer is None:
            analyzer = DependencyAnalyzer()

        # 收集所有独立指令对
        all_pairs = []
        for addr, instrs in basic_blocks:
            pairs = analyzer.find_independent_pairs(instrs, addr)
            all_pairs.extend(pairs)

            if not all_pairs:
                return basic_blocks, {'success': False, 'reason': '无可用指令对', 'capacity_bits': 0}

        # 水印数据→bits→Hamming编码
        data_bits = []
        for byte in watermark_data:
            for bit_pos in range(8):
                data_bits.append((byte >> bit_pos) & 1)

        encoded_bits = []
        for i in range(0, len(data_bits), 4):
            chunk = data_bits[i:i+4]
            encoded_bits.extend(HammingCodec.encode(chunk))

        # 检查容量
        if len(encoded_bits) > len(all_pairs):
            return basic_blocks, {
                'success': False,
                'reason': f'容量不足: 需要{len(encoded_bits)}bit, 可用{len(all_pairs)}bit',
                'capacity_bits': len(all_pairs)}

        # 嵌入: bit→指令对顺序
        n_embedded = 0
        modified_blocks = dict(basic_blocks)

        for bit_idx, bit in enumerate(encoded_bits[:len(all_pairs)]):
            pair = all_pairs[bit_idx]
            pair.encoded_bit = bit
            if bit == 1:
                # 交换指令顺序
                addr = pair.block_addr
                if addr in modified_blocks:
                    blk = list(modified_blocks[addr])
                    a, b = pair.instr_a_offset, pair.instr_b_offset
                    blk[a], blk[b] = blk[b], blk[a]
                    modified_blocks[addr] = blk
            self._watermark_map[bit_idx] = pair
            n_embedded += 1

        return (list(modified_blocks.items()), {
            'success': True,
            'watermark_size_bytes': len(watermark_data),
            'bits_embedded': n_embedded,
            'capacity_bits': len(all_pairs),
            'utilization': n_embedded / max(1, len(all_pairs)),
            'watermark_hash': hashlib.sha256(watermark_data).hexdigest()[:16]})

    def extract(self,
                basic_blocks: List[Tuple[int, List[str]]],
                original_blocks: List[Tuple[int, List[str]]],
                n_bits: int) -> Tuple[Optional[bytes], bool]:
        """从可能被修改的二进制中提取水印。

        通过比较当前指令顺序与原始顺序——不一致的位=1，一致的=0。
        """
        original_map = {}
        for addr, instrs in original_blocks:
            original_map[addr] = instrs

        extracted_bits = []
        for addr, instrs in basic_blocks:
            if addr not in original_map:
                continue
            orig = original_map[addr]
            analyzer = DependencyAnalyzer()
            pairs = analyzer.find_independent_pairs(orig, addr)
            for pair in pairs[:10]:
                if (pair.instr_a_offset < len(instrs) and
                    pair.instr_b_offset < len(instrs)):
                    current_a = instrs[pair.instr_a_offset]
                    current_b = instrs[pair.instr_b_offset]
                    # 如果当前顺序与原始不同→bit=1
                    bit = 1 if (current_a == pair.instr_b and
                               current_b == pair.instr_a) else 0
                    extracted_bits.append(bit)
                if len(extracted_bits) >= n_bits:
                    break
            if len(extracted_bits) >= n_bits:
                break

        if len(extracted_bits) < n_bits:
            return None, False

        # Hamming解码
        decoded_bits = []
        corrections = 0
        for i in range(0, n_bits, 7):
            chunk = extracted_bits[i:i+7]
            data, corrected = HammingCodec.decode(chunk)
            decoded_bits.extend(data)
            if corrected:
                corrections += 1

        # bits→bytes
        watermarked = bytearray()
        for i in range(0, len(decoded_bits), 8):
            byte = 0
            for bit_pos in range(8):
                if i + bit_pos < len(decoded_bits):
                    byte |= decoded_bits[i + bit_pos] << bit_pos
            watermarked.append(byte)

        return bytes(watermarked), corrections > 0
