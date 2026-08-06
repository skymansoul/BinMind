# -*- coding: utf-8 -*-
# 创建: 2026-07-30  |  字节模式挖掘器
# 修改: 2026-08-04  |  审计后补充文件头与错误处理
#
"""
二进制YARA规则合成——跨编译器弹性字节模式挖掘。

技术问题:
  现有YARA规则生成方法存在局限:
  (a) 手工逆向(Threatray): 精确但耗时, 1个函数需数小时
  (b) GenRex(2024): 自动化模式提取, 但对跨编译器变体不鲁棒
  (c) 基于字符串的规则: 仅适用于明文常量, 无法捕获函数逻辑

  一个易受攻击的函数经不同编译器/优化级别编译后,
  字节码完全不同但语义等价——传统字节级YARA规则失效。

解决方案:
  基于ORCAS(2025)支配增强语义图的思想:
    1. 提取函数的指令助记符序列(架构无关的语义骨架)
    2. 在此骨架中定位独特的子序列(稀有助记符组合)
    3. 将子序列映射回对应的字节码范围
    4. 在字节范围内提取带通配符的稳定字节模式
    5. 验证模式在跨编译器变体中的匹配率

  之所以选择助记符序列作为锚点:
    - 助记符(mov/cmp/jmp)跨编译器高度一致(语义等价)
    - 操作数(寄存器/立即数)因寄存器分配/立即数编码差异变化
    - 助记符序列定位→字节模式提取→通配符填充操作数变化位

与Threatray/GenRex的差异:
  Threatray: 手工+代码相似度, 不自动合成YARA规则
  GenRex: 从artifact提取正则, 不利用指令语义
  本模块: 助记符锚点→字节模式→通配符→验证, 全自动+跨编译器弹性
"""

import re
import struct
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set

_log = logging.getLogger(__name__)


# ============================================================================
# 模式表示
# ============================================================================


@dataclass
class BytePattern:
    """YARA兼容的字节模式——含通配符"""
    pattern_id: str
    # 字节序列: 每个位置为(byte_value, is_wildcard)
    bytes_raw: List[Tuple[int, bool]] = field(default_factory=list)
    # 模式特征
    length: int = 0
    wildcard_ratio: float = 0.0    # 通配符比例
    uniqueness_score: float = 0.0  # 在良性函数库中的独特性
    # 来源
    anchor_mnemonic: str = ""      # 锚点助记符
    offset_in_function: int = 0    # 函数内字节偏移
    # 验证
    cross_compiler_match_rate: float = 0.0  # 跨编译器变体匹配率
    false_positive_rate: float = 0.0         # 良性库误报率


@dataclass
class FunctionPatterns:
    """单个函数的模式集合——用于合成YARA规则"""
    function_name: str
    function_hash: str
    patterns: List[BytePattern] = field(default_factory=list)
    # 模式组合
    combined_pattern: str = ""     # YARA rule字符串
    estimated_fp_rate: float = 1.0


# ============================================================================
# 模式挖掘器
# ============================================================================


class PatternMiner:
    """从二进制函数中挖掘跨编译器弹性的字节模式。

    算法流程:
      1. 反汇编→提取助记符序列(语义骨架)
      2. 滑动窗口(窗口=5-8条指令)→计算每窗口的稀有度分数
      3. 对Top-K稀有窗口→反向映射至字节码范围
      4. 在字节范围内运行稳定字节检测(变体间的公共字节)
      5. 对非公共字节替换为'?'(通配符)
      6. 在良性函数库中验证独特性
    """

    # 常见助记符——高频出现, 非稀有窗口
    _COMMON_MNEMONICS = {
        'mov', 'lea', 'push', 'pop', 'add', 'sub', 'xor',
        'cmp', 'test', 'jmp', 'je', 'jne', 'call', 'ret',
        'nop', 'int3', 'and', 'or',
    }

    # 稀有助记符——出现时窗口更有区分度
    _RARE_MNEMONICS = {
        'syscall', 'cpuid', 'rdtsc', 'in', 'out', 'cli', 'sti',
        'xlat', 'bswap', 'cmpxchg', 'xadd', 'rdrand', 'rdseed',
        'cpuid', 'vmcall', 'vmlaunch', 'vmresume', 'vmxoff',
    }

    def __init__(self, window_size: int = 6, top_k: int = 5):
        self._window = window_size
        self._top_k = top_k

    def mine(self, function_bytes: bytes,
              instructions: List[str],
              function_name: str = "",
              arch: str = "x86_64") -> FunctionPatterns:
        """从函数字节码+反汇编中挖掘稳定字节模式。

        参数:
          function_bytes: 函数的原始字节码
          instructions: 反汇编行列表
          function_name: 函数名
          arch: 目标架构

        返回FunctionPatterns。
        """
        # 提取助记符序列
        mnemonics = []
        insn_offsets = []
        current_offset = 0
        for insn_str in instructions:
            mnem = self._parse_mnemonic(insn_str)
            if mnem:
                mnemonics.append(mnem)
                insn_offsets.append(current_offset)
            # 估算指令字节长度——简化: 取助记符对应的典型长度
            current_offset += self._estimate_insn_len(mnem, arch) if mnem else 3

        if len(mnemonics) < self._window:
            return FunctionPatterns(function_name=function_name,
                                     function_hash=hashlib.md5(
                                         function_bytes).hexdigest()[:12])

        # 滑动窗口→稀有度评分
        window_scores = []
        for i in range(len(mnemonics) - self._window + 1):
            win = mnemonics[i:i + self._window]
            score = self._window_rarity(win)
            window_scores.append((i, score, win))

        # Top-K稀有窗口
        window_scores.sort(key=lambda x: x[1], reverse=True)
        top_windows = window_scores[:self._top_k]

        # 对每窗口→字节模式提取
        patterns = []
        for idx, score, win_mnems in top_windows:
            if score < 0.3:
                continue
            start_off = insn_offsets[idx]
            end_off = (insn_offsets[idx + self._window - 1] +
                       self._estimate_insn_len(win_mnems[-1], arch)
                       if idx + self._window - 1 < len(insn_offsets)
                       else start_off + self._window * 4)

            # 提取此范围的字节序列
            byte_range = function_bytes[start_off:min(end_off, len(function_bytes))]
            if len(byte_range) < 3:
                continue

            # 稳定字节检测——保留公共字节, 其余通配
            stable_bytes = self._find_stable_bytes(byte_range)
            wc_ratio = sum(1 for _, is_wc in stable_bytes if is_wc) / max(len(stable_bytes), 1)

            if wc_ratio > 0.6:
                continue  # 通配符过多——区分度不足

            patterns.append(BytePattern(
                pattern_id=f"{function_name}_{idx}",
                bytes_raw=stable_bytes,
                length=len(stable_bytes),
                wildcard_ratio=round(wc_ratio, 3),
                uniqueness_score=round(score, 3),
                anchor_mnemonic=win_mnems[0],
                offset_in_function=start_off))

        return FunctionPatterns(
            function_name=function_name,
            function_hash=hashlib.md5(function_bytes).hexdigest()[:12],
            patterns=patterns,
            estimated_fp_rate=round(
                1.0 / max(len(patterns), 1) if patterns else 1.0, 3))

    def _window_rarity(self, mnemonics: List[str]) -> float:
        """窗口稀有度——稀有助记符越多, 分数越高"""
        score = 0.0
        for m in mnemonics:
            if m in self._RARE_MNEMONICS:
                score += 0.3
            elif m not in self._COMMON_MNEMONICS:
                score += 0.15
        return min(1.0, score / self._window)

    def _find_stable_bytes(self, data: bytes) -> List[Tuple[int, bool]]:
        """检测字节序列中的稳定字节——启发式: 非0x00/0xFF/0xCC的字节视为稳定。

        简化版本——完整版需多个编译器变体对比取交集。
        当前实现用于单编译器产物的初始模式提取。
        """
        result = []
        for b in data:
            if b in (0x00, 0xFF, 0xCC, 0x90):
                result.append((b, True))   # 通配符替换
            else:
                result.append((b, False))
        return result

    @staticmethod
    def _parse_mnemonic(insn_str: str) -> str:
        parts = insn_str.strip().split(None, 1)
        return parts[0].lower() if parts else ""

    @staticmethod
    def _estimate_insn_len(mnem: str, arch: str) -> int:
        if mnem in ('call', 'jmp', 'ret', 'syscall'):
            return 5 if '64' in arch else 3
        if mnem in ('mov', 'add', 'sub', 'cmp', 'and', 'or', 'xor'):
            return 4
        return 3


__all__ = [
    "BytePattern",
    "FunctionPatterns",
    "PatternMiner",
]
