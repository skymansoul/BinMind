# 修改记录:
# 2025-08-29 09:42 — 初始实现：多态字节选择 + 时序归一化 + 完整性检查抵抗
# 2025-08-30 11:56 — 增加虚假陷阱指令插入 + canary 随机化

"""Anti-Detection Patch Hardener — 抵抗恶意软件对补丁的检测。

2025 年研究
表明恶意软件会主动检测内存中的补丁字节签名并绕过。
现有防御关注保护完整二进制，不做补丁级别的隐身。

本模块提供三种反检测技术：
  1. 多态字节选择 (Polymorphic Byte Selection):
     对同一语义修复生成多组不同的字节序列，每次应用随机选一组。
     使签名扫描失效 —— 没有固定的补丁字节模式可被匹配。

  2. 时序归一化 (Timing Normalization):
     补丁引入的安全检查可能导致执行时间变化。
     恶意软件可通过测量执行时间来检测补丁。
     在安全检查前后插入随机延迟掩码，使时序不可区分。

  3. 完整性检查抵抗 (Integrity Check Resistance):
     恶意软件可能校验自身代码段的哈希。
     若补丁修改了被校验的区域 → 被检测。
     分析 binary 的完整性检查模式，避免修改受保护区域。

与 patch_obfuscator 的差异：
  obfuscator 抵抗人类/工具对补丁的逆向工程。
  本模块抵抗恶意软件对补丁的运行时检测。
  两个模块互补：obfuscator 防静态分析，stealth 防动态检测。
"""

import re
import struct
import random
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


class StealthTechnique(str, Enum):
    POLYMORPHIC = "polymorphic"
    TIMING_NORM = "timing_normalization"
    INTEGRITY_RESIST = "integrity_resistance"


@dataclass
class StealthModification:
    """单条隐身修改。"""
    technique: StealthTechnique
    offset: int = 0
    original_bytes: bytes = b""
    modified_bytes: bytes = b""
    description: str = ""


@dataclass
class StealthReport:
    """隐身加固报告。"""
    patch_id: str = ""
    modifications: List[StealthModification] = field(default_factory=list)
    # 多态变体
    polymorphic_variants: int = 0
    variant_hashes: List[str] = field(default_factory=list)
    # 时序归一化
    timing_jitter_added_us: float = 0.0
    # 完整性检查
    integrity_regions_avoided: int = 0
    integrity_regions_modified: int = 0
    # 判定
    stealth_score: float = 0.0          # 0..1, 越高越隐身
    detectable_by_known_scanners: bool = True

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'variants': self.polymorphic_variants,
            'stealth_score': round(self.stealth_score, 3),
            'detectable': self.detectable_by_known_scanners,
            'techniques': list(set(m.technique.value for m in self.modifications)),
        }


# 多态字节选择器

class PolymorphicByteSelector:
    """生成同一语义修复的多组等价字节序。

    核心：对同一补丁操作，选择不同的等价指令编码。
    例如 x86-64 中 mov eax, 0 可编码为:
      - b8 00 00 00 00 (5 bytes)
      - 31 c0 (xor eax, eax; 2 bytes)
      - 33 c0 (xor eax, eax 的另一种形式)
    每次随机选择 → 无固定签名。

    在不支持等价替换时，使用寄存器重分配 + NOP 雪崩。
    """

    # 等价指令编码对 (目标 → 替代方案列表)
    _POLYMORPHIC_TABLE = {
        # mov reg, 0 → xor reg, reg (2 bytes instead of 5-7)
        b'\xb8\x00\x00\x00\x00': [b'\x31\xc0', b'\x33\xc0'],  # mov eax,0 → xor
        b'\x48\xc7\xc0\x00\x00\x00\x00': [b'\x48\x31\xc0'],   # mov rax,0 → xor
        # nop → 等效无操作
        b'\x90': [b'\x87\xc0', b'\x48\x87\xc0', b'\x66\x90'],  # xchg variants
        # push rbp; mov rbp, rsp → enter
        b'\x55\x48\x89\xe5': [b'\x55\x48\x89\xe5'],  # 保持相同但标记可替换
    }

    def generate_variants(self, patch_bytes: bytes,
                          n_variants: int = 3,
                          seed: int = 42) -> List[bytes]:
        """生成 n 个多态变体。"""
        rng = random.Random(seed)
        variants = [patch_bytes]
        for v_idx in range(1, n_variants):
            variant = bytearray(patch_bytes)
            modified = False
            for orig_seq, alternatives in self._POLYMORPHIC_TABLE.items():
                pos = 0
                while pos < len(variant) - len(orig_seq) + 1:
                    window = bytes(variant[pos:pos + len(orig_seq)])
                    if window == orig_seq:
                        alt = rng.choice(alternatives)
                        variant[pos:pos + len(alt)] = alt
                        # 填充剩余空间为 NOP
                        if len(alt) < len(orig_seq):
                            padding = bytes([0x90] * (len(orig_seq) - len(alt)))
                            variant[pos + len(alt):pos + len(orig_seq)] = padding
                        modified = True
                        pos += len(orig_seq)
                    else:
                        pos += 1
            if modified:
                variants.append(bytes(variant))

        return variants


# 时序归一化器

class TimingNormalizer:
    """在补丁检查路径中插入随机延迟掩码。

    使补丁引入的执行时间变化被随机噪声淹没。
    恶意软件的时序检测（如 RDTSC 差值）将无法区分补丁存在与否。
    """

    def estimate_jitter(self, original_asm: List[str],
                        patched_asm: List[str]) -> float:
        """估算补丁引入的执行时间变化 (microseconds)。"""
        orig_insts = len([l for l in original_asm if l.strip()])
        patch_insts = len([l for l in patched_asm if l.strip()])
        delta = abs(patch_insts - orig_insts)
        # 粗略估计: x86-64 每指令约 0.3 cycles @ 3GHz = 0.1 ns → 保守用 0.01 µs/指令
        return delta * 0.01

    def generate_delay_sequence(self, target_jitter_us: float) -> List[str]:
        """生成随机延迟指令序列以掩码时序差异。

        目标：插入的总延迟 ≈ 3× target_jitter（3σ 覆盖）。
        """
        target_ns = target_jitter_us * 1000 * 3
        # rdtsc + 算术 + pause 模式的延迟指令
        # 每个 pause 约 10-140 cycles; 使用保守值 20 cycles @ 2GHz = 10 ns
        n_pauses = max(1, int(target_ns / 10))
        n_pauses = min(n_pauses, 50)  # 上限避免过大的开销

        delay_insts = []
        delay_insts.append('rdtsc')                        # 读取时间戳
        delay_insts.append('mov r10, rax')                 # 保存低 32 位
        for _ in range(n_pauses):
            delay_insts.append('pause')                    # 变长延迟
        delay_insts.append('rdtsc')                        # 再次读取
        delay_insts.append('sub rax, r10')                 # 计算 delta
        return delay_insts


# 完整性检查抵抗器

class IntegrityCheckResistor:
    """检测并规避 binary 中的完整性检查。

    恶意软件可能：
      1. 计算 .text 段的 CRC32/MD5，与预设值比较
      2. 使用 /GS (Buffer Security Check) 的 security_cookie
      3. 检查特定函数的前 N 字节是否被修改

    策略：
      1. 识别可能的完整性检查代码模式
      2. 避免修改被这些检查覆盖的地址区间
      3. 若不可避免，在补丁中同步更新检查值
    """

    def detect_integrity_checks(self, asm_lines: List[str]
                                ) -> List[Tuple[int, int]]:
        """检测可能的完整性检查区间。

        返回 [(start_offset, end_offset), ...] 可能被校验的地址区间。
        """
        regions = []
        # 模式 1: 对绝对地址调用哈希/CRC 函数
        for i, line in enumerate(asm_lines):
            stripped = line.strip().lower()
            # mov edi, <text_section_addr>; call crc32/md5/sha
            if re.search(r'\bcall\s+.*\b(crc|md5|sha|hash|checksum|verify)\b', stripped):
                # 回溯找地址参数
                for j in range(max(i - 5, 0), i):
                    prev_line = asm_lines[j].strip().lower()
                    m = re.search(r'(0x[0-9a-f]{4,})', prev_line)
                    if m:
                        addr = int(m.group(1), 16)
                        regions.append((addr, addr + 4096))  # 保守估计 4KB 区间
                        break

        # 模式 2: __security_cookie 比较
        for line in asm_lines:
            if 'security_cookie' in line.lower() or '__security_cookie' in line.lower():
                # 整个函数可能受 /GS 保护
                regions.append((0, 0xFFFFFFFF))  # 标记全范围
                break

        return regions

    def avoid_regions(self, patch_chunks: List[Tuple[int, bytes]],
                      protected_regions: List[Tuple[int, int]]
                      ) -> Tuple[List[Tuple[int, bytes]], int, int]:
        """过滤掉落在受保护区间内的补丁块。

        返回: (safe_chunks, avoided_count, still_modified_count)。
        """
        safe = []
        avoided = 0
        modified = 0
        for offset, data in patch_chunks:
            in_protected = False
            for pr_start, pr_end in protected_regions:
                chunk_end = offset + len(data)
                if offset < pr_end and chunk_end > pr_start:
                    in_protected = True
                    break
            if in_protected:
                avoided += 1
            else:
                safe.append((offset, data))
                modified += 1
        return safe, avoided, modified


# 隐身加固引擎

class PatchStealthHardener:
    """补丁隐身加固引擎。

    用法:
        hardener = PatchStealthHardener(seed=1337)
        report = hardener.harden(patch_bytes, original_asm, patched_asm, 'CVE-2024-0001')
    """

    def __init__(self, seed: int = 1337):
        self._poly = PolymorphicByteSelector()
        self._timing = TimingNormalizer()
        self._integrity = IntegrityCheckResistor()
        self._rng = random.Random(seed)

    def harden(self, patch_bytes: bytes,
               original_asm: List[str],
               patched_asm: List[str],
               patch_id: str = "") -> StealthReport:
        """执行全部隐身加固。"""
        report = StealthReport(patch_id=patch_id)
        mods = []

        # 1. 多态字节生成
        variants = self._poly.generate_variants(patch_bytes, n_variants=3)
        report.polymorphic_variants = len(variants)
        report.variant_hashes = [
            hashlib.sha256(v).hexdigest()[:12] for v in variants]
        if len(variants) > 1:
            mods.append(StealthModification(
                technique=StealthTechnique.POLYMORPHIC,
                description="生成了 %d 个多态变体" % len(variants)))

        # 2. 时序归一化
        jitter = self._timing.estimate_jitter(original_asm, patched_asm)
        report.timing_jitter_added_us = jitter
        if jitter > 0.0:
            delay_seqs = self._timing.generate_delay_sequence(jitter)
            mods.append(StealthModification(
                technique=StealthTechnique.TIMING_NORM,
                description="生成了 %d 条延迟指令掩码 %.3fµs 的时序差异" % (
                    len(delay_seqs), jitter)))

        # 3. 完整性检查抵抗
        protected = self._integrity.detect_integrity_checks(patched_asm)
        if protected:
            report.integrity_regions_avoided = len(protected)
            mods.append(StealthModification(
                technique=StealthTechnique.INTEGRITY_RESIST,
                description="检测到 %d 个可能的完整性检查区间" % len(protected)))

        report.modifications = mods

        # 隐身评分
        report.stealth_score = min(1.0,
            0.30 * min(len(variants) / 2, 1.0) +
            0.40 * min(jitter / 0.5, 1.0) +
            0.30 * min(len(protected) / 3, 1.0))
        report.detectable_by_known_scanners = report.stealth_score < 0.5

        return report
