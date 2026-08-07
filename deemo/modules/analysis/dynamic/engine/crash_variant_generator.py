# 创建: 2026-07-23 21:32
# 修改: 2026-07-23 — 长度字段变异 + 覆盖引导 + LCA 三角化
"""
崩溃变体生成器 — 从单个 PoC 输入变异出多个相关崩溃以三角化根因。

单一崩溃输入可能不足以精确定位根因——不同的崩溃变体
(同一 bug 的不同触发方式) 提供交叉验证信号。

策略:
  1. 受控变异: 仅改变输入中不影响崩溃可达性的字节
     (如 padding/填充字节、长度字段的低位)
  2. 覆盖引导: 保留触发崩溃的核心路径, 探索临近分支
  3. 堆布局扰动: 改变分配大小/顺序以暴露堆相关的时序 bug
  4. 环境扰动: 改变环境变量、文件内容、网络数据以暴露环境依赖

应用:
  - 根因三角化: 多个变体崩溃 → 共同祖先 → 根因
  - 补丁验证: 修复后所有变体不再崩溃 → 补丁正确
  - 可利用性评估: 变体中有 RIP 可控 → 可利用性提升

为什么需要变体生成而非仅用原始 PoC:
  原始 PoC 只能展示一种崩溃路径。如果根因是"无符号整数下溢",
  那么任何触发此下溢的输入都会崩溃——变体生成探索了"其他触发方式"。
  多个变体共享同一最近公共祖先 → 祖先即根因。

ref: Kumushi — AFL++ crash exploration generating variant
     crash traces for fault localization, 本项目简化 AFL++ 为
     受控变异 + 覆盖引导
ref: Crash exploration mode (AFL++) — 探索同一崩溃的不同路径,
     本项目取其理念但使用确定性变异 (非随机 havoc)
ref: Veritas — crash variant triangulation
     用于根因验证, 本项目的变体生成器即其 triangulation 输入
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional, Callable


@dataclass
class CrashVariant:
    """崩溃变体——原始 PoC 的变异版本 + 崩溃信息。"""
    variant_id: str = ''       # SHA-256(input) 前 8 字符
    original_input: bytes = b''
    mutated_input: bytes = b''
    mutation_sites: list[int] = field(default_factory=list)
    crash_addr: int = 0
    crash_type: str = ''
    stack_trace: list[int] = field(default_factory=list)
    parent_variant_id: str = ''  # 由此变体派生的


@dataclass
class TriangulationResult:
    """根因三角化结果——变体集合 + 最近公共祖先。"""
    variants: list[CrashVariant] = field(default_factory=list)
    common_ancestor_bb: int = 0   # 所有变体共享的基本块
    root_cause_hypothesis: str = ''
    confidence: float = 0.0       # 三角化置信度


# 受控变异策略

def mutate_length_field(input_bytes: bytes,
                        offset: int, size: int,
                        delta: int) -> bytes:
    """变异长度字段 (1/2/4/8 字节) — 常用于触发整数溢出变体。"""
    if offset + size > len(input_bytes):
        return bytes(input_bytes)
    arr = bytearray(input_bytes)
    if size == 4:
        original = struct.unpack_from('<I', arr, offset)[0]
        struct.pack_into('<I', arr, offset, max(0, original + delta))
    elif size == 2:
        original = struct.unpack_from('<H', arr, offset)[0]
        struct.pack_into('<H', arr, offset, max(0, (original + delta) & 0xFFFF))
    elif size == 1:
        arr[offset] = max(0, min(255, arr[offset] + delta))
    return bytes(arr)


def mutate_padding_bytes(input_bytes: bytes,
                         padding_ranges: list[tuple[int, int]]) -> bytes:
    """变异填充/对齐字节——不应影响崩溃可达性但可能改变内存布局。"""
    arr = bytearray(input_bytes)
    import random
    rng = random.Random(42)
    for start, end in padding_ranges:
        for i in range(start, min(end, len(arr))):
            arr[i] = rng.randint(0, 255)
    return bytes(arr)


def mutate_environment_context(input_bytes: bytes,
                               env_vars: dict[str, str],
                               seed: int = 0) -> tuple[bytes, dict[str, str]]:
    """扰动环境上下文——保持输入不变, 改变环境。"""
    import random
    rng = random.Random(seed)
    perturbed = dict(env_vars)
    for key in perturbed:
        if rng.random() < 0.3:
            perturbed[key] = perturbed[key] + chr(rng.randint(32, 126))
    return input_bytes, perturbed


# 覆盖引导变异

def coverage_guided_variants(
    input_bytes: bytes,
    target_crash_pc: int,
    executor: Callable[[bytes], tuple[int, bytearray]],  # → (crash_addr, bitmap)
    max_variants: int = 10,
) -> list[CrashVariant]:
    """生成保留崩溃核心路径但探索临近分支的变体。

    对输入的每个字节逐一翻转——若翻转后仍崩溃在同一地址,
    则视为变体; 若崩溃地址不同或未崩溃, 则丢弃。"""
    variants = []
    arr = bytearray(input_bytes)
    base_hash = hashlib.sha256(input_bytes).hexdigest()[:8]

    for i in range(len(arr)):
        if len(variants) >= max_variants:
            break
        original = arr[i]
        # 尝试翻转此字节
        for flip in (original ^ 0x01, original ^ 0xFF,
                     (original + 1) & 0xFF, (original - 1) & 0xFF):
            arr[i] = flip
            mutated = bytes(arr)
            try:
                crash_addr, bitmap = executor(mutated)
                if crash_addr == target_crash_pc:
                    # 同一崩溃地址 → 变体
                    vid = hashlib.sha256(mutated).hexdigest()[:8]
                    variants.append(CrashVariant(
                        variant_id=vid,
                        original_input=input_bytes,
                        mutated_input=mutated,
                        mutation_sites=[i],
                        crash_addr=crash_addr,
                        parent_variant_id=base_hash,
                    ))
                    break  # 此位置找到一个变体→跳到下一字节
            except Exception:
                pass
        arr[i] = original  # 恢复

    return variants


# 根因三角化

def triangulate_root_cause(variants: list[CrashVariant]) -> TriangulationResult:
    """从崩溃变体集合中三角化根因。

    找到所有变体共用栈帧中的最近公共祖先 (LCA) 基本块——
    此块最可能是根因所在。"""
    result = TriangulationResult(variants=variants)

    if not variants:
        return result

    # 提取所有变体的栈帧 (取前 5 帧)
    all_traces = [v.stack_trace[:5] for v in variants if v.stack_trace]
    if not all_traces:
        return result

    # 找到所有栈中共有的基本块——从最后一帧向前找
    common = set(all_traces[0])
    for trace in all_traces[1:]:
        common &= set(trace)

    # 找 common 中最近 (最低地址) 的——最近公共祖先
    if common:
        result.common_ancestor_bb = min(common)
        result.confidence = len(common) / max(1, len(all_traces[0]))

    # 生成假设
    if result.common_ancestor_bb > 0:
        result.root_cause_hypothesis = (
            f'root cause likely in BB @0x{result.common_ancestor_bb:x} '
            f'(shared by {len(variants)} crash variants, '
            f'confidence={result.confidence:.2f})')

    return result


# 变体驱动机

class CrashVariantGenerator:
    """崩溃变体生成器——组合多种变异策略 + 三角化。"""

    __slots__ = ('_variants', '_original_input', '_target_crash_pc')

    def __init__(self):
        self._variants: list[CrashVariant] = []
        self._original_input = b''
        self._target_crash_pc = 0

    def generate(self, original_input: bytes,
                 target_crash_pc: int,
                 executor: Callable,
                 max_variants: int = 20) -> list[CrashVariant]:
        self._original_input = original_input
        self._target_crash_pc = target_crash_pc
        self._variants = []

        # 策略1: 覆盖引导变异
        cov_variants = coverage_guided_variants(
            original_input, target_crash_pc, executor,
            max_variants=max_variants // 2)
        self._variants.extend(cov_variants)

        # 策略2: 长度字段变异
        remaining = max_variants - len(self._variants)
        for delta in (-1, 1, -256, 256, -65536, 65536):
            if len(self._variants) >= max_variants:
                break
            mutated = mutate_length_field(original_input, 0, 4, delta)
            try:
                crash_addr, _ = executor(mutated)
                if crash_addr == target_crash_pc:
                    vid = hashlib.sha256(mutated).hexdigest()[:8]
                    self._variants.append(CrashVariant(
                        variant_id=vid, original_input=original_input,
                        mutated_input=mutated, mutation_sites=[0],
                        crash_addr=crash_addr,
                    ))
            except Exception:
                pass

        return self._variants

    def triangulate(self) -> TriangulationResult:
        return triangulate_root_cause(self._variants)

    def stats(self) -> dict:
        return {
            'variants_generated': len(self._variants),
            'original_input_len': len(self._original_input),
            'target_crash_pc': hex(self._target_crash_pc),
        }


__all__ = [
    'CrashVariantGenerator', 'CrashVariant', 'TriangulationResult',
    'coverage_guided_variants', 'triangulate_root_cause',
    'mutate_length_field', 'mutate_padding_bytes',
]
