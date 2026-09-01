# 长度字段变异 + 覆盖引导 + LCA 三角化
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional, Callable


@dataclass
class CrashVariant:
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
    variants: list[CrashVariant] = field(default_factory=list)
    common_ancestor_bb: int = 0   # 所有变体共享的基本块
    root_cause_hypothesis: str = ''
    confidence: float = 0.0       # 三角化置信度


# 受控变异策略

def mutate_length_field(input_bytes: bytes,
                        offset: int, size: int,
                        delta: int) -> bytes:
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
