# -*- coding: utf-8 -*-
# 创建: 2026-08-01  |  种子合成器
# 修改: 2026-08-04  |  审计后补充文件头与错误处理
#
"""
DABSS种子合成引擎——从约束系统合成面向fuzzer的二进制种子。

合成策略: 边界精确→溢出探测→对齐攻击→空指针探测。
输出兼容AFL++命名规范(id:xxxxxx,src:xxxxxx)。
与fuzzing_orchestrator集成: launch_campaign(input_dir=种子目录)。
"""

import os
import struct
import json
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set

from .dabss_constraint_extractor import (
    SeedConstraint,
    VariableConstraint,
    ConstraintType,
    solve_seed_constraints,
)
from .dabss_flow_slicer import BufferSlice

_log = logging.getLogger(__name__)


# ============================================================================
# 种子输出类型
# ============================================================================


@dataclass
class SynthesizedSeed:
    """单条合成种子——可直接写入文件"""
    filename: str
    data: bytes
    # 元数据
    seed_type: str           # boundary | overflow | alignment | null_probe | random
    target_variable: str = ""
    target_value: int = 0
    constraint_source: str = ""   # 约束来源(sink_addr:mnemonic)
    # 质量指标
    constraint_satisfaction_rate: float = 0.0  # 满足约束的比例
    expected_path: str = ""                     # 预期触发的执行路径


@dataclass
class SeedCorpus:
    """完整种子语料——可直接注入fuzzer输入目录"""
    target_function: str
    target_binary: str
    seeds: List[SynthesizedSeed] = field(default_factory=list)
    total_seeds: int = 0
    total_bytes: int = 0
    # 语料统计
    boundary_seeds: int = 0
    overflow_seeds: int = 0
    alignment_seeds: int = 0
    null_probe_seeds: int = 0
    metadata_path: str = ""


# ============================================================================
# 种子合成器
# ============================================================================


class SeedSynthesizer:
    """种子合成器——约束→边界测试值→二进制种子。

    合成逻辑:
      边界精确: 取边界值±{0, 1}作为种子字节
      溢出探测: 取边界值+{1, 4, 16, 256}作为溢出输入
      对齐攻击: 取对齐值+{1, 3, 7}作为非对齐输入
    """

    # 字节序映射——架构→struct格式
    _ENDIAN_MAP = {
        'x86_64': '<', 'x86': '<', 'amd64': '<',
        'arm64': '<', 'arm32': '<', 'aarch64': '<',
        'mips32': '>', 'mips64': '>',
    }

    def __init__(self, arch: str = "x86_64"):
        self._arch = arch
        self._endian = self._ENDIAN_MAP.get(arch, '<')
        self._ptr_size = 8 if '64' in arch else 4

    def synthesize(self, seed_constraints: List[SeedConstraint],
                    slices: List[BufferSlice] = None,
                    function_name: str = "",
                    binary_path: str = ""
                    ) -> SeedCorpus:
        """从约束集合合成完整种子语料。

        每条SeedConstraint产出多颗种子（边界/溢出/对齐变体）。
        """
        corpus = SeedCorpus(
            target_function=function_name,
            target_binary=binary_path)

        for sc in seed_constraints:
            # 1. 边界精确种子
            for val in sc.boundary_values:
                seed_data = self._pack_value(val, sc.buffer_size_hint)
                corpus.seeds.append(SynthesizedSeed(
                    filename=f"seed_bound_{self._hash_val(val)}.bin",
                    data=seed_data,
                    seed_type="boundary",
                    target_value=val,
                    constraint_satisfaction_rate=1.0))

            # 2. 溢出探测种子
            if sc.buffer_size_hint > 0:
                h = sc.buffer_size_hint
                for overflow in [h + 1, h + 4, h + 16, h + 256, h * 2]:
                    if overflow <= 65536:
                        seed_data = self._pack_value(overflow, h)
                        corpus.seeds.append(SynthesizedSeed(
                            filename=f"seed_overflow_{overflow}.bin",
                            data=seed_data,
                            seed_type="overflow",
                            target_value=overflow,
                            constraint_satisfaction_rate=0.0))
                        corpus.overflow_seeds += 1

            # 3. 对齐攻击种子——偏移1/3/7字节破坏对齐
            for vc in sc.constraints:
                if vc.constraint_type == ConstraintType.ALIGN and vc.value > 1:
                    for misalign in [1, 3, 7]:
                        seed_data = self._pack_unaligned(
                            sc.buffer_size_hint, vc.value, misalign)
                        corpus.seeds.append(SynthesizedSeed(
                            filename=f"seed_misalign_{vc.value}_{misalign}.bin",
                            data=seed_data,
                            seed_type="alignment",
                            constraint_source=f"align={vc.value}",
                            constraint_satisfaction_rate=0.0))
                        corpus.alignment_seeds += 1

            # 4. 空指针探测种子——0x0/0x1/0xFF等小地址值
            for null_val in [0, 1, 0xFF, 0x1000]:
                seed_data = self._pack_value(null_val, sc.buffer_size_hint)
                corpus.seeds.append(SynthesizedSeed(
                    filename=f"seed_null_{null_val:x}.bin",
                    data=seed_data,
                    seed_type="null_probe",
                    target_value=null_val))
                corpus.null_probe_seeds += 1

        # 汇总统计
        corpus.total_seeds = len(corpus.seeds)
        corpus.total_bytes = sum(len(s.data) for s in corpus.seeds)
        corpus.boundary_seeds = sum(
            1 for s in corpus.seeds if s.seed_type == "boundary")

        # 生成语料元数据
        corpus.metadata_path = self._write_metadata(corpus, seed_constraints)

        return corpus

    def _pack_value(self, val: int, buf_hint: int = 0) -> bytes:
        """将整数值打包为种子字节序列。

        策略: 若buf_hint>0，生成hint字节的缓冲区，
        在其中填充边界值（小端/大端按架构）。
        """
        size = max(buf_hint, self._ptr_size, 4)
        data = b'\x41' * size  # 用'A'填充基线

        if val == 0:
            return data  # 零值——保留基线填充
        # 在缓冲区末尾附近放置边界值
        offset = max(0, size - self._ptr_size)
        try:
            packed = struct.pack(f'{self._endian}Q', val)[:self._ptr_size]
        except struct.error:
            packed = struct.pack(f'{self._endian}I', val & 0xFFFFFFFF)[:4]
        data = (data[:offset] + packed +
                data[offset + len(packed):])
        return data[:size]

    def _pack_unaligned(self, buf_hint: int, alignment: int,
                          misalign: int) -> bytes:
        """生成非对齐数据——在预期对齐位置插入偏移"""
        size = max(buf_hint, 16)
        data = bytearray(b'\x42' * size)
        # 在对齐边界处插入非对齐标记
        for i in range(misalign, size, alignment):
            data[i] = 0xFF
        return bytes(data)

    def _write_metadata(self, corpus: SeedCorpus,
                         constraints: List[SeedConstraint]) -> str:
        """写入语料元数据JSON——含约束信息与路径期望"""
        meta = {
            'target_function': corpus.target_function,
            'target_binary': corpus.target_binary,
            'total_seeds': corpus.total_seeds,
            'total_bytes': corpus.total_bytes,
            'breakdown': {
                'boundary': corpus.boundary_seeds,
                'overflow': corpus.overflow_seeds,
                'alignment': corpus.alignment_seeds,
                'null_probe': corpus.null_probe_seeds,
            },
            'constraints': [{
                'buffer_size_hint': sc.buffer_size_hint,
                'constraint_count': sc.constraint_count,
                'boundary_values': sc.boundary_values[:8],
            } for sc in constraints[:10]],  # 最多记录10条
            'arch': self._arch,
            'endian': self._endian,
        }
        return json.dumps(meta, indent=2)

    @staticmethod
    def _hash_val(val: int) -> str:
        return hashlib.md5(str(val).encode()).hexdigest()[:8]


# ============================================================================
# 种子导出——适配fuzzer输入格式
# ============================================================================


def export_to_fuzzer_dir(corpus: SeedCorpus, output_dir: str,
                          fuzzer_type: str = "aflpp") -> str:
    """导出种子至fuzzer输入目录。

    AFL++命名: id_XXXXXX_src_dabss_type_boundary (':'在Windows路径非法，用'_'替代)
    libFuzzer: 任意文件名
    """
    os.makedirs(output_dir, exist_ok=True)
    counter = 0
    for seed in corpus.seeds:
        if fuzzer_type in ('afl', 'aflpp'):
            fname = os.path.join(output_dir,
                                  f"id_{counter:06d}_src_dabss_"
                                  f"type_{seed.seed_type}_"
                                  f"val_{seed.target_value}")
        else:
            fname = os.path.join(output_dir, seed.filename)
        with open(fname, 'wb') as f:
            f.write(seed.data)
        counter += 1

    # 写入元数据
    if corpus.metadata_path:
        meta_file = os.path.join(output_dir, 'dabss_corpus_meta.json')
        with open(meta_file, 'w') as f:
            f.write(corpus.metadata_path)

    _log.info("导出%d颗种子至%s (%s格式)", counter, output_dir, fuzzer_type)
    return output_dir


# ============================================================================
# 便捷入口
# ============================================================================


def synthesize_seeds_from_slices(slices: List[BufferSlice],
                                   arch: str = "x86_64",
                                   function_name: str = "",
                                   output_dir: str = ""
                                   ) -> SeedCorpus:
    """从数据流切片直接合成种子——单行调用。

    返回SeedCorpus。
    """
    from .dabss_constraint_extractor import ConstraintExtractor
    extractor = ConstraintExtractor()
    constraints = extractor.extract(slices, function_name)
    synthesizer = SeedSynthesizer(arch)
    corpus = synthesizer.synthesize(constraints, slices, function_name)
    if output_dir:
        export_to_fuzzer_dir(corpus, output_dir)
    return corpus


__all__ = [
    "SynthesizedSeed",
    "SeedCorpus",
    "SeedSynthesizer",
    "export_to_fuzzer_dir",
    "synthesize_seeds_from_slices",
]
