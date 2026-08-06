# 语义保持的二进制变体生成——对抗鲁棒性训练数据增强
#
# 核心问题: 二进制分析ML模型对编译器/优化/混淆敏感——
# 同一代码O0 vs O3编译导致GNN嵌入偏移到不同区域。
# 现有obfuscation_resilience.py检测混淆但不生成对抗训练数据。
#
# 技术方案:
#   1. 汇编级语义等价变换: 寄存器重命名、独立指令重排、等价指令替换、NOP填充
#   2. 可控扰动半径: 量化变换对嵌入空间的扰动幅度
#   3. 对抗训练数据: 原始函数→多个变体，标签一致（语义未变）
#   4. 与certified_binary_robustness.py形成防御-训练闭环
#
# 核心变换器实现在 src/variant/semantic_transforms.py

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Tuple, Any

from .src.variant.semantic_transforms import (
    TransformKind, TransformResult, SemanticPreservingTransform,
)

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class AdversarialVariantGenerator:
    """语义保持的二进制对抗变体生成管线。

    用途:
      1. 对抗训练: 对训练集中每个函数生成N个变体，标签不变
      2. 鲁棒性测试: 不同扰动半径下测量模型预测一致性衰减曲线
      3. OOD检测训练: 极端变体（半径>0.5）作为OOD负样本
    """

    def __init__(self, seed: int = 42):
        self._transformer = SemanticPreservingTransform(seed=seed)

    def generate_variants(self,
                          instructions: List[str],
                          n_variants: int = 5,
                          radius_levels: Optional[List[float]] = None
                          ) -> List[Tuple[str, float, List[TransformResult]]]:
        """为一个函数生成多个语义保持变体。

        Returns:
            [(variant_code, actual_radius, transforms_applied), ...]
        """
        if radius_levels is None:
            radius_levels = [0.05, 0.10, 0.20, 0.30, 0.50][:n_variants]

        variants = []
        for level in radius_levels[:n_variants]:
            transforms = self._transformer.apply_transform(
                instructions, max_perturbation=level)
            if not transforms:
                transforms = [TransformResult(
                    original_instr="", transformed_instr="nop",
                    kind=TransformKind.NOP_PAD, perturbation_radius=0.01)]
                variant_lines = ["nop"] + list(instructions)
            else:
                variant_lines = self._apply_all_transforms(
                    list(instructions), transforms)

            actual_radius = sum(t.perturbation_radius for t in transforms)
            variants.append(('\n'.join(variant_lines), actual_radius, transforms))

        return variants

    def _apply_all_transforms(self, lines: List[str],
                              transforms: List[TransformResult]) -> List[str]:
        """将变换列表应用到指令行序列"""
        result = list(lines)
        for t in transforms:
            if t.kind == TransformKind.INST_REORDER:
                for i, line in enumerate(result):
                    if line.strip() == t.original_instr.strip().split('\n')[0]:
                        parts = t.transformed_instr.split('\n')
                        result[i] = parts[0]
                        if len(parts) > 1 and i + 1 < len(result):
                            result[i + 1] = parts[1]
                        break
            elif t.kind == TransformKind.NOP_PAD:
                for i, line in enumerate(result):
                    if line.strip() == t.original_instr.strip():
                        result.insert(i, 'nop')
                        break
            else:
                for i, line in enumerate(result):
                    if line.strip() == t.original_instr.strip():
                        result[i] = t.transformed_instr
                        break
        return result

    def generate_training_set(self,
                              functions: List[Tuple[str, List[str]]],
                              variants_per_func: int = 3
                              ) -> List[Tuple[str, List[str], str]]:
        """为训练集生成对抗增强数据。

        Returns:
            [(variant_func_id, variant_instructions, original_func_id), ...]
        """
        augmented = []
        for func_id, instrs in functions:
            variants = self.generate_variants(instrs, n_variants=variants_per_func)
            for var_code, radius, _ in variants:
                augmented.append((
                    f"{func_id}_v{radius:.2f}",
                    var_code.split('\n'), func_id))
        return augmented
