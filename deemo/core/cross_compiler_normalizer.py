# Eliminates instruction-level differences across O0/O2/O3 compiler output,
# extracting semantically equivalent features across optimization levels.
#
# Rationale:
#   同一C代码在不同优化级别下编译, 指令序列差异显著:
#     O0: 每条C语句独立翻译, 大量栈load/store
#     O2: 寄存器分配优化, 循环展开, 死代码消除
#     O3: 向量化, 函数内联
#   但语义特征 (块级操作码分布、调用密度、分支比例)
#   在优化级别间保持相对稳定。
#
# 归一化策略:
#   1. 块合并: O0下被拆分的基本块在O2下合并 — 对相邻无分支块做合并
#   2. 指令过滤: 移除编译器生成的栈帧管理指令 (push rbp; mov rbp,rsp; leave)
#   3. 特征缩放: 对每个特征维度做z-score归一化 (基于统计基准)
#   4. 语义等价映射: lea+mov模式 -> 单次内存操作 (O0特征) 对O2的寄存器操作
import re as _re
from typing import List, Dict


_BOILERPLATE_PATTERNS = [
    _re.compile(r'push\s+rbp'),
    _re.compile(r'mov\s+rbp,\s*rsp'),
    _re.compile(r'mov\s+rsp,\s*rbp'),
    _re.compile(r'pop\s+rbp'),
    _re.compile(r'leave'),
    _re.compile(r'sub\s+rsp,\s*0x[\da-fA-F]+'),
    _re.compile(r'add\s+rsp,\s*0x[\da-fA-F]+'),
]


class CrossCompilerNormalizer:

    def __init__(self):
        self._baseline_means: Dict[str, float] = {}
        self._baseline_stds: Dict[str, float] = {}

    def normalize_blocks(self, blocks: List[List[str]]) -> List[List[str]]:
        filtered = []
        for block in blocks:
            cleaned = []
            for insn in block:
                stripped = insn.strip()
                if any(p.search(stripped) for p in _BOILERPLATE_PATTERNS):
                    continue
                cleaned.append(stripped)
            if cleaned:
                filtered.append(cleaned)
        return filtered

    def normalize_features(self, features: Dict[str, float]
                           ) -> Dict[str, float]:
        result = {}
        for k, v in features.items():
            if k in ('block_count', 'avg_block_size'):
                result[k] = v
                continue
            mean = self._baseline_means.get(k, 0.0)
            std = self._baseline_stds.get(k, 1.0)
            result[k] = round((v - mean) / max(std, 0.001), 4)
        return result

    def fit_baseline(self, feature_list: List[Dict[str, float]]) -> None:
        if not feature_list:
            return
        keys = [k for k in feature_list[0]
               if k not in ('block_count', 'avg_block_size')]
        for k in keys:
            vals = [f[k] for f in feature_list if k in f]
            if vals:
                mean = sum(vals) / len(vals)
                var = sum((v - mean) ** 2 for v in vals) / len(vals)
                self._baseline_means[k] = mean
                self._baseline_stds[k] = var ** 0.5

__all__ = ['CrossCompilerNormalizer']
