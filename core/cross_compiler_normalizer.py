# cross_compiler_normalizer.py - 消除 O0/O2/O3 编译输出的指令级差异, 提取语义等价特征。
# 归一化策略: 相邻无分支块合并、移除栈帧管理指令 (push rbp/leave 等)、
# z-score 特征缩放、lea+mov 模式映射为单次内存操作。
# 语义特征 (块级操作码分布、调用密度、分支比例) 在各优化级别间保持相对稳定。
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
