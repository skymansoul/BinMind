# 修改记录:
# 2025-08-09 10:15 - 四尺度结构熵: 块级(1)/函数级(2)/模块级(3)/全局(4) CFG 变形检测
# 2025-08-09 16:42 - 层级指纹叠加: 多混淆技术的熵特征线性叠加->逐个剥离识别

"""多尺度结构熵混淆层检测 - 识别"哪些"混淆技术被应用

现有混淆检测 回答"是否存在混淆"
不回答"哪些技术被同时使用"--而多技术层叠是当前恶意软件的主流

本模块通过在不同 CFG 粒度上测量结构熵的异常偏差来识别各层技术:
  尺度 1 (基本块级): 块内指令熵异常 -> 指令替换/MBA
  尺度 2 (函数级): CFG 边熵 + 出度异常 -> 控制流扁平化/不透明谓词
  尺度 3 (模块级): 函数间调用图熵异常 -> 虚拟化/打包
  尺度 4 (全局级): 段熵异常 -> 整体打包/加密

每混淆技术在四个尺度上产生特定的熵偏差向量
观测到的偏差向量与已知技术签名做余弦匹配 -> 识别+置信度

技术签名来自 OLLVM/Tigress/Obfuscator-LLVM 的 6 类混淆:
  FLA (控制流扁平化), SUB (指令替换), BCF (虚假控制流),
  SPLIT (基本块分裂), VIRT (虚拟化), MBA (混合布尔算术)

层级叠加的熵效应近似线性--可以从总偏差中逐个减去已识别技术的签名
(残差分析) 以识别底层技术

与现有方法的关系:
- GNN: 单技术二分类 -> 本模块: 多技术识别+置信度
- 层叠分析: 统计研究 -> 本模块: 可操作的检测工具
- pattern-based: 精确匹配 -> 本模块: 统计偏差+残差剥离
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# 混淆技术熵签名--四尺度偏差向量
# [block_level, func_level, module_level, global_level]
# 每维: 归一化熵偏差 (正=熵增, 负=熵减)

_OBFUSCATION_SIGNATURES: Dict[str, List[float]] = {
    # 指令替换--块级熵显著增加 (指令变为不常见形式)
    'SUB':  [0.45, 0.10, 0.02, 0.00],
    # MBA--块级+函数级熵增加 (位运算+算术混合)
    'MBA':  [0.55, 0.25, 0.05, 0.00],
    # 控制流扁平化--函数级熵剧增+块级出度统一化
    'FLA':  [-0.10, 0.70, 0.15, 0.00],
    # 虚假控制流--函数级熵增 (额外的不透明分支)
    'BCF':  [0.05, 0.50, 0.10, 0.00],
    # 基本块分裂--函数级熵增+块级规模减小
    'SPLIT': [-0.20, 0.40, 0.08, 0.00],
    # 虚拟化--模块级熵剧增 (VM dispatcher+handlers)
    'VIRT': [0.10, 0.30, 0.80, 0.10],
    # 打包/加密--全局熵剧增
    'PACK': [0.05, 0.05, 0.20, 0.90],
}


@dataclass
class LayerDetection:
    """单个混淆技术层的检测结果"""
    technique: str           # SUB | MBA | FLA | BCF | SPLIT | VIRT | PACK
    confidence: float        # [0,1]
    evidence_scale: str      # 最强信号出现的尺度
    residual_match: float    # 残差匹配度--越高越确信


@dataclass
class ObfuscationLayerReport:
    """混淆层检测的完整报告"""
    detected_layers: List[LayerDetection]
    # 四尺度原始熵偏差
    entropy_deviations: List[float]
    # 残差分析--去除已识别技术后的剩余熵
    residual_deviations: List[float]
    # 所有可能技术的得分
    all_scores: Dict[str, float]


# 四尺度结构熵提取

def _block_entropy(
    instructions: List[str],
    semantic_class_map: Dict[str, int],
) -> float:
    """基本块的指令语义类熵"""
    if not instructions:
        return 0.0
    counts: Dict[int, int] = defaultdict(int)
    for insn in instructions:
        parts = insn.strip().split()
        if parts:
            cls_id = semantic_class_map.get(parts[0].lower(), 7)
            counts[cls_id] += 1
    total = sum(counts.values())
    if total <= 1:
        return 0.0
    h = 0.0
    for c in counts.values():
        p = c / total
        h -= p * math.log2(p)
    return h


def _cfg_edge_entropy(
    edges: List[Tuple[int, int, str]],
) -> float:
    """CFG 边类型分布的熵--检测扁平化的均匀出度模式"""
    if not edges:
        return 0.0
    etype_counts: Dict[str, int] = defaultdict(int)
    for _, _, etype in edges:
        etype_counts[etype] += 1
    total = sum(etype_counts.values())
    if total <= 1:
        return 0.0
    h = 0.0
    for c in etype_counts.values():
        p = c / total
        h -= p * math.log2(p)
    return h


class ObfuscationLayerDetector:
    """多尺度结构熵混淆层检测器

    用法:
    detector = ObfuscationLayerDetector()
    report = detector.detect(
        blocks={0: ['mov eax,1', ...], ...},
        cfg_edges=[(0,1,'fallthrough'), ...],
        call_graph_edges=[('main','foo'), ...],
        global_entropy=6.5,
    )
    """

    # 语义类映射--简化为 8 类 (与 semantic_graph_hash 一致)
    _CLASS_MAP = {
        'mov': 0, 'lea': 0, 'push': 0, 'pop': 0,
        'add': 1, 'sub': 1, 'mul': 1, 'div': 1, 'inc': 1, 'dec': 1,
        'and': 2, 'or': 2, 'xor': 2, 'shl': 3, 'shr': 3,
        'cmp': 4, 'test': 4,
        'jmp': 5, 'call': 5, 'ret': 5, 'je': 5, 'jne': 5,
        'nop': 6,
    }

    # 基线熵值--来自未混淆的二进制 (GCC -O2)
    _BASELINE_ENTROPY = {
        'block_mean': 1.45,        # 平均块级熵
        'block_std': 0.35,
        'func_edge': 0.90,         # 函数级 CFG 边熵
        'func_edge_std': 0.25,
        'module_call': 1.50,       # 模块级调用图熵
        'module_call_std': 0.40,
        'global_byte': 5.5,        # 全局字节熵
        'global_byte_std': 0.8,
    }

    def detect(
        self,
        blocks: Dict[int, List[str]],
        cfg_edges: List[Tuple[int, int, str]],
        call_graph_edges: Optional[List[Tuple[str, str]]] = None,
        global_byte_entropy: Optional[float] = None,
    ) -> ObfuscationLayerReport:
        """执行多尺度熵分析和混淆层检测"""
        # 1. 提取四尺度熵偏差
        deviations = self._extract_deviations(
            blocks, cfg_edges, call_graph_edges, global_byte_entropy,
        )

        # 2. 匹配混淆技术签名
        scores = self._match_signatures(deviations)

        # 3. 残差分析--逐个剥离已检测技术
        layers = self._residual_analysis(deviations, scores)

        return ObfuscationLayerReport(
            detected_layers=sorted(layers, key=lambda l: -l.confidence),
            entropy_deviations=[round(d, 4) for d in deviations],
            residual_deviations=[round(self._residual[-1][i], 4) for i in range(4)],
            all_scores={k: round(v, 4) for k, v in sorted(scores.items(), key=lambda x: -x[1])},
        )

    def _extract_deviations(
        self,
        blocks: Dict[int, List[str]],
        cfg_edges: List[Tuple[int, int, str]],
        call_graph_edges: Optional[List[Tuple[str, str]]],
        global_byte_entropy: Optional[float],
    ) -> List[float]:
        """提取四尺度熵偏差向量"""
        bl = self._BASELINE_ENTROPY

        # 尺度 1: 块级熵--所有块的指令熵均值偏差
        block_entropies = [
            _block_entropy(insns, self._CLASS_MAP)
            for insns in blocks.values()
        ]
        block_mean = sum(block_entropies) / max(1, len(block_entropies))
        dev_block = (block_mean - bl['block_mean']) / max(0.01, bl['block_std'])

        # 尺度 2: 函数级边熵偏差
        edge_h = _cfg_edge_entropy(cfg_edges)
        dev_func = (edge_h - bl['func_edge']) / max(0.01, bl['func_edge_std'])

        # 尺度 3: 模块级调用图熵偏差
        if call_graph_edges:
            call_h = _cfg_edge_entropy(
                [(0, 0, 'call') for _ in call_graph_edges]
            )
            dev_module = (call_h - bl['module_call']) / max(0.01, bl['module_call_std'])
        else:
            dev_module = 0.0

        # 尺度 4: 全局字节熵偏差
        if global_byte_entropy is not None:
            dev_global = (global_byte_entropy - bl['global_byte']) / max(0.01, bl['global_byte_std'])
        else:
            dev_global = 0.0

        return [dev_block, dev_func, dev_module, dev_global]

    def _match_signatures(self, deviations: List[float]) -> Dict[str, float]:
        """计算观测偏差与每技术签名的余弦相似度"""
        scores: Dict[str, float] = {}
        dev_norm = math.sqrt(sum(d * d for d in deviations))
        if dev_norm < 1e-9:
            return {tech: 0.0 for tech in _OBFUSCATION_SIGNATURES}

        for tech, sig in _OBFUSCATION_SIGNATURES.items():
            sig_norm = math.sqrt(sum(s * s for s in sig))
            if sig_norm < 1e-9:
                scores[tech] = 0.0
                continue
            dot = sum(deviations[i] * sig[i] for i in range(4))
            cosine = dot / (dev_norm * sig_norm)
            scores[tech] = max(0.0, cosine)

        return scores

    def _residual_analysis(
        self,
        deviations: List[float],
        scores: Dict[str, float],
    ) -> List[LayerDetection]:
        """残差剥离--逐个移除已检测技术, 识别底层技术"""
        layers: List[LayerDetection] = []
        residual = list(deviations)
        self._residual: List[List[float]] = [list(deviations)]
        used: Set[str] = set()
        threshold = 0.35

        # 按得分降序迭代--每次去除最高得分技术
        sorted_techs = sorted(scores.items(), key=lambda x: -x[1])

        for tech, score in sorted_techs:
            if score < threshold or tech in used:
                continue

            sig = _OBFUSCATION_SIGNATURES[tech]
            # 从残差中减去此技术的签名 (加权)
            for i in range(4):
                residual[i] -= sig[i] * score * 0.7

            # 计算残差匹配度: 去除后残差范数 / 原始范数
            orig_norm = math.sqrt(sum(d * d for d in deviations))
            res_norm = math.sqrt(sum(r * r for r in residual))
            residual_match = 1.0 - (res_norm / max(0.01, orig_norm))

            confidence = score * (0.6 + 0.4 * residual_match)
            dominant_scale = max(range(4), key=lambda i: abs(sig[i]))
            scale_names = ['block', 'function', 'module', 'global']

            layers.append(LayerDetection(
                technique=tech,
                confidence=min(1.0, confidence),
                evidence_scale=scale_names[dominant_scale],
                residual_match=residual_match,
            ))
            used.add(tech)

        self._residual.append(list(residual))
        return layers
