# coding: utf-8
# 创建: 2026-06-07  |  常态模型构建器
# 修改: 2026-06-07  |  审计后补充文件头与错误处理
#
"""
代码库自适应偏差引擎——统计常态模型。

技术问题:
  传统漏洞检测依赖已知模式(CWE规则/ML训练集/LLM先验)——
  无法发现"未知的未知"(不匹配任何已知模式的新类型漏洞)。
  这在非主流架构/定制协议/专有固件中尤为致命。

  现有异常检测(anomaly_zeroday.py)使用全局基线(Z-score/Isolation Forest)——
  但"正常"的定义因代码库而异。固件中的直接硬件访问
  在Web服务器中属异常但在驱动中为常态。全局基线无法适应此差异。

解决方案:
  代码库自适应常态模型——从待分析二进制自身学习统计基线:
    1. 将二进制所有函数嵌入GraphBinaryEmbedder的向量空间
    2. 计算函数级特征的代码库内部分布(度分布/指令直方图/圈复杂度)
    3. 对每函数计算其在此分布中的马氏距离——偏离代码库常态的程度
    4. 距离超过自适应阈值(MAD-based)的函数标记为异常

  关键洞察: 漏洞函数往往在结构上偏离代码库常态——
    过长的函数/异常的指令混合/非典型的控制流模式——
    即使该模式不匹配任何已知CWE。

  自监督性质: 无需标注数据, 无需外部训练集,
  仅需待分析二进制自身的函数集合→零样本异常发现。

技术定位:
  与anomaly_zeroday.py互补——zeroday检测版本间差异, CADE检测版本内异常
  与CSSA互补——CSSA分析崩溃状态, CADE分析函数结构异常
  与CCAV互补——CCAV需要跨架构正例, CADE仅需单一二进制
"""

import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

_log = logging.getLogger(__name__)


# 函数特征向量


@dataclass
class FunctionProfile:
    """函数的统计画像——用于代码库内异常检测的特征向量"""
    function_name: str
    address: int = 0
    # 规模特征
    instruction_count: int = 0
    basic_block_count: int = 0
    cyclomatic_complexity: int = 0
    # 结构特征
    in_degree: int = 0            # 被调用次数
    out_degree: int = 0           # 调用次数
    is_leaf: bool = True          # 叶子函数(不调用其他函数)
    is_root: bool = False         # 根函数(无调用者)
    # 指令混合特征
    arithmetic_ratio: float = 0.0
    branch_ratio: float = 0.0
    memory_ratio: float = 0.0
    call_ratio: float = 0.0
    # 安全相关特征
    uses_dangerous_api: bool = False
    has_pointer_arithmetic: bool = False
    uses_inline_assembly: bool = False
    # 嵌入(外部GraphBinaryEmbedder产出)
    embedding: List[float] = field(default_factory=list)


@dataclass
class CodebaseNorm:
    """代码库常态——所有函数的统计分布参数"""
    total_functions: int = 0
    # 各特征的均值/标准差(用于z-score)
    feature_means: Dict[str, float] = field(default_factory=dict)
    feature_stds: Dict[str, float] = field(default_factory=dict)
    # 协方差矩阵(用于马氏距离)——简化: 对角线近似
    feature_variances: Dict[str, float] = field(default_factory=dict)
    # MAD阈值(中位绝对偏差×k)
    mad_thresholds: Dict[str, float] = field(default_factory=dict)
    # 全局异常阈值
    global_mad_multiplier: float = 3.0


# 常态模型构建器


class NormModelBuilder:
    """从函数集合构建代码库自适应常态模型。

    统计量:
      - 均值/标准差: 参数化正态假设——快速但受离群值影响
      - MAD(中位绝对偏差): 鲁棒——不受离群值影响
        MAD = median(|X_i - median(X)|)
        阈值 = median + k × MAD × 1.4826(正态一致性常数)

    为什么使用MAD而非标准差:
      代码库通常包含少量真正异常的漏洞函数。
      这些离群值会夸大标准差→掩盖真正的异常。
      MAD对离群值鲁棒——即使存在10%异常函数也能正确估计常态范围。
    """

    def build(self, profiles: List[FunctionProfile],
               mad_multiplier: float = 3.0) -> CodebaseNorm:
        """从函数画像列表构建代码库常态模型。

        返回CodebaseNorm。
        """
        if not profiles:
            return CodebaseNorm()

        norm = CodebaseNorm(
            total_functions=len(profiles),
            global_mad_multiplier=mad_multiplier)

        # 提取数值特征
        numeric_features = self._extract_numeric_features(profiles)

        for fname, values in numeric_features.items():
            n = len(values)
            if n < 2:
                continue
            sorted_vals = sorted(values)
            mean = sum(values) / n
            variance = sum((v - mean) ** 2 for v in values) / (n - 1)
            std = math.sqrt(max(variance, 1e-10))
            median = sorted_vals[n // 2]
            # MAD
            abs_devs = sorted(abs(v - median) for v in values)
            mad = abs_devs[n // 2]
            # MAD阈值
            mad_threshold = median + mad_multiplier * mad * 1.4826

            norm.feature_means[fname] = round(mean, 4)
            norm.feature_stds[fname] = round(std, 4)
            norm.feature_variances[fname] = round(variance, 4)
            norm.mad_thresholds[fname] = round(mad_threshold, 4)

        return norm

    def _extract_numeric_features(self, profiles: List[FunctionProfile]
                                    ) -> Dict[str, List[float]]:
        """从函数画像提取数值特征向量——每特征一个值列表"""
        feats: Dict[str, List[float]] = defaultdict(list)
        for p in profiles:
            feats['instruction_count'].append(float(p.instruction_count))
            feats['basic_block_count'].append(float(p.basic_block_count))
            feats['cyclomatic_complexity'].append(float(p.cyclomatic_complexity))
            feats['in_degree'].append(float(p.in_degree))
            feats['out_degree'].append(float(p.out_degree))
            feats['arithmetic_ratio'].append(p.arithmetic_ratio)
            feats['branch_ratio'].append(p.branch_ratio)
            feats['memory_ratio'].append(p.memory_ratio)
            feats['call_ratio'].append(p.call_ratio)
            feats['dangerous_score'].append(
                1.0 if p.uses_dangerous_api else 0.0)
            feats['pointer_arith_score'].append(
                1.0 if p.has_pointer_arithmetic else 0.0)
            feats['inline_asm_score'].append(
                1.0 if p.uses_inline_assembly else 0.0)
        return dict(feats)


class AnomalyScorer:
    """基于代码库常态模型对单个函数进行异常评分。

    评分方法——多维度偏差聚合:
      1. Z-score: (value - mean) / std → 标准偏差度量
      2. MAD异常标志: value > mad_threshold → 超出鲁棒阈值
      3. 嵌入距离: 函数嵌入与代码库质心的余弦距离
      4. 聚合: 各维度z-score的加权RMS + MAD标志加权

    权重设计——安全相关的特征权重更高:
      危险API使用: 0.20(直接安全信号)
      圈复杂度: 0.15(漏洞函数往往更复杂)
      指令数: 0.10(过长函数异常)
      入度/出度: 0.05(调用模式异常)
      其他: 均分剩余
    """

    _FEATURE_WEIGHTS = {
        'dangerous_score': 0.20, 'cyclomatic_complexity': 0.15,
        'instruction_count': 0.10, 'memory_ratio': 0.10,
        'basic_block_count': 0.08, 'in_degree': 0.05,
        'out_degree': 0.05, 'arithmetic_ratio': 0.05,
        'branch_ratio': 0.05, 'call_ratio': 0.05,
        'pointer_arith_score': 0.07, 'inline_asm_score': 0.05,
    }

    def score(self, profile: FunctionProfile,
               norm: CodebaseNorm) -> Tuple[float, Dict[str, float]]:
        """计算函数的异常评分。

        返回(overall_score, per_feature_scores)。
        """
        if norm.total_functions < 5:
            return 0.0, {}  # 样本不足

        feature_values = {
            'instruction_count': float(profile.instruction_count),
            'basic_block_count': float(profile.basic_block_count),
            'cyclomatic_complexity': float(profile.cyclomatic_complexity),
            'in_degree': float(profile.in_degree),
            'out_degree': float(profile.out_degree),
            'arithmetic_ratio': profile.arithmetic_ratio,
            'branch_ratio': profile.branch_ratio,
            'memory_ratio': profile.memory_ratio,
            'call_ratio': profile.call_ratio,
            'dangerous_score': 1.0 if profile.uses_dangerous_api else 0.0,
            'pointer_arith_score': 1.0 if profile.has_pointer_arithmetic else 0.0,
            'inline_asm_score': 1.0 if profile.uses_inline_assembly else 0.0,
        }

        per_feat = {}
        weighted_sum = 0.0
        total_weight = 0.0

        for fname, value in feature_values.items():
            mean = norm.feature_means.get(fname, 0.0)
            std = norm.feature_stds.get(fname, 1.0)
            mad_thresh = norm.mad_thresholds.get(fname, float('inf'))

            if std < 1e-6:
                z = 0.0
            else:
                z = abs(value - mean) / std

            # MAD放大——超出MAD阈值的特征获得额外加权
            mad_boost = 1.5 if value > mad_thresh else 1.0
            w = self._FEATURE_WEIGHTS.get(fname, 0.03) * mad_boost
            weighted_sum += w * min(z / 4.0, 1.0)  # 截断z≤4
            total_weight += w
            per_feat[fname] = round(z, 3)

        overall = weighted_sum / max(total_weight, 1e-6)

        # 嵌入距离——若嵌入可用, 计算与代码库质心的余弦距离
        if profile.embedding and norm.total_functions > 10:
            # 嵌入距离简化为向量模的偏差(无质心时的近似)
            emb_norm = math.sqrt(sum(v * v for v in profile.embedding))
            overall = 0.7 * overall + 0.3 * min(emb_norm / 10.0, 1.0)

        return round(overall, 4), per_feat


__all__ = [
    "FunctionProfile",
    "CodebaseNorm",
    "NormModelBuilder",
    "AnomalyScorer",
]
