# 统计二进制协议字段类型推断 —— 跨消息值分布形状聚类。
# 对每字节偏移拟合7种分布(CONSTANT/COUNTER/CHECKSUM/LENGTH/ENUM/FLAGS/DATA),
# 选最高得分类型。多字节字段通过相邻同类型合并。
# 与consensus_alignment互补: 对齐找边界(where), 本模块推理语义(what)。

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class PositionProfile:
    """单字节偏移的值分布剖面"""
    offset: int
    values: List[int] = field(default_factory=list)
    unique_count: int = 0
    entropy: float = 0.0
    # 各类假设的得分
    constant_score: float = 0.0
    counter_score: float = 0.0
    checksum_score: float = 0.0
    length_score: float = 0.0
    enum_score: float = 0.0
    flags_score: float = 0.0
    data_score: float = 0.0
    # 最佳推断
    inferred_type: str = "unknown"
    type_confidence: float = 0.0


@dataclass
class FieldInference:
    """单字段的类型推断结果"""
    offset: int
    size: int                    # 字段宽度(字节), ≥1
    inferred_type: str           # 七种类型之一
    confidence: float            # [0,1]
    evidence: Dict[str, Any] = field(default_factory=dict)
    merged_from: List[int] = field(default_factory=list)
    # 若为多字节字段合并, 记录原始偏移


@dataclass
class InferenceReport:
    """统计类型推断完整报告"""
    total_messages: int
    max_message_length: int
    position_profiles: List[PositionProfile]
    inferred_fields: List[FieldInference]
    field_count: int


class StatisticalTypeInferrer:
    """统计字段类型推断器 —— 每偏移拟合7种分布, 相邻合并多字节字段。"""

    def __init__(self):
        pass

    def infer(self, messages: List[bytes]) -> InferenceReport:
        """从同协议多消息推断各字节位置的字段类型。"""
        if not messages:
            return InferenceReport(0, 0, [], [], 0)

        max_len = max(len(m) for m in messages)
        n = len(messages)

        # 为每条消息填充到相同长度(用-1标记不存在的位置)
        padded = []
        for m in messages:
            if len(m) < max_len:
                padded.append(list(m) + [-1] * (max_len - len(m)))
            else:
                padded.append(list(m[:max_len]))

        # 每个offset的跨消息值序列
        profiles: List[PositionProfile] = []
        for offset in range(max_len):
            vals = [padded[i][offset] for i in range(n)
                   if padded[i][offset] >= 0]
            if not vals:
                continue
            profile = self._analyze_position(offset, vals, messages)
            profiles.append(profile)

        # 合并相邻同类型单字节字段
        fields = self._merge_fields(profiles)

        return InferenceReport(
            total_messages=n,
            max_message_length=max_len,
            position_profiles=profiles,
            inferred_fields=fields,
            field_count=len(fields),
        )

    def _analyze_position(self, offset: int, vals: List[int],
                           messages: List[bytes]) -> PositionProfile:
        p = PositionProfile(offset=offset, values=list(vals))
        p.unique_count = len(set(vals))
        p.entropy = self._shannon_entropy_ints(vals)

        # 计算七种得分
        p.constant_score = self._score_constant(vals)
        p.counter_score = self._score_counter(vals)
        p.checksum_score = self._score_checksum(vals)
        p.length_score = self._score_length(offset, vals, messages)
        p.enum_score = self._score_enum(vals)
        p.flags_score = self._score_flags(vals)
        p.data_score = self._score_data(vals)

        # 最佳类型
        scores = [
            ("constant", p.constant_score),
            ("counter", p.counter_score),
            ("checksum", p.checksum_score),
            ("length", p.length_score),
            ("enum", p.enum_score),
            ("flags", p.flags_score),
            ("data", p.data_score),
        ]
        best_type, best_score = max(scores, key=lambda x: x[1])
        p.inferred_type = best_type
        p.type_confidence = round(best_score, 3)

        return p

    # ---- 各类型得分函数 ----
    @staticmethod
    def _score_constant(vals: List[int]) -> float:
        """同值率→常数字段得分"""
        if len(vals) < 2:
            return 0.5
        most_common_ratio = Counter(vals).most_common(1)[0][1] / len(vals)
        return min(most_common_ratio, 1.0)

    @staticmethod
    def _score_counter(vals: List[int]) -> float:
        """单调性→计数器得分。

        使用Kendall τ的简化版: 相邻对中递增的比例。
        """
        n = len(vals)
        if n < 3:
            return 0.0
        increasing = sum(1 for i in range(n - 1)
                        if vals[i + 1] > vals[i])
        decreasing = sum(1 for i in range(n - 1)
                        if vals[i + 1] < vals[i])
        # 步长一致性加分
        steps = [abs(vals[i + 1] - vals[i]) for i in range(n - 1)]
        step_consistency = 0.0
        if steps:
            mode_step = Counter(steps).most_common(1)[0][1]
            step_consistency = mode_step / len(steps)
        mono_ratio = max(increasing, decreasing) / max(n - 1, 1)
        return mono_ratio * 0.6 + step_consistency * 0.4

    @staticmethod
    def _score_checksum(vals: List[int]) -> float:
        """低R²线性拟合+高唯一值比→校验和得分"""
        n = len(vals)
        if n < 4:
            return 0.0
        # 简单线性拟合: val = a*i + b
        x_mean = (n - 1) / 2.0
        y_mean = sum(vals) / n
        cov = sum((i - x_mean) * (vals[i] - y_mean) for i in range(n))
        var_x = sum((i - x_mean) ** 2 for i in range(n))
        if var_x < 1e-6:
            return 0.0
        a = cov / var_x
        b = y_mean - a * x_mean
        y_pred = [a * i + b for i in range(n)]
        ss_res = sum((vals[i] - y_pred[i]) ** 2 for i in range(n))
        ss_tot = sum((v - y_mean) ** 2 for v in vals)
        r2 = 1.0 - ss_res / max(ss_tot, 1e-6)
        # 低R² + 中等唯一值比 → 校验和
        unique_ratio = len(set(vals)) / n
        return (1.0 - min(r2, 1.0)) * 0.5 + unique_ratio * 0.5

    @staticmethod
    def _score_length(offset: int, vals: List[int],
                       messages: List[bytes]) -> float:
        """val与msg_len的Pearson+offset拟合→长度字段得分"""
        n = min(len(vals), len(messages))
        if n < 4:
            return 0.0
        msg_lens = [len(m) for m in messages[:n]]
        v_mean = sum(vals[:n]) / n
        l_mean = sum(msg_lens) / n
        cov = sum((vals[i] - v_mean) * (msg_lens[i] - l_mean)
                  for i in range(n))
        std_v = math.sqrt(sum((v - v_mean) ** 2 for v in vals[:n]))
        std_l = math.sqrt(sum((l - l_mean) ** 2 for l in msg_lens))
        if std_v < 1e-6 or std_l < 1e-6:
            return 0.0
        pearson = cov / (std_v * std_l)
        # 正相关且值合理(val对长度有解释力)
        if pearson > 0.5:
            # 检查: val + offset ≈ msg_len (长度字段通常指示后续字节数)
            fit_count = sum(1 for i in range(n)
                          if abs(vals[i] + offset - msg_lens[i]) < 8)
            return max(pearson, fit_count / n)
        return max(0.0, pearson)

    @staticmethod
    def _score_enum(vals: List[int]) -> float:
        """唯一值数≤16+top3集中度→枚举得分"""
        n = len(vals)
        if n < 2:
            return 0.0
        unique = len(set(vals))
        if unique > min(16, n // 2):
            return 0.0
        # 值分布集中度
        counter = Counter(vals)
        top3_ratio = sum(c for _, c in counter.most_common(3)) / n
        return top3_ratio * min(1.0, 8.0 / max(unique, 1))

    @staticmethod
    def _score_flags(vals: List[int]) -> float:
        """2的幂占比+值种数少→标志位得分"""
        n = len(vals)
        if n < 2:
            return 0.0
        # 检查每个值是否为2的幂(或0)
        pow2_count = sum(1 for v in vals
                        if v == 0 or (v & (v - 1)) == 0)
        pow2_ratio = pow2_count / n
        # 值多样性: 标志位通常值种数少
        unique = len(set(vals))
        diversity_penalty = 1.0 / max(unique / 8.0, 1.0)
        return pow2_ratio * 0.6 + diversity_penalty * 0.4

    @staticmethod
    def _score_data(vals: List[int]) -> float:
        """高熵→数据字段得分(默认兜底类型)。

        数据字段特征: 高熵+高唯一值比+无结构。
        """
        n = len(vals)
        if n < 2:
            return 0.5
        ent = StatisticalTypeInferrer._shannon_entropy_ints(vals)
        unique_ratio = len(set(vals)) / n
        ent_norm = min(ent / 8.0, 1.0)
        return ent_norm * 0.5 + unique_ratio * 0.5

    @staticmethod
    def _shannon_entropy_ints(vals: List[int]) -> float:
        if not vals:
            return 0.0
        counter = Counter(vals)
        n = len(vals)
        return -sum((c / n) * math.log2(c / n)
                   for c in counter.values())

    @staticmethod
    def _merge_fields(profiles: List[PositionProfile]) -> List[FieldInference]:
        """合并相邻同类型单字节字段为多字节字段。"""
        if not profiles:
            return []

        fields: List[FieldInference] = []
        i = 0
        while i < len(profiles):
            p = profiles[i]
            merged = [p.offset]
            j = i + 1
            while j < len(profiles) and profiles[j].inferred_type == p.inferred_type:
                merged.append(profiles[j].offset)
                j += 1
            size = len(merged)
            avg_conf = sum(profiles[k].type_confidence
                         for k in range(i, j)) / size
            fields.append(FieldInference(
                offset=p.offset, size=size,
                inferred_type=p.inferred_type,
                confidence=round(avg_conf, 3),
                merged_from=merged if size > 1 else [],
            ))
            i = j

        return fields


def infer_field_types(messages: List[bytes]) -> InferenceReport:
    """便捷入口: 多消息→统计类型推断→InferenceReport。"""
    return StatisticalTypeInferrer().infer(messages)


__all__ = [
    "PositionProfile", "FieldInference", "InferenceReport",
    "StatisticalTypeInferrer", "infer_field_types",
]
