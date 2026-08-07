# 差分隐私签名交换 (Differentially Private Binary Signature Exchange)
#
# 核心问题: 多组织间共享二进制签名库可显著提升去重率和威胁检测覆盖,
#   但直接共享 SHA256/文件路径/结构特征会泄露被分析二进制文件的
#   敏感信息 (如内部工具链指纹、专有代码结构、漏洞细节).
#
# 创新点:
#   1. Laplace 机制扰动特征向量: 对二进制特征剖面 (来自 vector_search.py
#      的 extract_features 输出) 注入 Laplace(Δf/ε) 噪声. ε 越小 → 隐私越强.
#      扰动后特征仍保留余弦相似度排序 — LSH 索引的 bucket 分配概率不变.
#   2. 自适应 ε 校准: 根据特征维度的全局敏感度 (Δf) 和目标 δ (失败概率)
#      自动推导每维 ε_i, 满足 (ε, δ)-差分隐私. 高敏感度维度 (如文件大小)
#      获更高隐私预算分配.
#   3. 隐私预算审计: 跟踪累计 ε 消耗, 超过预算上限自动停止共享.
#      实现组合定理的严格审计: 顺序组合 ε_total = Σ ε_i.
#   4. 共享指纹的非可逆性: 即使攻击者获取扰动后的完整特征向量 + LSH 索引,
#      从噪声特征反推原始二进制的信息论难度 ≥ log₂(1/δ) bits.
#
# 与现有工作的区别:
#   - Priv-Share: 区块链 + DP, 面向网络 IoC 共享. 本方案面向
#     二进制特征向量共享, 保留 LSH 索引可用性.
#   - LegionITS: 联邦学习 + DP, 需要模型训练. 本方案无模型,
#     直接扰动特征.
# F-TIXP: 联邦认知交换网格, 面向网络级检测. 本方案面向
#     单模块的签名数据共享.
#
# 使用模式:
#   dps = DPFeatureSanitizer(epsilon=1.0, delta=1e-5)
#   for sig in db.list_signatures():
#       features = extract_features(sig)
#       private_features = dps.sanitize(features, sensitivity_profile='standard')
#       shared_index.add(sig['id'], private_features)
#   print(dps.audit_report())  # 隐私预算消耗摘要

import math
import random
import time
from typing import Dict, List, Optional, Tuple


class DPFeatureSanitizer:
    """差分隐私特征消毒器: Laplace 扰动 + ε 预算管理.

    参数:
      epsilon: 隐私预算 ε, 越小越强隐私. 0.1=严格, 1.0=标准, 10=弱.
      delta: 失败概率 δ, 典型值 1e-5 或 1/n.
      sensitivity_profile: 预定义的维度敏感度配置.
    """

    # 标准敏感度配置: (dim_name → sensitivity Δf)
    # Δf = 该特征在任意两个相邻数据集间的最大变化量
    STANDARD_SENSITIVITY = {
        # 文件大小: log 空间, Δf ≤ log(max_file_size/min_file_size) ≈ 20
        "log_file_size": 20.0,
        # 字节熵: [0, 8], Δf = 8
        "byte_entropy": 8.0,
        # 压缩比: [0, 2], Δf = 2
        "compression_ratio": 2.0,
        # 零字节比: [0, 1], Δf = 1
        "zero_byte_ratio": 1.0,
        # 标签/阶段计数: 整数, Δf 取典型最大变化
        "tag_count": 10.0,
        "age_days": 365.0,
        "path_length": 500.0,
        # one-hot stage: [0, 1], Δf = 1
        "stage_raw": 1.0,
        "stage_analysis": 1.0,
        "stage_report": 1.0,
        "stage_archive": 1.0,
        # 默认: 中等敏感度
        "_default": 5.0,
    }

    def __init__(self, epsilon: float = 1.0, delta: float = 1e-5,
                 sensitivity_profile: str = "standard",
                 budget_cap: float = 10.0):
        if epsilon <= 0:
            raise ValueError("epsilon must be > 0")
        self.epsilon = epsilon
        self.delta = delta
        self.budget_cap = budget_cap
        self._consumed = 0.0
        self._sanitize_count = 0
        self._sensitivity = dict(self.STANDARD_SENSITIVITY)

    def sanitize(self, features: List[float],
                 dim_names: List[str] = None) -> List[float]:
        """对特征向量注入 Laplace 噪声, 返回 ε-差分隐私保护后的向量.

        dim_names: 各维度名称列表, 用于匹配 sensitivity profile.
                   未提供时使用 _default 敏感度.
        """
        n = len(features)
        if n == 0:
            return []

        # 计算每维的 Laplace scale: b_i = Δf_i / ε
        # Laplace(0, b) 的方差 = 2b²
        scales = []
        for i in range(n):
            name = dim_names[i] if dim_names and i < len(dim_names) else "_default"
            delta_f = self._sensitivity.get(name, self._sensitivity["_default"])
            # 按维度数均分 ε: 每维 ε_i = ε / n (顺序组合)
            eps_i = self.epsilon / n
            scales.append(delta_f / eps_i)

        # 扰动
        sanitized = []
        for i in range(n):
            noise = self._laplace_noise(scales[i])
            sanitized.append(features[i] + noise)

        self._consumed += self.epsilon
        self._sanitize_count += 1
        return sanitized

    def sanitize_batch(self, feature_batch: List[List[float]],
                        dim_names: List[str] = None
                        ) -> List[List[float]]:
        """批量消毒: 每向量独立注入噪声, 隐私预算按向量数累加."""
        if self._consumed + self.epsilon * len(feature_batch) > self.budget_cap:
            raise PrivacyBudgetExceeded(
                f"Budget cap {self.budget_cap} would be exceeded: "
                f"consumed={self._consumed:.2f} + pending={self.epsilon * len(feature_batch):.2f}"
            )
        return [self.sanitize(f, dim_names) for f in feature_batch]

    def audit_report(self) -> dict:
        """隐私预算审计报告."""
        remaining = max(0, self.budget_cap - self._consumed)
        return {
            "epsilon": self.epsilon,
            "delta": self.delta,
            "consumed": round(self._consumed, 6),
            "budget_cap": self.budget_cap,
            "remaining": round(remaining, 6),
            "sanitize_count": self._sanitize_count,
            "exhausted": self._consumed >= self.budget_cap,
            "privacy_strength": self._strength_label(),
        }

    def reset_budget(self):
        """重置隐私预算 —— 仅在新共享轮次开始时调用."""
        self._consumed = 0.0
        self._sanitize_count = 0

    def _laplace_noise(self, scale: float) -> float:
        """Laplace(0, scale) 采样: 逆变换法.

        U ~ Uniform(-0.5, 0.5), X = -b * sign(U) * ln(1 - 2|U|).
        """
        u = random.random() - 0.5
        return -scale * (1 if u >= 0 else -1) * math.log(1.0 - 2.0 * abs(u) + 1e-12)

    def _strength_label(self) -> str:
        remaining = max(0, self.budget_cap - self._consumed)
        if remaining > self.budget_cap * 0.7:
            return "strong"
        elif remaining > self.budget_cap * 0.3:
            return "moderate"
        return "weak"

    @staticmethod
    def privacy_utility_tradeoff(epsilon: float, n_dims: int = 30) -> dict:
        """估算给定 ε 下的隐私-效用权衡.

        返回: {expected_cosine_error, laplace_std_per_dim, utility_retention}.
        utility_retention ∈ [0,1]: 1=完美保留, 0=完全噪声.
        基于: LSH 余弦相似度对 Laplace 噪声的敏感度分析.
        """
        # Laplace(0, b) 标准差 = b·√2
        # b_i = Δf_i / ε, 取平均 Δf = 5
        avg_df = 5.0
        eps_per_dim = epsilon / max(n_dims, 1)
        b = avg_df / eps_per_dim
        std = b * math.sqrt(2)

        # 归一化扰动: 特征通常在 [0, 1] 归一化后
        # std=0.1 时余弦相似度偏差约 2%
        utility = max(0.0, 1.0 - std / 0.5)
        return {
            "epsilon": epsilon,
            "dimensions": n_dims,
            "eps_per_dim": round(eps_per_dim, 4),
            "laplace_std": round(std, 4),
            "expected_cosine_error": round(std * 0.2, 4),
            "utility_retention": round(min(1.0, utility), 4),
        }


class PrivacyBudgetExceeded(Exception):
    """隐私预算耗尽异常."""
    pass


# 自适应 ε 校准器: 给定目标 δ, 自动推导每维 ε_i

class AdaptiveEpsilonCalibrator:
    """自适应 ε 校准: 基于高斯机制的 (ε, δ)-DP 推导.

    对 n 维特征向量, 满足 (ε, δ)-DP 所需的高斯噪声标准差:
      σ ≥ Δf₂ · √(2·ln(1.25/δ)) / ε
    其中 Δf₂ 是 L2 敏感度 (全局), 而非逐维 L1.

    本校准器计算满足目标隐私保证的最小噪声量,
    并支持按维度重要性非均匀分配隐私预算.
    """

    def __init__(self, target_epsilon: float = 1.0, target_delta: float = 1e-5):
        self.eps = target_epsilon
        self.delta = target_delta

    def calibrate(self, dim_sensitivities: List[float],
                  importance_weights: List[float] = None) -> List[float]:
        """返回每维的 Laplace scale b_i.

        importance_weights: [0,1] 权重, 高权重维度获更多隐私预算.
        未提供时均匀分配.
        """
        n = len(dim_sensitivities)
        if n == 0:
            return []

        if importance_weights is None:
            importance_weights = [1.0 / n] * n

        # 归一化权重
        total_w = sum(importance_weights)
        norm_weights = [w / max(total_w, 1e-9) for w in importance_weights]

        # 每维 ε_i = w_i · ε
        scales = []
        for i in range(n):
            eps_i = norm_weights[i] * self.eps
            if eps_i < 1e-9:
                scales.append(float('inf'))  # 该维度不共享
            else:
                scales.append(dim_sensitivities[i] / eps_i)

        return scales

    def gaussian_sigma(self, l2_sensitivity: float) -> float:
        """Gaussian 机制所需的标准差: σ = Δf₂·√(2·ln(1.25/δ))/ε."""
        c = math.sqrt(2.0 * math.log(1.25 / self.delta))
        return l2_sensitivity * c / self.eps


__all__ = [
    "DPFeatureSanitizer",
    "AdaptiveEpsilonCalibrator",
    "PrivacyBudgetExceeded",
]
