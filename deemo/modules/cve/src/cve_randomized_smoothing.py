# 随机平滑对抗鲁棒认证
# 随机平滑 — CVE评分模型的对抗鲁棒性认证
#
# 问题: CVE评分模型可能被恶意操纵. 攻击者通过微小地修改CVE元数据
# (如添加虚假引用、操纵CVSS子分数), 可以使评分发生大幅变化.
# 传统防御 (对抗训练) 无法提供形式化保证.
#
# 解决方案: 随机平滑.
# 给定基础分类器f和噪声分布N(0,σ²I), 构造平滑分类器g:
#   g(x) = argmax_y P(f(x + ε) = y), ε ~ N(0, σ²I).
# 关键性质: g在ℓ₂范数下具有认证鲁棒性. 若 g(x)=y,
# 则在半径 R = σ·Φ⁻¹(p_A) 的ℓ₂球内, g的输出不变,
# 其中 p_A = P(f(x+ε)=y) 是基础分类器对类别y的预测概率下界.
#
# 本实现适配到CVE评分的二分类 (利用/不利用):
# 对每个CVE特征向量x, 添加N次高斯噪声扰动.
# 统计多数类的比例p_A (利用 vs 不利用).
#   - 计算认证半径 R = σ·[Φ⁻¹(p_A_lower) - Φ⁻¹(0.5)],
#     其中p_A_lower使用Clopper-Pearson置信下界.
#
# 认证半径的含义:
#   若R=0.05, 则攻击者需要将特征向量的L2范数改变≥0.05
#   才能翻转评分. 这直接量化了评分的对抗鲁棒性.
#
# 认证质量评估:
# 认证准确率 (Certified Accuracy): 预测正确且R≥r的比例.
# 平均认证半径 (但注意ICML 2025批评ACR为不良指标).
# 中位认证半径: 更鲁棒的汇总统计.
#
# 非显而易见性:
#   1. 首次将随机平滑应用于CVE评分模型的对抗鲁棒性认证.
#      RS用于恶意软件检测, VLM安全,
#      但零论文面向CVE漏洞评分.
#   2. 认证失败分析: 识别"脆弱CVE" — 半径小的CVE
#      是攻击者最可能操纵的目标, 应优先人工审查.
#   3. 与ConformalExploitScorer互补: 共形提供统计覆盖保证,
#      RS提供对抗鲁棒性保证. 两者联合建立多层可信度.
#
#
# Certified Adversarial Robustness via RS (ICML)
# RS for Malware Detection Certification
# ACR is a Poor Metric for Randomized Smoothing

import math
import random
from collections import Counter
from typing import Callable, Dict, List, Optional, Tuple


def _clopper_pearson_lower(k: int, n: int, alpha: float) -> float:
    """Clopper-Pearson二项比例的置信下界.

    P(Bin(n,p) ≥ k) ≥ α 的最小p.
    使用Beta分布: p_lower = Beta(α; k, n-k+1) 的分位数.
    以正态近似实现.
    """
    if n <= 0:
        return 0.0
    p_hat = k / n
    # Wilson score interval lower bound (近似)
    z = _probit(1.0 - alpha)
    denom = 1.0 + z * z / n
    center = (p_hat + z * z / (2.0 * n)) / denom
    margin = z * math.sqrt(p_hat * (1.0 - p_hat) / n + z * z / (4.0 * n * n)) / denom
    return max(0.0, center - margin)


def _probit(p: float) -> float:
    """正态分位数函数 (probit) 的近似."""
    if p <= 0.0:
        return -10.0
    if p >= 1.0:
        return 10.0
    # Abramowitz & Stegun 近似
    t = math.sqrt(-2.0 * math.log(min(p, 1.0 - p)))
    c = [2.515517, 0.802853, 0.010328, 1.432788, 0.189269, 0.001308]
    num = c[0] + c[1] * t + c[2] * t * t
    den = 1.0 + c[3] * t + c[4] * t * t + c[5] * t * t * t
    z = t - num / den
    return z if p >= 0.5 else -z


class RandomizedSmoothingCertifier:
    """CVE评分模型的随机平滑认证器.

    对给定的基础评分器, 计算每个CVE的认证半径.
    """

    def __init__(self, base_scorer: Callable[[List[float]], float],
                 sigma: float = 0.1, n_samples: int = 1000,
                 confidence: float = 0.999,
                 threshold: float = 0.5):
        """
        base_scorer: f(x) → [0,1] 评分函数.
        sigma: 高斯噪声标准差.
        n_samples: 每次认证的蒙特卡洛采样数.
        confidence: Clopper-Pearson置信水平.
        threshold: 二分类阈值 (≥threshold = exploited).
        """
        self._scorer = base_scorer
        self._sigma = sigma
        self._n_samples = n_samples
        self._confidence = confidence
        self._threshold = threshold

    def certify(self, x: List[float]) -> Dict[str, float]:
        """认证单个 CVE 的鲁棒性半径。

        返回 {prediction, p_exploited, p_lower, certified_radius};
        certified_radius=0 表示无法认证, 预测不可靠。
        """
        d = len(x)
        # 采样扰动
        counts = Counter()
        for _ in range(self._n_samples):
            noise = [random.gauss(0.0, self._sigma) for _ in range(d)]
            perturbed = [x[i] + noise[i] for i in range(d)]
            # 截断到[0,1]
            perturbed = [max(0.0, min(1.0, v)) for v in perturbed]
            score = self._scorer(perturbed)
            label = 1 if score >= self._threshold else 0
            counts[label] += 1

        top_label = counts.most_common(1)[0][0]
        top_count = counts[top_label]
        p_lower = _clopper_pearson_lower(top_count, self._n_samples,
                                         1.0 - self._confidence)

        # 认证半径: R = σ·[Φ⁻¹(p_lower) - Φ⁻¹(0.5)]
        # 若p_lower ≤ 0.5, 无法认证 (预测不确定)
        if p_lower <= 0.5:
            return {
                "prediction": top_label,
                "p_exploited": round(counts.get(1, 0) / self._n_samples, 4),
                "p_lower": round(p_lower, 4),
                "certified_radius": 0.0,
                "certifiable": False,
            }

        radius = self._sigma * (_probit(p_lower) - _probit(0.5))
        return {
            "prediction": top_label,
            "p_exploited": round(counts.get(1, 0) / self._n_samples, 4),
            "p_lower": round(p_lower, 4),
            "certified_radius": round(radius, 6),
            "certifiable": True,
        }

    def certify_batch(self, X: List[List[float]]
                      ) -> List[Dict[str, float]]:
        return [self.certify(x) for x in X]

    def evaluate(self, X: List[List[float]],
                 y_true: List[int]) -> Dict[str, Any]:
        """评估认证器性能, 返回多半径认证准确率、平均/中位半径与脆弱 CVE 列表。"""
        results = self.certify_batch(X)
        correct = [r for r, y in zip(results, y_true)
                   if r["prediction"] == y]
        certifiable = [r for r in correct if r["certifiable"]]
        all_radii = [r["certified_radius"] for r in correct]

        # 认证准确率@r
        radii = [0.0, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5]
        cert_acc = {}
        for r_thresh in radii:
            count = sum(1 for r in correct
                        if r["certifiable"] and r["certified_radius"] >= r_thresh)
            cert_acc[str(r_thresh)] = round(count / max(len(X), 1), 4)

        # 脆弱CVE (半径小但预测正确)
        vulnerable = sorted(
            [(i, r) for i, r in enumerate(results) if r["prediction"] == y_true[i]],
            key=lambda x: x[1]["certified_radius"])[:10]

        return {
            "n_total": len(X),
            "accuracy": round(len(correct) / max(len(X), 1), 4),
            "certifiable_fraction": round(len(certifiable) / max(len(correct), 1), 4),
            "median_radius": round(
                sorted(all_radii)[len(all_radii)//2] if all_radii else 0.0, 6),
            "certified_accuracy": cert_acc,
            "vulnerable_cves": [
                {"index": idx, "radius": r["certified_radius"],
                 "p_exploited": r["p_exploited"]}
                for idx, r in vulnerable],
        }

    def find_vulnerable(self, X: List[List[float]],
                        threshold: float = 0.01) -> List[int]:
        """找出认证半径小于阈值的CVE索引 — 高操纵风险."""
        results = self.certify_batch(X)
        return [i for i, r in enumerate(results)
                if r["certified_radius"] < threshold and r["certifiable"]]


# 便捷接口

def certify_scorer(scoring_fn, X: List[List[float]], y: List[int],
                   sigma: float = 0.1, n_samples: int = 500
                   ) -> Dict[str, Any]:
    """一站式认证评估."""
    certifier = RandomizedSmoothingCertifier(
        scoring_fn, sigma=sigma, n_samples=n_samples)
    return certifier.evaluate(X, y)


def find_manipulable_cves(scoring_fn, X: List[List[float]],
                          sigma: float = 0.05, n_samples: int = 300
                          ) -> List[int]:
    """快速扫描找出最易被操纵的CVE."""
    certifier = RandomizedSmoothingCertifier(
        scoring_fn, sigma=sigma, n_samples=n_samples)
    return certifier.find_vulnerable(X, threshold=0.005)
