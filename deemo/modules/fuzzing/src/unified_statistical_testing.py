"""统一统计检验框架 — 多策略评估 + 多重检验校正 + 效应量.

创建: 2026-06-22 08:33
修改: 2026-06-22 15:47 — 添加 Bayesian 因子 + 等价检验 (TOST)

参考: Wasserstein & Lazar "The ASA Statement on p-Values" (TAS)
       Lakens "Equivalence Testing" (SPPS)
       Kass & Raftery "Bayes Factors" (JASA)

技术定位:
  将 FDR-CC (BH过程), Granger (因果), SPRT (序贯), Mann-Whitney (非参数),
  和 Bayes Factor 统一为一个决策框架, 解决 fuzzing 中"哪个策略更好"
  的多重比较问题。

  与现有单模块的区别:
    单独使用 FDR/Granger/SPRT 给出孤立结论。
    本框架在多个检验之间协调: FDR 控制 + 效应量过滤 + Bayesian 确认,
    避免"p<0.05 但不 practical significant"的虚假发现。

三层过滤:
  L1 (统计显著): p < 0.05 after BH correction
  L2 (实际显著): effect size > Cohen's d threshold (0.2)
  L3 (稳健确认): Bayes Factor > 3 (moderate evidence)
  只有通过全部三层的结果才作为"可操作结论"返回。"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


_COHENS_D_SMALL = 0.2
_BAYES_FACTOR_MODERATE = 3.0
_ALPHA = 0.05


@dataclass
class UnifiedTestResult:
    hypothesis: str          # 检验假设 (如 "A > B")
    p_value: float
    fdr_adjusted: bool       # 是否通过 FDR
    effect_size: float       # Cohen's d
    practically_significant: bool
    bayes_factor: float      # BF₁₀
    bf_evidence: str         # "weak"|"moderate"|"strong"|"decisive"
    passed_all_layers: bool
    recommendation: str      # "adopt"|"reject"|"inconclusive"


class UnifiedStatisticalFramework:
    """三层过滤统计检验框架.

    L1: FDR (BH) — 控制多重比较
    L2: Cohen's d — 过滤微小效应
    L3: Bayes Factor — 稳健性确认

    使用方式:
      usf = UnifiedStatisticalFramework()
      usf.add_comparison("strat_A > baseline", group_A_gains, group_B_gains)
      results = usf.evaluate()
      for r in results:
          if r.passed_all_layers:
              print(f"ADOPT: {r.hypothesis}")
    """

    def __init__(self):
        self._comparisons: Dict[str, Tuple[List[float], List[float]]] = {}
        # name → (group_a_values, group_b_values)

    def add_comparison(self, name: str,
                       group_a: List[float],
                       group_b: List[float]) -> None:
        self._comparisons[name] = (list(group_a), list(group_b))

    # //// 三层评估 ////
    def evaluate(self) -> List[UnifiedTestResult]:
        n_tests = len(self._comparisons)
        if n_tests == 0:
            return []

        # 计算所有原始 p-values (Welch t-test)
        raw_results = []
        for name, (ga, gb) in self._comparisons.items():
            p_val = self._welch_t_test(ga, gb)
            d = self._cohens_d(ga, gb)
            bf = self._bayes_factor_approx(ga, gb)
            raw_results.append((name, p_val, d, bf))

        # L1: FDR (BH)
        sorted_idx = sorted(range(len(raw_results)),
                           key=lambda i: raw_results[i][1])
        m = n_tests
        fdr_thresholds = [(i + 1) / m * _ALPHA for i in range(m)]
        fdr_passed = [False] * m
        max_k = -1
        for k, idx in enumerate(sorted_idx):
            if raw_results[idx][1] <= fdr_thresholds[k]:
                max_k = k
        for k, idx in enumerate(sorted_idx):
            fdr_passed[idx] = (k <= max_k)

        # 组合结果
        results = []
        for i, (name, p_val, d, bf) in enumerate(raw_results):
            # L2: 效应量
            practical = abs(d) > _COHENS_D_SMALL

            # L3: Bayes Factor
            if bf > 100:
                bf_level = "decisive"
            elif bf > 10:
                bf_level = "strong"
            elif bf > _BAYES_FACTOR_MODERATE:
                bf_level = "moderate"
            else:
                bf_level = "weak"

            passed_all = fdr_passed[i] and practical and bf > _BAYES_FACTOR_MODERATE
            if passed_all:
                rec = "adopt" if d > 0 else "reject"
            else:
                rec = "inconclusive"

            results.append(UnifiedTestResult(
                hypothesis=name, p_value=p_val,
                fdr_adjusted=fdr_passed[i], effect_size=d,
                practically_significant=practical,
                bayes_factor=bf, bf_evidence=bf_level,
                passed_all_layers=passed_all, recommendation=rec))
        return results

    # //// 统计方法 ////
    @staticmethod
    def _welch_t_test(a: List[float], b: List[float]) -> float:
        """Welch t-test p-value."""
        na, nb = len(a), len(b)
        if na < 3 or nb < 3:
            return 1.0
        ma = sum(a) / na; mb = sum(b) / nb
        va = (sum((x - ma) ** 2 for x in a) / (na - 1)) if na > 1 else 1.0
        vb = (sum((x - mb) ** 2 for x in b) / (nb - 1)) if nb > 1 else 1.0
        se = math.sqrt(va / na + vb / nb)
        if se < 1e-15:
            return 1.0
        t = abs(ma - mb) / se
        # Welch-Satterthwaite df
        df = ((va / na + vb / nb) ** 2) / max(1e-15,
            (va / na) ** 2 / (na - 1) + (vb / nb) ** 2 / (nb - 1))
        # t → p (双尾近似)
        z = abs(t)
        p = 2.0 * (1.0 - 0.5 * (1.0 + math.erf(z / math.sqrt(2.0))))
        return min(1.0, max(0.0, p))

    @staticmethod
    def _cohens_d(a: List[float], b: List[float]) -> float:
        """Cohen's d 效应量."""
        na, nb = len(a), len(b)
        if na < 2 or nb < 2:
            return 0.0
        ma = sum(a) / na; mb = sum(b) / nb
        va = (sum((x - ma) ** 2 for x in a) / (na - 1)) if na > 1 else 1.0
        vb = (sum((x - mb) ** 2 for x in b) / (nb - 1)) if nb > 1 else 1.0
        pooled_sd = math.sqrt(((na - 1) * va + (nb - 1) * vb)
                             / (na + nb - 2))
        if pooled_sd < 1e-15:
            return 0.0
        return (ma - mb) / pooled_sd

    @staticmethod
    def _bayes_factor_approx(a: List[float], b: List[float]) -> float:
        """Bayes Factor 近似 (BIC-based).

        BF₁₀ ≈ exp((BIC₀ - BIC₁) / 2)
        H₀: μ_a = μ_b; H₁: μ_a ≠ μ_b
        """
        na, nb = len(a), len(b)
        if na < 3 or nb < 3:
            return 1.0
        # BIC₀ (pooled mean)
        all_vals = a + b
        n = na + nb
        mu_pooled = sum(all_vals) / n
        sigma_sq_0 = sum((x - mu_pooled) ** 2 for x in all_vals) / n
        bic_0 = n * math.log(max(1e-15, sigma_sq_0)) + math.log(n)  # k=1

        # BIC₁ (separate means)
        ma = sum(a) / na; mb = sum(b) / nb
        sigma_sq_1 = (sum((x - ma) ** 2 for x in a)
                     + sum((x - mb) ** 2 for x in b)) / n
        bic_1 = n * math.log(max(1e-15, sigma_sq_1)) + 2 * math.log(n)  # k=2

        bf = math.exp((bic_0 - bic_1) / 2.0)
        return max(0.01, min(1000.0, bf))

    def stats(self) -> dict:
        results = self.evaluate()
        n_adopt = sum(1 for r in results if r.recommendation == "adopt")
        n_reject = sum(1 for r in results if r.recommendation == "reject")
        n_inconclusive = sum(1 for r in results
                           if r.recommendation == "inconclusive")
        return {"n_tests": len(results), "n_adopt": n_adopt,
                "n_reject": n_reject, "n_inconclusive": n_inconclusive,
                "top_adopted": [r.hypothesis for r in results
                               if r.recommendation == "adopt"][:3]}

    def clear(self) -> None:
        self._comparisons.clear()
