"""测试鞅与 e-value — 随时有效统计推断基础设施.

从 martingale_fuzz_assess.py 分离, 提供纯数学层。
参考: Shafer & Vovk (2019) "Game-Theoretic Foundations", Ramdas et al. (2023)
"""

import math
from typing import List, Tuple


def e_value_from_probability(p_null: float, p_alt: float,
                             clip_max: float = 20.0) -> float:
    """似然比 e-value: E = p_alt / p_null.

    若零假设为真, E[E] ≤ 1。若备择假设为真, E 可能很大。
    clip_max 防止单个异常事件主导整个鞅。
    """
    if p_null <= 0:
        return clip_max
    return min(clip_max, p_alt / p_null)


def update_martingale(current_martingale: float,
                      e_value: float) -> float:
    """鞅更新: M_t = M_{t-1} × E_t.

    在零假设下, E[M_t] = M₀ (通常 M₀=1)。
    若 M_t 很大 (如 >20), 可拒绝零假设。
    """
    return max(0.0, current_martingale * max(0.0, e_value))


class TestMartingale:
    """测试鞅 — 累积 e-value 以进行随时有效的假设检验.

    关键性质: 可在任意时刻停止并做出统计推断,
    无需多重检验校正 (Bonferroni 等)。
    这是 Martingale 相对于固定样本检验的核心优势。
    """

    def __init__(self, initial_value: float = 1.0,
                 rejection_threshold: float = 20.0):
        self.m0 = initial_value
        self.martingale = initial_value
        self.threshold = rejection_threshold
        self._history: List[Tuple[float, float]] = []  # (e_value, martingale)
        self.step: int = 0

    def update(self, p_null: float, p_alt: float) -> float:
        """基于似然比的一次更新."""
        e = e_value_from_probability(p_null, p_alt)
        self.martingale = update_martingale(self.martingale, e)
        self.step += 1
        self._history.append((e, self.martingale))
        return self.martingale

    def is_rejected(self) -> bool:
        """零假设是否可被拒绝 (在任意停止规则下有效)."""
        return self.martingale >= self.threshold

    def log10_evidence(self) -> float:
        """证据的 log₁₀ 尺度 — 更直观的强度表示.

        >1: 中等证据; >2: 强证据; >3: 决定性证据。
        """
        if self.martingale <= 0:
            return 0.0
        return math.log10(self.martingale)

    def reset(self) -> None:
        self.martingale = self.m0
        self._history.clear()
        self.step = 0


class SequentialProbabilityRatioTest:
    """Wald 序贯概率比检验 (SPRT) — 两个假设间的随时有效比较.

    持续观测, 直到累计证据支持 H₀ 或 H₁。
    用于 fuzzing: 比较两种突变策略的 bug 发现率。
    """

    def __init__(self, alpha: float = 0.05, beta: float = 0.20):
        # alpha: type-I error (错误拒绝 H₀)
        # beta:  type-II error (错误接受 H₀)
        self.alpha = alpha
        self.beta = beta
        self.A = beta / (1 - alpha)     # 接受 H₀ 的边界
        self.B = (1 - beta) / alpha      # 拒绝 H₀ 的边界
        self.log_A = math.log(self.A)
        self.log_B = math.log(self.B)
        self.llr_cumulative: float = 0.0  # 累积对数似然比
        self.step: int = 0
        self.decision: str = "continue"   # "accept_H0" | "reject_H0" | "continue"

    def update(self, success_H1: bool = False) -> str:
        """一次观测更新.

        简化: 假设每次执行成功概率 p₀(H₀) 和 p₁(H₁) 已知。
        实际 fuzzing 中, p₀ = 基线发现率, p₁ = 预期的改进率。
        success_H1=True 表示此执行中备择假设更可能。
        """
        self.step += 1
        if success_H1:
            self.llr_cumulative += 0.5   # 弱证据支持 H₁
        else:
            self.llr_cumulative -= 0.1   # 弱证据支持 H₀

        if self.llr_cumulative <= self.log_A:
            self.decision = "accept_H0"
        elif self.llr_cumulative >= self.log_B:
            self.decision = "reject_H0"
        else:
            self.decision = "continue"
        return self.decision

    def reset(self) -> None:
        self.llr_cumulative = 0.0
        self.step = 0
        self.decision = "continue"


def coverage_plateau_martingale(new_edges_per_window: List[int],
                                 window_size: int = 100) -> TestMartingale:
    """构建覆盖平台检测鞅.

    H₀ (零假设): 覆盖仍在增长 (每次执行有 λ₀ 概率发现新边)
    H₁ (备择):   覆盖已停滞 (发现概率降至 λ₁ < λ₀)

    对每个窗口, 使用二项似然比更新鞅。
    鞅增长 → 覆盖可能已停滞的证据。
    """
    tm = TestMartingale()
    lambda_zero = 0.02   # H₀: 每次执行 2% 概率新边
    lambda_one = 0.002   # H₁: 停滞, 仅 0.2%

    for new_edges in new_edges_per_window:
        if window_size <= 0:
            continue
        obs_rate = new_edges / window_size
        # 二项似然: P(obs|H₀) vs P(obs|H₁)
        p_null = (lambda_zero ** new_edges) * ((1 - lambda_zero) ** (window_size - new_edges))
        p_alt = (lambda_one ** new_edges) * ((1 - lambda_one) ** (window_size - new_edges))
        tm.update(p_null, p_alt)
    return tm
