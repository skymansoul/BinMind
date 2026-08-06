# 在线自适应去重阈值校准 — Thompson Sampling bandit + 成本敏感效用 + 漂移检测
import math
import random
import time
from collections import deque
from typing import Callable, Dict, List, Optional, Tuple

class _ThompsonBandit:
    """Beta-Bernoulli Thompson Sampling: 各 arm 维护 Beta(α,β) 后验,
    采样选最高值 arm, 奖励≥0.5 视为成功(α+=1), 否则失败(β+=1)."""

    def __init__(self, arms: List[float], prior_alpha: float = 1.0,
                 prior_beta: float = 1.0):
        self.arms = arms
        self.n_arms = len(arms)
        self._alphas = [prior_alpha] * self.n_arms
        self._betas = [prior_beta] * self.n_arms
        self._pulls = [0] * self.n_arms
        self._rng = random.Random(int(time.time() * 1e6) & 0x7FFFFFFF)

    def select(self) -> Tuple[int, float]:
        """Thompson 采样: 从各 arm 的后验采样, 返回采样值最大的 arm index."""
        best_idx, best_val = 0, -1.0
        for i in range(self.n_arms):
            sample = self._rng.betavariate(self._alphas[i], self._betas[i])
            if sample > best_val:
                best_val = sample
                best_idx = i
        return best_idx, self.arms[best_idx]

    def observe(self, arm_idx: int, reward: float):
        """用 [0, 1] 区间的奖励更新后验.

        reward ≥ 0.5 视为成功事件 (α+=1), 否则为失败 (β+=1).
        """
        self._pulls[arm_idx] += 1
        if reward >= 0.5:
            self._alphas[arm_idx] += reward
        else:
            self._betas[arm_idx] += (1.0 - reward)

    def best_arm(self) -> Tuple[int, float]:
        """返回后验均值最高的 arm (利用模式)."""
        means = [
            self._alphas[i] / (self._alphas[i] + self._betas[i])
            for i in range(self.n_arms)
        ]
        best = max(range(self.n_arms), key=lambda i: means[i])
        return best, self.arms[best]

    def stats(self) -> dict:
        return {
            "arms": self.arms,
            "alphas": self._alphas,
            "betas": self._betas,
            "pulls": self._pulls,
            "posterior_means": [
                round(self._alphas[i] / (self._alphas[i] + self._betas[i]), 4)
                for i in range(self.n_arms)
            ],
        }


# ---------------------------------------------------------------------------
# 自适应阈值校准器
# ---------------------------------------------------------------------------

class AdaptiveThresholdCalibrator:
    """在线自适应去重阈值校准器.

    用法: cal = AdaptiveThresholdCalibrator(thresholds=[...])
          cal.feedback(dups_found, false_positives, batch_size)
          best = cal.best_threshold()

    参数: lambda_fp(假阳性代价,>1→保守), lambda_fn(假阴性代价),
          explore_ratio(探索比), drift_window(漂移检测窗口), drift_threshold.
    """

    def __init__(self, thresholds: List[float] = None,
                 lambda_fp: float = 2.0, lambda_fn: float = 1.0,
                 explore_ratio: float = 0.1, drift_window: int = 50,
                 drift_threshold: float = 0.20):
        self.thresholds = thresholds or [0.75, 0.80, 0.82, 0.85, 0.88, 0.90, 0.92, 0.95]
        self.lambda_fp = lambda_fp
        self.lambda_fn = lambda_fn
        self.explore_ratio = explore_ratio
        self.drift_window = drift_window
        self.drift_threshold = drift_threshold

        self._bandit = _ThompsonBandit(self.thresholds)
        self._current_arm: Optional[int] = None
        self._current_threshold: float = self.thresholds[len(self.thresholds) // 2]
        self._reward_history: deque = deque(maxlen=drift_window)
        self._feedback_count: int = 0
        self._rng = random.Random(42)

        # 累积统计
        self._total_dups_found: int = 0
        self._total_fps_flagged: int = 0
        self._total_items_processed: int = 0

    def current_threshold(self) -> float:
        """返回当前推荐的最优阈值."""
        return self._current_threshold

    def select_for_batch(self) -> float:
        """为新批次选择阈值 (含探索噪声)."""
        if self._feedback_count < 10:
            # 冷启动: 均匀随机探索
            idx = self._rng.randint(0, len(self.thresholds) - 1)
            self._current_arm = idx
            self._current_threshold = self.thresholds[idx]
            return self._current_threshold

        if self._rng.random() < self.explore_ratio:
            # ε-greedy 探索
            idx = self._rng.randint(0, len(self.thresholds) - 1)
            self._current_arm = idx
            self._current_threshold = self.thresholds[idx]
            return self._current_threshold

        # Thompson 采样选择
        idx, val = self._bandit.select()
        self._current_arm = idx
        self._current_threshold = val
        return val

    def best_threshold(self) -> float:
        """返回当前后验最优阈值 (纯利用, 无探索)."""
        _, val = self._bandit.best_arm()
        return val

    def feedback(self, dup_pairs_found: int, false_positives: int,
                 batch_size: int, manual_feedback: float = None):
        """提交去重反馈: dup_pairs_found, false_positives, batch_size,
        manual_feedback(可选外部评分), 自动更新 bandit 后验并检测漂移."""
        self._feedback_count += 1
        self._total_items_processed += batch_size
        self._total_dups_found += dup_pairs_found
        self._total_fps_flagged += false_positives

        if manual_feedback is not None:
            reward = max(0.0, min(1.0, manual_feedback))
        else:
            reward = self._compute_utility(dup_pairs_found, false_positives,
                                           batch_size)

        self._reward_history.append(reward)
        if self._current_arm is not None:
            self._bandit.observe(self._current_arm, reward)
        if len(self._reward_history) >= self.drift_window:
            self._check_drift()

    def _compute_utility(self, dup_count: int, fp_count: int,
                         batch_size: int) -> float:
        """成本敏感效用: dup_reward - lambda_fp*fp_penalty - lambda_fn*fn_penalty,
        sigmoid 压缩至 [0,1]."""
        if batch_size <= 0:
            return 0.5
        max_possible = batch_size * (batch_size - 1) / 2
        dup_reward = min(dup_count / max(max_possible, 1), 1.0)
        fp_penalty = self.lambda_fp * (fp_count / max(batch_size, 1))
        dup_rate = dup_count / max(batch_size, 1)
        fn_penalty = self.lambda_fn * max(0, 0.3 - dup_rate) * 0.5
        raw = dup_reward - fp_penalty - fn_penalty
        return 1.0 / (1.0 + math.exp(-5.0 * raw))

    def _check_drift(self):
        """概念漂移检测: 窗口均值 vs 基线, 偏离超阈值则重置 bandit 后验."""
        if len(self._reward_history) < self.drift_window:
            return

        recent = list(self._reward_history)[-self.drift_window:]
        recent_mean = sum(recent) / len(recent)

        all_rewards = list(self._reward_history)
        if len(all_rewards) <= self.drift_window:
            return

        baseline = all_rewards[:-self.drift_window]
        baseline_mean = sum(baseline) / len(baseline)

        if baseline_mean <= 0.0:
            return

        drift = abs(recent_mean - baseline_mean) / baseline_mean
        if drift > self.drift_threshold:
            # 检测到漂移: 重置先验至弱信息先验 beta(2,2)
            self._bandit = _ThompsonBandit(
                self.thresholds, prior_alpha=2.0, prior_beta=2.0
            )

    def export_state(self) -> dict:
        """导出当前校准器完整状态, 用于跨会话持久化."""
        bs = self._bandit.stats()
        return {
            "thresholds": self.thresholds,
            "lambda_fp": self.lambda_fp,
            "lambda_fn": self.lambda_fn,
            "current_threshold": self._current_threshold,
            "best_threshold": self.best_threshold(),
            "bandit_state": bs,
            "feedback_count": self._feedback_count,
            "total_items": self._total_items_processed,
            "total_dups": self._total_dups_found,
            "total_fps": self._total_fps_flagged,
            "recent_reward_mean": (
                sum(self._reward_history) / max(len(self._reward_history), 1)
            ),
        }

    def load_state(self, state: dict):
        """从 export_state() 的输出恢复状态.

        仅恢复不依赖内部随机状态的统计量, bandit 后验从零开始.
        """
        self.lambda_fp = state.get("lambda_fp", self.lambda_fp)
        self.lambda_fn = state.get("lambda_fn", self.lambda_fn)
        self._feedback_count = state.get("feedback_count", 0)
        self._total_items_processed = state.get("total_items", 0)
        self._total_dups_found = state.get("total_dups", 0)
        self._total_fps_flagged = state.get("total_fps", 0)

    @property
    def stats(self) -> dict:
        return self.export_state()


# ---------------------------------------------------------------------------
# 去重阈值优化器 —— 封装 AdaptiveThresholdCalibrator + 去重引擎交互
# ---------------------------------------------------------------------------

class DedupThresholdOptimizer:
    """去重阈值优化包装器: 将 AdaptiveThresholdCalibrator 与现有去重引擎
    建立反馈回路, 无需侵入式修改引擎.用法见 AdaptiveThresholdCalibrator."""

    def __init__(self, dedup_engine=None,
                 thresholds: List[float] = None,
                 lambda_fp: float = 2.0, lambda_fn: float = 1.0):
        self._engine = dedup_engine
        self._cal = AdaptiveThresholdCalibrator(
            thresholds=thresholds,
            lambda_fp=lambda_fp, lambda_fn=lambda_fn,
        )
        self._batch_count = 0

    def select_threshold(self) -> float:
        return self._cal.select_for_batch()

    @property
    def threshold(self) -> float:
        """便捷属性: 返回当前最优阈值 (无探索)."""
        return self._cal.best_threshold()

    def record_batch(self, results: dict):
        """提交去重批次结果: {"total_items","duplicates_found","false_positives"}."""
        self._cal.feedback(results.get("duplicates_found", 0),
                          results.get("false_positives", 0),
                          max(results.get("total_items", 0), 1))
        self._batch_count += 1

    @property
    def optimizer_state(self) -> dict:
        return self._cal.export_state()

    @property
    def convergence_estimate(self) -> float:
        """收敛估计: bandit 后验方差均值的倒数, 越高越稳定."""
        bs = self._cal._bandit.stats()
        vars_ = [
            (bs["alphas"][i] * bs["betas"][i]) /
            ((bs["alphas"][i] + bs["betas"][i]) ** 2 *
             (bs["alphas"][i] + bs["betas"][i] + 1))
            for i in range(len(bs["arms"]))
        ]
        avg_var = sum(vars_) / len(vars_)
        return 1.0 / max(avg_var, 1e-9)


__all__ = [
    "AdaptiveThresholdCalibrator",
    "DedupThresholdOptimizer",
]
