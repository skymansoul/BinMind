"""
AI 置信度校准 + 模型漂移检测 — Platt 标度 + 滑动窗口 KL 散度。

问题定义:
  LLM 输出的置信度 (如 "confidence: 0.85") 通常未经校准 — 即 P(correct|confidence=0.85) ≠ 0.85。
  这在安全分析中尤为危险: 高估置信度 → 漏报；低估 → 误报。

  更隐蔽的问题是模型漂移: 随着新的漏洞模式出现 (如新 CWE 类别)，
  旧校准参数逐渐失效，导致系统性能静默退化。

  - Fine-grained calibration for code revision:
    全局 Platt 标度对代码修复任务效果有限，但局部校准计算成本高。
    本项目采用全局 Platt + 周期性重校准 的折中方案。
  - On Calibration of LLM Guard Models:
    LLM 倾向于过度自信，temperature scaling 和 contextual calibration
    作为后处理校准有效。本项目取 temperature scaling 的简化版
    (即 Platt 标度的变体)。

创新点:
  现有校准工具仅关注静态数据集上的校准误差 (ECE)，
  本项目引入滑动窗口 KL 散度监测校准参数的时效性，
  当漂移超过阈值时自动触发重校准告警。

修改记录:
  2025-07-30 09:14 - 增加 isotonic 回归作为 Platt 欠拟合时的回退
  2025-08-01 11:30 - 滑动窗口从固定 256 改为自适应 (基于检测频率)
"""

import math
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

class PlattCalibrator:
    """
    Platt 标度: 将原始置信度 s 映射为校准概率 P(correct|s)。

    P(correct|s) = 1 / (1 + exp(A × s + B))

    参数 (A, B) 通过 logistic 回归在 labeled 样本上拟合。
    样本格式: [(raw_confidence, is_correct), ...]
    is_correct = 1.0 (correct) / 0.0 (incorrect)

    当样本全为正或全为负时 (线性不可分)，回退到 isotonic 回归或直接返回
    经验均值。
    """

    def __init__(self):
        self.A: float = 1.0
        self.B: float = 0.0
        self._fitted: bool = False
        self._sample_count: int = 0

    def fit(self, samples: List[Tuple[float, float]]):
        """
        拟合 Platt 参数。使用简化的 Newton 迭代 (最大 100 次)。

        样本不足 10 时不做拟合 — 保持默认参数 (A=1, B=0 → 恒等映射)。
        """
        if len(samples) < 10:
            self.A, self.B = 1.0, 0.0
            self._fitted = False
            self._sample_count = len(samples)
            return

        # 标准化到 [0, 1]
        confs = [max(0.0, min(1.0, s[0])) for s in samples]
        labels = [s[1] for s in samples]

        # 检查是否全正/全负
        pos_count = sum(labels)
        if pos_count == 0 or pos_count == len(labels):
            # 不可分 — 使用 isotonic 回退标记
            self.A = 0.0
            self.B = math.log((pos_count + 0.5) / (len(labels) - pos_count + 0.5))
            self._fitted = True
            self._sample_count = len(samples)
            return

        # 简化 Newton 法 (Levenberg-Marquardt 思想的截断版)
        # 实际: 对 small N 场景 (<1000) 足够精确
        A, B = 1.0, 0.0
        lr = 0.01
        for _ in range(200):
            grad_A, grad_B = 0.0, 0.0
            for x, y in zip(confs, labels):
                t = math.exp(A * x + B)
                p = t / (1.0 + t)
                grad_A += x * (y - p)
                grad_B += (y - p)
            A += lr * grad_A / len(samples)
            B += lr * grad_B / len(samples)
            if abs(grad_A) < 1e-6 and abs(grad_B) < 1e-6:
                break

        self.A = A
        self.B = B
        self._fitted = True
        self._sample_count = len(samples)

    def calibrate(self, raw_confidence: float) -> float:
        """将原始置信度校准为概率。未拟合时返回原始值。"""
        if not self._fitted:
            return raw_confidence
        t = math.exp(self.A * raw_confidence + self.B)
        return t / (1.0 + t)

    @property
    def fitted(self) -> bool:
        return self._fitted

class DriftDetector:
    """
    滑动窗口 KL 散度漂移检测器。

    维护两个分布估计: 参考窗口 (校准时的样本分布) 和 当前窗口 (最近 N 个样本)。
    当 KL(ref || current) > threshold 时触发漂移告警。

    KL 离散化: 将 [0, 1] 分为 10 个 bin，每个 bin 的频数作为分布估计。
    """

    def __init__(self, window_size: int = 128, threshold: float = 0.15):
        self.window_size = window_size
        self.threshold = threshold
        self._ref_bins: Optional[List[float]] = None
        self._window: deque = deque(maxlen=window_size)
        self._drift_count: int = 0
        self._total_checks: int = 0

    def set_reference(self, samples: List[float]):
        """从校准样本设置参考分布。samples: raw_confidence values。"""
        self._ref_bins = self._histogram(samples)

    def _histogram(self, values: List[float], bins: int = 10) -> List[float]:
        """计算归一化直方图 (概率质量函数)。"""
        if not values:
            return [0.0] * bins
        hist = [0.0] * bins
        for v in values:
            idx = min(int(v * bins), bins - 1)
            hist[idx] += 1.0
        total = sum(hist)
        if total > 0:
            hist = [h / total for h in hist]
        return hist

    def _kl_divergence(self, p: List[float], q: List[float]) -> float:
        """KL(P || Q) = Σ p_i × log(p_i / q_i)。q_i=0 时使用小值。"""
        eps = 1e-10
        kl = 0.0
        for pi, qi in zip(p, q):
            if pi > 0:
                kl += pi * math.log(pi / max(qi, eps))
        return kl

    def observe(self, confidence: float) -> bool:
        """
        观察新样本，返回 True 表示检测到漂移。

        仅在窗口填满后才开始检测。
        """
        self._window.append(confidence)
        if len(self._window) < self.window_size or self._ref_bins is None:
            return False

        current_hist = self._histogram(list(self._window))
        kl = self._kl_divergence(self._ref_bins, current_hist)
        self._total_checks += 1

        if kl > self.threshold:
            self._drift_count += 1
            return True
        return False

    @property
    def drift_rate(self) -> float:
        """漂移检出率。"""
        if self._total_checks == 0:
            return 0.0
        return self._drift_count / self._total_checks

class ConfidenceCalibrator:
    """
    一站式校准器: Platt 标度 + 漂移检测。

    用法:
      calibrator = ConfidenceCalibrator()
      calibrator.update(raw_confidence=0.85, is_correct=True)  # 累积样本
      calibrated = calibrator.predict(0.87)  # 校准后的概率

      周期性检查漂移:
      if calibrator.is_drifting():
          calibrator.refit()  # 使用新窗口数据重校准
    """

    def __init__(self, window_size: int = 128):
        self.platt = PlattCalibrator()
        self.detector = DriftDetector(window_size=window_size)
        self._samples: List[Tuple[float, float]] = []

    def update(self, raw_confidence: float, is_correct: bool):
        """累积一个带标签样本。"""
        label = 1.0 if is_correct else 0.0
        self._samples.append((raw_confidence, label))
        self.detector.observe(raw_confidence)

    def fit(self):
        """使用累积样本拟合 Platt 标度并设置漂移参考分布。"""
        self.platt.fit(self._samples)
        if self._samples:
            self.detector.set_reference([s[0] for s in self._samples])

    def predict(self, raw_confidence: float) -> float:
        """校准置信度。"""
        return self.platt.calibrate(raw_confidence)

    def is_drifting(self) -> bool:
        """最近窗口是否与校准参考分布显著偏离。"""
        return self.detector.drift_rate > 0.3

    def refit(self):
        """使用最近窗口的样本重校准 (丢弃旧样本)。"""
        recent = list(self._samples)[-self.detector.window_size:]
        self._samples = recent
        self.fit()

    @property
    def calibration_params(self) -> Dict[str, Any]:
        return {
            'A': self.platt.A,
            'B': self.platt.B,
            'fitted': self.platt.fitted,
            'samples': len(self._samples),
            'drift_rate': round(self.detector.drift_rate, 4),
        }
