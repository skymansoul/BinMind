# coding: utf-8
"""
分布漂移检测 — 在 StreamingSketch 之上检测钩子执行行为的统计分布变化.

钩子管道的执行指标 (延迟、输出体积、产出键数) 在正常运行时形成稳态分布.
当以下事件发生时, 分布发生漂移:
  - 二进制特征变化 (不同架构、不同大小)
  - 钩子代码回归 (升级引入了性能退化)
  - 系统负载变化 (机器争用导致的延迟尖峰)
  - 数据污染 (异常输入导致钩子走入罕见代码路径)

CALM 使用 LLM 做语义漂移判断, 但对管道指标漂移,
统计方法更适合: 不需要 LLM 延迟, 量化可解释, 且能直接定位到具体钩子.

检测策略:
  1. 维持一个基线草图 (baseline, 长窗口) 和一个滑动窗口草图 (recent)
  2. 每次更新 recent 后, 计算两个草图之间的分布距离
  3. 距离超过阈值时触发漂移告警, 按严重程度分级
  4. 持续漂移达到确认期后, 自动将 recent 提升为新基线

距离度量: 使用质心级 Wasserstein 近似 + CDF 上确界差异 (KS 统计量).
两个度量的组合对位置漂移 (均值平移) 和形状漂移 (方差变化) 均敏感.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from modules.core.execution_sketch import StreamingSketch, MetricSketchGroup


class DriftSeverity(Enum):
    NOMINAL = 0       # 分布稳定
    MILD = 1           # 轻微漂移 — 记录但无需干预
    SIGNIFICANT = 2    # 显著漂移 — 建议检查
    SEVERE = 3          # 严重漂移 — 应触发告警/熔断


@dataclass
class DriftReport:
    """一次漂移检测的输出报告."""
    hook_name: str
    metric: str
    severity: DriftSeverity
    wasserstein_dist: float
    ks_statistic: float
    baseline_count: int
    recent_count: int
    baseline_mean: float
    recent_mean: float
    timestamp: float = field(default_factory=time.time)
    detail: str = ''

    def __repr__(self) -> str:
        return (f'Drift({self.hook_name}:{self.metric} '
                f'{self.severity.name} W={self.wasserstein_dist:.3f} KS={self.ks_statistic:.3f} '
                f'μ:{self.baseline_mean:.1f}→{self.recent_mean:.1f})')


def _wasserstein_centroids(a: StreamingSketch, b: StreamingSketch) -> float:
    """质心级 Wasserstein-1 距离的简化近似.

    在两个草图的所有质心对上计算 |mean_a - mean_b| * min(weight_a, weight_b),
    按均值排序后做前缀扫描. 复杂度 O(C_a + C_b).
    """
    # 收集所有 (mean, weight, source) 并按 mean 排序
    pts: List[Tuple[float, float, int]] = []
    for c in a._centroids:
        pts.append((c.mean, c.weight, 0))
    for c in b._centroids:
        pts.append((c.mean, c.weight, 1))
    if not pts:
        return 0.0
    pts.sort(key=lambda x: x[0])

    total = 0.0
    cum_a, cum_b = 0.0, 0.0
    for i in range(len(pts) - 1):
        mean_i, w_i, src_i = pts[i]
        mean_j = pts[i + 1][0]
        if src_i == 0:
            cum_a += w_i
        else:
            cum_b += w_i
        # 在两个相邻质心之间, |F_a - F_b| = |cum_a/total_a - cum_b/total_b|
        total_a = a._total_weight or 1.0
        total_b = b._total_weight or 1.0
        diff = abs(cum_a / total_a - cum_b / total_b)
        total += diff * (mean_j - mean_i)
    return total


def _ks_statistic(a: StreamingSketch, b: StreamingSketch) -> float:
    """CDF 上确界差异: max_x |F_a(x) - F_b(x)|.

    在 a 和 b 的所有质心均值点处评估 CDF 差异.
    """
    eval_points: List[float] = []
    for c in a._centroids:
        eval_points.append(c.mean)
    for c in b._centroids:
        eval_points.append(c.mean)
    if not eval_points:
        return 0.0

    max_diff = 0.0
    for x in eval_points:
        diff = abs(a.cdf(x) - b.cdf(x))
        if diff > max_diff:
            max_diff = diff
    return max_diff


class DriftDetector:
    """单指标的分布漂移检测器.

    维护基线 (长窗口) 和滑动窗口 (近期) 两个草图.
    每次记录新值时更新滑动窗口; 定期或在达到窗口大小时比较二者.
    """

    def __init__(
        self, hook_name: str = '', metric_name: str = '',
        window_size: int = 50,            # 滑动窗口的观测数, 超限后最旧值被归并
        baseline_min_samples: int = 30,    # 基线最少观测数 (不足时不做比较)
        w_thresholds: Tuple[float, float, float] = (0.08, 0.18, 0.35),
        ks_thresholds: Tuple[float, float, float] = (0.12, 0.25, 0.45),
        confirm_window: int = 3,           # 连续漂移确认次数 (自动更新基线)
    ):
        self.hook_name = hook_name
        self.metric_name = metric_name
        self.baseline = StreamingSketch(name=f'{hook_name}:{metric_name}:base')
        self.recent = StreamingSketch(name=f'{hook_name}:{metric_name}:recent')
        self._window_size = window_size
        self._baseline_min = baseline_min_samples
        self._w_thresh = w_thresholds
        self._ks_thresh = ks_thresholds
        self._confirm_window = confirm_window
        self._drift_streak = 0  # 连续漂移轮次
        self._recent_count = 0

    def record(self, value: float) -> Optional[DriftReport]:
        """记录一个观测值; 若窗口满则执行漂移检测并返回报告."""
        self.recent.add(value)
        self._recent_count += 1

        if self._recent_count < self._window_size:
            return None

        # 窗口满: 执行检测
        report = self._compare()
        self._recent_count = 0

        if report is not None and report.severity != DriftSeverity.NOMINAL:
            self._drift_streak += 1
            if self._drift_streak >= self._confirm_window:
                # 确认漂移: 将 recent 归并入 baseline, 开始追踪新稳态
                self.baseline.merge(self.recent)
                self.recent = StreamingSketch(name=self.recent.name)
                self._drift_streak = 0
        else:
            # 无漂移: 将 recent 归并入 baseline, 维持单一稳态模型
            self.baseline.merge(self.recent)
            self.recent = StreamingSketch(name=self.recent.name)
            self._drift_streak = max(0, self._drift_streak - 1)

        return report

    def _compare(self) -> Optional[DriftReport]:
        """比较基线 (baseline) 与滑动窗口 (recent) 的分布差异."""
        if self.baseline.count < self._baseline_min:
            # 基线样本不足, 暂不比较
            self.baseline.merge(self.recent)
            self.recent = StreamingSketch(name=self.recent.name)
            return None

        w_dist = _wasserstein_centroids(self.baseline, self.recent)
        ks_val = _ks_statistic(self.baseline, self.recent)

        # 综合判定: 任一维度过阈值即告警, 严重度取 max
        sev_w = DriftSeverity.NOMINAL
        sev_ks = DriftSeverity.NOMINAL

        for i, (w_t, ks_t) in enumerate(zip(self._w_thresh, self._ks_thresh)):
            severity = DriftSeverity(i + 1)
            if w_dist >= w_t and sev_w == DriftSeverity.NOMINAL:
                sev_w = severity
            if ks_val >= ks_t and sev_ks == DriftSeverity.NOMINAL:
                sev_ks = severity

        severity = sev_w if sev_w.value > sev_ks.value else sev_ks

        base_mean = self.baseline.mean()
        recent_mean = self.recent.mean()

        if severity == DriftSeverity.NOMINAL:
            detail = '分布无明显漂移'
        elif severity == DriftSeverity.MILD:
            detail = f'轻微偏移: 基线均值 {base_mean:.1f}, 近期 {recent_mean:.1f}'
        elif severity == DriftSeverity.SIGNIFICANT:
            dd = '增加' if recent_mean > base_mean else '下降'
            pct = abs(recent_mean - base_mean) / max(1, base_mean) * 100
            detail = f'均值{dd} {pct:.0f}%: {base_mean:.1f}→{recent_mean:.1f}'
        else:
            dd = '剧增' if recent_mean > base_mean else '骤降'
            pct = abs(recent_mean - base_mean) / max(1, base_mean) * 100
            detail = f'均值{dd} {pct:.0f}%: {base_mean:.1f}→{recent_mean:.1f}, '
            detail += '建议熔断该钩子或检查上游输入'

        return DriftReport(
            hook_name=self.hook_name, metric=self.metric_name,
            severity=severity, wasserstein_dist=w_dist,
            ks_statistic=ks_val,
            baseline_count=int(self.baseline.count),
            recent_count=int(self.recent.count),
            baseline_mean=base_mean, recent_mean=recent_mean,
            detail=detail,
        )

    def force_compare(self) -> Optional[DriftReport]:
        """外部触发的强制比较 (窗口未满时也执行)."""
        if self.recent.count < 2:
            return None
        return self._compare()

    def reset(self):
        self.baseline = StreamingSketch(name=self.baseline.name)
        self.recent = StreamingSketch(name=self.recent.name)
        self._drift_streak = 0
        self._recent_count = 0


class PipelineDriftMonitor:
    """管道级漂移监控 — 为每个钩子的延迟和产出指标维护独立的检测器.

    与 ProvenanceScheduler 集成: 在执行后调用 record() 收集指标,
    定期 poll() 获取漂移报告列表.

    报告策略:
      - 仅返回 SIGNIFICANT 或 SEVERE 的漂移 (减少噪声)
      - 按严重度降序排列
    """

    def __init__(self, window_size: int = 50, baseline_min_samples: int = 30):
        self._detectors: Dict[str, Dict[str, DriftDetector]] = {}
        self._window_size = window_size
        self._baseline_min = baseline_min_samples
        self._reports: List[DriftReport] = []

    def ensure_hook(self, hook_name: str, metrics: Tuple[str, ...] = ('latency_ms',)):
        """确保某钩子的指标检测器已初始化."""
        if hook_name not in self._detectors:
            self._detectors[hook_name] = {}
        for m in metrics:
            if m not in self._detectors[hook_name]:
                self._detectors[hook_name][m] = DriftDetector(
                    hook_name=hook_name, metric_name=m,
                    window_size=self._window_size,
                    baseline_min_samples=self._baseline_min,
                )

    def record(self, hook_name: str, metrics: Dict[str, float]) -> None:
        """记录一次钩子执行的指标值, 若触发漂移则追加报告."""
        self.ensure_hook(hook_name, tuple(metrics.keys()))
        for key, val in metrics.items():
            det = self._detectors.get(hook_name, {}).get(key)
            if det is None:
                continue
            report = det.record(val)
            if report is not None and report.severity.value >= DriftSeverity.SIGNIFICANT.value:
                self._reports.append(report)

    def poll(self) -> List[DriftReport]:
        """返回并清空待处理的漂移报告."""
        reports = self._reports
        self._reports = []
        return reports

    def force_check(self) -> List[DriftReport]:
        """强制检查所有检测器的当前状态."""
        reports = []
        for hook_dets in self._detectors.values():
            for det in hook_dets.values():
                r = det.force_compare()
                if r is not None and r.severity.value >= DriftSeverity.SIGNIFICANT.value:
                    reports.append(r)
        return reports

    def all_detectors(self) -> Dict[str, Dict[str, DriftDetector]]:
        return self._detectors

    def reset_hook(self, hook_name: str):
        if hook_name in self._detectors:
            for det in self._detectors[hook_name].values():
                det.reset()
