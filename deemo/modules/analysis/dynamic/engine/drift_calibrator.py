# 修改记录:
# 2025-08-02 11:33 - 校准动作注册表: 每类校准动作对应一个可插拔 handler
# 2025-08-03 16:07 - 校准效果验证: 执行校准后监控 3 个采集周期, 若度量未恢复则升级校准级别

"""分析管道漂移校准器 - 漂移检测->校准触发->效果验证的闭环

将 drift_metrics (度量收集) 和 drift_detector (漂移检测) 组合为
完整的自校准管线:

  度量收集 (定时) -> 漂移检测 -> 严重度判定 ->
  ├─ NORMAL: 继续收集
  ├─ MILD:   轻量校准 + 继续监控
  ├─ MODERATE: 中层校准 + 验证
  ├─ SEVERE:  深度校准 + 验证
  └─ CRITICAL: 重启管道

校准验证:
  执行校准后进入验证期--监控 3 个采集周期
  若 Mahalanobis 距离未回落到阈值以下 -> 升级校准级别
  若 3 次升级后仍未恢复 -> 触发 CRITICAL 级别

设计决策:
- 每类校准动作匹配一个优先级: 低优先级动作 (flush cache) 优先尝试
- 升级策略: flush -> reset context -> 注入噪声 -> prune -> 重启
- 避免过度校准: 冷却期机制防止校准震荡
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional, Set

from .drift_metrics import (
    DriftMetricCollector,
    MetricSnapshot,
    CoverageMarginalTracker,
    TaintConfidenceTracker,
)
from .drift_detector import (
    DriftDetector,
    DriftSeverity,
    CalibrationAction,
    DriftReport,
)

_log = logging.getLogger(__name__)


# 校准动作处理器注册表

CalibrationHandler = Callable[[], bool]
# 返回 True = 成功执行, False = 执行失败或不可用


class CalibrationRegistry:
    """校准动作 -> 处理器映射

    外部模块通过 register() 注册具体的校准逻辑
    例如: solver 模块可注册 FLUSH_SOLVER_CACHE -> z3_solver.reset_cache()
    """

    def __init__(self):
        self._handlers: Dict[CalibrationAction, List[CalibrationHandler]] = {}

    def register(self, action: CalibrationAction, handler: CalibrationHandler) -> None:
        """注册校准动作的处理器--支持同一动作多个处理器 (链式调用)"""
        if action not in self._handlers:
            self._handlers[action] = []
        self._handlers[action].append(handler)

    def execute(self, action: CalibrationAction) -> bool:
        """执行单个校准动作, 返回是否成功"""
        handlers = self._handlers.get(action, [])
        if not handlers:
            _log.debug(f"DriftCalibrator: no handler for {action.value}")
            return False

        all_ok = True
        for h in handlers:
            try:
                ok = h()
                if not ok:
                    all_ok = False
                    _log.warning(
                        f"DriftCalibrator: handler for {action.value} returned False"
                    )
            except Exception as e:
                all_ok = False
                _log.error(
                    f"DriftCalibrator: handler for {action.value} raised {e}"
                )
        return all_ok

    def execute_all(self, actions: List[CalibrationAction]) -> Dict[str, bool]:
        """按优先级顺序执行多个校准动作"""
        # 优先级: FLUSH < RESET < INJECT < PRUNE < RESTART
        priority = {
            CalibrationAction.NONE: 0,
            CalibrationAction.FLUSH_SOLVER_CACHE: 1,
            CalibrationAction.RESET_TAINT_MODEL: 2,
            CalibrationAction.RESET_SOLVER_CONTEXT: 3,
            CalibrationAction.INJECT_EXPLORATION_NOISE: 4,
            CalibrationAction.PRUNE_STALE_STATES: 5,
            CalibrationAction.RESTART_PIPELINE: 6,
        }
        sorted_actions = sorted(actions, key=lambda a: priority.get(a, 99))
        results = {}
        for action in sorted_actions:
            results[action.value] = self.execute(action)
        return results


# 主校准器

class DriftCalibrator:
    """分析管道漂移校准器--完整的监控-检测-校准-验证闭环

    用法:
    cal = DriftCalibrator()
    # 注册校准处理器
    cal.registry.register(CalibrationAction.FLUSH_SOLVER_CACHE, my_flush_fn)
    # 定时调用 (如每 60s)
    snap = MetricSnapshot(timestamp=time.time(), ...)
    report = cal.feed(snap)
    if report.is_calibrating:
        cal.apply_calibration(report)
    """

    # 验证期长度--校准后观察多少个采集周期
    VERIFICATION_PERIODS = 3
    # 最大升级次数--超过此数直接触发 CRITICAL
    MAX_ESCALATIONS = 3

    def __init__(
        self,
        collector: Optional[DriftMetricCollector] = None,
        detector: Optional[DriftDetector] = None,
    ):
        self.collector = collector or DriftMetricCollector()
        self.detector = detector or DriftDetector()
        self.registry = CalibrationRegistry()

        # 验证状态
        self._verifying = False
        self._verify_countdown = 0
        self._pre_calibration_d2 = 0.0
        self._escalation_count = 0
        self._last_severity: DriftSeverity = DriftSeverity.NORMAL

        # 历史报告--供外部查询趋势
        self._report_history: List[DriftReport] = []

        # 覆盖率边际跟踪
        self._coverage_tracker = CoverageMarginalTracker()
        # 污点置信度跟踪
        self._taint_tracker = TaintConfidenceTracker()

    def feed(self, snapshot: MetricSnapshot) -> DriftReport:
        """输入一个度量快照--返回漂移检测报告

        这是主入口--所有监控逻辑的集中点
        """
        # 更新度量收集器
        self.collector.collect(snapshot)
        self._coverage_tracker.update(snapshot.coverage_marginal_gain)
        self._taint_tracker.record(
            precise=int(snapshot.taint_confidence_mean * 100),
            approximate=int((1.0 - snapshot.taint_confidence_mean) * 100),
        )

        # 漂移检测
        report = self.detector.detect(snapshot)

        # 验证期逻辑
        if self._verifying:
            self._verify_countdown -= 1
            if report.severity <= DriftSeverity.MILD:
                # 度量恢复正常
                self._complete_verification(success=True)
            elif self._verify_countdown <= 0:
                # 验证期满但未恢复--升级
                self._escalate()

        self._report_history.append(report)
        if len(self._report_history) > 500:
            self._report_history = self._report_history[-300:]

        return report

    def apply_calibration(self, report: DriftReport) -> Dict[str, Any]:
        """执行漂移报告建议的校准动作

        返回执行结果摘要
        """
        if not report.is_calibrating:
            return {"status": "skipped", "reason": "not calibrating"}

        self.detector.mark_calibration_started()

        actions = report.recommended_actions
        results = self.registry.execute_all(actions)

        # 进入验证期
        self._verifying = True
        self._verify_countdown = self.VERIFICATION_PERIODS
        self._pre_calibration_d2 = report.mahalanobis_distance
        self._last_severity = report.severity

        _log.info(
            f"DriftCalibrator: applied {len(actions)} actions, "
            f"severity={report.severity.name}, "
            f"verification periods={self.VERIFICATION_PERIODS}"
        )

        return {
            "status": "calibrated",
            "actions": [a.value for a in actions],
            "results": results,
            "verification_periods": self.VERIFICATION_PERIODS,
            "pre_calibration_d2": self._pre_calibration_d2,
        }

    def _escalate(self) -> None:
        """升级校准级别"""
        self._escalation_count += 1

        if self._escalation_count >= self.MAX_ESCALATIONS:
            _log.critical(
                f"DriftCalibrator: {self.MAX_ESCALATIONS} escalations reached, "
                f"triggering RESTART_PIPELINE"
            )
            self.registry.execute(CalibrationAction.RESTART_PIPELINE)
            self._complete_verification(success=False)
            return

        # 升级到下一级严重度
        escalation_map = {
            DriftSeverity.MILD: DriftSeverity.MODERATE,
            DriftSeverity.MODERATE: DriftSeverity.SEVERE,
            DriftSeverity.SEVERE: DriftSeverity.CRITICAL,
        }
        new_severity = escalation_map.get(
            self._last_severity, DriftSeverity.CRITICAL
        )

        _log.warning(
            f"DriftCalibrator: escalating from {self._last_severity.name} "
            f"to {new_severity.name} (escalation {self._escalation_count}/"
            f"{self.MAX_ESCALATIONS})"
        )

        # 执行升级后的校准动作
        anomalous = getattr(self.detector, '_recent_samples', [])
        actions = self.detector._actions_for_severity(new_severity, [])
        self.registry.execute_all(actions)

        self._last_severity = new_severity
        self._verify_countdown = self.VERIFICATION_PERIODS

    def _complete_verification(self, success: bool) -> None:
        """结束验证期"""
        self._verifying = False
        self._verify_countdown = 0
        self._escalation_count = 0
        self.detector.mark_calibration_complete()

        if success:
            _log.info("DriftCalibrator: verification passed, metrics recovered")
        else:
            _log.warning("DriftCalibrator: verification failed after max escalations")

# 便捷查询
    @property
    def is_healthy(self) -> bool:
        """快速健康检查--管道是否正常运行"""
        if not self._report_history:
            return True
        recent = self._report_history[-5:]
        severe_count = sum(
            1 for r in recent
            if r.severity in (DriftSeverity.SEVERE, DriftSeverity.CRITICAL)
        )
        return severe_count == 0

    @property
    def is_verifying(self) -> bool:
        return self._verifying

    def summary(self) -> Dict[str, Any]:
        """生成当前状态的摘要报告"""
        trends = self.collector.get_all_trends()
        return {
            "uptime_seconds": self.collector.uptime_seconds,
            "collect_count": self.collector.collect_count,
            "is_healthy": self.is_healthy,
            "is_verifying": self._verifying,
            "escalation_count": self._escalation_count,
            "coverage_stagnating": self._coverage_tracker.is_stagnating(),
            "taint_degrading": self._taint_tracker.is_degrading,
            "coverage_gain_rate": self._coverage_tracker.current_gain_rate,
            "taint_confidence": self._taint_tracker.confidence,
            "metric_trends": {
                name: {"mean": t["mean"], "skewness": t["skewness"]}
                for name, t in trends.items()
            },
            "recent_reports": len(self._report_history),
        }
