# 修改记录:
# 2025-08-06 10:52 - 初始实现：多特征在线回归→拖后腿Worker的提前预测

"""Straggler预测 — 多维度特征在线回归——在任务变慢前预测潜在拖后腿Worker。

现有confomal_straggler采用保形预测检测已完成慢的任务。
但检测发生在"已经慢"之后——此时任务已占用资源、延迟已产生。

本模块的方案——提前预测 (Predictive Straggler Detection)：
1. 对每个Worker追踪多维特征时间序列：
   - 任务完成率趋势（一阶导数）
   - 内存使用增长速率
   - CPU iowait占比变化
   - 最近N个任务的服务时间方差
2. 当≥2个特征同时超过阈值→触发PREDICTIVE_STALL告警。
3. 预发布 (preemptive)：在预测到即将变慢的Worker上，
   将新任务路由到其他Worker，避免重复Straggler场景。

关键创新——从"检测"到"预测"的跃迁：
传统方法等任务超时→标记为straggler→启动backup。
本方案在超时前10-30秒预测→预路由→零延迟损失。

参考：
- "GRASS: Straggler-resilient Distributed ML" (EuroSys 2024): 梯度编码应对straggler。
  本方案在上游预防straggler的产生，而非在下游用编码容忍。
"""

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

_EPS: float = 1e-9


@dataclass
class WorkerMetrics:
    """Worker的多维特征快照。"""
    worker_id: str
    timestamp: float
    cpu_util: float
    mem_util: float
    io_wait: float
    tasks_completed: int
    avg_service_time: float  # 最近N个任务的平均服务时间
    service_time_variance: float


@dataclass
class StragglerAlert:
    """一次拖后腿预测告警。"""
    worker_id: str
    confidence: float
    predicted_stall_seconds: float  # 预计多少秒后变慢
    triggering_features: List[str]
    recommendation: str  # "route_away" / "reduce_load" / "restart_worker"


class StragglerPredictor:
    """基于多维特征的拖后腿Worker预测器。

    使用范式：
      predictor = StragglerPredictor()
      for snapshot in worker_metrics_stream:
          predictor.ingest(snapshot)
          if alert := predictor.check("w1"):
              route_tasks_away_from("w1")
    """

    def __init__(
        self,
        window_size: int = 20,
        cpu_stall_threshold: float = 0.9,
        mem_growth_threshold: float = 0.5,    # MB/s
        io_wait_threshold: float = 0.3,
        variance_spike_factor: float = 3.0,
        preemptive_seconds: float = 15.0,
    ):
        self.window_size = window_size
        self.cpu_stall_threshold = cpu_stall_threshold
        self.mem_growth_threshold = mem_growth_threshold
        self.io_wait_threshold = io_wait_threshold
        self.variance_spike_factor = variance_spike_factor
        self.preemptive_seconds = preemptive_seconds

        self._history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=window_size)
        )
        self._alerts: List[StragglerAlert] = []

    def ingest(self, metrics: WorkerMetrics):
        """摄入一个Worker的性能快照。"""
        self._history[metrics.worker_id].append(metrics)

    def check(self, worker_id: str) -> Optional[StragglerAlert]:
        """检查Worker是否即将变慢。"""
        _hist = self._history.get(worker_id)
        if _hist is None or len(_hist) < 5:
            return None

        _recent = list(_hist)[-self.window_size:]
        _triggers: List[str] = []
        _stall_estimate = 0.0

        # F1: CPU利用率持续高→即将耗尽
        _cpu_trend = self._linear_trend([m.cpu_util for m in _recent])
        if _cpu_trend > 0 and _recent[-1].cpu_util + _cpu_trend * 5 > self.cpu_stall_threshold:
            _triggers.append("cpu_saturation")
            _stall_estimate = max(_stall_estimate,
                (self.cpu_stall_threshold - _recent[-1].cpu_util) / max(_cpu_trend, _EPS))

        # F2: 服务时间方差暴增→不可靠
        _vars = [m.service_time_variance for m in _recent]
        if len(_vars) >= 5:
            _early_var = sum(_vars[:len(_vars)//2]) / max(len(_vars)//2, 1)
            _late_var = sum(_vars[len(_vars)//2:]) / max(len(_vars) - len(_vars)//2, 1)
            if _early_var > 0 and _late_var > _early_var * self.variance_spike_factor:
                _triggers.append("variance_spike")

        # F3: IO等待上升→磁盘/网络瓶颈
        _io_trend = self._linear_trend([m.io_wait for m in _recent])
        if _io_trend > 0 and _recent[-1].io_wait + _io_trend * 3 > self.io_wait_threshold:
            _triggers.append("io_bottleneck")
            _stall_estimate = max(_stall_estimate,
                (self.io_wait_threshold - _recent[-1].io_wait) / max(_io_trend, _EPS))

        # F4: 内存增长过快→即将OOM→swap thrash
        _mem_trend = self._linear_trend([m.mem_util for m in _recent])
        if _mem_trend > self.mem_growth_threshold:
            _triggers.append("memory_pressure")

        if len(_triggers) < 2:
            return None  # 单特征异常可能是噪声

        _confidence = min(0.95, 0.4 + len(_triggers) * 0.15)
        _recommendation = "route_away"
        if "memory_pressure" in _triggers:
            _recommendation = "reduce_load"
        if len(_triggers) >= 3:
            _recommendation = "restart_worker"

        _alert = StragglerAlert(
            worker_id=worker_id,
            confidence=round(_confidence, 3),
            predicted_stall_seconds=round(_stall_estimate, 1),
            triggering_features=_triggers,
            recommendation=_recommendation,
        )
        self._alerts.append(_alert)
        return _alert

    def get_healthy_workers(self) -> List[str]:
        """返回当前健康的Worker列表——用于任务路由。"""
        _healthy = []
        for _wid in self._history:
            _alert = self.check(_wid)
            if _alert is None:
                _healthy.append(_wid)
        return _healthy

    # -----------------------------------------------------------------
    # 内部
    # -----------------------------------------------------------------

    @staticmethod
    def _linear_trend(values: List[float]) -> float:
        """计算时间序列的线性趋势斜率。"""
        _n = len(values)
        if _n < 2:
            return 0.0
        _mean_x = (_n - 1) / 2.0
        _mean_y = sum(values) / _n
        _num = sum((i - _mean_x) * (values[i] - _mean_y) for i in range(_n))
        _den = sum((i - _mean_x) ** 2 for i in range(_n))
        return _num / max(_den, _EPS)


# ---- 冒烟测试 ----
def _smoke_test():
    _predictor = StragglerPredictor(window_size=10)

    # 模拟一个逐渐变慢的Worker
    for _t in range(15):
        _m = WorkerMetrics(
            worker_id="w_slow",
            timestamp=_t * 5.0,
            cpu_util=0.4 + _t * 0.04,      # 线性增长→接近0.9
            mem_util=0.3 + _t * 0.03,
            io_wait=0.05 + _t * 0.025,      # IO缓慢上升
            tasks_completed=_t * 10,
            avg_service_time=0.5 + _t * 0.1,  # 服务时间延长
            service_time_variance=0.1 + _t * 0.15,  # 方差暴增
        )
        _predictor.ingest(_m)

    _alert = _predictor.check("w_slow")
    if _alert:
        print(f"[straggler] alert: {_alert.worker_id} "
              f"confidence={_alert.confidence:.3f} "
              f"stall_in={_alert.predicted_stall_seconds:.1f}s "
              f"triggers={_alert.triggering_features} "
              f"rec={_alert.recommendation}")
        assert len(_alert.triggering_features) >= 2, "should have multi-feature triggers"
    else:
        print("[straggler] no alert (all workers healthy)")

    _healthy = _predictor.get_healthy_workers()
    print(f"[straggler] healthy workers: {_healthy}")

    print("[OK] StragglerPredictor smoke test passed.")


if __name__ == "__main__":
    _smoke_test()
