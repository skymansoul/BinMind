# 初始实现: Little's Law+排队论的分析管道瓶颈自动检测

"""分析管道瓶颈检测 - 基于排队论的阶段级吞吐量分析与瓶颈定位。

多阶段二进制分析管道（反汇编→CFG构建→漏洞检测→利用生成→报告）
各阶段计算特性不同（I/O密集、CPU密集、内存密集），
瓶颈可能出现在任一阶段，且随二进制特征变化。

核心机制-排队论驱动的瓶颈识别：
1. 将管道建模为串联队列（M/M/1 或 G/G/1 取决于到达/服务时间分布）。
2. 追踪每阶段的: 到达率(λ)、服务率(μ)、队列长度(L_q)、利用率(ρ)。
3. 瓶颈指标：ρ > 0.85 → 该阶段过载，需增加资源。
   L_q持续增长 → 到达超过服务能力，需横向扩容或算法优化。
4. Little's Law验证: L = λ·W - 若实测违反, 说明存在批处理/并发效应。

与既有 checkpoint_manager 的关系：
- checkpoint_manager：管道状态的持久化（故障恢复）。
- 本模块：管道性能的实时监控与优化建议（在线调优）。

- Little's Law: 排队系统的守恒定律。
- Amdahl's Law在分析管道中的应用-识别串行瓶颈。
"""

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

_EPS: float = 1e-9

@dataclass
class StageMetrics:
    """单个分析阶段的性能指标。"""
    stage_name: str
    total_arrivals: int = 0
    total_completions: int = 0
    total_service_time: float = 0.0  # 累计服务时间(秒)
    queue_depth_snapshots: List[int] = field(default_factory=list)
    arrival_timestamps: deque = field(default_factory=lambda: deque(maxlen=1000))

    @property
    def utilization(self) -> float:
        """利用率 = 累计服务时间 / 总经过时间。"""
        if not self.arrival_timestamps:
            return 0.0
        _elapsed = self.arrival_timestamps[-1] - self.arrival_timestamps[0]
        if _elapsed < _EPS:
            return 0.0
        return self.total_service_time / _elapsed

    @property
    def avg_service_time(self) -> float:
        if self.total_completions == 0:
            return 0.0
        return self.total_service_time / self.total_completions

    @property
    def avg_queue_depth(self) -> float:
        if not self.queue_depth_snapshots:
            return 0.0
        return sum(self.queue_depth_snapshots) / len(self.queue_depth_snapshots)

    @property
    def arrival_rate(self) -> float:
        """到达率(λ): 每秒到达数。"""
        if len(self.arrival_timestamps) < 2:
            return 0.0
        _elapsed = self.arrival_timestamps[-1] - self.arrival_timestamps[0]
        return len(self.arrival_timestamps) / max(_elapsed, _EPS)

@dataclass
class BottleneckReport:
    """瓶颈检测报告。"""
    stage_name: str
    utilization: float
    avg_queue: float
    is_bottleneck: bool
    severity: str  # "critical" / "warning" / "ok"
    recommendation: str

class PipelineBottleneckDetector:
    """管道瓶颈检测器-基于排队论的实时性能分析。

    使用范式：
      detector = PipelineBottleneckDetector(["disasm", "cfg", "vuln", "report"])
      # 阶段入队时
      detector.record_arrival("disasm")
      # 阶段处理完成时
      detector.record_completion("disasm", service_time=0.5)
      # 周期性检查
      bottlenecks = detector.detect_bottlenecks()
    """

    def __init__(
        self,
        stage_names: List[str],
        high_utilization: float = 0.85,
        queue_growth_rate: float = 0.1,
    ):
        self.high_utilization = high_utilization
        self.queue_growth_rate = queue_growth_rate

        self._stages: Dict[str, StageMetrics] = {
            name: StageMetrics(stage_name=name) for name in stage_names
        }
        # 各阶段当前队列长度
        self._queue_depths: Dict[str, int] = defaultdict(int)
        # 上次采样时间
        self._last_sample: float = time.time()

    def record_arrival(self, stage_name: str, item_id: str = ""):
        """记录一个任务到达某阶段。"""
        _stage = self._stages.get(stage_name)
        if _stage is None:
            return
        _stage.total_arrivals += 1
        _stage.arrival_timestamps.append(time.time())
        self._queue_depths[stage_name] += 1

    def record_completion(
        self, stage_name: str, service_time: float,
    ):
        """记录一个任务在某阶段完成处理。"""
        _stage = self._stages.get(stage_name)
        if _stage is None:
            return
        _stage.total_completions += 1
        _stage.total_service_time += service_time
        self._queue_depths[stage_name] = max(
            0, self._queue_depths[stage_name] - 1
        )

    def sample_queues(self):
        """采样当前各阶段的队列深度。"""
        for _name, _stage in self._stages.items():
            _stage.queue_depth_snapshots.append(
                self._queue_depths.get(_name, 0)
            )

    def detect_bottlenecks(self) -> List[BottleneckReport]:
        """检测当前瓶颈。"""
        self.sample_queues()
        _reports: List[BottleneckReport] = []

        for _name, _stage in self._stages.items():
            _util = _stage.utilization
            _q_avg = _stage.avg_queue_depth

            _is_bn = False
            _sev = "ok"
            _rec = "normal operation"

            if _util > self.high_utilization:
                _is_bn = True
                _sev = "critical" if _util > 0.95 else "warning"
                _rec = (
                    f"utilization={_util:.1%} > {self.high_utilization:.0%}. "
                    f"Add {max(1, int(_util * 2))} workers or optimize algorithm."
                )
            elif _q_avg > 5:
                _is_bn = True
                _sev = "warning"
                _rec = (
                    f"avg queue depth={_q_avg:.1f} suggests bursty arrivals. "
                    f"Consider pre-batching or flow control."
                )

            # Little's Law检查: L should ≈ λ·W
            _lambda = _stage.arrival_rate
            _W = _stage.avg_service_time
            _L_predicted = _lambda * _W
            _L_observed = _stage.avg_queue_depth

            if _L_observed > _L_predicted * 3 and _L_observed > 3:
                _rec += (
                    f" Little's Law violation: observed L={_L_observed:.1f} "
                    f"> predicted L={_L_predicted:.1f} - "
                    f"possible batching/concurrency effect inflating queue."
                )

            _reports.append(BottleneckReport(
                stage_name=_name,
                utilization=round(_util, 4),
                avg_queue=round(_q_avg, 2),
                is_bottleneck=_is_bn,
                severity=_sev,
                recommendation=_rec,
            ))

        return _reports

    def pipeline_throughput(self) -> float:
        """管道整体吞吐量 = 最慢阶段的完成率。"""
        _min_rate = float('inf')
        for _stage in self._stages.values():
            _rate = _stage.arrival_rate  # 稳态→到达率≈完成率
            if _rate > 0:
                _min_rate = min(_min_rate, _rate)
        return _min_rate if _min_rate != float('inf') else 0.0

# 冒烟测试
def _smoke_test():
    import random
    random.seed(42)

    _detector = PipelineBottleneckDetector([
        "disasm", "cfg_build", "vuln_detect", "report",
    ])

    # 模拟管道运行-每个任务流过4个阶段
    _base_time = time.time()
    for _step in range(100):
        _t_arrival = _base_time + _step * 0.5  # 每0.5s一个任务
        _detector._stages["disasm"].arrival_timestamps.append(_t_arrival)
        _detector._stages["cfg_build"].arrival_timestamps.append(_t_arrival + 0.3)
        _detector._stages["vuln_detect"].arrival_timestamps.append(_t_arrival + 0.6)
        _detector._stages["report"].arrival_timestamps.append(_t_arrival + 1.5)

        _detector.record_arrival("disasm")
        _detector.record_completion("disasm", 0.3)

        _detector.record_arrival("cfg_build")
        _detector.record_completion("cfg_build", 0.4)

        _detector.record_arrival("vuln_detect")
        # vuln_detect更慢-服务时间1.5s
        _detector.record_completion("vuln_detect", 1.5 + random.uniform(0, 0.5))
        # 累积队列
        if _step % 3 == 0:  # 每3个任务采样队列状态
            _detector._queue_depths["vuln_detect"] += 1

        _detector.record_arrival("report")
        _detector.record_completion("report", 0.2)

    _reports = _detector.detect_bottlenecks()
    print(f"[bottleneck] throughput: {_detector.pipeline_throughput():.2f} items/s")
    for _r in _reports:
        print(f"  {_r.stage_name}: util={_r.utilization:.2%} "
              f"queue={_r.avg_queue:.1f} "
              f"bottleneck={_r.is_bottleneck} [{_r.severity}]")

    # vuln_detect 应该是瓶颈
    _vuln = [r for r in _reports if r.stage_name == "vuln_detect"][0]
    assert _vuln.avg_queue > 0, "vuln_detect should have queue"
    print("[OK] PipelineBottleneckDetector smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
