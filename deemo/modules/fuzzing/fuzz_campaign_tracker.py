"""模糊测试活动追踪与报告器。

  EcoFuzz   -- exploration-vs-exploitation 状态追踪
  MicroFuzz     -- 生态/覆盖基的停止准则
  FuzzBench 指标体系 -- 标准化的模糊测试评测基准

提供跨天/周级别的模糊测试活动追踪, 包括:
  - 探索状态自动检测 (探索期 vs 利用期)
  - 覆盖增长率实时监控
  - 预测达到目标覆盖率所需的时间
  - Markdown/JSON 活动报告生成
  - 自定义停止准则评估
"""

import json
import logging
import math
import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

class CampaignPhase(str, Enum):
    """活动的宏观状态, 借鉴 EcoFuzz 的 state 切换思想。"""
    RAMP_UP = "ramp_up"          # 初始阶段, 覆盖率快速增长
    EXPLORATION = "exploration"  # 探索阶段, 仍有稳定新发现
    EXPLOITATION = "exploitation"  # 利用阶段, 在已知区域深挖
    STAGNATION = "stagnation"    # 停滞, 罕见新覆盖
    TERMINATED = "terminated"    # 已停止

@dataclass
class CampaignSnapshot:
    """活动在某一时刻的统计快照。"""
    timestamp: float
    elapsed_hours: float
    total_execs: int
    edges_covered: int
    unique_crashes: int
    execs_per_second: float
    coverage_rate: float
    phase: CampaignPhase
    queue_size: int
    avg_seed_energy: float = 0.0

@dataclass
class StopCriteria:
    """停止准则参数。

    MicroFuzz 提出基于生态学指标的停止准则:
      若连续 N 个周期新增覆盖边 < ε, 且无新崩溃, 则可停止。
    """
    max_hours: float = 72.0              # 硬上限: 最大运行时间
    stagnation_cycles: int = 5            # 允许的最大停滞周期数
    min_edge_goal: int = 0                # 最小覆盖边数目标 (0=禁用)
    crash_goal: int = 0                   # 目标崩溃发现数 (0=禁用)
    # 覆盖率增长阈值: 过去N分钟内新增边数必须 ≥ 此值, 否则计为停滞
    edge_growth_threshold: int = 2
    edge_growth_window_minutes: float = 30.0

class CampaignTracker:
    """模糊测试活动时间序列追踪器。

    记录每个采样周期的统计快照, 自动判断宏观阶段,
    评估是否满足停止条件。
    """

    def __init__(self, campaign_name: str = "",
                 output_dir: str = "./campaign_data"):
        self.campaign_name = campaign_name or f"campaign_{int(time.time())}"
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        self._snapshots: List[CampaignSnapshot] = []
        self._start_time: float = 0.0
        self._phase: CampaignPhase = CampaignPhase.RAMP_UP
        self._phase_cycles: int = 0
        self._stagnation_counter: int = 0

        # 覆盖增长的滑动窗口追踪
        self._edge_window: deque = deque(maxlen=100)
        # 每周期新增崩溃数
        self._crash_timeline: List[Tuple[float, int]] = []

    def start(self) -> None:
        self._start_time = time.time()
        self._phase = CampaignPhase.RAMP_UP
        self._stagnation_counter = 0

    def record_snapshot(self, total_execs: int, edges_covered: int,
                        unique_crashes: int, execs_per_second: float,
                        coverage_rate: float, queue_size: int,
                        avg_seed_energy: float = 0.0) -> CampaignSnapshot:
        """记录一次采样快照, 返回快照对象。

        应在每个 fuzz loop 迭代中调用 (或每 N 秒一次)。
        自动更新内部阶段状态。
        """
        elapsed = (time.time() - self._start_time) / 3600.0
        snap = CampaignSnapshot(
            timestamp=time.time(),
            elapsed_hours=elapsed,
            total_execs=total_execs,
            edges_covered=edges_covered,
            unique_crashes=unique_crashes,
            execs_per_second=execs_per_second,
            coverage_rate=coverage_rate,
            phase=self._phase,
            queue_size=queue_size,
            avg_seed_energy=avg_seed_energy,
        )
        self._snapshots.append(snap)

        # 追踪覆盖增长
        self._edge_window.append((snap.timestamp, edges_covered))

        # 更新宏观阶段
        self._update_phase(snap)

        return snap

    def _update_phase(self, snap: CampaignSnapshot) -> None:
        """基于近期覆盖率变化率更新活动阶段。

        启发式阈值 (可配置):
          - RAMP_UP: elapsed < 1h 且有增长
          - EXPLORATION: 过去 5 周期平均新边 ≥ 2
          - EXPLOITATION: 过去 5 周期平均新边 ∈ [0.5, 2)
          - STAGNATION: 过去 5 周期平均新边 < 0.5
        """
        recent = self._snapshots[-10:]
        if len(recent) < 3:
            return

        # 计算近期边增长速率
        growth_rates = []
        for i in range(1, len(recent)):
            delta = recent[i].edges_covered - recent[i - 1].edges_covered
            dt = max(1.0, (recent[i].timestamp - recent[i - 1].timestamp) / 60.0)
            growth_rates.append(delta / dt)  # 边/分钟

        avg_growth = sum(growth_rates) / len(growth_rates) if growth_rates else 0

        if snap.elapsed_hours < 1.0:
            self._phase = CampaignPhase.RAMP_UP
        elif avg_growth >= 2.0:
            self._phase = CampaignPhase.EXPLORATION
            self._stagnation_counter = 0
        elif avg_growth >= 0.5:
            self._phase = CampaignPhase.EXPLOITATION
            self._stagnation_counter = max(0, self._stagnation_counter - 1)
        else:
            self._stagnation_counter += 1
            if self._stagnation_counter >= 3:
                self._phase = CampaignPhase.STAGNATION

    def check_stop_criteria(self, criteria: StopCriteria) -> Tuple[bool, str]:
        """根据停止准则评估是否应停止活动。

        返回 (should_stop, reason)。
        """
        if not self._snapshots:
            return False, ""

        latest = self._snapshots[-1]

        # 硬超时
        if criteria.max_hours > 0 and latest.elapsed_hours >= criteria.max_hours:
            return True, f"达到最大运行时间 {criteria.max_hours}h"

        # 边数目标
        if criteria.min_edge_goal > 0 and latest.edges_covered >= criteria.min_edge_goal:
            return True, f"达到目标覆盖边数 {criteria.min_edge_goal}"

        # 崩溃目标
        if criteria.crash_goal > 0 and latest.unique_crashes >= criteria.crash_goal:
            return True, f"达到目标崩溃数 {criteria.crash_goal}"

        # 停滞检测
        if self._stagnation_counter >= criteria.stagnation_cycles:
            return True, f"连续 {self._stagnation_counter} 个周期无显著覆盖增长"

        return False, ""

    def predict_time_to_goal(self, target_edges: int) -> Optional[float]:
        """基于线性回归估计达到目标边数所需的剩余时间 (小时)。

        使用最近 20 个采样点拟合简单线性模型: edges = a * t + b。
        若当前无增长趋势 (a ≤ 0), 返回 None。
        """
        recent = self._snapshots[-20:]
        if len(recent) < 5:
            return None

        n = len(recent)
        sum_t = sum(s.elapsed_hours for s in recent)
        sum_e = sum(s.edges_covered for s in recent)
        sum_te = sum(s.elapsed_hours * s.edges_covered for s in recent)
        sum_t2 = sum(s.elapsed_hours ** 2 for s in recent)

        denom = n * sum_t2 - sum_t ** 2
        if abs(denom) < 1e-9:
            return None

        slope = (n * sum_te - sum_t * sum_e) / denom  # 边/小时

        if slope <= 0:
            return None

        current_edges = recent[-1].edges_covered
        remaining = target_edges - current_edges
        if remaining <= 0:
            return 0.0

        return remaining / slope

    def export_report(self, output_path: Optional[str] = None) -> str:
        """生成 Markdown 格式的活动进度报告。

        报告内容: 总体统计 / 覆盖率趋势 / 阶段时间线 / 崩溃列表。
        """
        if not self._snapshots:
            return "# No data\n"

        latest = self._snapshots[-1]
        first = self._snapshots[0]
        total_hours = latest.elapsed_hours

        # 计算关键指标
        edge_growth_rate = (
            (latest.edges_covered - first.edges_covered) / max(1, total_hours)
            if total_hours > 0 else 0
        )

        lines = [
            f"# Fuzzing Campaign Report: {self.campaign_name}",
            f"",
            f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"",
            f"## Summary",
            f"",
            f"| Metric | Value |",
            f"|---|---|",
            f"| Duration | {total_hours:.1f} hours |",
            f"| Total Executions | {latest.total_execs:,} |",
            f"| Execs/sec | {latest.execs_per_second:.1f} |",
            f"| Edges Covered | {latest.edges_covered} |",
            f"| Coverage Rate | {latest.coverage_rate:.2%} |",
            f"| Unique Crashes | {latest.unique_crashes} |",
            f"| Edge Growth Rate | {edge_growth_rate:.1f} edges/hour |",
            f"| Current Phase | **{latest.phase.value}** |",
            f"| Queue Size | {latest.queue_size} |",
            f"",
            f"## Phase Timeline",
            f"",
        ]

        # 阶段时间线
        phase_durations: Dict[CampaignPhase, float] = defaultdict(float)
        prev_snap = None
        for s in self._snapshots:
            if prev_snap is not None:
                dt = s.elapsed_hours - prev_snap.elapsed_hours
                phase_durations[prev_snap.phase] += dt
            prev_snap = s

        for phase in CampaignPhase:
            dur = phase_durations.get(phase, 0)
            if dur > 0.01:
                pct = dur / max(1, total_hours) * 100
                lines.append(f"- **{phase.value}**: {dur:.1f}h ({pct:.0f}%)")

        lines.extend([
            "",
            "## Coverage Trend",
            "",
            "| Time | Edges | Crashes | Phase |",
            "|---|---|---|---|",
        ])

        # 采样展示: 每 N 个快照取 1 个, 避免表格过长
        stride = max(1, len(self._snapshots) // 20)
        for s in self._snapshots[::stride]:
            lines.append(
                f"| {s.elapsed_hours:.1f}h | {s.edges_covered} | "
                f"{s.unique_crashes} | {s.phase.value} |"
            )

        # 最后一行
        last = self._snapshots[-1]
        lines.append(
            f"| {last.elapsed_hours:.1f}h | {last.edges_covered} | "
            f"{last.unique_crashes} | {last.phase.value} |"
        )

        report = "\n".join(lines)

        if output_path:
            full_path = os.path.join(self.output_dir, output_path)
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(report)

        return report

    def export_json(self, output_path: Optional[str] = None) -> Dict:
        """导出完整的快照时间序列为 JSON。"""
        data = {
            "campaign_name": self.campaign_name,
            "start_time": self._start_time,
            "snapshots": [
                {
                    "elapsed_hours": s.elapsed_hours,
                    "total_execs": s.total_execs,
                    "edges_covered": s.edges_covered,
                    "unique_crashes": s.unique_crashes,
                    "execs_per_second": s.execs_per_second,
                    "coverage_rate": s.coverage_rate,
                    "phase": s.phase.value,
                    "queue_size": s.queue_size,
                }
                for s in self._snapshots
            ],
        }

        if output_path:
            full_path = os.path.join(self.output_dir, output_path)
            with open(full_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

        return data

# 便捷入口

def create_tracker(name: str, output_dir: str = "./campaign_data") -> CampaignTracker:
    tracker = CampaignTracker(campaign_name=name, output_dir=output_dir)
    tracker.start()
    return tracker

# 简单的线性预测器

def estimate_remaining_time(
    current_edges: int,
    target_edges: int,
    edge_growth_per_hour: float,
) -> Optional[float]:
    """朴素的线性时间估算。

    若 edge_growth_per_hour ≤ 0, 返回 None (无法预测)。
    不考虑覆盖率增长的边际递减效应 — 实际时间通常比此估计长。
    """
    if edge_growth_per_hour <= 0:
        return None
    remaining = max(0, target_edges - current_edges)
    return remaining / edge_growth_per_hour
