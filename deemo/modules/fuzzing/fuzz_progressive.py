# 2026-08-03

"""渐进式多阶段模糊测试流水线 -- 有序串联不同策略以最大化长期覆盖收益。

参考:
  EcoFuzz (USENIX 2020, Zotero)    -- exploration→exploitation 状态机
  HFL: Hybrid Fuzzing on the Linux Kernel (Zotero) -- 内核混合模糊测试
  SAFL (Zotero)                     -- 符号执行+引导模糊测试的逐步覆盖加速
  Driller (NDSS 2016, Zotero)       -- 选择性符号执行增强模糊测试
  CSEFuzz (Zotero)                  -- 基于符号执行的模糊测试

设计原则:
  单一策略在整个模糊测试周期中不是最优的。不同的阶段应该采用不同的
  策略组合——初期快速探索, 中期深度挖掘, 后期冲刺突破。

流水线阶段:
  Phase 1 (RAMP_UP):   确定性变异 + Explore 能量 + 高频字典变异
  Phase 2 (EXPLORE):   随机 havoc + CoE 能量 + 结构感知变异
  Phase 3 (DEEPEN):    MOPT自适应 + Adaptive 能量 + 符号辅助突破
  Phase 4 (CONVERGE):  精确最小化 + Quad 能量 + 崩溃去重
"""

import logging
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class PipelineStage(str, Enum):
    RAMP_UP = "ramp_up"        # 初期: 快速建立覆盖基线
    EXPLORE = "explore"        # 中期: 广度优先, 探索新路径
    DEEPEN = "deepen"          # 后期: 深度变异, 突破复杂条件
    CONVERGE = "converge"      # 收敛: 精细化, 去重, 崩溃验证
    TERMINATED = "terminated"  # 终止


@dataclass
class StageConfig:
    """单个流水线阶段的配置。"""
    stage: PipelineStage
    mutation_mode: str = "havoc"       # havoc / deterministic / structure_aware / hybrid
    energy_policy: str = "explore"     # explore / coe / quad / lin / fast / adaptive
    scheduler_strategy: str = "aflfast"  # aflfast / bandit / roundrobin / weighted
    max_duration_minutes: float = 60.0
    # 触发下一阶段的条件
    min_edges_for_transition: int = 0
    min_crashes_for_transition: int = 0
    # 本阶段参数
    mutation_intensity: float = 1.0    # 变异密度乘数
    dict_weight: float = 0.3           # 字典使用权重
    symex_enabled: bool = False        # 符号执行辅助开关


@dataclass
class PipelineState:
    """流水线运行时的状态快照。"""
    current_stage: PipelineStage
    stage_start_time: float
    total_execs: int = 0
    edges_covered: int = 0
    unique_crashes: int = 0
    stage_changes: int = 0
    execs_per_second: float = 0.0
    coverage_growth_rate: float = 0.0   # 边/分钟


class ProgressivePipeline:
    """渐进式多阶段模糊测试流水线。

    根据预设的阶段配置自动切换变异策略、能量策略和调度策略,
    每个阶段有独立的持续时间上限和触发下一阶段的条件。

    配置参考 EcoFuzz 的 exploration/exploitation 自适应切换,
    但改为显式的多阶段计划而非在线启发式判断。
    """

    # 默认四阶段配置 (可被传入的 configs 覆盖)
    DEFAULT_CONFIGS: List[StageConfig] = [
        StageConfig(
            stage=PipelineStage.RAMP_UP,
            mutation_mode="deterministic",
            energy_policy="explore",
            scheduler_strategy="roundrobin",
            max_duration_minutes=15.0,
            min_edges_for_transition=500,
        ),
        StageConfig(
            stage=PipelineStage.EXPLORE,
            mutation_mode="havoc",
            energy_policy="coe",
            scheduler_strategy="aflfast",
            max_duration_minutes=90.0,
            min_edges_for_transition=2000,
        ),
        StageConfig(
            stage=PipelineStage.DEEPEN,
            mutation_mode="structure_aware",
            energy_policy="adaptive",
            scheduler_strategy="bandit",
            max_duration_minutes=180.0,
            mutation_intensity=1.5,
            dict_weight=0.5,
            symex_enabled=True,
        ),
        StageConfig(
            stage=PipelineStage.CONVERGE,
            mutation_mode="hybrid",
            energy_policy="quad",
            scheduler_strategy="weighted",
            max_duration_minutes=60.0,
            mutation_intensity=0.7,
        ),
    ]

    def __init__(self, configs: Optional[List[StageConfig]] = None):
        self._configs = configs or self.DEFAULT_CONFIGS
        self._stage_idx: int = 0
        self._state = PipelineState(
            current_stage=PipelineStage.RAMP_UP,
            stage_start_time=time.time(),
        )
        self._stage_history: List[PipelineState] = []

    @property
    def current_config(self) -> StageConfig:
        idx = min(self._stage_idx, len(self._configs) - 1)
        return self._configs[idx]

    @property
    def state(self) -> PipelineState:
        return self._state

    def update(self, total_execs: int, edges_covered: int,
               unique_crashes: int, execs_per_second: float) -> PipelineStage:
        """每个周期调用一次, 评估是否应切换到下一阶段。

        返回当前阶段 (若刚切换, 返回切换后的新阶段)。
        """
        self._state.total_execs = total_execs
        self._state.edges_covered = edges_covered
        self._state.unique_crashes = unique_crashes
        self._state.execs_per_second = execs_per_second

        cfg = self.current_config
        elapsed_minutes = (time.time() - self._state.stage_start_time) / 60.0

        should_transition = False
        reason = ""

        # 条件1: 超时
        if elapsed_minutes >= cfg.max_duration_minutes:
            should_transition = True
            reason = f"timeout ({elapsed_minutes:.0f}/{cfg.max_duration_minutes:.0f}min)"

        # 条件2: 达到覆盖目标
        elif cfg.min_edges_for_transition > 0 and edges_covered >= cfg.min_edges_for_transition:
            should_transition = True
            reason = f"edges_goal ({edges_covered}/{cfg.min_edges_for_transition})"

        # 条件3: 达到崩溃目标
        elif cfg.min_crashes_for_transition > 0 and unique_crashes >= cfg.min_crashes_for_transition:
            should_transition = True
            reason = f"crash_goal ({unique_crashes}/{cfg.min_crashes_for_transition})"

        if should_transition:
            # 保存旧状态
            self._stage_history.append(PipelineState(
                current_stage=self._state.current_stage,
                stage_start_time=self._state.stage_start_time,
                total_execs=total_execs,
                edges_covered=edges_covered,
                unique_crashes=unique_crashes,
                stage_changes=self._state.stage_changes,
            ))

            # 切换到下一阶段
            self._stage_idx = min(self._stage_idx + 1, len(self._configs) - 1)
            next_stage = self._configs[self._stage_idx].stage if self._stage_idx < len(self._configs) else PipelineStage.TERMINATED

            self._state = PipelineState(
                current_stage=next_stage,
                stage_start_time=time.time(),
                total_execs=total_execs,
                edges_covered=edges_covered,
                unique_crashes=unique_crashes,
                stage_changes=len(self._stage_history),
            )
            logger.info("流水线 %s→%s (%s)", self._stage_history[-1].current_stage.value, next_stage.value, reason)

        return self._state.current_stage

    def is_terminated(self) -> bool:
        return self._state.current_stage == PipelineStage.TERMINATED

    def stage_summary(self) -> Dict:
        return {
            "current_stage": self._state.current_stage.value,
            "stage_idx": self._stage_idx,
            "stage_elapsed_min": (time.time() - self._state.stage_start_time) / 60.0,
            "total_stages_configured": len(self._configs),
            "history": [
                {
                    "stage": h.current_stage.value,
                    "edges_at_end": h.edges_covered,
                    "crashes_at_end": h.unique_crashes,
                }
                for h in self._stage_history
            ],
            "current_config": {
                "mutation": self.current_config.mutation_mode,
                "energy": self.current_config.energy_policy,
                "scheduler": self.current_config.scheduler_strategy,
            },
        }


# ===== 阶段自适应切换器 (EcoFuzz 风格) =====

class AdaptiveStageSwitcher:
    """EcoFuzz 风格的在线阶段检测, 不依赖预设时间表。

    与 ProgressivePipeline 不同: 此处根据实时覆盖增长率
    动态决定当前处于哪个阶段, 而非按固定时间推进。

    当覆盖率增长快 (edge_growth > threshold_high) → EXPLORE
    当覆盖率增长中 → EXPLOIT
    当覆盖率停滞 (edge_growth < threshold_low 连续 N 周期) → DEEPEN (调用符号)
    """

    def __init__(self, growth_window: int = 10,
                 high_threshold: float = 5.0,
                 low_threshold: float = 1.0,
                 stagnation_cycles: int = 5):
        self.window = growth_window
        self.high = high_threshold   # 边/周期
        self.low = low_threshold
        self.stagnation_cycles = stagnation_cycles
        self._edge_history: List[int] = []
        self._current_phase = PipelineStage.EXPLORE
        self._stagnation_count = 0

    def update(self, current_edges: int) -> PipelineStage:
        self._edge_history.append(current_edges)
        if len(self._edge_history) > self.window * 2:
            self._edge_history.pop(0)

        if len(self._edge_history) < self.window:
            return self._current_phase

        recent = self._edge_history[-self.window:]
        growth = (recent[-1] - recent[0]) / self.window

        if growth >= self.high:
            self._current_phase = PipelineStage.EXPLORE
            self._stagnation_count = 0
        elif growth >= self.low:
            self._current_phase = PipelineStage.EXPLORE  # 仍有稳定增长
            self._stagnation_count = max(0, self._stagnation_count - 1)
        else:
            self._stagnation_count += 1
            if self._stagnation_count >= self.stagnation_cycles:
                self._current_phase = PipelineStage.DEEPEN
            else:
                self._current_phase = PipelineStage.CONVERGE

        return self._current_phase

    @property
    def phase(self) -> PipelineStage:
        return self._current_phase
