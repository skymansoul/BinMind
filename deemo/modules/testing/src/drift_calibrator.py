# 修改记录:
# 2025-07-30 11:23 - 从固定窗口改为指数加权窗口，对近期变化敏感度更高
# 2025-08-01 09:45 - 增加历史策略有效性追踪，避免反复推荐已被证明无效的策略
# 2025-08-03 15:17 - 引入 CUSUM 变点检测替代简单阈值，降低误报率

# Fuzzing 覆盖漂移校准器 — 检测覆盖率增长停滞并建议策略调整
#
# 设计动机:
#   长期 fuzzing (数小时→数天) 的覆盖增长非单调:
#     - 初期: 快速增长, 新边频繁
#     - 中期: 增长放缓, 发现新边需要更深度变异
#     - 后期: 饱和/漂移——在低价值区域反复变异, 覆盖几乎不变
#
#   现有 power_schedule.py 单次调度种子能量, seed_selector.py 选种子,
#   但两者均无全局视角: 当前整体 fuzzing 策略是否仍然有效?
#   是否应该切换策略 (如加大 havoc、导入新种子、偏重 dir_fuzz)?
#
# 核心方法:
#   1. 维护新边发现率的时间序列 (指数加权窗口, 半衰期 = 300s)
#   2. CUSUM (累积和) 变点检测: 检测发现率是否发生了系统性下降
#      (非临时波动, 而是结构性变化——参 Page 1954, Biometrika)
#   3. 当变点检测触发时, 从策略建议列表中选取历史上未被证伪的建议
#   4. 追踪每条建议的历史有效性 (是否在采纳后 N 轮内打破了停滞)
#
# 去耦合:
#   DriftCalibrator 只诊断 + 建议; 调用方负责执行建议内容。
#   建议是结构化数据, 调用方可按自有逻辑取舍。
#
# 参考文献:
#   Page 1954, "Continuous Inspection Schemes", Biometrika 41(1/2):100-115
#     — CUSUM 变点检测的奠基性工作。本项目使用其单侧均值上升/下降
#       检测公式: S_t = max(0, S_{t-1} + (x_t - μ_0 - k))
#   UNIFUZZ (Li et al. USENIX 2020) — 系统性评估多种 fuzzer 发现:
#       不同阶段切换策略可显著提升长期覆盖率; 本项目取其阶段性策略
#       切换思想但以数据驱动替代预设时间表。
#   CollAFL (Gan et al. S&P 2020) — 覆盖冲突解决; 本项目借鉴其
#       "覆盖质量退化"检测概念, 扩展为漂移校准器。
import math
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum


class DriftPhase(str, Enum):
    """Fuzzing 覆盖增长阶段。"""
    RAMP_UP = "ramp_up"        # 初期快速增长
    STEADY = "steady"           # 稳定增长
    SLOWING = "slowing"         # 增长放缓 (< 50% 峰值速率)
    PLATEAU = "plateau"         # 接近停滞 (> 300s 无新边)
    STALLED = "stalled"         # 确认停滞 (> 900s 无新边, CUSUM 触发)


class StrategyCategory(str, Enum):
    """建议策略的类型——与现有模块的接合点。"""
    SWITCH_POWER_SCHEDULE = "switch_power"    # → power_schedule.py
    INCREASE_HAVOC = "increase_havoc"          # → adaptive_mutator 调高 epsilon
    INJECT_FRESH_SEEDS = "inject_seeds"        # → 从外部语料导入新种子
    DIRECTED_FOCUS = "directed_focus"           # → directed_fuzz.py 激活
    DICTIONARY_ON = "dictionary_on"             # → dictionary_builder 产物注入
    CONCOLIC_BOOST = "concolic_boost"           # → concolic_bridge.py 求解新输入
    RESHUFFLE_CORPUS = "reshuffle_corpus"       # → coverage_index 蒸馏后重新排序


@dataclass
class CalibrationAdvice:
    """单条校准建议。"""
    strategy: StrategyCategory
    rationale: str
    confidence: float              # [0, 1], 基于历史成功率
    suggested_params: Dict[str, Any] = field(default_factory=dict)
    previously_failed: bool = False
    cooldown_remaining_s: float = 0.0  # 冷却期剩余时间 (秒)


@dataclass
class WindowSnapshot:
    """一个时间窗口的覆盖统计。"""
    timestamp: float
    new_edges: int
    total_edges: int
    execs: int
    new_crashes: int


class DriftCalibrator:
    """Fuzzing 覆盖漂移检测与策略校准器。

    典型用法:
        cal = DriftCalibrator()
        for each fuzzing round:
            cal.record_window(new_edges, total_edges, execs, new_crashes)
            advice = cal.check()
            if advice:
                # 调用方根据 advice 执行策略调整
                apply_advice(advice)
                cal.mark_advice_applied(advice)
            # 几轮后反馈:
            cal.record_advice_outcome(advice, was_effective=True)
    """

    def __init__(self,
                 window_half_life: float = 300.0,
                 plateau_threshold_s: float = 300.0,
                 stall_threshold_s: float = 900.0,
                 cusum_k: float = 0.5,
                 cusum_h: float = 5.0):
        """
        window_half_life: 指数加权窗口的半衰期 (秒)
        plateau_threshold_s: 多长时间无新边视为停滞警告
        stall_threshold_s: 多长时间无新边 + CUSUM触发确认为停滞
        cusum_k: CUSUM slack值 (标准差的倍数, 默认0.5σ)
        cusum_h: CUSUM 决策阈值 (默认5.0)
        """
        self._half_life = window_half_life
        self._plateau_s = plateau_threshold_s
        self._stall_s = stall_threshold_s
        self._cusum_k = cusum_k
        self._cusum_h = cusum_h

        # 窗口历史 (环形)
        self._windows: deque = deque(maxlen=128)
        # 指数加权统计
        self._ewma_rate: float = 0.0       # 新边/秒 的 EWMA
        self._ewma_crashes_rate: float = 0.0
        self._last_update: float = 0.0
        # CUSUM 状态
        self._cusum_pos: float = 0.0        # 上侧累积和 (检测下降)
        self._cusum_neg: float = 0.0        # 下侧累积和
        # 最近一次新边的时间
        self._last_new_edge_time: float = 0.0
        # 阶段
        self._phase: DriftPhase = DriftPhase.RAMP_UP
        self._phase_entered_at: float = time.monotonic()
        # 策略追踪
        self._strategy_history: Dict[str, List[Tuple[float, bool]]] = (
            defaultdict(list))
        self._strategy_cooldown: Dict[str, float] = {}  # strategy → cooldown_end_time
        # 基准: 最近一次的覆盖峰值
        self._peak_rate: float = 0.0
        # 轮次
        self._round = 0

    # ---- 输入 ----
    def record_window(self, new_edges: int, total_edges: int,
                      execs: int, new_crashes: int = 0) -> None:
        """记录一个时间窗口的覆盖统计。调用间隔通常为 30-60s。"""
        now = time.monotonic()
        self._round += 1

        snap = WindowSnapshot(
            timestamp=now, new_edges=new_edges,
            total_edges=total_edges, execs=execs,
            new_crashes=new_crashes)
        self._windows.append(snap)

        # 指数加权更新
        if self._last_update > 0:
            dt = now - self._last_update
            alpha = 1.0 - math.exp(-dt * math.log(2) / self._half_life)
        else:
            alpha = 1.0
        self._last_update = now

        if execs > 0:
            instant_rate = new_edges / max(1.0, dt if 'dt' in dir() else 1.0)
            instant_rate = new_edges  # 简化为绝对计数
            self._ewma_rate = (alpha * new_edges
                               + (1.0 - alpha) * self._ewma_rate)
            self._ewma_crashes_rate = (
                alpha * new_crashes
                + (1.0 - alpha) * self._ewma_crashes_rate)

        if new_edges > 0:
            self._last_new_edge_time = now

        # 更新峰值速率
        if self._ewma_rate > self._peak_rate:
            self._peak_rate = self._ewma_rate

        # CUSUM 更新 (检测 EWMA 速率下降)
        self._update_cusum(new_edges)

        # 阶段判定
        self._update_phase(now)

    def _update_cusum(self, new_edges: int) -> None:
        """CUSUM 单侧检测: 检测新边数是否系统性地低于 EWMA 基线。

        S_pos 检测上升 (这里监测的是 "停滞持续多久", 所以用 S_neg):
          S_0 = 0
          S_t = max(0, S_{t-1} + (μ - x_t - k))
        其中 μ = ewma_rate, k = cusum_k * σ_estimate, h = cusum_h
        """
        target = self._ewma_rate
        if target <= 0:
            return

        # 使用窗口内标准差估计
        if len(self._windows) >= 4:
            recent = [w.new_edges for w in
                      list(self._windows)[-8:]]
            mean_r = sum(recent) / len(recent)
            var_r = sum((x - mean_r) ** 2 for x in recent) / len(recent)
            sigma = math.sqrt(max(var_r, 1e-6))
        else:
            sigma = max(1.0, target * 0.3)

        k = self._cusum_k * sigma
        # 偏差 = 预期 - 实际, 正值表示低于预期
        deviation = target - new_edges - k
        self._cusum_pos = max(0.0, self._cusum_pos + deviation)
        # 下侧 (恢复检测): 实际优于预期
        self._cusum_neg = max(0.0,
                              self._cusum_neg + (new_edges - target - k))

    def _update_phase(self, now: float) -> None:
        """根据当前指标更新阶段。"""
        time_since_new = now - self._last_new_edge_time
        cusum_triggered = self._cusum_pos > self._cusum_h

        old_phase = self._phase

        if time_since_new > self._stall_s and cusum_triggered:
            self._phase = DriftPhase.STALLED
        elif time_since_new > self._plateau_s:
            self._phase = DriftPhase.PLATEAU
        elif (self._peak_rate > 0 and
              self._ewma_rate < 0.5 * self._peak_rate and
              self._round > 20):
            self._phase = DriftPhase.SLOWING
        elif self._round > 50:
            self._phase = DriftPhase.STEADY
        else:
            self._phase = DriftPhase.RAMP_UP

        if old_phase != self._phase:
            self._phase_entered_at = now

    # ---- 诊断 ----
    def check(self) -> List[CalibrationAdvice]:
        """检查并返回当前阶段下的策略建议。无建议时返回空列表。"""
        now = time.monotonic()
        advice_list: List[CalibrationAdvice] = []

        # 仅在 SLOWING / PLATEAU / STALLED 阶段生成建议
        if self._phase in (DriftPhase.RAMP_UP, DriftPhase.STEADY):
            return []

        candidate_strategies = self._candidates_for_phase(self._phase)
        for strat in candidate_strategies:
            # 检查冷却期
            cooldown_end = self._strategy_cooldown.get(strat.value, 0.0)
            cooldown_remaining = max(0.0, cooldown_end - now)
            if cooldown_remaining > 0:
                continue

            # 计算历史成功率
            hist = self._strategy_history.get(strat.value, [])
            total_attempts = len(hist)
            # 考虑衰减: 近期结果权重高于远期
            success_rate = self._weighted_success_rate(hist)

            advice_list.append(CalibrationAdvice(
                strategy=strat,
                rationale=self._rationale_for(strat),
                confidence=success_rate if total_attempts >= 2 else 0.5,
                previously_failed=(
                    total_attempts > 0 and success_rate < 0.3),
                cooldown_remaining_s=cooldown_remaining,
            ))

        # 按置信度降序
        advice_list.sort(key=lambda a: -a.confidence)
        return advice_list

    def _candidates_for_phase(self,
                               phase: DriftPhase) -> List[StrategyCategory]:
        """不同阶段推荐不同策略组合。"""
        if phase == DriftPhase.SLOWING:
            return [
                StrategyCategory.INCREASE_HAVOC,
                StrategyCategory.DICTIONARY_ON,
                StrategyCategory.RESHUFFLE_CORPUS,
            ]
        if phase == DriftPhase.PLATEAU:
            return [
                StrategyCategory.SWITCH_POWER_SCHEDULE,
                StrategyCategory.INCREASE_HAVOC,
                StrategyCategory.CONCOLIC_BOOST,
                StrategyCategory.INJECT_FRESH_SEEDS,
            ]
        # STALLED
        return [
            StrategyCategory.INJECT_FRESH_SEEDS,
            StrategyCategory.CONCOLIC_BOOST,
            StrategyCategory.DIRECTED_FOCUS,
            StrategyCategory.RESHUFFLE_CORPUS,
        ]

    def _rationale_for(self, strat: StrategyCategory) -> str:
        _rationales = {
            StrategyCategory.SWITCH_POWER_SCHEDULE:
                "切换能量调度算法, 改变种子优先级顺序以打破局部搜索",
            StrategyCategory.INCREASE_HAVOC:
                "增大havoc变异比例和epsilon探索率, 增加输入多样性",
            StrategyCategory.INJECT_FRESH_SEEDS:
                "从外部语料或已有崩溃中注入新种子, 引入未探索的路径前缀",
            StrategyCategory.DIRECTED_FOCUS:
                "激活定向fuzzing, 聚焦于当前覆盖稀少的代码区域",
            StrategyCategory.DICTIONARY_ON:
                "启用字典引导变异, 利用结构token提升变异命中率",
            StrategyCategory.CONCOLIC_BOOST:
                "对当前未探索的分支做约束求解, 生成可穿透magic bytes的输入",
            StrategyCategory.RESHUFFLE_CORPUS:
                "重新蒸馏语料库并重排序种子优先级, 清除低价值种子",
        }
        return _rationales.get(strat, "调整当前策略")

    @staticmethod
    def _weighted_success_rate(history: List[Tuple[float, bool]],
                                decay: float = 0.7) -> float:
        """加权成功率: 越近的结果权重越高。"""
        if not history:
            return 0.5  # 无历史时中性
        total_weight = 0.0
        weighted_success = 0.0
        for i, (_, success) in enumerate(reversed(history)):
            w = decay ** i
            weighted_success += w * (1.0 if success else 0.0)
            total_weight += w
        return weighted_success / max(0.01, total_weight)

    # ---- 反馈 ----
    def mark_advice_applied(self, advice: CalibrationAdvice) -> None:
        """标记一条建议已被采纳。设置冷却期防抖——同策略在 5min 内不再推荐。"""
        self._strategy_cooldown[advice.strategy.value] = (
            time.monotonic() + 300.0)

    def record_advice_outcome(self, advice: CalibrationAdvice,
                              was_effective: bool) -> None:
        """反馈一条建议的效果。was_effective 的判断标准由调用方定义
        (典型: 采纳后 N 轮内新边数是否 > 采纳前均值)。"""
        self._strategy_history[advice.strategy.value].append(
            (time.monotonic(), was_effective))
        # 保留最近 32 条
        if len(self._strategy_history[advice.strategy.value]) > 32:
            self._strategy_history[advice.strategy.value] = (
                self._strategy_history[advice.strategy.value][-32:])

    # ---- 统计 ----
    @property
    def phase(self) -> DriftPhase:
        return self._phase

    @property
    def ewma_new_edges(self) -> float:
        return self._ewma_rate

    @property
    def time_since_new_edge(self) -> float:
        if self._last_new_edge_time <= 0:
            return float('inf')
        return time.monotonic() - self._last_new_edge_time

    def stats(self) -> Dict[str, Any]:
        return {
            "phase": self._phase.value,
            "phase_duration_s": round(
                time.monotonic() - self._phase_entered_at, 1),
            "ewma_rate": round(self._ewma_rate, 3),
            "ewma_crashes_rate": round(self._ewma_crashes_rate, 3),
            "peak_rate": round(self._peak_rate, 3),
            "cusum_pos": round(self._cusum_pos, 3),
            "cusum_h": self._cusum_h,
            "cusum_triggered": self._cusum_pos > self._cusum_h,
            "time_since_new_edge_s": round(self.time_since_new_edge, 1),
            "windows_recorded": len(self._windows),
            "strategies_tracked": len(self._strategy_history),
        }

    def reset(self) -> None:
        self._windows.clear()
        self._ewma_rate = 0.0
        self._ewma_crashes_rate = 0.0
        self._last_update = 0.0
        self._cusum_pos = 0.0
        self._cusum_neg = 0.0
        self._last_new_edge_time = 0.0
        self._phase = DriftPhase.RAMP_UP
        self._phase_entered_at = time.monotonic()
        self._strategy_history.clear()
        self._strategy_cooldown.clear()
        self._peak_rate = 0.0
        self._round = 0
