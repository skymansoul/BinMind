#
# 路径多样性收敛分析器 — 检测自适应阈值系统的稳定/振荡/发散状态
#
# PathDiversityTracker._auto_adjust_threshold 是比例控制器——
# 探索速度 < 0.5/s 降阈值（促进更多路径被认定为"独特"从而保留）
# 探索速度 > 5/s 升阈值（减少冗余）。但纯比例控制在一个交替循环
# 的程序上可能持续振荡——阈值在两个相邻值间反复跳变，永不安全收敛
#
# 本模块不替代自适应阈值——它在外部观测其行为，诊断当前处于何种动力学状态：
#   (a) 收敛 (converged): 阈值稳定在单个值 ± 死区范围内
#   (b) 振荡 (oscillating): 阈值在两个（较少情况下三个）值间周期性跳变
#   (c) 发散 (diverging): 阈值单方向漂移，未表现出收敛趋势
#
# 诊断结果供 PathDiversityTracker 的调用方决策：
#   - 收敛 → 当前阈值可使用，ANN 索引结构可固化以减少重建开销
#   - 振荡 → 考虑引入死区或滞回，或切换到更大力度的阈值步长
#   - 发散 → 触发更激进的阈值步长或重启多样性策略
#
# 理论基础：
# 自适应滤波理论 (Haykin, Adapt 过滤 Theory, 5th ed.) 中的
# LMS 收敛性分析——误差信号的二阶统计量可区分稳定与振荡状态
#   本模块将阈值序列视为一维信号的采样值，应用滑动窗口方差 +
# 符号变化率 + 一阶导数符号一致性三个指标判定状态
#
# (Mai et al., 2021) — 符号执行中自适应搜索策略的收敛性
# 分析框架，其 stabili metric 定义被本模块的 _stability_index 借鉴并
# 扩展为三维判定（方差+符号变化率+导数一致性）

import math
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import deque


@dataclass
class ConvergenceState:
    """收敛分析的即时状态快照"""
    status: str = "unknown"          # "converged" / "oscillating" / "diverging"
    stability_index: float = 1.0     # [0, 1]，越高越稳定
    oscillation_amplitude: float = 0.0  # 振荡幅度（阈值单位）
    trend_direction: float = 0.0     # 一阶导数符号的平均值（正=上升趋势）
    samples_since_change: int = 0    # 阈值最后一次变化以来的采样数
    recommendation: str = ""         # 面向调用方的操作


class ConvergenceAnalyzer:
    """观测自适应阈值的时间序列并诊断动力学状态
    
    调用方每隔 N 秒调用 observe(threshold, metric) 推入最新观测
    get_st() 返回基于滑动窗口的诊断结果
    
    分离于 PathDiversityTracker 的设计理由：
    PathDiversityTracker 有 ~1800 行业务逻辑——路径特征提取、SimHash、
    ANN 索引、配额管理、热力图。收敛分析是"元观测"——它不参与路径管理
    只观测管理器的输出。独立模块避免循环依赖，且可复用于 Threshold 之外的
    自适应参数（如 SimHash 排斥汉明距离、预算刷新周期）
    """

    def __init__(self,
                 window_size: int = 30,
                 dead_zone_ratio: float = 0.05,
                 oscillation_max_period: int = 6,
                 divergence_trend_samples: int = 10):
        """
        window_s: 滑动窗口大小（观测次数），默认 30
        dead_zone_ratio: 死区占当前阈值的比例——在此范围内的阈值变化
        不计为"变化"，默认 0.05（5%）
        oscillation_max_period: 判定振荡的最大周期（窗口内）
        若阈值在 ≤此数 的观测内反复跳变即判定振荡
        divergence_trend_samples: 判定发散所需的趋势一致性样本数
        """
        self._window_size = window_size
        self._dead_zone_ratio = dead_zone_ratio
        self._oscillation_max_period = oscillation_max_period
        self._divergence_trend_samples = divergence_trend_samples

        self._thresholds: deque = deque(maxlen=window_size)
        self._metrics: deque = deque(maxlen=window_size)    # 每步的探索速度
        self._diversity_growth: deque = deque(maxlen=window_size)  # 每步新增路径数
        self._state = ConvergenceState()
        self._observation_count: int = 0

    def observe(self, threshold: float, exploration_rate: float,
                new_paths: int = 0):
        """记录一次观测
        
        threshold: 当前相似度阈值
        exploration_r: 当前探索速度（路径/秒）
        new_paths: 此步新增的独立路径数
        """
        self._observation_count += 1
        self._thresholds.append(threshold)
        self._metrics.append(exploration_rate)

        # 追踪路径多样性增长率——二阶导数信息
        if len(self._diversity_growth) >= 1:
            prev_total = sum(self._diversity_growth)
            # 增长率变化 = 当前新增 vs 窗口内平均新增
            if len(self._diversity_growth) > 0:
                avg_growth = prev_total / max(1, len(self._diversity_growth))
                growth_delta = new_paths - avg_growth
                self._diversity_growth.append(growth_delta)
            else:
                self._diversity_growth.append(float(new_paths))
        else:
            self._diversity_growth.append(float(new_paths))

        # 更新状态——仅在有足够样本时
        if self._observation_count >= max(5, self._window_size // 3):
            self._diagnose()

    def _diagnose(self):
        """核心诊断逻辑——三维判定"""
        thresholds = list(self._thresholds)
        if len(thresholds) < 5:
            return

        current = thresholds[-1]
        dead_zone = max(0.005, current * self._dead_zone_ratio)

        # 维度 1: 方差——阈值在窗口内的离散程度
        mean_t = sum(thresholds) / len(thresholds)
        variance = sum((t - mean_t) ** 2 for t in thresholds) / len(thresholds)
        std = math.sqrt(variance)

        # 维度 2: 符号变化率——阈值改变方向的频率
        # 先构建"显著变化"序列（过滤死区内抖动）
        significant = [thresholds[0]]
        for t in thresholds[1:]:
            if abs(t - significant[-1]) > dead_zone:
                significant.append(t)
        direction_changes = 0
        if len(significant) >= 3:
            for i in range(1, len(significant) - 1):
                prev_dir = significant[i] - significant[i - 1]
                curr_dir = significant[i + 1] - significant[i]
                if prev_dir * curr_dir < 0:  # 方向反转
                    direction_changes += 1

        # 维度 3: 一阶导数符号一致性——连续同号则趋势明确
        if len(thresholds) >= self._divergence_trend_samples:
            deltas = [thresholds[i + 1] - thresholds[i]
                      for i in range(len(thresholds) - 1)]
            recent_deltas = deltas[-self._divergence_trend_samples:]
            same_sign = 0
            for d in recent_deltas:
                if d > dead_zone:
                    same_sign += 1
                elif d < -dead_zone:
                    same_sign -= 1
            trend_strength = abs(same_sign) / len(recent_deltas)
        else:
            trend_strength = 0.0

        #---- 状态判定 ----

        # 死区较小→较窄的阈值范围也有可能判定振荡
        osc_indicator = direction_changes / max(1, len(significant) - 2)

        if std <= dead_zone * 2:
            status = "converged"
            stability = 0.95
            recommendation = "阈值已稳定——可固化 ANN 索引以减少重建"
        elif osc_indicator > 0.3 and len(significant) <= 4:
            status = "oscillating"
            # 振荡越频繁→稳定性越低
            stability = max(0.2, 1.0 - osc_indicator)
            # 将震荡幅度转换为
            amp = max(abs(significant[i] - significant[i - 1])
                      for i in range(1, len(significant))) if len(significant) >= 2 else 0.0
            if amp < dead_zone * 3:
                recommendation = "微幅振荡——建议将死区扩大至当前值的 1.5x"
            else:
                recommendation = "大幅振荡——建议引入滞回（hysteresis），步长减半"
        elif trend_strength > 0.7 and std > dead_zone * 3:
            status = "diverging"
            # 趋势越强→越不稳定
            stability = max(0.1, 1.0 - trend_strength)
            last_deltas = [thresholds[i + 1] - thresholds[i]
                           for i in range(len(thresholds) - 1)]
            avg_trend = sum(last_deltas[-self._divergence_trend_samples:]) / \
                        max(1, len(last_deltas[-self._divergence_trend_samples:]))
            if avg_trend > 0:
                recommendation = "阈值持续上升——可能过度排斥路径，建议干预上限"
            else:
                recommendation = "阈值持续下降——可能路径冗余严重，检查配额管理"
        else:
            status = "unstable"
            stability = 0.5
            recommendation = "暂未稳定——继续观测，当前样本数不足以判定"

        self._state = ConvergenceState(
            status=status,
            stability_index=round(stability, 3),
            oscillation_amplitude=round(std, 4),
            trend_direction=round(
                (thresholds[-1] - thresholds[0]) / max(0.001, len(thresholds)), 4),
            samples_since_change=self._count_since_last_change(
                thresholds, dead_zone),
            recommendation=recommendation,
        )

    def _count_since_last_change(self, thresholds: List[float],
                                  dead_zone: float) -> int:
        """从序列末尾向前计数——连续未发生显著变化的样本数"""
        count = 1
        for i in range(len(thresholds) - 1, 0, -1):
            if abs(thresholds[i] - thresholds[i - 1]) > dead_zone:
                break
            count += 1
        return count

    def get_state(self) -> ConvergenceState:
        return self._state

    def should_stabilize(self, consecutive_stable_samples: int = 15) -> bool:
        """返回 True 表示阈值已连续稳定足够长时间——可以降低观测频率
        或固化 ANN 索引参数"""
        return (self._state.status == "converged" and
                self._state.samples_since_change >= consecutive_stable_samples)

    def recommended_step_size(self, current_step: float) -> float:
        """根据诊断状态调整后的阈值步长
        
        振荡状态下步长减半，发散状态下步长加倍以加速收敛
        调用方（_auto_adjust_threshold）可选择采纳或忽略此
        """
        if self._state.status == "oscillating":
            return current_step * 0.5
        elif self._state.status == "diverging":
            return current_step * 2.0
        return current_step
