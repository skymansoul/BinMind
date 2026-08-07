# stub_temporal_patterns.py — 桩调用时序模式检测
# 从健康监控的调用时间戳序列中提取时序模式:
#   突发性 (Burstiness)、周期性 (Periodicity)、衰减趋势 (Decay)、
#   记忆性 (Memory)。
# 用于预测桩的未来使用窗口与废弃候选判定。
#
# 问题:
#   StubHealthMonitor 仅统计调用次数与末次时间，不分析调用时序分布。
#   "末次调用 90 天前"可能意味着:
#     a) 已废弃（所有调用是更久之前，且不再增长）
#     b) 周期性低谷（每季度调用一次，恰好处于间歇期）
#     c) 突发后静默（一次大规模使用后再无需求）
#   仅凭末次时间无法区分这三种情况。
#
# 方法:
#   1. 突发性参数 BP = (σ - μ) / (σ + μ)
#      其中 σ/μ 为事件间隔时间的标准差/均值。
#      BP > 0 → 突发（间隔波动大）；BP < 0 → 均匀。
#   2. 记忆系数 MC = 1 - (Σ|τ_{i+1}-τ_i| / Σ|τ_j-τ_k|)
#      度量连续间隔的相关性。MC > 0 → 正相关（长间隔后跟长间隔）。
#   3. 周期性: 自相关函数在 τ 处的峰值显著性。
#   4. 衰减趋势: 线性回归斜率 × 调用间隔的符号。
#   5. 综合模式分类: bursty | periodic | decaying | steady | cold
#
bursty_dynamics
#   本模块将 BP+MC 分析框架适配到桩系统调用时序场景，
#   并增加了周期性检测与衰减趋势两个独立维度。
import math as _math
import time as _time
from collections import defaultdict as _dd
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt


@_dc
class TemporalProfile:
    """单个模块的时序模式分析结果。"""
    module_name: str
    total_calls: int = 0
    # 时间窗口（秒）
    observation_span: float = 0.0
    # 突发性
    burstiness_bp: float = 0.0      # >0=突发, <0=均匀, ≈0=泊松
    is_bursty: bool = False          # BP > 0.3
    # 记忆性
    memory_coefficient: float = 0.0  # >0=正相关, <0=负相关
    has_memory: bool = False         # |MC| > 0.2
    # 周期性
    dominant_period: float = 0.0     # 秒，最强周期；0=无显著周期
    period_confidence: float = 0.0   # 0~1
    is_periodic: bool = False        # period_confidence > 0.6
    # 衰减趋势
    trend_slope: float = 0.0         # >0=增长, <0=衰减
    is_decaying: bool = False        # slope < -0.01 且持续
    # 综合分类
    pattern_class: str = 'unknown'   # bursty|periodic|decaying|steady|cold
    # 预测
    next_expected_window: str = ''   # 可读的预测窗口描述
    deprecation_risk: float = 0.0    # 0~1，基于模式的废弃风险


class TemporalAnalyzer:
    """时序模式分析器。

    输入: 带时间戳的调用记录列表 [(timestamp_float,), ...]
    输出: TemporalProfile

    最小数据要求: ≥5 次调用以进行有意义的统计分析。
    低于此阈值直接归类为 cold。
    """

    MIN_CALLS_FOR_ANALYSIS = 5

    def analyze(self, module_name: str,
                call_timestamps: list[float]) -> TemporalProfile:
        """对单个模块的调用时序执行完整分析。"""
        profile = TemporalProfile(
            module_name=module_name,
            total_calls=len(call_timestamps),
        )

        if len(call_timestamps) < self.MIN_CALLS_FOR_ANALYSIS:
            profile.pattern_class = 'cold'
            profile.deprecation_risk = 0.85 if len(call_timestamps) == 0 else 0.5
            profile.next_expected_window = 'insufficient_data'
            return profile

        sorted_ts = sorted(call_timestamps)
        profile.observation_span = sorted_ts[-1] - sorted_ts[0]

        # 1. 突发性
        intervals = [sorted_ts[i+1] - sorted_ts[i]
                    for i in range(len(sorted_ts) - 1)]
        profile.burstiness_bp = self._burstiness(intervals)
        profile.is_bursty = profile.burstiness_bp > 0.3

        # 2. 记忆性
        if len(intervals) >= 2:
            profile.memory_coefficient = self._memory_coeff(intervals)
            profile.has_memory = abs(profile.memory_coefficient) > 0.2

        # 3. 周期性（自相关）
        period, conf = self._detect_periodicity(sorted_ts)
        profile.dominant_period = period
        profile.period_confidence = conf
        profile.is_periodic = conf > 0.6

        # 4. 衰减趋势（线性回归斜率）
        profile.trend_slope = self._trend_slope(sorted_ts)
        profile.is_decaying = profile.trend_slope < -0.01 and len(call_timestamps) >= 10

        # 5. 综合分类
        profile.pattern_class = self._classify(profile)

        # 6. 预测与废弃风险
        profile.next_expected_window = self._predict_window(profile, sorted_ts)
        profile.deprecation_risk = self._deprecation_risk(profile, sorted_ts)

        return profile

    def analyze_from_monitor(self, module_name: str) -> TemporalProfile:
        """从 StubHealthMonitor 的类型观测记录中提取时序并分析。"""
        try:
            from modules.stubs.stub_health_monitor import StubHealthMonitor
            mon = StubHealthMonitor()
            # 从类型观测记录收集时间戳
            if not hasattr(mon, '_type_observations'):
                return TemporalProfile(module_name=module_name,
                                      pattern_class='cold',
                                      deprecation_risk=0.9)
            timestamps = []
            prefix = f'{module_name}::'
            for key, obs_list in mon._type_observations.items():
                if key.startswith(prefix):
                    timestamps.extend(o['ts'] for o in obs_list)
            return self.analyze(module_name, timestamps)
        except ImportError:
            return TemporalProfile(module_name=module_name,
                                  pattern_class='unknown')

# 统计算子
    @staticmethod
    def _burstiness(intervals: list[float]) -> float:
        """突发性参数 B = (σ - μ) / (σ + μ)。

        B ∈ [-1, 1]:
          B > 0  → 间隔方差大 → 突发模式
          B ≈ 0  → 泊松过程（随机独立事件）
          B < 0  → 间隔均匀 → 周期性规律调用
        """
        if not intervals:
            return 0.0
        n = len(intervals)
        mu = sum(intervals) / n
        if mu < 1e-9:
            return 0.0
        var = sum((x - mu) ** 2 for x in intervals) / n
        sigma = _math.sqrt(var)
        denom = sigma + mu
        return (sigma - mu) / denom if denom > 1e-9 else 0.0

    @staticmethod
    def _memory_coeff(intervals: list[float]) -> float:
        """记忆系数 MC = 1 - (Σ|τ_{i+1}-τ_i|) / (2 * (n-1) * mean)。

        度量连续间隔之间的相关性。
        MC > 0 → 正相关: 长间隔后跟长间隔，短间隔后跟短间隔
        MC ≈ 0 → 无记忆: 间隔独立
        MC < 0 → 负相关: 长间隔后跟短间隔（均值回归）
        """
        n = len(intervals)
        if n < 2:
            return 0.0
        mu = sum(intervals) / n
        if mu < 1e-9:
            return 0.0

        abs_diffs = sum(abs(intervals[i+1] - intervals[i])
                       for i in range(n - 1))
        # 分母: 所有间隔对差的均值 × 2(n-1)
        denominator = 2 * (n - 1) * mu
        if denominator < 1e-9:
            return 0.0
        return 1.0 - (abs_diffs / denominator)

    @staticmethod
    def _detect_periodicity(timestamps: list[float]) -> tuple[float, float]:
        """自相关检测周期性。返回 (主周期秒数, 置信度)。

        对间隔序列做自相关，找第一个显著峰（lag≥2）。
        置信度 = 峰值自相关系数。
        """
        if len(timestamps) < 10:
            return 0.0, 0.0

        intervals = [timestamps[i+1] - timestamps[i]
                    for i in range(len(timestamps) - 1)]
        n = len(intervals)
        if n < 4:
            return 0.0, 0.0

        mu = sum(intervals) / n
        var = sum((x - mu) ** 2 for x in intervals) / n
        if var < 1e-9:
            return 0.0, 0.0

        max_lag = min(n // 2, 30)
        best_corr = 0.0
        best_lag = 0

        for lag in range(2, max_lag):
            if n - lag < 3:
                break
            # 自相关系数
            cov = 0.0
            for i in range(n - lag):
                cov += (intervals[i] - mu) * (intervals[i + lag] - mu)
            corr = cov / ((n - lag) * var) if var > 1e-9 else 0.0

            if corr > best_corr and corr > 0.3:
                best_corr = corr
                best_lag = lag

        if best_lag == 0:
            return 0.0, 0.0

        # 主周期 = 平均间隔 × best_lag
        period = mu * best_lag
        return period, min(best_corr, 1.0)

    @staticmethod
    def _trend_slope(timestamps: list[float]) -> float:
        """对最近 50 次调用的间隔计算线性回归斜率。

        斜率 > 0 → 间隔增大 → 调用频率衰减。
        使用滑动窗口（最近 N 个间隔）捕捉趋势变化。
        """
        intervals = [timestamps[i+1] - timestamps[i]
                    for i in range(len(timestamps) - 1)]
        window = intervals[-50:] if len(intervals) > 50 else intervals
        n = len(window)
        if n < 3:
            return 0.0

        x_mean = (n - 1) / 2.0
        y_mean = sum(window) / n
        num = sum((i - x_mean) * (window[i] - y_mean) for i in range(n))
        den = sum((i - x_mean) ** 2 for i in range(n))
        return num / den if den > 1e-9 else 0.0

# 分类
    @staticmethod
    def _classify(p: TemporalProfile) -> str:
        """综合多维度信号分类。

        优先级:
          1. cold → 调用量 < 5
          2. periodic → 高周期置信度
          3. bursty → 高突发性
          4. decaying → 衰减趋势
          5. steady → 其余（健康规律调用）
        """
        if p.total_calls < TemporalAnalyzer.MIN_CALLS_FOR_ANALYSIS:
            return 'cold'

        if p.is_periodic and p.period_confidence > 0.7:
            if p.is_bursty:
                return 'periodic_bursty'
            return 'periodic'

        if p.is_bursty and p.burstiness_bp > 0.5:
            return 'bursty'

        if p.is_decaying and p.trend_slope < -0.05:
            return 'decaying'

        if p.is_bursty:
            return 'bursty'

        return 'steady'

    @staticmethod
    def _predict_window(p: TemporalProfile,
                        timestamps: list[float]) -> str:
        """预测下一次使用窗口。"""
        if p.pattern_class == 'cold':
            return 'no_prediction_available'
        if p.pattern_class in ('periodic', 'periodic_bursty') and p.dominant_period > 0:
            last = timestamps[-1]
            next_expected = last + p.dominant_period
            now = _time.time()
            if next_expected < now:
                return 'overdue'
            remaining = next_expected - now
            if remaining < 3600:
                return f'imminent (<{remaining/60:.0f}m)'
            if remaining < 86400:
                return f'today_or_tomorrow'
            return f'in_{remaining/86400:.1f}_days'
        if p.pattern_class == 'decaying':
            return 'likely_none_decaying'
        if p.pattern_class == 'bursty':
            return 'unpredictable_bursty'
        return 'steady_ongoing'

    @staticmethod
    def _deprecation_risk(p: TemporalProfile,
                          timestamps: list[float]) -> float:
        """基于时序模式评估废弃风险 (0~1)。"""
        if p.pattern_class == 'cold':
            return 0.85
        if p.pattern_class == 'decaying':
            return 0.7
        if p.pattern_class == 'bursty':
            # 突发模式: 检查最近一次突发距今多久
            last = timestamps[-1]
            now = _time.time()
            days_since = (now - last) / 86400.0
            if days_since > 180:
                return 0.6
            return 0.3
        if p.pattern_class in ('periodic', 'periodic_bursty'):
            # 周期性: 是否已过预期窗口
            if p.dominant_period > 0:
                last = timestamps[-1]
                expected_next = last + p.dominant_period
                if _time.time() > expected_next * 1.5:
                    return 0.4
            return 0.1
        # steady
        return 0.05


# 批量分析入口
def analyze_all_patterns() -> dict[str, TemporalProfile]:
    """对所有有调用记录的桩模块执行时序分析。"""
    try:
        from modules.stubs.stub_health_monitor import StubHealthMonitor
        mon = StubHealthMonitor()
        if not hasattr(mon, '_type_observations'):
            return {}
        # 按模块聚合时间戳
        by_module = _dd(list)
        for key, obs_list in mon._type_observations.items():
            module = key.split('::')[0]
            by_module[module].extend(o['ts'] for o in obs_list)
        analyzer = TemporalAnalyzer()
        return {
            mod: analyzer.analyze(mod, sorted(ts))
            for mod, ts in by_module.items()
        }
    except ImportError:
        return {}


__all__ = ['TemporalProfile', 'TemporalAnalyzer', 'analyze_all_patterns']
